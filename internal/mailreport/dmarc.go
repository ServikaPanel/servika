package mailreport

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// The wire shape of a DMARC aggregate report (RFC 7489 appendix C).
//
// Only the fields the panel stores are declared. encoding/xml ignores the rest,
// which is what keeps a reporter's extra elements from being a parse failure.
type feedback struct {
	XMLName  xml.Name `xml:"feedback"`
	Metadata struct {
		OrgName   string `xml:"org_name"`
		ReportID  string `xml:"report_id"`
		DateRange struct {
			Begin string `xml:"begin"`
			End   string `xml:"end"`
		} `xml:"date_range"`
	} `xml:"report_metadata"`
	Policy struct {
		P     string `xml:"p"`
		ADKIM string `xml:"adkim"`
		ASPF  string `xml:"aspf"`
	} `xml:"policy_published"`
	Records []struct {
		Row struct {
			SourceIP string `xml:"source_ip"`
			Count    string `xml:"count"`
			Policy   struct {
				Disposition string `xml:"disposition"`
				DKIM        string `xml:"dkim"`
				SPF         string `xml:"spf"`
			} `xml:"policy_evaluated"`
		} `xml:"row"`
		Identifiers struct {
			HeaderFrom string `xml:"header_from"`
		} `xml:"identifiers"`
	} `xml:"record"`
}

// ParseAggregate reads a DMARC aggregate report.
//
// A report is atomic: one unusable row rejects the whole document rather than
// being dropped. Storing the rest would produce a dashboard that under-counts
// without saying so, and the count is the entire point of the screen. The
// collector records the refusal, so a reporter sending malformed documents is
// visible rather than silently half-read.
func ParseAggregate(body []byte) (Report, error) {
	if len(body) > MaxUnpackedBytes {
		return Report{}, fmt.Errorf("the report is larger than %d bytes", MaxUnpackedBytes)
	}
	var document feedback
	decoder := xml.NewDecoder(bytes.NewReader(body))
	// A report is UTF-8 in practice, but some reporters label it otherwise.
	// Without a charset reader the decoder refuses the document outright, and
	// treating the bytes as they are is better than losing the report; a wrong
	// guess can only produce field values that then fail their own checks.
	decoder.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) { return input, nil }
	if err := decoder.Decode(&document); err != nil {
		if errors.Is(err, io.EOF) {
			return Report{}, ErrNotAReport
		}
		return Report{}, ErrNotAReport
	}
	if document.XMLName.Local != "feedback" {
		return Report{}, ErrNotAReport
	}

	report := Report{}
	var err error
	if report.OrgName, err = checkedField("org_name", document.Metadata.OrgName, maxOrgName); err != nil {
		return Report{}, err
	}
	if report.ReportID, err = checkedField("report_id", document.Metadata.ReportID, maxReportID); err != nil {
		return Report{}, err
	}
	if report.OrgName == "" || report.ReportID == "" {
		return Report{}, errors.New("the report has no org_name or report_id")
	}
	if report.DateBegin, err = parseEpoch(document.Metadata.DateRange.Begin); err != nil {
		return Report{}, fmt.Errorf("date_range begin: %w", err)
	}
	if report.DateEnd, err = parseEpoch(document.Metadata.DateRange.End); err != nil {
		return Report{}, fmt.Errorf("date_range end: %w", err)
	}
	if err := checkedRange(report.DateBegin, report.DateEnd); err != nil {
		return Report{}, err
	}
	if report.PolicyP, err = checkedField("p", document.Policy.P, maxShortResult); err != nil {
		return Report{}, err
	}
	if report.PolicyADKIM, err = alignmentFlag(document.Policy.ADKIM); err != nil {
		return Report{}, err
	}
	if report.PolicyASPF, err = alignmentFlag(document.Policy.ASPF); err != nil {
		return Report{}, err
	}

	if len(document.Records) > MaxRecords {
		return Report{}, fmt.Errorf("the report holds more than %d records", MaxRecords)
	}
	report.Rows = make([]Row, 0, len(document.Records))
	for index, record := range document.Records {
		row := Row{}
		if row.SourceIP, err = checkedIP("source_ip", record.Row.SourceIP); err != nil {
			return Report{}, fmt.Errorf("record %d: %w", index+1, err)
		}
		if row.MessageCount, err = parseCount(record.Row.Count); err != nil {
			return Report{}, fmt.Errorf("record %d: %w", index+1, err)
		}
		if row.Disposition, err = checkedField("disposition", record.Row.Policy.Disposition, maxShortResult); err != nil {
			return Report{}, fmt.Errorf("record %d: %w", index+1, err)
		}
		if row.DKIMResult, err = checkedField("dkim", record.Row.Policy.DKIM, maxShortResult); err != nil {
			return Report{}, fmt.Errorf("record %d: %w", index+1, err)
		}
		if row.SPFResult, err = checkedField("spf", record.Row.Policy.SPF, maxShortResult); err != nil {
			return Report{}, fmt.Errorf("record %d: %w", index+1, err)
		}
		if row.HeaderFrom, err = checkedField("header_from", record.Identifiers.HeaderFrom, maxHeaderFrom); err != nil {
			return Report{}, fmt.Errorf("record %d: %w", index+1, err)
		}
		report.Rows = append(report.Rows, row)
	}
	return report, nil
}

// parseEpoch reads the seconds-since-epoch form a DMARC date range uses.
func parseEpoch(value string) (time.Time, error) {
	seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return time.Time{}, errors.New("not a whole number of seconds")
	}
	return time.Unix(seconds, 0).UTC(), nil
}

// parseCount reads a row's message tally and refuses a value that would make
// every total on the dashboard meaningless.
func parseCount(value string) (uint64, error) {
	count, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return 0, errors.New("count is not a whole number")
	}
	if count > MaxMessageCount {
		return 0, fmt.Errorf("count is larger than %d", MaxMessageCount)
	}
	return count, nil
}

// alignmentFlag accepts the single letter DMARC uses for alignment mode, or
// nothing. The column is CHAR(1), so a longer value would be silently cut.
func alignmentFlag(value string) (string, error) {
	value = strings.TrimSpace(value)
	switch value {
	case "", "r", "s":
		return value, nil
	default:
		return "", fmt.Errorf("alignment mode %q is neither r nor s", value)
	}
}
