package mailreport

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The wire shape of a TLS-RPT report (RFC 8460 section 4).
type tlsDocument struct {
	OrgName   string `json:"organization-name"`
	ReportID  string `json:"report-id"`
	DateRange struct {
		Start string `json:"start-datetime"`
		End   string `json:"end-datetime"`
	} `json:"date-range"`
	Policies []struct {
		Policy struct {
			PolicyType string `json:"policy-type"`
		} `json:"policy"`
		Summary struct {
			Success uint64 `json:"total-successful-session-count"`
			Failure uint64 `json:"total-failure-session-count"`
		} `json:"summary"`
		FailureDetails []struct {
			ResultType   string `json:"result-type"`
			SendingMTAIP string `json:"sending-mta-ip"`
			ReceivingMX  string `json:"receiving-mx-hostname"`
			SessionCount uint64 `json:"failed-session-count"`
		} `json:"failure-details"`
	} `json:"policies"`
}

// ParseTLSRPT reads a TLS-RPT report.
//
// Like the DMARC parser this is atomic: an unusable entry rejects the document.
// The summary counts and the failure details have to agree with each other for
// the screen to mean anything, so keeping one without the other is worse than
// keeping neither.
//
// A report may describe several policies. Their summaries are added together
// and their failure details concatenated: the panel publishes one policy per
// domain, so more than one entry means the reporter also tried a different
// policy type (a DANE record, say) for the same names, and both outcomes are
// about the same mail.
func ParseTLSRPT(body []byte) (TLSReport, error) {
	if len(body) > MaxUnpackedBytes {
		return TLSReport{}, fmt.Errorf("the report is larger than %d bytes", MaxUnpackedBytes)
	}
	var document tlsDocument
	if err := json.Unmarshal(body, &document); err != nil {
		return TLSReport{}, ErrNotAReport
	}
	if document.OrgName == "" && document.ReportID == "" && len(document.Policies) == 0 {
		// Valid JSON that carries none of the report's required fields is
		// somebody else's attachment, not a broken report.
		return TLSReport{}, ErrNotAReport
	}

	report := TLSReport{}
	var err error
	if report.OrgName, err = checkedField("organization-name", document.OrgName, maxOrgName); err != nil {
		return TLSReport{}, err
	}
	if report.ReportID, err = checkedField("report-id", document.ReportID, maxReportID); err != nil {
		return TLSReport{}, err
	}
	if report.OrgName == "" || report.ReportID == "" {
		return TLSReport{}, errors.New("the report has no organization-name or report-id")
	}
	if report.DateBegin, err = parseRFC3339(document.DateRange.Start); err != nil {
		return TLSReport{}, fmt.Errorf("start-datetime: %w", err)
	}
	if report.DateEnd, err = parseRFC3339(document.DateRange.End); err != nil {
		return TLSReport{}, fmt.Errorf("end-datetime: %w", err)
	}
	if err := checkedRange(report.DateBegin, report.DateEnd); err != nil {
		return TLSReport{}, err
	}

	var details int
	for _, policy := range document.Policies {
		details += len(policy.FailureDetails)
	}
	if details > MaxRecords {
		return TLSReport{}, fmt.Errorf("the report holds more than %d failure entries", MaxRecords)
	}

	report.Failures = make([]TLSFailure, 0, details)
	for index, policy := range document.Policies {
		if report.PolicyType == "" {
			if report.PolicyType, err = checkedField("policy-type", policy.Policy.PolicyType, maxShortResult); err != nil {
				return TLSReport{}, err
			}
		}
		if policy.Summary.Success > MaxMessageCount || policy.Summary.Failure > MaxMessageCount {
			return TLSReport{}, fmt.Errorf("policy %d: a session count is larger than %d", index+1, MaxMessageCount)
		}
		report.SuccessCount += policy.Summary.Success
		report.FailureCount += policy.Summary.Failure

		for _, detail := range policy.FailureDetails {
			failure := TLSFailure{SessionCount: detail.SessionCount}
			if failure.SessionCount > MaxMessageCount {
				return TLSReport{}, fmt.Errorf("policy %d: failed-session-count is larger than %d", index+1, MaxMessageCount)
			}
			if failure.ResultType, err = checkedField("result-type", detail.ResultType, maxResultType); err != nil {
				return TLSReport{}, fmt.Errorf("policy %d: %w", index+1, err)
			}
			// The sending address is optional in a TLS-RPT failure entry, but a
			// value that is present has to be an address: it is grouped and
			// displayed as one.
			if strings.TrimSpace(detail.SendingMTAIP) != "" {
				if failure.SendingMTAIP, err = checkedIP("sending-mta-ip", detail.SendingMTAIP); err != nil {
					return TLSReport{}, fmt.Errorf("policy %d: %w", index+1, err)
				}
			}
			if failure.ReceivingMX, err = checkedField("receiving-mx-hostname", detail.ReceivingMX, maxHostname); err != nil {
				return TLSReport{}, fmt.Errorf("policy %d: %w", index+1, err)
			}
			report.Failures = append(report.Failures, failure)
		}
	}
	return report, nil
}

// parseRFC3339 reads the timestamp form TLS-RPT uses for its date range.
func parseRFC3339(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, errors.New("not an RFC 3339 timestamp")
	}
	return parsed.UTC(), nil
}
