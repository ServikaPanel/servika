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
	Policies []tlsPolicy `json:"policies"`
}

// tlsPolicy is one entry of the report's policies array.
type tlsPolicy struct {
	Policy struct {
		PolicyType string `json:"policy-type"`
	} `json:"policy"`
	Summary struct {
		Success uint64 `json:"total-successful-session-count"`
		Failure uint64 `json:"total-failure-session-count"`
	} `json:"summary"`
	FailureDetails []tlsFailureDetail `json:"failure-details"`
}

// tlsFailureDetail is one failure bucket inside a policy.
type tlsFailureDetail struct {
	ResultType   string `json:"result-type"`
	SendingMTAIP string `json:"sending-mta-ip"`
	ReceivingMX  string `json:"receiving-mx-hostname"`
	SessionCount uint64 `json:"failed-session-count"`
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
	if isNotATLSReport(document) {
		return TLSReport{}, ErrNotAReport
	}

	report, err := tlsHeader(document)
	if err != nil {
		return TLSReport{}, err
	}

	details := failureDetailCount(document)
	if details > MaxRecords {
		return TLSReport{}, fmt.Errorf("the report holds more than %d failure entries", MaxRecords)
	}

	report.Failures = make([]TLSFailure, 0, details)
	for index, policy := range document.Policies {
		if err := addPolicy(&report, policy); err != nil {
			return TLSReport{}, fmt.Errorf("policy %d: %w", index+1, err)
		}
	}
	return report, nil
}

// isNotATLSReport reports whether the document is valid JSON that carries none
// of the report's required fields, which makes it somebody else's attachment
// rather than a broken report.
func isNotATLSReport(document tlsDocument) bool {
	return document.OrgName == "" && document.ReportID == "" && len(document.Policies) == 0
}

// failureDetailCount totals the failure entries across every policy, so the
// ceiling cannot be stepped around by spreading them over several.
func failureDetailCount(document tlsDocument) int {
	var details int
	for _, policy := range document.Policies {
		details += len(policy.FailureDetails)
	}
	return details
}

// tlsHeader reads the report's metadata and date range.
func tlsHeader(document tlsDocument) (TLSReport, error) {
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
	return report, nil
}

// addPolicy folds one policy's summary and failure details into the report. The
// caller adds the policy number, so the message names which entry failed.
//
// The policy type is taken from the first policy only: the panel publishes one
// policy per domain, so a second entry is the reporter also trying a different
// policy type for the same names.
func addPolicy(report *TLSReport, policy tlsPolicy) error {
	var err error
	if report.PolicyType == "" {
		if report.PolicyType, err = checkedField("policy-type", policy.Policy.PolicyType, maxShortResult); err != nil {
			return err
		}
	}
	if policy.Summary.Success > MaxMessageCount || policy.Summary.Failure > MaxMessageCount {
		return fmt.Errorf("a session count is larger than %d", MaxMessageCount)
	}
	report.SuccessCount += policy.Summary.Success
	report.FailureCount += policy.Summary.Failure

	for _, detail := range policy.FailureDetails {
		failure, err := tlsFailure(detail)
		if err != nil {
			return err
		}
		report.Failures = append(report.Failures, failure)
	}
	return nil
}

// tlsFailure reads one failure bucket.
func tlsFailure(detail tlsFailureDetail) (TLSFailure, error) {
	failure := TLSFailure{SessionCount: detail.SessionCount}
	if failure.SessionCount > MaxMessageCount {
		return TLSFailure{}, fmt.Errorf("failed-session-count is larger than %d", MaxMessageCount)
	}
	var err error
	if failure.ResultType, err = checkedField("result-type", detail.ResultType, maxResultType); err != nil {
		return TLSFailure{}, err
	}
	// The sending address is optional in a TLS-RPT failure entry, but a value
	// that is present has to be an address: it is grouped and displayed as one.
	if strings.TrimSpace(detail.SendingMTAIP) != "" {
		if failure.SendingMTAIP, err = checkedIP("sending-mta-ip", detail.SendingMTAIP); err != nil {
			return TLSFailure{}, err
		}
	}
	if failure.ReceivingMX, err = checkedField("receiving-mx-hostname", detail.ReceivingMX, maxHostname); err != nil {
		return TLSFailure{}, err
	}
	return failure, nil
}

// parseRFC3339 reads the timestamp form TLS-RPT uses for its date range.
func parseRFC3339(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, errors.New("not an RFC 3339 timestamp")
	}
	return parsed.UTC(), nil
}
