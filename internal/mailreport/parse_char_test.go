package mailreport

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Every field of a report is a refusal point, and the parsers are atomic, so a
// value that fails any one of them rejects the whole document. These pin which
// value fails which check and what each refusal says.

// spoil replaces one fragment of the aggregate fixture.
func spoil(old, replacement string) string {
	return strings.Replace(aggregateXML("192.0.2.1", "1", "google.com"), old, replacement, 1)
}

// refuses parses a document and requires a refusal naming reason.
func refuses(t *testing.T, body, reason string) {
	t.Helper()
	_, err := ParseAggregate([]byte(body))
	if err == nil {
		t.Fatal("the report was accepted")
	}
	if !strings.Contains(err.Error(), reason) {
		t.Errorf("error %q does not name %q", err, reason)
	}
}

func TestAnAggregateReportRefusesEachSpoiledField(t *testing.T) {
	long := strings.Repeat("a", 300)
	for _, tc := range []struct{ name, body, reason string }{
		{
			"a report_id past the ceiling",
			spoil("<report_id>1234567890</report_id>", "<report_id>"+long+"</report_id>"),
			"report_id",
		},
		{
			"no org_name at all",
			spoil("<org_name>google.com</org_name>", "<org_name></org_name>"),
			"no org_name or report_id",
		},
		{
			"a begin that is not a number",
			spoil("<begin>1770000000</begin>", "<begin>yesterday</begin>"),
			"date_range begin",
		},
		{
			"an end that is not a number",
			spoil("<end>1770086400</end>", "<end>tomorrow</end>"),
			"date_range end",
		},
		{
			"a policy past the ceiling",
			spoil("<p>quarantine</p>", "<p>"+long+"</p>"),
			"p is longer than",
		},
		{
			"an adkim that is neither r nor s",
			spoil("<adkim>r</adkim>", "<adkim>maybe</adkim>"),
			"alignment mode",
		},
		{
			"an aspf that is neither r nor s",
			spoil("<aspf>r</aspf>", "<aspf>maybe</aspf>"),
			"alignment mode",
		},
		{
			"a disposition past the ceiling",
			spoil("<disposition>none</disposition>", "<disposition>"+long+"</disposition>"),
			"disposition",
		},
		{
			"a dkim result past the ceiling",
			spoil("<dkim>pass</dkim>", "<dkim>"+long+"</dkim>"),
			"dkim is longer than",
		},
		{
			"an spf result past the ceiling",
			spoil("<spf>pass</spf>", "<spf>"+long+"</spf>"),
			"spf is longer than",
		},
		{
			"a header_from past the ceiling",
			spoil("<header_from>example.com</header_from>", "<header_from>"+long+"</header_from>"),
			"header_from",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixedNow(t)
			refuses(t, tc.body, tc.reason)
		})
	}
}

// A document that is well-formed XML but is not a feedback report is somebody
// else's attachment, which the collector skips rather than records as broken.
func TestAnXMLDocumentThatIsNotAFeedbackIsNotAReport(t *testing.T) {
	fixedNow(t)
	if _, err := ParseAggregate([]byte(`<?xml version="1.0"?><invoice><total>5</total></invoice>`)); !errors.Is(err, ErrNotAReport) {
		t.Errorf("ParseAggregate = %v, want ErrNotAReport", err)
	}
}

// Some reporters label the document with a charset other than UTF-8. Without a
// charset reader the decoder refuses it outright, and losing the report is
// worse than reading the bytes as they are.
func TestALabelledCharsetDoesNotLoseTheReport(t *testing.T) {
	fixedNow(t)
	document := strings.Replace(aggregateXML("192.0.2.1", "1", "google.com"),
		`encoding="UTF-8"`, `encoding="ISO-8859-1"`, 1)

	report, err := ParseAggregate([]byte(document))
	if err != nil {
		t.Fatalf("a report labelled ISO-8859-1 was refused: %v", err)
	}
	if report.OrgName != "google.com" {
		t.Errorf("org_name = %q", report.OrgName)
	}
}

// A hostile document must not turn one message into a million inserts.
func TestAnAggregateReportWithTooManyRecordsIsRefused(t *testing.T) {
	fixedNow(t)
	var records strings.Builder
	for range MaxRecords + 1 {
		records.WriteString(`<record><row><source_ip>192.0.2.1</source_ip><count>1</count>` +
			`<policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>` +
			`</row><identifiers><header_from>example.com</header_from></identifiers></record>`)
	}
	document := strings.Replace(aggregateXML("192.0.2.1", "1", "google.com"),
		"</feedback>", records.String()+"</feedback>", 1)

	refuses(t, document, fmt.Sprintf("more than %d records", MaxRecords))
}

// The ceiling is judged on the unpacked bytes, before any of them are parsed.
func TestAnOversizedReportIsRefusedBeforeItIsParsed(t *testing.T) {
	fixedNow(t)
	oversized := make([]byte, MaxUnpackedBytes+1)
	refuses(t, string(oversized), "larger than")

	if _, err := ParseTLSRPT(oversized); err == nil {
		t.Fatal("an oversized TLS-RPT report was parsed")
	}
}

// tlsReport builds a TLS-RPT document from its parts, so a case can spoil one.
func tlsReport(policies string) string {
	return `{
      "organization-name": "Company-X",
      "report-id": "r1",
      "date-range": {"start-datetime": "2026-02-01T00:00:00Z", "end-datetime": "2026-02-01T23:59:59Z"},
      "policies": [` + policies + `]
    }`
}

// refusesTLS parses a TLS-RPT document and requires a refusal naming reason.
func refusesTLS(t *testing.T, body, reason string) {
	t.Helper()
	_, err := ParseTLSRPT([]byte(body))
	if err == nil {
		t.Fatal("the report was accepted")
	}
	if !strings.Contains(err.Error(), reason) {
		t.Errorf("error %q does not name %q", err, reason)
	}
}

func TestATLSReportRefusesEachSpoiledField(t *testing.T) {
	long := strings.Repeat("a", 300)
	const goodPolicy = `{"policy": {"policy-type": "sts"}, "summary": {}, "failure-details": []}`
	for _, tc := range []struct{ name, body, reason string }{
		{
			"an organization-name past the ceiling",
			strings.Replace(tlsReport(goodPolicy), `"Company-X"`, `"`+long+`"`, 1),
			"organization-name",
		},
		{
			"a report-id past the ceiling",
			strings.Replace(tlsReport(goodPolicy), `"r1"`, `"`+long+`"`, 1),
			"report-id",
		},
		{
			"no report-id at all",
			strings.Replace(tlsReport(goodPolicy), `"report-id": "r1"`, `"report-id": ""`, 1),
			"no organization-name or report-id",
		},
		{
			"a start that is not a timestamp",
			strings.Replace(tlsReport(goodPolicy), `"2026-02-01T00:00:00Z"`, `"yesterday"`, 1),
			"start-datetime",
		},
		{
			"an end that is not a timestamp",
			strings.Replace(tlsReport(goodPolicy), `"2026-02-01T23:59:59Z"`, `"tomorrow"`, 1),
			"end-datetime",
		},
		{
			"a backwards date range",
			strings.Replace(tlsReport(goodPolicy), `"start-datetime": "2026-02-01T00:00:00Z"`,
				`"start-datetime": "2026-02-02T00:00:00Z"`, 1),
			"range",
		},
		{
			"a policy-type past the ceiling",
			tlsReport(`{"policy": {"policy-type": "` + long + `"}, "summary": {}}`),
			"policy-type",
		},
		{
			"a session count past the ceiling",
			tlsReport(`{"policy": {"policy-type": "sts"},
			   "summary": {"total-successful-session-count": 9999999999999999}}`),
			"session count is larger than",
		},
		{
			"a failed-session-count past the ceiling",
			tlsReport(`{"policy": {"policy-type": "sts"}, "summary": {}, "failure-details":
			   [{"result-type": "x", "failed-session-count": 9999999999999999}]}`),
			"failed-session-count is larger than",
		},
		{
			"a result-type past the ceiling",
			tlsReport(`{"policy": {"policy-type": "sts"}, "summary": {}, "failure-details":
			   [{"result-type": "` + long + `", "failed-session-count": 1}]}`),
			"result-type",
		},
		{
			"a receiving-mx-hostname past the ceiling",
			tlsReport(`{"policy": {"policy-type": "sts"}, "summary": {}, "failure-details":
			   [{"result-type": "x", "receiving-mx-hostname": "` + long + `", "failed-session-count": 1}]}`),
			"receiving-mx-hostname",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixedNow(t)
			refusesTLS(t, tc.body, tc.reason)
		})
	}
}

// The failure entries are counted across every policy, so the ceiling cannot be
// stepped around by spreading them over several.
func TestATLSReportWithTooManyFailureEntriesIsRefused(t *testing.T) {
	fixedNow(t)
	var details strings.Builder
	for i := range MaxRecords + 1 {
		if i > 0 {
			details.WriteString(",")
		}
		details.WriteString(`{"result-type": "x", "failed-session-count": 1}`)
	}

	refusesTLS(t, tlsReport(`{"policy": {"policy-type": "sts"}, "summary": {}, "failure-details": [`+
		details.String()+`]}`), fmt.Sprintf("more than %d failure entries", MaxRecords))
}

// Several policies describe the same mail, so their summaries add up and their
// failure details concatenate.
func TestSeveralTLSPoliciesAreAddedTogether(t *testing.T) {
	fixedNow(t)
	body := tlsReport(`{"policy": {"policy-type": "sts"},
	    "summary": {"total-successful-session-count": 10, "total-failure-session-count": 1},
	    "failure-details": [{"result-type": "x", "failed-session-count": 1}]},
	   {"policy": {"policy-type": "tlsa"},
	    "summary": {"total-successful-session-count": 5, "total-failure-session-count": 2},
	    "failure-details": [{"result-type": "y", "failed-session-count": 2}]}`)

	report, err := ParseTLSRPT([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if report.SuccessCount != 15 || report.FailureCount != 3 {
		t.Errorf("counts = %d / %d, want 15 / 3", report.SuccessCount, report.FailureCount)
	}
	if len(report.Failures) != 2 {
		t.Errorf("failures = %d, want both policies' entries", len(report.Failures))
	}
	// The first policy names the type; a second one does not overwrite it.
	if report.PolicyType != "sts" {
		t.Errorf("policy type = %q, want the first policy's", report.PolicyType)
	}
}
