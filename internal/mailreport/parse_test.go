package mailreport

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fixedNow pins the clock so a report's date range is judged against a known
// point rather than the machine's own time.
func fixedNow(t *testing.T) {
	t.Helper()
	previous := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { nowFunc = previous })
}

// aggregateXML builds a report whose fields the caller can spoil one at a time.
func aggregateXML(sourceIP, count, orgName string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>%s</org_name>
    <report_id>1234567890</report_id>
    <date_range><begin>1770000000</begin><end>1770086400</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><adkim>r</adkim><aspf>r</aspf><p>quarantine</p></policy_published>
  <record>
    <row>
      <source_ip>%s</source_ip>
      <count>%s</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
  </record>
</feedback>`, orgName, sourceIP, count)
}

func TestAggregateReportIsRead(t *testing.T) {
	fixedNow(t)
	report, err := ParseAggregate([]byte(aggregateXML("192.0.2.1", "7", "google.com")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if report.OrgName != "google.com" || report.ReportID != "1234567890" {
		t.Errorf("metadata = %q / %q", report.OrgName, report.ReportID)
	}
	if len(report.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(report.Rows))
	}
	row := report.Rows[0]
	if row.SourceIP != "192.0.2.1" || row.MessageCount != 7 || row.SPFResult != "pass" {
		t.Errorf("row = %+v", row)
	}
}

// The stored address is the parsed form, so two spellings of one address group
// as a single source on the dashboard instead of two.
func TestASourceAddressIsStoredInItsCanonicalForm(t *testing.T) {
	fixedNow(t)
	report, err := ParseAggregate([]byte(aggregateXML("2001:0db8:0000:0000:0000:0000:0000:0001", "1", "google.com")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := report.Rows[0].SourceIP; got != "2001:db8::1" {
		t.Errorf("source_ip = %q, want the canonical form", got)
	}
}

// A report is atomic. One unusable row rejects the document rather than being
// dropped, because a silently shorter report under-counts on a screen whose
// whole purpose is the count.
func TestAnUnusableRowRejectsTheWholeReport(t *testing.T) {
	fixedNow(t)
	for _, spoiled := range []struct {
		name       string
		sourceIP   string
		count      string
		wantReason string
	}{
		{"not an address", "not-an-ip", "1", "source_ip"},
		{"empty address", "", "1", "source_ip"},
		{"count is not a number", "192.0.2.1", "many", "count"},
		{"count past the ceiling", "192.0.2.1", "99999999999999999", "count"},
	} {
		t.Run(spoiled.name, func(t *testing.T) {
			_, err := ParseAggregate([]byte(aggregateXML(spoiled.sourceIP, spoiled.count, "google.com")))
			if err == nil {
				t.Fatal("the report was accepted")
			}
			if !strings.Contains(err.Error(), spoiled.wantReason) {
				t.Errorf("error %q does not name %q", err, spoiled.wantReason)
			}
		})
	}
}

// org_name is two thirds of the deduplication key, so an oversized one is
// refused rather than truncated: shortening it would let one report be stored
// twice under two different keys.
func TestAnOversizedOrgNameIsRefusedNotTruncated(t *testing.T) {
	fixedNow(t)
	_, err := ParseAggregate([]byte(aggregateXML("192.0.2.1", "1", strings.Repeat("a", maxOrgName+1))))
	if err == nil {
		t.Fatal("an oversized org_name was accepted")
	}
	if !strings.Contains(err.Error(), "org_name") {
		t.Errorf("error %q does not name org_name", err)
	}
}

// These values are logged, so a newline in one forges a log line.
func TestAControlCharacterInAFieldIsRefused(t *testing.T) {
	fixedNow(t)
	_, err := ParseAggregate([]byte(aggregateXML("192.0.2.1", "1", "evil\nMar  1 00:00:00 servika: forged")))
	if err == nil {
		t.Fatal("a field holding a newline was accepted")
	}
}

// A date range outside the window any real report describes would sit outside
// every query the dashboard makes while still looking like data.
func TestAnImpossibleDateRangeIsRefused(t *testing.T) {
	fixedNow(t)
	document := strings.Replace(aggregateXML("192.0.2.1", "1", "google.com"),
		"<begin>1770000000</begin><end>1770086400</end>",
		"<begin>1770086400</begin><end>1770000000</end>", 1)
	if _, err := ParseAggregate([]byte(document)); err == nil {
		t.Error("a backwards date range was accepted")
	}

	future := strings.Replace(aggregateXML("192.0.2.1", "1", "google.com"),
		"<end>1770086400</end>", "<end>253402300799</end>", 1)
	if _, err := ParseAggregate([]byte(future)); err == nil {
		t.Error("a date range ending in the year 9999 was accepted")
	}
}

// A postmaster mailbox is full of ordinary mail, so "this is not a report" has
// to be distinguishable from "this report is broken".
func TestOrdinaryMailIsNotAReport(t *testing.T) {
	fixedNow(t)
	for _, body := range []string{"", "Hello, is this working?", "<html><body>hi</body></html>"} {
		if _, err := ParseAggregate([]byte(body)); !errors.Is(err, ErrNotAReport) {
			t.Errorf("ParseAggregate(%q) = %v, want ErrNotAReport", body, err)
		}
	}
}

func TestTLSRPTReportIsRead(t *testing.T) {
	fixedNow(t)
	body := `{
      "organization-name": "Company-X",
      "report-id": "2026-02-01T00:00:00Z_example.com",
      "date-range": {"start-datetime": "2026-02-01T00:00:00Z", "end-datetime": "2026-02-01T23:59:59Z"},
      "policies": [{
        "policy": {"policy-type": "sts"},
        "summary": {"total-successful-session-count": 5326, "total-failure-session-count": 303},
        "failure-details": [{
          "result-type": "certificate-expired",
          "sending-mta-ip": "2001:0db8::1",
          "receiving-mx-hostname": "mail.example.com",
          "failed-session-count": 100
        }]
      }]
    }`
	report, err := ParseTLSRPT([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if report.SuccessCount != 5326 || report.FailureCount != 303 || report.PolicyType != "sts" {
		t.Errorf("summary = %+v", report)
	}
	if len(report.Failures) != 1 || report.Failures[0].SendingMTAIP != "2001:db8::1" {
		t.Errorf("failures = %+v", report.Failures)
	}
}

func TestATLSRPTFailureWithABadAddressIsRefused(t *testing.T) {
	fixedNow(t)
	body := `{
      "organization-name": "Company-X",
      "report-id": "r1",
      "date-range": {"start-datetime": "2026-02-01T00:00:00Z", "end-datetime": "2026-02-01T23:59:59Z"},
      "policies": [{"policy": {"policy-type": "sts"}, "summary": {},
        "failure-details": [{"result-type": "x", "sending-mta-ip": "999.999.999.999", "failed-session-count": 1}]}]
    }`
	if _, err := ParseTLSRPT([]byte(body)); err == nil {
		t.Fatal("a failure entry with a bad address was accepted")
	}
}

func TestOrdinaryJSONIsNotATLSReport(t *testing.T) {
	fixedNow(t)
	for _, body := range []string{`{"hello":"world"}`, `not json at all`} {
		if _, err := ParseTLSRPT([]byte(body)); !errors.Is(err, ErrNotAReport) {
			t.Errorf("ParseTLSRPT(%q) = %v, want ErrNotAReport", body, err)
		}
	}
}

// A compression bomb is small on disk by definition, so the compressed ceiling
// cannot catch it; only the expanded one can.
func TestAGzipBombIsRefused(t *testing.T) {
	var packed bytes.Buffer
	writer := gzip.NewWriter(&packed)
	if _, err := writer.Write(bytes.Repeat([]byte("A"), MaxUnpackedBytes+1024)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if packed.Len() > MaxCompressedBytes {
		t.Fatalf("the fixture is %d bytes compressed, which the compressed ceiling would catch instead", packed.Len())
	}
	if _, err := Unpack(bytes.NewReader(packed.Bytes())); err == nil {
		t.Fatal("a gzip bomb was unpacked")
	}
}

func TestAZipWithTooManyEntriesIsRefused(t *testing.T) {
	var packed bytes.Buffer
	archive := zip.NewWriter(&packed)
	for i := 0; i <= MaxArchiveEntries; i++ {
		file, err := archive.Create(fmt.Sprintf("report-%d.xml", i))
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, err := file.Write([]byte("<feedback/>")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := Unpack(bytes.NewReader(packed.Bytes())); err == nil {
		t.Fatal("an archive with too many entries was unpacked")
	}
}

// The format is decided by magic bytes, so an attachment named .xml that is
// really a zip still goes through the zip path, and a bomb named .xml is still
// caught.
func TestTheFormatComesFromTheBytesNotTheName(t *testing.T) {
	fixedNow(t)
	var packed bytes.Buffer
	archive := zip.NewWriter(&packed)
	file, err := archive.Create("anything")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := file.Write([]byte(aggregateXML("192.0.2.1", "3", "google.com"))); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := archive.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	body, err := Unpack(bytes.NewReader(packed.Bytes()))
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	report, err := ParseAggregate(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if report.Rows[0].MessageCount != 3 {
		t.Errorf("count = %d, want 3", report.Rows[0].MessageCount)
	}
}

func TestAnOversizedAttachmentIsRefusedBeforeItIsRead(t *testing.T) {
	oversized := bytes.Repeat([]byte("A"), MaxCompressedBytes+1)
	if _, err := Unpack(bytes.NewReader(oversized)); err == nil {
		t.Fatal("an oversized attachment was accepted")
	}
}
