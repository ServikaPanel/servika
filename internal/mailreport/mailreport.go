// Package mailreport parses the deliverability reports other mail providers
// send about a hosted domain: DMARC aggregate reports (RFC 7489) and TLS-RPT
// reports (RFC 8460).
//
// Everything this package reads is UNTRUSTED. A report arrives as an email
// attachment from whoever chose to send one, so the archive, the XML and every
// field inside are hostile input until proven otherwise. The limits below are
// the boundary, and they are enforced before any value reaches the database.
//
// Parsing lives apart from internal/mail because it needs no mail stack: a
// report is bytes in and records out, which is what makes it testable.
package mailreport

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Limits on what a single report may contain.
//
// A DMARC report from a large provider is a few hundred kilobytes compressed
// and a few megabytes expanded, so these ceilings leave real reports far below
// them while a compression bomb hits one long before it costs anything.
const (
	// MaxCompressedBytes bounds the attachment as it arrives.
	MaxCompressedBytes = 4 << 20
	// MaxUnpackedBytes bounds what an archive is allowed to expand into. This
	// is the one that matters: a zip bomb is small on disk by definition.
	MaxUnpackedBytes = 32 << 20
	// MaxArchiveEntries bounds how many members an archive may hold. A report
	// archive carries exactly one document; anything else is not a report.
	MaxArchiveEntries = 4
	// MaxRecords bounds the rows in one report, so a hostile document cannot
	// turn one message into a million inserts.
	MaxRecords = 20000
	// MaxMessageCount bounds a single row's message tally. The dashboard sums
	// these, and a value near the integer ceiling would make every total
	// meaningless.
	MaxMessageCount = 1 << 40
)

// Field length ceilings, matched to the columns in migrations/0085_mail_reports.sql.
//
// A value over the ceiling is REJECTED rather than truncated: org_name and
// report_id are two thirds of the deduplication key, so shortening one would
// let the same report be stored twice under two different keys.
const (
	maxOrgName     = 255
	maxReportID    = 255
	maxHeaderFrom  = 255
	maxShortResult = 16
	maxResultType  = 64
	maxHostname    = 253
)

// ErrNotAReport is returned when the bytes are well formed but are not a report
// this package understands. The collector treats it as "skip this attachment",
// not as a failure: a postmaster mailbox is full of ordinary mail.
var ErrNotAReport = errors.New("not a deliverability report")

// Report is one DMARC aggregate report.
type Report struct {
	OrgName     string
	ReportID    string
	DateBegin   time.Time
	DateEnd     time.Time
	PolicyP     string
	PolicyADKIM string
	PolicyASPF  string
	Rows        []Row
}

// Row is one source address inside an aggregate report.
type Row struct {
	SourceIP     string
	MessageCount uint64
	Disposition  string
	DKIMResult   string
	SPFResult    string
	HeaderFrom   string
}

// TLSReport is one TLS-RPT report.
type TLSReport struct {
	OrgName      string
	ReportID     string
	DateBegin    time.Time
	DateEnd      time.Time
	PolicyType   string
	SuccessCount uint64
	FailureCount uint64
	Failures     []TLSFailure
}

// TLSFailure is one failure bucket inside a TLS-RPT report.
type TLSFailure struct {
	ResultType   string
	SendingMTAIP string
	ReceivingMX  string
	SessionCount uint64
}

// earliestReportDate and futureSlack bound the window a report may claim.
//
// A document is free to say its range began in the year 1000 or ends in 9999,
// and either would sit outside every date query the dashboard makes while
// looking like data. The future slack is generous because the reporter's clock
// is not ours.
var (
	earliestReportDate = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	futureSlack        = 48 * time.Hour
)

// nowFunc is the clock. It is a variable so a test can place a report's date
// range relative to a fixed point instead of the machine's own time.
var nowFunc = time.Now

// checkedField trims a value, refuses control characters and enforces a ceiling.
//
// Control characters are refused rather than stripped because these values are
// logged: a CR or LF in org_name forges a log line (G706), and the value is
// data, so there is no reading of it in which a newline was meant.
func checkedField(name, value string, limit int) (string, error) {
	value = strings.TrimSpace(value)
	if strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", fmt.Errorf("%s holds a control character", name)
	}
	if len(value) > limit {
		return "", fmt.Errorf("%s is longer than %d bytes", name, limit)
	}
	return value, nil
}

// checkedIP requires a value to be an address.
//
// The stored form is the PARSED address rather than the reporter's spelling, so
// "192.000.002.001" and "192.0.2.1" group as one source on the dashboard
// instead of two.
func checkedIP(name, value string) (string, error) {
	address := net.ParseIP(strings.TrimSpace(value))
	if address == nil {
		return "", fmt.Errorf("%s is not an IP address", name)
	}
	return address.String(), nil
}

// checkedRange refuses a date range that is backwards or outside the window any
// real report can describe.
func checkedRange(begin, end time.Time) error {
	if begin.IsZero() || end.IsZero() {
		return errors.New("the report has no date range")
	}
	if end.Before(begin) {
		return errors.New("the report's date range ends before it begins")
	}
	if begin.Before(earliestReportDate) {
		return errors.New("the report's date range begins before mail reporting existed")
	}
	if end.After(nowFunc().Add(futureSlack)) {
		return errors.New("the report's date range ends in the future")
	}
	return nil
}
