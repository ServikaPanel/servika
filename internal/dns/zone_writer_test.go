package dns

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestValidRecordFieldsRejectsZoneDirectiveInjection(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "record name newline", value: "www\n$INCLUDE /etc/passwd"},
		{name: "record value newline", value: "192.0.2.1\nmalicious"},
		{name: "record value NUL", value: "192.0.2.1\x00malicious"},
		{name: "BIND name directive", value: "$INCLUDE"},
		{name: "BIND value directive", value: "$INCLUDE /etc/passwd"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name, value := "www", "192.0.2.1"
			if test.name == "record name newline" || test.name == "BIND name directive" {
				name = test.value
			} else {
				value = test.value
			}
			if validRecordFields(name, value) {
				t.Fatalf("validRecordFields(%q, %q) = true, want false", name, value)
			}
		})
	}
}

func TestNormalizePriorityPreventsInvalidRecordSyntax(t *testing.T) {
	tests := []struct {
		name       string
		recordType string
		priority   int
		want       int
	}{
		{name: "A priority is removed", recordType: "A", priority: 10, want: 0},
		{name: "MX priority is preserved", recordType: "MX", priority: 10, want: 10},
		{name: "SRV priority is preserved", recordType: "SRV", priority: 20, want: 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizePriority(tt.recordType, tt.priority); got != tt.want {
				t.Fatalf("normalizePriority(%q, %d) = %d, want %d", tt.recordType, tt.priority, got, tt.want)
			}
		})
	}
}

func TestSOAValuesRenderAsAbsoluteDNSNames(t *testing.T) {
	ctx := zoneCtx{
		DomainName: "example.com",
		Serial:     "2026071801",
		SOA: SOA{
			PrimaryNS:  "ns2.example.net",
			Hostmaster: "dns@example.net",
			Refresh:    7200,
			Retry:      1200,
			Expire:     604800,
			Minimum:    300,
			TTL:        1800,
		},
	}
	var output bytes.Buffer
	if err := zoneTmpl.Execute(&output, ctx); err != nil {
		t.Fatalf("execute zone template: %v", err)
	}
	zone := output.String()
	for _, expected := range []string{"$TTL 1800", "SOA ns2.example.net. dns.example.net.", "7200  ; refresh", "1200  ; retry", "604800  ; expire", "300  ; minimum"} {
		if !strings.Contains(zone, expected) {
			t.Fatalf("zone does not contain %q:\n%s", expected, zone)
		}
	}
}

func TestTXTRecordsAreQuotedAndChunkedForBind(t *testing.T) {
	value := strings.Repeat("a", 260)
	quoted := txtQuote(value)
	if strings.Count(quoted, `"`) != 4 {
		t.Fatalf("txtQuote() did not produce two quoted segments: %s", quoted)
	}
	if !strings.Contains(quoted, `" "`) {
		t.Fatalf("txtQuote() did not split a value longer than 255 octets: %s", quoted)
	}
}

func TestTXTRecordsEscapeZoneControlCharacters(t *testing.T) {
	quoted := txtQuote("safe\nnext\\value\"")
	for _, unsafe := range []string{"\n", `next\value`, `value""`} {
		if strings.Contains(quoted, unsafe) {
			t.Fatalf("txtQuote() retained unsafe sequence %q: %s", unsafe, quoted)
		}
	}
}

func TestNextSerialAtAdvancesWithinTheSameDay(t *testing.T) {
	now := time.Date(2026, time.July, 19, 12, 0, 0, 0, time.UTC)
	if got := nextSerialAt(2026071907, now); got != 2026071908 {
		t.Fatalf("nextSerialAt() = %d, want 2026071908", got)
	}
	if got := nextSerialAt(2026071809, now); got != 2026071900 {
		t.Fatalf("nextSerialAt() = %d, want 2026071900", got)
	}
}

func TestZoneIncludeStatementAlwaysBlocksTransfers(t *testing.T) {
	unsigned := zoneIncludeStatement("example.com", false)
	if !strings.Contains(unsigned, "allow-transfer { none; };") {
		t.Fatalf("unsigned zone permits transfers: %s", unsigned)
	}
	if strings.Contains(unsigned, "dnssec-policy") {
		t.Fatalf("unsigned zone enables DNSSEC: %s", unsigned)
	}

	signed := zoneIncludeStatement("example.com", true)
	for _, expected := range []string{"allow-transfer { none; };", "dnssec-policy default;", `key-directory "/var/named/dynamic";`, "inline-signing yes;"} {
		if !strings.Contains(signed, expected) {
			t.Fatalf("signed zone does not contain %q: %s", expected, signed)
		}
	}
}

func TestZoneTemplateWritesPriorityOnlyForSupportedTypes(t *testing.T) {
	ctx := zoneCtx{
		DomainName: "example.com",
		Serial:     "2026071801",
		SOA:        defaultSOA("example.com", ""),
		Records: []Record{
			{Name: "@", Type: "A", Value: "192.0.2.10", TTL: 3600, Priority: 10},
			{Name: "@", Type: "MX", Value: "mail.example.com", TTL: 3600, Priority: 10},
			{Name: "_sip._tcp", Type: "SRV", Value: "5 5060 sip.example.com", TTL: 3600, Priority: 0},
		},
	}

	var output bytes.Buffer
	if err := zoneTmpl.Execute(&output, ctx); err != nil {
		t.Fatalf("execute zone template: %v", err)
	}
	zone := output.String()
	if strings.Contains(zone, "IN\tA\t10 192.0.2.10") {
		t.Fatalf("A record contains unsupported priority:\n%s", zone)
	}
	if !strings.Contains(zone, "IN\tMX\t10 mail.example.com.") {
		t.Fatalf("MX record does not contain its priority:\n%s", zone)
	}
	if !strings.Contains(zone, "IN\tSRV\t0 5 5060 sip.example.com.") {
		t.Fatalf("SRV record does not contain its zero priority:\n%s", zone)
	}
}

// Both the write and the delete path build a file name under ZoneDir from a
// value read back out of a row, so each asks zoneLeafName first. The gate is
// checked in both directions: an ordinary domain passes, and every shape that
// would place the path outside ZoneDir is refused.
func TestZoneLeafNameGuardsBothZonePaths(t *testing.T) {
	for _, name := range []string{"example.com", "sub.example.com", "xn--pta-6la.com"} {
		if !zoneLeafName(name) {
			t.Errorf("zoneLeafName(%q) refused an ordinary domain", name)
		}
	}
	for _, name := range []string{
		"", "..", "../../etc/named.conf", "/etc/named",
		`sub\..\..\evil`, "example.com/../../../var/named/other.com",
	} {
		if zoneLeafName(name) {
			t.Errorf("zoneLeafName(%q) was accepted", name)
		}
	}
}

// DeleteZone removes a file, so its gate is the one that decides whether an
// arbitrary path ending in ".zone" can be deleted from a tampered row.
func TestDeleteZoneRefusesANameThatIsNotALeaf(t *testing.T) {
	for _, name := range []string{"../../etc/named.conf", "..", "/etc/named", ""} {
		if err := DeleteZone(t.Context(), nil, name); err == nil {
			t.Errorf("DeleteZone(%q) was accepted", name)
		}
	}
}
