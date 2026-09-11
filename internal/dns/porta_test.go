package dns

import "testing"

func TestParseBindZoneBasics(t *testing.T) {
	zone := `$ORIGIN example.com.
$TTL 3600
@	IN	SOA	ns1.example.com. admin.example.com. (
			2026010101 ; serial
			3600 ; refresh
			900 ; retry
			1209600 ; expire
			3600 ; minimum
			)
@	3600	IN	A	192.0.2.10
www	IN	CNAME	example.com.
@	IN	MX	0 mail.example.com.
@	IN	TXT	"v=spf1 -all" ; comment
_sip._tcp	IN	SRV	10 5 5060 sip.example.com.
`
	records, soa := parseBindZone(zone, "example.com")
	if soa == nil {
		t.Fatal("SOA was not parsed")
	}
	if soa.Hostmaster != "admin@example.com" {
		t.Fatalf("hostmaster = %q, want admin@example.com", soa.Hostmaster)
	}
	byKey := map[string]Record{}
	for _, r := range records {
		byKey[r.Type+"|"+r.Name] = r
	}
	for _, want := range []struct {
		key      string
		value    string
		priority int
	}{
		{key: "MX|@", value: "mail.example.com"},
		{key: "TXT|@", value: "v=spf1 -all"},
		{key: "SRV|_sip._tcp", value: "5 5060 sip.example.com", priority: 10},
		{key: "CNAME|www", value: "example.com"},
	} {
		record, ok := byKey[want.key]
		if !ok || record.Value != want.value || record.Priority != want.priority {
			t.Errorf("%s parsed as %+v, want value %q and priority %d", want.key, record, want.value, want.priority)
		}
	}
}

func TestRenderBindZoneRoundTrip(t *testing.T) {
	soa := defaultSOA("example.com", "")
	in := []Record{
		{Name: "@", Type: "A", Value: "192.0.2.10", TTL: 3600},
		{Name: "@", Type: "MX", Value: "mail.example.com", TTL: 3600, Priority: 0},
		{Name: "www", Type: "CNAME", Value: "example.com", TTL: 3600},
	}
	zone := renderBindZone("example.com", soa, in)
	out, _ := parseBindZone(zone, "example.com")
	if len(out) != len(in) {
		t.Fatalf("round-trip changed record count: got %d, want %d\n%s", len(out), len(in), zone)
	}
}
