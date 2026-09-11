package dns

import (
	"reflect"
	"testing"
)

// parseBindZone keeps the records it understands and drops the rest of a line
// it cannot use. Every case here is a line shape the importer meets in a real
// zone file, and none of them may take a neighbouring record down with it.
func TestParseBindZoneSkipsWhatItCannotUse(t *testing.T) {
	cases := []struct {
		name string
		zone string
		want []Record
	}{
		{name: "an origin without a trailing dot",
			zone: "$ORIGIN example.com\nwww.example.com.\tIN\tA\t192.0.2.10\n",
			want: []Record{{Name: "www", Type: "A", Value: "192.0.2.10", TTL: 3600}}},
		{name: "a line that repeats the previous name",
			zone: "www\tIN\tA\t192.0.2.10\n\tIN\tTXT\t\"second\"\n",
			want: []Record{
				{Name: "www", Type: "A", Value: "192.0.2.10", TTL: 3600},
				{Name: "www", Type: "TXT", Value: "second", TTL: 3600},
			}},
		{name: "a line carrying a name and nothing else", zone: "www\n"},
		{name: "a line carrying only a TTL and a class", zone: "@\t3600\tIN\n"},
		{name: "a type the panel does not store", zone: "@\tIN\tFOO\t192.0.2.10\n"},
		{name: "a type with no rdata", zone: "@\tIN\tA\n"},
		{name: "an empty value", zone: "@\tIN\tTXT\t\"\"\n"},
		{name: "an MX with the host alone",
			zone: "@\tIN\tMX\tmail.example.com.\n",
			want: []Record{{Name: "@", Type: "MX", Value: "mail.example.com", TTL: 3600}}},
		{name: "an SRV missing a field",
			zone: "_sip._tcp\tIN\tSRV\t10 5060 sip.example.com.\n",
			want: []Record{{Name: "_sip._tcp", Type: "SRV", Value: "10 5060 sip.example.com.", TTL: 3600}}},
		{name: "a $TTL the records inherit",
			zone: "$TTL 60\n@\tIN\tA\t192.0.2.10\n",
			want: []Record{{Name: "@", Type: "A", Value: "192.0.2.10", TTL: 60}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			records, soa := parseBindZone(tc.zone, "example.com")
			if soa != nil {
				t.Errorf("soa = %+v, want none", soa)
			}
			if !reflect.DeepEqual(records, tc.want) {
				t.Errorf("records = %+v, want %+v", records, tc.want)
			}
		})
	}
}
