package waf

import (
	"os"
	"strings"
	"testing"
)

func TestMapWAFMode(t *testing.T) {
	tests := []struct {
		name        string
		mode        string
		wantEnabled any
		wantMode    any
		wantOK      bool
	}{
		{name: "inherit", mode: "inherit", wantEnabled: nil, wantMode: nil, wantOK: true},
		{name: "empty inherits", mode: "", wantEnabled: nil, wantMode: nil, wantOK: true},
		{name: "whitespace inherits", mode: "  ", wantEnabled: nil, wantMode: nil, wantOK: true},
		{name: "off", mode: "off", wantEnabled: 0, wantMode: "off", wantOK: true},
		{name: "block maps to on", mode: "block", wantEnabled: 1, wantMode: "on", wantOK: true},
		{name: "detect", mode: "detect", wantEnabled: 1, wantMode: "detect", wantOK: true},
		{name: "uppercase normalized", mode: "BLOCK", wantEnabled: 1, wantMode: "on", wantOK: true},
		{name: "invalid rejected", mode: "on", wantEnabled: nil, wantMode: nil, wantOK: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			en, mode, ok := mapWAFMode(test.mode)
			if ok != test.wantOK || en != test.wantEnabled || mode != test.wantMode {
				t.Fatalf("mapWAFMode(%q) = (%v, %v, %t), want (%v, %v, %t)",
					test.mode, en, mode, ok, test.wantEnabled, test.wantMode, test.wantOK)
			}
		})
	}
}

func TestMapWAFParanoia(t *testing.T) {
	tests := []struct {
		in   int
		want any
	}{
		{in: 0, want: nil},
		{in: 1, want: 1},
		{in: 4, want: 4},
		{in: 5, want: nil},
		{in: -1, want: nil},
	}
	for _, test := range tests {
		if got := mapWAFParanoia(test.in); got != test.want {
			t.Fatalf("mapWAFParanoia(%d) = %v, want %v", test.in, got, test.want)
		}
	}
}

// libmodsecurity is compiled into libmodsecurity.so.3 and loaded into EVERY
// nginx worker, so a crash in it takes every site on the server down rather than
// the one domain whose request triggered it, and a parser bypass in it defeats
// the protection the panel sells per domain.
//
// The floor is 3.0.16, which is where CVE-2026-52747 is fixed: the multipart
// parser silently stripped embedded line breaks from form-field values and so
// walked past request-body inspection entirely, which is the request shape a
// webshell upload uses. 3.0.15 carries the two crash fixes below it.
//
// This asserts the exact pin rather than a range, so a bump has to state which
// release it moves to and why; there is no CI gate that re-checks these against
// an advisory feed.
func TestTheWAFPinsAreNotBelowTheirSecurityFloor(t *testing.T) {
	body, err := os.ReadFile("../../assets/ops/servika-waf-setup")
	if err != nil {
		t.Fatalf("read the WAF setup script: %v", err)
	}
	for _, pin := range []string{"MODSEC_VER=v3.0.16", "CONNECTOR_VER=v1.0.4"} {
		if !strings.Contains(string(body), "\n"+pin+"\n") {
			t.Errorf("%s is not the pinned version", pin)
		}
	}
}
