package autoconfig

import (
	"encoding/xml"
	"fmt"
	"strings"
	"testing"
)

// The address is the only client-controlled value that reaches the response, so
// it has to be a plain mailbox before it goes anywhere near the XML encoder.
func TestRequestedAddressAcceptsABareMailbox(t *testing.T) {
	body := autodiscoverPost("user@example.com")
	got, err := requestedAddress(body)
	if err != nil {
		t.Fatalf("requestedAddress: %v", err)
	}
	if got != "user@example.com" {
		t.Errorf("requestedAddress = %q, want user@example.com", got)
	}
}

// A body carrying markup, a display name, or nothing at all must be refused
// rather than escaped and echoed: the endpoint has no reason to accept it, and
// refusing keeps the response shape fixed.
func TestRequestedAddressRejectsAnythingElse(t *testing.T) {
	cases := map[string][]byte{
		"markup in the address":   autodiscoverPost("user@example.com</EMailAddress><x>"),
		"display name form":       autodiscoverPost("Someone <user@example.com>"),
		"empty address":           autodiscoverPost(""),
		"no domain part":          autodiscoverPost("user"),
		"not autodiscover at all": []byte(`<?xml version="1.0"?><Autodiscover xmlns="http://example.com/other"><Request><EMailAddress>user@example.com</EMailAddress></Request></Autodiscover>`),
		"not xml":                 []byte("user@example.com"),
	}
	for name, body := range cases {
		if got, err := requestedAddress(body); err == nil {
			t.Errorf("%s: requestedAddress accepted it and returned %q", name, got)
		}
	}
}

// Whatever survives validation still has to be encoded, never concatenated. This
// proves the encoder is what produces the element, so a value that somehow got
// through could not close it early.
func TestOutlookResponseEscapesTheAddress(t *testing.T) {
	response := autodiscoverResponse{
		XMLName: xml.Name{Local: "Autodiscover"},
		Xmlns:   autodiscoverResponseNS,
		Response: autodiscoverBody{
			Xmlns: autodiscoverPayloadNS,
			Account: autodiscoverAccount{
				AccountType: "email", Action: "settings",
				Protocols: []autodiscoverProtocol{{
					Type: "IMAP", Server: "mail.example.com", Port: imapPort,
					LoginName: `a"<&>b@example.com`,
				}},
			},
		},
	}
	out, err := xml.Marshal(response)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(out)
	if strings.Contains(body, "<LoginName>a\"<&>b@example.com</LoginName>") {
		t.Error("the address was written into the document unescaped")
	}
	if !strings.Contains(body, "&lt;") || !strings.Contains(body, "&amp;") {
		t.Errorf("the address was not escaped: %s", body)
	}
}

// Outlook checks the namespaces, and the envelope and the payload use different
// ones. Collapsing them into one produces a document Outlook discards without a
// visible error.
func TestOutlookResponseUsesBothNamespaces(t *testing.T) {
	if autodiscoverResponseNS == autodiscoverPayloadNS {
		t.Fatal("the envelope and payload namespaces must differ")
	}
	response := autodiscoverResponse{
		XMLName:  xml.Name{Local: "Autodiscover"},
		Xmlns:    autodiscoverResponseNS,
		Response: autodiscoverBody{Xmlns: autodiscoverPayloadNS},
	}
	out, err := xml.Marshal(response)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{autodiscoverResponseNS, autodiscoverPayloadNS} {
		if !strings.Contains(string(out), want) {
			t.Errorf("the response does not declare %s", want)
		}
	}
}

// The ports are the contract with the client. These are what the Dovecot drop-in
// and the Postfix submission service actually run, and the firewall opens; any
// other value configures an account that cannot connect.
func TestAnnouncedPortsMatchTheRunningServices(t *testing.T) {
	if imapPort != 143 {
		t.Errorf("IMAP announced on %d, but Dovecot serves 143 (993 is not opened in the firewall)", imapPort)
	}
	if submissionPort != 587 {
		t.Errorf("submission announced on %d, but Postfix serves 587", submissionPort)
	}
}

// Dovecot's userdb matches the full address, so a client told to log in with the
// local part alone fails authentication on the first connection.
func TestThunderbirdUsernameIsTheFullAddress(t *testing.T) {
	if usernameIsFullAddress != "%EMAILADDRESS%" {
		t.Errorf("username placeholder = %q, want %%EMAILADDRESS%%", usernameIsFullAddress)
	}
}

// The vhost is matched by Host header, and a request may arrive with a port, a
// trailing dot, mixed case, or the www label. All of them name the same site.
func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"Example.COM":     "example.com",
		"example.com:443": "example.com",
		"www.example.com": "example.com",
		"example.com.":    "example.com",
		"":                "",
		// Everything below is rejected outright rather than cleaned up: the value
		// reaches a query, a log line and the response body.
		"example.com/evil":    "",
		"example.com\r\nX: 1": "",
		"exam ple.com":        "",
		"localhost":           "",
		"exa<mple.com":        "",
		// A label longer than DNS allows. The value reaches a query and the
		// response body, so it is refused rather than truncated.
		strings.Repeat("a", 64) + ".example.com": "",
	}
	for input, want := range cases {
		if got := normalizeHost(input); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", input, got, want)
		}
	}
}

func autodiscoverPost(address string) []byte {
	var buf strings.Builder
	buf.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	buf.WriteString(`<Autodiscover xmlns="` + autodiscoverRequestNS + `"><Request>`)
	buf.WriteString(`<AcceptableResponseSchema>` + autodiscoverPayloadNS + `</AcceptableResponseSchema>`)
	fmt.Fprintf(&buf, `<EMailAddress>%s</EMailAddress>`, address)
	buf.WriteString(`</Request></Autodiscover>`)
	return []byte(buf.String())
}
