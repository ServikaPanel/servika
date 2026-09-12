package logsink

import (
	"strings"
	"testing"
)

// The one thing this package must never do. The login body is the case that
// made the rule: every sign-in would otherwise put a working credential into a
// table an operator reads casually and a backup copies off the server.
func TestALoginBodyKeepsNoPassword(t *testing.T) {
	body := []byte(`{"username":"root","password":"hunter2","totp":"123456"}`)

	stored, ok := RedactJSON(body)

	if !ok {
		t.Fatal("a well-formed login body was refused, so nothing is stored and nothing is proven")
	}
	if strings.Contains(stored, "hunter2") {
		t.Errorf("the password survived redaction: %s", stored)
	}
	if strings.Contains(stored, "123456") {
		t.Errorf("the 2FA code survived redaction: %s", stored)
	}
	if !strings.Contains(stored, "root") {
		t.Errorf("the username was redacted too, which leaves the row useless: %s", stored)
	}
	if !strings.Contains(stored, redactedValue) {
		t.Errorf("the redacted field was removed rather than marked: %s", stored)
	}
}

// A secret nested inside an object or an array is the same secret.
func TestANestedSecretIsRedactedToo(t *testing.T) {
	body := []byte(`{"servers":[{"host":"db1","db_password":"s3cret"}],` +
		`"remote":{"credentials":{"api_key":"AKIA123"}}}`)

	stored, ok := RedactJSON(body)

	if !ok {
		t.Fatal("the body was refused")
	}
	for _, secret := range []string{"s3cret", "AKIA123"} {
		if strings.Contains(stored, secret) {
			t.Errorf("%q survived redaction at depth: %s", secret, stored)
		}
	}
	if !strings.Contains(stored, "db1") {
		t.Errorf("a non-secret sibling was lost: %s", stored)
	}
}

// The key list matches on the normalized name, so one entry covers every
// spelling a caller uses.
func TestOneEntryCoversEverySpelling(t *testing.T) {
	for _, key := range []string{
		"password", "Password", "new_password", "current-password", "db_password",
		"token", "refreshToken", "API_KEY", "apiKey", "private_key",
		"Authorization", "cookie", "session_id", "totp", "credential", "SERVIKA_DB_DSN",
	} {
		if !IsSecretKey(key) {
			t.Errorf("%q is not treated as a secret", key)
		}
	}
	// Whole words, not substrings. A substring rule blanks these too, and a row
	// whose ordinary fields are redacted is a row nobody can read.
	for _, key := range []string{
		"username", "domain", "email", "id", "status",
		"keyboard_layout", "monkey", "passenger_count", "keystone",
	} {
		if IsSecretKey(key) {
			t.Errorf("%q is treated as a secret, so the row loses data it needs", key)
		}
	}
}

// A body whose shape is unknown is stored as nothing.
//
// Redaction works on field names. A document that does not parse has no field
// names to check, so storing it raw would store whatever secret it held.
func TestABodyThatDoesNotParseIsNotStored(t *testing.T) {
	for _, body := range [][]byte{
		[]byte(`this is not json, password=hunter2`),
		[]byte(`{"password":"hunter2"`),
		[]byte("\x00\x01binary"),
	} {
		if stored, ok := RedactJSON(body); ok {
			t.Errorf("%q was stored as %q", body, stored)
		}
	}
}

// An oversized body is stored as nothing rather than truncated, because a cut
// JSON document is not JSON and the column would refuse the whole batch.
func TestAnOversizedBodyIsNotStored(t *testing.T) {
	big := `{"note":"` + strings.Repeat("a", MaxBodyBytes) + `"}`
	if _, ok := RedactJSON([]byte(big)); ok {
		t.Error("a body past the ceiling was stored")
	}
	small := `{"note":"` + strings.Repeat("a", 100) + `"}`
	if _, ok := RedactJSON([]byte(small)); !ok {
		t.Error("a small body was refused")
	}
}

// A query string carries secrets as readily as a body: a signon token, a
// one-time code, an API key pasted into a URL.
func TestAQueryStringIsRedacted(t *testing.T) {
	stored, ok := RedactPairs(map[string][]string{
		"page":  {"2"},
		"token": {"abc123"},
	})

	if !ok {
		t.Fatal("the query string was refused")
	}
	if strings.Contains(stored, "abc123") {
		t.Errorf("the token survived redaction: %s", stored)
	}
	if !strings.Contains(stored, `"page":"2"`) {
		t.Errorf("a non-secret parameter was lost: %s", stored)
	}
}

// An empty query string is stored as NULL, not as an empty object.
func TestNothingIsStoredForAnEmptyQueryString(t *testing.T) {
	if _, ok := RedactPairs(nil); ok {
		t.Error("an empty query string produced a value to store")
	}
}
