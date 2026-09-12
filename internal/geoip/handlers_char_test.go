package geoip

import (
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"servika/internal/secret"
)

// The license key is a stored secret, so SaveCredentials seals it and never
// hands it back. These cases pin the refusals and what actually reaches the
// UPDATE.

// sealing prepares the encryption the handler uses. Without it Encrypt fails,
// which is the failure the last case below exercises.
func sealing(t *testing.T) {
	t.Helper()
	if err := secret.Init([]byte("a-test-key-of-at-least-32-characters")); err != nil {
		t.Fatalf("secret.Init: %v", err)
	}
}

// saveRequest posts one credentials body.
func saveRequest(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/system/geoip/credentials", strings.NewReader(body))
}

// save runs the handler and returns the status and what it wrote.
func save(t *testing.T, script *sqlScript, body string) (int, map[string]any) {
	t.Helper()
	handlers := &Handlers{DB: scriptDB(t, script)}
	recorder := httptest.NewRecorder()
	handlers.SaveCredentials(recorder, saveRequest(body))

	var decoded map[string]any
	if raw := recorder.Body.Bytes(); len(raw) > 0 {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("the response is not JSON: %v (%s)", err, raw)
		}
	}
	return recorder.Code, decoded
}

func TestTheLicenseKeyIsStoredSealed(t *testing.T) {
	sealing(t)
	script := newScript()

	status, body := save(t, script, `{"account_id":"12345","license_key":"a-real-key"}`)
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("status = %d, body = %v, want 200 and ok", status, body)
	}
	if len(script.execs) != 1 {
		t.Fatalf("statements = %d, want 1", len(script.execs))
	}
	args := script.execs[0].args
	if len(args) != 2 || args[0] != "12345" {
		t.Fatalf("arguments = %v, want the account id and the sealed key", args)
	}
	sealed, _ := args[1].(string)
	if sealed == "a-real-key" {
		t.Fatal("the license key was stored in the clear")
	}
	if !secret.IsEncrypted(sealed) {
		t.Errorf("stored value = %q, want it sealed", sealed)
	}
	// The clearing statement writes NULL; this one must not.
	if strings.Contains(script.execs[0].query, "maxmind_license_key=NULL") {
		t.Errorf("the stored key was cleared instead of written: %q", script.execs[0].query)
	}
}

// Clearing is a legitimate action: it turns the feature off without touching
// the country rules already stored.
func TestBothHalvesEmptyClearsTheAccount(t *testing.T) {
	sealing(t)
	script := newScript()

	status, body := save(t, script, `{"account_id":"  ","license_key":""}`)
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("status = %d, body = %v, want 200 and ok", status, body)
	}
	if len(script.execs) != 1 {
		t.Fatalf("statements = %d, want 1", len(script.execs))
	}
	if !strings.Contains(script.execs[0].query, "maxmind_license_key=NULL") {
		t.Errorf("the clearing statement is %q", script.execs[0].query)
	}
	if len(script.execs[0].args) != 0 {
		t.Errorf("the clearing statement bound %v, want nothing", script.execs[0].args)
	}
}

func TestTheCredentialsAreRefusedWhenTheyCannotAuthenticate(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"a body that is not JSON", `{"account_id":`, "invalid request body"},
		{"an account id with no key", `{"account_id":"12345"}`, "both the account id and the license key are required"},
		{"a key with no account id", `{"license_key":"a-real-key"}`, "both the account id and the license key are required"},
		{"an account id that is not a number", `{"account_id":"acct-1","license_key":"k"}`, "the account id is a number"},
		{"an account id past the length limit", `{"account_id":"` + strings.Repeat("1", 33) +
			`","license_key":"k"}`, "the account id is a number"},
		{"a license key carrying whitespace", `{"account_id":"12345","license_key":"a key"}`,
			"the license key contains whitespace"},
		{"a license key carrying a newline", `{"account_id":"12345","license_key":"a\nkey"}`,
			"the license key contains whitespace"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sealing(t)
			script := newScript()

			status, body := save(t, script, tc.body)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (%v)", status, body)
			}
			if got, _ := body["error"].(string); got != tc.want {
				t.Errorf("error = %q, want %q", got, tc.want)
			}
			if len(script.execs) != 0 {
				t.Errorf("a refused request still wrote %v", script.execs)
			}
		})
	}
}

// A write that fails answers as a failure and says nothing about the key.
func TestAFailedWriteIsReportedWithoutTheKey(t *testing.T) {
	sealing(t)
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"a failed clear", `{"account_id":"","license_key":""}`, "the credentials could not be cleared"},
		{"a failed store", `{"account_id":"12345","license_key":"a-real-key"}`,
			"the credentials could not be stored"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := newScript()
			script.fail["UPDATE panel_settings"] = errDatabaseGone

			status, body := save(t, script, tc.body)
			if status != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500 (%v)", status, body)
			}
			if got, _ := body["error"].(string); got != tc.want {
				t.Errorf("error = %q, want %q", got, tc.want)
			}
			if strings.Contains(strings.Join(messagesOf(body), " "), "a-real-key") {
				t.Error("the response carried the license key")
			}
		})
	}
}

// messagesOf collects the strings a response carries, so a test can check that
// none of them is the secret.
func messagesOf(body map[string]any) []string {
	var out []string
	for _, value := range body {
		if text, ok := value.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

// errDatabaseGone is what the script answers a write with.
var errDatabaseGone = driver.ErrBadConn
