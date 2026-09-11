package mail

import (
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	tokenRead    = "FROM webmail_tokens WHERE token=?"
	tokenConsume = "UPDATE webmail_tokens SET used=1"
	signonToken  = "deadbeefdeadbeefdeadbeef"
)

// redeemEnvironment writes the shared secret Roundcube presents and sets the
// master password, empty when master is.
func redeemEnvironment(t *testing.T, master string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "internal.token")
	if err := os.WriteFile(path, []byte("internal-secret\n"), 0o600); err != nil {
		t.Fatalf("write the shared secret: %v", err)
	}
	t.Setenv("SERVIKA_PMA_TOKEN", path)
	t.Setenv(masterPassEnvName, master)
}

func redeemScript() *sqlScript {
	s := newScript()
	s.rows[tokenRead] = [][]driver.Value{{"box@example.com", int64(0), int64(0)}}
	return s
}

func redeem(t *testing.T, s *sqlScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/internal/webmail-redeem", strings.NewReader(body))
	request.Header.Set("X-Internal-Auth", "internal-secret")
	recorder := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, s)}).WebmailRedeem(recorder, request)
	return recorder
}

// Every refusal the redeem endpoint gives once the shared secret matched.
func TestWebmailRedeemRefusals(t *testing.T) {
	const gone = "token is no longer valid"
	const failed = "database operation failed"
	token := `{"token":"` + signonToken + `"}`
	cases := []struct {
		name, master, body string
		setup              func(*sqlScript)
		status             int
		text               string
	}{
		{"no master password", "", token, noSetup, http.StatusServiceUnavailable, "webmail signon is not configured on this server"},
		{"a body that is not JSON", "master-secret", `{`, noSetup, http.StatusBadRequest, "token is required"},
		{"an empty token", "master-secret", `{"token":""}`, noSetup, http.StatusBadRequest, "token is required"},
		{"an unknown token", "master-secret", token, func(s *sqlScript) { s.rows[tokenRead] = nil }, http.StatusNotFound, "token not found"},
		{"a token read that fails", "master-secret", token, func(s *sqlScript) { s.fail[tokenRead] = errScripted }, http.StatusInternalServerError, failed},
		{"a used token", "master-secret", token, func(s *sqlScript) { s.rows[tokenRead] = [][]driver.Value{{"box@example.com", int64(1), int64(0)}} }, http.StatusGone, gone},
		{"an expired token", "master-secret", token, func(s *sqlScript) { s.rows[tokenRead] = [][]driver.Value{{"box@example.com", int64(0), int64(1)}} }, http.StatusGone, gone},
		{"a consume that fails", "master-secret", token, func(s *sqlScript) { s.fail[tokenConsume] = errScripted }, http.StatusInternalServerError, failed},
		{"a token another request consumed", "master-secret", token, func(s *sqlScript) { s.affected[tokenConsume] = 0 }, http.StatusGone, gone},
		{"a consume count that cannot be read", "master-secret", token, func(s *sqlScript) { s.affectedFail[tokenConsume] = errScripted }, http.StatusGone, gone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			redeemEnvironment(t, c.master)
			script := redeemScript()
			c.setup(script)
			assertAnswer(t, redeem(t, script, c.body), c.status, c.text)
		})
	}
}

// A good token is consumed once and exchanged for the master login.
func TestWebmailRedeemHandsOverTheMasterLogin(t *testing.T) {
	redeemEnvironment(t, "master-secret")
	script := redeemScript()

	recorder := redeem(t, script, `{"token":"`+signonToken+`"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	if body := jsonBody(t, recorder); body["username"] != "box@example.com*servika-webmail" || body["password"] != "master-secret" {
		t.Fatalf("answer = %v", body)
	}
	if consume := script.onlyExec(t, tokenConsume); !slices.Equal(consume.args, []driver.Value{signonToken}) {
		t.Fatalf("consumed %#v", consume.args)
	}
}
