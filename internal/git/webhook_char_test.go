package git

import (
	"context"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// A webhook delivery is unauthenticated apart from what it carries: a token in
// the URL that locates the repository, and a signature that proves the body came
// from the configured remote. The tests below pin what is refused, what is
// treated as a replay, and what a delivery actually runs.

// setForTest points a package variable somewhere else for one test.
func setForTest[T any](t *testing.T, target *T, value T) {
	t.Helper()
	previous := *target
	*target = value
	t.Cleanup(func() { *target = previous })
}

const (
	webhookToken   = "0123456789abcdef0123"
	webhookKey     = "the signing key, which is not the token"
	repoLookup     = "FROM git_repos g JOIN domains d ON d.id=g.domain_id"
	deliveryInsert = "INSERT IGNORE INTO git_webhook_deliveries"
)

// connectedRepo scripts the repository row a delivery resolves to.
func connectedRepo(script *sqlScript, signingKey string) {
	script.rows[repoLookup] = [][]driver.Value{
		{int64(4), int64(7), "c_acme", "https://github.com/acme/site.git", "main", "public_html", signingKey},
	}
}

// pulled records what the webhook asked the pull to do.
type pulled struct {
	calls    []string
	failWith error
}

// install points the pull seam at the recorder.
func (p *pulled) install(t *testing.T) {
	t.Helper()
	setForTest(t, &pullRepository, func(systemUser, repoURL, targetDir, branch, _ string) (string, string, error) {
		p.calls = append(p.calls, strings.Join([]string{systemUser, repoURL, targetDir, branch}, " "))
		if p.failWith != nil {
			return "", "", p.failWith
		}
		return "1a2b3c4d", "Fast-forward", nil
	})
}

// deliver posts a webhook body with the headers a GitHub delivery carries.
func deliver(t *testing.T, handlers *Handlers, body, event, delivery, signature string) *httptest.ResponseRecorder {
	t.Helper()
	route := chi.NewRouteContext()
	route.URLParams.Add("secret", webhookToken)
	r := httptest.NewRequest(http.MethodPost, "/git-webhook/"+webhookToken, strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
	if event != "" {
		r.Header.Set("X-GitHub-Event", event)
	}
	if delivery != "" {
		r.Header.Set("X-GitHub-Delivery", delivery)
	}
	if signature != "" {
		r.Header.Set("X-Hub-Signature-256", signature)
	}

	recorder := httptest.NewRecorder()
	handlers.Webhook(recorder, r)
	return recorder
}

// signedPush delivers a correctly signed push event.
func signedPush(t *testing.T, handlers *Handlers) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"ref":"refs/heads/main"}`
	return deliver(t, handlers, body, "push", "d-1", githubSign(webhookKey, []byte(body)))
}

// assertRefused checks the status and the message of a refused delivery.
func assertRefused(t *testing.T, recorder *httptest.ResponseRecorder, status int, message string) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("status = %d, want %d (body %s)", recorder.Code, status, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), message) {
		t.Errorf("body = %s, want %q", recorder.Body, message)
	}
}

// A signed push pulls the repository the token located, and records the commit
// it landed on.
func TestASignedPushPullsTheRepositoryItNames(t *testing.T) {
	script := newScript()
	connectedRepo(script, webhookKey)
	recorder := &pulled{}
	recorder.install(t)

	answer := signedPush(t, &Handlers{DB: scriptDB(t, script)})

	if answer.Code != http.StatusOK || !strings.Contains(answer.Body.String(), `"commit":"1a2b3c4d"`) {
		t.Fatalf("status = %d, body = %s", answer.Code, answer.Body)
	}
	want := "c_acme https://github.com/acme/site.git public_html main"
	if len(recorder.calls) != 1 || recorder.calls[0] != want {
		t.Errorf("pull calls = %v, want [%s]", recorder.calls, want)
	}
	if !ranStatement(script, "UPDATE git_repos SET last_sync=NOW()") {
		t.Errorf("the result was not recorded: %v", script.steps)
	}
}

// A ping is answered without pulling, because that is what GitHub sends to check
// the endpoint when the hook is created.
func TestAPingIsAnsweredWithoutPulling(t *testing.T) {
	script := newScript()
	connectedRepo(script, webhookKey)
	recorder := &pulled{}
	recorder.install(t)

	body := `{"zen":"Speak like a human."}`
	answer := deliver(t, &Handlers{DB: scriptDB(t, script)}, body, "ping", "d-2", githubSign(webhookKey, []byte(body)))

	if answer.Code != http.StatusOK || !strings.Contains(answer.Body.String(), `"pong":true`) {
		t.Fatalf("status = %d, body = %s", answer.Code, answer.Body)
	}
	if len(recorder.calls) != 0 {
		t.Errorf("pull calls = %v, want none", recorder.calls)
	}
}

// The same delivery id twice is a replay, and the second one is refused by the
// unique key rather than pulling again.
func TestARepeatedDeliveryIsRefusedAsAReplay(t *testing.T) {
	script := newScript()
	connectedRepo(script, webhookKey)
	// The insert affects no row when the delivery id is already recorded.
	script.affected = map[string]int64{deliveryInsert: 0}
	recorder := &pulled{}
	recorder.install(t)

	assertRefused(t, signedPush(t, &Handlers{DB: scriptDB(t, script)}),
		http.StatusConflict, "already processed")
	if len(recorder.calls) != 0 {
		t.Errorf("pull calls = %v, want none", recorder.calls)
	}
}

// A pull that fails drops the replay row, or GitHub's own retry of the same
// delivery would be refused as a replay and the site would never update.
func TestAFailedPullReleasesTheDeliveryForARetry(t *testing.T) {
	script := newScript()
	connectedRepo(script, webhookKey)
	recorder := &pulled{failWith: errors.New("fatal: could not read from remote")}
	recorder.install(t)

	assertRefused(t, signedPush(t, &Handlers{DB: scriptDB(t, script)}),
		http.StatusInternalServerError, "operation failed")
	if !ranStatement(script, "DELETE FROM git_webhook_deliveries WHERE delivery_id=?") {
		t.Errorf("the delivery was not released: %v", script.steps)
	}
	if !ranStatement(script, "last_status=?") {
		t.Errorf("the failure was not recorded: %v", script.steps)
	}
}

func TestAWebhookRefusesADeliveryItCannotTrust(t *testing.T) {
	body := `{"ref":"refs/heads/main"}`
	cases := []struct {
		name                      string
		signingKey                string
		event, delivery, signture string
		status                    int
		message                   string
	}{
		{
			name: "no signature at all", signingKey: webhookKey,
			event: "push", delivery: "d-1", signture: "",
			status: http.StatusUnauthorized, message: "signature required",
		},
		{
			name: "a signature under another key", signingKey: webhookKey,
			event: "push", delivery: "d-1", signture: githubSign("another key", []byte(body)),
			status: http.StatusUnauthorized, message: "signature verification failed",
		},
		{
			name: "a repository with no signing key", signingKey: "",
			event: "push", delivery: "d-1", signture: githubSign(webhookKey, []byte(body)),
			status: http.StatusServiceUnavailable, message: "no webhook signing key",
		},
		{
			name: "no delivery id", signingKey: webhookKey,
			event: "push", delivery: "", signture: githubSign(webhookKey, []byte(body)),
			status: http.StatusBadRequest, message: "delivery id missing or invalid",
		},
		{
			name: "a delivery id that is too long", signingKey: webhookKey,
			event: "push", delivery: strings.Repeat("d", 129), signture: githubSign(webhookKey, []byte(body)),
			status: http.StatusBadRequest, message: "delivery id missing or invalid",
		},
		{
			name: "an event this does not act on", signingKey: webhookKey,
			event: "issues", delivery: "d-1", signture: githubSign(webhookKey, []byte(body)),
			status: http.StatusBadRequest, message: "unsupported webhook event",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			script := newScript()
			connectedRepo(script, testCase.signingKey)
			recorder := &pulled{}
			recorder.install(t)

			assertRefused(t,
				deliver(t, &Handlers{DB: scriptDB(t, script)}, body, testCase.event, testCase.delivery, testCase.signture),
				testCase.status, testCase.message)
			if len(recorder.calls) != 0 {
				t.Errorf("pull calls = %v, want none", recorder.calls)
			}
		})
	}
}

// A token no repository carries is a 404, and a token too short to be one is
// refused before the database is asked at all.
func TestAWebhookRefusesATokenItCannotResolve(t *testing.T) {
	script := newScript()
	script.rows[repoLookup] = nil
	recorder := &pulled{}
	recorder.install(t)

	assertRefused(t, signedPush(t, &Handlers{DB: scriptDB(t, script)}),
		http.StatusNotFound, "secret did not match")

	short := newScript()
	route := chi.NewRouteContext()
	route.URLParams.Add("secret", "tooshort")
	r := httptest.NewRequest(http.MethodPost, "/git-webhook/tooshort", strings.NewReader("{}"))
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
	answer := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, short)}).Webhook(answer, r)

	assertRefused(t, answer, http.StatusBadRequest, "invalid secret")
	if len(short.steps) != 0 {
		t.Errorf("the database was asked anyway: %v", short.steps)
	}
}

// ranStatement reports whether the script saw a statement carrying fragment.
func ranStatement(script *sqlScript, fragment string) bool {
	script.mu.Lock()
	defer script.mu.Unlock()
	for _, step := range script.steps {
		if strings.Contains(step, fragment) {
			return true
		}
	}
	return false
}
