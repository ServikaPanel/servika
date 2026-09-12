package github

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
)

// Choosing a repository writes the two webhook values the deploy path depends
// on, and registers the hook at GitHub. The URL path token and the HMAC signing
// key must stay independent: the URL is written to the nginx access log on every
// delivery, so anyone who reads the log would otherwise hold the signing key.
// None of that was reachable in a test.

// useScript answers the queries the handler runs and records its writes.
type useScript struct {
	mu sync.Mutex
	// rows answers a query whose text contains the fragment with one row.
	rows map[string][]driver.Value
	// noRows answers with no row (sql.ErrNoRows).
	noRows map[string]bool
	// queryErr fails a matching query, execErr a matching statement.
	queryErr map[string]error
	execErr  map[string]error
	execs    []string
	execArgs map[string][]driver.Value
}

func (s *useScript) answer(query string) (driver.Rows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for fragment, err := range s.queryErr {
		if strings.Contains(query, fragment) {
			return nil, err
		}
	}
	for fragment := range s.noRows {
		if strings.Contains(query, fragment) {
			return &useRows{done: true}, nil
		}
	}
	for fragment, values := range s.rows {
		if strings.Contains(query, fragment) {
			return &useRows{values: values}, nil
		}
	}
	return nil, fmt.Errorf("the test script has no answer for: %s", query)
}

func (s *useScript) record(query string, args []driver.NamedValue) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execs = append(s.execs, query)
	if s.execArgs == nil {
		s.execArgs = map[string][]driver.Value{}
	}
	values := make([]driver.Value, 0, len(args))
	for _, a := range args {
		values = append(values, a.Value)
	}
	s.execArgs[query] = values
	for fragment, err := range s.execErr {
		if strings.Contains(query, fragment) {
			return err
		}
	}
	return nil
}

func (s *useScript) argsOf(fragment string) []driver.Value {
	s.mu.Lock()
	defer s.mu.Unlock()
	for query, values := range s.execArgs {
		if strings.Contains(query, fragment) {
			return values
		}
	}
	return nil
}

func (s *useScript) wrote(fragment string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, query := range s.execs {
		if strings.Contains(query, fragment) {
			return true
		}
	}
	return false
}

type useRows struct {
	values []driver.Value
	done   bool
}

func (r *useRows) Columns() []string { return make([]string, len(r.values)) }
func (r *useRows) Close() error      { return nil }
func (r *useRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, r.values)
	return nil
}

type useConn struct{ script *useScript }

func (c useConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c useConn) Driver() driver.Driver                        { return useDriver{} }
func (c useConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c useConn) Close() error                                 { return nil }
func (c useConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c useConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	return c.script.answer(query)
}

func (c useConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.script.record(query, args); err != nil {
		return nil, err
	}
	return useResult{}, nil
}

type useResult struct{}

func (useResult) LastInsertId() (int64, error) { return 1, nil }
func (useResult) RowsAffected() (int64, error) { return 1, nil }

type useDriver struct{}

func (useDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// The query fragments the handler runs.
const (
	qDomain   = "SELECT system_user FROM domains WHERE id=?"
	qToken    = "SELECT pat FROM github_connections"
	qSecrets  = "COALESCE(webhook_secret,'')"
	qPanel    = "FROM panel_settings WHERE id=1"
	qOldHook  = "SELECT webhook_id FROM github_connections"
	insRepo   = "INSERT INTO git_repos"
	updRepo   = "UPDATE github_connections SET selected_repo"
	updWebURL = "UPDATE github_connections SET webhook_id"
)

// connected is a domain with a token and no repository chosen yet, on a panel
// with no custom domain.
func connected() *useScript {
	return &useScript{
		rows: map[string][]driver.Value{
			qDomain:  {"c_shop"},
			qToken:   {"ghp_token"},
			qSecrets: {"", ""},
			qPanel:   {nil, nil},
			qOldHook: {int64(0)},
		},
	}
}

// ghRequest is one recorded call to GitHub.
type ghRequest struct {
	method string
	path   string
	token  string
	body   any
}

// fakeGitHub stands in for the API and answers each call in order.
type fakeGitHub struct {
	calls    []ghRequest
	body     []byte
	status   int
	callErr  error
	postOnly bool
}

func (f *fakeGitHub) install(t *testing.T) {
	t.Helper()
	previous := githubCall
	t.Cleanup(func() { githubCall = previous })
	githubCall = func(_ context.Context, method, path, token string, body any) ([]byte, int, error) {
		f.calls = append(f.calls, ghRequest{method: method, path: path, token: token, body: body})
		if method == "DELETE" && f.postOnly {
			return nil, 204, nil
		}
		if f.callErr != nil {
			return nil, 0, f.callErr
		}
		status := f.status
		if status == 0 {
			status = 201
		}
		answer := f.body
		if answer == nil {
			answer = []byte(`{"id":4242}`)
		}
		return answer, status, nil
	}
}

// useRepo posts a body for domain 7.
func useRepo(t *testing.T, script *useScript, gh *fakeGitHub, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	gh.install(t)
	db := sql.OpenDB(useConn{script: script})
	t.Cleanup(func() { _ = db.Close() })

	request := httptest.NewRequest(http.MethodPost, "/domains/7/github/use", strings.NewReader(body))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", "7")
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeCtx))

	recorder := httptest.NewRecorder()
	(&Handlers{DB: db, WebhookBase: "https://203.0.113.9:8443"}).Use(recorder, request)

	answer := map[string]any{}
	if recorder.Code == http.StatusOK {
		if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
			t.Fatalf("the answer is not readable: %s", recorder.Body)
		}
	}
	return recorder, answer
}

// Every refusal, and none of them writes a row.
func TestEveryRefusalStopsBeforeTheWrite(t *testing.T) {
	unknown := &useScript{queryErr: map[string]error{qDomain: errors.New("no such row")}}
	recorder, _ := useRepo(t, unknown, &fakeGitHub{}, `{"repo":"acme/site"}`)
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("an unknown domain answered %d, want 500: %s", recorder.Code, recorder.Body)
	}

	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "not json", body: `{`},
		{name: "no repo", body: `{"repo":""}`},
		{name: "a repo with no owner", body: `{"repo":"site"}`},
	} {
		script := connected()
		recorder, _ := useRepo(t, script, &fakeGitHub{}, tc.body)
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400: %s", tc.name, recorder.Code, recorder.Body)
		}
		if !strings.Contains(recorder.Body.String(), "repo (owner/name) and branch are required") {
			t.Errorf("%s: message = %s", tc.name, recorder.Body)
		}
		if script.wrote(insRepo) {
			t.Errorf("%s: the refusal still wrote a row", tc.name)
		}
	}

	noToken := connected()
	noToken.rows[qToken] = []driver.Value{""}
	recorder, _ = useRepo(t, noToken, &fakeGitHub{}, `{"repo":"acme/site"}`)
	if recorder.Code != http.StatusBadRequest ||
		!strings.Contains(recorder.Body.String(), "connect with a token first") {
		t.Errorf("a domain with no token answered %d: %s", recorder.Code, recorder.Body)
	}
	if noToken.wrote(insRepo) {
		t.Error("a row was written for a domain with no token")
	}
}

// A repository with no branch or directory takes the documented defaults, and
// the stored URL carries no token.
func TestTheStoredRepositoryTakesTheDefaults(t *testing.T) {
	script := connected()

	recorder, _ := useRepo(t, script, &fakeGitHub{}, `{"repo":"acme/site"}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body)
	}
	args := script.argsOf(insRepo)
	if len(args) != 6 {
		t.Fatalf("insert arguments = %v", args)
	}
	if args[1] != "https://github.com/acme/site.git" {
		t.Errorf("repo url = %v", args[1])
	}
	if args[2] != "main" || args[3] != "public_html" {
		t.Errorf("branch and directory = %v and %v, want main and public_html", args[2], args[3])
	}
	if selected := script.argsOf(updRepo); len(selected) != 3 || selected[0] != "acme/site" || selected[1] != "main" {
		t.Errorf("the connection stored %v", selected)
	}
}

// The URL path token and the signing key are two independent values, and a row
// still carrying the pre-separation pair gets a fresh key.
func TestTheURLTokenAndTheSigningKeyStayIndependent(t *testing.T) {
	fresh := connected()

	args := storedPair(t, fresh, `{"repo":"acme/site"}`)

	token, key := args[4].(string), args[5].(string)
	if len(token) != 40 || len(key) != 64 {
		t.Errorf("token is %d characters and key %d, want 40 and 64", len(token), len(key))
	}
	if token == key {
		t.Error("a fresh row got one value for both the URL token and the signing key")
	}
}

// storedPair runs the handler and returns the arguments of the git_repos write.
func storedPair(t *testing.T, script *useScript, body string) []driver.Value {
	t.Helper()
	if recorder, _ := useRepo(t, script, &fakeGitHub{}, body); recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	args := script.argsOf(insRepo)
	if len(args) != 6 {
		t.Fatalf("insert arguments = %v", args)
	}
	return args
}

// A pair that is already two independent values is kept, so choosing another
// branch does not break every configured delivery.
func TestAnExistingPairIsKept(t *testing.T) {
	script := connected()
	script.rows[qSecrets] = []driver.Value{"oldtoken", "oldkey"}

	args := storedPair(t, script, `{"repo":"acme/site"}`)

	if args[4] != "oldtoken" || args[5] != "oldkey" {
		t.Errorf("an existing pair was replaced: %v", args)
	}
}

// A row still carrying the pre-separation pair gets a fresh signing key, and
// keeps the URL token that configured deliveries already use.
func TestASharedPairIsSplitApart(t *testing.T) {
	script := connected()
	script.rows[qSecrets] = []driver.Value{"sameforboth", "sameforboth"}

	args := storedPair(t, script, `{"repo":"acme/site"}`)

	if args[4] != "sameforboth" {
		t.Errorf("the URL token was rotated: %v", args[4])
	}
	if key, ok := args[5].(string); !ok || key == "sameforboth" || len(key) != 64 {
		t.Errorf("the shared signing key was not replaced: %v", args[5])
	}
}

// A write that fails stops the request rather than reporting a repository that
// was never stored.
func TestAFailedWriteIsReported(t *testing.T) {
	for _, fragment := range []string{insRepo, updRepo} {
		script := connected()
		script.execErr = map[string]error{fragment: errors.New("write failed")}

		recorder, _ := useRepo(t, script, &fakeGitHub{}, `{"repo":"acme/site"}`)

		if recorder.Code != http.StatusInternalServerError {
			t.Errorf("a failed %s answered %d: %s", fragment, recorder.Code, recorder.Body)
		}
		if !strings.Contains(recorder.Body.String(), "operation failed") {
			t.Errorf("message = %s", recorder.Body)
		}
	}
}

// Without auto-deploy nothing is registered at GitHub.
func TestWithoutAutoDeployNoHookIsRegistered(t *testing.T) {
	script := connected()
	gh := &fakeGitHub{}

	recorder, answer := useRepo(t, script, gh, `{"repo":"acme/site","auto_deploy":false}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body)
	}
	if len(gh.calls) != 0 {
		t.Errorf("GitHub was called %v", gh.calls)
	}
	if _, reported := answer["webhook_ok"]; reported {
		t.Errorf("the answer reports a webhook that was never asked for: %v", answer)
	}
}

// GitHub verifies the panel certificate on delivery, so auto-deploy on an
// IP-based endpoint is refused rather than registered insecurely.
func TestAutoDeployIsRefusedWithoutATrustedPanelDomain(t *testing.T) {
	script := connected()
	gh := &fakeGitHub{}

	_, answer := useRepo(t, script, gh, `{"repo":"acme/site","auto_deploy":true}`)

	if answer["webhook_ok"] != false {
		t.Errorf("webhook_ok = %v, want false", answer["webhook_ok"])
	}
	if !strings.Contains(fmt.Sprint(answer["webhook_error"]), "valid TLS certificate") {
		t.Errorf("webhook_error = %v", answer["webhook_error"])
	}
	if len(gh.calls) != 0 {
		t.Errorf("an untrusted endpoint was still registered: %v", gh.calls)
	}
}

// trusted is a panel on a custom domain with an active certificate.
func trusted() *useScript {
	script := connected()
	script.rows[qPanel] = []driver.Value{"panel.example.com", "active"}
	return script
}

// The registered hook signs with the signing key, never with the URL token, and
// requires GitHub to verify the certificate. A previous hook is removed first.
func TestTheRegisteredHookSignsWithTheKeyAndTheOldOneIsRemoved(t *testing.T) {
	script := trusted()
	script.rows[qSecrets] = []driver.Value{"urltoken", "signingkey"}
	script.rows[qOldHook] = []driver.Value{int64(11)}
	gh := &fakeGitHub{postOnly: true}

	recorder, answer := useRepo(t, script, gh, `{"repo":"acme/site","auto_deploy":true}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body)
	}
	wantURL := "https://panel.example.com/api/v1/git-webhook/urltoken"
	assertHookCalls(t, gh, wantURL)
	if answer["webhook_ok"] != true || answer["webhook_url"] != wantURL {
		t.Errorf("answer = %v", answer)
	}
	if stored := script.argsOf(updWebURL); len(stored) != 3 || stored[0] != int64(4242) {
		t.Errorf("the webhook id was stored as %v", stored)
	}
}

// assertHookCalls checks the delete-then-create pair and the created hook.
func assertHookCalls(t *testing.T, gh *fakeGitHub, wantURL string) {
	t.Helper()
	if len(gh.calls) != 2 {
		t.Fatalf("GitHub was called %v, want a delete and a create", gh.calls)
	}
	if gh.calls[0].method != "DELETE" || gh.calls[0].path != "/repos/acme/site/hooks/11" {
		t.Errorf("the previous hook was not removed first: %v", gh.calls[0])
	}
	if gh.calls[1].method != "POST" || gh.calls[1].path != "/repos/acme/site/hooks" {
		t.Errorf("the hook was not created: %v", gh.calls[1])
	}
	if gh.calls[1].token != "ghp_token" {
		t.Errorf("the call used token %q", gh.calls[1].token)
	}
	hook, ok := gh.calls[1].body.(ghHook)
	if !ok {
		t.Fatalf("the created hook is %T", gh.calls[1].body)
	}
	for _, field := range []struct {
		name string
		got  string
		want string
	}{
		{name: "signing secret", got: hook.Config.Secret, want: "signingkey"},
		{name: "insecure_ssl", got: hook.Config.InsecureSSL, want: "0"},
		{name: "delivery url", got: hook.Config.URL, want: wantURL},
	} {
		if field.got != field.want {
			t.Errorf("%s = %q, want %q", field.name, field.got, field.want)
		}
	}
}

// A GitHub that refuses, or answers something unreadable, is reported in the
// answer rather than failing the whole request: the repository is stored.
func TestAFailedRegistrationIsReportedInTheAnswer(t *testing.T) {
	refused := trusted()
	recorder, answer := useRepo(t, refused, &fakeGitHub{status: 401, body: []byte(`{"message":"Bad credentials"}`)},
		`{"repo":"acme/site","auto_deploy":true}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body)
	}
	if answer["webhook_ok"] != false ||
		!strings.Contains(fmt.Sprint(answer["webhook_error"]), "The token is invalid or lacks permission (401)") {
		t.Errorf("answer = %v", answer)
	}
	if !refused.wrote(insRepo) {
		t.Error("the repository was not stored although only the hook failed")
	}

	unreachable := trusted()
	_, answer = useRepo(t, unreachable, &fakeGitHub{callErr: errors.New("no network")},
		`{"repo":"acme/site","auto_deploy":true}`)
	if answer["webhook_ok"] != false {
		t.Errorf("an unreachable GitHub reported %v", answer)
	}

	garbled := trusted()
	_, answer = useRepo(t, garbled, &fakeGitHub{body: []byte(`not json`)},
		`{"repo":"acme/site","auto_deploy":true}`)
	if answer["webhook_ok"] != false ||
		!strings.Contains(fmt.Sprint(answer["webhook_error"]), "could not parse webhook response") {
		t.Errorf("answer = %v", answer)
	}
}
