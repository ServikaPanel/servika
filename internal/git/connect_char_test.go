package git

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// Connect stores the repository and hands back a deploy key. It writes two
// independent secrets, and the tests below pin that they are two.

const domainLookup = "SELECT system_user FROM domains WHERE id=?"

// ownedDomain scripts the domain the request names.
func ownedDomain(script *sqlScript, systemUser string) {
	script.rows[domainLookup] = [][]driver.Value{{systemUser}}
}

// storedRepo scripts the row the answer is read back from.
func storedRepo(script *sqlScript) {
	script.rows["FROM git_repos WHERE id=?"] = [][]driver.Value{
		{int64(4), int64(7), "https://github.com/acme/site.git", "main", "public_html",
			"ssh-ed25519 AAAA", "the token", "the signing key", "", "", "pending", "2026-01-01 00:00"},
	}
}

// connectWith sends a connect request as the panel would.
func connectWith(t *testing.T, handlers *Handlers, body string) *httptest.ResponseRecorder {
	t.Helper()
	route := chi.NewRouteContext()
	route.URLParams.Add("id", "7")
	r := httptest.NewRequest(http.MethodPost, "/domains/7/git", strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))

	recorder := httptest.NewRecorder()
	handlers.Connect(recorder, r)
	return recorder
}

// hostChecks installs the two host seams a connect reaches and records the URLs
// that were vetted.
func hostChecks(t *testing.T, keyErr, vetErr error) *[]string {
	t.Helper()
	var vetted []string
	setForTest(t, &deployKeyFor, func(string) (string, error) {
		return "ssh-ed25519 AAAA the-deploy-key", keyErr
	})
	setForTest(t, &checkGitURL, func(url string) error {
		vetted = append(vetted, url)
		return vetErr
	})
	return &vetted
}

// A connect stores the row and answers with the key the operator has to add to
// the remote.
func TestAConnectStoresTheRepositoryAndAnswersTheDeployKey(t *testing.T) {
	script := newScript()
	ownedDomain(script, "c_acme")
	storedRepo(script)
	vetted := hostChecks(t, nil, nil)

	recorder := connectWith(t, &Handlers{DB: scriptDB(t, script)},
		`{"repo_url":"https://github.com/acme/site.git","branch":"release","target_dir":"public_html/app"}`)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	var answer Repo
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("decode the answer: %v", err)
	}
	if answer.DeployKeyPub != "ssh-ed25519 AAAA" {
		t.Errorf("answer = %+v", answer)
	}
	if len(*vetted) != 1 || (*vetted)[0] != "https://github.com/acme/site.git" {
		t.Errorf("vetted = %v", *vetted)
	}
	inserted := insertArgs(t, script, "INSERT INTO git_repos")
	if inserted[1] != "https://github.com/acme/site.git" || inserted[2] != "release" || inserted[3] != "public_html/app" {
		t.Errorf("stored row = %v", inserted)
	}
	assertTwoSecrets(t, inserted)
}

// assertTwoSecrets checks the stored URL token and signing key.
//
// They are two independent values. Deriving one from the other makes the
// signature prove nothing beyond the URL, which is in the nginx access log on
// every delivery.
func assertTwoSecrets(t *testing.T, inserted []driver.Value) {
	t.Helper()
	token, signingKey := inserted[5].(string), inserted[6].(string)
	if token == signingKey {
		t.Errorf("the URL token and the signing key are the same value: %v", token)
	}
	if len(token) != 40 || len(signingKey) != 64 {
		t.Errorf("token = %d characters, signing key = %d", len(token), len(signingKey))
	}
}

// An empty branch and target directory take the defaults, so the common case is
// one field on the form.
func TestAConnectWithoutABranchTakesTheDefaults(t *testing.T) {
	script := newScript()
	ownedDomain(script, "c_acme")
	storedRepo(script)
	hostChecks(t, nil, nil)

	recorder := connectWith(t, &Handlers{DB: scriptDB(t, script)},
		`{"repo_url":"https://github.com/acme/site.git","branch":"  ","target_dir":""}`)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	inserted := insertArgs(t, script, "INSERT INTO git_repos")
	if inserted[2] != "main" || inserted[3] != "public_html" {
		t.Errorf("stored row = %v, want the defaults", inserted)
	}
}

func TestAConnectRefusesWhatItMustNotStore(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		script  func(*sqlScript)
		keyErr  error
		vetErr  error
		status  int
		message string
	}{
		{
			name:    "a URL that is not a repository",
			body:    `{"repo_url":"file:///etc/passwd"}`,
			status:  http.StatusBadRequest,
			message: "invalid repo_url",
		},
		{
			name:    "a host the guard refuses",
			body:    `{"repo_url":"https://10.0.0.1/site.git"}`,
			vetErr:  errors.New("private address"),
			status:  http.StatusBadRequest,
			message: "repository host is not permitted",
		},
		{
			name:    "a branch that is not a branch name",
			body:    `{"repo_url":"https://github.com/acme/site.git","branch":"main;id"}`,
			status:  http.StatusBadRequest,
			message: "invalid branch",
		},
		{
			name:    "a target outside the home",
			body:    `{"repo_url":"https://github.com/acme/site.git","target_dir":"../../etc"}`,
			status:  http.StatusBadRequest,
			message: "invalid target_dir",
		},
		{
			name:    "a body that is not JSON",
			body:    `{"repo_url":`,
			status:  http.StatusBadRequest,
			message: "invalid request body",
		},
		{
			name:    "a domain that is not there",
			body:    `{"repo_url":"https://github.com/acme/site.git"}`,
			script:  func(s *sqlScript) { s.rows[domainLookup] = nil },
			status:  http.StatusNotFound,
			message: "domain not found",
		},
		{
			name:    "a deploy key that cannot be written",
			body:    `{"repo_url":"https://github.com/acme/site.git"}`,
			keyErr:  errors.New("permission denied"),
			status:  http.StatusInternalServerError,
			message: "operation failed",
		},
		{
			name:    "a row that cannot be stored",
			body:    `{"repo_url":"https://github.com/acme/site.git"}`,
			script:  func(s *sqlScript) { s.fail["INSERT INTO git_repos"] = errors.New("disk full") },
			status:  http.StatusInternalServerError,
			message: "operation failed",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			script := newScript()
			ownedDomain(script, "c_acme")
			storedRepo(script)
			if testCase.script != nil {
				testCase.script(script)
			}
			hostChecks(t, testCase.keyErr, testCase.vetErr)

			recorder := connectWith(t, &Handlers{DB: scriptDB(t, script)}, testCase.body)

			if recorder.Code != testCase.status ||
				!strings.Contains(recorder.Body.String(), testCase.message) {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
			}
		})
	}
}

// insertArgs returns the arguments of the one statement carrying fragment.
func insertArgs(t *testing.T, script *sqlScript, fragment string) []driver.Value {
	t.Helper()
	script.mu.Lock()
	defer script.mu.Unlock()
	for _, exec := range script.execs {
		if strings.Contains(exec.query, fragment) {
			return exec.args
		}
	}
	t.Fatalf("no statement carrying %q ran: %v", fragment, script.steps)
	return nil
}
