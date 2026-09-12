package composer

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// The endpoint runs composer as the tenant through runuser, so nothing but the
// slot gate was reachable in a test. A seam carries the process. These tests pin
// every refusal, the argument list each command produces, and what the answer
// carries.

// domainScript answers the one query the handler runs.
type domainScript struct {
	systemUser string
	err        error
}

func (s domainScript) Connect(context.Context) (driver.Conn, error) { return s, nil }
func (s domainScript) Driver() driver.Driver                        { return s }
func (s domainScript) Open(string) (driver.Conn, error)             { return s, nil }
func (s domainScript) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (s domainScript) Close() error                                 { return nil }
func (s domainScript) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (s domainScript) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &userRow{user: s.systemUser}, nil
}

type userRow struct {
	user string
	done bool
}

func (r *userRow) Columns() []string { return []string{"system_user"} }
func (r *userRow) Close() error      { return nil }
func (r *userRow) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.user
	return nil
}

// runRecorder stands in for runuser and records the argument list and the
// environment it was given.
type runRecorder struct {
	args   []string
	env    []string
	script string
}

func (rec *runRecorder) install(t *testing.T) {
	t.Helper()
	previous := runCommand
	t.Cleanup(func() { runCommand = previous })
	runCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		rec.args = append([]string{name}, args...)
		script := rec.script
		if script == "" {
			script = "echo done"
		}
		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
		rec.env = cmd.Env
		return cmd
	}
}

// runComposer posts a command for domain 7 and returns the recorder's answer.
func runComposer(t *testing.T, script domainScript, rec *runRecorder, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec.install(t)
	db := sql.OpenDB(script)
	t.Cleanup(func() { _ = db.Close() })

	request := httptest.NewRequest(http.MethodPost, "/domains/7/composer", strings.NewReader(body))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", "7")
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeCtx))

	recorder := httptest.NewRecorder()
	(&Handlers{DB: db}).Run(recorder, request)
	return recorder
}

// tenant is a script for a normal hosting account.
func tenant() domainScript { return domainScript{systemUser: "c_shop"} }

// withComposer points the binary at a file that exists, so the installed check
// passes without a composer on the machine running the test.
func withComposer(t *testing.T) {
	t.Helper()
	t.Setenv("SERVIKA_COMPOSER_BIN", "/bin/echo")
}

// Every refusal, and none of them starts a process.
func TestEveryRefusalStopsBeforeTheProcess(t *testing.T) {
	for _, tc := range []struct {
		name     string
		script   domainScript
		noBinary bool
		body     string
		status   int
		contains string
	}{
		{
			name:     "an unknown domain",
			script:   domainScript{err: errors.New("no such row")},
			body:     `{"command":"install"}`,
			status:   http.StatusNotFound,
			contains: "domain not found",
		},
		{
			name:     "a domain that is not a hosting account",
			script:   domainScript{systemUser: "root"},
			body:     `{"command":"install"}`,
			status:   http.StatusBadRequest,
			contains: "invalid user",
		},
		{
			name:     "no composer on the server",
			script:   tenant(),
			noBinary: true,
			body:     `{"command":"install"}`,
			status:   http.StatusServiceUnavailable,
			contains: "composer is not installed on the server",
		},
		{
			name:     "a body that is not json",
			script:   tenant(),
			body:     `{`,
			status:   http.StatusBadRequest,
			contains: "invalid request body",
		},
		{
			name:     "a command outside the list",
			script:   tenant(),
			body:     `{"command":"exec"}`,
			status:   http.StatusBadRequest,
			contains: "command is not allowed",
		},
		{
			name:     "no command at all",
			script:   tenant(),
			body:     `{}`,
			status:   http.StatusBadRequest,
			contains: "command is not allowed",
		},
		{
			name:     "a package name that is not one",
			script:   tenant(),
			body:     `{"command":"require","package":"vendor/pkg; rm -rf /"}`,
			status:   http.StatusBadRequest,
			contains: "invalid package name",
		},
		{
			name:     "a require with no package",
			script:   tenant(),
			body:     `{"command":"require"}`,
			status:   http.StatusBadRequest,
			contains: "invalid package name",
		},
	} {
		if tc.noBinary {
			t.Setenv("SERVIKA_COMPOSER_BIN", "/nonexistent/composer")
		} else {
			withComposer(t)
		}
		rec := &runRecorder{}

		recorder := runComposer(t, tc.script, rec, tc.body)

		if recorder.Code != tc.status {
			t.Errorf("%s: status = %d, want %d: %s", tc.name, recorder.Code, tc.status, recorder.Body)
		}
		if !strings.Contains(recorder.Body.String(), tc.contains) {
			t.Errorf("%s: message = %s, want %q", tc.name, recorder.Body, tc.contains)
		}
		if len(rec.args) != 0 {
			t.Errorf("%s: the refusal still started %v", tc.name, rec.args)
		}
	}
}

// The argument list is what keeps a tenant's command off a shell and inside its
// own account, so each accepted command's arguments are pinned.
func TestEachCommandProducesItsOwnArguments(t *testing.T) {
	withComposer(t)
	for _, tc := range []struct {
		body string
		want []string
	}{
		{
			body: `{"command":"install"}`,
			want: []string{"runuser", "-u", "c_shop", "--", "/bin/echo", "install", "--no-interaction", "--no-ansi", "-d", "/home/c_shop/public_html", "--no-scripts", "--no-plugins"},
		},
		{
			body: `{"command":"update"}`,
			want: []string{"runuser", "-u", "c_shop", "--", "/bin/echo", "update", "--no-interaction", "--no-ansi", "-d", "/home/c_shop/public_html", "--no-scripts", "--no-plugins"},
		},
		{
			body: `{"command":"show"}`,
			want: []string{"runuser", "-u", "c_shop", "--", "/bin/echo", "show", "--no-interaction", "--no-ansi", "-d", "/home/c_shop/public_html"},
		},
		{
			body: `{"command":"require","package":"monolog/monolog:^3.0"}`,
			want: []string{"runuser", "-u", "c_shop", "--", "/bin/echo", "require", "--no-interaction", "--no-ansi", "-d", "/home/c_shop/public_html", "monolog/monolog:^3.0"},
		},
		{
			body: `{"command":"remove","package":"monolog/monolog"}`,
			want: []string{"runuser", "-u", "c_shop", "--", "/bin/echo", "remove", "--no-interaction", "--no-ansi", "-d", "/home/c_shop/public_html", "monolog/monolog"},
		},
	} {
		rec := &runRecorder{}

		recorder := runComposer(t, tenant(), rec, tc.body)

		if recorder.Code != http.StatusOK {
			t.Fatalf("%s answered %d: %s", tc.body, recorder.Code, recorder.Body)
		}
		if strings.Join(rec.args, " ") != strings.Join(tc.want, " ") {
			t.Errorf("%s ran\n %v\nwant\n %v", tc.body, rec.args, tc.want)
		}
	}
}

// A finished run reports the command, whether it succeeded, and its output.
func TestTheAnswerCarriesTheOutcomeAndTheOutput(t *testing.T) {
	withComposer(t)
	rec := &runRecorder{script: "echo boom; exit 1"}

	recorder := runComposer(t, tenant(), rec, `{"command":"validate"}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body)
	}
	var answer struct {
		OK      bool   `json:"ok"`
		Command string `json:"command"`
		Output  string `json:"output"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("the answer is not readable: %s", recorder.Body)
	}
	if answer.OK {
		t.Error("a failed command was reported as ok")
	}
	if answer.Command != "validate" {
		t.Errorf("command = %q", answer.Command)
	}
	if !strings.Contains(answer.Output, "boom") {
		t.Errorf("output = %q, want the process output", answer.Output)
	}
}

// A long output is cut to its LAST 20000 characters, because the end carries the
// error and the panel must not answer with tens of megabytes.
func TestALongOutputIsCutToItsEnd(t *testing.T) {
	withComposer(t)
	rec := &runRecorder{script: "yes a | head -n 25000; echo THEEND"}

	recorder := runComposer(t, tenant(), rec, `{"command":"install"}`)

	var answer struct {
		Output string `json:"output"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("the answer is not readable: %s", recorder.Body)
	}
	if len(answer.Output) != 20000 {
		t.Fatalf("output is %d characters, want 20000", len(answer.Output))
	}
	if !strings.HasSuffix(answer.Output, "THEEND\n") {
		t.Errorf("the end of the output was cut away: %q", answer.Output[len(answer.Output)-20:])
	}
}

// An account already holding its slots is refused rather than queued, because a
// waiting request holds a panel goroutine behind a ten-minute install.
func TestAnAccountAtItsSlotLimitIsRefused(t *testing.T) {
	withComposer(t)
	const user = "c_full"
	for range concurrentRunsPerUser {
		release, ok := acquireRunSlot(user)
		if !ok {
			t.Fatal("the account could not fill its own slots")
		}
		defer release()
	}
	rec := &runRecorder{}

	recorder := runComposer(t, domainScript{systemUser: user}, rec, `{"command":"install"}`)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "another composer command is already running") {
		t.Errorf("message = %s", recorder.Body)
	}
	if len(rec.args) != 0 {
		t.Error("a refused run still started a process")
	}
}
