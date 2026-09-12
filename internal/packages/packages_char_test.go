package packages

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

// The package manager is dnf and rpm on the host, so every handler here is
// measured through the runCommand seam: what argv it builds, and what it makes
// of the output.

// dnfHost records the commands a handler runs and answers each one.
type dnfHost struct {
	calls   []string
	answers map[string]string // first argument -> stdout
	failing map[string]bool   // first argument -> the command fails
}

// fakeDNF installs the recorder for one test.
func fakeDNF(t *testing.T) *dnfHost {
	t.Helper()
	host := &dnfHost{answers: map[string]string{}, failing: map[string]bool{}}
	previous := runCommand
	runCommand = func(_ context.Context, name string, arguments ...string) *exec.Cmd {
		host.calls = append(host.calls, name+" "+strings.Join(arguments, " "))
		verb := ""
		if len(arguments) > 0 {
			verb = arguments[0]
		}
		if host.failing[verb] {
			return exec.Command("/bin/sh", "-c", "exit 1")
		}
		return exec.Command("/bin/echo", "-n", host.answers[verb])
	}
	t.Cleanup(func() { runCommand = previous })
	return host
}

// ran reports whether a command carrying fragment was run.
func (h *dnfHost) ran(fragment string) bool {
	for _, call := range h.calls {
		if strings.Contains(call, fragment) {
			return true
		}
	}
	return false
}

// assertStatus checks a handler's status and the text of its answer.
func assertStatus(t *testing.T, recorder *httptest.ResponseRecorder, status int, message string) {
	t.Helper()
	if recorder.Code != status || !strings.Contains(recorder.Body.String(), message) {
		t.Fatalf("status = %d, body = %s; want %d carrying %q",
			recorder.Code, recorder.Body.String(), status, message)
	}
}

// get calls a handler with a query string.
func get(t *testing.T, handler http.HandlerFunc, query string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler(recorder, httptest.NewRequest(http.MethodGet, "/packages?"+query, nil))
	return recorder
}

// post calls a handler with a JSON body.
func post(t *testing.T, handler http.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler(recorder, httptest.NewRequest(http.MethodPost, "/packages", strings.NewReader(body)))
	return recorder
}

// A package name reaches an argv, so the character set is the boundary.
func TestOnlyAPackageNameIsAccepted(t *testing.T) {
	for _, name := range []string{
		"nginx", "php-fpm", "python3.12", "gcc-c++", "lib_x", "A9",
	} {
		if !safe(name) {
			t.Errorf("%q was refused", name)
		}
	}
	for _, hostile := range []string{
		"", "   ", "nginx; rm -rf /", "nginx&&id", "$(id)", "`id`", "nginx|cat",
		"--installroot=/", "nginx\nphp", "nginx php", "nginx/../etc", "ünicode",
		strings.Repeat("a", 81),
	} {
		if safe(hostile) {
			t.Errorf("%q was accepted", hostile)
		}
	}
}

const searchOutput = `Last metadata expiration check: 0:01:23 ago.
=========== Name Exactly Matched: nginx ===========
nginx.x86_64 : A high performance web server
=========== Name & Summary Matched: nginx ===========
nginx-mod-http-perl.aarch64 : Nginx HTTP perl module
python3-nginx.noarch : Python bindings
oddball : no arch suffix at all
a line with no separator
`

// A search reads dnf's two-column output, strips the architecture suffix and
// marks what is installed and what the panel protects.
func TestASearchReadsTheDNFTable(t *testing.T) {
	host := fakeDNF(t)
	host.answers["search"] = searchOutput
	host.answers["-qa"] = "nginx\ncoreutils\n"

	recorder := get(t, (&Handlers{}).Search, "q=nginx")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var answer struct {
		Total   int       `json:"total"`
		Content []Package `json:"content"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The metadata line, the two heading lines and the line with no separator
	// are all dropped.
	want := []Package{
		{Name: "nginx", Description: "A high performance web server", Installed: true, Protected: true},
		{Name: "nginx-mod-http-perl", Description: "Nginx HTTP perl module"},
		{Name: "python3-nginx", Description: "Python bindings"},
		{Name: "oddball", Description: "no arch suffix at all"},
	}
	if answer.Total != len(want) {
		t.Fatalf("total = %d, want %d: %+v", answer.Total, len(want), answer.Content)
	}
	for i, expected := range want {
		if answer.Content[i] != expected {
			t.Errorf("row %d = %+v, want %+v", i, answer.Content[i], expected)
		}
	}
	if !host.ran("dnf search --quiet nginx") {
		t.Errorf("the query did not reach dnf as its own argument: %v", host.calls)
	}
}

// The answer is capped so one query cannot return a whole repository.
func TestASearchStopsAtTwoHundredResults(t *testing.T) {
	host := fakeDNF(t)
	var table strings.Builder
	for i := range 250 {
		table.WriteString("pkg")
		table.WriteString(strings.Repeat("x", i%3))
		table.WriteString(".x86_64 : a package\n")
	}
	host.answers["search"] = table.String()

	recorder := get(t, (&Handlers{}).Search, "q=pkg")

	var answer struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if answer.Total != 200 {
		t.Errorf("total = %d, want the 200 cap", answer.Total)
	}
}

func TestASearchRefusesWhatMustNotReachDNF(t *testing.T) {
	for _, tc := range []struct{ name, query, message string }{
		{"no query at all", "", "q parameter is required"},
		{"a query that is not a package name", "q=nginx%3Bid", "invalid search query"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := fakeDNF(t)

			assertStatus(t, get(t, (&Handlers{}).Search, tc.query), http.StatusBadRequest, tc.message)

			if len(host.calls) != 0 {
				t.Errorf("a refused query still reached the host: %v", host.calls)
			}
		})
	}
}

// The installed list is rpm's own output, filtered by name or summary.
func TestTheInstalledListFiltersOnNameAndSummary(t *testing.T) {
	host := fakeDNF(t)
	host.answers["-qa"] = "nginx|1.26.0|A web server\n" +
		"vim-enhanced|9.1|A text editor\n" +
		"bash|5.2|The GNU shell\n" +
		"short-line\n"

	recorder := get(t, (&Handlers{}).Installed, "q=web")

	var answer struct {
		Total   int       `json:"total"`
		Content []Package `json:"content"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if answer.Total != 1 || answer.Content[0].Name != "nginx" {
		t.Fatalf("content = %+v, want only the summary match", answer.Content)
	}
	if answer.Content[0].Version != "1.26.0" || !answer.Content[0].Installed || !answer.Content[0].Protected {
		t.Errorf("row = %+v", answer.Content[0])
	}
}

// A package the panel depends on cannot be removed, and the refusal happens
// before dnf is reached.
func TestAProtectedPackageIsNeverRemoved(t *testing.T) {
	host := fakeDNF(t)

	assertStatus(t, post(t, (&Handlers{}).Remove, `{"package":"nginx"}`),
		http.StatusForbidden, "cannot be removed: nginx")

	if len(host.calls) != 0 {
		t.Errorf("a protected package still reached dnf: %v", host.calls)
	}
}

// What each write handler builds, and what it says when dnf refuses.
func TestTheWriteHandlersBuildTheirArgv(t *testing.T) {
	for _, tc := range []struct {
		name, body, argv, failure string
		handler                   func(*Handlers) http.HandlerFunc
		verb                      string
	}{
		{
			name: "install", body: `{"package":"vim-enhanced"}`,
			argv: "dnf install -y vim-enhanced", verb: "install",
			failure: "package installation failed",
			handler: func(h *Handlers) http.HandlerFunc { return h.Install },
		},
		{
			name: "remove", body: `{"package":"vim-enhanced"}`,
			argv: "dnf remove -y vim-enhanced", verb: "remove",
			failure: "package removal failed",
			handler: func(h *Handlers) http.HandlerFunc { return h.Remove },
		},
		{
			name: "upgrade one package", body: `{"package":"vim-enhanced"}`,
			argv: "dnf upgrade -y vim-enhanced", verb: "upgrade",
			failure: "package upgrade failed",
			handler: func(h *Handlers) http.HandlerFunc { return h.Update },
		},
		{
			name: "upgrade everything", body: `{}`,
			argv: "dnf upgrade -y", verb: "upgrade",
			failure: "package upgrade failed",
			handler: func(h *Handlers) http.HandlerFunc { return h.Update },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := fakeDNF(t)

			assertStatus(t, post(t, tc.handler(&Handlers{}), tc.body), http.StatusOK, `"ok":true`)

			if !host.ran(tc.argv) {
				t.Errorf("the command was %v, want %q", host.calls, tc.argv)
			}
		})
		t.Run(tc.name+" fails", func(t *testing.T) {
			host := fakeDNF(t)
			host.failing[tc.verb] = true

			assertStatus(t, post(t, tc.handler(&Handlers{}), tc.body),
				http.StatusInternalServerError, tc.failure)
		})
	}
}

// Every write handler refuses a body it cannot read and a name that is not one.
func TestTheWriteHandlersRefuseWhatMustNotReachDNF(t *testing.T) {
	handlers := map[string]http.HandlerFunc{
		"install": (&Handlers{}).Install,
		"remove":  (&Handlers{}).Remove,
		"update":  (&Handlers{}).Update,
	}
	for name, handler := range handlers {
		t.Run(name+" refuses a body that is not JSON", func(t *testing.T) {
			host := fakeDNF(t)
			assertStatus(t, post(t, handler, `{"package":`), http.StatusBadRequest, "invalid request body")
			if len(host.calls) != 0 {
				t.Errorf("a refused body still reached dnf: %v", host.calls)
			}
		})
		t.Run(name+" refuses a name that is not one", func(t *testing.T) {
			host := fakeDNF(t)
			assertStatus(t, post(t, handler, `{"package":"nginx;id"}`), http.StatusBadRequest, "invalid package")
			if len(host.calls) != 0 {
				t.Errorf("a refused name still reached dnf: %v", host.calls)
			}
		})
	}
}

// Update alone accepts an empty package, which means "upgrade everything".
func TestOnlyUpdateAcceptsAnEmptyPackage(t *testing.T) {
	fakeDNF(t)

	assertStatus(t, post(t, (&Handlers{}).Install, `{"package":""}`),
		http.StatusBadRequest, "invalid package name")
	assertStatus(t, post(t, (&Handlers{}).Update, `{"package":""}`), http.StatusOK, `"ok":true`)
}

func TestInfoAsksDNFAndReportsItsFailure(t *testing.T) {
	host := fakeDNF(t)

	assertStatus(t, get(t, (&Handlers{}).Info, "name=nginx"), http.StatusOK, `"name":"nginx"`)
	if !host.ran("dnf info nginx") {
		t.Errorf("the command was %v", host.calls)
	}

	assertStatus(t, get(t, (&Handlers{}).Info, "name=nginx;id"),
		http.StatusBadRequest, "invalid package name")

	host.failing["info"] = true
	assertStatus(t, get(t, (&Handlers{}).Info, "name=nginx"),
		http.StatusInternalServerError, "package information lookup failed")
}

// Status answers only for the names it was asked about, and a name that is not
// a package name is dropped rather than refusing the whole request.
func TestStatusAnswersOnlyForTheNamesItWasAsked(t *testing.T) {
	host := fakeDNF(t)
	host.answers["-qa"] = "nginx\nbash\n"

	recorder := get(t, (&Handlers{}).Status, "names=nginx,vim-enhanced,%20,nginx%3Bid")

	var answer map[string]bool
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(answer) != 2 || !answer["nginx"] || answer["vim-enhanced"] {
		t.Errorf("answer = %v, want nginx true and vim-enhanced false only", answer)
	}
}

// An empty list asks the host nothing at all.
func TestStatusWithNoNamesAsksTheHostNothing(t *testing.T) {
	host := fakeDNF(t)

	assertStatus(t, get(t, (&Handlers{}).Status, ""), http.StatusOK, "{}")

	if len(host.calls) != 0 {
		t.Errorf("an empty list still reached rpm: %v", host.calls)
	}
}
