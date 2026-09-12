package php

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// The debug log is read as root out of a directory the tenant owns, so every
// read goes through the beneath helpers. Those need openat2, which is Linux
// only, so this file carries the tests that touch the file itself.

// debugHome creates a tenant home under a temporary root and returns the system
// user that names it.
func debugHome(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	setForTest(t, &tenantHomeRoot, root)
	if err := os.MkdirAll(filepath.Join(root, "c_acme", ".servika"), 0o755); err != nil {
		t.Fatalf("create the tenant home: %v", err)
	}
	return "c_acme"
}

// writeDebugLog puts a log in place for the tenant.
func writeDebugLog(t *testing.T, systemUser, body string) {
	t.Helper()
	path := filepath.Join(tenantHomeRoot, systemUser, ".servika", "php_debug.log")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write the debug log: %v", err)
	}
}

// debugLogOf asks the handler for the log of domain 7.
func debugLogOf(t *testing.T, handlers *Handlers) *httptest.ResponseRecorder {
	t.Helper()
	route := chi.NewRouteContext()
	route.URLParams.Add("id", "7")
	r := httptest.NewRequest(http.MethodGet, "/domains/7/php-debug-log", nil)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))

	recorder := httptest.NewRecorder()
	handlers.GetDebugLog(recorder, r)
	return recorder
}

// loggedLines decodes the answer's lines.
func loggedLines(t *testing.T, recorder *httptest.ResponseRecorder) []string {
	t.Helper()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	var answer struct {
		Lines []string `json:"lines"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("decode the answer: %v", err)
	}
	return answer.Lines
}

// debugDomain scripts the domain row the debug endpoints resolve.
func debugDomain(script *sqlScript, systemUser string) {
	script.rows["SELECT system_user FROM domains WHERE id=?"] = [][]driver.Value{{systemUser}}
}

func TestTheDebugLogIsReturnedLineByLine(t *testing.T) {
	systemUser := debugHome(t)
	writeDebugLog(t, systemUser, "first\nsecond\nthird\n")
	script := newScript()
	debugDomain(script, systemUser)

	lines := loggedLines(t, debugLogOf(t, &Handlers{DB: scriptDB(t, script)}))

	if strings.Join(lines, "|") != "first|second|third" {
		t.Errorf("lines = %v", lines)
	}
}

// A log nobody has written yet is not an error: debug mode may simply never
// have been triggered.
func TestAMissingDebugLogAnswersNoLines(t *testing.T) {
	systemUser := debugHome(t)
	script := newScript()
	debugDomain(script, systemUser)

	lines := loggedLines(t, debugLogOf(t, &Handlers{DB: scriptDB(t, script)}))

	if len(lines) != 0 {
		t.Errorf("lines = %v, want none", lines)
	}
}

// An empty log answers an empty list rather than one empty line.
func TestAnEmptyDebugLogAnswersNoLines(t *testing.T) {
	systemUser := debugHome(t)
	writeDebugLog(t, systemUser, "")
	script := newScript()
	debugDomain(script, systemUser)

	lines := loggedLines(t, debugLogOf(t, &Handlers{DB: scriptDB(t, script)}))

	if len(lines) != 0 {
		t.Errorf("lines = %v, want none", lines)
	}
}

// The answer is capped at the last 200 lines, so a log that has been growing
// for a month does not become the response.
func TestALongDebugLogIsCutToItsLastLines(t *testing.T) {
	systemUser := debugHome(t)
	var body strings.Builder
	for i := 1; i <= 250; i++ {
		fmt.Fprintf(&body, "line %d\n", i)
	}
	writeDebugLog(t, systemUser, body.String())
	script := newScript()
	debugDomain(script, systemUser)

	lines := loggedLines(t, debugLogOf(t, &Handlers{DB: scriptDB(t, script)}))

	if len(lines) != 200 {
		t.Fatalf("lines = %d, want 200", len(lines))
	}
	if lines[0] != "line 51" || lines[199] != "line 250" {
		t.Errorf("the window is %q..%q", lines[0], lines[199])
	}
}

// Only the last 64KB are read, and the partial line the window starts in is
// dropped rather than reported as a line of its own.
func TestAHugeDebugLogIsReadFromItsTail(t *testing.T) {
	systemUser := debugHome(t)
	var body strings.Builder
	body.WriteString(strings.Repeat("x", 70<<10))
	body.WriteString("\nthe last line\n")
	writeDebugLog(t, systemUser, body.String())
	script := newScript()
	debugDomain(script, systemUser)

	lines := loggedLines(t, debugLogOf(t, &Handlers{DB: scriptDB(t, script)}))

	if len(lines) != 1 || lines[0] != "the last line" {
		t.Errorf("lines = %v, want only the complete last line", lines)
	}
}

// A directory in place of the log is not read: the tenant owns the directory it
// sits in and can put anything there.
func TestADebugLogThatIsNotAFileAnswersNoLines(t *testing.T) {
	systemUser := debugHome(t)
	path := filepath.Join(tenantHomeRoot, systemUser, ".servika", "php_debug.log")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("create the directory: %v", err)
	}
	script := newScript()
	debugDomain(script, systemUser)

	lines := loggedLines(t, debugLogOf(t, &Handlers{DB: scriptDB(t, script)}))

	if len(lines) != 0 {
		t.Errorf("lines = %v, want none", lines)
	}
}

// A system user that is not a provisioned tenant account is refused, because
// the home it names decides which tree the read is confined to.
func TestADebugLogRefusesASystemUserThatIsNotATenant(t *testing.T) {
	debugHome(t)
	script := newScript()
	debugDomain(script, "c_../../etc")

	recorder := debugLogOf(t, &Handlers{DB: scriptDB(t, script)})

	if recorder.Code != http.StatusBadRequest ||
		!strings.Contains(recorder.Body.String(), "invalid system user") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
}

func TestADebugLogRefusesADomainThatIsNotThere(t *testing.T) {
	debugHome(t)
	script := newScript()
	script.rows["SELECT system_user FROM domains WHERE id=?"] = nil

	recorder := debugLogOf(t, &Handlers{DB: scriptDB(t, script)})

	if recorder.Code != http.StatusNotFound ||
		!strings.Contains(recorder.Body.String(), "domain not found") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
}
