package middleware

import (
	"context"
	"errors"
	"go/scanner"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func withDemoLookup(t *testing.T, demo bool, err error) {
	t.Helper()
	previous := demoDomainLookup
	demoDomainLookup = func(context.Context, int64) (bool, error) { return demo, err }
	t.Cleanup(func() { demoDomainLookup = previous })
}

func demoRequest() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/domains/7/anything", nil)
}

// A demo subscription is read-only for EVERY role, because is_demo is a
// property of the domain rather than of the caller. That is what the thirty
// per-handler copies already do.
func TestADemoDomainRefusesTheWrite(t *testing.T) {
	withDemoLookup(t, true, nil)
	recorder := httptest.NewRecorder()

	if EnforceDomainNotDemo(recorder, demoRequest(), 7, "the nginx settings") {
		t.Fatal("a demo domain was allowed through")
	}
	if recorder.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if !strings.Contains(recorder.Body.String(), "the nginx settings cannot be changed for a demo subscription") {
		t.Errorf("the refusal does not name what was refused: %s", recorder.Body.String())
	}
}

// A flag that could not be read must refuse. Failing open would make every demo
// domain writable for the duration of a database incident.
func TestAnUnreadableDemoFlagRefusesTheWrite(t *testing.T) {
	withDemoLookup(t, false, errors.New("the database is unreachable"))
	recorder := httptest.NewRecorder()

	if EnforceDomainNotDemo(recorder, demoRequest(), 7, "applications") {
		t.Fatal("an unreadable flag let the write through")
	}
	if recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
}

// And an ordinary domain is untouched, or the guard would refuse everything and
// the tests above would prove nothing.
func TestAnOrdinaryDomainPassesTheDemoGuard(t *testing.T) {
	withDemoLookup(t, false, nil)
	recorder := httptest.NewRecorder()

	if !EnforceDomainNotDemo(recorder, demoRequest(), 7, "applications") {
		t.Fatalf("an ordinary domain was refused: %s", recorder.Body.String())
	}
	if recorder.Code != http.StatusOK || recorder.Body.Len() != 0 {
		t.Errorf("the guard wrote a response for a domain it allowed: %d %s",
			recorder.Code, recorder.Body.String())
	}
}

// routeLine matches one tenant-scoped route declaration in the router table:
//
//	r.With(middleware.CustomerScope).Post("/domains/{id}/x", someH.Method)
var routeLine = regexp.MustCompile(
	`CustomerScope[^)]*\)\.(Post|Put|Delete|Patch)\("[^"]*",\s*(\w+)\.`)

// handlerVar matches the construction of a handler value in main:
//
//	appInstallH := &appinstall.Handlers{...}
var handlerVar = regexp.MustCompile(`(\w+)\s*:?=\s*&?(\w+)\.Handlers\b`)

// aliasedImport matches an import that renames a package:
//
//	githubpkg "servika/internal/github"
var aliasedImport = regexp.MustCompile(`(\w+)\s+"servika/internal/(\w+)"`)

// CustomerScope enforces ownership and suspension and never reads is_demo, so
// every tenant-facing package has to remember the demo guard on its own. Four
// of them did not, and each ran a real host mutation on a subscription the flag
// exists to keep read-only: a whole CMS unpacked into the document root, the
// live vhost's security headers rewritten, a MariaDB account opened to an
// outside address, and an MTA-STS enforce policy published.
//
// The check is per PACKAGE, not per handler: it catches a package that guards
// nothing at all, which is the shape this defect had every time it appeared.
func TestEveryTenantWritePackageGuardsDemoSubscriptions(t *testing.T) {
	root := repositoryRootFrom(t)
	router, err := os.ReadFile(filepath.Join(root, "cmd", "server", "main.go"))
	if err != nil {
		t.Fatalf("read the router: %v", err)
	}

	// An aliased import (githubpkg "servika/internal/github") names a package by
	// something other than its directory, so the alias is resolved first or the
	// lookup below opens a directory that does not exist.
	directory := map[string]string{}
	for _, match := range aliasedImport.FindAllStringSubmatch(string(router), -1) {
		directory[match[1]] = match[2]
	}

	owners := map[string]string{}
	for _, match := range handlerVar.FindAllStringSubmatch(string(router), -1) {
		owners[match[1]] = match[2]
	}

	packages := map[string]bool{}
	for _, match := range routeLine.FindAllStringSubmatch(string(router), -1) {
		pkg, ok := owners[match[2]]
		if !ok {
			continue
		}
		if dir, aliased := directory[pkg]; aliased {
			pkg = dir
		}
		packages[pkg] = true
	}
	if len(packages) < 10 {
		t.Fatalf("only %d tenant-write packages were found; the router shape changed and this test is not reading it",
			len(packages))
	}

	var unguarded []string
	for pkg := range packages {
		if !guardsDemo(t, filepath.Join(root, "internal", pkg)) {
			unguarded = append(unguarded, pkg)
		}
	}
	sort.Strings(unguarded)
	for _, pkg := range unguarded {
		t.Errorf("internal/%s serves a tenant write route but never reads is_demo; "+
			"a demo subscription can change the host through it", pkg)
	}
}

// guardsDemo reports whether a package refuses demo subscriptions anywhere,
// either through the shared helper or its own column read.
//
// It reads TOKENS, not text. Every one of these packages carries a comment
// explaining that CustomerScope never reads is_demo, so a text search finds the
// column name in a package that does nothing with it and the check passes on a
// sentence rather than on code.
func guardsDemo(t *testing.T, dir string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		body, err := os.ReadFile(path) // #nosec G304 -- a repository source file.
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		if fileGuardsDemo(path, body) {
			return true
		}
	}
	return false
}

// fileGuardsDemo scans one file for the guard call or for SQL naming the column.
// Comments are not scanned, so only code counts.
func fileGuardsDemo(path string, body []byte) bool {
	fileSet := token.NewFileSet()
	file := fileSet.AddFile(path, fileSet.Base(), len(body))
	var scan scanner.Scanner
	scan.Init(file, body, nil, 0) // 0: comments are skipped.
	for {
		_, tok, literal := scan.Scan()
		switch tok {
		case token.EOF:
			return false
		case token.IDENT:
			if literal == "EnforceDomainNotDemo" {
				return true
			}
		case token.STRING:
			if strings.Contains(literal, "is_demo") {
				return true
			}
		}
	}
}

// repositoryRootFrom walks up from this package to the directory holding go.mod.
func repositoryRootFrom(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for range 8 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("go.mod is not above this package")
	return ""
}
