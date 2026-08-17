package sitesecurity

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func names(packages []Package) []string {
	out := make([]string, 0, len(packages))
	for _, pkg := range packages {
		out = append(out, pkg.Name+"@"+pkg.Version)
	}
	slices.Sort(out)
	return out
}

// npm lockfile v3: every installed package is keyed by its path, and the
// package name is everything after the LAST node_modules segment. Reading the
// first one instead would call a nested dependency by its parent's name and
// query the feed for the wrong package.
func TestTheNPMPathKeyNamesTheDeepestPackage(t *testing.T) {
	body := []byte(`{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "my-app", "version": "1.0.0"},
	    "node_modules/lodash": {"version": "4.17.15"},
	    "node_modules/a/node_modules/b": {"version": "2.0.0"},
	    "node_modules/a/node_modules/@scope/c": {"version": "3.1.0"}
	  }
	}`)
	got, err := ParseNPMLock(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"@scope/c@3.1.0", "b@2.0.0", "lodash@4.17.15"}
	if !slices.Equal(names(got), want) {
		t.Errorf("got %q, want %q", names(got), want)
	}
}

// The root project is keyed by the empty string. It is the application itself,
// not a dependency, and no feed has advisories for it.
func TestTheRootProjectIsNotADependency(t *testing.T) {
	body := []byte(`{"packages": {"": {"name": "my-app", "version": "1.0.0"}}}`)
	got, err := ParseNPMLock(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("the root project was reported as a dependency: %q", names(got))
	}
}

// npm 6 lockfiles are still in the wild. Read as v3 they yield nothing at all
// rather than an error, so the whole site would look clean.
func TestTheVersionOneLayoutIsReadToo(t *testing.T) {
	body := []byte(`{
	  "lockfileVersion": 1,
	  "dependencies": {
	    "lodash": {"version": "4.17.15"},
	    "express": {"version": "4.17.1", "dependencies": {"qs": {"version": "6.7.0"}}}
	  }
	}`)
	got, err := ParseNPMLock(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"express@4.17.1", "lodash@4.17.15", "qs@6.7.0"}
	if !slices.Equal(names(got), want) {
		t.Errorf("got %q, want %q", names(got), want)
	}
}

// One package at one version appears many times in a deep tree. Each copy would
// otherwise be a separate feed query and a separate row saying the same thing.
func TestOnePackageAtOneVersionIsReportedOnce(t *testing.T) {
	body := []byte(`{
	  "packages": {
	    "node_modules/lodash": {"version": "4.17.15"},
	    "node_modules/a/node_modules/lodash": {"version": "4.17.15"},
	    "node_modules/b/node_modules/lodash": {"version": "4.17.21"}
	  }
	}`)
	got, err := ParseNPMLock(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"lodash@4.17.15", "lodash@4.17.21"}
	if !slices.Equal(names(got), want) {
		t.Errorf("got %q, want %q", names(got), want)
	}
}

// A tenant file with a huge dependency list must not turn into an unbounded
// number of feed requests.
func TestTheDependencyCountIsCapped(t *testing.T) {
	var builder strings.Builder
	builder.WriteString(`{"packages": {`)
	for i := range maxPackagesPerLockfile + 500 {
		if i > 0 {
			builder.WriteByte(',')
		}
		fmt.Fprintf(&builder, `"node_modules/pkg%d": {"version": "1.0.0"}`, i)
	}
	builder.WriteString(`}}`)

	got, err := ParseNPMLock([]byte(builder.String()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) > maxPackagesPerLockfile {
		t.Errorf("got %d packages, want at most %d", len(got), maxPackagesPerLockfile)
	}
}

// A malformed lockfile is an error the caller drops the installation over, not
// a panic and not a silent empty list that reads as "no dependencies".
func TestMalformedInputIsAnError(t *testing.T) {
	for _, body := range []string{"", "not json", "[]", `{"packages": "text"}`} {
		if _, err := ParseNPMLock([]byte(body)); err == nil {
			t.Errorf("ParseNPMLock accepted %q", body)
		}
	}
	for _, body := range []string{"", "not json", `{"packages": {"a": 1}}`} {
		if _, err := ParseComposerLock([]byte(body)); err == nil {
			t.Errorf("ParseComposerLock accepted %q", body)
		}
	}
}

func TestComposerReadsTheProductionPackagesOnly(t *testing.T) {
	body := []byte(`{
	  "packages": [
	    {"name": "monolog/monolog", "version": "1.10.0"},
	    {"name": "guzzlehttp/guzzle", "version": "v7.4.0"}
	  ],
	  "packages-dev": [
	    {"name": "phpunit/phpunit", "version": "9.5.0"}
	  ]
	}`)
	got, err := ParseComposerLock(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"guzzlehttp/guzzle@v7.4.0", "monolog/monolog@1.10.0"}
	if !slices.Equal(names(got), want) {
		t.Errorf("got %q, want %q", names(got), want)
	}
}

// A branch install has no orderable version, so it is dropped here rather than
// counted as something the sweep failed to judge.
func TestAComposerBranchInstallIsDropped(t *testing.T) {
	body := []byte(`{"packages": [
	  {"name": "a/b", "version": "dev-main"},
	  {"name": "c/d", "version": "1.x-dev"},
	  {"name": "e/f", "version": "2.0.0"}
	]}`)
	got, err := ParseComposerLock(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !slices.Equal(names(got), []string{"e/f@2.0.0"}) {
		t.Errorf("got %q, want only e/f@2.0.0", names(got))
	}
}
