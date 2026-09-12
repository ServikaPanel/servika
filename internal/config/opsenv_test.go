package config

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The ops tools each carry their own copy of load_servika_env, and that
// duplication is deliberate.
//
// A sourced library is the obvious alternative and it is the wrong one HERE.
// assets/ops/servika-offsite-lib shows the pattern the repository already uses
// for shared shell code, and its callers source it BEST EFFORT, because a
// release where the library has not landed yet must still work: servika-update
// installs servika-db-backup before the ops loop, to take the pre-update dump.
// Reading the environment cannot be best effort. A tool that fails to load
// /etc/servika/env knows no paths, no port and no DSN, so a missing or stale
// library would break the update path outright rather than degrade it.
//
// What the duplication really costs is DRIFT: a fix applied to ten copies and
// not the eleventh is a bug that shows up on one tool only. The measured
// incident was the opposite case, a locale-collation bug that hit every copy at
// once and made the loader skip SERVIKA_LISTEN, which broke servika-update.
// This test is what turns a partial fix into a build failure.
//
// Only the PARSE LOOP is compared. servika-verify's permission block reports a
// reason instead of exiting, which is its whole purpose, and that difference is
// deliberate.
var (
	loaderBody = regexp.MustCompile(`(?ms)^load_servika_env\(\) \{.*?^\}`)
	parseLoop  = regexp.MustCompile(`(?ms)^\s*while IFS= read -r line.*?^\s*done < "\$ENV_FILE"`)
)

// opsScriptsWithLoader returns every ops tool that defines the loader.
func opsScriptsWithLoader(t *testing.T) map[string]string {
	t.Helper()
	dir := filepath.Join("..", "..", "assets", "ops")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the ops directory: %v", err)
	}
	found := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		if loader := loaderBody.Find(body); loader != nil {
			found[entry.Name()] = string(loader)
		}
	}
	return found
}

func TestTheOpsEnvironmentLoaderDoesNotDrift(t *testing.T) {
	scripts := opsScriptsWithLoader(t)
	if len(scripts) < 2 {
		t.Fatalf("found %d ops tools with a loader, expected the whole set", len(scripts))
	}

	loops := map[string][]string{}
	for name, loader := range scripts {
		loop := parseLoop.FindString(loader)
		if loop == "" {
			t.Errorf("%s has a loader with no recognisable parse loop", name)
			continue
		}
		loops[loop] = append(loops[loop], name)
	}
	if len(loops) <= 1 {
		return
	}

	var report []string
	for loop, names := range loops {
		sort.Strings(names)
		report = append(report, strings.Join(names, ", ")+":\n"+loop)
	}
	sort.Strings(report)
	t.Errorf("the ops environment loaders have drifted into %d different parse loops:\n\n%s",
		len(loops), strings.Join(report, "\n\n"))
}

// The loader must keep reading keys with POSIX classes. A character RANGE is
// collation-ordered, and under tr_TR.UTF-8 `a-z` excludes `i`, so `[A-Za-z0-9_]`
// silently skipped SERVIKA_LISTEN and broke servika-update. Every script also
// pins LC_ALL, and both halves of that fix have to stay.
func TestTheOpsEnvironmentLoaderKeepsItsLocaleFix(t *testing.T) {
	dir := filepath.Join("..", "..", "assets", "ops")
	for name, loader := range opsScriptsWithLoader(t) {
		if !strings.Contains(loader, "[[:alnum:]_]") {
			t.Errorf("%s parses keys without a POSIX class, so a Turkish locale cuts the key at its first i", name)
		}
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !strings.Contains(string(body), "export LC_ALL=C") {
			t.Errorf("%s does not pin LC_ALL, so its own ranges are collation-ordered", name)
		}
	}
}
