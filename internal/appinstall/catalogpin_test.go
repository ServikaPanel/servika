package appinstall

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// migrationsDir is where the catalog's seed and every later correction live.
const migrationsDir = "../../migrations"

// readMigrations returns every migration file, in the order the runner applies
// them.
func readMigrations(t *testing.T) []string {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(migrationsDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".sql") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the migrations: %v", err)
	}
	// WalkDir returns lexical order, which is the order the runner applies.
	return paths
}

// catalogVersion returns the version a code is pinned at after every migration
// has run: the seed, then each UPDATE that moves it.
func catalogVersion(t *testing.T, code string) string {
	t.Helper()
	seed := regexp.MustCompile(`\('` + regexp.QuoteMeta(code) + `', '[^']*', '([^']*)'`)
	update := regexp.MustCompile(`(?s)UPDATE app_catalog\s+SET version\s*=\s*'([^']*)'.*?WHERE code = '` +
		regexp.QuoteMeta(code) + `'`)

	version := ""
	for _, path := range readMigrations(t) {
		body, err := os.ReadFile(path) // #nosec G304 -- a repository path this test walked.
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(body)
		if match := seed.FindStringSubmatch(text); match != nil {
			version = match[1]
		}
		if match := update.FindStringSubmatch(text); match != nil {
			version = match[1]
		}
	}
	return version
}

// The seeded pin 2.0.19 is inside the affected range of GHSA-8hgv-xc77-jmcr
// (CVE-2026-86197), fixed in 2.0.20: Grav 2.0 renders editor-authored Twig in
// page content by default and the shipped sandbox policy allowlists addcss and
// addjs on Grav\Common\Assets, so an account holding only page-edit rights can
// register arbitrary script into rendered pages and escalate to super-admin.
//
// The panel places the files and pins the digest, so the installation looks
// vouched for; the digest says nothing about whether the release is vulnerable.
func TestTheGravPinIsPastTheTwigSandboxAdvisory(t *testing.T) {
	version := catalogVersion(t, "grav")
	if version == "" {
		t.Fatal("no Grav version is pinned in the migrations")
	}
	if !atLeastVersion(version, "2.0.20") {
		t.Fatalf("Grav is pinned at %s, inside the range CVE-2026-86197 fixes in 2.0.20", version)
	}
}

// A moved pin whose digest was not moved with it installs nothing at all: the
// installer refuses an archive that does not match. The two have to travel
// together.
func TestTheMovedGravPinCarriesItsOwnDigestAndURL(t *testing.T) {
	version := catalogVersion(t, "grav")

	var correction string
	for _, path := range readMigrations(t) {
		body, err := os.ReadFile(path) // #nosec G304 -- a repository path this test walked.
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(body), "UPDATE app_catalog") && strings.Contains(string(body), "'grav'") {
			correction = string(body)
		}
	}
	if correction == "" {
		t.Fatal("the Grav pin was never corrected")
	}
	if !strings.Contains(correction, "/download/"+version+"/grav-admin-v"+version+".zip") {
		t.Errorf("the URL does not name the pinned version %s", version)
	}
	if !regexp.MustCompile(`sha256\s*=\s*'[0-9a-f]{64}'`).MatchString(correction) {
		t.Error("the correction carries no 64-character sha256")
	}
	// The archive still wraps everything in one directory, so strip_components
	// must NOT be changed; a correction that touched it would be a silent change
	// to where the files land.
	if strings.Contains(correction, "strip_components") {
		t.Error("the correction changes strip_components, which the archive shape does not call for")
	}
}

// atLeastVersion compares two dotted numeric versions.
func atLeastVersion(have, want string) bool {
	haveParts := strings.Split(have, ".")
	wantParts := strings.Split(want, ".")
	for i := range max(len(haveParts), len(wantParts)) {
		h, w := partAt(haveParts, i), partAt(wantParts, i)
		if h != w {
			return h > w
		}
	}
	return true
}

func partAt(parts []string, i int) int {
	if i >= len(parts) {
		return 0
	}
	value := 0
	for _, r := range parts[i] {
		if r < '0' || r > '9' {
			return value
		}
		value = value*10 + int(r-'0')
	}
	return value
}
