package hostapps

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// migrationsDir holds the catalog's seed and every later correction.
const migrationsDir = "../../migrations"

// catalogEnabled reports whether a host-app catalog entry is offered after every
// migration has run: the seed, then each UPDATE that changes it.
func catalogEnabled(t *testing.T, code string) (enabled, seeded bool) {
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

	// The seed's enabled flag is the last value of the row's tuple.
	seed := regexp.MustCompile(`\('` + regexp.QuoteMeta(code) + `',[^;]*?,(\d)\)[,;]`)
	// An UPDATE naming this code, in a statement that sets enabled.
	update := regexp.MustCompile(`UPDATE host_app_catalog SET enabled = (\d)[^;]*?'` +
		regexp.QuoteMeta(code) + `'`)

	for _, path := range paths {
		body, err := os.ReadFile(path) // #nosec G304 -- a repository path this test walked.
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(body)
		if match := seed.FindStringSubmatch(text); match != nil {
			enabled, seeded = match[1] == "1", true
		}
		if match := update.FindStringSubmatch(text); match != nil {
			enabled = match[1] == "1"
		}
	}
	return enabled, seeded
}

// CVE-2026-50884 lets a low-privilege user of Statping-ng escalate to
// Administrator, and its range is {introduced: 0, last_affected: 0.93.0} with no
// fixed event: 0.93.0 is upstream's newest release, so there is nothing to
// upgrade to. An install button for it offers a status page any low-privilege
// user can take over, pinned and vouched for by the panel.
func TestStatpingIsNotOfferedWhileItsEscalationHasNoFix(t *testing.T) {
	enabled, seeded := catalogEnabled(t, "statping")
	if !seeded {
		t.Fatal("the Statping catalog row is not in the migrations at all")
	}
	if enabled {
		t.Fatal("Statping-ng is offered although CVE-2026-50884 has no fixed release")
	}
}

// The row is withheld, not removed: the entry stays visible with its version so
// an operator sees what is being held back, and one UPDATE brings it back once
// upstream ships a fixed build.
func TestTheWithheldEntryIsKeptRatherThanDeleted(t *testing.T) {
	var deletes int
	err := filepath.WalkDir(migrationsDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".sql") {
			return err
		}
		body, readErr := os.ReadFile(path) // #nosec G304 -- a repository path this test walked.
		if readErr != nil {
			return readErr
		}
		if regexp.MustCompile(`DELETE FROM host_app_catalog[^;]*'statping'`).Match(body) {
			deletes++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the migrations: %v", err)
	}
	if deletes > 0 {
		t.Fatal("the Statping row is deleted rather than withheld, so an operator cannot see what is missing")
	}
}

// The same treatment the other two withheld entries already get, so one reading
// of the catalog explains all three.
func TestTheOtherWithheldEntriesStayWithheld(t *testing.T) {
	for _, code := range []string{"teamspeak", "minio"} {
		enabled, seeded := catalogEnabled(t, code)
		if !seeded {
			t.Errorf("the %s catalog row is not in the migrations", code)
			continue
		}
		if enabled {
			t.Errorf("%s is offered again although it was deliberately withheld", code)
		}
	}
}
