package antivirus

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"servika/internal/avsettings"
)

// A sweep reaches files outside every tenant home, so the tenant a finding
// belongs to is read from its PATH. Getting this wrong in either direction is
// worse than not resolving it at all: a finding attributed to the wrong tenant
// puts a neighbour's file on their screen, and one attributed to nobody cannot
// be quarantined.
func TestTheTenantIsReadFromThePathAndOnlyFromATenantHome(t *testing.T) {
	cases := []struct {
		path string
		user string
		ok   bool
	}{
		{"/home/c_example/public_html/shell.php", "c_example", true},
		{"/home/c_example/mail/x.php", "c_example", true},
		// The tenant prefix is what every other part of the panel keys on, so a
		// directory somebody made under /home by hand is not a tenant.
		{"/home/backups/shell.php", "", false},
		{"/home/ubuntu/shell.php", "", false},
		// Outside /home there is no tenant at all.
		{"/var/www/shell.php", "", false},
		{"/tmp/c_example/shell.php", "", false},
		// A path that stops at the home directory itself names no file in it.
		{"/home/c_example", "", false},
		{"/home/", "", false},
		{"/home", "", false},
		{"", "", false},
		// A name that merely starts with the same letters is a different tenant.
		{"/home/c_examplex/public_html/a.php", "c_examplex", true},
	}
	for _, c := range cases {
		user, ok := systemUserFromPath(c.path)
		if ok != c.ok || user != c.user {
			t.Errorf("systemUserFromPath(%q) = (%q, %v), want (%q, %v)",
				c.path, user, ok, c.user, c.ok)
		}
	}
}

// The sweep and a domain scan must inspect the same way. What differs is the
// roots and the exclusion list, not the rules.
func TestTheSweepAppliesTheExclusionListToTheWalk(t *testing.T) {
	root := t.TempDir()
	shell := []byte("<?php eval($_POST['c']); ?>")

	if err := os.WriteFile(filepath.Join(root, "found.php"), shell, 0o600); err != nil {
		t.Fatal(err)
	}
	skipped := filepath.Join(root, "cache")
	if err := os.MkdirAll(skipped, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skipped, "hidden.php"), shell, 0o600); err != nil {
		t.Fatal(err)
	}

	req := DefaultRequest(root)
	_, findings, _ := runScan(context.Background(), root, req)
	if len(findings) != 2 {
		t.Fatalf("without an exclusion list both webshells must be found, got %d: %v",
			len(findings), findings)
	}

	req.Excluded = []string{"/cache/"}
	_, findings, _ = runScan(context.Background(), root, req)
	if len(findings) != 1 {
		t.Fatalf("with /cache/ excluded one webshell must remain, got %d: %v",
			len(findings), findings)
	}
	if !strings.HasSuffix(findings[0].File, "found.php") {
		t.Errorf("the wrong file survived the exclusion: %s", findings[0].File)
	}
}

// An excluded directory is skipped WHOLE. Testing each file inside it instead
// would still walk /proc and /sys entry by entry, which is most of what the
// exclusion list exists to avoid.
func TestAnExcludedDirectoryIsNotDescendedInto(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "excluded", "a", "b", "c")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	// A file no read could succeed on: if the walk descends and opens it, the
	// scan behaves differently from one that skipped the directory.
	blocked := filepath.Join(deep, "x.php")
	if err := os.WriteFile(blocked, []byte("<?php eval($_POST['c']); ?>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o600) })

	req := DefaultRequest(root)
	req.Excluded = []string{"/excluded/"}
	scanned, findings, complete := runScan(context.Background(), root, req)
	if scanned != 0 {
		t.Errorf("the walk descended into an excluded directory: %d files counted", scanned)
	}
	if len(findings) != 0 {
		t.Errorf("an excluded directory still produced findings: %v", findings)
	}
	if !complete {
		t.Error("skipping an excluded directory was reported as an incomplete scan")
	}
}

// Both sides call one function, or the screen would describe an exclusion the
// scanner does not apply.
func TestTheScannerAndTheSettingsAgreeOnWhatIsExcluded(t *testing.T) {
	settings := avsettings.Settings{ExcludedPaths: "/proc\nnode_modules/\n"}
	list := settings.ExcludedList()
	for _, path := range []string{
		"/proc/1/cmdline",
		"/home/c_a/public_html/node_modules/x/index.js",
		"/home/c_a/public_html/index.php",
		"/procedures/x.php",
	} {
		if settings.Excluded(path) != avsettings.PathExcluded(list, path) {
			t.Errorf("the two exclusion tests disagree on %q", path)
		}
	}
}

// clamscan is handed the root and walks it itself, so it cannot be told about
// the exclusion list. Running it for a sweep of / would read every data file on
// the machine, which is exactly the cost the list exists to avoid.
func TestClamAVIsNotRunForASweepThatCarriesAnExclusionList(t *testing.T) {
	body, err := os.ReadFile("antivirus.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "err == nil && len(req.Excluded) == 0") {
		t.Error("clamscan is run with an exclusion list it cannot honour")
	}
}

// The sweep writes its scan row with a NULL domain and its own scope, and
// resolves a domain per finding. A single domain id for the whole sweep would
// attribute every finding on the server to one tenant.
func TestTheSweepRecordsNoDomainForItselfAndOnePerFinding(t *testing.T) {
	body, err := os.ReadFile("sweep.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	if !strings.Contains(source, "INSERT INTO av_scans (domain_id, scope, status, engine) VALUES (NULL,?,?,?)") {
		t.Error("the sweep no longer records itself with a NULL domain and a scope")
	}
	if !strings.Contains(source, "insertSweepFinding(h.DB, sid, owners.forPath(f.File), f)") {
		t.Error("the sweep no longer resolves a domain per finding")
	}
	if !strings.Contains(source, "domain_id IS NULL") {
		t.Error("the sweep status query no longer restricts itself to sweeps")
	}
	// A sweep that would inspect nothing is refused rather than recorded as a
	// finished scan with no findings, which reads exactly like a clean server.
	if !strings.Contains(source, "every detection layer is switched off") {
		t.Error("a sweep with every layer off is no longer refused")
	}
}

// A sweep finding outside every tenant home is REFUSED containment rather than
// contained somewhere generic. The quarantine store is one directory per tenant
// and RemoveStoreForUser refuses any name without the tenant prefix, so there is
// nowhere for such a file to go.
func TestASweepFindingWithNoTenantCannotBeQuarantined(t *testing.T) {
	body, err := os.ReadFile("sweep.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	if !strings.Contains(source, "if !domainID.Valid {") ||
		!strings.Contains(source, "return 0, \"\", reasonPathOutsideHome") {
		t.Error("a finding outside every tenant home is no longer refused containment")
	}
	// The tenant is read from the finding's own row. Accepting it from the
	// request would let an admin name a domain the file does not belong to, and
	// the containment writes into that domain's store.
	if !strings.Contains(source, "SELECT domain_id FROM av_findings WHERE id=?") {
		t.Error("the tenant is no longer read from the finding row")
	}
	if !strings.Contains(source, "h.quarantineFinding(domainID, systemUser, fid)") {
		t.Error("the sweep no longer reuses the per-domain containment")
	}
}
