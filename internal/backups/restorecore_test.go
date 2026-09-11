package backups

import (
	"context"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"testing"
)

// The bulk restore path answers with a sentence per domain, and every outcome is
// pinned here in the order restoreCore checks for it.
func TestRestoreCoreAnswersEveryOutcome(t *testing.T) {
	cases := []struct {
		name    string
		entries []tarEntry
		mode    string
		setup   func(t *testing.T, f *restoreFixture)
		fail    [][]string
		imports map[string]error
		want    string
		wantErr string
	}{
		{name: "an unknown backup", entries: siteArchive(), mode: "files",
			setup:   func(_ *testing.T, f *restoreFixture) { f.script.rows[coreLookup] = nil },
			wantErr: "backup not found"},
		{name: "a failed lookup", entries: siteArchive(), mode: "files",
			setup: func(_ *testing.T, f *restoreFixture) {
				f.script.fail = map[string]error{coreLookup: errors.New("connection lost")}
			},
			wantErr: "backup lookup failed"},
		{name: "a corrupt archive", entries: siteArchive(), mode: "files",
			setup: func(_ *testing.T, f *restoreFixture) {
				f.script.rows[coreLookup] = [][]driver.Value{{"c_example", archiveName, "corrupt"}}
			},
			wantErr: "this backup is recorded as corrupt; restore it from the domain's own backup page to confirm that"},
		{name: "a system user outside the namespace", entries: siteArchive(), mode: "files",
			setup: func(_ *testing.T, f *restoreFixture) {
				f.script.rows[coreLookup] = [][]driver.Value{{"root", archiveName, ""}}
			},
			wantErr: "invalid backup file"},
		{name: "a file name with a path", entries: siteArchive(), mode: "files",
			setup: func(_ *testing.T, f *restoreFixture) {
				f.script.rows[coreLookup] = [][]driver.Value{{"c_example", "x/" + archiveName, ""}}
			},
			wantErr: "invalid backup file"},
		{name: "an archive missing on disk", mode: "files", wantErr: "backup file is missing on disk"},
		{name: "a mode the archive has nothing for", entries: []tarEntry{dumpEntry("c_example_main")}, mode: "files",
			wantErr: "the backup has no content for this restore mode"},
		{name: "a staging directory that cannot be made", entries: siteArchive(), mode: "files",
			setup:   func(t *testing.T, f *restoreFixture) { t.Setenv("TMPDIR", filepath.Join(f.root, "missing")) },
			wantErr: "could not prepare backup restore"},
		{name: "an archive that escapes its directory", entries: siteArchive(tarEntry{name: "../x", body: "x"}), mode: "files",
			wantErr: "invalid backup archive"},
		{name: "full", entries: siteArchive(dumpEntry("c_example_main")), mode: "full",
			want: "restored files and 1 database(s)"},
		{name: "full, the home copy fails", entries: siteArchive(dumpEntry("c_example_main")), mode: "full",
			fail: [][]string{{"rsync"}}, wantErr: "the home directory could not be restored"},
		{name: "full, an import fails", entries: siteArchive(dumpEntry("c_example_main")), mode: "full",
			imports: map[string]error{"c_example_main": errors.New("import refused")},
			wantErr: "files were restored but 1 database import(s) failed — c_example_main: error: import refused"},
		{name: "full, no database in the archive", entries: siteArchive(manifestOnly), mode: "full",
			wantErr: "files were restored but no database was restored — "},
		{name: "files", entries: siteArchive(), mode: "files", want: "restored files"},
		{name: "files, the home copy fails", entries: siteArchive(), mode: "files",
			fail: [][]string{{"rsync"}}, wantErr: "the home directory could not be restored"},
		{name: "database", entries: siteArchive(dumpEntry("c_example_main")), mode: "database",
			want: "restored 1 database(s)"},
		{name: "database, an import fails", entries: siteArchive(dumpEntry("c_example_main")), mode: "database",
			imports: map[string]error{"c_example_main": errors.New("import refused")},
			wantErr: "1 database import(s) failed — c_example_main: error: import refused"},
		{name: "database, no database in the archive", entries: siteArchive(manifestOnly), mode: "database",
			wantErr: "the backup has no database to restore"},
		{name: "database, every database refused", entries: siteArchive(dumpEntry("mysql")), mode: "database",
			wantErr: "no database was restored — mysql: rejected (system database)"},
		{name: "a mode only the domain page offers", entries: siteArchive(dumpEntry("c_example_main")), mode: "db",
			wantErr: "invalid restore mode"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRestoreFixture(t, "", c.entries...)
			extractingCommands(t, c.fail...)
			withImports(t, c.imports)
			if c.setup != nil {
				c.setup(t, f)
			}

			got, err := restoreCore(context.Background(), f.h.DB, 5, 9, c.mode, false)

			if c.wantErr != "" {
				if err == nil || err.Error() != c.wantErr {
					t.Fatalf("restoreCore = (%q, %v), want the error %q", got, err, c.wantErr)
				}
			} else if err != nil || got != c.want {
				t.Fatalf("restoreCore = (%q, %v), want %q", got, err, c.want)
			}
			if domainLocked(5) {
				t.Error("the domain is still held after restoreCore returned")
			}
		})
	}
}

func TestRestoreCoreRefusesABusyDomain(t *testing.T) {
	f := newRestoreFixture(t, "", siteArchive()...)
	extractingCommands(t)
	release, ok := lockDomain(5)
	if !ok {
		t.Fatal("the domain could not be claimed")
	}
	defer release()
	if _, err := restoreCore(context.Background(), f.h.DB, 5, 9, "files", false); !errors.Is(err, ErrDomainBusy) {
		t.Fatalf("restoreCore = %v, want ErrDomainBusy", err)
	}
}
