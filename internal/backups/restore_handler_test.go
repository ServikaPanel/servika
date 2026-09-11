package backups

import (
	"archive/tar"
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const (
	archiveName   = "c_example-20260101-000000.tar.gz"
	restoreLookup = "d.system_user, d.domain_name, b.file, COALESCE(b.verification,'')"
	coreLookup    = "d.system_user, b.file, COALESCE(b.verification,'')"
)

// restoreFixture is a backup root holding one archive of c_example, a database
// that answers every read a restore makes, and the handlers over it.
type restoreFixture struct {
	root   string
	script *sqlScript
	h      *Handlers
}

// newRestoreFixture writes entries as the archive (none leaves it missing) and
// answers both backup lookups with it.
func newRestoreFixture(t *testing.T, verification string, entries ...tarEntry) *restoreFixture {
	t.Helper()
	root := t.TempDir()
	t.Setenv("SERVIKA_BACKUP_ROOT", root)
	if len(entries) > 0 {
		writeTarGz(t, filepath.Join(root, "c_example", archiveName), entries...)
	}
	script := &sqlScript{rows: map[string][][]driver.Value{
		restoreLookup:   {{"c_example", "example.com", archiveName, verification}},
		coreLookup:      {{"c_example", archiveName, verification}},
		ownedListQuery:  {},
		otherOwnerQuery: {{int64(0)}},
		"SELECT size_b FROM backups WHERE id=? AND domain_id=?":              {},
		"SELECT COALESCE(sha256,'') FROM backups WHERE id=? AND domain_id=?": {},
		"SELECT remote_status FROM backups WHERE id=? AND domain_id=?":       {},
		"FROM backup_settings WHERE id=1":                                    {},
	}}
	return &restoreFixture{root: root, script: script, h: &Handlers{DB: scriptDB(t, script)}}
}

func (f *restoreFixture) restore(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	f.h.Restore(w, domainRequest(http.MethodPost, "/domains/5/backups/9/restore", body, "id", "5", "bid", "9"))
	return w
}

// siteArchive is a home with one page plus the given database members.
func siteArchive(extra ...tarEntry) []tarEntry {
	return append([]tarEntry{
		{name: "c_example/", typeflag: tar.TypeDir},
		{name: "c_example/public_html/", typeflag: tar.TypeDir},
		{name: "c_example/public_html/index.php", body: "<?php"},
	}, extra...)
}

func dumpEntry(name string) tarEntry {
	return tarEntry{name: "__db__/" + name + ".sql", body: "-- " + name}
}

var manifestOnly = tarEntry{name: "__db__/manifest.json", body: "{}"}

func responseBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return body
}

func assertRefusal(t *testing.T, w *httptest.ResponseRecorder, status int, message string) {
	t.Helper()
	if w.Code != status || responseBody(t, w)["error"] != message {
		t.Fatalf("answered %d %s, want %d %q", w.Code, w.Body.String(), status, message)
	}
}

// Every refusal before the restore touches the site, in the order the handler
// checks them.
func TestRestoreRefusesARequestItCannotServe(t *testing.T) {
	cases := []struct {
		name    string
		entries []tarEntry
		setup   func(t *testing.T, f *restoreFixture)
		body    string
		status  int
		message string
	}{
		{name: "a malformed body", entries: siteArchive(), body: `{"mode":`,
			status: http.StatusBadRequest, message: "invalid request body"},
		{name: "an unknown backup", entries: siteArchive(),
			setup:  func(_ *testing.T, f *restoreFixture) { f.script.rows[restoreLookup] = nil },
			status: http.StatusNotFound, message: "backup not found"},
		{name: "a failed lookup", entries: siteArchive(),
			setup: func(_ *testing.T, f *restoreFixture) {
				f.script.fail = map[string]error{restoreLookup: errors.New("connection lost")}
			},
			status: http.StatusInternalServerError, message: "internal server error"},
		{name: "a system user outside the namespace", entries: siteArchive(),
			setup: func(_ *testing.T, f *restoreFixture) {
				f.script.rows[restoreLookup] = [][]driver.Value{{"root", "example.com", archiveName, ""}}
			},
			status: http.StatusBadRequest, message: "invalid system user"},
		{name: "a file name with a path", entries: siteArchive(),
			setup: func(_ *testing.T, f *restoreFixture) {
				f.script.rows[restoreLookup] = [][]driver.Value{{"c_example", "example.com", "../" + archiveName, ""}}
			},
			status: http.StatusBadRequest, message: "invalid backup file"},
		{name: "an empty file name", entries: siteArchive(),
			setup: func(_ *testing.T, f *restoreFixture) {
				f.script.rows[restoreLookup] = [][]driver.Value{{"c_example", "example.com", "", ""}}
			},
			status: http.StatusBadRequest, message: "invalid backup file"},
		{name: "an archive missing on disk",
			status: http.StatusNotFound, message: "backup file is missing on disk"},
		{name: "a RAR archive", entries: siteArchive(),
			setup:  func(t *testing.T, f *restoreFixture) { renameArchive(t, f, "c_example.rar") },
			status: http.StatusBadRequest, message: "unsupported backup archive"},
		{name: "an archive of unknown type", entries: siteArchive(),
			setup:  func(t *testing.T, f *restoreFixture) { renameArchive(t, f, "c_example.bin") },
			status: http.StatusBadRequest, message: "unsupported backup archive"},
		{name: "a mode the archive has nothing for", entries: []tarEntry{dumpEntry("c_example_main")},
			body:   `{"mode":"files"}`,
			status: http.StatusBadRequest, message: "the backup has no content for this restore mode"},
		{name: "a staging directory that cannot be made", entries: siteArchive(),
			setup:  func(t *testing.T, f *restoreFixture) { t.Setenv("TMPDIR", filepath.Join(f.root, "missing")) },
			status: http.StatusInternalServerError, message: "could not prepare backup restore"},
		{name: "an archive that escapes its directory", entries: siteArchive(tarEntry{name: "/etc/cron.d/x", body: "x"}),
			status: http.StatusBadRequest, message: "invalid backup archive"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRestoreFixture(t, "", c.entries...)
			commands := extractingCommands(t)
			if c.setup != nil {
				c.setup(t, f)
			}
			assertRefusal(t, f.restore(t, c.body), c.status, c.message)
			if commands.ran("rsync") {
				t.Error("the home was restored after a refusal")
			}
			if domainLocked(5) {
				t.Error("the domain is still held after the refusal")
			}
		})
	}
}

// renameArchive moves the fixture archive to name and points the lookup at it.
func renameArchive(t *testing.T, f *restoreFixture, name string) {
	t.Helper()
	dir := filepath.Join(f.root, "c_example")
	if err := os.Rename(filepath.Join(dir, archiveName), filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	f.script.rows[restoreLookup] = [][]driver.Value{{"c_example", "example.com", name, ""}}
	f.script.rows[coreLookup] = [][]driver.Value{{"c_example", name, ""}}
}

// The integrity scan's corrupt verdict takes an explicit override.
func TestRestoreOfACorruptArchiveNeedsTheOverride(t *testing.T) {
	f := newRestoreFixture(t, "corrupt", siteArchive()...)
	extractingCommands(t)
	assertRefusal(t, f.restore(t, `{"mode":"files"}`), http.StatusConflict,
		"this backup is recorded as corrupt; restore it only by confirming that explicitly")

	if w := f.restore(t, `{"mode":"files","allow_corrupt":true}`); w.Code != http.StatusOK {
		t.Fatalf("the confirmed restore answered %d: %s", w.Code, w.Body.String())
	}
}

func TestRestoreRefusesABusyDomain(t *testing.T) {
	f := newRestoreFixture(t, "", siteArchive()...)
	extractingCommands(t)
	release, ok := lockDomain(5)
	if !ok {
		t.Fatal("the domain could not be claimed")
	}
	defer release()
	assertRefusal(t, f.restore(t, `{"mode":"files"}`), http.StatusConflict, ErrDomainBusy.Error())
}

// An empty body is a full restore: the home and every database, with the
// strategy named in the answer.
func TestRestoreFullRestoresTheHomeAndTheDatabases(t *testing.T) {
	f := newRestoreFixture(t, "", siteArchive(dumpEntry("c_example_main"))...)
	commands := extractingCommands(t)
	imports := withImports(t, nil)

	w := f.restore(t, `{"clean":true}`)

	if w.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", w.Code, w.Body.String())
	}
	want := map[string]any{
		"ok": true, "mode": "full", "domain_name": "example.com", "file": archiveName,
		"databases": []any{map[string]any{"db": "c_example_main", "status": "restored"}},
		"warning":   "Clean restore: files missing from the backup were DELETED and database tables were recreated.",
	}
	if got := responseBody(t, w); !reflect.DeepEqual(got, want) {
		t.Errorf("body = %v, want %v", got, want)
	}
	if imports.imported["c_example_main"] != "-- c_example_main" {
		t.Errorf("imported = %v", imports.imported)
	}
	assertHomeRestored(t, commands, filepath.Join(f.root, "c_example", archiveName), []string{"c_example", "__db__"}, true)
	if progress := progressRead(5); !progress.Done || progress.Error != "" {
		t.Errorf("progress = %+v, want a finished record without an error", progress)
	}
	if domainLocked(5) {
		t.Error("the domain is still held after the restore")
	}
}

// assertHomeRestored checks the extraction and the three home commands.
func assertHomeRestored(t *testing.T, commands *commandRecorder, abs string, members []string, clean bool) {
	t.Helper()
	var extract, rsync []string
	for _, argv := range commands.argvs() {
		switch {
		case hasArgvPrefix(argv, []string{"tar", "-xz", "-f", abs, "-C"}):
			extract = argv
		case hasArgvPrefix(argv, []string{"rsync"}):
			rsync = argv
		}
	}
	if extract == nil || !slices.Equal(extract[6:], members) {
		t.Fatalf("extraction = %v, want the members %v", extract, members)
	}
	wantRsync := []string{"rsync", "-a"}
	if clean {
		wantRsync = append(wantRsync, "--delete")
	}
	wantRsync = append(wantRsync, extract[5]+"/c_example/", "/home/c_example/")
	if !slices.Equal(rsync, wantRsync) {
		t.Errorf("rsync = %v, want %v", rsync, wantRsync)
	}
	if !commands.ran("chown", "-R", "c_example:c_example", "/home/c_example") ||
		!commands.ran("restorecon", "-R", "/home/c_example") {
		t.Errorf("the ownership and labels were not restored: %v", commands.argvs())
	}
}

func TestRestoreFullReportsWhatDidNotComeBack(t *testing.T) {
	cases := []struct {
		name    string
		entries []tarEntry
		fail    [][]string
		imports map[string]error
		message string
	}{
		{name: "the home copy fails", entries: siteArchive(dumpEntry("c_example_main")), fail: [][]string{{"rsync"}},
			message: "could not restore the home directory"},
		{name: "a database import fails", entries: siteArchive(dumpEntry("c_example_main")),
			imports: map[string]error{"c_example_main": errors.New("import refused")},
			message: "files were restored but a database import failed — c_example_main: error: import refused"},
		{name: "the archive holds no database", entries: siteArchive(manifestOnly),
			message: "files were restored but no database was restored — "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRestoreFixture(t, "", c.entries...)
			extractingCommands(t, c.fail...)
			withImports(t, c.imports)

			assertRefusal(t, f.restore(t, ""), http.StatusInternalServerError, c.message)
			if progress := progressRead(5); progress.Error != "the restore did not complete" {
				t.Errorf("progress = %+v, want the incomplete restore recorded", progress)
			}
		})
	}
}

func TestRestoreFilesRestoresOnlyTheHome(t *testing.T) {
	f := newRestoreFixture(t, "", siteArchive(dumpEntry("c_example_main"))...)
	commands := extractingCommands(t)
	imports := withImports(t, nil)

	w := f.restore(t, `{"mode":"files"}`)

	want := map[string]any{
		"ok": true, "mode": "files", "domain_name": "example.com", "file": archiveName,
		"warning": "Files from the backup were written over the live ones; active files missing from the backup were kept.",
	}
	if got := responseBody(t, w); w.Code != http.StatusOK || !reflect.DeepEqual(got, want) {
		t.Fatalf("answered %d %v, want %v", w.Code, got, want)
	}
	assertHomeRestored(t, commands, filepath.Join(f.root, "c_example", archiveName), []string{"c_example"}, false)
	if len(imports.imported) != 0 {
		t.Errorf("a files-only restore imported %v", imports.imported)
	}

	g := newRestoreFixture(t, "", siteArchive()...)
	extractingCommands(t, []string{"rsync"})
	assertRefusal(t, g.restore(t, `{"mode":"files"}`), http.StatusInternalServerError, "could not restore the home directory")
}

func TestRestoreDatabaseModeSeparatesItsOutcomes(t *testing.T) {
	cases := []struct {
		name    string
		entries []tarEntry
		body    string
		imports map[string]error
		status  int
		field   string
		message string
	}{
		{name: "restored", entries: siteArchive(dumpEntry("c_example_main")), body: `{"mode":"database","db":" c_example_main "}`,
			status: http.StatusOK, field: "warning", message: "1 database(s) restored — c_example_main: restored"},
		{name: "an import fails", entries: siteArchive(dumpEntry("c_example_main")), body: `{"mode":"database"}`,
			imports: map[string]error{"c_example_main": errors.New("import refused")},
			status:  http.StatusInternalServerError, field: "error", message: "a database import failed — c_example_main: error: import refused"},
		{name: "the archive holds no database", entries: siteArchive(manifestOnly), body: `{"mode":"database"}`,
			status: http.StatusBadRequest, field: "error", message: "the backup has no database to restore"},
		{name: "every database is refused", entries: siteArchive(dumpEntry("mysql")), body: `{"mode":"database"}`,
			status: http.StatusBadRequest, field: "error", message: "no database was restored — mysql: rejected (system database)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRestoreFixture(t, "", c.entries...)
			commands := extractingCommands(t)
			withImports(t, c.imports)

			w := f.restore(t, c.body)

			if w.Code != c.status || responseBody(t, w)[c.field] != c.message {
				t.Fatalf("answered %d %s, want %d %s=%q", w.Code, w.Body.String(), c.status, c.field, c.message)
			}
			if commands.ran("rsync") {
				t.Error("a database restore touched the home")
			}
		})
	}
}

// The selected files land in a folder or in place, and the answer says which.
func TestRestoreFileModeReportsWhereTheFilesWent(t *testing.T) {
	cases := []struct {
		name   string
		count  int
		folder string
		err    error
		status int
		want   map[string]any
	}{
		{name: "into a folder", count: 2, folder: "restore-20260101-000000", status: http.StatusOK,
			want: map[string]any{"file_count": float64(2), "target_folder": "restore-20260101-000000",
				"warning": "The selected files were extracted into restore-20260101-000000/; existing files were kept."}},
		{name: "in place", count: 1, status: http.StatusOK,
			want: map[string]any{"file_count": float64(1), "warning": "The selected files were written back to their original locations."}},
		{name: "the copy fails", err: errors.New("openat2"), status: http.StatusInternalServerError,
			want: map[string]any{"error": "could not restore the selected files"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRestoreFixture(t, "", siteArchive()...)
			extractingCommands(t)
			var gotPaths []string
			var gotTarget, gotUser string
			var extracted bool
			setForTest(t, &restoreSelected, func(_ context.Context, tmp, systemUser string, paths []string, target string) (int, string, error) {
				gotPaths, gotTarget, gotUser = paths, target, systemUser
				_, statErr := os.Stat(filepath.Join(tmp, "c_example", "public_html", "index.php"))
				extracted = statErr == nil
				return c.count, c.folder, c.err
			})

			w := f.restore(t, `{"mode":"file","paths":["public_html/index.php"],"target":"in_place"}`)

			body := responseBody(t, w)
			for key, value := range c.want {
				if !reflect.DeepEqual(body[key], value) {
					t.Errorf("%s = %v, want %v", key, body[key], value)
				}
			}
			if w.Code != c.status {
				t.Errorf("answered %d, want %d", w.Code, c.status)
			}
			if !extracted || gotUser != "c_example" || gotTarget != "in_place" || !slices.Equal(gotPaths, []string{"public_html/index.php"}) {
				t.Errorf("the copy got (%t, %q, %q, %v)", extracted, gotUser, gotTarget, gotPaths)
			}
		})
	}
}

func TestRestoreDBModeRestoresOneDatabase(t *testing.T) {
	cases := []struct {
		name, body string
		status     int
		field      string
		message    string
	}{
		{"no database named", `{"mode":"db","db":"  "}`, http.StatusBadRequest, "error", "no database was selected"},
		{"a database not in the backup", `{"mode":"db","db":"c_example_missing"}`, http.StatusBadRequest, "error",
			`database "c_example_missing" is not in the backup`},
		{"over itself", `{"mode":"db","db":" c_example_main ","target_db":" "}`, http.StatusOK, "databases", "restored over c_example_main"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRestoreFixture(t, "", siteArchive(dumpEntry("c_example_main"))...)
			extractingCommands(t)
			withImports(t, nil)

			w := f.restore(t, c.body)

			if w.Code != c.status || responseBody(t, w)[c.field] != c.message {
				t.Fatalf("answered %d %s, want %d %s=%q", w.Code, w.Body.String(), c.status, c.field, c.message)
			}
			if !strings.Contains(w.Body.String(), `"`+c.field+`"`) {
				t.Errorf("the answer has no %s field", c.field)
			}
		})
	}
}
