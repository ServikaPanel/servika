package backups

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// writeGzip writes content gzip-compressed at path, for an archive whose tar
// stream is not a tar stream at all.
func writeGzip(t *testing.T, path, content string) {
	t.Helper()
	file, err := os.Create(path) // #nosec G304 -- a path under the test's temporary directory.
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	zipped := gzip.NewWriter(file)
	if _, err := zipped.Write([]byte(content)); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := zipped.Close(); err != nil {
		t.Fatalf("close the gzip stream: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
}

// The members a restore extracts decide what it can overwrite, so each mode is
// pinned against an archive in the current layout and in the legacy one.
func TestMembersForModePicksWhatEachModeExtracts(t *testing.T) {
	current := []string{
		"c_example", "c_example/public_html/index.php",
		"__db__/c_example_main.sql", "__db__/manifest.json",
		"c_example/public_html/nested.sql",
	}
	legacy := []string{"dump.sql", "old.sql", "c_example/public_html/nested.sql"}
	homeless := []string{"__db__/c_example_main.sql"}

	cases := []struct {
		name    string
		mode    string
		members []string
		paths   []string
		want    []string
	}{
		{"files with a home", "files", current, nil, []string{"c_example"}},
		{"files without a home", "files", homeless, nil, nil},
		{"database in the current layout", "database", current, nil, []string{"__db__"}},
		{"db in the legacy layout", "db", legacy, nil, []string{"dump.sql", "old.sql"}},
		{"full in the current layout", "full", current, nil, []string{"c_example", "__db__"}},
		{"full without a home", "full", homeless, nil, []string{"__db__"}},
		// A nested .sql under the home is a file, not a dump, and it marks the home.
		{"full in the legacy layout", "full", legacy, nil, []string{"c_example", "dump.sql", "old.sql"}},
		{"file keeps only safe paths", "file", current,
			[]string{"public_html/index.php", "./logs/a.log", "../escape", "/etc/passwd", "", "a/../../b"},
			[]string{"c_example/public_html/index.php", "c_example/logs/a.log"}},
		{"file with no paths", "file", current, nil, []string{}},
		{"an unknown mode", "everything", current, nil, nil},
	}
	for _, c := range cases {
		got := membersForMode(c.mode, "c_example", c.members, c.paths)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: membersForMode = %#v, want %#v", c.name, got, c.want)
		}
	}
}

// The current layout names each database by its file under __db__; users.sql and
// the manifest are not databases. An archive with no dump there falls back to the
// first top-level .sql file as the main database.
func TestArchiveDBFilesReadsBothLayouts(t *testing.T) {
	current := t.TempDir()
	dbDir := filepath.Join(current, "__db__")
	for _, name := range []string{"c_example_main.sql", "c_example_wp.sql", dbUsersFileName, "manifest.json"} {
		writeFixtureFile(t, filepath.Join(dbDir, name), "-- dump")
	}
	if err := os.MkdirAll(filepath.Join(dbDir, "directory.sql"), 0o700); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"c_example_main": filepath.Join(dbDir, "c_example_main.sql"),
		"c_example_wp":   filepath.Join(dbDir, "c_example_wp.sql"),
	}
	if got := archiveDBFiles(current, "c_example"); !reflect.DeepEqual(got, want) {
		t.Errorf("current layout = %v, want %v", got, want)
	}

	// An empty __db__ does not hide the legacy dump beside it, and only the first
	// .sql file in name order is taken.
	legacy := t.TempDir()
	if err := os.MkdirAll(filepath.Join(legacy, "__db__"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(legacy, "a-directory.sql"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(legacy, "b.sql"), "-- first")
	writeFixtureFile(t, filepath.Join(legacy, "c.sql"), "-- second")
	want = map[string]string{"c_example_main": filepath.Join(legacy, "b.sql")}
	if got := archiveDBFiles(legacy, "c_example"); !reflect.DeepEqual(got, want) {
		t.Errorf("legacy layout = %v, want %v", got, want)
	}

	if got := archiveDBFiles(t.TempDir(), "c_example"); len(got) != 0 {
		t.Errorf("an archive with no dump = %v, want nothing", got)
	}
}

func writeFixtureFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The contents listing splits home files from database dumps and names paths
// relative to the home, the way the granular restore screen shows them.
func TestScanArchiveContentsListsFilesAndDumps(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "c_example-20260101-000000.tar.gz")
	writeTarGz(t, abs,
		tarEntry{name: "./", typeflag: tar.TypeDir},
		tarEntry{name: "c_example/", typeflag: tar.TypeDir},
		// A doubled separator names the home itself, which is not listed.
		tarEntry{name: "c_example//", typeflag: tar.TypeDir},
		tarEntry{name: "c_example/public_html/", typeflag: tar.TypeDir},
		tarEntry{name: "./c_example/public_html/index.php", body: "<?php"},
		tarEntry{name: "__db__/c_example_main.sql", body: "-- dump"},
		tarEntry{name: "__db__/manifest.json", body: "{}"},
		tarEntry{name: "legacy.sql", body: "-- legacy"},
		tarEntry{name: "other/readme.txt", body: "outside the home"},
	)

	files, dbs, truncated, err := scanArchiveContents(abs, "c_example")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	wantFiles := []ContentFile{
		{Path: "public_html", IsDir: true},
		{Path: "public_html/index.php", Size: 5},
		{Path: "other/readme.txt", Size: 16},
	}
	if !reflect.DeepEqual(files, wantFiles) {
		t.Errorf("files = %#v, want %#v", files, wantFiles)
	}
	wantDBs := []ContentDB{{Name: "c_example_main", Size: 7}, {Name: "c_example_main", Size: 9}}
	if !reflect.DeepEqual(dbs, wantDBs) {
		t.Errorf("databases = %#v, want %#v", dbs, wantDBs)
	}
	if truncated {
		t.Error("a short archive was reported as truncated")
	}
}

// The listing stops at 6000 files and says so, and it keeps counting past the cap
// only to report that.
func TestScanArchiveContentsCapsTheFileList(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "big.tar.gz")
	entries := make([]tarEntry, 0, 6002)
	for i := range 6001 {
		entries = append(entries, tarEntry{name: fmt.Sprintf("c_example/f%05d", i), body: "x"})
	}
	entries = append(entries, tarEntry{name: "__db__/c_example_main.sql", body: "-- dump"})
	writeTarGz(t, abs, entries...)

	files, dbs, truncated, err := scanArchiveContents(abs, "c_example")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(files) != 6000 || !truncated {
		t.Errorf("files=%d truncated=%t, want 6000 and true", len(files), truncated)
	}
	if len(dbs) != 1 {
		t.Errorf("a dump after the cap was not listed: %v", dbs)
	}
}

// An archive that cannot be opened is an error; one whose tar stream breaks
// part-way lists what came before the break without an error.
func TestScanArchiveContentsOnAnUnreadableArchive(t *testing.T) {
	dir := t.TempDir()
	if _, _, _, err := scanArchiveContents(filepath.Join(dir, "missing.tar.gz"), "c_example"); err == nil {
		t.Error("a missing archive was listed")
	}
	plain := filepath.Join(dir, "plain.tar.gz")
	writeFixtureFile(t, plain, "not gzip")
	if _, _, _, err := scanArchiveContents(plain, "c_example"); err == nil {
		t.Error("an archive that is not gzip was listed")
	}
	broken := filepath.Join(dir, "broken.tar.gz")
	writeGzip(t, broken, "not a tar stream")
	files, dbs, truncated, err := scanArchiveContents(broken, "c_example")
	if err != nil || len(files) != 0 || len(dbs) != 0 || truncated {
		t.Errorf("a broken tar stream = (%v, %v, %t, %v), want an empty listing", files, dbs, truncated, err)
	}
}

// The pre-scan allows the relative links a project tree carries and refuses every
// member that leaves the extraction directory or is a device.
func TestRestoreArchiveScanRefusesEveryJailEscape(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name  string
		entry tarEntry
		want  string
	}{
		{"an absolute member", tarEntry{name: "/etc/passwd", body: "x"},
			"security: invalid member path: /etc/passwd"},
		{"an escaping member", tarEntry{name: "../outside", body: "x"},
			"security: invalid member path: ../outside"},
		{"an absolute symlink", tarEntry{name: "c_example/link", typeflag: tar.TypeSymlink, linkname: "/etc"},
			"security: absolute symlink target rejected: c_example/link -> /etc"},
		{"an escaping symlink", tarEntry{name: "c_example/link", typeflag: tar.TypeSymlink, linkname: "../../etc"},
			"security: out-of-archive symlink rejected: c_example/link -> ../../etc"},
		{"an absolute hardlink", tarEntry{name: "c_example/hard", typeflag: tar.TypeLink, linkname: "/etc/shadow"},
			"security: invalid hardlink rejected: c_example/hard -> /etc/shadow"},
		{"an escaping hardlink", tarEntry{name: "c_example/hard", typeflag: tar.TypeLink, linkname: "./../x"},
			"security: invalid hardlink rejected: c_example/hard -> ./../x"},
		{"a character device", tarEntry{name: "c_example/null", typeflag: tar.TypeChar},
			"security: device/fifo member rejected: c_example/null"},
		{"a block device", tarEntry{name: "c_example/disk", typeflag: tar.TypeBlock},
			"security: device/fifo member rejected: c_example/disk"},
		{"a fifo", tarEntry{name: "c_example/pipe", typeflag: tar.TypeFifo},
			"security: device/fifo member rejected: c_example/pipe"},
	}
	for i, c := range cases {
		abs := filepath.Join(dir, fmt.Sprintf("case%d.tar.gz", i))
		writeTarGz(t, abs, tarEntry{name: "c_example/index.php", body: "<?php"}, c.entry)
		err := restoreArchiveScan(abs)
		if err == nil || err.Error() != c.want {
			t.Errorf("%s: restoreArchiveScan = %v, want %q", c.name, err, c.want)
		}
	}

	clean := filepath.Join(dir, "clean.tar.gz")
	writeTarGz(t, clean,
		tarEntry{name: "./c_example/", typeflag: tar.TypeDir},
		tarEntry{name: "c_example/public_html/index.php", body: "<?php"},
		tarEntry{name: "c_example/public_html/current", typeflag: tar.TypeSymlink, linkname: "index.php"},
		tarEntry{name: "c_example/public_html/up", typeflag: tar.TypeSymlink, linkname: "../logs"},
		tarEntry{name: "c_example/public_html/copy", typeflag: tar.TypeLink, linkname: "./c_example/public_html/index.php"},
	)
	if err := restoreArchiveScan(clean); err != nil {
		t.Errorf("an archive with internal links was refused: %v", err)
	}
}

func TestRestoreArchiveScanOnAnUnreadableArchive(t *testing.T) {
	dir := t.TempDir()
	if err := restoreArchiveScan(filepath.Join(dir, "missing.tar.gz")); err == nil {
		t.Error("a missing archive passed the scan")
	}
	plain := filepath.Join(dir, "plain.tar.gz")
	writeFixtureFile(t, plain, "not gzip")
	if err := restoreArchiveScan(plain); err == nil {
		t.Error("an archive that is not gzip passed the scan")
	}
	broken := filepath.Join(dir, "broken.tar.gz")
	writeGzip(t, broken, "not a tar stream")
	if err := restoreArchiveScan(broken); err == nil || err.Error() != "archive could not be read: unexpected EOF" {
		t.Errorf("a broken tar stream = %v, want the read error named", err)
	}
}
