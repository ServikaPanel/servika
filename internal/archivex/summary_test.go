package archivex

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTarGz builds a .tar.gz whose members are the given paths. A path ending
// in "/" becomes a directory entry.
func writeTarGz(t *testing.T, names ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "archive.tar.gz")
	file, err := os.Create(path) // #nosec G304 -- test-owned path under t.TempDir().
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	for _, name := range names {
		header := &tar.Header{Name: name, Mode: 0o644, Typeflag: tar.TypeReg}
		body := "x"
		if strings.HasSuffix(name, "/") {
			header.Typeflag, header.Mode, body = tar.TypeDir, 0o755, ""
		}
		header.Size = int64(len(body))
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("write header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("write body %s: %v", name, err)
		}
	}
	for _, closer := range []func() error{tw.Close, gz.Close, file.Close} {
		if err := closer(); err != nil {
			t.Fatalf("close archive: %v", err)
		}
	}
	return path
}

func summarize(t *testing.T, path string, markers ...string) Summary {
	t.Helper()
	summary, err := Summarize(context.Background(), path, TypeTARGzip, Limits{}, markers)
	if err != nil {
		t.Fatalf("Summarize() = %v, want nil", err)
	}
	return summary
}

// Nearly every real site backup is wrapped in one directory. Extracting it into
// public_html without noticing produces public_html/backup/public_html and a
// site that does not load, which is the whole reason this exists.
func TestSummarizeFindsTheSingleContainerDirectory(t *testing.T) {
	got := summarize(t, writeTarGz(t,
		"backup/", "backup/index.php", "backup/wp-config.php", "backup/wp-content/style.css"))

	if got.ContainerRoot != "backup" {
		t.Errorf("ContainerRoot = %q, want \"backup\"", got.ContainerRoot)
	}
	if len(got.Roots) != 1 || got.Roots[0] != "backup" {
		t.Errorf("Roots = %v, want [backup]", got.Roots)
	}
	if got.Members != 4 {
		t.Errorf("Members = %d, want 4", got.Members)
	}
}

// Several roots means there is nothing to unwrap; claiming one would silently
// discard everything outside it.
func TestSummarizeReportsNoContainerForSeveralRoots(t *testing.T) {
	got := summarize(t, writeTarGz(t, "public_html/index.php", "db.sql", "logs/error.log"))

	if got.ContainerRoot != "" {
		t.Errorf("ContainerRoot = %q, want empty for a multi-root archive", got.ContainerRoot)
	}
	if len(got.Roots) != 3 {
		t.Errorf("Roots = %v, want three entries", got.Roots)
	}
}

// A single loose file also has exactly one root. Treating that as a container
// and stripping it would delete the only member.
func TestSummarizeDoesNotTreatALoneFileAsAContainer(t *testing.T) {
	if got := summarize(t, writeTarGz(t, "dump.sql")); got.ContainerRoot != "" {
		t.Errorf("ContainerRoot = %q, want empty: the single root is a file", got.ContainerRoot)
	}
}

// The marker paths drive both the "this is a WordPress backup" label and the
// config rewrite that follows, so they must be the DIRECTORIES holding them.
func TestSummarizeRecordsMarkerDirectories(t *testing.T) {
	got := summarize(t, writeTarGz(t,
		"site/wp-config.php",
		"site/wp-content/plugins/demo/tests/wp-config.php",
		"site/.env"),
		"wp-config.php", ".env", "artisan")

	want := []string{"site", "site/wp-content/plugins/demo/tests"}
	if strings.Join(got.Markers["wp-config.php"], ",") != strings.Join(want, ",") {
		t.Errorf("wp-config.php markers = %v, want %v", got.Markers["wp-config.php"], want)
	}
	if _, present := got.Markers["artisan"]; present {
		t.Errorf("an absent marker was reported: %v", got.Markers)
	}
}

// A plugin's test fixture routinely ships its own wp-config.php. The real one is
// the shallowest, and picking the deep one would rewrite a fixture and leave the
// site broken.
func TestAppRootPrefersTheShallowestMarker(t *testing.T) {
	summary := summarize(t, writeTarGz(t,
		"wp-content/plugins/demo/tests/wp-config.php", "wp-config.php", "index.php"),
		"wp-config.php")

	app, dir := AppRoot(summary)
	if app != "wordpress" {
		t.Errorf("app = %q, want wordpress", app)
	}
	if dir != "" {
		t.Errorf("dir = %q, want the archive root", dir)
	}
}

// artisan is what separates a Laravel project from the many others that ship a
// .env, so it must be consulted first.
func TestAppRootPrefersArtisanOverABareEnv(t *testing.T) {
	summary := summarize(t, writeTarGz(t, "app/.env", "app/artisan"), "artisan", ".env")
	if app, dir := AppRoot(summary); app != "laravel" || dir != "app" {
		t.Errorf("AppRoot() = (%q, %q), want (laravel, app)", app, dir)
	}
}

func TestAppRootReportsNothingForAPlainArchive(t *testing.T) {
	summary := summarize(t, writeTarGz(t, "site/index.html"), "wp-config.php", "artisan")
	if app, dir := AppRoot(summary); app != "" || dir != "" {
		t.Errorf("AppRoot() = (%q, %q), want empty", app, dir)
	}
}

// Summarize rides on Scan, so a hostile archive must be refused at inventory
// time rather than described and only rejected later at extraction.
func TestSummarizeRefusesAnEscapingMember(t *testing.T) {
	_, err := Summarize(context.Background(), writeTarGz(t, "../../etc/cron.d/job"),
		TypeTARGzip, Limits{}, nil)
	if !errors.Is(err, ErrUnsafePath) {
		t.Errorf("Summarize() = %v, want ErrUnsafePath", err)
	}
}

func TestSummarizeAppliesTheMemberLimit(t *testing.T) {
	_, err := Summarize(context.Background(), writeTarGz(t, "a", "b", "c"),
		TypeTARGzip, Limits{MaxMembers: 2}, nil)
	if !errors.Is(err, ErrTooManyMembers) {
		t.Errorf("Summarize() = %v, want ErrTooManyMembers", err)
	}
}

// A negative count would reach tar as a malformed flag; refuse it here.
func TestExtractStripRefusesANegativeCount(t *testing.T) {
	_, err := ExtractStrip(context.Background(), writeTarGz(t, "a"), TypeTARGzip, t.TempDir(), "c_test", -1, Limits{})
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("ExtractStrip() = %v, want ErrUnsupported", err)
	}
}

// The extraction path must take the format from the CALLER, not from the
// filename.
//
// A caller that resolved the archive symlink-safely hands over the
// /proc/self/fd path of the pinned descriptor, which carries no suffix.
// Deriving the format here answered TypeUnknown for every such call and refused
// the archive before opening anything, which broke the file manager's
// extraction completely for every supported format while telling the customer
// their archive was corrupt.
func TestExtractAcceptsAPathWithNoRecognizableSuffix(t *testing.T) {
	pinned := filepath.Join(t.TempDir(), "12") // the shape of /proc/self/fd/<n>
	body, err := os.ReadFile(writeTarGz(t, "site/index.php"))
	if err != nil {
		t.Fatalf("read the archive: %v", err)
	}
	if err := os.WriteFile(pinned, body, 0o600); err != nil {
		t.Fatalf("stage the suffix-less copy: %v", err)
	}
	if DetectType(pinned) != TypeUnknown {
		t.Fatalf("the staged path %q is classifiable, so it does not exercise the defect", pinned)
	}

	_, err = ExtractStrip(context.Background(), pinned, TypeTARGzip, t.TempDir(), "c_test", 0, Limits{})
	// The extractor itself needs runuser and a real tenant account, so it fails
	// here for its own reasons. What matters is that the format was accepted:
	// ErrUnsupported means the type was rejected before the archive was read.
	if errors.Is(err, ErrUnsupported) {
		t.Fatal("an explicitly typed archive was refused as unsupported because its path has no suffix")
	}
}

// An unclassifiable archive whose caller ALSO does not know the format is still
// refused, so the explicit parameter did not turn the check off.
func TestExtractStillRefusesAnUnknownType(t *testing.T) {
	_, err := ExtractStrip(context.Background(), writeTarGz(t, "a"), TypeUnknown, t.TempDir(), "c_test", 0, Limits{})
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("ExtractStrip() with TypeUnknown = %v, want ErrUnsupported", err)
	}
}

func TestStripSupportedCoversTheTarFamily(t *testing.T) {
	for _, archiveType := range []Type{TypeTAR, TypeTARGzip, TypeTARBzip2, TypeTARXz} {
		if !StripSupported(archiveType) {
			t.Errorf("StripSupported(%v) = false; tar carries --strip-components itself", archiveType)
		}
	}
	if StripSupported(TypeUnknown) {
		t.Error("StripSupported(TypeUnknown) = true")
	}
}

func TestStripFlagRendersTheCount(t *testing.T) {
	if got := stripFlag(1); got != "--strip-components=1" {
		t.Errorf("stripFlag(1) = %q", got)
	}
}
