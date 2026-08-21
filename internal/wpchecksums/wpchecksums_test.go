package wpchecksums

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// realVersionPHP is the shape wordpress.org ships, trimmed to the parts that
// carry a value. The tail matters: $wp_local_package is the LAST assignment in
// the file on a localized build, so a reader that stops early misses exactly the
// line the locale depends on.
const realVersionPHP = `<?php
/**
 * WordPress Version
 *
 * @package WordPress
 */

/**
 * The WordPress version string.
 *
 * @global string $wp_version
 */
$wp_version = '7.1';

/**
 * @global int $wp_db_version
 */
$wp_db_version = 61833;

/**
 * @global string $tinymce_version
 */
$tinymce_version = '49110-20250317';

$required_php_version = '7.4';

$required_mysql_version = '5.5.5';

$wp_local_package = 'tr_TR';
`

func TestTheVersionAndTheLocaleAreBothRead(t *testing.T) {
	if got := findVar("wp_version", realVersionPHP[versionFileOffset:]); got != "7.1" {
		t.Fatalf("version = %q, want 7.1", got)
	}
	if got := findVar("wp_local_package", realVersionPHP[versionFileOffset:]); got != "tr_TR" {
		t.Fatalf("locale = %q, want tr_TR", got)
	}
}

// An English build has no $wp_local_package at all. Reading one anyway would ask
// wordpress.org for a locale it does not publish.
func TestAnEnglishInstallationReportsNoLocale(t *testing.T) {
	english := realVersionPHP[:len(realVersionPHP)-len("$wp_local_package = 'tr_TR';\n")]
	if got := findVar("wp_local_package", english[versionFileOffset:]); got != "" {
		t.Fatalf("locale = %q, want empty", got)
	}
	if got := findVar("wp_version", english[versionFileOffset:]); got != "7.1" {
		t.Fatalf("version = %q, want 7.1", got)
	}
}

// The version and the locale reach a URL query and a cache file name, so what
// they may contain is a boundary rather than tidiness.
func TestAVersionOrLocaleThatCouldEscapeIsRefused(t *testing.T) {
	for _, bad := range []string{
		"../../etc/passwd", "7.1/../..", "7.1&locale=x", "7.1 7.2", "7.1;rm", "7.1\n7.2",
		"", "111111111111111111111111111111111111",
	} {
		if validVersion(bad) {
			t.Errorf("validVersion(%q) = true, want false", bad)
		}
	}
	for _, good := range []string{"7.1", "6.5.5", "7.1-alpha", "5.9-RC1"} {
		if !validVersion(good) {
			t.Errorf("validVersion(%q) = false, want true", good)
		}
	}
	for _, bad := range []string{"tr-TR/../x", "tr_TR&v=1", "tr TR", "tr.TR", "aaaaaaaaaaaaaaaaa"} {
		if validLocale(bad) {
			t.Errorf("validLocale(%q) = true, want false", bad)
		}
	}
	for _, good := range []string{"", "ja", "tr_TR", "de_DE_formal"} {
		if !validLocale(good) {
			t.Errorf("validLocale(%q) = false, want true", good)
		}
	}
}

// An empty locale and an explicit en_US are the same published table, so they
// share one cache entry rather than fetching the same bytes under two names.
func TestEnglishAndAnEmptyLocaleShareOneCacheEntry(t *testing.T) {
	if a, b := tag(Details{Version: "7.1"}), tag(Details{Version: "7.1", Locale: "en_US"}); a != b {
		t.Fatalf("tags differ: %q and %q", a, b)
	}
	if got := tag(Details{Version: "7.1", Locale: "tr_TR"}); got != "7.1-tr_TR" {
		t.Fatalf("localized tag = %q", got)
	}
}

// The two filters are wp-cli's, and a difference shows up as a finding on a
// healthy site rather than as an error, so each case here is measured against
// the command's own source.
func TestTheFileFiltersMatchTheCommand(t *testing.T) {
	// The table pass skips the site's own files and nothing else.
	for _, skipped := range []string{"wp-content/themes/x.php", "wp-content/index.php"} {
		if keepInTable(skipped) {
			t.Errorf("keepInTable(%q) = true, want false", skipped)
		}
	}
	for _, kept := range []string{"wp-admin/index.php", "wp-includes/version.php", "readme.html", "index.php"} {
		if !keepInTable(kept) {
			t.Errorf("keepInTable(%q) = false, want true", kept)
		}
	}

	// The disk pass keeps the two core directories and the root wp-* files.
	for _, kept := range []string{
		"wp-admin/index.php", "wp-admin/css/deep/x.css", "wp-includes/version.php",
		"wp-login.php", "wp-settings.php", "wp-cron.php",
	} {
		if !keepOnDisk(kept) {
			t.Errorf("keepOnDisk(%q) = false, want true", kept)
		}
	}
	// wp-config.php holds the database password and is the site's own file.
	// readme.html and index.php are verified by the table pass but are NOT
	// collected by the disk pass, so they can never be reported as extra.
	for _, dropped := range []string{
		"wp-config.php", "readme.html", "index.php", "license.txt",
		"wp-content/plugins/x.php", "shell.php",
	} {
		if keepOnDisk(dropped) {
			t.Errorf("keepOnDisk(%q) = true, want false", dropped)
		}
	}
}

// A table is fetched once and read from disk afterwards, because the fallback is
// entered when the network is down and a table fetched only at that moment would
// never arrive.
func TestATableIsCachedAndReadBackFromDisk(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SERVIKA_WP_CHECKSUM_DIR", dir)

	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if got := r.URL.Query().Get("locale"); got != "tr_TR" {
			t.Errorf("locale in query = %q, want tr_TR", got)
		}
		if got := r.URL.Query().Get("version"); got != "7.1" {
			t.Errorf("version in query = %q, want 7.1", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"checksums": map[string]string{"wp-includes/version.php": "45ddd1e022352fc0ca84e372536426c8"},
		})
	}))
	defer server.Close()
	swapEndpoint(t, server.URL)

	details := Details{Version: "7.1", Locale: "tr_TR"}
	first, err := Table(context.Background(), details)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if first["wp-includes/version.php"] != "45ddd1e022352fc0ca84e372536426c8" {
		t.Fatalf("table = %v", first)
	}
	if _, err := Table(context.Background(), details); err != nil {
		t.Fatalf("second read: %v", err)
	}
	if hits != 1 {
		t.Fatalf("the endpoint was asked %d times, want 1", hits)
	}

	// The file carries a published checksum table, not a secret, but it is
	// written 0600 like everything else the panel puts under /var/lib/servika.
	info, err := os.Stat(filepath.Join(dir, "7.1-tr_TR.json"))
	if err != nil {
		t.Fatalf("cache file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode = %v, want 0600", info.Mode().Perm())
	}
}

// Proof the cache read is what answered the second call rather than a memory
// map: with the endpoint taken away entirely, the table still comes back.
func TestTheCacheAnswersWithTheEndpointGone(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SERVIKA_WP_CHECKSUM_DIR", dir)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"checksums": map[string]string{"wp-admin/index.php": "abc"},
		})
	}))
	swapEndpoint(t, server.URL)
	details := Details{Version: "6.5"}
	if _, err := Table(context.Background(), details); err != nil {
		t.Fatalf("warm: %v", err)
	}
	server.Close()

	table, err := Table(context.Background(), details)
	if err != nil {
		t.Fatalf("cached read after the server went away: %v", err)
	}
	if table["wp-admin/index.php"] != "abc" {
		t.Fatalf("table = %v", table)
	}
}

// Measured against the live endpoint: a version wordpress.org never published
// answers HTTP 200 with the body {"checksums":false}. It is neither a 404 nor an
// empty object, and decoding that field straight into a map turns the one
// definite answer there is into "cannot unmarshal bool", which reads exactly
// like a truncated response.
//
// The distinction is the whole point. version.php is BOTH the source of the
// version and one of the files being verified, so editing it to name a version
// that was never released blinds the entire check and the edited file escapes
// with it. Reporting that as "wordpress.org is unreachable" hides an attack
// behind a network fault.
func TestAnUnpublishedVersionIsAnAnswerRatherThanAFailure(t *testing.T) {
	for _, body := range []string{`{"checksums":false}`, `{"checksums":null}`, `{"checksums":{}}`} {
		dir := t.TempDir()
		t.Setenv("SERVIKA_WP_CHECKSUM_DIR", dir)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, body)
		}))
		swapEndpoint(t, server.URL)

		_, err := Table(context.Background(), Details{Version: "99.99"})
		if !errors.Is(err, ErrUnknownVersion) {
			t.Errorf("%s: err = %v, want ErrUnknownVersion", body, err)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("%s: the cache directory holds %d entries, want 0", body, len(entries))
		}
		server.Close()
	}
}

// A transport failure is TEMPORARY and must never be remembered. Caching it
// would leave that installation unchecked for the life of the process because
// wordpress.org hiccupped once, which is the opposite of what the negative cache
// is for.
func TestATemporaryFailureIsNotRemembered(t *testing.T) {
	t.Setenv("SERVIKA_WP_CHECKSUM_DIR", t.TempDir())
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"checksums": map[string]string{"wp-admin/index.php": "abc"},
		})
	}))
	defer server.Close()
	swapEndpoint(t, server.URL)

	details := Details{Version: "7.1"}
	if _, err := Table(context.Background(), details); err == nil {
		t.Fatal("a 502 was accepted as an answer")
	}
	table, err := Table(context.Background(), details)
	if err != nil {
		t.Fatalf("the second attempt was refused from the negative cache: %v", err)
	}
	if table["wp-admin/index.php"] != "abc" {
		t.Fatalf("table = %v", table)
	}
}

// The definite answer, on the other hand, IS remembered, or a site on a version
// nobody published asks wordpress.org again on every check.
func TestADefiniteAbsenceIsAskedOnlyOnce(t *testing.T) {
	t.Setenv("SERVIKA_WP_CHECKSUM_DIR", t.TempDir())
	asked := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked++
		_, _ = io.WriteString(w, `{"checksums":false}`)
	}))
	defer server.Close()
	swapEndpoint(t, server.URL)

	details := Details{Version: "6.99.99"}
	for range 3 {
		if _, err := Table(context.Background(), details); !errors.Is(err, ErrUnknownVersion) {
			t.Fatalf("err = %v, want ErrUnknownVersion", err)
		}
	}
	if asked != 1 {
		t.Fatalf("wordpress.org was asked %d times, want 1", asked)
	}
}

// A half-written cache file parses as nothing. It must send the caller back to
// the network rather than being read as an empty, and therefore clean, table.
func TestACorruptCacheFileIsIgnored(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SERVIKA_WP_CHECKSUM_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "7.1.json"), []byte(`{"wp-admin`), 0o600); err != nil {
		t.Fatal(err)
	}
	if table := readCache("7.1"); table != nil {
		t.Fatalf("a truncated cache file was read as %v", table)
	}
}

// The key is built from version.php, so the join is confined even though both
// halves are validated: a value that travels through a file outlives the code
// that wrote it.
func TestACacheKeyCannotLeaveTheCacheDirectory(t *testing.T) {
	t.Setenv("SERVIKA_WP_CHECKSUM_DIR", t.TempDir())
	for _, bad := range []string{"../escape", "a/b", "../../etc/cron.d/x"} {
		if _, ok := cachePath(bad); ok {
			t.Errorf("cachePath(%q) was allowed", bad)
		}
	}
	if _, ok := cachePath("7.1-tr_TR"); !ok {
		t.Error("an ordinary key was refused")
	}
}

// Verdicts come out of a map iteration, which Go randomises. Without a stable
// order the same installation reports a different list on every run.
func TestTheVerdictListIsStable(t *testing.T) {
	list := []Verdict{
		{Message: MessageModified, Rel: "wp-includes/b.php"},
		{Message: MessageMissing, Rel: "wp-admin/a.php"},
		{Message: MessageExtra, Rel: "wp-includes/b.php"},
	}
	sortVerdicts(list)
	want := []string{"wp-admin/a.php", "wp-includes/b.php", "wp-includes/b.php"}
	for i, expect := range want {
		if list[i].Rel != expect {
			t.Fatalf("position %d = %q, want %q", i, list[i].Rel, expect)
		}
	}
	// The two entries for the same path are ordered by message, and "File
	// doesn't verify against checksum" sorts before "File should not exist".
	if list[1].Message != MessageModified || list[2].Message != MessageExtra {
		t.Fatalf("ties are not ordered by message: %q then %q", list[1].Message, list[2].Message)
	}
}

// An empty table is refused rather than compared. Comparing against nothing
// reports every file as extra and no file as missing, which reads as a site full
// of planted files.
func TestAnEmptyTableIsRefusedRatherThanCompared(t *testing.T) {
	if _, err := Verify("/nonexistent", "public_html", nil); err == nil {
		t.Fatal("an empty table was compared")
	}
}

func swapEndpoint(t *testing.T, url string) {
	t.Helper()
	previous := endpoint
	endpoint = url
	negative.Clear()
	t.Cleanup(func() {
		endpoint = previous
		negative.Clear()
	})
}
