package antivirus

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The scan measured on a tree rather than on a rule. Every unit here is
// exercised somewhere else too, but only this test proves they compose: that
// the walk opens what the rules need, that a location verdict survives a file
// too large to read, and that ordinary WordPress files come back clean.

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestTheScanReportsWhatItShouldAndNothingElse(t *testing.T) {
	root := t.TempDir()
	// Clean files that must NOT be reported.
	write(t, root, "index.php", "<?php require_once __DIR__.'/wp-load.php';")
	write(t, root, "wp-content/uploads/2026/08/photo.jpg", "\xff\xd8\xff\xe0JFIF")
	write(t, root, "wp-content/plugins/x/class.wp.hooks.php", "<?php add_action('init', function(){});")
	write(t, root, ".well-known/acme-challenge/tok3n", "abc123")
	write(t, root, "assets/app.min.js", `!function(e,t){"object"==typeof exports&&module.exports}(this);`)
	write(t, root, ".htaccess", "RewriteEngine On\nRewriteRule ^ index.php [L]\n")
	// Files that MUST be reported.
	write(t, root, "wp-content/uploads/2026/08/shell.php", "<?php echo 1;")
	write(t, root, "photo.jpg.php", "<?php echo 1;")
	write(t, root, "wp-content/themes/y/hacked.js", `eval(String.fromCharCode(97,98));`)
	write(t, root, "sub/.htaccess", "AddType application/x-httpd-php .jpg\n")
	write(t, root, "wp-content/plugins/z/back.php", `<?php eval($_POST['c']);`)
	// A payload past the read limit: only its location can convict it.
	big := make([]byte, 4*1024*1024)
	for i := range big {
		big[i] = 'a'
	}
	write(t, root, "wp-content/uploads/2026/08/huge.php", string(big))

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	scanned, findings := runScan(ctx, root, DefaultRequest(root))
	t.Logf("scanned=%d findings=%d", scanned, len(findings))
	got := map[string]Finding{}
	for _, f := range findings {
		rel, _ := filepath.Rel(root, f.File)
		got[filepath.ToSlash(rel)] = f
		t.Logf("  %-46s %-9s %3d  %s", rel, f.Level, f.Score, f.Rules)
	}
	for _, want := range []string{
		"wp-content/uploads/2026/08/shell.php", "photo.jpg.php",
		"wp-content/themes/y/hacked.js", "sub/.htaccess",
		"wp-content/plugins/z/back.php", "wp-content/uploads/2026/08/huge.php",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("MISSED %s", want)
		}
	}
	for _, clean := range []string{
		"index.php", "wp-content/uploads/2026/08/photo.jpg",
		"wp-content/plugins/x/class.wp.hooks.php", ".well-known/acme-challenge/tok3n",
		"assets/app.min.js", ".htaccess",
	} {
		if f, ok := got[clean]; ok {
			t.Errorf("FALSE POSITIVE %s (%s %d %s)", clean, f.Level, f.Score, f.Rules)
		}
	}
}
