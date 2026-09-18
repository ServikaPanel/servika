package wordpress

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"servika/internal/secret"
)

// sealingKey prepares internal/secret for one test. Without it every seal fails
// and the install reports that it stored nothing.
func sealingKey(t *testing.T) {
	t.Helper()
	if err := secret.Init([]byte("test-key-for-wordpress-install-passwords")); err != nil {
		t.Fatalf("init the sealing key: %v", err)
	}
}

// The install must write the password into the table instead of the response,
// and it must write it sealed: a row readable by anyone who can read the panel
// database is the leak this replaced, not a fix for it.
func TestInstallSealsThePasswordIntoTheTable(t *testing.T) {
	sealingKey(t)
	root := tenantRoot(t)
	rec := recordWP(t, map[string]wpAnswer{"core version": {out: "7.1\n"}})
	recordHost(t)

	script := adminDomain(domainScript("c_test"))
	if code := runInstall(t, script, installBody).Code; code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	stored := execArgsFor(script, "INSERT INTO wp_install_passwords")
	if stored == nil {
		t.Fatalf("no row was written; statements = %v", script.steps)
	}
	target := filepath.Join(root, "blog")
	if got, want := stored[1], driver.Value(target); got != want {
		t.Errorf("target = %v, want the absolute install directory %v", got, want)
	}
	if got, want := stored[2], driver.Value("admin"); got != want {
		t.Errorf("admin_user = %v, want %v", got, want)
	}
	sealed, _ := stored[3].(string)
	if !secret.IsEncrypted(sealed) {
		t.Fatalf("admin_password = %q, want a sealed value", sealed)
	}
	if strings.Contains(sealed, rec.adminPass) {
		t.Errorf("the sealed value carries the password in the clear")
	}
	opened, err := secret.DecryptWith(sealed, installPasswordAAD(1, target))
	if err != nil {
		t.Fatalf("open the sealed password: %v", err)
	}
	if opened != rec.adminPass {
		t.Errorf("opened = %q, want the password that went in on stdin (%q)", opened, rec.adminPass)
	}
}

// The AAD binds the row to its domain and its directory. A ciphertext moved to
// another row must fail to open rather than reveal a password for a site its
// holder does not own.
func TestASealedPasswordDoesNotOpenUnderAnotherRow(t *testing.T) {
	sealingKey(t)
	sealed, err := secret.EncryptWith("s3cret", installPasswordAAD(1, "/home/c_one/public_html"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	moved := []struct {
		name     string
		domainID int64
		target   string
	}{
		{"another domain", 2, "/home/c_one/public_html"},
		{"another directory", 1, "/home/c_one/public_html/shop"},
	}
	for _, row := range moved {
		if _, err := secret.DecryptWith(sealed, installPasswordAAD(row.domainID, row.target)); err == nil {
			t.Errorf("%s: the moved ciphertext opened, want a failure", row.name)
		}
	}
	// The negative half alone proves nothing: a seal that never opened would pass
	// it. The original binding must still work.
	if opened, err := secret.DecryptWith(sealed, installPasswordAAD(1, "/home/c_one/public_html")); err != nil || opened != "s3cret" {
		t.Errorf("the original row did not open: %q, %v", opened, err)
	}
}

// The reveal answers once. The second call finds nothing, because the row is
// deleted in the same transaction that read it.
func TestRevealAnswersOnceAndForgetsTheRow(t *testing.T) {
	sealingKey(t)
	root := tenantRoot(t)
	recordWP(t, nil)
	target := filepath.Join(root, "blog")
	// #nosec G301 -- a test directory under t.TempDir().
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("make the install directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "wp-config.php"), []byte("<?php"), 0o600); err != nil {
		t.Fatalf("write wp-config.php: %v", err)
	}
	sealed, err := secret.EncryptWith("s3cret", installPasswordAAD(1, target))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	script := domainScript("c_test")
	script.rows["FROM wp_install_passwords"] = [][]driver.Value{{"admin", sealed}}

	got := revealPassword(t, script)
	if got.AdminUser != "admin" || got.AdminPassword != "s3cret" {
		t.Errorf("reveal = %+v, want the stored account and password", got)
	}
	if !sawStatement(script, "DELETE FROM wp_install_passwords") {
		t.Errorf("the row was not deleted; statements = %v", script.steps)
	}
}

// A directory with no stored password is a 404, not a server error, because the
// normal case is a password that was already taken.
func TestRevealReportsNoStoredPassword(t *testing.T) {
	sealingKey(t)
	root := tenantRoot(t)
	recordWP(t, nil)
	target := filepath.Join(root, "blog")
	// #nosec G301 -- a test directory under t.TempDir().
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("make the install directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "wp-config.php"), []byte("<?php"), 0o600); err != nil {
		t.Fatalf("write wp-config.php: %v", err)
	}
	script := domainScript("c_test")
	script.rows["FROM wp_install_passwords"] = [][]driver.Value{}

	h := &Handlers{DB: scriptDB(t, script)}
	recorder := httptest.NewRecorder()
	h.RevealInstallPassword(recorder,
		wpRequest(http.MethodPost, "/domains/1/wordpress/install-password", `{"dir":"blog"}`))
	if recorder.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body %s", recorder.Code, recorder.Body.String())
	}
}

// revealPassword drives the reveal endpoint and decodes its answer.
func revealPassword(t *testing.T, script *sqlScript) installResponse {
	t.Helper()
	h := &Handlers{DB: scriptDB(t, script)}
	recorder := httptest.NewRecorder()
	h.RevealInstallPassword(recorder,
		wpRequest(http.MethodPost, "/domains/1/wordpress/install-password", `{"dir":"blog"}`))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", recorder.Code, recorder.Body.String())
	}
	var got installResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode the response: %v", err)
	}
	return got
}

// execArgsFor returns the arguments of the first statement whose text holds the
// fragment, or nil when the script recorded none.
func execArgsFor(script *sqlScript, fragment string) []driver.Value {
	script.mu.Lock()
	defer script.mu.Unlock()
	for _, statement := range script.execs {
		if strings.Contains(statement.query, fragment) {
			return statement.args
		}
	}
	return nil
}

// sawStatement reports whether the script ran a statement holding the fragment.
func sawStatement(script *sqlScript, fragment string) bool {
	script.mu.Lock()
	defer script.mu.Unlock()
	for _, step := range script.steps {
		if strings.Contains(step, fragment) {
			return true
		}
	}
	return false
}

// storedPasswordTargets must answer an empty set rather than fail when the
// query cannot run, because the list endpoint still has installations to show.
func TestStoredPasswordTargetsSurvivesAFailedQuery(t *testing.T) {
	script := newScript()
	script.rows["FROM wp_install_passwords"] = [][]driver.Value{{"/home/c_one/public_html"}}
	if got := storedPasswordTargets(context.Background(), scriptDB(t, script), 1); !got["/home/c_one/public_html"] {
		t.Errorf("targets = %v, want the stored directory", got)
	}
	empty := newScript()
	if got := storedPasswordTargets(context.Background(), scriptDB(t, empty), 1); len(got) != 0 {
		t.Errorf("targets = %v, want an empty set when the query cannot run", got)
	}
}
