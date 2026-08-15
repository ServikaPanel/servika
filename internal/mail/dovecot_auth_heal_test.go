package mail

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stockAuthConf mirrors the password-database section of Dovecot's own
// 10-auth.conf: one active include, the rest commented out.
const stockAuthConf = `##
## Password databases
##

#!include auth-deny.conf.ext
#!include auth-master.conf.ext

!include auth-system.conf.ext

#!include auth-sql.conf.ext
#!include auth-ldap.conf.ext
`

const servikaDropIn = `protocols = imap lmtp

passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}
`

// dovecotEnv points the repair at a temporary conf.d and reports its path. The
// Servika drop-in is only created when the host is supposed to have one.
func dovecotEnv(t *testing.T, authConf string, withDropIn bool) string {
	t.Helper()
	dir := t.TempDir()
	auth := filepath.Join(dir, "10-auth.conf")
	if err := os.WriteFile(auth, []byte(authConf), 0o644); err != nil {
		t.Fatalf("write 10-auth.conf: %v", err)
	}
	dropIn := filepath.Join(dir, "10-servika-mail.conf")
	if withDropIn {
		if err := os.WriteFile(dropIn, []byte(servikaDropIn), 0o644); err != nil {
			t.Fatalf("write the drop-in: %v", err)
		}
	}
	previousAuth, previousDropIn := dovecotAuthConf, dovecotServikaConf
	dovecotAuthConf, dovecotServikaConf = auth, dropIn
	t.Cleanup(func() { dovecotAuthConf, dovecotServikaConf = previousAuth, previousDropIn })
	return dir
}

func TestDisableStockPAMCommentsTheActiveInclude(t *testing.T) {
	dir := dovecotEnv(t, stockAuthConf, true)

	if !disableStockPAM() {
		t.Fatal("the active PAM include was not disabled")
	}
	patched, err := os.ReadFile(filepath.Join(dir, "10-auth.conf"))
	if err != nil {
		t.Fatalf("read 10-auth.conf: %v", err)
	}
	body := string(patched)
	for line := range strings.SplitSeq(body, "\n") {
		if strings.HasPrefix(line, "!include auth-system.conf.ext") {
			t.Errorf("the PAM include is still active:\n%s", body)
		}
	}
	if !strings.Contains(body, "#!include auth-system.conf.ext") {
		t.Errorf("the line was not commented out:\n%s", body)
	}
	// Every other include must survive untouched.
	for _, kept := range []string{
		"#!include auth-deny.conf.ext",
		"#!include auth-master.conf.ext",
		"#!include auth-sql.conf.ext",
		"#!include auth-ldap.conf.ext",
	} {
		if !strings.Contains(body, kept) {
			t.Errorf("%q disappeared from the file", kept)
		}
	}
	// The blank line after the include belongs to the operator's file. A pattern
	// ending in \s* would consume it, because \s matches newlines in multiline
	// mode and $ then matches at the end of the empty line.
	if !strings.Contains(body, "PAM delayed every login and exposed system accounts over IMAP\n\n#!include auth-sql.conf.ext") {
		t.Errorf("the blank line after the include was swallowed:\n%s", body)
	}
}

// The stock file is only patched once; running the repair again must report no
// change, or every startup would reload Dovecot for nothing.
func TestDisableStockPAMIsIdempotent(t *testing.T) {
	dir := dovecotEnv(t, stockAuthConf, true)

	if !disableStockPAM() {
		t.Fatal("the first call should have changed the file")
	}
	afterFirst, err := os.ReadFile(filepath.Join(dir, "10-auth.conf"))
	if err != nil {
		t.Fatalf("read 10-auth.conf: %v", err)
	}
	if disableStockPAM() {
		t.Error("the second call reported another change")
	}
	afterSecond, err := os.ReadFile(filepath.Join(dir, "10-auth.conf"))
	if err != nil {
		t.Fatalf("read 10-auth.conf: %v", err)
	}
	if string(afterFirst) != string(afterSecond) {
		t.Errorf("the second call changed the file again:\n%s", afterSecond)
	}
}

// A line carrying trailing whitespace is still an active include.
func TestDisableStockPAMHandlesTrailingWhitespace(t *testing.T) {
	dir := dovecotEnv(t, "!include auth-system.conf.ext  \t\n", true)

	if !disableStockPAM() {
		t.Fatal("an include with trailing whitespace was not recognised")
	}
	patched, err := os.ReadFile(filepath.Join(dir, "10-auth.conf"))
	if err != nil {
		t.Fatalf("read 10-auth.conf: %v", err)
	}
	if !strings.HasPrefix(string(patched), "#!include auth-system.conf.ext") {
		t.Errorf("the line was not commented out:\n%s", patched)
	}
}

func TestAppendAuthCacheAddsTheSettingsOnce(t *testing.T) {
	dir := dovecotEnv(t, stockAuthConf, true)

	if !appendAuthCache() {
		t.Fatal("the auth cache was not appended")
	}
	patched, err := os.ReadFile(filepath.Join(dir, "10-servika-mail.conf"))
	if err != nil {
		t.Fatalf("read the drop-in: %v", err)
	}
	body := string(patched)
	if !strings.Contains(body, "auth_cache_size = 10M") {
		t.Errorf("the cache setting was not written:\n%s", body)
	}
	if !strings.Contains(body, "driver = sql") {
		t.Error("the existing configuration was not preserved")
	}
	if appendAuthCache() {
		t.Error("the second call appended the block again")
	}
	if count := strings.Count(body, "auth_cache_size"); count != 1 {
		t.Errorf("auth_cache_size appears %d times, want 1", count)
	}
}

// A drop-in whose last line has no terminator would otherwise be merged with the
// first line of the block, producing a setting Dovecot cannot parse.
func TestAppendAuthCacheDoesNotJoinAnUnterminatedLastLine(t *testing.T) {
	dir := dovecotEnv(t, stockAuthConf, true)
	dropIn := filepath.Join(dir, "10-servika-mail.conf")
	if err := os.WriteFile(dropIn, []byte("protocols = imap lmtp"), 0o644); err != nil {
		t.Fatalf("write the drop-in: %v", err)
	}

	if !appendAuthCache() {
		t.Fatal("the auth cache was not appended")
	}
	patched, err := os.ReadFile(dropIn)
	if err != nil {
		t.Fatalf("read the drop-in: %v", err)
	}
	if !strings.HasPrefix(string(patched), "protocols = imap lmtp\n") {
		t.Errorf("the last line lost its own terminator:\n%s", patched)
	}
}

// The guard that matters most: a Dovecot installed for a different purpose, for
// example giving system users IMAP, must not be touched at all.
func TestHealDovecotAuthLeavesAForeignDovecotAlone(t *testing.T) {
	dir := dovecotEnv(t, stockAuthConf, false) // no Servika drop-in

	HealDovecotAuth(context.Background())

	after, err := os.ReadFile(filepath.Join(dir, "10-auth.conf"))
	if err != nil {
		t.Fatalf("read 10-auth.conf: %v", err)
	}
	if string(after) != stockAuthConf {
		t.Errorf("a Dovecot without a Servika drop-in was modified:\n%s", after)
	}
}
