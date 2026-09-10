package mail

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The two maps as servika-mail-setup wrote them before the fix.
const (
	stockDovecotSQLConf = `driver = mysql
connect = host=127.0.0.1 dbname=panel user=mailro password=secret
default_pass_scheme = SHA512-CRYPT
password_query = SELECT m.email AS user, m.password_hash AS password FROM mailboxes m JOIN mail_domains md ON md.id=m.mail_domain_id WHERE m.email='%u' AND m.status='active' AND md.status='active'
user_query = SELECT CONCAT('/home/',md.system_user,'/mail/',m.local_part) AS home, md.uid_n AS uid, md.gid_n AS gid, CONCAT('maildir:/home/',md.system_user,'/mail/',m.local_part) AS mail, CASE WHEN m.quota_bytes > 0 THEN CONCAT('*:bytes=', m.quota_bytes) ELSE NULL END AS quota_rule FROM mailboxes m JOIN mail_domains md ON md.id=m.mail_domain_id WHERE m.email='%u' AND m.status='active' AND md.status='active'
iterate_query = SELECT email AS user FROM mailboxes WHERE status='active'
`
	stockPostfixMailboxMap = `hosts = 127.0.0.1
user = mailro
query = SELECT CONCAT(md.system_user,'/mail/',m.local_part,'/') FROM mailboxes m JOIN mail_domains md ON md.id=m.mail_domain_id WHERE m.email='%s' AND m.status='active' AND md.status='active'
`
)

// A path rebuilt from md.system_user and m.local_part is per SYSTEM USER while
// uniqueness on mailboxes is (domain_id, local_part), so two mail domains on one
// system user resolved to one store. Every rebuilt path has to become a read of
// the column the panel writes.
func TestRewriteReplacesEveryRebuiltPathInTheDovecotMap(t *testing.T) {
	out, changed := rewriteMaildirQuery(stockDovecotSQLConf)
	if !changed {
		t.Fatal("the stock Dovecot map was left unchanged")
	}
	if strings.Contains(out, "m.local_part") {
		t.Errorf("a path is still rebuilt from the local part:\n%s", out)
	}
	if !strings.Contains(out, "TRIM(TRAILING '/' FROM m.maildir) AS home") {
		t.Errorf("home is not read from m.maildir:\n%s", out)
	}
	if !strings.Contains(out, "CONCAT('maildir:', m.maildir) AS mail") {
		t.Errorf("the mail location is not read from m.maildir:\n%s", out)
	}
	// Everything the repair was not asked about survives, the password among it.
	if !strings.Contains(out, "password=secret") || !strings.Contains(out, "iterate_query = ") {
		t.Errorf("the repair rewrote more than the maildir paths:\n%s", out)
	}
}

// Postfix's map is relative to virtual_mailbox_base (/home), so it keeps the
// path minus that prefix rather than the absolute column value.
func TestRewriteMakesThePostfixMapRelativeToTheMailboxBase(t *testing.T) {
	out, changed := rewriteMaildirQuery(stockPostfixMailboxMap)
	if !changed {
		t.Fatal("the stock Postfix map was left unchanged")
	}
	if strings.Contains(out, "m.local_part") {
		t.Errorf("the Postfix map still rebuilds the path:\n%s", out)
	}
	if !strings.Contains(out, "SUBSTRING(m.maildir, 7)") {
		t.Errorf("the Postfix map does not strip the /home/ prefix from m.maildir:\n%s", out)
	}
}

// A host already carrying the new form must come out byte-for-byte identical, or
// every boot would rewrite the file and reload two mail services for nothing.
func TestRewriteIsIdempotent(t *testing.T) {
	once, _ := rewriteMaildirQuery(stockDovecotSQLConf)
	twice, changed := rewriteMaildirQuery(once)
	if changed {
		t.Error("a file that already reads m.maildir was rewritten again")
	}
	if twice != once {
		t.Errorf("the second pass changed the file:\n%s", twice)
	}
}

// The repair only runs where Servika's own mail drop-in is present, so a Dovecot
// installed for another purpose is never touched.
func TestHealLeavesAHostWithoutTheServikaDropInAlone(t *testing.T) {
	dir := t.TempDir()
	sqlConf := filepath.Join(dir, "dovecot-sql.conf.ext")
	if err := os.WriteFile(sqlConf, []byte(stockDovecotSQLConf), 0o600); err != nil {
		t.Fatalf("write the map: %v", err)
	}
	restore := pointMailHealAt(t, filepath.Join(dir, "absent-10-servika-mail.conf"), sqlConf, filepath.Join(dir, "absent.cf"))
	defer restore()

	HealMaildirQuery(t.Context())

	after, err := os.ReadFile(sqlConf)
	if err != nil {
		t.Fatalf("read the map back: %v", err)
	}
	if string(after) != stockDovecotSQLConf {
		t.Error("the map was rewritten on a host that never ran the Servika mail setup")
	}
}

// pointMailHealAt redirects the heal's three paths and restores them afterwards.
func pointMailHealAt(t *testing.T, dropIn, sqlConf, postfixMap string) func() {
	t.Helper()
	originalDropIn, originalSQL, originalPostfix := dovecotServikaConf, dovecotSQLConf, postfixMailboxMap
	dovecotServikaConf, dovecotSQLConf, postfixMailboxMap = dropIn, sqlConf, postfixMap
	return func() {
		dovecotServikaConf, dovecotSQLConf, postfixMailboxMap = originalDropIn, originalSQL, originalPostfix
	}
}

// The shipped templates are what a NEW installation gets, so they must already
// carry what the heal produces; otherwise a fresh host would be repaired on its
// first boot, or worse, left on the broken form.
func TestShippedTemplatesReadTheMaildirColumn(t *testing.T) {
	for _, template := range []string{
		"../../assets/mail/dovecot/dovecot-sql.conf.ext.tmpl",
		"../../assets/mail/postfix/mysql-virtual-mailboxes.cf.tmpl",
	} {
		body, err := os.ReadFile(template)
		if err != nil {
			t.Fatalf("read %s: %v", template, err)
		}
		if _, changed := rewriteMaildirQuery(string(body)); changed {
			t.Errorf("%s still rebuilds a maildir path from m.local_part", template)
		}
		if !strings.Contains(string(body), "m.maildir") {
			t.Errorf("%s does not read m.maildir", template)
		}
	}
}
