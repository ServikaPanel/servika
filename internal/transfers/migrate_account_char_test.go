package transfers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"servika/internal/domainblock"
	"servika/internal/mail"
	"servika/internal/provisioner"
)

// accountHarness fakes everything one account migration reaches: the database,
// every local and remote command, and every provider seam. Each fake reads the
// harness fields when it is called, so a test sets a field to change an answer.
type accountHarness struct {
	t        *testing.T
	h        *Handlers
	script   *sqlScript
	commands *commandRecorder
	creates  *dbCreates
	log      logLines
	calls    []string
	webRoot  string
	source   *RemoteSource
	account  RemoteAccount
	settings MigrationSettings

	blocked      bool
	blockedErr   error
	provisionErr error
	limitsErr    error
	lookupErr    error
	ftpErr       error
	certPath     string
	outcome      provisioner.IssueOutcome
	issueErr     error

	rsync, cert, zone, mailboxes, aliases commandAnswer
	dump                                  string
}

func newAccountHarness(t *testing.T) *accountHarness {
	t.Helper()
	a := &accountHarness{t: t, script: newScript(), source: passwordSource("cpanel"),
		account: RemoteAccount{SourceAccount: "acme", DomainName: "Example.com"}}
	a.webRoot = filepath.Join(t.TempDir(), "c_example_com", "public_html")
	if err := os.MkdirAll(a.webRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	a.dump = dumpFile(t, completeDump)
	a.script.insertID = 42
	a.script.rows["COALESCE(web_root,'')"] = [][]driver.Value{}
	a.script.rows["SELECT ipv4 FROM domains"] = [][]driver.Value{{"203.0.113.99"}}
	a.script.rows["FROM customers"] = [][]driver.Value{{int64(1)}}
	a.script.answer = accountLookups
	a.h = &Handlers{DB: scriptDB(t, a.script), Mail: &mail.Handlers{}}
	setForTest(t, &migrationBackupRoot, t.TempDir())
	a.commands = withCommandScript(t, a.answer)
	a.creates = withDBCreates(t)
	withDNSSeams(t, nil, nil)
	withSQLImports(t, nil)
	loadedPHP(t, "8.2", "8.3")
	a.installSeams()
	return a
}

func (a *accountHarness) installSeams() {
	t := a.t
	setForTest(t, &blockedDomain, a.blockedDomain)
	setForTest(t, &provisionAccount, a.provision)
	setForTest(t, &deprovisionAccount, a.deprovision)
	setForTest(t, &applyResourceLimits, a.applyLimits)
	setForTest(t, &lookupSystemUser, a.lookup)
	setForTest(t, &createFTPAccount, a.createFTP)
	setForTest(t, &enableLetsEncrypt, a.issue)
	setForTest(t, &installImportedSSL, a.installSSL)
	setForTest(t, &rerenderVhost, func(*sql.DB, int64) error { return nil })
	setForTest(t, &enableMailDomain, enabledMail)
	setForTest(t, &createMailbox, mailboxAnswer)
	setForTest(t, &createMailAlias, answerWith[mail.Handlers](http.StatusCreated, `{}`))
}

// accountLookups answers every database name as free and every DNS record
// lookup as absent.
func accountLookups(query string, args []driver.Value) ([][]driver.Value, bool) {
	if strings.Contains(query, "information_schema.schemata") {
		return countRow(false), true
	}
	return dnsHolders{}.answer(query, args)
}

func (a *accountHarness) record(format string, args ...any) {
	a.calls = append(a.calls, fmt.Sprintf(format, args...))
}

func (a *accountHarness) blockedDomain(context.Context, *sql.DB, string) (bool, domainblock.Rule, error) {
	return a.blocked, domainblock.Rule{}, a.blockedErr
}

func (a *accountHarness) provision(domainName, php string) (*provisioner.Result, error) {
	a.record("provision %s %s", domainName, php)
	return &provisioner.Result{SystemUser: "c_example_com", WebRoot: a.webRoot}, a.provisionErr
}

func (a *accountHarness) deprovision(domainName, systemUser string) error {
	a.record("deprovision %s %s", domainName, systemUser)
	return nil
}

func (a *accountHarness) applyLimits(_ context.Context, _ *sql.DB, domainID int64) error {
	a.record("limits %d", domainID)
	return a.limitsErr
}

func (a *accountHarness) lookup(name string) (*user.User, error) {
	return &user.User{Username: name, Uid: "1001", Gid: "1002"}, a.lookupErr
}

func (a *accountHarness) createFTP(_ *sql.DB, domainID int64, systemUser, password string, uid, gid int) error {
	a.record("ftp %d %s %d-char password %d %d", domainID, systemUser, len(password), uid, gid)
	return a.ftpErr
}

func (a *accountHarness) issue(domain, systemUser, php, backend string) (string, string, provisioner.IssueOutcome, error) {
	a.record("letsencrypt %s %s %s %s", domain, systemUser, php, backend)
	return a.certPath, "/ssl/example.com.key", a.outcome, a.issueErr
}

func (a *accountHarness) installSSL(domain string, _, _ []byte) (string, string, time.Time, error) {
	a.record("import-ssl %s", domain)
	return importedSSL(domain, nil, nil)
}

// answer answers each command by what it runs: rsync, the dump, the certificate
// reader, the zone reader, the forwarder list and the mailbox list each have a
// field; anything else succeeds with no output.
func (a *accountHarness) answer(argv []string) commandAnswer {
	last := argv[len(argv)-1]
	switch {
	case slices.Contains(argv, "rsync"):
		return a.rsync
	case strings.Contains(last, "mysqldump"):
		return commandAnswer{file: a.dump}
	case strings.Contains(last, certMarkerStart):
		return a.cert
	case strings.Contains(last, "cat /var/named/"):
		return a.zone
	case strings.Contains(last, "/etc/valias/"):
		return a.aliases
	case strings.Contains(last, "/shadow"):
		return a.mailboxes
	}
	return commandAnswer{}
}

func (a *accountHarness) run() (*MigrationResult, error) {
	return a.h.MigrateAccount(a.t.Context(), a.source, a.account, a.settings, a.log.logf)
}

// existing makes the target check find domain 15, owned by c_old, at root.
func (a *accountHarness) existing(root string) {
	a.script.rows["COALESCE(web_root,'')"] = [][]driver.Value{{int64(15), "c_old", root}}
}

const (
	provisioned   = "provision example.com 8.3"
	limited       = "limits 42"
	ftpCreated    = "ftp 42 c_example_com 16-char password 1001 1002"
	deprovisioned = "deprovision example.com c_example_com"
)

func assertMigrationRefused(t *testing.T, a *accountHarness, result *MigrationResult, calls []string, rolledBack bool) {
	t.Helper()
	if result != nil || !reflect.DeepEqual(a.calls, calls) {
		t.Fatalf("result %+v, calls\n%q\nwant\n%q", result, a.calls, calls)
	}
	var deleted [][]driver.Value
	if rolledBack {
		deleted = [][]driver.Value{{int64(42)}}
	}
	assertExecArgs(t, a.script, "DELETE FROM domains", deleted...)
}

// Every refusal before or during the migration is returned, and a refusal after
// the account was created removes it again.
func TestMigrateAccountRefusals(t *testing.T) {
	cases := []struct {
		name       string
		prepare    func(a *accountHarness)
		want       string
		calls      []string
		rolledBack bool
	}{
		{"an invalid domain", func(a *accountHarness) { a.account.DomainName = "nodot" }, "invalid domain name", nil, false},
		{"a banned list that cannot be read", func(a *accountHarness) { a.blockedErr = errScripted }, "banned domain list: scripted failure", nil, false},
		{"a banned domain", func(a *accountHarness) { a.blocked = true }, "'example.com' may not be added to this server", nil, false},
		{"a target check that fails", func(a *accountHarness) { a.script.fail["COALESCE(web_root,'')"] = errScripted }, "target check: scripted failure", nil, false},
		{"an existing domain without overwrite", func(a *accountHarness) { a.existing("") }, "'example.com' already exists on this server (overwrite is off)", nil, false},
		{"an owner that does not exist", func(a *accountHarness) {
			a.settings.CustomerID = 5
			a.script.rows["FROM customers"] = [][]driver.Value{{int64(0)}}
		}, "invalid customer", nil, false},
		{"a provisioning failure", func(a *accountHarness) { a.provisionErr = errScripted }, "provisioning: scripted failure", []string{provisioned}, false},
		{"a domain record that cannot be written", func(a *accountHarness) { a.script.fail["INSERT INTO domains"] = errScripted },
			"domain record: scripted failure", []string{provisioned, deprovisioned}, false},
		{"an invalid source web root", func(a *accountHarness) {
			a.settings.Files = true
			a.account.WebRoot = "relative/path"
		}, "the source web root is invalid", []string{provisioned, limited, ftpCreated, deprovisioned}, true},
		{"a file transfer that fails", func(a *accountHarness) {
			a.settings.Files = true
			a.account.WebRoot = "/home/acme/public_html"
			a.rsync = commandAnswer{stderr: "rsync: connection refused", exit: 12}
		}, "file transfer: rsync failed: rsync: connection refused", []string{provisioned, limited, ftpCreated, deprovisioned}, true},
		{"a database step that fails", func(a *accountHarness) {
			a.settings.Databases = true
			a.account.Databases = []string{"acme_wp"}
			a.creates.fail["c_example_com_wp"] = true
		}, "database migration failed: acme_wp", []string{provisioned, limited, ftpCreated, deprovisioned}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newAccountHarness(t)
			c.prepare(a)
			result, err := a.run()
			assertErrText(t, err, c.want)
			assertMigrationRefused(t, a, result, c.calls, c.rolledBack)
		})
	}
}

// A target directory that cannot be made stops the migration and removes the
// created account.
func TestMigrateAccountStopsWhenTheTargetDirectoryCannotBeMade(t *testing.T) {
	a := newAccountHarness(t)
	blocker := writeFile(t, "not-a-directory", nil)
	a.webRoot = filepath.Join(blocker, "public_html")
	a.settings.Files = true
	a.account.WebRoot = "/home/acme/public_html"
	result, err := a.run()
	assertErrText(t, err, "target directory: mkdir "+blocker+": not a directory")
	assertMigrationRefused(t, a, result, []string{provisioned, limited, ftpCreated, deprovisioned}, true)
}

// Overwrite writes into an existing domain's own root, falls back to the home
// public_html when the domain has none, and never removes a domain it did not
// create.
func TestMigrateAccountOverwritesAnExistingDomain(t *testing.T) {
	a := newAccountHarness(t)
	a.existing("")
	a.settings.Overwrite = true
	result, err := a.run()
	assertErrText(t, err, "")
	if !reflect.DeepEqual(result, &MigrationResult{DomainID: 15}) || len(a.calls) != 0 {
		t.Fatalf("result %+v, calls %q", result, a.calls)
	}
	assertLog(t, &a.log, "found an existing domain on this server, writing over it (id=15, root=/home/c_old/public_html)")
	assertExecArgs(t, a.script, "SET status='active'")

	b := newAccountHarness(t)
	b.existing(b.webRoot)
	b.settings = MigrationSettings{Overwrite: true, Files: true}
	b.account.WebRoot = "/home/acme/public_html"
	b.rsync = commandAnswer{stderr: "refused", exit: 1}
	_, err = b.run()
	assertErrText(t, err, "file transfer: rsync failed: refused")
	assertExecArgs(t, b.script, "DELETE FROM domains")
}

// rsyncArgv is the argv the password path runs to copy the web root.
func rsyncArgv(webRoot string) []string {
	ssh := "ssh -p 22 -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/var/lib/servika/known_hosts_migration" +
		" -o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes -o PermitLocalCommand=no -o PubkeyAuthentication=no" +
		" -o PreferredAuthentications=password,keyboard-interactive -o NumberOfPasswordPrompts=1"
	return []string{"sshpass", "-e", "rsync", "-a", "--numeric-ids", "--timeout=120", "--partial", "--no-perms",
		"--chmod=Du=rwx,Dgo=rx,Fu=rw,Fgo=r", "--safe-links", "-e", ssh, "--exclude=.git/", "--exclude=*.sock", "--exclude=.cpanel/",
		"root@src.example.com:/home/acme/public_html/", webRoot + "/"}
}

// A new account with every step on: files, a database found in the copied
// configuration and rewritten, DNS, the source certificate and a mailbox, then
// the domain is activated.
func TestMigrateAccountMigratesEverything(t *testing.T) {
	a := newAccountHarness(t)
	const wpConfig = "<?php\ndefine('DB_NAME', 'acme_wp');\ndefine('DB_USER', 'acme');\ndefine('DB_PASSWORD', 'old');\n"
	wp := writeSiteFile(t, a.webRoot, "wp-config.php", wpConfig, 0o640)
	a.account.WebRoot = "/home/acme/public_html"
	a.account.PHPVersion = "8.2"
	a.settings = MigrationSettings{Files: true, Databases: true, DNS: true, SSL: true, Mail: true, PlanID: 2, CustomerID: 3}
	a.zone = commandAnswer{output: "@ IN A 198.51.100.7\n"}
	a.cert = commandAnswer{output: certMarkerStart + "\n" + string(selfSignedPEM(t)) + "\n" + certMarkerKey + "\nKEY\n" + certMarkerEnd + "\n"}
	a.mailboxes = commandAnswer{output: "info\n"}
	a.aliases = commandAnswer{output: "sales: out@example.com\n"}

	result, err := a.run()
	assertErrText(t, err, "")
	want := &MigrationResult{DomainID: 42, FileBytes: int64(len(wpConfig)), DBCount: 1, DNSCount: 1, MailCount: 1,
		Warnings: []string{"the imported SSL certificate is self-signed; renew it via Let's Encrypt once DNS points at this server"}}
	if !reflect.DeepEqual(result, want) {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
	if !reflect.DeepEqual(a.calls, []string{"provision example.com 8.2", limited, ftpCreated, "import-ssl example.com"}) {
		t.Fatalf("calls = %q", a.calls)
	}
	assertExecArgs(t, a.script, "INSERT INTO domains", []driver.Value{"example.com", "c_example_com", "8.2", "203.0.113.99", "203.0.113.99",
		"c_example_com", "c_example_com_db", "c_example_com_main", a.webRoot, int64(2), int64(3)})
	assertExecArgs(t, a.script, "SET status='active'", []driver.Value{int64(42)})
	assertExecArgs(t, a.script, "DELETE FROM domains")
	if !a.commands.ran(rsyncArgv(a.webRoot)...) || !a.commands.ran("chown", "-R", "c_example_com:c_example_com", a.webRoot) {
		t.Fatalf("commands = %q", a.commands.argvs())
	}
	rewritten, err := os.ReadFile(wp)
	if err != nil || !strings.Contains(string(rewritten), "define('DB_NAME', 'c_example_com_wp');") {
		t.Fatalf("wp-config = %q, %v", rewritten, err)
	}
	assertLogHolds(t, &a.log,
		"creating the system account (php 8.2)...",
		"copying files: /home/acme/public_html -> "+a.webRoot,
		"discovery found no database; 1 name(s) read from configuration: [acme_wp]",
		"1 configuration file(s) updated (database connection)",
		"DNS: 1 record(s) migrated",
		"SSL: imported the source certificate (self-signed)",
		"Mail: 1 mailbox(es) migrated",
		"Mail: new credential info@example.com / pw-info",
	)
}

// Every step that degrades instead of failing adds its warning, in step order.
func TestMigrateAccountReportsEveryWarning(t *testing.T) {
	a := newAccountHarness(t)
	loadedPHP(t, "8.2")
	a.account.PHPVersion = "8.1"
	a.settings = MigrationSettings{Files: true, Databases: true, DNS: true, SSL: true, Mail: true}
	a.limitsErr = errScripted
	a.ftpErr = errScripted
	a.zone = commandAnswer{stderr: "denied", exit: 1}
	a.certPath = "/ssl/example.com.crt"
	a.outcome = provisioner.IssueOutcome{Reason: "rate limited"}
	a.h.Mail = nil

	result, err := a.run()
	assertErrText(t, err, "")
	want := []string{
		"PHP 8.1 is not installed, provisioned with 8.2",
		"resource limits could not be applied",
		"files were not migrated: this domain has no web root of its own (it may be a redirect subdomain)",
		"no database migrated: the source has no database for this site (an addon/subdomain's database migrates with the main domain, or discovery could not see it)",
		"DNS was created from the default template",
		"SSL is self-signed, renew it once DNS points at this server (rate limited)",
		"mail could not be migrated",
	}
	if !reflect.DeepEqual(result.Warnings, want) || result.DomainID != 42 {
		t.Fatalf("result = %+v", result)
	}
	assertExecArgs(t, a.script, "ssl_source=?", []driver.Value{"self-signed", "/ssl/example.com.crt", "/ssl/example.com.key", int64(42)})
	assertLogHolds(t, &a.log,
		"warning: source PHP 8.1 is not installed here, using 8.2 instead",
		"warning: resource limits could not be applied: scripted failure",
		"warning: the FTP account could not be created: scripted failure",
		"no web root for this domain (redirect or hosting-less); files not migrated",
		"warning: no database was found on the source for this site; SQL was not migrated",
		"warning: DNS could not be migrated (default template used): the source DNS records could not be read",
		"SSL: the source has no usable certificate; trying Let's Encrypt",
		"requesting an SSL certificate...",
		"SSL: self-signed",
		"warning: mail could not be migrated: mail provider is not ready",
	)
}

func assertSSLSource(t *testing.T, a *accountHarness, source string) {
	t.Helper()
	var want [][]driver.Value
	if source != "" {
		want = [][]driver.Value{{source, "/ssl/example.com.crt", "/ssl/example.com.key", int64(42)}}
	}
	assertExecArgs(t, a.script, "ssl_source=?", want...)
}

// The Let's Encrypt outcome decides the stored certificate source and the
// warning; a source with no mailbox migrates no mail and says nothing.
func TestMigrateAccountLetsEncryptOutcomes(t *testing.T) {
	cases := []struct {
		name     string
		certPath string
		outcome  provisioner.IssueOutcome
		issueErr error
		source   string
		warnings []string
	}{
		{"a real certificate", "/ssl/example.com.crt", provisioner.IssueOutcome{Real: true}, nil, "letsencrypt", nil},
		{"a self-signed fallback", "/ssl/example.com.crt", provisioner.IssueOutcome{}, nil, "self-signed",
			[]string{"SSL is self-signed, renew it once DNS points at this server"}},
		{"no certificate", "", provisioner.IssueOutcome{}, errScripted, "", []string{"SSL could not be obtained"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newAccountHarness(t)
			a.settings = MigrationSettings{SSL: true, Mail: true}
			a.lookupErr = errScripted
			a.certPath, a.outcome, a.issueErr = c.certPath, c.outcome, c.issueErr
			result, err := a.run()
			assertErrText(t, err, "")
			if !reflect.DeepEqual(result.Warnings, c.warnings) || result.MailCount != 0 {
				t.Fatalf("result = %+v", result)
			}
			if want := []string{provisioned, limited, "letsencrypt example.com c_example_com 8.3 php-fpm"}; !reflect.DeepEqual(a.calls, want) {
				t.Fatalf("calls = %q", a.calls)
			}
			assertSSLSource(t, a, c.source)
		})
	}
}
