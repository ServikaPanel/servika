package antivirus

// The database scan, measured against a real MariaDB.
//
// Nothing here can be proved with a fake: what is being tested is a connection
// as a tenant account, a read of information_schema, and an autoload column
// whose accepted values changed with WordPress 6.6. The test is skipped without
// SERVIKA_TEST_DSN, like every other live test in this package.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"

	"servika/internal/credentials"
)

// tenantServer is a second connection to the same server, used to build the
// tenant schema the scan then reads as the tenant.
func tenantServer(t *testing.T) (*sql.DB, *mysql.Config) {
	t.Helper()
	raw := os.Getenv("SERVIKA_TEST_DSN")
	if raw == "" {
		t.Skip("SERVIKA_TEST_DSN is not set")
	}
	settings, err := mysql.ParseDSN(raw)
	if err != nil {
		t.Fatalf("parse the test DSN: %v", err)
	}
	handle, err := sql.Open("mysql", raw)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := handle.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	return handle, settings
}

// overTCP points the scan at the same server the test DSN names. Production
// always uses the unix socket; this is the seam that lets the scan itself run
// against a server reachable only over TCP.
func overTCP(t *testing.T, settings *mysql.Config) {
	t.Helper()
	original := schemaDSN
	t.Cleanup(func() { schemaDSN = original })
	schemaDSN = func(schema tenantSchema) string {
		out := mysql.NewConfig()
		out.User = schema.user
		out.Passwd = schema.password
		out.Net = settings.Net
		out.Addr = settings.Addr
		out.DBName = schema.name
		out.Timeout = dbConnectTimeout
		out.ReadTimeout = dbConnectTimeout * 2
		return out.FormatDSN()
	}
}

// wpFixture builds a domain, a tenant schema with WordPress tables, and the
// db_accounts row that ties them together.
type wpFixture struct {
	domainID int64
	schema   string
	user     string
	password string
}

func newWPFixture(t *testing.T, panel *sql.DB, server *sql.DB, suffix string) wpFixture {
	t.Helper()
	f := wpFixture{
		schema:   "c_avdb" + suffix,
		user:     "c_avdb" + suffix,
		password: "TestOnlyPassword" + suffix,
	}

	res, err := panel.Exec(`INSERT INTO domains (domain_name, system_user) VALUES (?,?)`,
		"avdb"+suffix+".example.test", "c_avdb"+suffix)
	if err != nil {
		t.Fatalf("fixture domain: %v", err)
	}
	f.domainID, _ = res.LastInsertId()
	t.Cleanup(func() { _, _ = panel.Exec(`DELETE FROM domains WHERE id=?`, f.domainID) })

	// The schema and the account the scan will authenticate as. '%' rather than
	// 'localhost' only because the test reaches the server over TCP; production
	// creates 'user'@'localhost' and connects over the socket.
	for _, statement := range []string{
		"CREATE DATABASE IF NOT EXISTS `" + f.schema + "`",
		"CREATE USER IF NOT EXISTS '" + f.user + "'@'%' IDENTIFIED BY '" + f.password + "'",
		"GRANT ALL PRIVILEGES ON `" + f.schema + "`.* TO '" + f.user + "'@'%'",
		"FLUSH PRIVILEGES",
	} {
		if _, err := server.Exec(statement); err != nil {
			t.Fatalf("fixture schema: %v (%s)", err, statement)
		}
	}
	t.Cleanup(func() {
		_, _ = server.Exec("DROP DATABASE IF EXISTS `" + f.schema + "`")
		_, _ = server.Exec("DROP USER IF EXISTS '" + f.user + "'@'%'")
	})

	// db_pass_plain accepts a legacy plaintext value: DecryptDBPass passes an
	// unprefixed value through unchanged.
	if _, err := panel.Exec(
		`INSERT INTO db_accounts (domain_id, db_name, db_user, db_pass_plain) VALUES (?,?,?,?)`,
		f.domainID, f.schema, f.user, f.password); err != nil {
		t.Fatalf("fixture db_accounts: %v", err)
	}
	t.Cleanup(func() { _, _ = panel.Exec(`DELETE FROM db_accounts WHERE db_name=?`, f.schema) })
	return f
}

// installWordPress creates the two tables the scan reads, with the given
// autoload value on the injected option.
func installWordPress(t *testing.T, server *sql.DB, schema, prefix, autoload, optionValue string) {
	t.Helper()
	exec := func(statement string, args ...any) {
		t.Helper()
		if _, err := server.Exec(statement, args...); err != nil {
			t.Fatalf("fixture: %v (%s)", err, statement)
		}
	}
	table := "`" + schema + "`.`" + prefix + "options`"
	exec("CREATE TABLE IF NOT EXISTS " + table + " (" +
		"option_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY," +
		"option_name VARCHAR(191) NOT NULL," +
		"option_value LONGTEXT NOT NULL," +
		"autoload VARCHAR(20) NOT NULL DEFAULT 'yes')")
	exec("INSERT INTO "+table+" (option_name, option_value, autoload) VALUES (?,?,?)",
		"siteurl", "https://example.com", "yes")
	exec("INSERT INTO "+table+" (option_name, option_value, autoload) VALUES (?,?,?)",
		"widget_evil", optionValue, autoload)

	posts := "`" + schema + "`.`" + prefix + "posts`"
	exec("CREATE TABLE IF NOT EXISTS " + posts + " (" +
		"ID BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY," +
		"post_title TEXT NOT NULL," +
		"post_content LONGTEXT NOT NULL," +
		"post_status VARCHAR(20) NOT NULL DEFAULT 'publish')")
	exec("INSERT INTO "+posts+" (post_title, post_content, post_status) VALUES (?,?,?)",
		"Hello", "<p>An ordinary page.</p>", "publish")
}

func runDBScan(t *testing.T, panel *sql.DB) DBScanResult {
	t.Helper()
	h := &Handlers{DB: panel}
	rec := httptest.NewRecorder()
	h.AdminDBScan(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("the scan answered %d: %s", rec.Code, rec.Body.String())
	}
	var result DBScanResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return result
}

func findingsFor(t *testing.T, panel *sql.DB, domainID int64) []string {
	t.Helper()
	rows, err := panel.Query(
		`SELECT file FROM av_findings WHERE domain_id=? AND engine=? ORDER BY id`,
		domainID, EngineDatabase)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var file string
		if err := rows.Scan(&file); err != nil {
			t.Fatal(err)
		}
		out = append(out, file)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// MEASURED: WordPress 6.6 changed what the autoload column carries. A query
// asking only for 'yes' finds nothing on a current installation, so the
// autoloaded values, which are the ones WordPress loads on every request, would
// all be missed. This is the whole reason to look in wp_options at all.
func TestEveryAutoloadValueWordPressWritesIsRead(t *testing.T) {
	panel, settings := tenantServer(t)
	overTCP(t, settings)

	for _, autoload := range []string{"yes", "on", "auto"} {
		t.Run(autoload, func(t *testing.T) {
			f := newWPFixture(t, panel, panel, autoload)
			installWordPress(t, panel, f.schema, "wp_", autoload,
				`eval(base64_decode('c3lzdGVtKCRfR0VUWyJjIl0pOw=='));`)
			t.Cleanup(func() { _, _ = panel.Exec(`DELETE FROM av_findings WHERE domain_id=?`, f.domainID) })

			result := runDBScan(t, panel)
			if result.Failed != 0 {
				t.Fatalf("%d schemas could not be read", result.Failed)
			}
			found := findingsFor(t, panel, f.domainID)
			if len(found) != 1 {
				t.Fatalf("autoload=%s produced %d findings, want 1: %v", autoload, len(found), found)
			}
			if !strings.Contains(found[0], "wp_options") || !strings.Contains(found[0], "widget_evil") {
				t.Errorf("the finding does not name the row: %q", found[0])
			}
		})
	}
}

// A row WordPress does NOT autoload is not read, because it is not loaded on
// every request and reading every option on every site is what the autoload
// filter exists to avoid.
func TestANonAutoloadedOptionIsNotRead(t *testing.T) {
	panel, settings := tenantServer(t)
	overTCP(t, settings)

	f := newWPFixture(t, panel, panel, "off")
	installWordPress(t, panel, f.schema, "wp_", "off",
		`eval(base64_decode('c3lzdGVtKCRfR0VUWyJjIl0pOw=='));`)
	t.Cleanup(func() { _, _ = panel.Exec(`DELETE FROM av_findings WHERE domain_id=?`, f.domainID) })

	if result := runDBScan(t, panel); result.Failed != 0 {
		t.Fatalf("%d schemas could not be read", result.Failed)
	}
	if found := findingsFor(t, panel, f.domainID); len(found) != 0 {
		t.Errorf("a non-autoloaded option was read: %v", found)
	}
}

// A schema the scan could not open is COUNTED, never passed over. An empty
// finding list is byte-for-byte what a clean site produces.
func TestASchemaThatCannotBeOpenedIsCountedAsFailed(t *testing.T) {
	panel, settings := tenantServer(t)
	overTCP(t, settings)

	f := newWPFixture(t, panel, panel, "denied")
	installWordPress(t, panel, f.schema, "wp_", "yes", "https://example.com")
	// The stored password no longer authenticates, which is what a rotated or
	// hand-edited account looks like.
	if _, err := panel.Exec(`UPDATE db_accounts SET db_pass_plain=? WHERE db_name=?`,
		"NotThePassword", f.schema); err != nil {
		t.Fatal(err)
	}

	result := runDBScan(t, panel)
	if result.Failed < 1 {
		t.Fatal("a schema whose credentials are wrong was not counted as failed")
	}
	// And it is not counted as a schema that was read.
	for _, name := range findingsFor(t, panel, f.domainID) {
		t.Errorf("a finding was recorded for an unreadable schema: %q", name)
	}
}

// A database behind something other than WordPress is neither a failure nor a
// finding: there is nothing here to scan.
func TestASchemaWithNoWordPressTablesIsNotAnInstallation(t *testing.T) {
	panel, settings := tenantServer(t)
	overTCP(t, settings)

	f := newWPFixture(t, panel, panel, "plain")
	if _, err := panel.Exec("CREATE TABLE `" + f.schema + "`.`invoices` (id INT PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}

	before := runDBScan(t, panel)
	if before.Failed != 0 {
		t.Fatalf("%d schemas could not be read", before.Failed)
	}
	if found := findingsFor(t, panel, f.domainID); len(found) != 0 {
		t.Errorf("a non-WordPress schema produced findings: %v", found)
	}
}

// A site with a table prefix of its own is still found: the table names come
// from information_schema rather than from a tenant's $table_prefix.
func TestACustomTablePrefixIsFound(t *testing.T) {
	panel, settings := tenantServer(t)
	overTCP(t, settings)

	f := newWPFixture(t, panel, panel, "prefix")
	installWordPress(t, panel, f.schema, "xyz9_", "yes",
		`<script>eval(atob('YWxlcnQoMSk='))</script>`)
	t.Cleanup(func() { _, _ = panel.Exec(`DELETE FROM av_findings WHERE domain_id=?`, f.domainID) })

	if result := runDBScan(t, panel); result.Failed != 0 {
		t.Fatalf("%d schemas could not be read", result.Failed)
	}
	found := findingsFor(t, panel, f.domainID)
	if len(found) != 1 || !strings.Contains(found[0], "xyz9_options") {
		t.Fatalf("a custom prefix was not scanned: %v", found)
	}
}

// The recorded finding is reachable from a scan row, exactly as a file finding
// is, and it carries the engine that makes it uncontainable.
func TestADatabaseFindingIsRecordedLikeAnyOther(t *testing.T) {
	panel, settings := tenantServer(t)
	overTCP(t, settings)

	f := newWPFixture(t, panel, panel, "record")
	installWordPress(t, panel, f.schema, "wp_", "yes", `assert($_POST['x']);`)
	t.Cleanup(func() { _, _ = panel.Exec(`DELETE FROM av_findings WHERE domain_id=?`, f.domainID) })

	if result := runDBScan(t, panel); result.Findings != 1 {
		t.Fatalf("the scan reported %d findings, want 1 (failed %d)", result.Findings, result.Failed)
	}

	var scanID int64
	var engine, level string
	if err := panel.QueryRow(
		`SELECT f.scan_id, f.engine, f.level FROM av_findings f WHERE f.domain_id=? AND f.engine=?`,
		f.domainID, EngineDatabase).Scan(&scanID, &engine, &level); err != nil {
		t.Fatalf("the finding was not recorded: %v", err)
	}
	if scanID == 0 {
		t.Error("the finding is not tied to a scan row, so it is reachable from no run")
	}
	if level != LevelCritical {
		t.Errorf("the finding came back %s, want %s", level, LevelCritical)
	}
	var status, scanEngine string
	if err := panel.QueryRow(`SELECT status, engine FROM av_scans WHERE id=?`, scanID).
		Scan(&status, &scanEngine); err != nil {
		t.Fatalf("the scan row is missing: %v", err)
	}
	if status != "finished" || scanEngine != EngineDatabase {
		t.Errorf("the scan row reads status=%q engine=%q", status, scanEngine)
	}
}

// The containment gate, measured end to end rather than on the source: the
// automatic pass must not select this finding, and the handler must refuse it.
func TestADatabaseFindingIsNeverContained(t *testing.T) {
	panel, settings := tenantServer(t)
	overTCP(t, settings)

	f := newWPFixture(t, panel, panel, "contain")
	installWordPress(t, panel, f.schema, "wp_", "yes", `assert($_POST['x']);`)
	t.Cleanup(func() { _, _ = panel.Exec(`DELETE FROM av_findings WHERE domain_id=?`, f.domainID) })

	runDBScan(t, panel)

	var scanID, findingID int64
	if err := panel.QueryRow(
		`SELECT scan_id, id FROM av_findings WHERE domain_id=? AND engine=?`,
		f.domainID, EngineDatabase).Scan(&scanID, &findingID); err != nil {
		t.Fatalf("the finding was not recorded: %v", err)
	}

	h := &Handlers{DB: panel}
	// The automatic pass selects nothing, so neither counter moves. Counting a
	// refusal as a failure is what sends an operator after a fault that is not
	// there.
	outcome := h.autoQuarantine(context.Background(), scanID)
	if outcome.Taken != 0 || outcome.Failed != 0 {
		t.Errorf("automatic containment reported taken=%d failed=%d for a database finding",
			outcome.Taken, outcome.Failed)
	}
	// And the handler refuses with the reason that says what is true.
	if reason := h.quarantineFinding(f.domainID, "c_avdbcontain", findingID); reason != reasonNotAFile {
		t.Errorf("containment answered %q, want %q", reason, reasonNotAFile)
	}
}

// MariaDB accepts a table name that is not an identifier: a backtick inside a
// quoted name is written by doubling it. Such a name reaches this package
// through information_schema, which reports what the TENANT named their table,
// so it is refused rather than quoted. Quoting would be trusting the escape;
// refusing is not trusting anything.
//
// Non-vacuous in both directions: the same site's ordinary wp_options IS
// scanned in the same pass, so a refusal that swallowed the whole schema would
// fail here too.
func TestATableNameThatIsNotAnIdentifierIsRefused(t *testing.T) {
	panel, settings := tenantServer(t)
	overTCP(t, settings)

	f := newWPFixture(t, panel, panel, "ident")
	installWordPress(t, panel, f.schema, "wp_", "yes", `assert($_POST['x']);`)
	t.Cleanup(func() { _, _ = panel.Exec(`DELETE FROM av_findings WHERE domain_id=?`, f.domainID) })

	// A second options table whose name carries a backtick. The doubling is how
	// MariaDB spells one inside a quoted identifier.
	hostile := "`" + f.schema + "`.`wp``evil_options`"
	if _, err := panel.Exec("CREATE TABLE " + hostile + " (" +
		"option_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY," +
		"option_name VARCHAR(191) NOT NULL," +
		"option_value LONGTEXT NOT NULL," +
		"autoload VARCHAR(20) NOT NULL DEFAULT 'yes')"); err != nil {
		t.Fatalf("the server refused the fixture table, so this proves nothing: %v", err)
	}
	if _, err := panel.Exec("INSERT INTO "+hostile+" (option_name, option_value, autoload) VALUES (?,?,?)",
		"payload", `assert($_POST['x']);`, "yes"); err != nil {
		t.Fatal(err)
	}
	// The name really is what the test claims: not an identifier.
	if credentials.ValidDBIdentifier("wp`evil_options") {
		t.Fatal("the fixture name passes ValidDBIdentifier, so it proves nothing")
	}

	result := runDBScan(t, panel)
	if result.Failed != 0 {
		t.Fatalf("%d schemas could not be read", result.Failed)
	}
	found := findingsFor(t, panel, f.domainID)
	if len(found) != 1 {
		t.Fatalf("the pass reported %d findings, want 1 (the ordinary table only): %v", len(found), found)
	}
	if !strings.Contains(found[0], "wp_options") {
		t.Errorf("the surviving finding is not the ordinary table: %q", found[0])
	}
	if strings.Contains(found[0], "evil_options") {
		t.Errorf("a name that is not an identifier reached a statement: %q", found[0])
	}
}
