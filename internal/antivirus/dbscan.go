package antivirus

// Malware that lives in a WordPress database rather than in a file.
//
// The file scan walks the disk, so it cannot see the most common shape of a
// WordPress compromise: a payload written into wp_options with autoload on,
// which WordPress loads on EVERY request, or injected into post content. A site
// can be reported clean by every file pass on this server and still be serving
// spam from a row.
//
// This is the FIRST place in the panel that opens a sql.DB against a tenant
// schema. The panel's own connection cannot do it: the installer creates
// 'panel'@'127.0.0.1' with GRANT ALL on panel.* alone, so it has no privilege
// anywhere else. Four rules bind anything that touches this file.
//
// THE SCHEMA LIST COMES FROM db_accounts, AND wp-config.php IS NEVER READ. A
// tenant cannot CREATE DATABASE: every account the panel makes is granted on
// one schema and carries no global CREATE, so every tenant database was created
// by the panel and has a db_accounts row. That row is also the ownership proof,
// which is exactly how internal/siteimport uses it. Reading the tenant's
// wp-config.php instead would mean following a path a tenant controls (a
// planted symlink), trusting a DB_HOST a tenant controls (the panel would dial
// wherever they name and hand over their own database password on the way), and
// interpolating a $table_prefix a tenant controls into SQL.
//
// EVERY IDENTIFIER IS VALIDATED BEFORE IT IS INTERPOLATED. MariaDB does not
// accept a placeholder where a schema or table name goes, so the name is built
// into the statement, and credentials.ValidDBIdentifier is the gate. The table
// name comes from information_schema rather than from a tenant's configuration,
// but it is still checked: what a row in that view says is what the tenant
// named their table.
//
// THE CONNECTION GOES OVER THE UNIX SOCKET. The panel creates every tenant
// account as 'user'@'localhost', and MariaDB treats a TCP connection to
// 127.0.0.1 as a different host, so it answers access denied. The password is
// decrypted from db_accounts and put in a DSN, never in an argument list.
//
// A SCHEMA THAT COULD NOT BE READ IS COUNTED, NEVER PASSED OVER. An empty
// finding list is byte-for-byte what a clean site produces, so a scan that
// could not connect must not read as one that found nothing.

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"

	"servika/internal/config"
	"servika/internal/credentials"
	"servika/internal/httpx"
)

const (
	// dbScanBudget bounds the whole pass. It is shorter than the file scan's
	// because this reads rows rather than walking a filesystem, and the request
	// that started it is waiting.
	dbScanBudget = 4 * time.Minute
	// dbConnectTimeout bounds one connection. A schema whose account no longer
	// authenticates must not spend the whole budget.
	dbConnectTimeout = 5 * time.Second
	// dbRowLimit bounds how many rows of one table are read. A site with more
	// autoloaded options than this has a problem of its own, and the limit is
	// reported rather than silently applied.
	dbRowLimit = 5000
)

// DBScanResult is what one pass reports.
type DBScanResult struct {
	// Schemas is how many tenant databases were opened and read.
	Schemas int `json:"schemas"`
	// Installations is how many of them held WordPress tables.
	Installations int `json:"installations"`
	// Findings is the total across every schema.
	Findings int `json:"findings"`
	// Failed is how many schemas could NOT be read. It is reported beside the
	// findings rather than folded into them, because a schema that failed is
	// not a schema that came back clean, and an empty finding list looks
	// identical for both.
	Failed int `json:"failed"`
}

// tenantSchema is one database the panel knows belongs to a domain.
type tenantSchema struct {
	domainID int64
	name     string
	user     string
	password string
}

// AdminDBScan answers POST /admin/antivirus/db-scan (AdminOnly).
//
// Admin only, and not scoped: it opens a connection to every tenant database on
// the server, which is not something a reseller's scope makes reasonable.
func (h *Handlers) AdminDBScan(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), dbScanBudget)
	defer cancel()

	schemas, err := h.tenantSchemas(ctx)
	if err != nil {
		log.Printf("antivirus: the tenant database list could not be read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the tenant databases could not be listed")
		return
	}

	result := DBScanResult{}
	for _, schema := range schemas {
		if ctx.Err() != nil {
			break
		}
		findings, installed, err := scanSchema(ctx, schema)
		if err != nil {
			// #nosec G706 -- the schema name passed ValidDBIdentifier, so it carries no CR/LF.
			log.Printf("antivirus: %s could not be scanned: %v", schema.name, err)
			result.Failed++
			continue
		}
		result.Schemas++
		if !installed {
			continue
		}
		result.Installations++
		if len(findings) == 0 {
			continue
		}
		// One scan row per schema, so a finding is reachable from the run that
		// produced it exactly as a file finding is.
		if _, err := RecordScan(h.DB, schema.domainID, EngineDatabase, len(findings), findings); err != nil {
			// #nosec G706 -- the schema name passed ValidDBIdentifier.
			log.Printf("antivirus: the findings for %s could not be recorded: %v", schema.name, err)
			result.Failed++
			continue
		}
		result.Findings += len(findings)
	}

	httpx.WriteJSON(w, http.StatusOK, result)
}

// tenantSchemas lists every database the panel created for a domain.
//
// The join to domains is what excludes a row whose domain has been deleted: the
// cascade removes it, but a scan that raced the deletion would otherwise try to
// record a finding against a domain that is gone.
func (h *Handlers) tenantSchemas(ctx context.Context) ([]tenantSchema, error) {
	rows, err := h.DB.QueryContext(ctx,
		`SELECT a.domain_id, a.db_name, a.db_user, a.db_pass_plain
		   FROM db_accounts a JOIN domains d ON d.id = a.domain_id
		  ORDER BY a.domain_id, a.db_name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []tenantSchema
	for rows.Next() {
		var schema tenantSchema
		var stored string
		if err := rows.Scan(&schema.domainID, &schema.name, &schema.user, &stored); err != nil {
			return nil, err
		}
		// A name or user that is not a valid identifier can never be
		// interpolated into a statement, so it is refused here rather than
		// further down where the refusal would be one branch among many.
		if !credentials.ValidDBIdentifier(schema.name) || !credentials.ValidDBIdentifier(schema.user) {
			// #nosec G706 -- the value is refused precisely because it is not an identifier, so it is not logged.
			log.Printf("antivirus: a db_accounts row for domain %d carries an identifier that is not valid; skipping it",
				schema.domainID)
			continue
		}
		password, err := credentials.DecryptDBPass(schema.user, stored)
		if err != nil {
			// #nosec G706 -- the user name passed ValidDBIdentifier.
			log.Printf("antivirus: the stored password for %s could not be read: %v", schema.user, err)
			continue
		}
		schema.password = password
		out = append(out, schema)
	}
	// A query that broke half way would otherwise scan a short list and report
	// the rest of the server as having no databases at all.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// schemaDSN builds the connection string for one tenant schema.
//
// The DSN is assembled by the DRIVER rather than by string concatenation, so
// the password is escaped by the code that owns the format.
//
// It is a seam. Production always connects over the unix socket, because the
// panel creates every tenant account as 'user'@'localhost' and MariaDB treats a
// TCP connection to 127.0.0.1 as a different host; a test runs against a server
// it can only reach over TCP, and replacing the whole open would leave the
// scan itself unexercised.
var schemaDSN = func(schema tenantSchema) string {
	settings := mysql.NewConfig()
	settings.User = schema.user
	settings.Passwd = schema.password
	settings.Net = "unix"
	settings.Addr = config.MySQLSocket()
	settings.DBName = schema.name
	settings.Timeout = dbConnectTimeout
	settings.ReadTimeout = dbConnectTimeout * 2
	settings.Params = map[string]string{"charset": "utf8mb4"}
	return settings.FormatDSN()
}

// openSchema connects as the schema's own account.
func openSchema(ctx context.Context, schema tenantSchema) (*sql.DB, error) {
	handle, err := sql.Open("mysql", schemaDSN(schema))
	if err != nil {
		return nil, err
	}
	// Two is enough for one schema at a time and keeps a server-wide pass from
	// holding a connection per tenant against MariaDB's max_connections.
	handle.SetMaxOpenConns(2)
	if err := handle.PingContext(ctx); err != nil {
		_ = handle.Close()
		return nil, err
	}
	return handle, nil
}

// scanSchema reads one tenant database and weighs what it finds.
//
// The second return says whether the schema held WordPress tables at all. A
// database behind something other than WordPress is not a failure and not a
// finding; it is simply out of scope for this pass.
func scanSchema(ctx context.Context, schema tenantSchema) ([]Finding, bool, error) {
	handle, err := openSchema(ctx, schema)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = handle.Close() }()

	tables, err := wordpressTables(ctx, handle, schema.name)
	if err != nil {
		return nil, false, err
	}
	if len(tables.options) == 0 && len(tables.posts) == 0 {
		return nil, false, nil
	}

	var findings []Finding
	for _, table := range tables.options {
		found, err := scanOptions(ctx, handle, table)
		if err != nil {
			return nil, true, err
		}
		findings = append(findings, found...)
	}
	for _, table := range tables.posts {
		found, err := scanPosts(ctx, handle, table)
		if err != nil {
			return nil, true, err
		}
		findings = append(findings, found...)
	}
	return findings, true, nil
}

// wordpressTables is the option and post tables in one schema.
//
// A site can carry several WordPress installations in one database, told apart
// by their table prefix, so both are lists. The names come from
// information_schema rather than from a tenant's $table_prefix, and each is
// still validated: what that view reports is what the tenant named their table.
type wpTables struct {
	options []string
	posts   []string
}

func wordpressTables(ctx context.Context, handle *sql.DB, schema string) (wpTables, error) {
	var out wpTables
	rows, err := handle.QueryContext(ctx,
		`SELECT TABLE_NAME FROM information_schema.TABLES
		  WHERE TABLE_SCHEMA = ? AND (TABLE_NAME LIKE '%options' OR TABLE_NAME LIKE '%posts')`, schema)
	if err != nil {
		return out, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return out, err
		}
		if !credentials.ValidDBIdentifier(name) {
			// A table whose name is not an identifier cannot be interpolated,
			// and quoting it would be trusting the escape rather than refusing
			// the input. The name is not logged, because it is refused for
			// carrying characters that do not belong in a log line either.
			continue
		}
		switch {
		case strings.HasSuffix(name, "options"):
			out.options = append(out.options, name)
		case strings.HasSuffix(name, "posts"):
			out.posts = append(out.posts, name)
		}
	}
	return out, rows.Err()
}

// scanOptions weighs every autoloaded option value.
//
// autoload is checked against THREE values. WordPress 6.6 changed what it
// writes: the column now carries 'on', 'auto' and 'off' beside the historic
// 'yes' and 'no', so a query asking only for 'yes' misses every autoloaded row
// on a current installation, which is the whole point of looking here.
//
// There is no content prefilter. The autoloaded set is bounded and it is the
// dangerous one: WordPress loads every row in it on every request.
func scanOptions(ctx context.Context, handle *sql.DB, table string) ([]Finding, error) {
	// #nosec G202 -- table passed credentials.ValidDBIdentifier, so it is [A-Za-z0-9_]{1,64}; MariaDB accepts no placeholder here.
	query := "SELECT option_id, option_name, option_value FROM `" + table +
		"` WHERE autoload IN ('yes','on','auto') LIMIT " + strconv.Itoa(dbRowLimit)
	rows, err := handle.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Finding
	for rows.Next() {
		var id int64
		var name, value string
		if err := rows.Scan(&id, &name, &value); err != nil {
			return nil, err
		}
		if finding, ok := weighRow(table, "option", id, name, value); ok {
			out = append(out, finding)
		}
	}
	return out, rows.Err()
}

// postPrefilter is what makes scanning post content affordable.
//
// wp_posts holds every revision of every page, so weighing all of it would read
// the whole site. The filter bounds what is READ, and a rule whose trigger is
// not reachable through one of these substrings cannot fire on a post. That is
// a stated limit rather than a hidden one: the autoloaded options above carry
// no prefilter at all, and they are where an injection that has to run on every
// request must live.
var postPrefilter = []string{
	"eval", "base64_decode", "gzinflate", "gzuncompress", "gzdecode", "str_rot13",
	"assert(", "shell_exec", "passthru", "proc_open", "popen", "system(",
	"create_function", "preg_replace", "move_uploaded_file", "file_put_contents",
	"FilesMan", "<script",
}

func scanPosts(ctx context.Context, handle *sql.DB, table string) ([]Finding, error) {
	conditions := make([]string, 0, len(postPrefilter))
	args := make([]any, 0, len(postPrefilter))
	for _, term := range postPrefilter {
		conditions = append(conditions, "post_content LIKE ?")
		args = append(args, "%"+term+"%")
	}
	// #nosec G202 -- table passed credentials.ValidDBIdentifier; the conditions are a fixed count of literal LIKE clauses and every term is bound.
	query := "SELECT ID, post_title, post_content FROM `" + table +
		"` WHERE post_status IN ('publish','draft','private','pending') AND (" +
		strings.Join(conditions, " OR ") + ") LIMIT " + strconv.Itoa(dbRowLimit)
	rows, err := handle.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Finding
	for rows.Next() {
		var id int64
		var title, content string
		if err := rows.Scan(&id, &title, &content); err != nil {
			return nil, err
		}
		if finding, ok := weighRow(table, "post", id, title, content); ok {
			out = append(out, finding)
		}
	}
	return out, rows.Err()
}

// weighRow turns one row into a finding, or into nothing.
//
// The level comes from the same thresholds the file scan uses, so a single
// moderate signal never convicts: a page builder storing a PHP snippet and a
// theme storing an analytics script are each one signal, and reporting either
// would report a working site.
func weighRow(table, kind string, id int64, name, value string) (Finding, bool) {
	matches := evaluateDatabaseValue(clampValue(value))
	if len(matches) == 0 {
		return Finding{}, false
	}
	score, signature, names, level := verdict(matches, 0)
	if level == "" {
		return Finding{}, false
	}
	return Finding{
		File:      describeRow(table, kind, id, name),
		Signature: signature,
		Engine:    EngineDatabase,
		Score:     score,
		Level:     level,
		Rules:     strings.Join(names, ", "),
	}, true
}

// describeRow names the row a finding is about.
//
// It goes into av_findings.file, which for every other engine is a path. That
// is why EngineDatabase exists: the three places that would try to act on a
// path ask the engine first. The name is TRUNCATED rather than refused, because
// a value that will not fit is still a finding somebody has to see, and the
// column is 512 characters.
func describeRow(table, kind string, id int64, name string) string {
	described := table + " #" + strconv.FormatInt(id, 10)
	if trimmed := strings.TrimSpace(name); trimmed != "" && kind == "option" {
		described += " (" + trimmed + ")"
	}
	const limit = 500
	if len(described) > limit {
		described = described[:limit] + "…"
	}
	// A row name is tenant text and this string reaches a log line and a screen,
	// so the characters that would break either are removed rather than escaped.
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return -1
		}
		return r
	}, described)
}
