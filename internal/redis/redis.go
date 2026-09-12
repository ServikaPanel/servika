// Package redis manages isolated per-tenant Valkey and Redis caches.
// A single Valkey instance uses one ACL user per domain, restricted to the ~<system-user>:* key prefix
// with @dangerous and @admin denied, so sites cannot access each other's caches.
// ACLs are managed through valkey-cli without an additional Go dependency.
package redis

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"servika/internal/config"
	"servika/internal/httpx"
	"servika/internal/logx"
	"servika/internal/secret"

	"github.com/go-chi/chi/v5"
)

type Handlers struct{ DB *sql.DB }

// systemUserPattern restricts system_user to a safe character set to prevent valkey-cli argument injection.
var systemUserPattern = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)

const (
	redisHost = "127.0.0.1"
	redisPort = 6379
)

func adminPass() string { return os.Getenv("SERVIKA_REDIS_ADMIN_PASS") }

// cli runs valkey-cli with the admin password in REDISCLI_AUTH rather than argv.
func cli(args ...string) (string, error) {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	cmd := exec.Command("valkey-cli", args...)
	cmd.Env = []string{
		"REDISCLI_AUTH=" + adminPass(),
		"LANG=C",
		"LC_ALL=C",
	}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// cliInput runs valkey-cli with the command on STDIN rather than argv.
//
// /proc/<pid>/cmdline is mode 444 on Linux while /proc/<pid>/environ is 400, so
// every c_* tenant on the host, each of which has a shell, cron and PHP, can
// read another tenant's ACL password out of an argument while the command runs.
// The admin password already travels in REDISCLI_AUTH for the same reason; this
// closes the tenant credential.
//
// valkey-cli exits 0 for a command the SERVER refused, reporting it only in the
// output, so the text is inspected rather than the exit status.
func cliInput(command string) (string, error) {
	// #nosec G204 -- a fixed binary with no arguments; the command travels on stdin.
	cmd := exec.Command("valkey-cli")
	cmd.Env = []string{
		"REDISCLI_AUTH=" + adminPass(),
		"LANG=C",
		"LC_ALL=C",
	}
	cmd.Stdin = strings.NewReader(command + "\n")
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, err
	}
	if strings.Contains(text, "(error)") {
		return text, fmt.Errorf("valkey refused the command: %s", text)
	}
	return text, nil
}

// aclSafePassword reports whether a password may be written into a valkey-cli
// command line on stdin. valkey-cli parses that line with its own tokenizer, so
// whitespace or a quote would split the token and change the rule being set.
// genPass produces hex, so this is a guard on a value arriving from elsewhere.
func aclSafePassword(password string) bool {
	if password == "" {
		return false
	}
	return !strings.ContainsAny(password, " \t\r\n\x00\"'\\")
}

func genPass() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// enableUser creates a tenant ACL limited to the <system-user>:* key and channel prefixes while denying
// dangerous and administrative commands. Isolation remains enforced because flushall, flushdb,
// keys, config, and swapdb return NOPERM. Read-only diagnostic commands required by the WordPress
// Redis Object Cache plugin are re-enabled. info and dbsize expose aggregate statistics but not
// another tenant's keys, which is acceptable for the shared cache.
//
// scan and randomkey must be denied EXPLICITLY: they belong to @read/@keyspace,
// not @dangerous or @admin, and the ACL key pattern restricts which keys a user
// may operate on, NOT which key names an iteration returns. Without these two
// denials a tenant could enumerate every key name in the shared cache, including
// its neighbours'.
func enableUser(systemUser, password string) error {
	if !aclSafePassword(password) {
		return fmt.Errorf("the ACL password contains characters valkey-cli cannot carry")
	}
	// On STDIN, never argv: the password would otherwise be readable by every
	// other account on the host (see cliInput).
	//
	// resetpass comes BEFORE the new password, and it is not optional. SETUSER
	// MERGES into the existing rule set, and the `>` verb ADDS a password to the
	// user's list rather than replacing it, so without this every password ever
	// issued to this ACL user stays valid. The panel stores only the newest one,
	// so re-issuing looked like a rotation and revoked nothing: a credential
	// disclosed out of the tenant's wp-config.php could not be taken back short
	// of deleting the user and taking the object cache down with it. The file
	// also grew a password per call for a caller that looped the endpoint.
	//
	// Measured against Valkey 8: two SETUSER calls without resetpass leave two
	// hashes in ACL GETUSER and both authenticate; with resetpass exactly one
	// remains, the earlier ones answer WRONGPASS, and the key and channel scopes
	// are unchanged.
	if _, err := cliInput(strings.Join([]string{
		"ACL", "SETUSER", systemUser, "on", "resetpass", ">" + password,
		"resetkeys", "~" + systemUser + ":*", "resetchannels", "&" + systemUser + ":*",
		"+@all", "-@dangerous", "-@admin", "-scan", "-randomkey",
		"+info", "+dbsize", "+command", "+ping", "+echo", "+client|no-evict",
	}, " ")); err != nil {
		return err
	}
	_, err := cli("ACL", "SAVE")
	return err
}

// HealScanACL denies scan and randomkey on every existing tenant ACL user.
//
// SETUSER merges into the current rule set, so the stored password and key
// pattern are preserved and only these two commands are withdrawn. main calls it
// at startup so tenants created before the denial existed are closed too.
func HealScanACL() {
	out, err := cli("ACL", "LIST")
	if err != nil {
		return
	}
	healed := 0
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "user" {
			continue
		}
		name := fields[1]
		// Tenant ACL users are named after the system user (c_<slug>); never
		// touch "default" or any operator-created account.
		if name == "default" || !strings.HasPrefix(name, "c_") {
			continue
		}
		if _, err := cli("ACL", "SETUSER", name, "-scan", "-randomkey"); err == nil {
			healed++
		}
	}
	if healed > 0 {
		_, _ = cli("ACL", "SAVE")
		logx.Infof("redis: denied scan/randomkey on %d tenant ACL user(s)", healed)
	}
}

func disableUser(systemUser string) error {
	// A swallowed DELUSER leaves the ACL user active with a still-valid password
	// after the panel believes it revoked; surface the error to the caller.
	if _, err := cli("ACL", "DELUSER", systemUser); err != nil {
		return err
	}
	_, err := cli("ACL", "SAVE")
	return err
}

// ---- Automatic WordPress connection through wp-cli as the domain user ----

func wpBin() string { return config.WPCLIBin() }

// setSecretConstant writes a wp-config.php constant whose VALUE is a credential,
// supplying it on stdin through wp-cli's own --prompt mechanism so it never
// reaches argv, where /proc/<pid>/cmdline publishes it to every other account.
//
// Three measured properties of the pinned wp-cli shape this, the same ones
// internal/wordpress documents for its own secret path:
//
//   - --quiet is REQUIRED, or wp-cli echoes the whole command line it assembled,
//     the prompted value included, which only moves the secret to another place.
//   - --quiet is NOT SUFFICIENT: the prompt line itself carries the value on
//     stdout, so nothing here returns that output.
//   - The exit code proves nothing, because wp-cli SILENTLY IGNORES a --prompt
//     name it does not recognise and exits 0 having done nothing. The constant is
//     read back instead.
func setSecretConstant(systemUser, dir, key, value string) error {
	full := []string{"-u", systemUser, "--", "env", "HOME=/home/" + systemUser,
		"/usr/bin/php", "-d", "memory_limit=512M", wpBin(),
		"config", "set", key, "--type=constant", "--raw", "--path=" + dir,
		"--quiet", "--prompt=value"}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	cmd := exec.Command("runuser", full...)
	cmd.Stdin = strings.NewReader(value + "\n")
	if _, err := cmd.CombinedOutput(); err != nil {
		// The output is deliberately dropped: the prompt line carries the value.
		return fmt.Errorf("wp config set %s: %w", key, err)
	}
	stored, err := runWPCommand(systemUser, "config", "get", key, "--type=constant", "--path="+dir)
	if err != nil {
		return fmt.Errorf("wp config get %s: %w", key, err)
	}
	if strings.TrimSpace(string(stored)) != value {
		return fmt.Errorf("%s was not written", key)
	}
	return nil
}

func runWPCommand(systemUser string, args ...string) ([]byte, error) {
	full := append([]string{"-u", systemUser, "--", "env", "HOME=/home/" + systemUser,
		"/usr/bin/php", "-d", "memory_limit=512M", wpBin()}, args...)
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	return exec.Command("runuser", full...).CombinedOutput()
}

// wpDirectories finds WordPress installations with wp-config.php in <system-user>/public_html or one level below.
func wpDirectories(systemUser string) []string {
	root := "/home/" + systemUser + "/public_html"
	candidates := []string{root}
	if entries, err := os.ReadDir(root); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				candidates = append(candidates, filepath.Join(root, e.Name()))
			}
		}
	}
	var out []string
	for _, d := range candidates {
		// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
		if _, err := os.Stat(filepath.Join(d, "wp-config.php")); err == nil {
			out = append(out, d)
		}
	}
	return out
}

// connectWordPress automatically connects Redis to WordPress installations and returns the number connected.
// This is a best-effort operation. It does not use `wp redis enable` because that command invokes
// Predis and FLUSHDB, which the ACL correctly denies. Instead, the drop-in is copied directly,
// WP_REDIS_PASSWORD uses the [username, password] array format for ACL authentication, and
// selective flush implements runtime flushing with scan and unlink.
func connectWordPress(systemUser, password string) int {
	connected := 0
	for _, dir := range wpDirectories(systemUser) {
		set := func(key, value string, raw bool) {
			args := []string{"config", "set", key, value, "--type=constant", "--path=" + dir}
			if raw {
				args = append(args, "--raw")
			}
			_, _ = runWPCommand(systemUser, args...)
		}
		set("WP_REDIS_HOST", redisHost, false)
		set("WP_REDIS_PORT", strconv.Itoa(redisPort), true)
		// The drop-in authenticates ACL users when WP_REDIS_PASSWORD is an array of
		// username and password. The value carries the credential, so it goes on
		// stdin through wp-cli's own --prompt mechanism rather than into argv,
		// where every other account on the host would read it.
		if err := setSecretConstant(systemUser, dir, "WP_REDIS_PASSWORD",
			"array('"+systemUser+"','"+password+"')"); err != nil {
			// #nosec G706 -- logged values are a validated identifier, a path this package composed, and error text.
			logx.Errorf("redis: could not write WP_REDIS_PASSWORD for %s in %s: %v", systemUser, dir, err)
			continue
		}
		set("WP_REDIS_PREFIX", systemUser+":", false)
		set("WP_REDIS_SELECTIVE_FLUSH", "true", true)
		set("WP_REDIS_CLIENT", "phpredis", false)
		set("WP_CACHE", "true", true)
		// Remove obsolete single-string USERNAME or PASSWORD configuration.
		_, _ = runWPCommand(systemUser, "config", "delete", "WP_REDIS_USERNAME", "--path="+dir)

		if _, err := runWPCommand(systemUser, "plugin", "install", "redis-cache", "--activate", "--path="+dir); err != nil {
			continue
		}
		// Install the drop-in directly to avoid the FLUSHDB performed by wp redis enable.
		src := filepath.Join(dir, "wp-content/plugins/redis-cache/includes/object-cache.php")
		dst := filepath.Join(dir, "wp-content/object-cache.php")
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		if _, err := exec.Command("runuser", "-u", systemUser, "--", "cp", "-f", src, dst).CombinedOutput(); err != nil {
			continue
		}
		// Treat a status containing "Connected" as a successful connection.
		if out, err := runWPCommand(systemUser, "redis", "status", "--path="+dir); err == nil && strings.Contains(string(out), "Connected") {
			connected++
		}
	}
	return connected
}

// disconnectWordPress disables Redis in WordPress installations by removing the drop-in and constants.
// It does not use `wp redis disable`, which may attempt FLUSHDB, so the drop-in is removed directly.
func disconnectWordPress(systemUser string) {
	for _, dir := range wpDirectories(systemUser) {
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		_, _ = exec.Command("runuser", "-u", systemUser, "--", "rm", "-f",
			filepath.Join(dir, "wp-content/object-cache.php")).CombinedOutput()
		for _, key := range []string{"WP_REDIS_HOST", "WP_REDIS_PORT", "WP_REDIS_USERNAME",
			"WP_REDIS_PASSWORD", "WP_REDIS_PREFIX", "WP_REDIS_SELECTIVE_FLUSH", "WP_REDIS_CLIENT", "WP_CACHE"} {
			_, _ = runWPCommand(systemUser, "config", "delete", key, "--path="+dir)
		}
	}
}

type statusResponse struct {
	Enabled     bool   `json:"enabled"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password,omitempty"`
	Prefix      string `json:"prefix"`
	WPSnippet   string `json:"wp_snippet,omitempty"`
	WPConnected int    `json:"wp_connected,omitempty"`
}

// domainSystemUser resolves the domain to its system user and reports whether
// that user carries the managed tenant prefix. Ownership and suspension are
// already enforced by CustomerScope on the route.
func (h *Handlers) domainSystemUser(r *http.Request) (id int64, systemUser string, ok bool) {
	id, _ = strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user FROM domains WHERE id=?`, id).Scan(&systemUser); err != nil {
		return id, "", false
	}
	return id, systemUser, systemUserPattern.MatchString(systemUser)
}

func wpSnippet(systemUser, password string) string {
	return "// Redis object cache\n" +
		"define( 'WP_REDIS_HOST', '" + redisHost + "' );\n" +
		"define( 'WP_REDIS_PORT', " + strconv.Itoa(redisPort) + " );\n" +
		"define( 'WP_REDIS_PASSWORD', array( '" + systemUser + "', '" + password + "' ) );\n" +
		"define( 'WP_REDIS_PREFIX', '" + systemUser + ":' );\n" +
		"define( 'WP_REDIS_SELECTIVE_FLUSH', true );\n" +
		"define( 'WP_REDIS_CLIENT', 'phpredis' );\n" +
		"define( 'WP_CACHE', true );"
}

// GET /domains/{id}/redis
// Password returns the tenant's Redis ACL password in the clear.
//
// The column holds ciphertext sealed with the row's OWN system_user as the
// additional authenticated data, so a value copied into another tenant's row
// does not open. That is why the query reads system_user back rather than
// taking it from the caller: the AAD has to be the one the value was sealed
// with, which survives a rename of the column the caller happens to hold.
//
// A row written before encryption existed carries no prefix and secret.Decrypt
// returns it unchanged, so an install that predates this keeps working.
func Password(ctx context.Context, db *sql.DB, domainID int64) (string, error) {
	var rowSystemUser, stored string
	var enabled int
	err := db.QueryRowContext(ctx,
		`SELECT enabled, system_user, redis_pass FROM domain_redis WHERE domain_id=?`,
		domainID).Scan(&enabled, &rowSystemUser, &stored)
	if err != nil {
		return "", err
	}
	if enabled == 0 {
		return "", errors.New("redis is not enabled for this domain")
	}
	return secret.DecryptWith(stored, rowSystemUser)
}

// SavePassword seals a tenant's Redis ACL password and writes the row.
//
// It is the one place outside the HTTP handler that records this credential, so
// the sealing cannot be skipped by a caller that builds the statement itself.
// The system_user is validated first because it is both the AAD the value is
// sealed against and the name every later read binds to.
func SavePassword(ctx context.Context, db *sql.DB, domainID int64, systemUser, password string) error {
	if !systemUserPattern.MatchString(systemUser) {
		return fmt.Errorf("invalid system user: %q", systemUser)
	}
	if password == "" {
		return errors.New("the password is empty")
	}
	sealed, err := secret.EncryptWith(password, systemUser)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx,
		`INSERT INTO domain_redis (domain_id, system_user, redis_pass, enabled) VALUES (?,?,?,1)
		 ON DUPLICATE KEY UPDATE system_user=VALUES(system_user), redis_pass=VALUES(redis_pass), enabled=1`,
		domainID, systemUser, sealed)
	return err
}

func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	id, systemUser, ok := h.domainSystemUser(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	var enabled int
	var password string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT enabled, redis_pass FROM domain_redis WHERE domain_id=?`, id).Scan(&enabled, &password)
	if err != nil || enabled == 0 {
		httpx.WriteJSON(w, http.StatusOK, statusResponse{Enabled: false, Host: redisHost, Port: redisPort, Username: systemUser, Prefix: systemUser + ":"})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, statusResponse{
		Enabled: true, Host: redisHost, Port: redisPort, Username: systemUser, Password: "***",
		Prefix: systemUser + ":", WPSnippet: wpSnippet(systemUser, "***"),
	})
}

// POST /domains/{id}/redis enables the tenant cache.
func (h *Handlers) Open(w http.ResponseWriter, r *http.Request) {
	id, systemUser, ok := h.domainSystemUser(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if adminPass() == "" {
		httpx.WriteError(w, http.StatusServiceUnavailable, "redis is not configured (SERVIKA_REDIS_ADMIN_PASS is missing)")
		return
	}
	password := genPass()
	if err := enableUser(systemUser, password); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "redis ACL could not be created")
		return
	}
	sealed, err := secret.EncryptWith(password, systemUser)
	if err != nil {
		if err := disableUser(systemUser); err != nil {
			// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
			httpx.LogR(r, "redis enable rollback ACL user %s: %v", systemUser, err)
		}
		// #nosec G706 -- logged values are a validated identifier and an error; no raw tenant string with CR/LF reaches the log.
		httpx.LogR(r, "redis enable: could not seal the password for %s: %v", systemUser, err)
		httpx.WriteError(w, http.StatusInternalServerError, "redis settings could not be saved")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO domain_redis (domain_id, system_user, redis_pass, enabled) VALUES (?,?,?,1)
		 ON DUPLICATE KEY UPDATE system_user=VALUES(system_user), redis_pass=VALUES(redis_pass), enabled=1`,
		id, systemUser, sealed); err != nil {
		if err := disableUser(systemUser); err != nil { // Roll back the ACL if the database write fails.
			// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
			httpx.LogR(r, "redis enable rollback ACL user %s: %v", systemUser, err)
		}
		httpx.WriteError(w, http.StatusInternalServerError, "redis settings could not be saved")
		return
	}
	// Connect existing WordPress installations on a best-effort basis, retaining the manual snippet otherwise.
	connected := connectWordPress(systemUser, password)
	httpx.WriteJSON(w, http.StatusOK, statusResponse{
		Enabled: true, Host: redisHost, Port: redisPort, Username: systemUser, Password: password,
		Prefix: systemUser + ":", WPSnippet: wpSnippet(systemUser, password), WPConnected: connected,
	})
}

// DELETE /domains/{id}/redis disables the tenant cache.
func (h *Handlers) Close(w http.ResponseWriter, r *http.Request) {
	id, systemUser, ok := h.domainSystemUser(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	// The Valkey account and the WordPress drop-in are named after the SYSTEM
	// USER, not after this domain, so a shared name makes neither this domain's
	// to remove. Only the row is. This is the same question the domain deletion
	// path asks before it calls CloseDomain.
	if h.sharedSystemUser(r, id, systemUser) {
		h.forgetRow(w, r, id)
		return
	}
	detachWordPress(systemUser) // Remove the WordPress drop-in while the credentials are still valid.
	if err := revokeACL(systemUser); err != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		httpx.LogR(r, "redis disable ACL user %s: %v", systemUser, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not revoke Redis credentials")
		return
	}
	h.forgetRow(w, r, id)
}

// sharedSystemUser reports whether another TOP-LEVEL domain answers to the same
// system user. An addon row is not counted: it belongs to the same tenant and
// shares the account by design.
//
// A failed lookup counts as shared. Keeping a live account costs a stale
// credential; revoking a shared one takes the other tenant's cache down.
func (h *Handlers) sharedSystemUser(r *http.Request, id int64, systemUser string) bool {
	var others int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM domains WHERE system_user=? AND parent_domain_id IS NULL AND id<>?`,
		systemUser, id).Scan(&others); err != nil {
		// #nosec G706 -- logged values are a validated identifier and an error; no raw tenant string with CR/LF reaches the log.
		httpx.LogR(r, "redis disable: sibling lookup for %s failed: %v", systemUser, err)
		return true
	}
	return others > 0
}

// forgetRow removes the domain_redis row and answers the request.
func (h *Handlers) forgetRow(w http.ResponseWriter, r *http.Request, id int64) {
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM domain_redis WHERE domain_id=?`, id); err != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		httpx.LogR(r, "redis delete domain_redis row %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not update Redis state")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// CloseDomain removes the WordPress drop-in, Valkey ACL user, and domain_redis row when
// domains.Delete removes a domain. Explicit cleanup is required because domain_redis lacks
// an ON DELETE CASCADE foreign key and would otherwise retain an orphaned row.
func CloseDomain(db *sql.DB, id int64, systemUser string) error {
	disconnectWordPress(systemUser)
	var errs []error
	if err := disableUser(systemUser); err != nil {
		errs = append(errs, fmt.Errorf("disable ACL user %s: %w", systemUser, err))
	}
	if err := ForgetDomain(db, id); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// ForgetDomain removes only the domain_redis row, leaving the ACL user and the
// WordPress drop-in in place.
//
// It exists for the one case where the Valkey account is not this domain's to
// revoke: the account is named after the SYSTEM USER, and an upgraded panel can
// still carry two domains sharing one, so disabling it would cut the surviving
// domain's cache off.
func ForgetDomain(db *sql.DB, id int64) error {
	if _, err := db.Exec(`DELETE FROM domain_redis WHERE domain_id=?`, id); err != nil {
		return fmt.Errorf("delete domain_redis row %d: %w", id, err)
	}
	return nil
}
