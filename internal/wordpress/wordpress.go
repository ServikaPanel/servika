// Package wordpress provides one-click WordPress installation and management through wp-cli.
// Commands run as the c_<slug> domain user, paths remain restricted to public_html, and root-site deletion is prohibited.
package wordpress

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"servika/internal/config"
	"servika/internal/credentials"
	"servika/internal/files"
	"servika/internal/httpx"
	"servika/internal/middleware"
	"servika/internal/quota"
	"servika/internal/subdomain"

	"github.com/go-chi/chi/v5"
)

type Handlers struct{ DB *sql.DB }

func wpBin() string { return config.WPCLIBin() }

var (
	subdirectoryPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]{0,30}[a-z0-9])?$`)
	reAdmin             = regexp.MustCompile(`^[A-Za-z0-9._@-]{3,60}$`)
	reEmail             = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	reDBName            = regexp.MustCompile(`define\(\s*['"]DB_NAME['"]\s*,\s*['"]([^'"]+)['"]`)
	reManagedDBName     = regexp.MustCompile(`^wp_([a-f0-9]{8})$`)
)

type Installation struct {
	Dir      string `json:"dir"`
	SiteURL  string `json:"site_url"`
	AdminURL string `json:"admin_url"`
	Version  string `json:"version"`
}

// domain resolves the site the request targets. A {sid} URL parameter selects that
// subdomain, replacing the site name and document root with the subdomain's own, so
// WordPress is discovered and installed under the subdomain instead of public_html.
func (h *Handlers) domain(r *http.Request) (id int64, systemUser, domainName, root string, ssl, ok bool) {
	id, _ = strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var cert string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user, domain_name, COALESCE(cert_path,'') FROM domains WHERE id=?`, id).
		Scan(&systemUser, &domainName, &cert); err != nil {
		return id, "", "", "", false, false
	}
	root = filepath.Join(tenantHomeRoot, systemUser, "public_html")
	if raw := chi.URLParam(r, "sid"); raw != "" {
		sid, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return id, "", "", "", false, false
		}
		scope, scopeOK := subdomain.ResolveScope(r.Context(), h.DB, id, sid)
		if !scopeOK {
			return id, "", "", "", false, false
		}
		// A subdomain carries its own certificate state, so SSL comes from the scope.
		return id, systemUser, scope.FQDN, scope.DocRoot, scope.HasTLS, true
	}
	return id, systemUser, domainName, root, cert != "", true
}

const (
	// wpLocalTimeout bounds a wp-cli call that only touches the local site. It
	// matches the router's own 300-second request timeout, so it cannot fail an
	// operation whose caller is still waiting, while still keeping a wp-cli that
	// hangs on an unreachable database from living for the rest of the panel's life.
	wpLocalTimeout = 5 * time.Minute
	// wpNetworkTimeout bounds the calls that download from wordpress.org (core
	// download/update, plugin and theme updates, checksum verification). Those
	// legitimately outlast the request on a slow link, so the budget is larger; the
	// point is only that the process cannot run forever.
	wpNetworkTimeout = 15 * time.Minute
)

// runWP runs wp-cli as the domain user with HOME set and without a shell.
// It invokes PHP directly with a 512 MB memory limit because the raw .phar shebang does not read
// WP_CLI_PHP_ARGS and archive extraction can exceed the default 128 MB limit.
func runWP(systemUser string, args ...string) ([]byte, error) {
	return runWPTimeout(wpLocalTimeout, systemUser, args...)
}

// runWPTimeout is runWP with an explicit budget, for the calls that reach
// wordpress.org. The deadline is not tied to the HTTP request: an update that is
// rewriting core files must not be killed halfway because the operator closed the
// tab, which would leave the site on a mixture of two versions.
func runWPTimeout(timeout time.Duration, systemUser string, args ...string) ([]byte, error) {
	return runWPInput(timeout, systemUser, "", args...)
}

// runWPInput is runWPTimeout with data on the process's standard input. It is
// how a secret reaches wp-cli: an argument named on the command line is visible
// to every other account on the host, because /proc/<pid>/cmdline is mode 444
// while /proc/<pid>/environ is 400. During an install that window is seconds
// long and it carries the site's database password and the new administrator
// password, so a neighbouring c_* tenant only has to be looking.
func runWPInput(timeout time.Duration, systemUser, stdin string, args ...string) ([]byte, error) {
	return wpInput(timeout, systemUser, stdin, args...)
}

// execWPInput is the real wp-cli call runWPInput makes on a host.
func execWPInput(timeout time.Duration, systemUser, stdin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	full := append([]string{"-u", systemUser, "--", "env", "HOME=/home/" + systemUser,
		"/usr/bin/php", "-d", "memory_limit=512M", wpBin()}, args...)
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	cmd := exec.CommandContext(ctx, "runuser", full...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

// runWPSecret runs wp-cli with the single argument named by promptArg supplied
// on stdin through wp-cli's own --prompt mechanism, so it never appears in argv.
//
// Two measured properties of the pinned wp-cli 2.12.0 shape this:
//
//   - --quiet is REQUIRED. Without it wp-cli echoes the whole command line it
//     assembled, the prompted value included, which would simply move the secret
//     from one output to another. It does not suppress real errors: a failing
//     command still exits non-zero with its message on stderr.
//   - --quiet is NOT SUFFICIENT. The prompt line itself still carries the value
//     ("1/10 [--dbpass=<dbpass>]: <secret>") on stdout, and every caller here
//     puts the tail of this output into an HTTP error body, so the secret is
//     removed from what this function returns.
//
// The exit code proves nothing on its own: wp-cli SILENTLY IGNORES a --prompt
// name it does not recognise, exiting 0 with an empty stderr and acting as if
// the argument were absent. Every caller verifies the result afterwards.
func runWPSecret(systemUser, promptArg, secret string, args ...string) ([]byte, error) {
	args = append(args, "--quiet", "--prompt="+promptArg)
	out, err := runWPInput(wpLocalTimeout, systemUser, secret+"\n", args...)
	return redact(out, secret), err
}

// redact removes a secret from output that is about to be shown to someone.
func redact(out []byte, secret string) []byte {
	if secret == "" {
		return out
	}
	return bytes.ReplaceAll(out, []byte(secret), []byte("[redacted]"))
}

// wpCheckPasswordPHP asks WordPress itself whether an account answers to a
// password. The snippet is a constant and BOTH values arrive on stdin, so
// neither the login nor the password is interpolated into PHP source or reaches
// argv.
// #nosec G101 -- PHP source that READS a password from stdin, not a credential; the name is what the rule matched on.
const wpCheckPasswordPHP = `$login = trim(fgets(STDIN));
$pass = trim(fgets(STDIN));
$user = get_user_by("login", $login);
if (!$user) { echo "NOUSER"; exit; }
echo wp_check_password($pass, $user->user_pass, $user->ID) ? "OK" : "MISMATCH";`

// checkPasswordStdin builds the two-line payload wpCheckPasswordPHP reads with
// fgets. A value carrying a line break would shift that protocol and make the
// snippet compare a different pair than the caller asked about, so it is
// refused rather than trimmed into something nobody typed.
func checkPasswordStdin(login, password string) (string, bool) {
	if strings.ContainsAny(login, "\r\n\x00") || strings.ContainsAny(password, "\r\n\x00") {
		return "", false
	}
	return login + "\n" + password + "\n", true
}

// passwordWorks reports whether login answers to password in the installation
// at target.
func passwordWorks(systemUser, target, login, password string) bool {
	stdin, ok := checkPasswordStdin(login, password)
	if !ok {
		return false
	}
	out, err := runWPInput(wpLocalTimeout, systemUser, stdin,
		"eval", wpCheckPasswordPHP, "--path="+target)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "OK"
}

// configPasswordMatches reads DB_PASSWORD back out of the generated
// wp-config.php. An ignored --prompt writes it EMPTY while still exiting 0.
func configPasswordMatches(systemUser, target, want string) bool {
	out, err := runWP(systemUser, "config", "get", "DB_PASSWORD", "--path="+target)
	if err != nil {
		return false
	}
	return string(bytes.TrimSpace(out)) == want
}

func scheme(ssl bool) string {
	if ssl {
		return "https://"
	}
	return "http://"
}

// GET /domains/{id}/wordpress discovers installations in public_html and one directory level below.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	_, systemUser, _, root, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	out := []Installation{}
	candidates := []string{root}
	if entries, err := os.ReadDir(root); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				candidates = append(candidates, filepath.Join(root, e.Name()))
			}
		}
	}
	for _, dir := range candidates {
		// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
		if _, err := os.Stat(filepath.Join(dir, "wp-config.php")); err != nil {
			continue
		}
		installation := Installation{Dir: "/" + strings.TrimPrefix(strings.TrimPrefix(dir, root), "/")}
		if installation.Dir == "/" {
			installation.Dir = "/ (root)"
		}
		if b, err := runWP(systemUser, "core", "version", "--path="+dir); err == nil {
			installation.Version = strings.TrimSpace(string(b))
		}
		if b, err := runWP(systemUser, "option", "get", "siteurl", "--path="+dir); err == nil {
			installation.SiteURL = strings.TrimSpace(string(b))
			installation.AdminURL = installation.SiteURL + "/wp-admin"
		}
		out = append(out, installation)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// AllInstallation summarizes one WordPress installation for the aggregate table.
type AllInstallation struct {
	DomainID    int64  `json:"domain_id"`
	DomainName  string `json:"domain_name"`
	Dir         string `json:"dir"`
	Version     string `json:"version"`
	LastVersion string `json:"last_version"` // Target version when an update exists.
	Status      string `json:"status"`       // WordPress update status.
	InstallDate string `json:"install_date"` // wp-config.php mtime, YYYY-MM-DD
	SiteURL     string `json:"site_url"`
	AdminURL    string `json:"admin_url"`
}

type wpCandidate struct {
	domainID               int64
	systemUser, domainName string
	ssl                    bool
	dir, root              string
}

// GET /wordpress/all reports every WordPress installation in the caller's scope
// with its version and update state.
//
// The wp-cli fan-out behind it is NOT on this path: one shared pass produces the
// whole server's inventory (inventory.go) and this narrows its result, because
// the pass costs two PHP processes and one wordpress.org call per site and the
// dashboard fetches this on mount.
func (h *Handlers) ListAll(w http.ResponseWriter, r *http.Request) {
	visible, err := h.visibleDomainIDs(r)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list domains")
		return
	}
	installs, err := Inventory(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the WordPress inventory")
		return
	}
	out := make([]AllInstallation, 0, len(installs))
	for _, install := range installs {
		if visible[install.DomainID] {
			out = append(out, install)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// visibleDomainIDs returns the domains this caller may see: a reseller sees only
// its own customers' sites.
//
// An unreadable row is an ERROR rather than a silently narrower set, because a
// missing id hides that domain's installations and an absent site reads as a
// domain with no WordPress on it.
func (h *Handlers) visibleDomainIDs(r *http.Request) (map[int64]bool, error) {
	cond, arg := middleware.ScopeSQL(r, "d")
	// #nosec G701 G202 -- cond is a constant scope fragment from ScopeSQL with a literal alias; all user values are bound via arg placeholders.
	rows, err := h.DB.QueryContext(r.Context(), `SELECT d.id FROM domains d`+cond, arg...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	visible := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		visible[id] = true
	}
	return visible, rows.Err()
}

// inspectInstallation collects version, update state, and installation date for one WordPress installation.
func inspectInstallation(ctx context.Context, a wpCandidate) AllInstallation {
	directoryPath := strings.TrimPrefix(strings.TrimPrefix(a.dir, a.root), "/")
	base := scheme(a.ssl) + a.domainName
	if directoryPath != "" {
		base += "/" + directoryPath
	}
	directoryLabel := "/" + directoryPath
	if directoryLabel == "/" {
		directoryLabel = "/ (root)"
	}
	installation := AllInstallation{
		DomainID: a.domainID, DomainName: a.domainName, Dir: directoryLabel,
		SiteURL: base, AdminURL: base + "/wp-admin", Status: "unknown",
	}
	// Read the installed version.
	c1, cancel1 := context.WithTimeout(ctx, 15*time.Second)
	if b, err := wpStdout(c1, a.systemUser, "core", "version", "--path="+a.dir); err == nil {
		installation.Version = strings.TrimSpace(string(b))
	}
	cancel1()
	// Check for updates with a timeout because wp-cli calls the wordpress.org API.
	c2, cancel2 := context.WithTimeout(ctx, 25*time.Second)
	if b, err := wpStdout(c2, a.systemUser, "core", "check-update", "--path="+a.dir, "--format=json"); err == nil {
		bt := bytes.TrimSpace(b)
		if len(bt) == 0 || string(bt) == "[]" {
			installation.Status = "current"
		} else {
			var ups []struct {
				Version string `json:"version"`
			}
			if json.Unmarshal(bt, &ups) == nil {
				if len(ups) > 0 {
					installation.Status = "outdated"
					installation.LastVersion = ups[0].Version
				} else {
					installation.Status = "current"
				}
			}
		}
	}
	cancel2()
	// Use the wp-config.php modification time as the installation date because it rarely changes.
	if fi, err := os.Stat(filepath.Join(a.dir, "wp-config.php")); err == nil {
		installation.InstallDate = fi.ModTime().Format("2006-01-02")
	}
	return installation
}

// wpStdout runs wp-cli as the domain user with a context timeout and returns only stdout.
// Discarding stderr prevents deprecation warnings from corrupting JSON output.
func wpStdout(ctx context.Context, systemUser string, args ...string) ([]byte, error) {
	return wpOutput(ctx, systemUser, args...)
}

// execWPStdout is the real wp-cli call wpStdout makes on a host.
func execWPStdout(ctx context.Context, systemUser string, args ...string) ([]byte, error) {
	full := append([]string{"-u", systemUser, "--", "env", "HOME=/home/" + systemUser,
		"/usr/bin/php", "-d", "memory_limit=512M", wpBin()}, args...)
	// #nosec G204 G702 -- fixed binary (runuser) with separate args (no shell); systemUser is validated before exec.
	cmd := exec.CommandContext(ctx, "runuser", full...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.Bytes(), err
}

// wpInstallLock serializes concurrent WordPress installs per target path.
var wpInstallLock sync.Map

// installAlreadyExists checks if target dir already has WordPress content.
func installAlreadyExists(target string) (string, bool) {
	entries, err := os.ReadDir(target)
	if err != nil {
		return "", false
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "wp-config.php" {
			return "WordPress is already installed in this directory", true
		}
		if placeholderName(name) {
			continue
		}
		return "Target directory already contains content", true
	}
	return "", false
}

// placeholderFiles are the names a directory may hold and still count as empty:
// what a control panel or a browser leaves in a fresh document root.
var placeholderFiles = map[string]bool{
	"index.html": true, "index.htm": true, "index.php": true,
	"favicon.ico": true, "favicon.png": true,
	"robots.txt": true, "sitemap.xml": true,
	"cgi-bin": true,
}

// placeholderName reports whether one directory entry may be overwritten by an
// install. Every dotfile passes, which covers .htaccess, .htpasswd and
// .well-known.
func placeholderName(name string) bool {
	return placeholderFiles[name] || strings.HasPrefix(name, ".")
}

// POST /domains/{id}/wordpress installs WordPress.
func (h *Handlers) Install(w http.ResponseWriter, r *http.Request) {
	id, systemUser, domainName, root, ssl, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if !strings.HasPrefix(systemUser, "c_") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user")
		return
	}
	req, ok := decodeInstallRequest(w, r)
	if !ok {
		return
	}
	target, release, ok := prepareTarget(w, systemUser, root, req.SubDir)
	if release != nil {
		defer release()
	}
	if !ok {
		return
	}
	site, ok := h.createSiteDatabase(w, r, id)
	if !ok {
		return
	}
	url := scheme(ssl) + domainName
	if req.SubDir != "" {
		url += "/" + req.SubDir
	}
	adminPassword, ok := h.installSite(w, systemUser, target, url, req, site)
	if !ok {
		return
	}
	// #nosec G204 G702 -- fixed binaries (chown/restorecon) with separate args (no shell); systemUser is validated and target is internal.
	_ = wpCommand("chown", "-R", systemUser+":"+systemUser, target).Run()
	// #nosec G204 G702 -- fixed binary (restorecon) with separate args (no shell); systemUser is validated and target is internal.
	_ = wpCommand("restorecon", "-R", target).Run()

	version := ""
	if b, err := runWP(systemUser, "core", "version", "--path="+target); err == nil {
		version = strings.TrimSpace(string(b))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "site_url": url, "admin_url": url + "/wp-admin",
		"admin_user": req.AdminUser, "admin_password": adminPassword,
		"version": version, "db_name": site.name,
	})
}

// installRequest is what the caller asks for.
type installRequest struct {
	SubDir     string `json:"sub_dir"`
	SiteTitle  string `json:"site_title"`
	AdminUser  string `json:"admin_user"`
	AdminEmail string `json:"admin_email"`
}

// decodeInstallRequest reads the request and refuses every value the install
// cannot use. It answers the caller itself and reports whether the install may
// go on.
func decodeInstallRequest(w http.ResponseWriter, r *http.Request) (installRequest, bool) {
	var req installRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return req, false
	}
	req.SubDir = strings.Trim(strings.TrimSpace(req.SubDir), "/")
	req.SiteTitle = strings.TrimSpace(req.SiteTitle)
	req.AdminUser = strings.TrimSpace(req.AdminUser)
	req.AdminEmail = strings.TrimSpace(req.AdminEmail)
	if req.SiteTitle == "" || len(req.SiteTitle) > 120 {
		httpx.WriteError(w, http.StatusBadRequest, "site title is required (maximum 120 characters)")
		return req, false
	}
	if !reAdmin.MatchString(req.AdminUser) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid administrator username")
		return req, false
	}
	if !reEmail.MatchString(req.AdminEmail) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid email address")
		return req, false
	}
	if req.SubDir != "" && !subdirectoryPattern.MatchString(req.SubDir) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid subdirectory (lowercase letters, digits, and hyphens only)")
		return req, false
	}
	return req, true
}

// prepareTarget takes the per-directory lock and makes the directory the
// install writes into. The release function is returned whenever the lock was
// taken, including on a later failure, so the caller can defer it once.
func prepareTarget(w http.ResponseWriter, systemUser, root, subDir string) (target string, release func(), ok bool) {
	target = root
	if subDir != "" {
		target = filepath.Join(root, subDir)
	}
	// Lock to serialize concurrent installs to the same target.
	if _, loaded := wpInstallLock.LoadOrStore(target, true); loaded {
		httpx.WriteError(w, http.StatusConflict, "wordPress installation is already in progress for this directory")
		return "", nil, false
	}
	release = func() { wpInstallLock.Delete(target) }
	if msg, exists := installAlreadyExists(target); exists {
		httpx.WriteError(w, http.StatusConflict, msg)
		return target, release, false
	}
	// #nosec G301 G703 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	if err := os.MkdirAll(target, 0o755); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create target directory")
		return target, release, false
	}
	// #nosec G204 G702 -- fixed binaries (chown/restorecon) with separate args (no shell); systemUser is validated and target is internal.
	_ = wpCommand("chown", "-R", systemUser+":"+systemUser, target).Run()
	// #nosec G204 G702 -- fixed binary (restorecon) with separate args (no shell); systemUser is validated and target is internal.
	_ = wpCommand("restorecon", "-R", target).Run()
	return target, release, true
}

// siteDatabase is the database an install creates for its site.
type siteDatabase struct {
	name string
	user string
	pass string
}

// createSiteDatabase enforces the plan database quota at this point of use,
// matching the normal database endpoint. Without this, repeated WordPress
// installs in different subdirectories bypass the customer's max_db limit. A
// per-customer lock held across the check and the database creation makes the
// pair atomic against concurrent installs and concurrent normal database
// creation.
func (h *Handlers) createSiteDatabase(w http.ResponseWriter, r *http.Request, domainID int64) (siteDatabase, bool) {
	slug := randSlug()
	site := siteDatabase{name: "wp_" + slug, user: "wpu_" + slug, pass: credentials.RandomPassword(24)}
	dbErr := func() error {
		unlock := quota.LockCustomerForDomain(r.Context(), h.DB, domainID)
		defer unlock()
		if err := quota.CheckDatabaseAllowed(r.Context(), h.DB, domainID); err != nil {
			return err
		}
		return createMySQLDB(h.DB, domainID, site.name, site.user, site.pass)
	}()
	if dbErr != nil {
		if limitErr, ok := errors.AsType[*quota.LimitError](dbErr); ok {
			httpx.WriteError(w, http.StatusForbidden, limitErr.Message)
			return site, false
		}
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return site, false
	}
	return site, true
}

// installSite runs the wp-cli stages that turn an empty directory into a
// working site, and undoes the database and the directory when one of them
// fails. It returns the administrator password on success.
func (h *Handlers) installSite(w http.ResponseWriter, systemUser, target, url string,
	req installRequest, site siteDatabase) (string, bool) {
	fail := func(stage string, out []byte) {
		_ = dropMySQLDB(h.DB, site.name, site.user)
		if req.SubDir != "" { // Remove only the subdirectory created by this operation.
			// Best effort, and already logged inside: the install's own failure
			// is what the caller is told, and a rollback that could not finish
			// must not replace that message with its own.
			_ = removeInstall(systemUser, target, "wordpress install rollback")
		}
		msg := strings.TrimSpace(string(out))
		if len(msg) > 600 {
			msg = msg[len(msg)-600:]
		}
		httpx.WriteError(w, http.StatusInternalServerError, stage+" failed: "+msg)
	}

	if out, err := runWPTimeout(wpNetworkTimeout, systemUser, "core", "download", "--path="+target, "--locale=en_US"); err != nil {
		fail("WordPress download", out)
		return "", false
	}
	if out, err := runWPSecret(systemUser, "dbpass", site.pass, "config", "create",
		"--dbname="+site.name, "--dbuser="+site.user, "--dbhost=localhost",
		"--locale=en_US", "--path="+target, "--skip-check"); err != nil {
		fail("wp-config creation", out)
		return "", false
	}
	// A wp-config.php whose DB_PASSWORD went in empty is a site that cannot
	// reach its own database, reported as a successful install.
	if !configPasswordMatches(systemUser, target, site.pass) {
		fail("wp-config creation", []byte("the database password was not stored in wp-config.php"))
		return "", false
	}
	adminPassword := randomPassword()
	if out, err := runWPSecret(systemUser, "admin_password", adminPassword,
		"core", "install", "--url="+url, "--title="+req.SiteTitle,
		"--admin_user="+req.AdminUser, "--admin_email="+req.AdminEmail,
		"--skip-email", "--path="+target); err != nil {
		fail("WordPress installation", out)
		return "", false
	}
	// Measured with an unrecognised --prompt name: wp-cli exits 0 with an empty
	// stderr and the account is never created at all. Handing the caller a
	// password for an account that does not answer to it, or does not exist,
	// is worse than the exposure this replaced.
	if !passwordWorks(systemUser, target, req.AdminUser, adminPassword) {
		fail("WordPress installation", []byte("the administrator account was not created with the generated password"))
		return "", false
	}
	return adminPassword, true
}

// POST /domains/{id}/wordpress/update updates an installation from {dir}.
func (h *Handlers) Update(w http.ResponseWriter, r *http.Request) {
	_, systemUser, _, root, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	var updateRequest struct {
		Dir string `json:"dir"`
	}
	if err := json.NewDecoder(r.Body).Decode(&updateRequest); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	dir, err := resolveDirectory(root, updateRequest.Dir)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	out1, e1 := runWPTimeout(wpNetworkTimeout, systemUser, "core", "update", "--path="+dir)
	out2, _ := runWP(systemUser, "core", "update-db", "--path="+dir)
	if e1 != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		httpx.LogR(r, "wp core update failed for %s (dir=%s): %s", systemUser, dir, strings.TrimSpace(string(out1)))
		httpx.WriteError(w, http.StatusInternalServerError, "update failed")
		return
	}
	version := ""
	if b, err := runWP(systemUser, "core", "version", "--path="+dir); err == nil {
		version = strings.TrimSpace(string(b))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "version": version,
		"output": strings.TrimSpace(string(out1)) + "\n" + strings.TrimSpace(string(out2))})
}

// DELETE /domains/{id}/wordpress removes an installation from {dir, db_delete}.
func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	id, systemUser, _, root, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if !strings.HasPrefix(systemUser, "c_") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user")
		return
	}
	var deleteRequest struct {
		Dir      string `json:"dir"`
		DBDelete bool   `json:"delete_db"`
	}
	if err := json.NewDecoder(r.Body).Decode(&deleteRequest); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	dir, err := resolveDirectory(root, deleteRequest.Dir)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	// Protect the site root by refusing to remove the document root itself.
	if dir == root {
		httpx.WriteError(w, http.StatusBadRequest, "wordPress in the root directory cannot be removed from the panel because it would delete the entire site; use File Manager")
		return
	}
	if deleteRequest.DBDelete {
		h.dropSiteDatabase(r, id, dir)
	}
	// The root path was rejected above, so this is a subdirectory.
	if err := removeInstall(systemUser, dir, "wordpress delete"); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete record")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// dropSiteDatabase removes the database the installation's wp-config.php names.
//
// Cross-tenant guard: only databases that belong to this domain AND carry the
// wp_ prefix are dropped, which is what prevents an arbitrary DB drop through
// the payload. A name that fails either test is left alone, silently, because
// the directory deletion the caller asked for still applies.
func (h *Handlers) dropSiteDatabase(r *http.Request, domainID int64, dir string) {
	// #nosec G304 G703 -- dir derives from a validated systemUser/domain path, not raw tenant input; tenant file reads otherwise use safeio (openat2).
	b, err := os.ReadFile(filepath.Join(dir, "wp-config.php"))
	if err != nil {
		return
	}
	m := reDBName.FindSubmatch(b)
	if len(m) != 2 {
		return
	}
	dbName := string(m[1])
	if !h.dropAllowed(r, domainID, dbName) {
		return
	}
	if dbUser, ok := managedDBAccount(dbName); ok {
		_ = dropMySQLDB(h.DB, dbName, dbUser)
	}
}

// resolveDirectory converts a directory value into a safe absolute path under root
// containing wp-config.php. The caller supplies root so a subdomain request is confined
// to the subdomain's document root instead of the parent domain's public_html.
// removeBeneathHome deletes an absolute path inside a tenant's home through
// openat2, and reports what it could not do.
//
// The prefix check that used to stand alone here decided nothing about safety.
// The panel runs as root and every directory on the way is the tenant's, so a
// component swapped for a symlink sends the deletion outside the home while the
// string still reads like a path inside it. resolveDirectory's own
// `strings.HasPrefix(clean, root+"/")` has the same blind spot, and its
// `os.Stat` for wp-config.php follows links as well, so a linked directory
// holding one passes.
//
// The prefix is still computed, but only to turn the absolute path into the
// relative one the primitive takes; the refusal comes from the kernel.
func removeBeneathHome(systemUser, absolutePath, what string) error {
	home, rel, err := homeRel(systemUser, absolutePath)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if err := files.RemoveAllBeneath(home, rel); err != nil && !errors.Is(err, os.ErrNotExist) {
		// #nosec G706 -- rel is derived from a filepath.Clean'ed path whose source is either the regex-validated sub_dir or resolveDirectory, which rejects CR/LF/NUL; `what` is a literal.
		log.Printf("%s: could not remove %q: %v", what, rel, err)
		return err
	}
	return nil
}

// homeRel splits an absolute path inside a tenant home into the (home, rel) pair
// every files.*Beneath primitive takes. The prefix comparison decides nothing
// about safety; the refusal comes from the kernel inside the primitive. It exists
// only to turn a path resolveDirectory already bounded to the document root into
// the relative form openat2 needs.
func homeRel(systemUser, absolutePath string) (home, rel string, err error) {
	home = filepath.Join(tenantHomeRoot, systemUser)
	rel, ok := strings.CutPrefix(filepath.Clean(absolutePath), home+"/")
	if !ok {
		return "", "", fmt.Errorf("path is outside the tenant home")
	}
	return home, rel, nil
}

func resolveDirectory(root, directoryValue string) (string, error) {
	// Refused before anything is built from it. A control character survives
	// filepath.Clean, so without this it reaches a filesystem call and a log
	// line, where CR/LF lets the caller forge entries.
	if strings.ContainsAny(directoryValue, "\r\n\x00") {
		return "", fmt.Errorf("directory name contains control characters")
	}
	d := strings.TrimPrefix(strings.TrimSpace(directoryValue), "/ (root)")
	rel := strings.Trim(strings.TrimSpace(d), "/")
	dir := root
	if rel != "" && rel != "(root)" {
		dir = filepath.Join(root, rel)
	}
	clean := filepath.Clean(dir)
	if clean != root && !strings.HasPrefix(clean, root+"/") {
		return "", fmt.Errorf("path is outside the domain directory")
	}
	if _, err := os.Stat(filepath.Join(clean, "wp-config.php")); err != nil {
		return "", fmt.Errorf("WordPress was not found in this directory")
	}
	return clean, nil
}

// managedDBAccount validates a package-managed database name and derives its paired account.
func managedDBAccount(dbName string) (string, bool) {
	m := reManagedDBName.FindStringSubmatch(dbName)
	if len(m) != 2 {
		return "", false
	}
	return "wpu_" + m[1], true
}

// dbNameWPGuard validates that a database name is a syntactically valid MySQL identifier
// and carries the wp_ prefix used by managed WordPress installations. Rejects names that
// fail the identifier check (SQL injection / cross-tenant guard).
func dbNameWPGuard(dbAdi string) bool {
	if !credentials.ValidDBIdentifier(dbAdi) {
		return false
	}
	return strings.HasPrefix(dbAdi, "wp_")
}

// dbOwnedBy checks whether the authenticated domain owns the given WordPress database.
// The database must belong to a db_accounts row whose domain_id matches the request domain.
func (h *Handlers) dbOwnedBy(r *http.Request, domainID int64, dbAdi string) bool {
	var cnt int
	err := h.DB.QueryRowContext(r.Context(),
		"SELECT COUNT(*) FROM db_accounts WHERE domain_id=? AND db_name=?", domainID, dbAdi).Scan(&cnt)
	return err == nil && cnt > 0
}

// dropAllowed gates database deletion for managed WordPress databases.
// A database may only be dropped when:
//   - It passes dbNameWPGuard (wp_ prefix + valid MySQL identifier)
//   - The authenticated domain owns it (dbOwnedBy)
//
// Without this gate a tenant could supply an arbitrary dbName in the delete payload
// and trick the panel into dropping another customer's database (cross-tenant DB drop).
func (h *Handlers) dropAllowed(r *http.Request, domainID int64, dbAdi string) bool {
	return dbNameWPGuard(dbAdi) && h.dbOwnedBy(r, domainID, dbAdi)
}

func randSlug() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b) // Eight hexadecimal characters.
}

// randomPassword returns a generated WordPress password.
//
// It defers to credentials.RandomPassword rather than drawing its own: this was
// a byte-for-byte copy of that function, so the modulo bias in it had to be
// found and fixed twice, and a second generator is what let the two drift.
func randomPassword() string {
	return credentials.RandomPassword(18)
}
