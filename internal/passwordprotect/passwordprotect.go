// Package passwordprotect manages directory-based .htpasswd authentication for nginx.
// Security relies on strict input validation, explicit exec arguments without a shell, and
// configuration rollback when vhost rendering fails, keeping customer sites operational.
package passwordprotect

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
	"strings"

	"servika/internal/httpx"
	"servika/internal/provisioner"
	"servika/internal/subdomain"

	"github.com/go-chi/chi/v5"
)

// Handlers provides HTTP handlers for directory password protection.
type Handlers struct {
	DB *sql.DB
}

const htpasswdDir = "/etc/nginx/htpasswd" // #nosec G101 -- filesystem path, not a credential

// A password file holds bcrypt hashes for a protected directory, so it is a
// secret and is kept away from every other account on the host. It used to be
// written 0644 root:root inside a 0755 directory, which every `c_*` tenant could
// read: measured, a plain `cat` as a tenant printed the hash verbatim.
//
// nginx opens the file as its own worker user, so the group carries all the
// access it needs and nothing for other closes it to everyone else. Measured
// against a real nginx with these modes: 401 with no credentials, 401 with a
// wrong password, 200 with the right one, and `Permission denied` for a tenant
// on both the file and the directory.
const (
	nginxAccount                 = "nginx"
	htpasswdDirMode  os.FileMode = 0o750
	htpasswdFileMode os.FileMode = 0o640
)

// nginxGID answers the group id nginx runs under.
//
// It is resolved BEFORE anything is written, so a host with no nginx account
// refuses the request instead of leaving a hash behind that nothing can close.
func nginxGID() (int, error) {
	account, err := user.Lookup(nginxAccount)
	if err != nil {
		return 0, fmt.Errorf("look up the %s account: %w", nginxAccount, err)
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return 0, fmt.Errorf("parse the %s group id: %w", nginxAccount, err)
	}
	return gid, nil
}

// secureHtpasswd gives a path the ownership and mode that close it to everything
// but nginx.
//
// The chown runs BEFORE the chmod, and a failed chown leaves the mode exactly as
// it was: the other order produces a file nginx cannot read, which takes the
// protected directory down rather than merely leaving it readable. This is the
// same rule `ensurePMAOwnership` follows for phpMyAdmin's own secrets.
func secureHtpasswd(path string, uid, gid int, mode os.FileMode) error {
	// #nosec G703 -- the path is the fixed htpasswd directory or a name htpasswdFile built from validated identifiers.
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("set %s ownership: %w", path, err)
	}
	// #nosec G302 G703 -- 0640/0750 root:nginx: the daemon reads it through the group and no other account can; the path is fixed or built from validated identifiers.
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("set %s permissions: %w", path, err)
	}
	return nil
}

var (
	pathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]{0,200}$`)
	reUser      = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)
)

// Record describes a user assigned to a protected directory.
type Record struct {
	ID        int64  `json:"id"`
	Path      string `json:"path"`
	Username  string `json:"username"`
	CreatedAt string `json:"created_at"`
}

func (h *Handlers) domain(r *http.Request) (id int64, systemUser, version string, demo, ok bool) {
	id, _ = strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var isDemo int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user, COALESCE(php_version,'8.3'), COALESCE(is_demo,0) FROM domains WHERE id=?`, id).
		Scan(&systemUser, &version, &isDemo); err != nil {
		return id, "", "", false, false
	}
	return id, systemUser, version, isDemo == 1, true
}

// scope resolves which document root the request targets. A {sid} URL parameter
// selects that subdomain, and 0 means the domain's own root. The subdomain must
// belong to the domain in the URL, so a tenant cannot address another domain's
// subdomain by guessing its id.
func (h *Handlers) scope(r *http.Request, domainID int64) (subdomainID int64, ok bool) {
	raw := chi.URLParam(r, "sid")
	if raw == "" {
		return 0, true
	}
	sid, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || sid <= 0 {
		return 0, false
	}
	var found int64
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT id FROM subdomains WHERE id=? AND domain_id=?`, sid, domainID).Scan(&found); err != nil {
		return 0, false
	}
	return found, true
}

// GET /domains/{id}/password-protection and the /subdomain/{sid} variant.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	id, _, _, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	subdomainID, ok := h.scope(r, id)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "subdomain not found")
		return
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, path, username, created_at FROM protected_directories WHERE domain_id=? AND subdomain_id=? ORDER BY path, username`, id, subdomainID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list records")
		return
	}
	defer func() { _ = rows.Close() }()
	out := []Record{}
	for rows.Next() {
		var record Record
		if err := rows.Scan(&record.ID, &record.Path, &record.Username, &record.CreatedAt); err == nil {
			out = append(out, record)
		}
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "listing failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// POST /domains/{id}/password-protection {path, username, password}
func (h *Handlers) Add(w http.ResponseWriter, r *http.Request) {
	id, systemUser, version, demo, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "not available for demo subscriptions")
		return
	}
	if !strings.HasPrefix(systemUser, "c_") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user")
		return
	}
	subdomainID, ok := h.scope(r, id)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "subdomain not found")
		return
	}
	var req struct {
		Path     string `json:"path"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	path := normalizePath(req.Path)
	if !pathPattern.MatchString(path) || strings.Contains(path, "..") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid path (example: /private)")
		return
	}
	if !reUser.MatchString(req.Username) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid username")
		return
	}
	if len(req.Password) < 4 || len(req.Password) > 128 {
		httpx.WriteError(w, http.StatusBadRequest, "password must contain 4 to 128 characters")
		return
	}
	// htpasswd reads one line from stdin, so a line break would silently store a
	// truncated password and lock the customer out of the directory they just
	// protected. NUL would truncate it the same way.
	if strings.ContainsAny(req.Password, "\r\n\x00") {
		httpx.WriteError(w, http.StatusBadRequest, "password cannot contain line breaks")
		return
	}
	gid, err := nginxGID()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not resolve the nginx account")
		return
	}
	if err := os.MkdirAll(htpasswdDir, htpasswdDirMode); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create htpasswd directory")
		return
	}
	// MkdirAll leaves an existing directory's mode alone, so a host installed
	// before this was tightened still carries 0755 here until this runs.
	if err := secureHtpasswd(htpasswdDir, 0, gid, htpasswdDirMode); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not secure the htpasswd directory")
		return
	}
	file := htpasswdFile(id, subdomainID, path)
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	_, statErr := os.Stat(file)
	created := statErr != nil
	if _, err := htpasswdCommand(file, req.Username, req.Password, created).CombinedOutput(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_ = exec.Command("restorecon", file).Run() // Apply the SELinux httpd_config_t context.
	if err := secureHtpasswd(file, 0, gid, htpasswdFileMode); err != nil {
		// The file already holds the hash, so leaving it behind would publish it
		// to every account on the host while the screen reported success. Only a
		// file this request created is removed; an existing one loses just the
		// user that was added to it.
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		_ = exec.Command("htpasswd", "-D", file, req.Username).Run()
		if created {
			// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
			_ = os.Remove(file)
		}
		httpx.WriteError(w, http.StatusInternalServerError, "could not secure the password file")
		return
	}

	if _, err := h.DB.Exec(
		`INSERT INTO protected_directories (domain_id, subdomain_id, path, username, htpasswd_file) VALUES (?,?,?,?,?)
		 ON DUPLICATE KEY UPDATE htpasswd_file=VALUES(htpasswd_file)`,
		id, subdomainID, path, req.Username, file); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not add record")
		return
	}

	if err := h.render(id, subdomainID, systemUser, version); err != nil {
		// Roll back the record and htpasswd entry when vhost validation fails, then render again.
		_, _ = h.DB.Exec(`DELETE FROM protected_directories WHERE domain_id=? AND subdomain_id=? AND path=? AND username=?`, id, subdomainID, path, req.Username)
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		_ = exec.Command("htpasswd", "-D", file, req.Username).Run()
		if remaining := h.userCount(id, subdomainID, path); remaining == 0 {
			// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
			_ = os.Remove(file)
		}
		_ = h.render(id, subdomainID, systemUser, version)
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// DELETE /domains/{id}/password-protection/{kid}
func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	id, systemUser, version, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	subdomainID, ok := h.scope(r, id)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "subdomain not found")
		return
	}
	kid, _ := strconv.ParseInt(chi.URLParam(r, "kid"), 10, 64)
	var path, username, file string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT path, username, htpasswd_file FROM protected_directories WHERE id=? AND domain_id=? AND subdomain_id=?`, kid, id, subdomainID).
		Scan(&path, &username, &file); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "record not found")
		return
	}
	if _, err := h.DB.Exec(`DELETE FROM protected_directories WHERE id=? AND domain_id=? AND subdomain_id=?`, kid, id, subdomainID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete record")
		return
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_ = exec.Command("htpasswd", "-D", file, username).Run()
	if h.userCount(id, subdomainID, path) == 0 {
		_ = os.Remove(file) // Remove the location block when no user remains for this path.
	}
	if err := h.render(id, subdomainID, systemUser, version); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// htpasswdCommand builds the .htpasswd write with the password on stdin.
//
// -i is what reads it from there. The earlier -b form took the password as an
// argv element, where /proc/<pid>/cmdline publishes it to every local account
// for as long as htpasswd runs, and a tenant reaches that window with arbitrary
// shell from a cron entry. -c is added when the file does not exist yet.
func htpasswdCommand(file, username, password string, create bool) *exec.Cmd {
	flag := "-iB"
	if create {
		flag = "-ciB"
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec, and the password travels on stdin.
	command := exec.Command("htpasswd", flag, file, username)
	// htpasswd reads one line and strips the terminator; Add rejects a password
	// containing one, so nothing is lost here.
	command.Stdin = strings.NewReader(password + "\n")
	return command
}

// htpasswdFile names the password file per scope, so the same path protected on a
// domain and on one of its subdomains cannot share, and overwrite, one file.
func htpasswdFile(domainID, subdomainID int64, path string) string {
	if subdomainID > 0 {
		return htpasswdDir + "/d" + strconv.FormatInt(domainID, 10) +
			"_s" + strconv.FormatInt(subdomainID, 10) + "_" + sanitize(path)
	}
	return htpasswdDir + "/d" + strconv.FormatInt(domainID, 10) + "_" + sanitize(path)
}

func (h *Handlers) userCount(id, subdomainID int64, path string) int {
	var n int
	_ = h.DB.QueryRow(`SELECT COUNT(*) FROM protected_directories WHERE domain_id=? AND subdomain_id=? AND path=?`, id, subdomainID, path).Scan(&n)
	return n
}

// render publishes the protection change to the vhost that owns the scope: the
// subdomain's own server block, or the parent domain's.
func (h *Handlers) render(domainID, subdomainID int64, systemUser, version string) error {
	if subdomainID > 0 {
		return subdomain.ReRender(h.DB, subdomainID)
	}
	return h.reRender(domainID, systemUser, version)
}

// reRender rebuilds the vhost and restores the backup when nginx validation fails.
func (h *Handlers) reRender(domainID int64, systemUser, version string) error {
	socket, err := provisioner.PHPSocketFor(systemUser, version)
	if err != nil {
		return fmt.Errorf("php socket: %w", err)
	}
	cfg := "/etc/nginx/conf.d/dom_" + systemUser + ".conf"
	// #nosec G703 G304 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	backup, _ := os.ReadFile(cfg) // Nil when no backup exists.
	if err := provisioner.ApplyVhostForDomain(h.DB, domainID, socket, version); err != nil {
		if backup != nil {
			// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
			_ = os.WriteFile(cfg, backup, 0o644) // Restore the last known-good configuration.
			_ = exec.Command("nginx", "-t").Run()
		}
		return err
	}
	return nil
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
	}
	if path == "" {
		path = "/"
	}
	return path
}

var reNonAlnum = regexp.MustCompile(`[^A-Za-z0-9]+`)

func sanitize(s string) string {
	s = reNonAlnum.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		s = "root"
	}
	return s
}
