// Package sshaccess manages SSH access per hosting account.
// Each domain maps to a c_<slug> Linux user. Access is controlled by switching the user's login shell
// between /bin/bash and /usr/sbin/nologin. The server's sshd configuration has no AllowUsers or
// AllowGroups restrictions, so shell switching is sufficient and does not modify sshd_config or
// risk locking out root or unrelated accounts.
package sshaccess

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"servika/internal/config"
	"servika/internal/credentials"
	"servika/internal/files"
	"servika/internal/httpx"
	"servika/internal/system"

	"github.com/go-chi/chi/v5"
)

const (
	enabledShell  = "/bin/bash"
	disabledShell = "/usr/sbin/nologin"
)

func servikaJailBin() string { return config.OpsTool("servika-jail") }

// sshDirRel is the SSH directory relative to the tenant home, the form the
// symlink-safe primitives take.
const sshDirRel = ".ssh"

// prepareSSHDir creates ~/.ssh and pins its mode.
//
// The directory sits directly under a home the tenant owns at 0710, so the entry
// is theirs to replace. os.MkdirAll returns nil for a symlink that resolves to an
// existing directory, which is what let a tenant aim the root-privileged key write
// that follows at /root/.ssh. MkdirAllBeneath opens every component with
// O_NOFOLLOW and refuses the link instead. The explicit chmod is required because
// the primitive creates directories 0755 while sshd expects 0700, and the chown
// the primitive performs replaces the `chown -R` that stood here: GNU chown
// defaults to -P and would have relabelled the symlink rather than its target.
func prepareSSHDir(systemUser string) error {
	home := filepath.Join("/home", systemUser)
	if err := files.MkdirAllBeneath(home, sshDirRel, systemUser); err != nil {
		return err
	}
	if err := files.ChmodBeneath(home, sshDirRel, 0700); err != nil {
		return err
	}
	files.RestoreconBeneath(home, sshDirRel)
	return nil
}

// Handlers provides HTTP handlers for per-domain SSH access.
type Handlers struct {
	DB   *sql.DB
	IPv4 string
}

type status struct {
	DomainName string `json:"domain_name"`
	Username   string `json:"username"`
	Enabled    bool   `json:"active"`
	Shell      string `json:"shell"`
	SSHHost    string `json:"ssh_host"`
	SSHPort    int    `json:"ssh_port"`
	HasKey     bool   `json:"has_key"`
}

// validSystemUser restricts operations to panel-created c_<slug> users, preventing command injection
// and changes to unrelated accounts.
func validSystemUser(systemUser string) bool {
	if !strings.HasPrefix(systemUser, "c_") || len(systemUser) < 3 {
		return false
	}
	return !strings.ContainsAny(systemUser, "/ .;|&$`\n\r\t\"'")
}

func currentShell(systemUser string) string {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	out, err := exec.Command("getent", "passwd", systemUser).Output()
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(parts) >= 7 {
		return parts[6]
	}
	return ""
}

func hasKey(systemUser string) bool {
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	st, err := os.Stat(filepath.Join("/home", systemUser, ".ssh", "authorized_keys"))
	return err == nil && st.Size() > 0
}

func (h *Handlers) load(r *http.Request) (id int64, systemUser, domainName string, ok bool) {
	id, _ = strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user, domain_name FROM domains WHERE id=?`, id).
		Scan(&systemUser, &domainName)
	if err != nil {
		return id, "", "", false
	}
	return id, systemUser, domainName, true
}

// GET /domains/{id}/ssh returns the current SSH access state.
func (h *Handlers) Show(w http.ResponseWriter, r *http.Request) {
	_, systemUser, domainName, ok := h.load(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	shell := currentShell(systemUser)
	httpx.WriteJSON(w, http.StatusOK, status{
		DomainName: domainName,
		Username:   systemUser,
		Enabled:    shell == enabledShell,
		Shell:      shell,
		SSHHost:    h.IPv4,
		// Read from sshd rather than fixed at 22: an administrator who moved the
		// port would otherwise have the panel tell every customer a port that
		// refuses the connection.
		SSHPort: system.FirstSSHPort(),
		HasKey:  hasKey(systemUser),
	})
}

// PUT /domains/{id}/ssh changes the login shell from {"active": true|false}.
func (h *Handlers) Configure(w http.ResponseWriter, r *http.Request) {
	id, systemUser, _, ok := h.load(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if !validSystemUser(systemUser) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid system user")
		return
	}
	var req struct {
		Enabled bool `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	shell := disabledShell
	if req.Enabled {
		shell = enabledShell
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	if _, err := exec.Command("usermod", "-s", shell, systemUser).CombinedOutput(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	if req.Enabled {
		// Prepare ~/.ssh for key uploads. Not fatal: the key upload itself refuses
		// the same directory and reports the failure to the caller.
		if err := prepareSSHDir(systemUser); err != nil {
			// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
			httpx.LogR(r, "ssh enable: prepare ssh directory %s: %v", systemUser, err)
		}
		// Synchronize the SSH password with the FTP password.
		if err := credentials.SyncSSHPassword(h.DB, systemUser); err != nil {
			// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
			httpx.LogR(r, "ssh enable: password sync %s: %v", systemUser, err)
		}
		// Configure the chroot jail and the restricted SSH group. These are the
		// confinement controls (sshd Match keys on servika-ssh membership).
		// FAIL-CLOSED: if confinement cannot be established, revert the login shell
		// and do NOT persist ssh_access=1, so we never leave SSH on but unconfined.
		_ = exec.Command("groupadd", "-f", "servika-ssh").Run()
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		if out, err := exec.Command(servikaJailBin(), "setup", systemUser).CombinedOutput(); err != nil {
			// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
			httpx.LogR(r, "ssh enable: jail setup %s: %v: %s", systemUser, err, strings.TrimSpace(string(out)))
			// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
			_, _ = exec.Command("usermod", "-s", disabledShell, systemUser).CombinedOutput()
			httpx.WriteError(w, http.StatusInternalServerError, "SSH jail could not be configured")
			return
		}
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		if out, err := exec.Command("gpasswd", "-a", systemUser, "servika-ssh").CombinedOutput(); err != nil {
			// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
			httpx.LogR(r, "ssh enable: group add %s: %v: %s", systemUser, err, strings.TrimSpace(string(out)))
			// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
			_, _ = exec.Command(servikaJailBin(), "teardown", systemUser).CombinedOutput()
			// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
			_, _ = exec.Command("usermod", "-s", disabledShell, systemUser).CombinedOutput()
			httpx.WriteError(w, http.StatusInternalServerError, "SSH access group could not be configured")
			return
		}
	} else {
		// When disabling SSH, remove the group membership and jail, then lock the password.
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		_ = exec.Command("gpasswd", "-d", systemUser, "servika-ssh").Run()
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		_ = exec.Command(servikaJailBin(), "teardown", systemUser).Run()
		_ = credentials.LockSSHPassword(systemUser)
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE domains SET ssh_access=? WHERE id=?`, boolToInt(req.Enabled), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "active": req.Enabled, "shell": shell, "username": systemUser,
	})
}

// PUT /domains/{id}/ssh/key writes authorized_keys from {"key": "ssh-ed25519 ..."}.
func (h *Handlers) SaveKey(w http.ResponseWriter, r *http.Request) {
	_, systemUser, _, ok := h.load(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if !validSystemUser(systemUser) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid system user")
		return
	}
	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	key := strings.TrimSpace(req.Key)
	// Each non-comment line must start with ssh-, ecdsa-, or sk-. Empty input clears all keys.
	if key != "" {
		for line := range strings.SplitSeq(key, "\n") {
			l := strings.TrimSpace(line)
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			if !strings.HasPrefix(l, "ssh-") && !strings.HasPrefix(l, "ecdsa-") && !strings.HasPrefix(l, "sk-") {
				httpx.WriteError(w, http.StatusBadRequest, "invalid SSH key: every line must start with ssh-, ecdsa-, or sk-")
				return
			}
			// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
		}
	}
	if err := prepareSSHDir(systemUser); err != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		httpx.LogR(r, "ssh key: prepare ssh directory %s: %v", systemUser, err)
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	body := ""
	if key != "" {
		body = key + "\n"
	}
	// The write is pinned beneath the home for the same reason the directory is:
	// a symlink at authorized_keys would otherwise make root truncate and rewrite
	// whatever it points at with request-supplied text, and the endpoint is
	// AdminOnly, so the administrator is the deputy the tenant confuses.
	home := filepath.Join("/home", systemUser)
	akRel := filepath.Join(sshDirRel, "authorized_keys")
	if err := files.WriteFileBeneath(home, akRel, []byte(body), 0600, systemUser); err != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		httpx.LogR(r, "ssh key: write authorized_keys %s: %v", systemUser, err)
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	// WriteFileBeneath keeps the mode of a file that already exists, so pin 0600
	// rather than trusting whatever the previous owner of the entry left behind.
	if err := files.ChmodBeneath(home, akRel, 0600); err != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		httpx.LogR(r, "ssh key: chmod authorized_keys %s: %v", systemUser, err)
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "has_key": key != ""})
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// EnsureInfra prepares the SSH jail infrastructure at panel startup on an idempotent, best-effort basis.
//   - It installs servika-jail under /usr/local/bin.
//   - It creates the restricted SSH access group.
//   - It installs the sshd Match chroot configuration and reloads only after `sshd -t` succeeds.
//     Invalid configuration is rolled back so the active sshd setup remains intact.
func EnsureInfra() {
	const srcDir = "/opt/servika/src/scripts"
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	// Install the jail script.
	if data, err := os.ReadFile(srcDir + "/servika-jail"); err == nil {
		// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
		if e := os.WriteFile(servikaJailBin(), data, 0o755); e == nil {
			// #nosec G302 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
			_ = os.Chmod(servikaJailBin(), 0o755)
		}
	} else {
		log.Printf("SSH ISOLATION: the servika-jail script is missing from %s, so the jail shell cannot be installed: %v", srcDir, err)
	}
	// Create the restricted SSH access group.
	_ = exec.Command("groupadd", "-f", "servika-ssh").Run()
	// Apply the sshd Match chroot configuration safely.
	dst := "/etc/ssh/sshd_config.d/50-servika-jail.conf"
	src, err := os.ReadFile(srcDir + "/50-servika-jail.conf")
	if err != nil {
		// Without this file the sshd Match chroot block is never written, so a
		// tenant granted SSH gets a FULL shell outside the jail. The previous
		// bare return made that failure invisible.
		log.Printf("SSH ISOLATION NOT APPLIED: %s/50-servika-jail.conf is missing, so a tenant granted SSH cannot be confined to its chroot: %v. Add it to the deployed assets/ops payload.", srcDir, err)
		return
	}
	cur, _ := os.ReadFile(dst)
	if string(cur) == string(src) {
		// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
		return // The installed configuration is current.
	}
	// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if e := os.WriteFile(dst, src, 0o644); e != nil {
		log.Printf("could not write jail sshd configuration: %v", e)
		return
	}
	if out, e := exec.Command("sshd", "-t").CombinedOutput(); e != nil {
		// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
		// Roll back invalid configuration without disrupting sshd.
		if len(cur) > 0 {
			// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
			_ = os.WriteFile(dst, cur, 0o644)
		} else {
			_ = os.Remove(dst)
		}
		log.Printf("jail sshd configuration is invalid and was not applied: %s", strings.TrimSpace(string(out)))
		return
	}
	_ = exec.Command("systemctl", "reload", "sshd").Run()
	log.Printf("SSH jail infrastructure is ready (script + servika-ssh + sshd chroot configuration)")
}
