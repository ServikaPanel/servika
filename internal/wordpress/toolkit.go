// toolkit.go provides WordPress plugin, theme, and user management, password resets,
// core repair, maintenance mode, cache operations, and bulk updates.
// Commands run as the domain user through runWP or wpStdout, with paths restricted to public_html by resolveDirectory.
package wordpress

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"servika/internal/httpx"
	"servika/internal/wpchecksums"
)

// reSlug strictly validates plugin and theme slugs to prevent argument injection, including leading hyphens.
var reSlug = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$`)

// directoryFromQuery converts the GET dir query parameter into a safe absolute path
// under root, which is the domain's public_html or a subdomain's document root.
func (h *Handlers) directoryFromQuery(r *http.Request, root string) (string, error) {
	d := r.URL.Query().Get("dir")
	if d == "" {
		d = "/"
	}
	return resolveDirectory(root, d)
}

// writeJSONArray forwards a wp-cli JSON array unchanged, returning [] for errors or empty output.
func writeJSONArray(w http.ResponseWriter, raw []byte, err error) {
	bt := strings.TrimSpace(string(raw))
	if err != nil || bt == "" {
		httpx.WriteJSON(w, http.StatusOK, []any{})
		return
	}
	var arr []json.RawMessage
	if json.Unmarshal([]byte(bt), &arr) != nil {
		httpx.WriteJSON(w, http.StatusOK, []any{})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, arr)
}

// GET /domains/{id}/wordpress/status?dir= returns core version and updates, PHP, database size, and maintenance state.
func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	_, systemUser, _, root, _, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	dir, err := h.directoryFromQuery(r, root)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Run five wp-cli calls concurrently so latency is bounded by the slowest call, usually check-update.
	// Each goroutine writes to a distinct map key.
	out := map[string]any{"version": "", "update_available": false, "target_version": "",
		"php": "", "db_mb": "", "maintenance": false}
	var wg sync.WaitGroup
	wg.Add(5)
	go func() {
		defer wg.Done()
		if b, e := wpStdout(ctx, systemUser, "core", "version", "--path="+dir); e == nil {
			out["version"] = strings.TrimSpace(string(b))
		}
	}()
	go func() {
		defer wg.Done()
		if b, e := wpStdout(ctx, systemUser, "core", "check-update", "--path="+dir, "--format=json"); e == nil {
			bt := strings.TrimSpace(string(b))
			if bt != "" && bt != "[]" {
				var ups []struct {
					Version string `json:"version"`
				}
				if json.Unmarshal([]byte(bt), &ups) == nil && len(ups) > 0 {
					out["update_available"] = true
					out["target_version"] = ups[0].Version
				}
			}
		}
	}()
	go func() {
		defer wg.Done()
		if b, e := wpStdout(ctx, systemUser, "eval", "echo PHP_VERSION;", "--path="+dir); e == nil {
			out["php"] = strings.TrimSpace(string(b))
		}
	}()
	go func() {
		defer wg.Done()
		if b, e := wpStdout(ctx, systemUser, "db", "size", "--size_format=mb", "--path="+dir); e == nil {
			out["db_mb"] = strings.TrimSpace(string(b))
		}
	}()
	go func() {
		defer wg.Done()
		out["maintenance"] = maintenanceEnabled(dir)
	}()
	wg.Wait()
	httpx.WriteJSON(w, http.StatusOK, out)
}

// GET /domains/{id}/wordpress/plugins?dir= lists plugins.
func (h *Handlers) Plugins(w http.ResponseWriter, r *http.Request) {
	_, systemUser, _, root, _, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	dir, err := h.directoryFromQuery(r, root)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	b, e := wpStdout(ctx, systemUser, "plugin", "list", "--path="+dir, "--format=json",
		"--fields=name,status,version,update,update_version")
	writeJSONArray(w, b, e)
}

// GET /domains/{id}/wordpress/themes?dir= lists themes.
func (h *Handlers) Themes(w http.ResponseWriter, r *http.Request) {
	_, systemUser, _, root, _, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	dir, err := h.directoryFromQuery(r, root)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	b, e := wpStdout(ctx, systemUser, "theme", "list", "--path="+dir, "--format=json",
		"--fields=name,status,version,update,update_version")
	writeJSONArray(w, b, e)
}

// GET /domains/{id}/wordpress/users?dir= lists users.
func (h *Handlers) Users(w http.ResponseWriter, r *http.Request) {
	_, systemUser, _, root, _, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	dir, err := h.directoryFromQuery(r, root)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	b, e := wpStdout(ctx, systemUser, "user", "list", "--path="+dir, "--format=json",
		"--fields=ID,user_login,user_email,display_name,roles")
	writeJSONArray(w, b, e)
}

// prepareMutation resolves the domain, demo state, and directory for mutations.
// A false return means the error response has already been written.
func (h *Handlers) prepareMutation(w http.ResponseWriter, r *http.Request, directory string) (systemUser, dir string, ok bool) {
	_, systemUser, _, root, _, demo, found := h.domain(r)
	if !found {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return "", "", false
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "not available for demo subscriptions")
		return "", "", false
	}
	d, err := resolveDirectory(root, directory)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return "", "", false
	}
	return systemUser, d, true
}

// POST /domains/{id}/wordpress/plugin applies {dir, action: update|update-all|active|passive, name}.
func (h *Handlers) PluginAction(w http.ResponseWriter, r *http.Request) {
	var req struct{ Dir, Action, Name string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	systemUser, dir, ok := h.prepareMutation(w, r, req.Dir)
	if !ok {
		return
	}
	h.packageAction(w, systemUser, dir, "plugin", req.Action, req.Name)
}

// POST /domains/{id}/wordpress/theme applies {dir, action: update|update-all|active, name}.
func (h *Handlers) ThemeAction(w http.ResponseWriter, r *http.Request) {
	var req struct{ Dir, Action, Name string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	systemUser, dir, ok := h.prepareMutation(w, r, req.Dir)
	if !ok {
		return
	}
	h.packageAction(w, systemUser, dir, "theme", req.Action, req.Name)
}

// packageAction performs shared update, activation, and deactivation operations for plugins and themes.
func (h *Handlers) packageAction(w http.ResponseWriter, systemUser, dir, packageType, action, name string) {
	var args []string
	switch action {
	case "update-all":
		args = []string{packageType, "update", "--all", "--path=" + dir}
	case "update":
		if !reSlug.MatchString(name) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid name")
			return
		}
		args = []string{packageType, "update", name, "--path=" + dir}
	case "active":
		if !reSlug.MatchString(name) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid name")
			return
		}
		args = []string{packageType, "activate", name, "--path=" + dir}
	case "passive":
		if packageType != "plugin" || !reSlug.MatchString(name) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid action")
			return
		}
		args = []string{packageType, "deactivate", name, "--path=" + dir}
	default:
		httpx.WriteError(w, http.StatusBadRequest, "unknown action")
		return
	}
	out, err := runWPTimeout(wpNetworkTimeout, systemUser, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "output": truncateOutput(string(out))})
}

// POST /domains/{id}/wordpress/user-password updates {dir, user_id, password?}.
// An empty password generates and returns a secure password.
func (h *Handlers) UserPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Dir      string `json:"dir"`
		UserID   int    `json:"user_id"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	systemUser, dir, ok := h.prepareMutation(w, r, req.Dir)
	if !ok {
		return
	}
	if req.UserID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user")
		return
	}
	password := strings.TrimSpace(req.Password)
	if password == "" {
		password = randomPassword()
	} else if len(password) < 8 || len(password) > 100 {
		httpx.WriteError(w, http.StatusBadRequest, "password must contain 8 to 100 characters")
		return
	}
	// The login is read BEFORE the update because the verification below needs
	// it, and because a user id that names nobody must not be reported as a
	// completed password change.
	b, err := runWP(systemUser, "user", "get", strconv.Itoa(req.UserID), "--field=user_login", "--path="+dir)
	login := strings.TrimSpace(string(b))
	if err != nil || login == "" {
		httpx.WriteError(w, http.StatusNotFound, "user not found")
		return
	}
	// The password goes in on stdin: an argument is readable by every other
	// account on the host through /proc/<pid>/cmdline, and this one may be a
	// password the customer chose and uses elsewhere.
	if _, err := runWPSecret(systemUser, "user_pass", password, "user", "update",
		strconv.Itoa(req.UserID), "--skip-email", "--path="+dir); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	// Measured with an unrecognised --prompt name: wp-cli exits 0, changes
	// nothing, and the OLD password keeps working. Reporting that as a completed
	// change tells the customer something untrue about their own account.
	//
	// The message says "could not be confirmed" rather than "was not applied",
	// because the check itself can fail on a site whose plugins break `wp eval`,
	// and in that case the password may well have changed. Plugins are
	// deliberately NOT skipped: `wp user update` hashed the password through the
	// same stack, so a plugin that replaces the hasher must be loaded here too or
	// the comparison would be against a hash nothing produced.
	if !passwordWorks(systemUser, dir, login, password) {
		httpx.WriteError(w, http.StatusInternalServerError, "the password change could not be confirmed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "password": password, "username": login})
}

// POST /domains/{id}/wordpress/repair repairs an installation from {dir}.
// It verifies core checksums, downloads core files without modifying wp-content, updates the database,
// and verifies checksums again.
func (h *Handlers) Repair(w http.ResponseWriter, r *http.Request) {
	var req struct{ Dir string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	systemUser, dir, ok := h.prepareMutation(w, r, req.Dir)
	if !ok {
		return
	}
	beforeVerdicts, beforeOutput, beforeMeasured, _ := h.runChecksums(systemUser, dir)
	before := checksumState(beforeVerdicts, beforeMeasured)
	// Download the installed version to avoid an unintended upgrade.
	version := ""
	if b, e := runWP(systemUser, "core", "version", "--path="+dir); e == nil {
		version = strings.TrimSpace(string(b))
	}
	dlArgs := []string{"core", "download", "--force", "--skip-content", "--path=" + dir}
	if version != "" {
		dlArgs = append(dlArgs, "--version="+version)
	}
	// A repair must put back the core the site was RUNNING, and `wp core
	// download` defaults to en_US whatever is installed. Measured on a real
	// Turkish WordPress 7.1: the command announces "Downloading WordPress 7.1
	// (en_US)" and wp-includes/version.php loses its $wp_local_package line, md5
	// 45ddd1e0... becoming c77f737c.... Only that one core file differs between
	// the two packages (wp-content/languages is preserved by --skip-content), but
	// WordPress reads that global to decide which package it updates from
	// afterwards, so the site drifts to the English core for good.
	//
	// The locale is read from version.php beneath the home rather than from the
	// command, so a symlink planted where that file belongs cannot choose it. An
	// unreadable locale leaves the argument off, which is exactly today's
	// behaviour: losing a working repair over a line nothing else depends on
	// would be the worse failure.
	if details, err := wpchecksums.ReadDetails("/home/"+systemUser, relativeToHome(systemUser, dir)); err == nil && details.Locale != "" {
		dlArgs = append(dlArgs, "--locale="+details.Locale)
	}
	// Reinstall core while preserving content, plugins, and themes, then update the database.
	_, dlErr := runWPTimeout(wpNetworkTimeout, systemUser, dlArgs...)
	if dlErr != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not download WordPress core")
		return
	}
	_, _ = runWP(systemUser, "core", "update-db", "--path="+dir)
	afterVerdicts, afterOutput, afterMeasured, _ := h.runChecksums(systemUser, dir)
	after := checksumState(afterVerdicts, afterMeasured)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "before": before, "after": after,
		"output": truncateOutput(beforeOutput + "\n---\n" + afterOutput),
	})
}

// POST /domains/{id}/wordpress/tool applies {dir, action: maintenance-on|maintenance-off|cache-clear|update-all}.
func (h *Handlers) ToolAction(w http.ResponseWriter, r *http.Request) {
	var req struct{ Dir, Action string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	systemUser, dir, ok := h.prepareMutation(w, r, req.Dir)
	if !ok {
		return
	}
	var out []byte
	var err error
	switch req.Action {
	case "maintenance-on":
		err = enableMaintenance(systemUser, dir)
		if err == nil {
			out = []byte("Maintenance mode enabled.")
		}
	case "maintenance-off":
		err = disableMaintenance(dir)
		if err == nil {
			out = []byte("Maintenance mode disabled.")
		}
	case "cache-clear":
		out, err = runWP(systemUser, "cache", "flush", "--path="+dir)
	case "update-all":
		var b strings.Builder
		o1, e1 := runWPTimeout(wpNetworkTimeout, systemUser, "core", "update", "--path="+dir)
		b.Write(o1)
		o2, _ := runWPTimeout(wpNetworkTimeout, systemUser, "plugin", "update", "--all", "--path="+dir)
		b.WriteString("\n")
		b.Write(o2)
		o3, _ := runWPTimeout(wpNetworkTimeout, systemUser, "theme", "update", "--all", "--path="+dir)
		b.WriteString("\n")
		b.Write(o3)
		_, _ = runWP(systemUser, "core", "update-db", "--path="+dir)
		out, err = []byte(b.String()), e1
	default:
		httpx.WriteError(w, http.StatusBadRequest, "unknown action")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "output": truncateOutput(string(out))})
}

// truncateOutput truncates long wp-cli output to the final 600 characters for error messages.
func truncateOutput(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 600 {
		s = "…" + s[len(s)-600:]
	}
	return s
}
