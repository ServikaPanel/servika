// Package composer: per-domain PHP Composer execution (whitelist + as the domain user).
package composer

import (
	"context"
	"database/sql"
	"encoding/json"
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
	"servika/internal/httpx"
	"servika/internal/subdomain"

	"github.com/go-chi/chi/v5"
)

type Handlers struct {
	DB *sql.DB
}

var rePkg = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*)/[a-z0-9]([a-z0-9._-]*)(:[\^~<>=0-9.* |,-]+)?$`)

// composerTimeout bounds a dependency resolution that talks to packagist. It sits
// above the router's own 300-second request timeout because a large install
// legitimately outlasts the request; the point is that the process ends.
const composerTimeout = 10 * time.Minute

// concurrentRunsPerUser is how many composer processes one hosting account may
// hold at a time. The same number internal/laravel's execGate uses for the same
// class of command.
//
// Without it the endpoint had no bound at all: the deadline is detached from the
// request on purpose, so a customer issuing hundreds of `composer update` calls
// held that many resolver processes for ten minutes each. They run through
// runuser inside servika.service's cgroup rather than the tenant's plan-limited
// slice, and the unit sets no resource limits, so neither the plan nor a cgroup
// ceiling applied. Composer's resolver is memory-hungry, which made this a CPU,
// RAM and bandwidth exhaustion vector against every other tenant on the host.
const concurrentRunsPerUser = 3

// runSlots holds one buffered channel per system user, created on first use.
var runSlots sync.Map

// acquireRunSlot takes a slot for systemUser WITHOUT blocking, and reports
// whether it got one.
//
// A blocking gate would be wrong on a request path: the caller would wait behind
// a ten-minute install while holding a panel goroutine, which is most of the
// resource the gate exists to protect. Refusing tells the customer what is
// happening instead.
func acquireRunSlot(systemUser string) (release func(), ok bool) {
	value, _ := runSlots.LoadOrStore(systemUser, make(chan struct{}, concurrentRunsPerUser))
	slots := value.(chan struct{})
	select {
	case slots <- struct{}{}:
		return func() { <-slots }, true
	default:
		return nil, false
	}
}

func composerBin() string { return config.ComposerBin() }

// load resolves the domain and the directory composer must run in. A {sid} URL
// parameter selects that subdomain's document root, so composer acts on the
// subdomain's own dependencies instead of the parent domain's public_html.
func (h *Handlers) load(r *http.Request) (id int64, systemUser, directory string, ok bool) {
	id, _ = strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user FROM domains WHERE id=?`, id).Scan(&systemUser); err != nil {
		return id, "", "", false
	}
	directory = "/home/" + systemUser + "/public_html"
	if raw := chi.URLParam(r, "sid"); raw != "" {
		sid, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return id, "", "", false
		}
		scope, scopeOK := subdomain.ResolveScope(r.Context(), h.DB, id, sid)
		if !scopeOK {
			return id, "", "", false
		}
		directory = scope.DocRoot
	}
	return id, systemUser, directory, true
}

// GET /domains/{id}/composer, status (is composer installed, does composer.json exist)
func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	_, systemUser, directory, ok := h.load(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	var version string
	installed := false
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	vc := exec.Command(composerBin(), "--version", "--no-ansi")
	vc.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/tmp",
		"COMPOSER_HOME=/tmp",
	}
	if out, err := vc.Output(); err == nil { // stdout-only: exclude the stderr plugin warning
		installed = true
		version = strings.TrimSpace(string(out))
	}
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	_, jErr := os.Stat(filepath.Join(directory, "composer.json"))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"installed":     installed,
		"version":       version,
		"composer_json": jErr == nil,
		"username":      systemUser,
		"dir":           directory,
	})
}

// POST /domains/{id}/composer  body {"command":"install|update|dump-autoload|validate|require|remove","package":"vendor/pkg"}
func (h *Handlers) Run(w http.ResponseWriter, r *http.Request) {
	_, systemUser, directory, ok := h.load(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if !strings.HasPrefix(systemUser, "c_") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user")
		return
	}
	if _, err := os.Stat(composerBin()); err != nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "composer is not installed on the server")
		return
	}
	var req struct {
		Command string `json:"command"`
		Package string `json:"package"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	allowed := map[string]bool{"install": true, "update": true, "dump-autoload": true, "validate": true, "require": true, "remove": true, "show": true}
	if !allowed[req.Command] {
		httpx.WriteError(w, http.StatusBadRequest, "command is not allowed")
		return
	}
	// Pass arguments explicitly without a shell to prevent command injection.
	args := []string{"-u", systemUser, "--", composerBin(), req.Command, "--no-interaction", "--no-ansi", "-d", directory}
	if req.Command == "install" || req.Command == "update" {
		args = append(args, "--no-scripts", "--no-plugins")
	}
	if req.Command == "require" || req.Command == "remove" {
		pkg := strings.TrimSpace(req.Package)
		if !rePkg.MatchString(pkg) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid package name (expected vendor/package[:version])")
			return
		}
		args = append(args, pkg)
	}
	// Taken AFTER validation so a malformed request cannot burn a slot, and
	// before the process is started so nothing runs ungated.
	release, gotSlot := acquireRunSlot(systemUser)
	if !gotSlot {
		httpx.WriteError(w, http.StatusConflict,
			"another composer command is already running for this account, wait for it to finish")
		return
	}
	defer release()
	// Composer resolves and downloads from packagist, so an unreachable mirror would
	// otherwise leave the process running for the life of the panel. The deadline is
	// not tied to the request: a half-written vendor/ directory is worse than one
	// that finishes after the caller stopped waiting.
	ctx, cancel := context.WithTimeout(context.Background(), composerTimeout)
	defer cancel()
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	cmd := runCommand(ctx, "runuser", args...)
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/home/" + systemUser,
		"COMPOSER_HOME=/home/" + systemUser + "/.composer",
		"COMPOSER_ALLOW_SUPERUSER=0",
	}
	out, err := cmd.CombinedOutput()
	output := string(out)
	if len(output) > 20000 {
		output = output[len(output)-20000:]
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":      err == nil,
		"command": req.Command,
		"output":  output,
	})
}
