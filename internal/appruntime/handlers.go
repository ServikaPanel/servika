package appruntime

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"servika/internal/httpx"
)

// Handlers provides HTTP handlers for application runtime management.
type Handlers struct {
	DB *sql.DB
}

// List reports every installed interpreter, grouped by kind.
// GET /app-runtimes
func (h *Handlers) List(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"node":   Installed(Node),
		"python": Installed(Python),
	})
}

type opReq struct {
	Kind    string `json:"kind"`
	Version string `json:"version"`
}

// parseOp validates the request into a kind and a version that is safe to name
// in a shell script. It rejects "system" outright: the panel neither installs
// nor removes what the operating system ships.
func parseOp(req opReq) (Kind, string, error) {
	kind := Kind(strings.TrimSpace(req.Kind))
	version := strings.TrimSpace(req.Version)
	if !ValidKind(string(kind)) {
		return "", "", fmt.Errorf("runtime must be node or python")
	}
	if version == SystemVersion {
		return "", "", fmt.Errorf("the system runtime is managed by the operating system")
	}
	switch kind {
	case Node:
		if !reNodeVersion.MatchString(version) {
			return "", "", fmt.Errorf("invalid Node.js version")
		}
	case Python:
		if !rePythonVersion.MatchString(version) {
			return "", "", fmt.Errorf("invalid Python version, expected a form such as 3.12")
		}
	}
	return kind, version, nil
}

// Install starts a detached runtime installation.
// POST /app-runtimes/install
func (h *Handlers) Install(w http.ResponseWriter, r *http.Request) {
	var req opReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	kind, version, err := parseOp(req)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, installed := Resolve(kind, version); installed {
		httpx.WriteError(w, http.StatusConflict, "that runtime is already installed")
		return
	}
	// dnf holds the rpm lock for a whole transaction, and two `n` installs would
	// race over the same version root, so only one operation runs at a time.
	if opRunning() {
		httpx.WriteError(w, http.StatusConflict,
			"a runtime operation is already running, try again when it finishes")
		return
	}

	script := nodeInstallScript(version)
	if kind == Python {
		script = pythonInstallScript(version)
	}
	descriptor := opDescriptor{Kind: string(kind), Version: version, Action: "install"}
	if err := startOp(descriptor, script); err != nil {
		log.Printf("runtime install %s %s: %v", kind, version, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not start the installation")
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"started": true, "kind": string(kind), "version": version,
	})
}

// Remove starts a detached runtime removal.
// POST /app-runtimes/remove
func (h *Handlers) Remove(w http.ResponseWriter, r *http.Request) {
	var req opReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	kind, version, err := parseOp(req)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Only a version the panel actually lists as installed may be removed.
	// installedPython hides the OS interpreter's own versioned name (python3.12
	// on AlmaLinux 10), so this refuses a direct API call to remove it, which
	// would run `dnf remove python3.12` and take the base interpreter with it.
	if _, installed := Resolve(kind, version); !installed {
		httpx.WriteError(w, http.StatusConflict, "that runtime is not installed")
		return
	}

	// FAIL-CLOSED: a count error must not let a removal proceed and leave a
	// running application pointing at an interpreter that no longer exists.
	var count int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM apps WHERE runtime=? AND runtime_version=?`,
		string(kind), version).Scan(&count); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not verify runtime usage")
		return
	}
	if count > 0 {
		httpx.WriteError(w, http.StatusConflict,
			fmt.Sprintf("%d applications use this runtime; move them to another version first", count))
		return
	}
	if opRunning() {
		httpx.WriteError(w, http.StatusConflict,
			"a runtime operation is already running, try again when it finishes")
		return
	}

	script := nodeRemoveScript(version)
	if kind == Python {
		script = pythonRemoveScript(version)
	}
	descriptor := opDescriptor{Kind: string(kind), Version: version, Action: "remove"}
	if err := startOp(descriptor, script); err != nil {
		log.Printf("runtime remove %s %s: %v", kind, version, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not start the removal")
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"started": true, "kind": string(kind), "version": version,
	})
}

// Status reports whether an operation is running, and which one.
// GET /app-runtimes/status
//
// The screen calls this on load so an operation started in another tab, or
// before this page was opened, is picked up rather than lost.
func (h *Handlers) Status(w http.ResponseWriter, _ *http.Request) {
	descriptor := readOpDescriptor()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"running": opRunning(),
		"kind":    descriptor.Kind,
		"version": descriptor.Version,
		"action":  descriptor.Action,
		"status":  opState(),
	})
}

// LogTail returns the end of the operation log with the running flag.
// GET /app-runtimes/log
//
// The flag travels WITH the log rather than being polled separately, so the
// screen cannot read the last lines of a finished run and still believe it is
// in progress.
func (h *Handlers) LogTail(w http.ResponseWriter, _ *http.Request) {
	descriptor := readOpDescriptor()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"log":     readOpLog(),
		"running": opRunning(),
		"kind":    descriptor.Kind,
		"version": descriptor.Version,
		"action":  descriptor.Action,
	})
}
