// Package packages provides a DNF-backed server package manager.
package packages

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"servika/internal/httpx"
)

// ProtectedPackages contains packages whose removal would break the system.
var ProtectedPackages = map[string]bool{
	"bash": true, "glibc": true, "kernel": true, "systemd": true,
	"openssh": true, "openssh-server": true, "openssh-clients": true,
	"sudo": true, "dnf": true, "rpm": true, "filesystem": true,
	"setup": true, "selinux-policy": true, "selinux-policy-targeted": true,
	"libselinux": true, "policycoreutils": true,
	// Required for the panel to function
	"nginx": true, "mariadb": true, "mariadb-server": true, "mariadb-common": true,
	"bind": true, "bind-utils": true,
	"pure-ftpd": true, "pure-ftpd-mysql": true,
	"php": true, "php-fpm": true, "php-cli": true, "php-common": true,
}

// Handlers provides HTTP handlers for package management.
type Handlers struct {
	DB *sql.DB
}

// safe returns true if the package name contains only safe characters.
func safe(s string) bool {
	if s == "" || len(s) > 80 {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
			(c < '0' || c > '9') && c != '-' && c != '_' && c != '.' && c != '+' {
			return false
		}
	}
	return true
}

// Package describes an operating system package.
type Package struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Repo        string `json:"repo,omitempty"`
	Description string `json:"description,omitempty"`
	Installed   bool   `json:"installed"`
	Protected   bool   `json:"protected"`
}

// Search runs dnf search and returns at most 200 results.
func (h *Handlers) Search(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		httpx.WriteError(w, http.StatusBadRequest, "q parameter is required")
		return
	}
	if !safe(q) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid search query")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	// Parse the Name and Summary Matched sections from dnf search.
	out, _ := runCommand(ctx, "dnf", "search", "--quiet", q).CombinedOutput()
	lines := strings.Split(string(out), "\n")
	packageList := []Package{}
	installedPackages := installedSet()
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "===") || strings.HasPrefix(ln, "Last metadata") {
			continue
		}
		// format: "package-name.x86_64 : description"
		if !strings.Contains(ln, " : ") {
			continue
		}
		parts := strings.SplitN(ln, " : ", 2)
		nameArch := strings.TrimSpace(parts[0])
		desc := strings.TrimSpace(parts[1])
		// strip arch suffix
		name := nameArch
		if i := strings.LastIndex(name, "."); i > 0 {
			suf := name[i+1:]
			if suf == "x86_64" || suf == "noarch" || suf == "i686" || suf == "src" || suf == "aarch64" {
				name = name[:i]
			}
		}
		packageList = append(packageList, Package{
			Name:        name,
			Description: desc,
			Installed:   installedPackages[name],
			Protected:   ProtectedPackages[name],
		})
		if len(packageList) >= 200 {
			break
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"q":       q,
		"total":   len(packageList),
		"content": packageList,
	})
}

// installedSet returns the set of all installed package names.
func installedSet() map[string]bool {
	// context.Background() rather than a request context: the same command the
	// literal exec.Command built, routed through the seam.
	out, _ := runCommand(context.Background(), "rpm", "-qa", "--qf", "%{NAME}\n").CombinedOutput()
	set := make(map[string]bool, 600)
	for ln := range strings.SplitSeq(string(out), "\n") {
		ln = strings.TrimSpace(ln)
		if ln != "" {
			set[ln] = true
		}
	}
	return set
}

// Installed lists installed packages with an optional filter.
func (h *Handlers) Installed(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	out, _ := runCommand(r.Context(), "rpm", "-qa", "--qf", "%{NAME}|%{VERSION}|%{SUMMARY}\n").CombinedOutput()
	packageList := []Package{}
	for ln := range strings.SplitSeq(string(out), "\n") {
		parts := strings.SplitN(ln, "|", 3)
		if len(parts) < 3 {
			continue
		}
		name := parts[0]
		if q != "" && !strings.Contains(strings.ToLower(name), q) && !strings.Contains(strings.ToLower(parts[2]), q) {
			continue
		}
		packageList = append(packageList, Package{
			Name:        name,
			Version:     parts[1],
			Description: parts[2],
			Installed:   true,
			Protected:   ProtectedPackages[name],
		})
		if len(packageList) >= 500 {
			break
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"total":   len(packageList),
		"content": packageList,
	})
}

type operationRequest struct {
	Package string `json:"package"`
}

// Install installs a package with DNF.
func (h *Handlers) Install(w http.ResponseWriter, r *http.Request) {
	var req operationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !safe(req.Package) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid package name")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	cmd := runCommand(ctx, "dnf", "install", "-y", req.Package)
	if _, err := cmd.CombinedOutput(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "package installation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"package": req.Package,
	})
}

// Remove runs dnf remove and rejects protected packages.
func (h *Handlers) Remove(w http.ResponseWriter, r *http.Request) {
	var req operationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !safe(req.Package) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid package name")
		return
	}
	if ProtectedPackages[req.Package] {
		httpx.WriteError(w, http.StatusForbidden,
			"this package is required by the system and cannot be removed: "+req.Package)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	cmd := runCommand(ctx, "dnf", "remove", "-y", req.Package)
	if _, err := cmd.CombinedOutput(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "package removal failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"package": req.Package,
	})
}

// Update upgrades one package or all packages with DNF.
func (h *Handlers) Update(w http.ResponseWriter, r *http.Request) {
	var req operationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Package != "" && !safe(req.Package) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid package")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
	defer cancel()
	args := []string{"upgrade", "-y"}
	if req.Package != "" {
		args = append(args, req.Package)
	}
	cmd := runCommand(ctx, "dnf", args...)
	if _, err := cmd.CombinedOutput(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "package upgrade failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"package": req.Package,
	})
}

// Info runs dnf info for a package.
func (h *Handlers) Info(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if !safe(name) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid package name")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if _, err := runCommand(ctx, "dnf", "info", name).CombinedOutput(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "package information lookup failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"name": name,
		"ok":   true,
	})
}

// Status returns installation states for a comma-separated package list.
func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	namesParam := r.URL.Query().Get("names")
	if namesParam == "" {
		httpx.WriteJSON(w, http.StatusOK, map[string]bool{})
		return
	}
	set := installedSet()
	res := make(map[string]bool)
	for name := range strings.SplitSeq(namesParam, ",") {
		name = strings.TrimSpace(name)
		if name == "" || !safe(name) {
			continue
		}
		res[name] = set[name]
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}
