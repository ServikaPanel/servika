package plugin

// Package plugin provides the out-of-process plugin runtime.
// Plugins run as separate services and communicate with Servika through Unix sockets.

import (
	"context"
	"database/sql"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"servika/internal/config"
	"servika/internal/httpx"
	"servika/internal/middleware"

	"github.com/go-chi/chi/v5"
)

const (
	// pluginDialAttempts and pluginDialDelay together cover a plugin restart:
	// long enough for a service to come back, short enough that a genuinely dead
	// plugin still answers within a second and a half instead of hanging.
	pluginDialAttempts = 6
	pluginDialDelay    = 250 * time.Millisecond
)

func bundleRoot() string { return config.PluginRoot() }

// Handlers provides plugin registry, bundle, proxy, and health endpoints.
type Handlers struct{ DB *sql.DB }

// Plugin describes a registered out-of-process plugin.
type Plugin struct {
	Name    string `json:"name"`
	Label   string `json:"label"`
	Version string `json:"version"`
	Enabled bool   `json:"enabled"`
	UI      bool   `json:"ui"`
	Health  string `json:"health"`
	socket  string
}

func validName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, character := range name {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func (h *Handlers) get(ctx context.Context, name string) (*Plugin, error) {
	var plugin Plugin
	var enabled, ui int
	err := h.DB.QueryRowContext(ctx,
		`SELECT name, label, version, enabled, ui, health, COALESCE(socket, '') FROM plugins WHERE name = ?`, name).
		Scan(&plugin.Name, &plugin.Label, &plugin.Version, &enabled, &ui, &plugin.Health, &plugin.socket)
	if err != nil {
		return nil, err
	}
	plugin.Enabled, plugin.UI = enabled == 1, ui == 1
	return &plugin, nil
}

// List returns the registered plugins available to the administrator interface.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT name, label, version, enabled, ui, health FROM plugins ORDER BY label`)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "plugins could not be loaded")
		return
	}
	defer func() { _ = rows.Close() }()

	plugins := []Plugin{}
	for rows.Next() {
		var plugin Plugin
		var enabled, ui int
		if err := rows.Scan(&plugin.Name, &plugin.Label, &plugin.Version, &enabled, &ui, &plugin.Health); err != nil {
			continue
		}
		plugin.Enabled, plugin.UI = enabled == 1, ui == 1
		plugins = append(plugins, plugin)
	}
	httpx.WriteJSON(w, http.StatusOK, plugins)
}

// Bundle serves the frontend JavaScript bundle of an enabled plugin.
func (h *Handlers) Bundle(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if !validName(name) {
		http.NotFound(w, r)
		return
	}
	plugin, err := h.get(r.Context(), name)
	if err != nil || !plugin.Enabled || !plugin.UI {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(bundleRoot(), name, "app.js")
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	if _, err := os.Stat(path); err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	http.ServeFile(w, r, path)
}

// Proxy forwards an authenticated administrator request to a plugin Unix socket.
func (h *Handlers) Proxy(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if !validName(name) {
		httpx.WriteError(w, http.StatusNotFound, "plugin not found")
		return
	}
	plugin, err := h.get(r.Context(), name)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "plugin is not registered")
		return
	}
	if !plugin.Enabled {
		httpx.WriteError(w, http.StatusPaymentRequired, "plugin is not enabled")
		return
	}
	if plugin.socket == "" {
		httpx.WriteError(w, http.StatusServiceUnavailable, "plugin socket is not configured")
		return
	}

	proxy := &httputil.ReverseProxy{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialPluginSocket(ctx, plugin.socket)
			},
			ResponseHeaderTimeout: 0,
		},
		Director: func(request *http.Request) {
			request.URL.Scheme = "http"
			request.URL.Host = "plugin"
			prefix := "/api/v1/plugin/" + name
			request.URL.Path = strings.TrimPrefix(request.URL.Path, prefix)
			if request.URL.Path == "" {
				request.URL.Path = "/"
			}
			request.Header.Del("X-Servika-User")
			request.Header.Del("X-Servika-Uid")
			request.Header.Del("X-Servika-Role")
			if claims := middleware.ClaimsFrom(request); claims != nil {
				request.Header.Set("X-Servika-Uid", strconv.FormatInt(claims.UserID, 10))
				request.Header.Set("X-Servika-User", claims.Username)
				request.Header.Set("X-Servika-Role", claims.Role)
			}
		},
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			// The panel stays up when a plugin does not. The real error goes to the
			// log; the caller gets a code it can act on, plus the header that tells
			// a client this is worth retrying rather than a permanent gateway fault.
			// #nosec G706 -- name passed validName above, an allowlist of [a-z0-9-] bounded to 64 characters, so it cannot carry CR/LF or control characters; err is a dial error.
			log.Printf("plugin proxy %s: %v", name, err)
			w.Header().Set("Retry-After", "3")
			httpx.WriteError(w, http.StatusServiceUnavailable, "plugin is restarting")
		},
	}
	proxy.ServeHTTP(w, r)
}

// CheckHealth probes enabled plugin sockets and records their health state.
func (h *Handlers) CheckHealth(ctx context.Context) {
	rows, err := h.DB.QueryContext(ctx, `SELECT name, COALESCE(socket, '') FROM plugins WHERE enabled = 1`)
	if err != nil {
		return
	}
	type record struct{ name, socket string }
	var plugins []record
	for rows.Next() {
		var plugin record
		if err := rows.Scan(&plugin.name, &plugin.socket); err == nil {
			plugins = append(plugins, plugin)
		}
	}
	_ = rows.Close()

	for _, plugin := range plugins {
		health := "unhealthy"
		if plugin.socket != "" {
			connection, err := net.DialTimeout("unix", plugin.socket, 2*time.Second)
			if err == nil {
				_ = connection.Close()
				health = "healthy"
			}
		}
		_, _ = h.DB.ExecContext(ctx,
			`UPDATE plugins SET health = ?, last_checked = NOW() WHERE name = ?`, health, plugin.name)
	}
}

// HealthLoop periodically checks enabled plugin sockets until the context is canceled.
func (h *Handlers) HealthLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	h.CheckHealth(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.CheckHealth(ctx)
		}
	}
}

// Routes registers administrator-only plugin API routes.
func (h *Handlers) Routes(r chi.Router) {
	r.With(middleware.AdminOnly).Get("/plugins", h.List)
	r.With(middleware.AdminOnly).HandleFunc("/plugin/{name}/*", h.Proxy)
}

// dialPluginSocket connects to a plugin's socket, retrying briefly.
//
// Installing or updating a plugin restarts it, and its socket disappears for a
// second or two. Without this the panel answers an error for every request that
// lands in that window, which reads as a broken module rather than one being
// restarted.
//
// Retrying the DIAL is safe for any method: the request is only written once a
// connection exists, so a POST is never delivered twice. Retrying the request
// itself would not be.
func dialPluginSocket(ctx context.Context, socket string) (net.Conn, error) {
	var dialer net.Dialer
	var lastErr error
	for attempt := range pluginDialAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(pluginDialDelay):
			}
		}
		conn, err := dialer.DialContext(ctx, "unix", socket)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
