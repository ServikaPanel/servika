package httpx

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
)

// SessionCookie is the name of the HttpOnly cookie that carries the session JWT
// for both administrators and customers. The token is never exposed to
// JavaScript (no localStorage), so an XSS in the SPA cannot exfiltrate it.
const SessionCookie = "servika_session"

// isHTTPS reports whether the original client request used TLS. nginx terminates
// TLS and forwards X-Forwarded-Proto; a direct connection sets r.TLS. When true
// the session cookie is marked Secure. Dev-over-http (no proxy, no TLS) keeps it
// unset so the cookie is still stored by the browser on localhost.
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

// SetSessionCookie issues the session cookie carrying the signed JWT. It is
// HttpOnly (JS-unreadable), Secure on HTTPS, and SameSite=Strict so the browser
// never attaches it to cross-site requests — this is the CSRF defense.
func SetSessionCookie(w http.ResponseWriter, r *http.Request, token string, maxAgeSec int) {
	// #nosec G124 -- HttpOnly + SameSite=Strict are set; Secure is intentionally conditional on isHTTPS so the cookie still works on localhost dev over HTTP.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAgeSec,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

// ClearSessionCookie expires the session cookie on logout. Attributes mirror
// SetSessionCookie so the browser reliably matches and removes it.
func ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	// #nosec G124 -- HttpOnly + SameSite=Strict are set; Secure is intentionally conditional on isHTTPS to mirror SetSessionCookie so the browser reliably removes it.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

// ErrorBody is the standard HTTP API error response.
type ErrorBody struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id,omitempty"`
}

// WriteJSON writes a JSON response with the provided HTTP status.
func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// WriteError writes a standard JSON error response.
func WriteError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, ErrorBody{Error: message})
}

// WriteErrorR writes a JSON error response annotated with the chi RequestID from context.
func WriteErrorR(w http.ResponseWriter, r *http.Request, status int, message string) {
	reqID := middleware.GetReqID(r.Context())
	WriteJSON(w, status, ErrorBody{Error: message, RequestID: reqID})
}

// ClientIP returns the originating client address.
//
// SECURITY: Proxy headers are trusted ONLY when the request arrives from the
// local reverse-proxy (nginx, 127.0.0.1). Otherwise the client could forge
// X-Forwarded-For to bypass login rate-limiting and poison the audit log with
// spoofed IPs.
//
// Header priority (matching nginx behavior):
//   - X-Real-IP: written AUTHORITATIVELY by nginx with $remote_addr; any value
//     sent by the client is OVERWRITTEN — this is the trusted source.
//   - X-Forwarded-For: nginx uses $proxy_add_x_forwarded_for which APPENDS to
//     the client-supplied value; the LAST element is therefore the trusted one.
func ClientIP(r *http.Request) string {
	remote := hostOnly(r.RemoteAddr)
	if !isLocalProxy(remote) {
		return remote // direct connection — do not trust headers
	}
	// A loopback peer can be nginx OR a same-host tenant process (both 127.0.0.1).
	// When the shared secret is INSTALLED (the normal case) trust the proxy
	// headers only on a request that carries nginx's X-Servika-Proxy; otherwise
	// fall back to remote so a tenant cannot forge X-Real-IP to bypass the login
	// rate-limit. When no secret exists yet (first boot / rollback) the previous
	// loopback-trust behaviour is kept so nobody is locked out.
	if secret := ProxySecret(); secret != "" && !hasProxySecretHeader(r, secret) {
		return remote
	}
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		parts := strings.Split(v, ",")
		if last := strings.TrimSpace(parts[len(parts)-1]); last != "" {
			return last
		}
	}
	return remote
}

// AuditIP returns the client address to record in the audit log.
//
// A real operator always arrives through nginx and keeps their real address. An
// internal or automated action originates on the box itself, and recording
// 127.0.0.1 for it is misleading: the reader cannot tell it apart from a genuine
// visitor that happens to sit behind the loopback interface. Such rows are
// labelled "system" instead.
//
// The check requires BOTH a loopback resolved address and a loopback peer, so a
// forged X-Real-IP of 127.0.0.1 from a remote client cannot claim the label.
func AuditIP(r *http.Request) string {
	ip := ClientIP(r)
	if (ip == "127.0.0.1" || ip == "::1") && isLocalProxy(hostOnly(r.RemoteAddr)) {
		return "system"
	}
	return ip
}

// isLocalProxy reports whether ip is a loopback address (our nginx).
func isLocalProxy(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && p.IsLoopback()
}

// hostOnly strips the port from "ip:port" (including IPv6 brackets).
func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
