package middleware

import (
	"net/http"

	"servika/internal/httpx"
)

// The session cookie's SameSite=Strict was the ONLY CSRF control: no route
// validated a token, an Origin, a Referer or a Sec-Fetch-Site header.
//
// SameSite is evaluated against the registrable domain (the SITE), not the
// origin. The panel accepts any hostname as its own custom domain and never
// checks that it does not share a registrable domain with a hosted tenant
// domain, and a tenant can create subdomains freely. With the panel at
// panel.example.com and example.com hosted on the same server, a page the
// tenant controls is SAME-SITE with the panel, so the browser attaches the
// session cookie to a top-level request it makes.
//
// No handler enforced a content type either, and every mutating handler decodes
// with a JSON decoder that ignores it, so a plain HTML form with
// enctype="text/plain" produces a body the decoder accepts and fires no CORS
// preflight. CORS then blocks READING the response but not executing the
// request, and POST /api/v1/users with "role":"admin" against an
// administrator's session is a full panel takeover.
//
// This closes it at the edge. Sec-Fetch-Site and Origin are both forbidden
// header names: a page cannot set or remove them, so a browser request always
// carries what it really is.

// EnforceSameOrigin refuses a state-changing request that a browser says came
// from somewhere other than the panel's own origin.
//
// The rules, in order:
//
//   - Sec-Fetch-Site, when present, is authoritative. same-origin is the panel's
//     own page; none is a user-initiated navigation (a typed URL, a bookmark).
//     cross-site and SAME-SITE are refused, and refusing same-site is the point:
//     that is exactly the tenant subdomain case SameSite=Strict permits.
//   - Origin, when present, must match the request host. That covers a browser
//     old enough to omit Sec-Fetch-Site.
//   - Neither header means a non-browser client: curl, a script, the panel's own
//     loopback callbacks. Those are not driven by an attacker's page, and
//     refusing them would break every scripted integration for no gain.
//
// Only state-changing methods are checked. A GET has no side effect to protect,
// and refusing one would break links.
func EnforceSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !stateChanging(r.Method) || originAllowed(r) {
			next.ServeHTTP(w, r)
			return
		}
		httpx.LogR(r, "cross-origin write refused: method=%s path=%q sec-fetch-site=%q origin=%q",
			r.Method, r.URL.Path, r.Header.Get("Sec-Fetch-Site"), r.Header.Get("Origin"))
		httpx.WriteError(w, http.StatusForbidden, "cross-origin request refused")
	})
}

func stateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// originAllowed reports whether the request demonstrably comes from the panel's
// own origin, or from a client that is not a browser at all.
func originAllowed(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "same-site", "cross-site":
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		return sameOrigin(origin, r.Host)
	}
	return true
}
