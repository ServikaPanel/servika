package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func passThrough() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("reached the handler"))
	})
}

func crossOriginRequest(method string, headers map[string]string) *http.Request {
	request := httptest.NewRequest(method, "/api/v1/users", strings.NewReader(`{"role":"admin"}`))
	request.Host = "panel.example.com:8443"
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	return request
}

func reached(t *testing.T, headers map[string]string, method string) bool {
	t.Helper()
	recorder := httptest.NewRecorder()
	EnforceSameOrigin(passThrough()).ServeHTTP(recorder, crossOriginRequest(method, headers))
	return strings.Contains(recorder.Body.String(), "reached the handler")
}

// SameSite is scoped to the registrable domain, not the origin. A tenant
// subdomain of the panel's own domain is SAME-SITE, so the browser attaches the
// session cookie to a top-level request a page under the tenant's control
// makes. That is the case SameSite=Strict permits and this refuses.
func TestASameSiteWriteIsRefused(t *testing.T) {
	if reached(t, map[string]string{"Sec-Fetch-Site": "same-site"}, http.MethodPost) {
		t.Error("a same-site write reached the handler; this is the tenant-subdomain CSRF")
	}
}

func TestACrossSiteWriteIsRefused(t *testing.T) {
	for _, headers := range []map[string]string{
		{"Sec-Fetch-Site": "cross-site"},
		{"Origin": "https://evil.example"},
		// A form post carries Origin even without Sec-Fetch-Site.
		{"Origin": "https://tenant.example.com:8443", "Content-Type": "text/plain"},
	} {
		if reached(t, headers, http.MethodPost) {
			t.Errorf("a cross-origin write reached the handler: %v", headers)
		}
	}
}

// The panel's own page must keep working, or this refuses everything and proves
// nothing.
func TestThePanelsOwnWriteIsAllowed(t *testing.T) {
	for _, headers := range []map[string]string{
		{"Sec-Fetch-Site": "same-origin"},
		{"Sec-Fetch-Site": "same-origin", "Origin": "https://panel.example.com:8443"},
		{"Origin": "https://panel.example.com:8443"},
		// A user-initiated navigation: a typed URL or a bookmark.
		{"Sec-Fetch-Site": "none"},
	} {
		if !reached(t, headers, http.MethodPost) {
			t.Errorf("the panel's own write was refused: %v", headers)
		}
	}
}

// A non-browser client sends neither header. It is not driven by an attacker's
// page, and refusing it would break every scripted integration and the panel's
// own loopback callbacks.
func TestANonBrowserClientIsAllowed(t *testing.T) {
	if !reached(t, nil, http.MethodPost) {
		t.Error("a request with no browser headers was refused")
	}
}

// A read has no side effect to protect and refusing one would break links.
func TestReadsAreNotChecked(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		if !reached(t, map[string]string{"Sec-Fetch-Site": "cross-site"}, method) {
			t.Errorf("a cross-site %s was refused", method)
		}
	}
}

// Every state-changing method is covered, not just POST.
func TestEveryWriteMethodIsChecked(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if reached(t, map[string]string{"Sec-Fetch-Site": "cross-site"}, method) {
			t.Errorf("a cross-site %s reached the handler", method)
		}
	}
}

// Sec-Fetch-Site wins over Origin, because it is the header that distinguishes
// same-site from same-origin and Origin alone cannot.
func TestSecFetchSiteDecidesWhenBothArePresent(t *testing.T) {
	// A same-site page can set no header, but it CAN be on a host that happens
	// to match nothing; this pins which one the check trusts.
	if reached(t, map[string]string{
		"Sec-Fetch-Site": "same-site",
		"Origin":         "https://panel.example.com:8443",
	}, http.MethodPost) {
		t.Error("Origin overrode a same-site verdict")
	}
}
