package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBodyLimitExemptsUpload verifies the multipart upload path can stream a body
// larger than the 10 MB JSON cap, while other paths remain capped.
func TestBodyLimitExemptsUpload(t *testing.T) {
	const size = 11 << 20 // 11 MB, over the 10 MB JSON cap
	body := strings.Repeat("a", size)

	cases := []struct {
		name   string
		method string
		path   string
		capped bool // true when the body should be truncated to the JSON cap
	}{
		{"upload exempt", http.MethodPost, "/api/v1/domains/5/files/upload", false},
		// A site archive and a SQL dump both stream; capping them at the JSON
		// limit would truncate the body before the handler ever sees it.
		{"import archive exempt", http.MethodPost, "/api/v1/domains/5/import/archive", false},
		{"import sql exempt", http.MethodPost, "/api/v1/domains/5/import/sql", false},
		// The apply and config calls are ordinary JSON and stay capped.
		{"import apply capped", http.MethodPost, "/api/v1/domains/5/import/archive/apply", true},
		{"import config capped", http.MethodPost, "/api/v1/domains/5/import/config", true},
		// A mailbox arrives as a Maildir tar, an mbox or a .pst, and the handler
		// enforces its own 4 GiB limit. A MaxBytesReader composes with the one
		// under it, so the JSON cap here would decide instead.
		{"mailbox import exempt", http.MethodPost, "/api/v1/domains/5/mail/9/import", false},
		// A BIND zone arrives as JSON on a path with the same last segment, so
		// the suffix alone must not exempt it.
		{"dns import capped", http.MethodPost, "/api/v1/domains/5/dns/import", true},
		{"json capped", http.MethodPost, "/api/v1/domains/5/databases", true},
		{"get on upload path capped", http.MethodGet, "/api/v1/domains/5/files/upload", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var readN int
			var readErr error
			h := BodyLimit(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				b, err := io.ReadAll(r.Body)
				readN = len(b)
				readErr = err
			}))
			req := httptest.NewRequest(c.method, c.path, strings.NewReader(body))
			h.ServeHTTP(httptest.NewRecorder(), req)

			if c.capped {
				// MaxBytesReader returns an error once the cap is exceeded.
				if readErr == nil {
					t.Errorf("%s: expected body to be capped, but full body read (%d bytes)", c.path, readN)
				}
			} else {
				if readErr != nil {
					t.Errorf("%s: expected full body, got error after %d bytes: %v", c.path, readN, readErr)
				}
				if readN != size {
					t.Errorf("%s: read %d bytes, want %d", c.path, readN, size)
				}
			}
		})
	}
}
