package middleware

import (
	"net/http"
	"strings"
)

const maxJSONBodyBytes = 10 << 20 // 10 MB

// BodyLimit caps the request body at maxJSONBodyBytes for JSON endpoints.
// Multipart upload endpoints are exempted because they stream large files and
// enforce their own multi-GiB limit via http.MaxBytesReader; applying the JSON
// cap here would truncate valid uploads over 10 MB before the upload limit runs.
// Exempt: file uploads, cPanel account-transfer archive uploads, site archive
// and SQL imports, and the mailbox import.
func BodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && isStreamingUpload(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
		next.ServeHTTP(w, r)
	})
}

func isStreamingUpload(p string) bool {
	return strings.HasSuffix(p, "/files/upload") ||
		strings.HasSuffix(p, "/admin/transfers/analyze") ||
		strings.HasSuffix(p, "/admin/transfers/import") ||
		strings.HasSuffix(p, "/import/archive") ||
		strings.HasSuffix(p, "/import/sql") ||
		isMailboxImport(p)
}

// isMailboxImport matches POST /domains/{id}/mail/{mid}/import, which streams a
// Maildir tar, an mbox or a .pst and enforces its own multi-GiB limit. The last
// segment alone is not enough: /domains/{id}/dns/import carries a JSON zone body
// and keeps the JSON cap.
func isMailboxImport(p string) bool {
	return strings.HasSuffix(p, "/import") && strings.Contains(p, "/mail/")
}
