package provisioner

import (
	"fmt"
	"html"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Per-domain maintenance mode.
//
// THE rule this whole feature is shaped around: the response is 503, never 200
// or 403. A maintenance page served with 200 is indexed as the site's real
// content, and 403 reads as removed. 503 is the only code that says "temporary"
// without damaging how the site is indexed, and it is why the page is served
// through error_page rather than by rewriting the request to a file.
//
// The mode is a fragment injected into the domain's ordinary vhost, not a
// replacement vhost like suspension uses. It has to be: an excepted address
// must reach the REAL site, which a replacement vhost no longer contains.

// maintenanceDir holds one generated HTML file per domain. It sits beside the
// brand error pages (see landing.go) for the same reason: nginx must read it,
// the panel writes it, and no tenant may.
const maintenanceDir = "/usr/share/servika/maintenance"

// maintenanceURI is the internal path error_page redirects to. It is not a real
// file name; the location resolves it to <domain id>.html through try_files.
const maintenanceURI = "/_servika_maint.html"

// accentPattern is the only colour form written into the document.
var accentPattern = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// MaintenancePage is what the customer controls about the page.
//
// The values arrive exactly as they were typed. Escaping happens here, at
// render time, rather than on the way into the database, so the editor shows
// the customer their own text back instead of an escaped copy of it.
type MaintenancePage struct {
	Title   string
	Message string
	Accent  string
	LogoURL string
}

// defaults for a customer who turned the mode on without writing anything.
const (
	defaultMaintenanceTitle   = "We will be back shortly"
	defaultMaintenanceMessage = "This website is temporarily unavailable while we carry out maintenance. Please try again in a little while."
	defaultMaintenanceAccent  = "#0f172a"
)

// MaintenancePagePath returns where one domain's generated page lives.
//
// The name is the domain's ID, never its name. A domain deleted and recreated
// under the same name gets a new ID, so it cannot inherit the page the previous
// owner wrote.
func MaintenancePagePath(domainID int64) string {
	return filepath.Join(maintenanceDir, strconv.FormatInt(domainID, 10)+".html")
}

// WriteMaintenancePage generates the page nginx serves for one domain.
func WriteMaintenancePage(domainID int64, page MaintenancePage) error {
	if domainID <= 0 {
		return fmt.Errorf("maintenance page: invalid domain id %d", domainID)
	}
	// #nosec G301 -- root-owned directory nginx must read; it holds no secret.
	if err := os.MkdirAll(maintenanceDir, 0o755); err != nil {
		return fmt.Errorf("maintenance page: %w", err)
	}
	path := MaintenancePagePath(domainID)
	next := []byte(renderMaintenanceHTML(page))
	// #nosec G304 -- path is built from a validated integer domain id under a fixed root-owned directory.
	if existing, err := os.ReadFile(path); err == nil && string(existing) == string(next) {
		return nil // unchanged, so nginx keeps serving the same inode
	}
	// #nosec G306 -- root-owned web content nginx must read; no secret is stored here.
	return os.WriteFile(path, next, 0o644)
}

// RemoveMaintenancePage deletes a domain's generated page.
//
// A missing file is not an error: the page only exists once the mode has been
// turned on, and deletion runs for every domain.
func RemoveMaintenancePage(domainID int64) error {
	if domainID <= 0 {
		return nil
	}
	if err := os.Remove(MaintenancePagePath(domainID)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// renderMaintenanceHTML builds the document.
//
// Every customer-controlled value is either HTML-escaped or matched against a
// pattern before it reaches the output. A value that fails its pattern is
// DROPPED rather than written through: a colour that is not a colour, placed in
// a style attribute, ends the attribute and the rest of the document with it.
func renderMaintenanceHTML(page MaintenancePage) string {
	title := strings.TrimSpace(page.Title)
	if title == "" {
		title = defaultMaintenanceTitle
	}
	message := strings.TrimSpace(page.Message)
	if message == "" {
		message = defaultMaintenanceMessage
	}
	accent := strings.TrimSpace(page.Accent)
	if !accentPattern.MatchString(accent) {
		accent = defaultMaintenanceAccent
	}

	logo := ""
	if target := validMaintenanceLogo(page.LogoURL); target != "" {
		logo = fmt.Sprintf("<img class=\"logo\" src=\"%s\" alt=\"\">", html.EscapeString(target))
	}

	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>` + html.EscapeString(title) + `</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#f8fafc;color:#0f172a;
       display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px}
  .card{max-width:560px;width:100%;background:#fff;border:1px solid #e2e8f0;border-radius:16px;
        padding:48px;text-align:center}
  .bar{height:4px;border-radius:2px;background:` + accent + `;width:56px;margin:0 auto 28px}
  .logo{max-height:56px;max-width:220px;margin:0 auto 24px;display:block}
  h1{font-size:22px;line-height:1.3;margin:0 0 12px;color:` + accent + `}
  p{color:#475569;line-height:1.65;font-size:15px;white-space:pre-line}
  @media (prefers-color-scheme:dark){
    body{background:#0b1120;color:#e2e8f0}
    .card{background:#111827;border-color:#1f2937}
    p{color:#94a3b8}
  }
</style>
</head>
<body>
<div class="card">` + logo + `<div class="bar"></div>
<h1>` + html.EscapeString(title) + `</h1>
<p>` + html.EscapeString(message) + `</p>
</div>
</body>
</html>
`
}

// validMaintenanceLogo returns the logo URL when it may be embedded, else "".
//
// https only. The page is served over TLS, so an http image is blocked as mixed
// content and the customer sees a broken page with no explanation of why.
func validMaintenanceLogo(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return ""
	}
	return parsed.String()
}

// buildMaintenanceBlock renders one vhost's maintenance fragment, or "" when
// the domain is not in maintenance.
func buildMaintenanceBlock(domainName string) string {
	if packageDB == nil {
		return ""
	}
	var domainID int64
	var enabled int
	if err := packageDB.QueryRow(
		`SELECT id, COALESCE(maintenance_enabled,0) FROM domains WHERE domain_name=? LIMIT 1`,
		domainName).Scan(&domainID, &enabled); err != nil || enabled != 1 {
		return ""
	}

	rows, err := packageDB.Query(
		`SELECT ip FROM domain_maintenance_ips WHERE domain_id=? ORDER BY id`, domainID)
	var exceptions []string
	if err == nil {
		for rows.Next() {
			var value string
			if rows.Scan(&value) != nil {
				continue
			}
			// Re-validated here rather than trusted from the write path: this
			// string goes into a regex nginx must parse, and a value that is
			// not an address would take the whole configuration down.
			if parsed := net.ParseIP(strings.TrimSpace(value)); parsed != nil {
				exceptions = append(exceptions, regexp.QuoteMeta(parsed.String()))
			}
		}
		_ = rows.Close()
	}

	return assembleMaintenanceBlock(domainID, exceptions)
}

// assembleMaintenanceBlock renders the fragment from values already validated.
//
// It is split from the database read so the whole shape can be asserted: the
// exemption ordering, the anchored address pattern and the 503 fallback are the
// entire boundary and none of them needs a database to be wrong.
//
// exceptions are regexp-quoted addresses.
func assembleMaintenanceBlock(domainID int64, exceptions []string) string {
	var body strings.Builder
	body.WriteString("    # ---- Maintenance mode, managed by Servika ----\n")
	// Retry-After sits in SERVER context. An add_header inside a location
	// cancels every header inherited from the server block, so putting it in
	// the page's own location would strip the site's security headers off the
	// maintenance response. The fragment only exists while the mode is on, so
	// server context costs nothing when it is off.
	body.WriteString("    add_header Retry-After \"3600\" always;\n")
	body.WriteString("    set $servika_maint 1;\n")
	// THE trap. nginx evaluates `if` in the REWRITE phase, BEFORE it has
	// matched a location, so a server-context `return 503` fires on the ACME
	// challenge path too. A domain left in maintenance would pass its first
	// certificate check and then fail every renewal, silently, weeks later.
	body.WriteString("    if ($request_uri ~ \"^/\\.well-known/\") { set $servika_maint 0; }\n")
	if len(exceptions) > 0 {
		// $remote_addr is the canonical form of the client address and the
		// stored values are canonicalised the same way, so the two compare as
		// text. The anchors are what make 203.0.113.5 not match 203.0.113.55.
		fmt.Fprintf(&body, "    if ($remote_addr ~ \"^(%s)$\") { set $servika_maint 0; }\n",
			strings.Join(exceptions, "|"))
	}
	body.WriteString("    if ($servika_maint) { return 503; }\n")
	fmt.Fprintf(&body, "    error_page 503 %s;\n", maintenanceURI)
	fmt.Fprintf(&body, "    location = %s {\n", maintenanceURI)
	body.WriteString("        internal;\n")
	fmt.Fprintf(&body, "        root %s;\n", maintenanceDir)
	// =503 rather than the implicit 404. A missing file would otherwise answer
	// 404, which tells a crawler the page is gone; this degrades to a bodyless
	// 503, which is still the correct answer.
	fmt.Fprintf(&body, "        try_files /%d.html =503;\n", domainID)
	body.WriteString("        access_log off;\n")
	body.WriteString("    }\n")
	return body.String()
}
