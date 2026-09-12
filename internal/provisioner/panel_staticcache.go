package provisioner

import (
	"os"
	"strings"
)

// The panel's three static locations and the freshness each one has earned.
//
// The SPA build emits content-hashed file names (app.8f3a91.js), so the URL
// changes whenever the bytes do and the browser may keep the old one for ever.
// phpMyAdmin and Roundcube ship FIXED file names, so the same URL carries new
// bytes after an update; those two get a short lifetime and revalidate against
// the ETag nginx already sends.
const (
	panelHashedAssetCache = `add_header Cache-Control "public, max-age=31536000, immutable" always;`
	panelPlainAssetCache  = `add_header Cache-Control "public, max-age=3600" always;`
)

// panelStaticCacheLocations pairs each static location with its directive.
//
// The two regex openers are copied from assets/nginx/_panel.conf verbatim,
// because the repair matches an installed vhost by the trimmed opening line.
var panelStaticCacheLocations = []struct {
	open, cacheControl string
}{
	{"location /assets/ {", panelHashedAssetCache},
	{`location ~ ^/pma/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt|svg|woff2?|map))$ {`, panelPlainAssetCache},
	{`location ~ ^/webmail/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt|svg|woff2?|map))$ {`, panelPlainAssetCache},
}

// blockBounds returns the line range of the location whose opening line is
// openLine, or ok=false when the file declares no such location or never
// closes it.
//
// The closing brace is matched at the OPENING line's own indent, so a nested
// location is stepped over rather than mistaken for the end. replaceIndentedBlock
// takes the same care and for the same reason.
func blockBounds(lines []string, openLine string) (start, end int, ok bool) {
	for i, line := range lines {
		if strings.TrimSpace(line) != openLine {
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		for j := i + 1; j < len(lines); j++ {
			if lines[j] == indent+"}" {
				return i, j, true
			}
		}
		return 0, 0, false
	}
	return 0, 0, false
}

// rewriteCacheLines returns the body of one location with a single freshness
// directive in it.
//
// It removes every `expires` line. nginx writes its own Cache-Control from
// `expires`, so a location carrying both sends the header TWICE (measured
// against nginx 1.27: `Cache-Control: max-age=604800` followed by
// `Cache-Control: public, immutable`). One directive is one header.
func rewriteCacheLines(body []string, cacheControl, indent string) []string {
	out := make([]string, 0, len(body)+1)
	written := false
	for _, line := range body {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "expires "):
			continue
		case strings.HasPrefix(trimmed, "add_header Cache-Control"):
			if written {
				continue
			}
			out = append(out, indent+cacheControl)
			written = true
		default:
			out = append(out, line)
		}
	}
	if !written {
		out = append(out, indent+cacheControl)
	}
	return out
}

// bodyIndent reports the indent the location's own directives use, so a
// rewritten line lines up with the lines around it.
func bodyIndent(body []string) string {
	for _, line := range body {
		if strings.TrimSpace(line) == "" {
			continue
		}
		return line[:len(line)-len(strings.TrimLeft(line, " \t"))]
	}
	return "        "
}

// ensureGzipVary adds `gzip_vary on;` under the panel's `gzip on;`.
//
// A compressed response and an uncompressed one share one URL, so a cache that
// does not know the encoding belongs in the key can hand gzip bytes to a client
// that asked for none. nginx defaults gzip_vary off, and the panel compresses
// CSS, JavaScript, JSON and SVG.
func ensureGzipVary(lines []string) []string {
	for _, line := range lines {
		if strings.TrimSpace(line) == "gzip_vary on;" {
			return lines
		}
	}
	for i, line := range lines {
		if strings.TrimSpace(line) != "gzip on;" {
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		out := make([]string, 0, len(lines)+1)
		out = append(out, lines[:i+1]...)
		out = append(out, indent+"gzip_vary on;")
		return append(out, lines[i+1:]...)
	}
	return lines
}

// applyPanelStaticCache returns the vhost with one correct Cache-Control in
// each static location, and with the compression variant declared.
func applyPanelStaticCache(content string) string {
	lines := ensureGzipVary(strings.Split(content, "\n"))
	for _, location := range panelStaticCacheLocations {
		start, end, ok := blockBounds(lines, location.open)
		if !ok {
			continue
		}
		raw := lines[start+1 : end]
		body := rewriteCacheLines(raw, location.cacheControl, bodyIndent(raw))
		next := make([]string, 0, len(lines))
		next = append(next, lines[:start+1]...)
		next = append(next, body...)
		next = append(next, lines[end:]...)
		lines = next
	}
	return strings.Join(lines, "\n")
}

// healPanelStaticCacheOnStartup keeps the panel's static locations current.
//
// It carries no sentinel, for the reason healPanelIndexNoCacheOnStartup states:
// a sentinel answers "has this run before", and the question that matters is
// "is this block current". Rendering and comparing answers the second one and
// stays silent when there is nothing to do.
func healPanelStaticCacheOnStartup() {
	original, err := os.ReadFile(panelVhostPath)
	if err != nil {
		return
	}
	content := string(original)
	updated := applyPanelStaticCache(content)
	if updated == content {
		return
	}
	applyPanelVhostRepair(updated, original, panelVhostRepair{
		writeFailure: "could not update the static cache headers",
		step:         "static cache headers",
		success:      "the static cache headers were brought up to date + nginx reloaded",
	})
}
