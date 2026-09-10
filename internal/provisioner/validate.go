package provisioner

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const maxNginxValidationMessage = 4000

// ValidateNginxDirectives validates custom nginx directives entered at the plan or domain level
// without disrupting the live configuration:
//   - It embeds the directives in a temporary server{} block under /etc/nginx/conf.d.
//   - It runs `nginx -t`, which parses and validates the full configuration without opening sockets.
//   - It always removes the temporary file.
//
// For invalid input, it returns nginx's error output so the caller can display the error
// and reject the change. Empty input is valid.
//
// Validation runs in the server context because the directives are also injected into
// the server block of the actual domain vhost, matching per-domain extra_directives.
func ValidateNginxDirectives(directives string) error {
	d := strings.TrimSpace(directives)
	if d == "" {
		return nil
	}
	// The probe file lands in the tree `nginx -t` validates, so it both sees a
	// render in flight and is seen by one. See nginxlock.go.
	nginxMu.Lock()
	defer nginxMu.Unlock()

	tmp, err := os.CreateTemp("/etc/nginx/conf.d", "_planvalidate_*.conf.tmp")
	if err != nil {
		return fmt.Errorf("create temporary validation file: %w", err)
	}
	tmpPath := tmp.Name()
	// nginx reads only *.conf files, so the ".tmp" suffix excludes the file from validation.
	// Rename it to an actual ".conf" file before running the check.
	finalPath := strings.TrimSuffix(tmpPath, ".tmp")

	block := fmt.Sprintf(`# Temporary plan-directive validation, removed automatically
server {
    listen 127.0.0.1:65071;
    server_name _servika_plan_validate;
    root /var/www/_default80;
    # ---- validated directives ----
%s
}
`, indentLines(d, "    "))

	if _, err := tmp.WriteString(block); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temporary validation file: %w", err)
	}
	_ = tmp.Close()

	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("prepare temporary validation file: %w", err)
	}
	defer func() { _ = os.Remove(finalPath) }()

	out, err := exec.Command("nginx", "-t").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", sanitizeNginxValidationMessage(out, finalPath, "(directives)", err))
	}
	return nil
}

// ValidateCustomVhost validates a full raw nginx vhost before it is persisted and activated.
func ValidateCustomVhost(content string) error {
	c := strings.TrimSpace(content)
	if c == "" {
		return fmt.Errorf("custom vhost content cannot be empty")
	}
	// The probe file lands in the tree `nginx -t` validates, so it both sees a
	// render in flight and is seen by one. See nginxlock.go.
	nginxMu.Lock()
	defer nginxMu.Unlock()

	tmp, err := os.CreateTemp("/etc/nginx/conf.d", "_customvhost_validate_*.conf.tmp")
	if err != nil {
		return fmt.Errorf("temporary validation file could not be created")
	}
	tmpPath := tmp.Name()
	finalPath := strings.TrimSuffix(tmpPath, ".tmp")

	if _, err := tmp.WriteString(c + "\n"); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("temporary validation file could not be written")
	}
	_ = tmp.Close()

	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("temporary validation file could not be prepared")
	}
	defer func() { _ = os.Remove(finalPath) }()

	out, err := exec.Command("nginx", "-t").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", sanitizeNginxValidationMessage(out, finalPath, "(custom vhost)", err))
	}
	return nil
}

func sanitizeNginxValidationMessage(output []byte, path, label string, fallback error) string {
	message := strings.TrimSpace(string(output))
	message = strings.ReplaceAll(message, path, label)
	if message == "" && fallback != nil {
		message = fallback.Error()
	}
	if len(message) > maxNginxValidationMessage {
		message = message[:maxNginxValidationMessage] + "..."
	}
	return message
}

var forbiddenNginxDirectives = map[string]bool{
	"alias": true, "root": true,
	"proxy_pass": true, "fastcgi_pass": true, "uwsgi_pass": true, "scgi_pass": true,
	"grpc_pass": true, "memcached_pass": true,
	"include": true, "load_module": true,
	"ssl_certificate": true, "ssl_certificate_key": true, "ssl_trusted_certificate": true,
	"error_log": true, "access_log": true, "fastcgi_param": true,
	"auth_basic_user_file": true, "secure_link_secret": true,
	// The request-body ceiling is the PLAN's, rendered by the panel from
	// nginx_settings.client_max_body. A tenant stating one here would both bypass
	// a billed tier boundary and let nginx spool an oversized body into
	// client_body_temp_path, which is root-owned and outside the tenant's XFS
	// quota. An operator states the plan's value in the plan's own field.
	"client_max_body_size": true,
}

// DangerousNginxDirective returns the first forbidden custom directive name, or
// "" when none is present. It tokenizes with nginx semantics: inside a quoted
// string ("..." or '...') the characters #, ;, { and } are literal, so only
// unquoted '#' starts a comment and unquoted ;{} separate statements. That way
// `add_header X-Test "#"; alias /etc/;` splits into two statements and the
// alias is still caught, instead of being hidden inside a fake comment.
func DangerousNginxDirective(directives string) string {
	var current strings.Builder
	var quote byte // 0, '"' or '\''
	var statements []string
	flush := func() {
		if t := strings.TrimSpace(current.String()); t != "" {
			statements = append(statements, t)
		}
		current.Reset()
	}
	raw := []byte(directives)
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if quote != 0 {
			if c == '\\' && i+1 < len(raw) { // escape: keep the next byte verbatim
				current.WriteByte(c)
				current.WriteByte(raw[i+1])
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			current.WriteByte(c)
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
			current.WriteByte(c)
		case '#': // comment: skip to end of line
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
		case ';', '{', '}', '\n':
			flush()
		default:
			current.WriteByte(c)
		}
	}
	flush()

	for _, statement := range statements {
		fields := strings.Fields(statement)
		if len(fields) == 0 {
			continue
		}
		// Strip quotes from the directive name too (nginx rejects a quoted
		// directive name anyway, but the denylist must still see it): "alias" -> alias.
		name := strings.ToLower(strings.Trim(fields[0], `"'`))
		if forbiddenNginxDirectives[name] ||
			strings.Contains(name, "_by_lua") ||
			strings.HasPrefix(name, "lua_") ||
			strings.HasPrefix(name, "js_") ||
			strings.HasPrefix(name, "perl") {
			return name
		}
	}
	return ""
}

// indentLines adds a prefix to each non-empty line to keep the nginx block readable.
func indentLines(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}
