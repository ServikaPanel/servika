package optimize

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Measure reads the two facts every proposal is computed from.
//
// A read that fails leaves the field at zero, and Compute refuses to propose
// anything from zeroed facts. That is deliberate: a buffer pool computed from
// an unread memory figure would propose 128M on a 64 GB server, and the
// operator has no way to tell that number apart from a considered one.
func Measure() Facts {
	facts := Facts{CPUs: runtime.NumCPU()}
	if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		facts.MemoryMB = parseMemTotalMB(string(raw))
	}
	return facts
}

// parseMemTotalMB reads MemTotal out of /proc/meminfo, which reports kilobytes.
func parseMemTotalMB(text string) int {
	for line := range strings.SplitSeq(text, "\n") {
		rest, found := strings.CutPrefix(line, "MemTotal:")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0
		}
		kilobytes, err := strconv.Atoi(fields[0])
		if err != nil || kilobytes <= 0 {
			return 0
		}
		return kilobytes / 1024
	}
	return 0
}

// Current reads what the host has now for every parameter in specs, keyed the
// same way a Proposal is.
//
// A parameter this cannot read is simply ABSENT from the map rather than
// present and empty, and Compute reads an absent key as "not set", which it
// offers. That is the right direction for a fresh host. It is the wrong
// direction for a host whose file could not be read at all, so every read
// failure is returned to the caller instead of being swallowed; the caller
// decides whether a partial reading is worth showing.
func Current(ctx context.Context, db *sql.DB) (map[string]string, []error) {
	values := map[string]string{}
	var problems []error

	if db != nil {
		mariadb, err := readMariaDBValues(ctx, db)
		if err != nil {
			problems = append(problems, fmt.Errorf("mariadb variables: %w", err))
		}
		for name, value := range mariadb {
			values[ServiceMariaDB+":"+name] = value
		}
	}

	if text, err := os.ReadFile(nginxPath); err != nil {
		problems = append(problems, fmt.Errorf("read %s: %w", nginxPath, err))
	} else if value := parseNginxDirective(string(text), "worker_connections"); value != "" {
		values[ServiceNginx+":worker_connections"] = value
	}

	if text, err := os.ReadFile(fpmPoolPath); err != nil {
		problems = append(problems, fmt.Errorf("read %s: %w", fpmPoolPath, err))
	} else {
		for name, value := range parseFPMPool(string(text)) {
			values[ServicePHPFPM+":"+name] = value
		}
	}

	for _, item := range specs {
		if item.service != ServiceSysctl {
			continue
		}
		path, err := procSysPath(item.param)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		raw, err := os.ReadFile(path) // #nosec G304 -- path is derived from the compile-time specs table through procSysPath, which refuses anything that is not a dotted sysctl name.
		if err != nil {
			problems = append(problems, fmt.Errorf("read %s: %w", path, err))
			continue
		}
		values[ServiceSysctl+":"+item.param] = strings.TrimSpace(string(raw))
	}

	return values, problems
}

// mariadbParams returns the MariaDB parameters specs asks about.
func mariadbParams() []string {
	var names []string
	for _, item := range specs {
		if item.service == ServiceMariaDB {
			names = append(names, item.param)
		}
	}
	return names
}

// readMariaDBValues asks the running server, not the configuration files.
//
// The files are only half the answer: a value set with SET GLOBAL is live and
// absent from every file, and a value in a file the server rejected at startup
// is in the file and not live. What the screen must compare against is what the
// server is actually running on.
//
// GLOBAL_VALUE is reported in BYTES for the size parameters (measured on
// 10.11), which is why sameValue compares numerically rather than as text.
func readMariaDBValues(ctx context.Context, db *sql.DB) (map[string]string, error) {
	names := mariadbParams()
	if len(names) == 0 {
		return nil, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(names)), ",")
	args := make([]any, 0, len(names))
	for _, name := range names {
		args = append(args, name)
	}
	// #nosec G202 -- the interpolated fragment is only a "?,?,?" placeholder run
	// sized from the compile-time specs table; every value is bound.
	query := `SELECT LOWER(VARIABLE_NAME), GLOBAL_VALUE
	          FROM information_schema.SYSTEM_VARIABLES
	          WHERE VARIABLE_NAME IN (` + placeholders + `)`
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	values := map[string]string{}
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			return nil, err
		}
		values[name] = strings.TrimSpace(value)
	}
	return values, rows.Err()
}

// procSysPath maps a sysctl name onto its /proc/sys path.
//
// It refuses anything that is not a dotted lowercase name, because the result
// is opened. Nothing in specs can fail that test today; the check is here so
// that a parameter added later cannot turn a table entry into a path traversal.
func procSysPath(param string) (string, error) {
	if param == "" {
		return "", fmt.Errorf("empty sysctl name")
	}
	for _, r := range param {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return "", fmt.Errorf("sysctl name %q carries %q", param, r)
		}
	}
	if strings.Contains(param, "..") {
		return "", fmt.Errorf("sysctl name %q is not a name", param)
	}
	return filepath.Join("/proc/sys", strings.ReplaceAll(param, ".", "/")), nil
}

// parseNginxDirective returns the value of a simple one-argument directive.
//
// The LAST occurrence wins, which is what nginx itself does within one context,
// and a commented line is skipped. This reads nginx.conf rather than "nginx -T"
// because the question is what the FILE says, which is what an edit has to
// agree with; a value that came from an include would be reported by -T and
// then not be there to change.
func parseNginxDirective(text, directive string) string {
	value := ""
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rest, found := strings.CutPrefix(line, directive)
		if !found || rest == "" {
			continue
		}
		// The directive name must be followed by whitespace, or
		// "worker_connections" would also match "worker_connections_extra".
		if !isSpace(rest[0]) {
			continue
		}
		rest = strings.TrimSpace(rest)
		rest = strings.TrimSuffix(rest, ";")
		if fields := strings.Fields(rest); len(fields) > 0 {
			value = fields[0]
		}
	}
	return value
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' }

// parseFPMPool reads the pm.* settings out of a php-fpm pool file.
//
// php-fpm comments with ";" and not "#", and a commented default like
// ";pm.max_children = 5" appears in every stock pool. Reading one as a live
// value would tell the operator the pool is set to a number it is not.
func parseFPMPool(text string) map[string]string {
	values := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		name = strings.TrimSpace(name)
		if !strings.HasPrefix(name, "pm.") {
			continue
		}
		values[name] = strings.TrimSpace(value)
	}
	return values
}

// readFileIfPresent returns a file's text, or empty text when it is absent.
func readFileIfPresent(path string) (string, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path comes from an optimize_backups row this package wrote from the compile-time specs table.
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// backupExists reports whether a recorded backup copy is still on disk. An
// empty path means the file did not exist before the apply, which is a state a
// revert can put back by deleting it.
func backupExists(path string) bool {
	if path == "" {
		return true
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// parseDropIn reads "name = value" out of one of the panel's own drop-ins. It
// serves both the MariaDB form (which has a [mysqld] section line) and the
// sysctl form (which has none), because the only difference is a line this
// skips either way.
func parseDropIn(text string) map[string]string {
	values := map[string]string{}
	for line := range strings.SplitSeq(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "[") {
			continue
		}
		name, value, found := strings.Cut(trimmed, "=")
		if !found {
			continue
		}
		values[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}
	return values
}
