// Package apps manages long-running tenant applications: a Node.js or Python
// process supervised by systemd inside the tenant's own resource slice,
// listening on a loopback port and published by nginx under a path mount.
//
// Everything a customer types reaches a systemd unit file, so validation here is
// the boundary. A tenant with SSH already runs code as their own user, which is
// why the start command is free-form argv rather than an allowlist; what must
// not happen is a value escaping its field and becoming a DIFFERENT directive.
package apps

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"servika/internal/appruntime"
)

// App is one managed application.
type App struct {
	ID          int64  `json:"id"`
	DomainID    int64  `json:"domain_id"`
	SubdomainID int64  `json:"subdomain_id"` // 0 means the domain itself.
	Name        string `json:"name"`
	Runtime     string `json:"runtime"`
	Version     string `json:"runtime_version"`
	AppRoot     string `json:"app_root"` // home-relative
	Start       string `json:"start_command"`
	Mount       string `json:"mount_path"`
	Port        int    `json:"port"`
	Enabled     bool   `json:"enabled"`
}

// Port range. It sits BELOW the default ephemeral range
// (net.ipv4.ip_local_port_range = 32768 60999) so an outgoing connection can
// never take a port an application is meant to hold.
const (
	PortMin = 30000
	PortMax = 30999
)

var (
	reName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)
	reAppRoot = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	reMount   = regexp.MustCompile(`^/([A-Za-z0-9._~-]+/)*$`)
	reEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	reUser    = regexp.MustCompile(`^c_[A-Za-z0-9_]+$`)
)

const (
	maxArgvTokens = 32
	maxTokenLen   = 256
	maxEnvValue   = 4096
)

// ValidName reports whether a display name is acceptable.
func ValidName(name string) bool { return reName.MatchString(strings.TrimSpace(name)) }

// ValidSystemUser reports whether a value is a tenant login this package will act on.
func ValidSystemUser(systemUser string) bool { return reUser.MatchString(systemUser) }

// NormalizeMount canonicalizes a mount path to a leading and trailing slash and
// rejects anything nginx would read as more than one location prefix.
//
// The trailing slash matters: `location ^~ /api` also matches `/apixyz`, which
// would quietly capture a sibling path the tenant did not mean to hand over.
func NormalizeMount(mount string) (string, error) {
	mount = strings.TrimSpace(mount)
	if mount == "" {
		mount = "/"
	}
	if !strings.HasPrefix(mount, "/") {
		mount = "/" + mount
	}
	if !strings.HasSuffix(mount, "/") {
		mount += "/"
	}
	if strings.Contains(mount, "..") || strings.Contains(mount, "//") {
		return "", errors.New("invalid mount path")
	}
	if len(mount) > 128 || !reMount.MatchString(mount) {
		return "", errors.New("invalid mount path")
	}
	return mount, nil
}

// SafeAppDir resolves a home-relative application directory to an absolute path
// inside the tenant's home, refusing an escape through `..` or a symlink.
//
// Unlike the Laravel toolkit's own directory this is NOT restricted to
// public_html: a Node or Python application is served by proxy, so its source
// belongs outside the document root rather than inside it.
func SafeAppDir(systemUser, appRoot string) (string, error) {
	if !ValidSystemUser(systemUser) {
		return "", errors.New("invalid system user")
	}
	appRoot = strings.TrimSpace(appRoot)
	if strings.HasPrefix(appRoot, "/") {
		// The field is home-relative. Quietly stripping the slash would turn
		// "/etc/passwd" into "/home/<user>/etc/passwd", which is inside the
		// home but is not what the author asked for.
		return "", errors.New("application directory must be relative to the home directory")
	}
	rel := strings.Trim(appRoot, "/")
	if rel == "" {
		return "", errors.New("application directory is required")
	}
	if len(rel) > 255 || strings.Contains(rel, "..") || !reAppRoot.MatchString(rel) {
		return "", errors.New("invalid application directory")
	}
	home := filepath.Join(tenantHomeRoot, systemUser)
	abs := filepath.Clean(filepath.Join(home, rel))
	if abs != home && !strings.HasPrefix(abs, home+"/") {
		return "", errors.New("application directory cannot leave the home directory")
	}
	if err := refuseSymlinkEscape(home, abs); err != nil {
		return "", err
	}
	return abs, nil
}

// ParseStartCommand splits a start command into argv and refuses any token that
// would not survive a systemd unit file intact.
//
// Splitting is on whitespace only. Quoting is REJECTED rather than interpreted,
// because a shell-looking quote that silently became two arguments would be a
// worse answer than saying the field does not take quotes.
func ParseStartCommand(command string) ([]string, error) {
	// Checked on the RAW string, before splitting. strings.Fields treats a
	// newline as ordinary whitespace, so a pasted second line would survive as
	// extra arguments that no single token ever carries and no per-token check
	// could see: the author would get a command they did not write.
	if strings.ContainsAny(command, "\r\n\x00") {
		return nil, errors.New("start command must be a single line")
	}
	command = strings.TrimSpace(command)
	if command == "" {
		return nil, errors.New("start command is required")
	}
	argv := strings.Fields(command)
	if len(argv) == 0 {
		return nil, errors.New("start command is required")
	}
	if len(argv) > maxArgvTokens {
		return nil, fmt.Errorf("start command may hold at most %d arguments", maxArgvTokens)
	}
	for _, token := range argv {
		if err := validToken(token); err != nil {
			return nil, err
		}
	}
	return argv, nil
}

// validToken refuses what must never reach an ExecStart line.
func validToken(token string) error {
	if len(token) > maxTokenLen {
		return errors.New("an argument is too long")
	}
	for _, r := range token {
		switch {
		case r < 0x20 || r == 0x7f:
			// A newline ends the directive and starts another one; every other
			// control character has no business in an argument either.
			return errors.New("an argument holds a control character")
		case r == '%':
			// systemd expands %i, %n, %h and friends inside ExecStart.
			return errors.New("an argument holds '%', which systemd expands")
		case r == '"' || r == '\'' || r == '\\':
			// systemd applies its own quoting rules to ExecStart, so a quote
			// would change the split rather than group what the author meant.
			return errors.New("an argument holds a quote or backslash, which this field does not support")
		}
	}
	return nil
}

// ValidEnvName reports whether a name can be a shell-style environment variable.
func ValidEnvName(name string) bool { return reEnvName.MatchString(name) }

// ValidEnvValue reports whether a value survives an EnvironmentFile line.
//
// systemd reads that file line by line, so a newline inside a value would define
// a SECOND variable the customer never asked for and the panel never recorded.
func ValidEnvValue(value string) bool {
	if len(value) > maxEnvValue {
		return false
	}
	return !strings.ContainsAny(value, "\r\n\x00")
}

// ReservedEnvNames are set by the panel itself. Letting a customer override PORT
// would point the application away from the port nginx proxies to, which reads
// as "the application is down" with nothing in the log to say why.
var ReservedEnvNames = map[string]bool{"PORT": true, "HOST": true}

// portFree reports whether nothing currently listens on a loopback port. The
// UNIQUE constraint on apps.port is the real authority; this only avoids
// choosing a port some other daemon already sits on.
var portFree = func(port int) bool {
	listener, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}

// ErrNoFreePort is returned when the whole range is taken.
var ErrNoFreePort = errors.New("no free application port is available")

// AllocatePort inserts the application with the first usable port.
//
// The candidate is chosen and then INSERTED; a duplicate key sends the loop to
// the next one. Checking first and inserting after would let two creations
// arriving together agree on the same port.
func AllocatePort(ctx context.Context, db *sql.DB, insert func(ctx context.Context, port int) error) (int, error) {
	// Start after the highest port in use so a normal create takes one attempt
	// instead of walking every port a long-lived host has already handed out.
	var highest sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(port) FROM apps`).Scan(&highest); err != nil {
		return 0, err
	}
	start := PortMin
	if highest.Valid && int(highest.Int64) >= PortMin && int(highest.Int64) < PortMax {
		start = int(highest.Int64) + 1
	}
	total := PortMax - PortMin + 1
	for offset := range total {
		port := PortMin + (start-PortMin+offset)%total
		if !portFree(port) {
			continue
		}
		err := insert(ctx, port)
		if err == nil {
			return port, nil
		}
		if !isDuplicateKey(err) {
			return 0, err
		}
	}
	return 0, ErrNoFreePort
}

// isDuplicateKey reports whether an insert failed on a UNIQUE constraint.
//
// The driver's error is matched on text because the panel does not import the
// MySQL error package anywhere else, and a false negative here is safe: it
// surfaces as a failed create rather than as two applications on one port.
func isDuplicateKey(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "Error 1062") || strings.Contains(message, "Duplicate entry")
}

// ResolveRuntime returns the interpreter for an application, or an error naming
// what is missing.
func ResolveRuntime(runtime, version string) (string, error) {
	if !appruntime.ValidKind(runtime) {
		return "", errors.New("runtime must be node or python")
	}
	path, ok := resolveRuntimePath(appruntime.Kind(runtime), version)
	if !ok {
		return "", fmt.Errorf("%s %s is not installed on this server", runtime, displayVersion(version))
	}
	return path, nil
}

func displayVersion(version string) string {
	if strings.TrimSpace(version) == "" {
		return appruntime.SystemVersion
	}
	return version
}
