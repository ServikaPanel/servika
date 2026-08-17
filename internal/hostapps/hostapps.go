// Package hostapps runs applications that belong to the SERVER rather than to a
// tenant: Gitea, Grafana, a MinIO bucket store. internal/apps runs a customer's
// application in the customer's home, in the customer's slice, published
// through the customer's vhost. There is no customer here.
//
// The design is derived from internal/apps and keeps every rule that package
// learned: the two StartLimit keys live in [Unit], the environment goes in an
// EnvironmentFile rather than Environment=, the log lives in a root-owned
// directory, and ExecStart is argv that never passes through a shell. What
// changes is in this file's comments, and each change exists because the
// application is the operator's rather than a customer's.
package hostapps

import (
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"
)

// The port range these applications are assigned from.
//
// It is SEPARATE from the tenant range (30000-30999) and sits below the default
// ephemeral range (net.ipv4.ip_local_port_range = 32768 60999), so an outgoing
// connection can never take a port an application holds. The separation matters
// because the firewall treats the two ranges differently: every tenant port is
// dropped unconditionally, while a host port can be opened deliberately.
const (
	PortMin = 31000
	PortMax = 31999
)

// userPrefix names the Linux account an application runs as.
//
// It is NOT the tenant "c_" prefix. Every place in this panel that enumerates
// tenants keys on that prefix (credentials.ValidCustomerDBIdentifier is the
// enforcing one), and a host application appearing in those lists would be
// offered a database, a quota, a backup schedule and a vhost, none of which it
// has.
const userPrefix = "svk_"

// Refusal reasons, carried beside the English message because the screen
// renders twelve languages.
const (
	ReasonUnknownApp    = "host_app_unknown"
	ReasonDisabled      = "host_app_disabled"
	ReasonNoBuild       = "host_app_no_build_for_architecture"
	ReasonNoChecksum    = "host_app_no_checksum"
	ReasonChecksum      = "host_app_checksum_mismatch"
	ReasonAlready       = "host_app_already_installed"
	ReasonNoPort        = "host_app_no_free_port"
	ReasonBadArgs       = "host_app_bad_start_command"
	ReasonBadEntry      = "host_app_invalid_catalog_entry"
	ReasonNotFound      = "host_app_not_found"
	ReasonBusy          = "host_app_busy"
	ReasonDownload      = "host_app_download_failed"
	ReasonUnpack        = "host_app_unpack_failed"
	ReasonBinaryMissing = "host_app_binary_missing"
	ReasonPortTaken     = "host_app_port_taken"
	ReasonFeatureOff    = "host_apps_switched_off"
)

// Refusal carries a reason code beside the message.
type Refusal struct {
	Reason  string
	Message string
}

func (r *Refusal) Error() string { return r.Message }

func refuse(reason, format string, args ...any) error {
	return &Refusal{Reason: reason, Message: fmt.Sprintf(format, args...)}
}

// ReasonOf returns the stable reason code of a refusal, or "" for anything else.
func ReasonOf(err error) string {
	var refusal *Refusal
	if errors.As(err, &refusal) {
		return refusal.Reason
	}
	return ""
}

// Entry is one catalog row.
type Entry struct {
	Code            string `json:"code"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	URLAMD64        string `json:"url_amd64,omitempty"`
	SHA256AMD64     string `json:"sha256_amd64,omitempty"`
	URLARM64        string `json:"url_arm64,omitempty"`
	SHA256ARM64     string `json:"sha256_arm64,omitempty"`
	ArchiveKind     string `json:"archive_kind"`
	StripComponents int    `json:"strip_components"`
	BinaryPath      string `json:"binary_path"`
	StartArgs       string `json:"start_args"`
	PortEnvName     string `json:"port_env_name"`
	TakesPort       bool   `json:"takes_port"`
	DefaultPort     int    `json:"default_port"`
	NeedsDataDir    bool   `json:"needs_data_dir"`
	Enabled         bool   `json:"enabled"`
}

var (
	codePattern    = regexp.MustCompile(`^[a-z][a-z0-9]{1,31}$`)
	sha256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	envNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
)

// archiveKinds are the shapes the unpacker understands.
var archiveKinds = map[string]bool{
	"binary": true, "tar.gz": true, "tar.xz": true, "tar.bz2": true, "zip": true,
}

// ValidEntry checks a catalog row and names the field that is wrong.
//
// It runs on the ADMIN write path and again on the install path. The second
// check is not redundant: the row can be edited between the two, and everything
// in it reaches either a URL, a file path or a systemd unit.
func ValidEntry(entry Entry) (string, error) {
	switch {
	case !codePattern.MatchString(entry.Code):
		return "code", refuse(ReasonBadEntry, "the code must be 2 to 32 lowercase letters and digits")
	case strings.TrimSpace(entry.Name) == "" || len(entry.Name) > 64:
		return "name", refuse(ReasonBadEntry, "the name is required and may be at most 64 characters")
	case strings.TrimSpace(entry.Version) == "" || len(entry.Version) > 64:
		return "version", refuse(ReasonBadEntry, "the version is required")
	case !archiveKinds[entry.ArchiveKind]:
		return "archive_kind", refuse(ReasonBadEntry, "%q is not an archive kind this understands", entry.ArchiveKind)
	case entry.StripComponents < 0 || entry.StripComponents > 4:
		return "strip_components", refuse(ReasonBadEntry, "the strip level must be between 0 and 4")
	case !validRelPath(entry.BinaryPath):
		return "binary_path", refuse(ReasonBadEntry, "the binary path must be a relative path inside the archive")
	case !envNamePattern.MatchString(entry.PortEnvName):
		return "port_env_name", refuse(ReasonBadEntry, "the port variable must be an uppercase environment name")
	case entry.DefaultPort < 0 || entry.DefaultPort > 65535:
		return "default_port", refuse(ReasonBadEntry, "the default port is not a port number")
	}
	for field, url := range map[string]string{"url_amd64": entry.URLAMD64, "url_arm64": entry.URLARM64} {
		if url != "" && !strings.HasPrefix(url, "https://") {
			return field, refuse(ReasonBadEntry, "a download URL must start with https://")
		}
	}
	for field, digest := range map[string]string{"sha256_amd64": entry.SHA256AMD64, "sha256_arm64": entry.SHA256ARM64} {
		if digest != "" && !sha256Pattern.MatchString(digest) {
			return field, refuse(ReasonBadEntry, "a checksum must be 64 lowercase hex characters")
		}
	}
	if entry.URLAMD64 == "" && entry.URLARM64 == "" {
		return "url_amd64", refuse(ReasonBadEntry, "at least one architecture needs a download URL")
	}
	if _, err := BuildArgv(entry, "/tmp/x", 31000); err != nil {
		return "start_args", err
	}
	return "", nil
}

// validRelPath accepts a path inside the unpacked tree and nothing else. The
// value is joined onto a directory the panel created and then made executable,
// so an absolute path or a "..' would reach outside it.
func validRelPath(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || len(value) > 255 {
		return false
	}
	if strings.Contains(value, "..") {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '/', r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// Download picks the URL and digest for the architecture this panel is running
// on, and REFUSES when the project publishes no build for it.
//
// This is not a theoretical case. TeamSpeak ships no arm64 Linux server at all
// (measured: the arm64 URL answers 404), so on an arm64 host the honest answer
// is that the application cannot be installed, said before anything is
// downloaded rather than as a failure halfway through.
func Download(entry Entry) (url, digest string, err error) {
	switch runtime.GOARCH {
	case "amd64":
		url, digest = entry.URLAMD64, entry.SHA256AMD64
	case "arm64":
		url, digest = entry.URLARM64, entry.SHA256ARM64
	default:
		return "", "", refuse(ReasonNoBuild, "this panel is running on %s, which the catalog does not cover", runtime.GOARCH)
	}
	if url == "" {
		return "", "", refuse(ReasonNoBuild, "%s publishes no %s build", entry.Name, runtime.GOARCH)
	}
	// A missing checksum is refused at INSTALL time rather than at catalog
	// time, so an operator can save a half-filled row and finish it later. What
	// must never happen is an install that ran without one, because the archive
	// becomes a program this server executes as a dedicated account.
	if !sha256Pattern.MatchString(digest) {
		return "", "", refuse(ReasonNoChecksum, "%s has no checksum for %s, so it cannot be verified", entry.Name, runtime.GOARCH)
	}
	return url, digest, nil
}

// SystemUser is the Linux account an application runs as.
func SystemUser(code string) string { return userPrefix + code }

// ValidSystemUser reports whether a name is one this package hands out. It is
// the gate on every removal, because removing an application removes a home
// directory and a Linux account by name.
func ValidSystemUser(name string) bool {
	rest, found := strings.CutPrefix(name, userPrefix)
	return found && codePattern.MatchString(rest)
}

// BuildArgv turns a catalog row into the argv of an ExecStart line.
//
// The rules are internal/apps's, for the same reasons and with one addition.
// The raw string is checked for \r, \n and \0 BEFORE it is split, because
// strings.Fields treats a newline as whitespace and a per-token check can never
// see one; a token carrying % is refused because systemd would expand it as a
// specifier; and the first word is always the absolute path the panel resolved,
// never text from the row.
//
// The addition is that {data} and {port} are substituted first, so a row can
// name the data directory the panel chose without the panel having to
// understand the product's own flag syntax.
func BuildArgv(entry Entry, dataDir string, port int) ([]string, error) {
	raw := entry.StartArgs
	if strings.ContainsAny(raw, "\r\n\x00") {
		return nil, refuse(ReasonBadArgs, "the start arguments carry a line break")
	}
	raw = strings.ReplaceAll(raw, "{data}", dataDir)
	raw = strings.ReplaceAll(raw, "{port}", fmt.Sprintf("%d", port))

	fields := strings.Fields(raw)
	for _, token := range fields {
		if strings.Contains(token, "%") {
			return nil, refuse(ReasonBadArgs, "systemd would read %q as a specifier", token)
		}
	}
	return fields, nil
}

// NextPort picks a free port from this package's own range.
//
// taken carries every port already assigned. The search starts after the
// highest one in use rather than at the bottom, so a port freed by a removal is
// not handed straight to the next application: a browser tab or a bookmark
// still pointing at the old one would land on something else entirely.
func NextPort(taken map[int]bool, highest int) (int, error) {
	start := PortMin
	if highest >= PortMin && highest < PortMax {
		start = highest + 1
	}
	total := PortMax - PortMin + 1
	for offset := range total {
		port := PortMin + (start-PortMin+offset)%total
		if !taken[port] {
			return port, nil
		}
	}
	return 0, refuse(ReasonNoPort, "every port between %d and %d is in use", PortMin, PortMax)
}

// InRange reports whether a port belongs to this package.
func InRange(port int) bool { return port >= PortMin && port <= PortMax }
