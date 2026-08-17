package hostapps

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"servika/internal/config"
)

const unitDir = "/etc/systemd/system"

// UnitName is the systemd unit for a server-level application.
func UnitName(code string) string { return "servika-hostapp-" + code + ".service" }

// UnitPath is where that unit is written.
func UnitPath(code string) string { return filepath.Join(unitDir, UnitName(code)) }

// InstallDir is where an application's own files live.
func InstallDir(code string) string { return filepath.Join(config.HostAppRoot(), code) }

// DataDir is the one directory the service may write.
func DataDir(code string) string { return filepath.Join(InstallDir(code), "data") }

// EnvPath is the EnvironmentFile for an application.
func EnvPath(code string) string { return filepath.Join(config.HostAppEnvDir(), code+".env") }

// LogPath is where the application's output is appended.
func LogPath(code string) string { return filepath.Join(config.HostAppLogDir(), code+".log") }

// systemCommand runs a privileged tool without inheriting panel secrets.
func systemCommand(name string, arguments ...string) *exec.Cmd {
	return systemCommandContext(context.Background(), name, arguments...)
}

// systemCommandContext is the same with a deadline, used for the unpacking tools
// that work on an archive a remote server supplied.
func systemCommandContext(ctx context.Context, name string, arguments ...string) *exec.Cmd {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); every value is validated before exec.
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"LC_ALL=C",
	}
	return command
}

// RenderUnit builds the systemd unit for a server-level application.
//
// It is internal/apps/RenderUnit with three deliberate differences, and each one
// exists because this application belongs to the operator rather than to a
// tenant.
//
// There is no Slice=. A tenant application runs inside its customer's slice so
// the plan's MemoryMax and TasksMax reach it; there is no plan here, and putting
// the operator's own Gitea under a tenant's accounting would charge a customer
// for it.
//
// ReadWritePaths names the DATA directory only, so the unpacked program the
// service executes is read-only to the account running it. internal/apps has to
// read-write the whole home because a tenant's application and a tenant's files
// are the same tree; here they are two directories and the separation is free.
//
// What is IDENTICAL, and must stay identical, is the placement of the two
// StartLimit keys. systemd 257 answers `Unknown key 'StartLimitIntervalSec' in
// section [Service], ignoring.` while silently accepting StartLimitBurst there
// (measured with systemd-analyze verify), so a [Service] spelling leaves the
// burst counting against the default ten-second window; with RestartSec=5 only
// two starts fit it, the burst is never reached, and an application that cannot
// start restarts every five seconds for good instead of reaching failed, which
// is the one state the screen reads as broken.
func RenderUnit(entry Entry, systemUser string, execStart []string) string {
	var body strings.Builder
	fmt.Fprintf(&body, `[Unit]
Description=Servika server application %s (%s)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
User=%s
Group=%s
WorkingDirectory=%s
EnvironmentFile=%s
ExecStart=%s
Restart=always
RestartSec=5
StandardOutput=append:%s
StandardError=append:%s
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=%s
ProtectHome=yes
PrivateTmp=yes
ProtectProc=invisible
RestrictNamespaces=yes
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LimitCORE=0

[Install]
WantedBy=multi-user.target
`,
		entry.Code, entry.Name,
		systemUser, systemUser,
		InstallDir(entry.Code),
		EnvPath(entry.Code),
		strings.Join(execStart, " "),
		LogPath(entry.Code), LogPath(entry.Code),
		DataDir(entry.Code))
	return body.String()
}

// RenderEnvFile builds the EnvironmentFile body.
//
// The port variable comes LAST and is not settable from the form. The panel
// assigns the port and derives both the firewall rule and the screen's link from
// it, so an application listening somewhere else reads as down with nothing in
// its log to explain it.
//
// The variable's NAME comes from the catalog because the products disagree:
// Grafana reads GF_SERVER_HTTP_PORT and ignores PORT entirely (measured), which
// is exactly the failure above.
func RenderEnvFile(entry Entry, port int, values map[string]string) string {
	names := make([]string, 0, len(values))
	for name := range values {
		if name == entry.PortEnvName || !envNamePattern.MatchString(name) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	var body strings.Builder
	body.WriteString("# Managed automatically by Servika. DO NOT EDIT.\n")
	for _, name := range names {
		fmt.Fprintf(&body, "%s=%s\n", name, values[name])
	}
	if entry.TakesPort {
		fmt.Fprintf(&body, "%s=%d\n", entry.PortEnvName, port)
	}
	return body.String()
}

// WriteEnvFile installs the EnvironmentFile as root-only.
//
// The service's own account never opens this file by name: systemd parses
// EnvironmentFile= in the manager process, as root, and hands the resulting
// environment to the child. Environment= would instead publish every value
// through `systemctl show` to any local account, including the tenants.
func WriteEnvFile(entry Entry, port int, values map[string]string) error {
	// #nosec G301 -- root-owned system directory; the files inside carry the restrictive mode.
	if err := os.MkdirAll(config.HostAppEnvDir(), 0o755); err != nil {
		return fmt.Errorf("create the environment directory: %w", err)
	}
	path := EnvPath(entry.Code)
	body := RenderEnvFile(entry, port, values)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return fmt.Errorf("write the environment file: %w", err)
	}
	// A file that already existed keeps its old mode through WriteFile, so the
	// restriction is asserted rather than assumed.
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict the environment file: %w", err)
	}
	return nil
}

// EnsureLogFile creates the log as root-only before systemd opens it, so the
// append: target is never a name the service's own account could win a race for.
func EnsureLogFile(code string) error {
	// #nosec G301 -- root-owned log directory the panel serves back through its own endpoint.
	if err := os.MkdirAll(config.HostAppLogDir(), 0o750); err != nil {
		return fmt.Errorf("create the log directory: %w", err)
	}
	path := LogPath(code)
	// #nosec G304 -- a fixed path this package owns, named after a validated catalog code.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open the log: %w", err)
	}
	return file.Close()
}

// Status is what the panel can say about a running application.
type Status struct {
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
	Restarts    string `json:"restarts"`
	Installed   bool   `json:"installed"`
}

// UnitStatus reads systemd's view of one application.
func UnitStatus(code string) Status {
	status := Status{}
	if _, err := os.Stat(UnitPath(code)); err == nil {
		status.Installed = true
	}
	output, err := systemCommand("systemctl", "show",
		"-p", "ActiveState", "-p", "SubState", "-p", "NRestarts", UnitName(code)).Output()
	if err != nil {
		return status
	}
	for line := range strings.SplitSeq(string(output), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch key {
		case "ActiveState":
			status.ActiveState = strings.TrimSpace(value)
		case "SubState":
			status.SubState = strings.TrimSpace(value)
		case "NRestarts":
			status.Restarts = strings.TrimSpace(value)
		}
	}
	return status
}

// InstallUnit writes the unit file and reloads systemd.
func InstallUnit(code, body string) error {
	// #nosec G306 -- root-owned systemd unit that PID 1 must read; the secrets live in the EnvironmentFile beside it.
	if err := os.WriteFile(UnitPath(code), []byte(body), 0o644); err != nil {
		return fmt.Errorf("write the unit: %w", err)
	}
	if output, err := systemCommand("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("reload systemd: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

// Enable starts an application and makes it survive a reboot.
func Enable(code string) error {
	if output, err := systemCommand("systemctl", "enable", "--now", UnitName(code)).CombinedOutput(); err != nil {
		return fmt.Errorf("start the application: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

// Disable stops an application and keeps it stopped across a reboot.
//
// Stopping alone is not enough: the unit carries Restart=always, so a process
// killed by anything other than systemd comes straight back.
func Disable(code string) error {
	if output, err := systemCommand("systemctl", "disable", "--now", UnitName(code)).CombinedOutput(); err != nil {
		return fmt.Errorf("stop the application: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

// maxLogBytes bounds what a log poll pulls into memory.
const maxLogBytes = 60000

// LogTail returns the end of an application's log.
//
// The open is O_NOFOLLOW with a regular-file check on the DESCRIPTOR because the
// process writing this file runs as the application's own account: the panel
// owns the directory, but the file itself is filled by a program a third party
// wrote, and a link planted at that name would otherwise be read through.
func LogTail(code string) string {
	path := LogPath(code)
	// #nosec G304 -- a fixed path this package owns, named after a validated catalog code.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	offset := int64(0)
	if info.Size() > maxLogBytes {
		offset = info.Size() - maxLogBytes
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(file, maxLogBytes))
	if err != nil {
		return ""
	}
	return string(body)
}

// Restart restarts an application in place.
func Restart(code string) error {
	if output, err := systemCommand("systemctl", "restart", UnitName(code)).CombinedOutput(); err != nil {
		return fmt.Errorf("restart the application: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}
