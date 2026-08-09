package apps

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"servika/internal/config"
)

const unitDir = "/etc/systemd/system"

// UnitName is the systemd unit for an application.
func UnitName(id int64) string { return "servika-app-" + strconv.FormatInt(id, 10) + ".service" }

// UnitPath is where that unit is written.
func UnitPath(id int64) string { return filepath.Join(unitDir, UnitName(id)) }

// EnvPath is the EnvironmentFile for an application.
func EnvPath(id int64) string {
	return filepath.Join(config.AppEnvDir(), strconv.FormatInt(id, 10)+".env")
}

// LogPath is where the application's output is appended.
//
// It is under a ROOT-owned directory rather than the tenant's home because
// systemd opens an append: target with O_APPEND|O_CREAT and follows a symlink: a
// tenant able to write the directory would redirect a root-opened descriptor.
func LogPath(id int64) string {
	return filepath.Join(config.AppLogDir(), strconv.FormatInt(id, 10)+".log")
}

// systemCommand runs a privileged tool without inheriting panel secrets.
func systemCommand(name string, arguments ...string) *exec.Cmd {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); every value is validated before exec.
	command := exec.Command(name, arguments...)
	command.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"LC_ALL=C",
	}
	return command
}

// RenderUnit builds the systemd unit for an application.
//
// execStart comes from ResolveExec: its first element is an absolute path this
// package found on disk and the rest passed ParseStartCommand, so nothing here
// can introduce a second directive.
//
// The environment is NOT written into this file. Any local user reads
// `systemctl show <unit>` and gets every Environment= value back, and an
// application's environment carries its database password.
//
// The two StartLimit keys belong to [Unit] and NOWHERE else. systemd 257 on
// AlmaLinux 10 answers `Unknown key 'StartLimitIntervalSec' in section
// [Service], ignoring.` while silently accepting StartLimitBurst there
// (measured with systemd-analyze verify), so putting them in [Service] leaves
// the burst against the DEFAULT ten-second interval. With RestartSec=5 only two
// starts fit that window, the burst is never reached, and an application that
// cannot start restarts every five seconds for good instead of landing in
// failed where the panel would show it.
func RenderUnit(app App, systemUser, appDir string, execStart []string) string {
	var body strings.Builder
	fmt.Fprintf(&body, `[Unit]
Description=Servika application %d (%s)
After=network.target mariadb.service
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
User=%s
Group=%s
WorkingDirectory=%s
Slice=servika-%s.slice
EnvironmentFile=%s
ExecStart=%s
Restart=always
RestartSec=5
StandardOutput=append:%s
StandardError=append:%s
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/home/%s
ProtectHome=tmpfs
BindPaths=/home/%s
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
		app.ID, app.Name,
		systemUser, systemUser,
		appDir,
		systemUser,
		EnvPath(app.ID),
		strings.Join(execStart, " "),
		LogPath(app.ID), LogPath(app.ID),
		systemUser, systemUser)
	return body.String()
}

// RenderEnvFile builds the EnvironmentFile body.
//
// PORT and HOST come last and are not customer-settable: they are the contract
// nginx proxies against, and an application listening somewhere else reads as
// down with nothing in the log to explain it.
func RenderEnvFile(app App, values map[string]string) string {
	names := make([]string, 0, len(values))
	for name := range values {
		if ReservedEnvNames[name] {
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
	fmt.Fprintf(&body, "PORT=%d\n", app.Port)
	body.WriteString("HOST=127.0.0.1\n")
	return body.String()
}

// WriteEnvFile installs the EnvironmentFile as root-only.
//
// The service's own user never opens this file by name: systemd parses
// EnvironmentFile= in the manager process, as root, and hands the resulting
// environment to the child. So the tenant needs no access to it at all, and the
// file carrying every application secret stays 0600 root:root.
func WriteEnvFile(app App, values map[string]string) error {
	// #nosec G301 -- root-owned system directory; the files inside carry the restrictive mode.
	if err := os.MkdirAll(config.AppEnvDir(), 0o755); err != nil {
		return fmt.Errorf("create the environment directory: %w", err)
	}
	path := EnvPath(app.ID)
	if err := os.WriteFile(path, []byte(RenderEnvFile(app, values)), 0o600); err != nil {
		return fmt.Errorf("write the environment file: %w", err)
	}
	// A file that already existed keeps its old mode through WriteFile, so the
	// restriction is asserted rather than assumed.
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict the environment file: %w", err)
	}
	return nil
}

// EnsureLogFile creates the application log as root-only before systemd opens
// it, so the append: target is never a name a tenant could win a race for.
//
// The tenant's process writes to it through a descriptor systemd opened and
// passed down, never by opening the path, so it needs no permission here either.
func EnsureLogFile(id int64) error {
	// #nosec G301 -- root-owned log directory the panel serves back through its own endpoint.
	if err := os.MkdirAll(config.AppLogDir(), 0o750); err != nil {
		return fmt.Errorf("create the log directory: %w", err)
	}
	path := LogPath(id)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- a fixed path this package owns, named after a row id.
	if err != nil {
		return fmt.Errorf("open the log: %w", err)
	}
	return file.Close()
}
