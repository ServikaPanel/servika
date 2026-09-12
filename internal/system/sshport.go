package system

import (
	"context"
	"net/http"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"servika/internal/httpx"
)

// SSH port detection, read from what sshd EFFECTIVELY serves rather than from
// sshd_config.
//
// The source is `sshd -T`. Parsing the main configuration file by hand is wrong
// on a modern installation: the port often lives in an include under
// /etc/ssh/sshd_config.d/ (the AlmaLinux 10 default) and the main file carries no
// Port line at all. `sshd -T` resolves every include and prints the effective
// configuration.

const (
	// DefaultSSHPort is the port almost all automated scanning and brute-force
	// traffic on the internet aims at, so the panel warns while it is in use.
	DefaultSSHPort = 22

	sshPortCacheTTL  = 60 * time.Second
	sshdQueryTimeout = 5 * time.Second
)

var (
	sshPortMu       sync.Mutex
	sshPortCache    []int
	sshPortCachedAt time.Time

	// portDirectivePattern reads the `port <n>` lines out of `sshd -T` output,
	// which is lowercase and unindented. The separators are [ \t] rather than \s
	// because \s also matches a newline in multiline mode, which would let the
	// pattern join a bare `port` line to a number on the next line.
	portDirectivePattern = regexp.MustCompile(`(?mi)^port[ \t]+(\d{1,5})[ \t]*$`)

	// listenPortPattern reads the local port out of an `ss -lntp` row.
	listenPortPattern = regexp.MustCompile(`:(\d{1,5})\s`)
)

// SSHPorts returns the ports sshd listens on, ascending and without repeats.
// When detection fails it returns the default port: showing the warning while the
// answer is unknown is better than quietly reporting the server as hardened.
//
// The result is cached for a minute because the per-domain SSH screen calls this
// too. Only a successful detection is cached, so a transient failure does not
// pin the fallback for the whole minute.
func SSHPorts() []int {
	sshPortMu.Lock()
	defer sshPortMu.Unlock()
	if sshPortCache != nil && time.Since(sshPortCachedAt) < sshPortCacheTTL {
		return sshPortCache
	}

	ports := sshdEffectivePorts()
	if len(ports) == 0 {
		ports = listeningSSHPorts() // sshd -T unavailable, so look at what is bound
	}
	if len(ports) == 0 {
		return []int{DefaultSSHPort}
	}
	sshPortCache, sshPortCachedAt = ports, time.Now()
	return ports
}

// sshdCommand builds a detection subprocess. The context comes from
// context.Background() rather than the request: a customer-facing screen calls
// this, and a client disconnecting mid-detection must not cancel a probe whose
// answer is about to be cached. The environment is an explicit allowlist so no
// panel secret is handed to the subprocess.
func sshdCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sshdQueryTimeout)
	defer cancel()
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"}
	return cmd.Output()
}

func sshdEffectivePorts() []int {
	out, err := sshdCommand("sshd", "-T")
	if err != nil {
		// sshd is not on PATH on every distribution.
		out, err = sshdCommand("/usr/sbin/sshd", "-T")
		if err != nil {
			return nil
		}
	}
	var ports []int
	for _, match := range portDirectivePattern.FindAllStringSubmatch(string(out), -1) {
		if port, convErr := strconv.Atoi(match[1]); convErr == nil && port > 0 && port < 65536 {
			ports = append(ports, port)
		}
	}
	return uniqueSorted(ports)
}

func listeningSSHPorts() []int {
	out, err := sshdCommand("ss", "-lntp")
	if err != nil {
		return nil
	}
	var ports []int
	for line := range strings.SplitSeq(string(out), "\n") {
		if !strings.Contains(line, "sshd") {
			continue
		}
		if match := listenPortPattern.FindStringSubmatch(line); match != nil {
			if port, convErr := strconv.Atoi(match[1]); convErr == nil {
				ports = append(ports, port)
			}
		}
	}
	return uniqueSorted(ports)
}

func uniqueSorted(in []int) []int {
	if len(in) == 0 {
		return nil
	}
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

// FirstSSHPort returns the port to show a customer as their SSH endpoint.
func FirstSSHPort() int {
	if ports := SSHPorts(); len(ports) > 0 {
		return ports[0]
	}
	return DefaultSSHPort
}

// SSHSecurityStatus backs the warning the panel shows while SSH is on port 22.
type SSHSecurityStatus struct {
	Ports        []int `json:"ports"`
	DefaultPort  bool  `json:"default_port"` // true means the warning is shown
	DefaultValue int   `json:"default_value"`
}

// SSHSecurity serves GET /system/ssh-security (admin only).
func SSHSecurity(w http.ResponseWriter, _ *http.Request) {
	ports := SSHPorts()
	httpx.WriteJSON(w, http.StatusOK, SSHSecurityStatus{
		Ports:        ports,
		DefaultPort:  slices.Contains(ports, DefaultSSHPort),
		DefaultValue: DefaultSSHPort,
	})
}
