package panelport

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func complain(format string, args ...any) {
	// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
	log.Printf("panel port: "+format, args...)
}

// verifyDeadline bounds how long a change waits for the panel to answer on its
// new port before it is treated as failed.
//
// systemd's own restart of this service takes a second or two and the panel
// then runs migrations and a chain of host heals before it listens, so a short
// deadline would roll back a change that was about to work. A long one leaves
// an operator staring at a screen; 90 seconds is the compromise, and the screen
// says what it is waiting for.
const verifyDeadline = 90 * time.Second

// probeInterval is how often the port is tried while waiting.
const probeInterval = 2 * time.Second

// Reachable reports whether something is accepting connections on a port.
//
// This is a TCP connect and deliberately not an HTTP request. What the rollback
// has to know is whether the panel is answering at all; an HTTP check would
// also fail on a certificate the panel cannot help (the panel port is served
// over TLS by nginx with whatever certificate the operator installed), and
// rolling back a working panel because its certificate expired would be the
// worst possible reading of the situation.
func Reachable(ctx context.Context, host string, port int) bool {
	if host == "" || host == "::" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	host = strings.Trim(host, "[]")
	address := net.JoinHostPort(host, strconv.Itoa(port))

	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// WaitReachable polls until the port answers or the deadline passes.
func WaitReachable(ctx context.Context, host string, port int, deadline time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	for {
		if Reachable(ctx, host, port) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(probeInterval):
		}
	}
}

// plan is the set of edits one port change makes, computed before anything is
// written so a refusal costs nothing.
type plan struct {
	kind    string
	oldPort int
	newPort int
	host    string
	// files maps a path to the content it should get.
	files map[string]string
	order []string
}

// planChange works out every file that has to move.
//
// Both kinds touch MORE than the obvious file, and missing the extra one fails
// silently rather than loudly. A backend change has to move the proxy_pass
// lines in the panel vhost, or nginx keeps proxying to a port nothing is on. An
// external change has to move the custom panel domain's own proxy to the panel
// port, or that domain serves a blank page for the one operator who set it up.
func planChange(kind string, current Ports, newPort int) (plan, error) {
	result := plan{kind: kind, newPort: newPort, host: current.BackendHost, files: map[string]string{}}

	panelText, err := os.ReadFile(panelVhostPath()) // #nosec G304 -- fixed path.
	if err != nil {
		return result, refuse(ReasonUnreadable, "%s could not be read: %v", panelVhostPath(), err)
	}
	domainText, domainPresent := readOptional(panelDomainVhostPath())

	switch kind {
	case KindBackend:
		result.oldPort = current.Backend

		envText, err := os.ReadFile(envPath()) // #nosec G304 -- fixed path.
		if err != nil {
			return result, refuse(ReasonUnreadable, "%s could not be read: %v", envPath(), err)
		}
		written, err := SetEnvListen(string(envText), current.BackendHost, newPort)
		if err != nil {
			return result, err
		}
		result.add(envPath(), written)

		moved, replaced := SetProxyPort(string(panelText), current.Backend, newPort)
		if replaced == 0 {
			return result, refuse(ReasonNotFound,
				"%s does not proxy to 127.0.0.1:%d, so this panel is not the one it serves",
				panelVhostPath(), current.Backend)
		}
		result.add(panelVhostPath(), moved)

		if domainPresent {
			if movedDomain, count := SetProxyPort(domainText, current.Backend, newPort); count > 0 {
				result.add(panelDomainVhostPath(), movedDomain)
			}
		}

	case KindExternal:
		result.oldPort = current.External

		moved, err := SetNginxListenPort(string(panelText), newPort)
		if err != nil {
			return result, err
		}
		result.add(panelVhostPath(), moved)

		if domainPresent {
			// The custom domain proxies to the panel's external port over TLS.
			if movedDomain, count := SetProxyPort(domainText, current.External, newPort); count > 0 {
				result.add(panelDomainVhostPath(), movedDomain)
			}
		}

	default:
		return result, refuse(ReasonUnknownKind, "%q is not something this can move", kind)
	}

	if result.oldPort == newPort {
		return result, refuse(ReasonSamePort, "the panel is already on port %d", newPort)
	}
	return result, nil
}

func (p *plan) add(path, content string) {
	if _, seen := p.files[path]; !seen {
		p.order = append(p.order, path)
	}
	p.files[path] = content
}

func readOptional(path string) (string, bool) {
	raw, err := os.ReadFile(path) // #nosec G304 -- one of the fixed paths above.
	if err != nil {
		return "", false
	}
	return string(raw), true
}

// writePlan backs every file up, writes the new content, and asks nginx whether
// it will accept the result. A refusal restores everything before returning,
// because a configuration nginx rejects also breaks the NEXT unrelated reload,
// turning one bad port into an outage on every site.
func writePlan(ctx context.Context, p plan) ([]changeSet, error) {
	var changes []changeSet
	for _, path := range p.order {
		backup, err := backupOne(path)
		if err != nil {
			_ = restoreAll(changes)
			return nil, fmt.Errorf("back up %s: %w", path, err)
		}
		changes = append(changes, changeSet{Path: path, Backup: backup})
		if err := writeFilePreservingMode(path, p.files[path]); err != nil {
			_ = restoreAll(changes)
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
	}
	if out, err := run(ctx, "nginx", "-t"); err != nil {
		_ = restoreAll(changes)
		return nil, refuse(ReasonVerifyFailed, "nginx refused the new configuration: %s", tail(out))
	}
	return changes, nil
}

// ApplyExternal moves the port a browser connects to.
//
// This one runs IN PROCESS, because moving it does not restart the panel: nginx
// reloads, the backend keeps its connections, and the request that asked for
// the change is still there to be told what happened. That is the whole reason
// it is a separate path from the backend change.
func ApplyExternal(ctx context.Context, current Ports, newPort int) error {
	p, err := planChange(KindExternal, current, newPort)
	if err != nil {
		return err
	}
	changes, err := writePlan(ctx, p)
	if err != nil {
		return err
	}

	if out, err := run(ctx, "systemctl", "reload", "nginx"); err != nil {
		_ = restoreAll(changes)
		_, _ = run(ctx, "systemctl", "reload", "nginx")
		return refuse(ReasonVerifyFailed, "nginx would not reload: %s", tail(out))
	}
	if WaitReachable(ctx, "127.0.0.1", newPort, 20*time.Second) {
		return nil
	}

	// Nothing is answering on the new port. Put the file back, reload again,
	// and say which of the two states the server ended in, because "the change
	// failed" and "the change failed and the old port is gone too" need
	// completely different things from the operator.
	if restoreErr := restoreAll(changes); restoreErr != nil {
		return restoreErr
	}
	if out, err := run(ctx, "systemctl", "reload", "nginx"); err != nil {
		return refuse(ReasonRollbackFailed,
			"the new port did not answer and nginx would not reload the old configuration: %s", tail(out))
	}
	if !WaitReachable(ctx, "127.0.0.1", current.External, 20*time.Second) {
		return refuse(ReasonRollbackFailed,
			"the new port did not answer and port %d has not come back either", current.External)
	}
	return refuse(ReasonRolledBack, "nothing answered on port %d, so port %d was put back", newPort, current.External)
}

// StartBackendChange writes the new backend port and hands the rest to a
// DETACHED helper.
//
// The verification cannot run here. Moving this port restarts servika.service,
// which kills the process running the check, so an in-process rollback would
// never execute: the panel would simply stop and the last thing anybody saw
// would be a request that never returned. The helper runs under its own
// transient unit, survives the restart, and writes its verdict to a file the
// panel folds into the history table when it comes back.
func StartBackendChange(ctx context.Context, current Ports, newPort int, historyID int64) error {
	p, err := planChange(KindBackend, current, newPort)
	if err != nil {
		return err
	}
	changes, err := writePlan(ctx, p)
	if err != nil {
		return err
	}

	if err := WriteOutcome(Outcome{
		HistoryID: historyID, Kind: KindBackend,
		OldPort: current.Backend, NewPort: newPort, State: StateRunning,
	}); err != nil {
		_ = restoreAll(changes)
		return fmt.Errorf("record the change: %w", err)
	}

	if err := writeHelper(changes, current, newPort, historyID); err != nil {
		_ = restoreAll(changes)
		ClearOutcome()
		return err
	}
	if out, err := run(ctx, "systemd-run", "--unit="+helperUnit, "--collect", helperPath()); err != nil {
		_ = restoreAll(changes)
		ClearOutcome()
		return refuse(ReasonVerifyFailed, "the change helper would not start: %s", tail(out))
	}
	return nil
}

// trimSpace is here so handlers.go does not need the strings import twice over.
func trimSpace(value string) string { return strings.TrimSpace(value) }

func tail(out string) string {
	out = strings.TrimSpace(out)
	lines := strings.Split(out, "\n")
	if len(lines) > 4 {
		lines = lines[len(lines)-4:]
	}
	return strings.Join(lines, "; ")
}
