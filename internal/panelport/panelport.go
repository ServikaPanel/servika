// Package panelport moves the panel's own ports.
//
// This is the one change in the panel that can take the panel away: the screen
// that would put it back is the screen that just disappeared. Everything in
// this file is PURE, so the rules that decide whether a change is even allowed
// can be tested without a panel to lose.
package panelport

import (
	"bufio"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The two things that can move.
const (
	KindBackend  = "backend"  // SERVIKA_LISTEN, what nginx proxies to.
	KindExternal = "external" // The nginx listen line a browser connects to.
)

// Refusal reasons, carried beside the English message because the screen
// renders twelve languages.
const (
	ReasonBadPort        = "panel_port_out_of_range"
	ReasonReservedPort   = "panel_port_reserved"
	ReasonAppPort        = "panel_port_in_app_range"
	ReasonSamePort       = "panel_port_unchanged"
	ReasonInUse          = "panel_port_in_use"
	ReasonUnknownKind    = "panel_port_unknown_kind"
	ReasonNotFound       = "panel_port_directive_not_found"
	ReasonBusy           = "panel_port_change_in_progress"
	ReasonVerifyFailed   = "panel_port_verification_failed"
	ReasonRolledBack     = "panel_port_rolled_back"
	ReasonRollbackFailed = "panel_port_rollback_failed"
	ReasonUnreadable     = "panel_port_host_unreadable"
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

// reservedPorts are the ports another service on this server already answers
// on. Taking one would not merely fail: nginx would bind it, the real service
// would stop, and the failure would show up as mail or DNS quietly breaking
// rather than as anything the panel said.
//
// SSH is here under both its stock number and the second one the panel's own
// hardening suggests, because the port an operator reaches this machine on is
// the one thing that must survive every mistake this package can make.
var reservedPorts = map[int]string{
	21:   "FTP",
	22:   "SSH",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	143:  "IMAP",
	443:  "HTTPS",
	465:  "SMTPS",
	587:  "submission",
	993:  "IMAPS",
	995:  "POP3S",
	2222: "SSH (alternate)",
	3306: "MariaDB",
	6379: "Valkey",
}

// The tenant application range. internal/firewall DROPS every port in it, so a
// panel moved into it would be reachable from loopback and from nowhere else:
// the operator's browser would simply time out, with nothing in any log to say
// why.
const (
	appPortMin = 30000
	appPortMax = 30999
)

// ValidatePort decides whether a port may be taken at all.
//
// Out-of-range values are REFUSED rather than clamped. A clamp would move the
// panel to a port the operator never asked for, which on this particular screen
// means they go looking for it on the number they typed.
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return refuse(ReasonBadPort, "%d is not a port number", port)
	}
	if port < 1024 {
		// A privileged port is not refused for permission reasons (this runs as
		// root) but because everything down there belongs to a service that
		// either exists on this server or will when a feature is switched on.
		if name, taken := reservedPorts[port]; taken {
			return refuse(ReasonReservedPort, "port %d belongs to %s on this server", port, name)
		}
		return refuse(ReasonReservedPort, "ports below 1024 belong to system services")
	}
	if name, taken := reservedPorts[port]; taken {
		return refuse(ReasonReservedPort, "port %d belongs to %s on this server", port, name)
	}
	if port >= appPortMin && port <= appPortMax {
		return refuse(ReasonAppPort,
			"ports %d-%d are dropped at the firewall for tenant applications, so the panel would be unreachable there",
			appPortMin, appPortMax)
	}
	return nil
}

// ValidKind accepts only the two things this package can move.
func ValidKind(kind string) bool {
	return kind == KindBackend || kind == KindExternal
}

// ParseListen reads the port out of a SERVIKA_LISTEN value.
//
// The value may be ":8080", "127.0.0.1:8080" or "[::1]:8080", and the HOST part
// is preserved by every writer here: an installation bound to loopback must
// stay bound to loopback, because widening it would put the panel API on every
// address the server has without anybody asking for that.
func ParseListen(value string) (host string, port int, err error) {
	value = strings.TrimSpace(strings.Trim(strings.TrimSpace(value), `"'`))
	index := strings.LastIndex(value, ":")
	if index < 0 {
		return "", 0, fmt.Errorf("%q has no port", value)
	}
	host = value[:index]
	port, convErr := strconv.Atoi(value[index+1:])
	if convErr != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("%q has no port", value)
	}
	return host, port, nil
}

// ReadEnvListen finds SERVIKA_LISTEN in an environment file.
//
// The LAST assignment wins, which is what systemd's EnvironmentFile does, and a
// commented line is not an assignment. Reading the first one instead would
// report a port the panel is not on whenever somebody left an old line above.
func ReadEnvListen(text string) string {
	value := ""
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, rest, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(name) != "SERVIKA_LISTEN" {
			continue
		}
		value = strings.TrimSpace(rest)
	}
	return value
}

// SetEnvListen rewrites SERVIKA_LISTEN in place and REFUSES when it is absent.
//
// Appending it instead would look like it worked: systemd takes the last
// assignment, so an appended line does win, but the file is also rewritten by
// the installer from a managed list, and a value the installer does not know
// about is silently dropped on the next update. A file without the assignment
// is a file this package does not understand, and saying so is better than
// changing a port that comes back on its own weeks later.
func SetEnvListen(text, host string, port int) (string, error) {
	replaced := false
	var out strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		name, _, found := strings.Cut(trimmed, "=")
		if !found || strings.HasPrefix(trimmed, "#") || strings.TrimSpace(name) != "SERVIKA_LISTEN" {
			out.WriteString(line)
			out.WriteString("\n")
			continue
		}
		fmt.Fprintf(&out, "SERVIKA_LISTEN=%s:%d\n", host, port)
		replaced = true
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if !replaced {
		return "", refuse(ReasonNotFound, "SERVIKA_LISTEN is not set in this file")
	}
	return out.String(), nil
}

// ReadNginxListenPort finds the port of the panel's own listen line.
//
// It matches the "default_server" form specifically, because the panel vhost is
// the only default server on its port and every other listen line in the file
// belongs to something else.
func ReadNginxListenPort(text string) int {
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "listen ") {
			continue
		}
		if !strings.Contains(line, "default_server") {
			continue
		}
		if port := listenPortOf(line); port > 0 {
			return port
		}
	}
	return 0
}

// listenPortOf reads the port from "listen 8443 ssl default_server;" and from
// the "listen [::]:8443 ssl default_server;" form beside it.
func listenPortOf(line string) int {
	fields := strings.Fields(strings.TrimSuffix(strings.TrimSpace(line), ";"))
	if len(fields) < 2 {
		return 0
	}
	value := fields[1]
	if index := strings.LastIndex(value, ":"); index >= 0 {
		value = value[index+1:]
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0
	}
	return port
}

// SetNginxListenPort rewrites every default_server listen line to a new port,
// keeping the address part so the IPv4 and IPv6 lines stay a matched pair.
//
// Rewriting only one of them is the silent failure this guards: nginx starts
// happily with the panel on 9443 over IPv4 and 8443 over IPv6, and an operator
// whose browser prefers IPv6 sees the old port keep working right up until the
// day it does not.
func SetNginxListenPort(text string, port int) (string, error) {
	replaced := 0
	var out strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || !strings.HasPrefix(trimmed, "listen ") ||
			!strings.Contains(trimmed, "default_server") {
			out.WriteString(line)
			out.WriteString("\n")
			continue
		}
		fields := strings.Fields(strings.TrimSuffix(trimmed, ";"))
		if len(fields) < 2 {
			out.WriteString(line)
			out.WriteString("\n")
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		address := fields[1]
		if index := strings.LastIndex(address, ":"); index >= 0 {
			address = address[:index+1] + strconv.Itoa(port)
		} else {
			address = strconv.Itoa(port)
		}
		rest := ""
		if len(fields) > 2 {
			rest = " " + strings.Join(fields[2:], " ")
		}
		fmt.Fprintf(&out, "%slisten %s%s;\n", indent, address, rest)
		replaced++
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if replaced == 0 {
		return "", refuse(ReasonNotFound, "this file has no default_server listen line")
	}
	return out.String(), nil
}

// SetProxyPort rewrites every "proxy_pass <scheme>://127.0.0.1:<port>" that
// currently names oldPort.
//
// It is keyed on the OLD port rather than on "any loopback proxy_pass", because
// the panel vhost also proxies to php-fpm, to phpMyAdmin and to the panel's own
// external port, and rewriting those would point the panel at itself.
func SetProxyPort(text string, oldPort, newPort int) (string, int) {
	from := fmt.Sprintf("127.0.0.1:%d", oldPort)
	to := fmt.Sprintf("127.0.0.1:%d", newPort)
	replaced := 0

	var out strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || !strings.HasPrefix(trimmed, "proxy_pass ") ||
			!strings.Contains(line, from) {
			out.WriteString(line)
			out.WriteString("\n")
			continue
		}
		out.WriteString(strings.ReplaceAll(line, from, to))
		out.WriteString("\n")
		replaced++
	}
	if scanner.Err() != nil {
		return text, 0
	}
	return out.String(), replaced
}
