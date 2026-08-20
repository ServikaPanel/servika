package panelport

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The health check URL the ops tools use after a restart lives in the same
// environment file as SERVIKA_LISTEN, and it is DERIVED from it. Two settings
// naming one port is the whole defect this closes.
//
// The installer used to write SERVIKA_HEALTH with 8080 written into it while
// PRESERVING an existing SERVIKA_LISTEN two lines above, and this package
// rewrites only the latter when an operator moves the backend port. From that
// moment servika-update health-checked a port nothing answers on, never saw the
// panel come up, and restored the previous binary, every release asset AND the
// pre-update database dump. A healthy update rolled itself back, every time,
// for good.
//
// So SERVIKA_LISTEN is the single authority for where the backend listens.
// Nothing here invents a port; it only repairs a stale copy of one.

const envHealthName = "SERVIKA_HEALTH"

// HealthURL renders the health check URL for a listen host and port.
//
// A listen address may name no host at all (":8080") or a wildcard, and neither
// can be dialled: an empty host is not a URL and connecting to 0.0.0.0 is not
// portable. Every such form collapses to loopback, which is where the panel
// answers in all of them. This is the ONE place that rule lives, because the
// -print-ports flag and the heal below have to give the same answer.
func HealthURL(host string, port int) string {
	switch strings.Trim(strings.TrimSpace(host), "[]") {
	case "", "0.0.0.0", "::", "*":
		host = "127.0.0.1"
	}
	return "http://" + joinHostPort(host, port) + "/healthz"
}

// joinHostPort brackets an IPv6 literal, which net.JoinHostPort also does; it is
// written out here so this file stays pure string work with no address parsing
// to disagree with ParseListen about.
func joinHostPort(host string, port int) string {
	host = strings.Trim(host, "[]")
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(port)
}

// ReadEnvHealth finds SERVIKA_HEALTH in an environment file, last assignment
// winning for the same reason ReadEnvListen does.
func ReadEnvHealth(text string) string {
	value := ""
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, rest, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(name) != envHealthName {
			continue
		}
		value = strings.TrimSpace(rest)
	}
	return value
}

// SetEnvHealthPort rewrites only the PORT of every SERVIKA_HEALTH assignment and
// reports whether anything changed.
//
// Only the port, because the scheme, the host and the path may all have been set
// deliberately: an operator who pointed the check at a second loopback address
// keeps that address. A value this cannot parse is left EXACTLY as it is, the
// same rule internal/optimize follows for a current value it does not recognise,
// because somebody wrote it in a form this code does not know. A line already on
// the right port is left BYTE for byte, quotes and spacing included, so a boot
// that changes nothing writes nothing.
//
// An ABSENT assignment is not added. That is SetEnvListen's rule and it holds
// here for the same reason: the installer rewrites this file from a managed
// list, so a line it does not write is dropped again on the next install, and a
// setting that comes back weeks later is worse than one that was never there.
func SetEnvHealthPort(text string, port int) (string, bool, error) {
	changed := false
	var out strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		name, value, found := strings.Cut(trimmed, "=")
		next, ok := "", false
		if found && !strings.HasPrefix(trimmed, "#") && strings.TrimSpace(name) == envHealthName {
			next, ok = replaceURLPort(strings.TrimSpace(value), port)
		}
		if !ok {
			out.WriteString(line)
			out.WriteString("\n")
			continue
		}
		fmt.Fprintf(&out, "%s=%s\n", envHealthName, next)
		changed = true
	}
	if err := scanner.Err(); err != nil {
		return "", false, err
	}
	return out.String(), changed, nil
}

// replaceURLPort swaps the port of "http://host:port/path", reporting whether it
// both could and needed to.
//
// It refuses a value with no explicit port rather than inserting one: a URL
// written without a port names the scheme's default, and making that explicit is
// a change nobody asked for.
func replaceURLPort(value string, port int) (string, bool) {
	scheme, rest, found := strings.Cut(strings.Trim(value, `"'`), "://")
	if !found || scheme == "" || rest == "" {
		return "", false
	}
	authority, path, hadPath := strings.Cut(rest, "/")
	host, portText, hadPort := cutHostPort(authority)
	if !hadPort || host == "" {
		return "", false
	}
	current, err := strconv.Atoi(portText)
	if err != nil || current == port {
		return "", false
	}
	next := scheme + "://" + joinHostPort(host, port)
	if hadPath {
		next += "/" + path
	}
	return next, true
}

// cutHostPort splits an authority on the port separator, which for an IPv6
// literal is the colon AFTER the closing bracket rather than one of the many
// inside it.
func cutHostPort(authority string) (host, port string, found bool) {
	if end := strings.LastIndex(authority, "]"); end >= 0 {
		if end+1 < len(authority) && authority[end+1] == ':' {
			return authority[:end+1], authority[end+2:], true
		}
		return authority, "", false
	}
	index := strings.LastIndex(authority, ":")
	if index < 0 {
		return authority, "", false
	}
	return authority[:index], authority[index+1:], true
}

// HealHealthURL repairs a SERVIKA_HEALTH whose port no longer matches the port
// the panel listens on.
//
// It runs at startup because the panel that moved the backend port restarts
// immediately afterwards, so the repair lands in the same breath as the change
// that needed it. It is also what fixes an installation that moved its port
// before this existed and would otherwise keep rolling back every update.
//
// Nothing here is fatal: this is a repair, and an environment file the panel
// could not read is a problem it already survived to get this far.
func HealHealthURL() {
	path := envPath()
	// #nosec G304 -- fixed path, overridable only by the operator's own environment.
	text, err := os.ReadFile(path)
	if err != nil {
		log.Printf("health url heal: %s could not be read: %v", path, err)
		return
	}
	if ReadEnvHealth(string(text)) == "" {
		// Not set: the ops tools derive it, so there is nothing to repair.
		// SetEnvHealthPort would not add it either, so what this exits BEFORE is
		// the SERVIKA_LISTEN complaint below, which would otherwise print on
		// every boot of an installation that has nothing wrong with it.
		return
	}
	_, port, err := ParseListen(ReadEnvListen(string(text)))
	if err != nil {
		log.Printf("health url heal: %s does not set SERVIKA_LISTEN to an address with a port", path)
		return
	}
	next, changed, err := SetEnvHealthPort(string(text), port)
	if err != nil {
		log.Printf("health url heal: %s could not be rewritten: %v", path, err)
		return
	}
	if !changed {
		return
	}
	if err := replaceEnvFile(path, next); err != nil {
		log.Printf("health url heal: %s was left unchanged: %v", path, err)
		return
	}
	log.Printf("health url heal: %s now names port %d, which is where the panel listens", envHealthName, port)
}

// replaceEnvFile writes the environment file through a sibling temporary file
// and renames it into place.
//
// The file carries every panel secret and the server refuses to boot without
// three of them, so a truncating write that died halfway would mean a panel that
// does not come back. os.CreateTemp opens with 0600, which umask can only
// narrow, so the replacement is never wider than the file it replaces.
func replaceEnvFile(path, content string) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".env.health.*")
	if err != nil {
		return fmt.Errorf("create a temporary file beside %s: %w", path, err)
	}
	name := temp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := temp.WriteString(content); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", name, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
