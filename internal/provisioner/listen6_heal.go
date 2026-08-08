package provisioner

import (
	"log"
	"os"
	"strings"
)

// The shipped nginx files are COPIED, not rendered, so the template-side
// listen6 helper never reaches them. They still carry unconditional
// `listen [::]` lines, and on a kernel booted with ipv6.disable=1 that is what
// stops nginx from starting at all.
//
// The transform runs in both directions. Removing the lines on a host without
// IPv6 is the part that keeps nginx alive; putting them BACK when IPv6 is
// enabled later matters just as much, because a panel that stays IPv4-only
// after the operator turned IPv6 on is unreachable from an IPv6 client with no
// visible reason.

// listenPrefix is the indentation-insensitive marker for an nginx listen line.
const listenPrefix = "listen "

// withoutIPv6Listen drops every IPv6 listen line.
func withoutIPv6Listen(text string) string {
	lines := strings.Split(text, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if ipv6ListenTail(line) != "" {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// withIPv6Listen adds an IPv6 sibling for every plain listen line that has none.
//
// The sibling is looked for anywhere in the FILE rather than on the next line,
// because the shipped panel vhost separates the two by several directives and a
// neighbour-only check would duplicate the line there. nginx refuses a
// duplicate listen on the same address and port, which would fail the whole
// server.
func withIPv6Listen(text string) string {
	lines := strings.Split(text, "\n")
	present := map[string]bool{}
	for _, line := range lines {
		if tail := ipv6ListenTail(line); tail != "" {
			present[tail] = true
		}
	}

	out := make([]string, 0, len(lines))
	for _, line := range lines {
		out = append(out, line)
		tail := plainListenTail(line)
		if tail == "" || present[tail] {
			continue
		}
		present[tail] = true
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		out = append(out, indent+listenPrefix+"[::]:"+tail+";")
	}
	return strings.Join(out, "\n")
}

// adjustIPv6Listen shapes a shipped file to what this host can bind.
func adjustIPv6Listen(text string) string {
	if hostHasIPv6() {
		return withIPv6Listen(text)
	}
	return withoutIPv6Listen(text)
}

// plainListenTail returns what follows "listen " on an IPv4/any listen line, or
// empty for anything else.
func plainListenTail(line string) string {
	rest, ok := listenTail(line)
	if !ok || strings.HasPrefix(rest, "[") {
		return "" // already an IPv6 line
	}
	return rest
}

// ipv6ListenTail returns what follows "listen [::]:" on an IPv6 listen line.
func ipv6ListenTail(line string) string {
	rest, ok := listenTail(line)
	if !ok {
		return ""
	}
	tail, found := strings.CutPrefix(rest, "[::]:")
	if !found {
		return ""
	}
	return tail
}

// listenTail returns the directive's argument text without its semicolon.
func listenTail(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	rest, found := strings.CutPrefix(trimmed, listenPrefix)
	if !found {
		return "", false
	}
	rest, found = strings.CutSuffix(rest, ";")
	if !found {
		return "", false // a continuation or a comment, not a directive
	}
	return strings.TrimSpace(rest), true
}

// HealPanelIPv6Listen brings the panel vhost's listen lines in line with the
// host.
//
// The panel vhost is patched in place by several heals rather than replaced
// wholesale, so this follows the same shape: read, transform, validate, and put
// the original back when nginx refuses the result.
func HealPanelIPv6Listen() {
	// #nosec G304 -- fixed system configuration path built from a package constant, never from request input.
	original, err := os.ReadFile(panelVhostPath)
	if err != nil {
		return // no panel vhost yet; install writes it
	}
	updated := adjustIPv6Listen(string(original))
	if updated == string(original) {
		return
	}
	// 0640 root:nginx is deliberate: this file carries the X-Servika-Proxy
	// secret, so hardenSecretVhostPerms keeps it off world-readable, and nginx
	// still has to read it.
	// #nosec G306 G703 -- root-owned nginx configuration at a package-constant path; nothing here comes from a request, and 0640 is required because the file carries the proxy secret and nginx must still read it.
	if err := os.WriteFile(panelVhostPath, []byte(updated), 0o640); err != nil {
		log.Printf("panel ipv6 listen heal: could not write %s: %v", panelVhostPath, err)
		return
	}
	if output, err := tenantCommand("nginx", "-t").CombinedOutput(); err != nil {
		// #nosec G306 G703 -- root-owned nginx configuration restored to its previous bytes after a failed validation; the path is a package constant.
		_ = os.WriteFile(panelVhostPath, original, 0o640)
		log.Printf("panel ipv6 listen heal: nginx -t rejected the change, reverted: %s", strings.TrimSpace(string(output)))
		return
	}
	if output, err := tenantCommand("systemctl", "reload", "nginx").CombinedOutput(); err != nil {
		log.Printf("panel ipv6 listen heal: nginx reload failed: %s", strings.TrimSpace(string(output)))
		return
	}
	log.Printf("panel ipv6 listen heal: %s adjusted for kernel IPv6 support", panelVhostPath)
}
