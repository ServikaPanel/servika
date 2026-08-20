package provisioner

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"log"
	"os"
	"slices"
	"strings"
)

// The two catch-all vhosts answer every request whose Host or SNI matches no
// tenant: port 80 also serves the shared ACME challenge webroot that every
// certificate order depends on.
//
// They were install-only until now. servika-install.sh copied them once and
// nothing ever looked at them again, so an edit to either template reached new
// installs and no existing one. Carrying the canonical text in the binary lets a
// startup heal deliver it, which is where a repair for existing installs belongs.
//
//go:embed nginx/_default80.conf
var default80Conf string

//go:embed nginx/_default443.conf
var default443Conf string

const (
	default80Path  = "/etc/nginx/conf.d/_default80.conf"
	default443Path = "/etc/nginx/conf.d/_default443.conf"
	// defaultWebroot is the document root both vhosts declare. Nothing has ever
	// created it, and nginx -t does not check that a root exists, so the miss was
	// invisible.
	defaultWebroot = "/var/www/_default80"
	// defaultParkPage is the file both vhosts fall back to. Its ABSENCE is not a
	// blank page: `try_files $uri /index.html` redirects internally to a path that
	// re-enters the same location, so nginx answers 500 and logs `rewrite or
	// internal redirection cycle`. Measured against nginx 1.29.8 with the shipped
	// _default80.conf: directory present and this file missing gives HTTP 500 for
	// every request with an unmatched Host, and 200 as soon as it exists.
	//
	// The ACME location is unaffected either way, which was measured separately: a
	// real token under /var/www/_acme still answered 200 with the right body while
	// ordinary requests were failing, because that location carries its own root.
	// So this never touched certificate renewal, only visitors.
	defaultParkPage = defaultWebroot + "/index.html"
)

// knownDefault80 and knownDefault443 hold the SHA-256 of every version of each
// file Servika has ever shipped, the current one included.
//
// A file whose hash is in its list is untouched since install, so replacing it
// is safe. A file whose hash is NOT in the list carries an operator edit, and
// overwriting that silently is worse than shipping nothing: the heal leaves it
// alone and says so. The current hash has to stay in the list, otherwise the
// heal would warn about its own output on the next boot; a test enforces that.
var (
	knownDefault80 = []string{
		"458c8db8907221c4a482d739ef45114f2c4b579234a3e18b56f289ade392d892",
		"775ed398a3339b41bb6c1553c43bd397b4b214dc981bef0650eeeaec01ddcdee",
		"9741384d7544f55aff7f98a33472842962d69fec2d8bc45d1d667683106546ad",
	}
	knownDefault443 = []string{
		"ffc263422c7ea634e3c8ef6c574657562f4cd5f007f34fd7fa1a953cc9485010",
		"5aa184a5974b255af0ac5d532b14e8f2658fb5f22ae5fbe1fef65f8103bc70b4",
	}
)

// vhostAction is what the heal decides to do with one managed file.
type vhostAction int

const (
	vhostInstall    vhostAction = iota // absent: write it
	vhostUpToDate                      // already the current text: nothing to do
	vhostReplace                       // a previously shipped version: bring it forward
	vhostKeepEdited                    // operator-modified: leave it and warn
)

func contentHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// decideVhostAction chooses what to do from the file's current state alone, with
// no filesystem or nginx involved, so the decision table is directly testable.
func decideVhostAction(existing string, exists bool, wanted string, known []string) vhostAction {
	if !exists {
		return vhostInstall
	}
	if existing == wanted {
		return vhostUpToDate
	}
	if slices.Contains(known, contentHash(existing)) {
		return vhostReplace
	}
	return vhostKeepEdited
}

// HealDefaultVhostsOnStartup brings the port 80 and port 443 catch-all vhosts up
// to the shipped text on an existing install.
//
// Each write is validated on its own: a file that breaks nginx -t is restored
// (or removed again when it was absent) before the next one is considered, so
// one bad template cannot take the other down with it, and nginx is never left
// unable to start.
func HealDefaultVhostsOnStartup() {
	// Both vhosts declare this root. Creating it is not cosmetic: the plan
	// directive validator builds its throwaway server block on the same path.
	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	if err := os.MkdirAll(defaultWebroot, 0o755); err != nil {
		log.Printf("default vhost heal: could not create %s: %v", defaultWebroot, err)
	}
	// The page goes down BEFORE the vhosts. The other order leaves a window in
	// which nginx serves a location whose fallback file is not there yet, and the
	// answer in that window is the 500 this exists to remove.
	ensureDefaultParkPage()

	changed := false
	changed = healManagedVhost(default80Path, default80Conf, knownDefault80) || changed
	changed = healManagedVhost(default443Path, default443Conf, knownDefault443) || changed

	if !changed {
		return
	}
	if output, err := tenantCommand("systemctl", "reload", "nginx").CombinedOutput(); err != nil {
		log.Printf("default vhost heal: nginx reload failed: %s", strings.TrimSpace(string(output)))
	}
}

// ensureDefaultParkPage writes the catch-all fallback page, comparing content
// first so a boot that changes nothing touches nothing. The shape is the same as
// Ensure404Page: this is a panel-generated asset, not an operator's file, and an
// operator who wants their own page edits the vhost, which the heal below
// already leaves alone once it differs from every shipped version.
func ensureDefaultParkPage() {
	next := []byte(defaultParkHTML())
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	if existing, err := os.ReadFile(defaultParkPage); err == nil && string(existing) == string(next) {
		return
	}
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(defaultParkPage, next, 0o644); err != nil {
		log.Printf("default vhost heal: could not write %s: %v", defaultParkPage, err)
		return
	}
	log.Printf("default vhost heal: %s written", defaultParkPage)
}

// healManagedVhost applies one file and reports whether it wrote anything.
//
// The wanted text is shaped to what this host can bind before anything is
// compared. The hash list gains the OTHER variant of the same canonical text,
// so a file this heal itself stripped of its IPv6 listen lines is recognised as
// shipped rather than mistaken for an operator edit: without that, a host
// without IPv6 would warn on every boot and never receive a template update
// again.
func healManagedVhost(path, canonical string, known []string) bool {
	wanted := adjustIPv6Listen(canonical)
	other := withIPv6Listen(canonical)
	if wanted == other {
		other = withoutIPv6Listen(canonical)
	}
	known = append(slices.Clone(known), contentHash(other))
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	original, readErr := os.ReadFile(path)
	exists := readErr == nil

	switch decideVhostAction(string(original), exists, wanted, known) {
	case vhostUpToDate:
		return false
	case vhostKeepEdited:
		log.Printf("default vhost heal: %s differs from every shipped version, left untouched", path)
		return false
	}

	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(path, []byte(wanted), 0o644); err != nil {
		log.Printf("default vhost heal: could not write %s: %v", path, err)
		return false
	}

	if output, err := tenantCommand("nginx", "-t").CombinedOutput(); err != nil {
		if exists {
			// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640). healManagedVhost is unexported and both call sites pass a package constant, so path carries no caller input.
			_ = os.WriteFile(path, original, 0o644)
		} else {
			_ = os.Remove(path)
		}
		log.Printf("default vhost heal: nginx -t rejected %s, reverted: %s", path, strings.TrimSpace(string(output)))
		return false
	}

	log.Printf("default vhost heal: %s updated", path)
	return true
}
