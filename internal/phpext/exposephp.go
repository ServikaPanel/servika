package phpext

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
)

// hardeningDropinName is the managed php.d file this package owns. The 99
// prefix keeps it last, so it wins over anything the distribution or an
// operator wrote earlier in the directory.
const hardeningDropinName = "99-servika-hardening.ini"

// hardeningDropin is what that file holds.
const hardeningDropin = `; Servika PHP hardening, generated automatically.
; With expose_php on, PHP answers every request with X-Powered-By: PHP/<exact
; version>, so one unauthenticated HEAD request tells a scanner the patch level
; of every site on this server. nginx's own banner is already off
; (server_tokens off in 00-servika-perf.conf); this is the same class.
expose_php = Off
`

// HealExposePHP writes the hardening drop-in for every installed PHP runtime.
//
// The installer writes it too, and so does a version installed later, but
// neither reaches a host that was provisioned before this existed, which is why
// it runs at startup like every other host-configuration repair. Nothing is
// reloaded when every file already matches, so a normal boot does not restart a
// single pool.
func HealExposePHP() {
	changed := false
	for _, version := range installedVersions() {
		wrote, err := writeHardeningDropin(version.IniDir)
		if err != nil {
			log.Printf("PHP %s: expose_php drop-in: %v", version.Version, err)
			continue
		}
		if !wrote {
			continue
		}
		changed = true
		if _, err := runCommand("systemctl", "reload-or-restart", version.Service); err != nil {
			// The file is on disk, so the next start of the pool picks it up. The
			// banner stays until then, and saying so beats a silent partial repair.
			log.Printf("PHP %s: %s did not reload, the drop-in applies at its next start: %v",
				version.Version, version.Service, err)
		}
	}
	if !changed {
		return
	}
	// A tenant runs its OWN php-fpm master, so reloading the shared service
	// leaves those masters serving with the old ini set.
	reloadTenantMasters()
}

// writeHardeningDropin writes the drop-in into dir and reports whether the file
// changed. An unchanged file is left alone, mtime included.
func writeHardeningDropin(dir string) (bool, error) {
	path := filepath.Join(dir, hardeningDropinName)
	// #nosec G304 -- dir comes from the installed-runtime list, never from a request.
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, []byte(hardeningDropin)) {
		return false, nil
	}
	// #nosec G306 -- root-owned php.d drop-in the interpreter must read; it holds no secret.
	if err := os.WriteFile(path, []byte(hardeningDropin), 0o644); err != nil {
		return false, err
	}
	return true, nil
}
