package provisioner

import (
	"log"
	"os"
	"path/filepath"
	"strings"
)

// serverTokensFile is the drop-in this heal owns. The 00 prefix keeps it beside
// the other http-context files the panel writes.
const serverTokensFile = "00-servika-hardening.conf"

const serverTokensBody = `# Servika nginx hardening, generated automatically.
# nginx defaults server_tokens to on, so every response from the panel and from
# every hosted site carries its exact version, and every nginx error page prints
# it in the body. That turns picking a CVE for this build into a lookup.
server_tokens off;
`

// HealServerTokens turns nginx's version banner off on a host where nothing
// else has decided the directive.
//
// It was written only by servika-optimize, which is an opt-in tuning pass, so a
// stock installation disclosed the build to every unauthenticated visitor until
// somebody chose to run it.
//
// nginx refuses a duplicate server_tokens in the same context, and refusing is
// fatal to the whole server, so this writes nothing when the directive already
// appears in nginx.conf or in any conf.d file. That covers the optimize pass's
// own copy, and an operator who set the directive by hand keeps their value.
func HealServerTokens() {
	target := filepath.Join(nginxConfDir, serverTokensFile)
	if _, err := os.Stat(target); err == nil {
		return // already ours
	}
	if declared, err := serverTokensDeclared(); err != nil || declared {
		return
	}
	// #nosec G306 -- root-owned nginx configuration nginx must read; it carries no secret.
	if err := os.WriteFile(target, []byte(serverTokensBody), 0o644); err != nil {
		log.Printf("server_tokens heal: could not write %s: %v", target, err)
		return
	}
	if output, err := tenantCommand("nginx", "-t").CombinedOutput(); err != nil {
		_ = os.Remove(target)
		log.Printf("server_tokens heal: nginx -t rejected the drop-in, removed it: %s",
			strings.TrimSpace(string(output)))
		return
	}
	if output, err := tenantCommand("systemctl", "reload", "nginx").CombinedOutput(); err != nil {
		// The file is valid and on disk, so the next start applies it.
		log.Printf("server_tokens heal: nginx reload failed, the drop-in applies at the next start: %s",
			strings.TrimSpace(string(output)))
		return
	}
	log.Printf("server_tokens heal: nginx no longer advertises its version")
}

// serverTokensDeclared reports whether nginx.conf or any conf.d file already
// carries a server_tokens directive.
func serverTokensDeclared() (bool, error) {
	files, err := filepath.Glob(filepath.Join(nginxConfDir, "*.conf"))
	if err != nil {
		return false, err
	}
	for _, path := range append(files, nginxMainConf) {
		// #nosec G304 -- a glob match under the package's own nginx conf.d, or the main conf path constant.
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		if declaresServerTokens(string(body)) {
			return true, nil
		}
	}
	return false, nil
}

// declaresServerTokens reports whether body holds an uncommented server_tokens
// directive. A commented line is not a directive, and the installer's own notes
// mention the name.
func declaresServerTokens(body string) bool {
	for line := range strings.SplitSeq(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "server_tokens ") || strings.HasPrefix(trimmed, "server_tokens\t") {
			return true
		}
	}
	return false
}
