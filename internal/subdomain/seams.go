package subdomain

import (
	"os/exec"

	"servika/internal/dns"
	"servika/internal/provisioner"
)

// Seams: unexported package variables whose defaults are exactly what this
// package does on a real host. A characterization test replaces one so a
// subdomain can be created, re-rendered and deleted without /home, without
// /etc/nginx, without systemd and without a running nginx.
//
// They are NOT operator configuration: there is no environment variable, no
// paths.go entry and no README row, and only the call sites the tests reach are
// routed through them.
var (
	// tenantHomeRoot is where a tenant home lives. Every document root,
	// certificate and removal this package performs is beneath it.
	tenantHomeRoot = "/home"

	// nginxConfDir is where a subdomain's server block is written.
	nginxConfDir = "/etc/nginx/conf.d"

	// runCommand runs a host command and reports only whether it worked.
	runCommand = func(name string, args ...string) error {
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		return exec.Command(name, args...).Run()
	}

	// commandOutput runs a host command and returns what it printed, which is
	// what an nginx refusal is reported with.
	commandOutput = func(name string, args ...string) ([]byte, error) {
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		return exec.Command(name, args...).CombinedOutput()
	}

	tenantFPMActive    = provisioner.TenantFPMActive
	phpSocketFor       = provisioner.PHPSocketFor
	applySubdomainFPM  = provisioner.ApplySubdomainFPM
	removeSubdomainFPM = provisioner.RemoveSubdomainFPM
	protectedBlocks    = provisioner.ProtectedBlocks

	// reRenderSubdomain rewrites a subdomain's vhost once its own pool exists.
	reRenderSubdomain = ReRender

	// writeZone rewrites the parent domain's zone file.
	writeZone = dns.WriteZone

	// issueSelfSignedCertificate and issueLetsEncryptCertificate write a
	// certificate pair into the ROOT-OWNED staging directory. Neither tool
	// exists in a test.
	issueSelfSignedCertificate  = issueSelfSigned
	issueLetsEncryptCertificate = issueLetsEncrypt
)
