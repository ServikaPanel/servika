package passwordprotect

import (
	"os/exec"

	"servika/internal/provisioner"
	"servika/internal/subdomain"
)

// Adding a protected directory reaches the host at every step: it resolves the
// nginx account, writes a password file under /etc/nginx/htpasswd, runs
// htpasswd and restorecon, and re-renders a vhost that `nginx -t` validates.
// Each step is a variable so a test can run the endpoint on a machine that is
// not a web host.
var (
	gidOfNginx   = nginxGID
	secureFile   = secureHtpasswd
	runCommand   = exec.Command
	phpSocketFor = provisioner.PHPSocketFor
	applyVhost   = provisioner.ApplyVhostForDomain
	reRenderSub  = subdomain.ReRender
)
