package panelsettings

import (
	"net"

	"servika/internal/config"
)

// Saving a panel domain resolves the name, runs acme.sh, installs a certificate
// into /etc/ssl/servika and rewrites an nginx vhost. Each step is a variable so
// a test can run the endpoint on a machine that is not a panel host.
var (
	lookupHost     = net.LookupHost
	issueCert      = issuePanelCertificate
	restoreSelf    = restorePanelSelfSigned
	certExpiry     = certificateExpiry
	writePortless  = writePortlessPanelVhost
	removePortless = removePortlessPanelVhost
	publicIPv4     = config.PublicIPv4
)
