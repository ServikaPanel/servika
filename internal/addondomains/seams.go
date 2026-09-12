package addondomains

import (
	"servika/internal/dns"
	"servika/internal/domainblock"
	"servika/internal/provisioner"
)

// The steps below leave the panel: they read the banned-domain list through a
// package cache, build a directory under a tenant home, render an nginx vhost
// and write a BIND zone. Each is a variable so a test can stand in for it and
// pin the order and the answers of the create path on a machine that is not a
// host.
var (
	refuseIfBlocked = domainblock.RefuseIfBlocked
	prepareRoot     = prepareDocRoot
	renderVhost     = provisioner.RerenderVhost
	seedDNS         = dns.SeedDefaults
	writeZone       = dns.WriteZone
	cleanupAddon    = Cleanup
)
