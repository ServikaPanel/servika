package waf

import "servika/internal/provisioner"

// The effective state and the module check read the host's ModSecurity
// installation. They are variables so a test can run the endpoints on a machine
// that has no nginx.
var (
	wafEffective    = provisioner.WAFEffective
	wafModuleLoaded = provisioner.WAFModuleLoaded
)
