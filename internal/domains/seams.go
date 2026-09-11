package domains

import (
	"servika/internal/addondomains"
	"servika/internal/antivirus"
	"servika/internal/apps"
	"servika/internal/config"
	"servika/internal/credentials"
	"servika/internal/dns"
	"servika/internal/domainblock"
	"servika/internal/geoip"
	"servika/internal/laravel"
	"servika/internal/mail"
	"servika/internal/middleware"
	"servika/internal/provisioner"
	"servika/internal/quota"
	"servika/internal/redis"
	"servika/internal/resourcelimit"
	"servika/internal/tenantaccount"
)

// The calls the handlers in this package make outside their own database
// handle: the host, the MariaDB accounts, BIND and the other panel packages.
// Each is a variable whose default is the call this package made before, so a
// test can run a handler's own decisions without provisioning a tenant, opening
// a MariaDB socket or reloading a service. None of them is operator
// configuration.

// Placing a tenant on the host and taking it off again.
var (
	provisionTenant           = provisioner.Provision
	deprovisionTenant         = provisioner.Deprovision
	otherTopLevelDomainsUsing = provisioner.OtherTopLevelDomainsUsing
	removeMaintenancePage     = provisioner.RemoveMaintenancePage
	ensureTenantAccount       = tenantaccount.Ensure
	cleanupAddonDomain        = addondomains.Cleanup
	teardownApps              = apps.TeardownForDomain
	teardownLaravel           = laravel.TeardownForDomain
	deleteSystemdSlice        = resourcelimit.DeleteSystemdSlice
	removeQuarantineStore     = antivirus.RemoveStoreForUser
	forgetRedisDomain         = redis.ForgetDomain
	closeRedisDomain          = redis.CloseDomain
	cleanupMailDomain         = mail.CleanupDomain
	applyResourceLimits       = resourcelimit.ApplyAll
	applyMailPlanLimits       = mail.ApplyPlanLimitsToDomain
)

// Rendering a vhost, and the runtime a suspension stops.
var (
	rerenderVhost         = provisioner.RerenderVhost
	phpSocketFor          = provisioner.PHPSocketFor
	applyVhostForDomain   = provisioner.ApplyVhostForDomain
	applyWAF              = provisioner.WAFApply
	suspendUserRuntime    = provisioner.SuspendUserRuntime
	suspendApps           = apps.SuspendForUser
	writeMaintenancePage  = provisioner.WriteMaintenancePage
	wwwResolvesToApex     = provisioner.WWWResolvesToApex
	certificateCoversHost = provisioner.CertificateCoversHost
	geoDatabaseAvailable  = geoip.Available
	geoKnownCountry       = geoip.KnownCountry
)

// Certificates.
var (
	enableSelfSigned     = provisioner.EnableSelfSigned
	enableLetsEncrypt    = provisioner.EnableLetsEncrypt
	issueMailCertificate = provisioner.IssueMailCertificate
	applyMailSNI         = mail.ApplySNI
)

// DNS, and the addresses this server answers on.
var (
	seedDNSDefaults       = dns.SeedDefaults
	writeDNSZone          = dns.WriteZone
	deleteDNSZone         = dns.DeleteZone
	repointIPv6           = dns.RepointIPv6
	nameserversConfigured = dns.NameserversConfigured
	readNameserverPair    = dns.NameserverPair
	addressIsLocal        = config.AddressIsLocal
)

// Accounts, quotas and MariaDB credentials.
var (
	refuseIfBlocked             = domainblock.RefuseIfBlocked
	resellerOwnsCustomer        = middleware.ResellerOwnsCustomer
	checkResellerDomainAllowed  = quota.CheckResellerDomainAllowed
	checkResellerDiskAllowed    = quota.CheckResellerDiskAllowed
	checkResellerTrafficAllowed = quota.CheckResellerTrafficAllowed
	checkDomainAllowed          = quota.CheckDomainAllowed
	lockCustomerForDomain       = quota.LockCustomerForDomain
	checkDatabaseAllowed        = quota.CheckDatabaseAllowed
	createFTPAccount            = credentials.FTPCreate
	mysqlCreateDBForUser        = credentials.MySQLCreateDBForUser
	mysqlDropAllForDomain       = credentials.MySQLDropAllForDomain
	mysqlAddUser                = credentials.MySQLAddUser
	mysqlChangePassword         = credentials.MySQLChangePassword
	encryptDBPass               = credentials.EncryptDBPass
	decryptDBPass               = credentials.DecryptDBPass
)
