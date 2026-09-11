package transfers

import (
	"os/exec"
	"os/user"

	"servika/internal/credentials"
	"servika/internal/cron"
	"servika/internal/dns"
	"servika/internal/domainblock"
	"servika/internal/domains"
	"servika/internal/mail"
	"servika/internal/phpversion"
	"servika/internal/provisioner"
	"servika/internal/resourcelimit"
	"servika/internal/sqlimport"
)

// The host and the other packages a transfer drives. Each is a variable whose
// default is the call this package made before, so a test can run a whole
// import or migration without root, a remote server or a real account.

// commandContext starts every local process: ssh, rsync, tar, mysql and chown.
var commandContext = exec.CommandContext

// Account, certificate and resource steps.
var (
	blockedDomain       = domainblock.Blocked
	provisionAccount    = provisioner.Provision
	deprovisionAccount  = provisioner.Deprovision
	enableLetsEncrypt   = provisioner.EnableLetsEncrypt
	installImportedSSL  = provisioner.InstallImportedSSL
	rerenderVhost       = provisioner.RerenderVhost
	applyResourceLimits = resourcelimit.ApplyAll
	lookupSystemUser    = user.Lookup
	phpVersions         = phpversion.AllVersions
)

// Database and DNS steps.
var (
	createFTPAccount     = credentials.FTPCreate
	createMySQLDB        = credentials.MySQLCreateDB
	createMySQLDBForUser = credentials.MySQLCreateDBForUser
	importSQLDump        = sqlimport.Import
	seedDNSDefaults      = dns.SeedDefaults
	writeDNSZone         = dns.WriteZone
)

// The in-process handlers an import reuses rather than repeating their work.
var (
	enableMailDomain = mail.EnableDomain
	createMailbox    = (*mail.Handlers).Create
	createMailAlias  = (*mail.Handlers).CreateAlias
	createDomain     = (*domains.Handlers).Create
	deleteDomain     = (*domains.Handlers).Delete
	createCronJob    = (*cron.Handlers).Create
)

// migrateAccount and runMigration are the steps the job handlers start, so a
// test can observe a job without migrating a site.
var (
	migrateAccount = (*Handlers).MigrateAccount
	runMigration   = (*Handlers).runMigrationJob
)
