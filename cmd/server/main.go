package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"servika/internal/accounts"
	"servika/internal/addondomains"
	"servika/internal/antivirus"
	"servika/internal/appinstall"
	"servika/internal/appruntime"
	"servika/internal/apps"
	"servika/internal/auth"
	"servika/internal/autoconfig"
	"servika/internal/avsettings"
	"servika/internal/backups"
	"servika/internal/chains"
	"servika/internal/composer"
	"servika/internal/config"
	"servika/internal/credentials"
	"servika/internal/cron"
	"servika/internal/customer"
	"servika/internal/datamigrate"
	"servika/internal/db"
	"servika/internal/dbremote"
	"servika/internal/dns"
	"servika/internal/domainblock"
	"servika/internal/domains"
	"servika/internal/files"
	"servika/internal/firewall"
	"servika/internal/geoip"
	"servika/internal/git"
	githubpkg "servika/internal/github"
	"servika/internal/hostapps"
	"servika/internal/httpx"
	"servika/internal/laravel"
	"servika/internal/logs"
	"servika/internal/mail"
	"servika/internal/mailreport"
	"servika/internal/metrics"
	"servika/internal/middleware"
	"servika/internal/monitor"
	"servika/internal/mtasts"
	"servika/internal/nginxset"
	"servika/internal/notifications"
	"servika/internal/optimize"
	"servika/internal/overview"
	"servika/internal/packages"
	"servika/internal/panelport"
	"servika/internal/panelsettings"
	"servika/internal/passwordprotect"
	"servika/internal/performance"
	"servika/internal/php"
	"servika/internal/phpext"
	"servika/internal/phpversion"
	"servika/internal/plans"
	"servika/internal/plugin"
	"servika/internal/pma"
	"servika/internal/provisioner"
	"servika/internal/redis"
	"servika/internal/resource"
	"servika/internal/resourcelimit"
	"servika/internal/secret"
	"servika/internal/serverip"
	"servika/internal/sitecopy"
	"servika/internal/siteimport"
	"servika/internal/sitesecurity"
	"servika/internal/slowquery"
	"servika/internal/sshaccess"
	"servika/internal/stats"
	"servika/internal/subdomain"
	"servika/internal/system"
	"servika/internal/transfers"
	"servika/internal/users"
	"servika/internal/waf"
	"servika/internal/wordpress"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// version is the panel's reported current version. Release builds override it at
// build time via ldflags (see scripts/build-assets.sh: -X main.version=...). It
// keeps this fallback value when built manually with `go build`.
var version = "1.3.0"

// buildDate is embedded at build time via ldflags (see scripts/build-assets.sh:
// -X main.buildDate=...). It stays "development" when built manually with `go build`.
var buildDate = "development"

// pinTempDir moves every large temporary file the panel writes onto persistent
// disk. AlmaLinux 10 (the RHEL 10 default) mounts /tmp as tmpfs, i.e. RAM: if the
// panel's os.CreateTemp("", ...) / os.MkdirTemp("", ...) calls land there, a
// cPanel account import (archive up to 20 GiB, doubled again by its multipart
// copy), a database import (2 GiB raw + 2 GiB expanded), or a backup restore
// drags the server into OOM — the service does not slow down, it dies. TMPDIR is
// inherited by subprocesses too (tar, mysql, mysqldump, rsync), so this single
// point fixes every stream. An externally supplied TMPDIR is left untouched.
func pinTempDir() {
	if strings.TrimSpace(os.Getenv("TMPDIR")) != "" {
		return
	}
	const dir = "/var/lib/servika/tmp"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("could not create temp dir (%s), falling back to /tmp: %v", dir, err)
		return
	}
	// #nosec G302 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
	if err := os.Chmod(dir, 0o700); err != nil {
		log.Printf("could not set temp dir permissions: %v", err)
	}
	if err := os.Setenv("TMPDIR", dir); err != nil {
		log.Printf("could not set TMPDIR: %v", err)
		return
	}
	log.Printf("temporary file directory: %s", dir)
}

// printPortsIfAsked answers "-print-ports" and reports whether it did.
//
// servika-verify needs both of the panel's ports and must not guess either. The
// upstream this was taken from wrote that lookup twice and got it wrong twice:
// first a hardcoded port that produced three false alarms on a server whose port
// had been moved, then a pattern that missed the "listen 127.0.0.1:9443 ssl"
// form and a GUESSING fallback that mistook an unrelated port for the panel's.
// internal/panelport already reads both ports out of the files that hold them,
// knows every listen form the panel writes, and REFUSES rather than guessing, so
// this hands that answer to the shell instead of growing a second parser.
//
// It runs before config.Load, which requires the JWT and secret keys: reporting
// a port is not a reason to need them, and servika-verify has to work on an
// installation that is broken enough to be worth verifying.
func printPortsIfAsked() bool {
	if len(os.Args) < 2 || (os.Args[1] != "-print-ports" && os.Args[1] != "--print-ports") {
		return false
	}
	ports, err := panelport.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "the panel's ports could not be read: %v\n", err)
		os.Exit(1)
	}
	// Plain KEY=VALUE lines so a shell reads them field by field. Never a form
	// that invites eval: this output is parsed by a tool running as root.
	fmt.Printf("backend_host=%s\n", ports.BackendHost)
	fmt.Printf("backend=%d\n", ports.Backend)
	fmt.Printf("external=%d\n", ports.External)
	fmt.Printf("health_url=%s\n", panelport.HealthURL(ports.BackendHost, ports.Backend))
	return true
}

func main() {
	if printPortsIfAsked() {
		return
	}
	// The malware scan runs as a subprocess of this same binary, placed in a
	// systemd slice so the kernel enforces the operator's resource limits: a
	// child started by a service otherwise joins the SERVICE's cgroup, where
	// servika.service sets no limits at all. Like the port reporter, it answers
	// before config.Load, because a scan needs the paths from the environment
	// file and nothing else, and it hands its findings back through a file
	// rather than opening a database connection of its own.
	if antivirus.RunWorkerIfAsked() {
		return
	}
	// Which malware rule set is loaded, for servika-verify. Same reasoning as
	// the port reporter: the panel already reads and verifies the signed
	// package, so the shell is handed that answer rather than growing a second
	// reader of a binary container.
	if antivirus.PrintRuleSetIfAsked() {
		return
	}
	// The real-time watcher, which is the same binary again under its own unit.
	// It answers here for the same reason: watching files is not a reason to
	// need the JWT secret. Unlike the scan worker it DOES open the database,
	// because a long-running watcher has no parent to hand its findings to.
	if antivirus.RunWatcherIfAsked() {
		return
	}
	// The nightly sweep, when a systemd timer owns the schedule rather than the
	// in-process scheduler below. It opens the database like the watcher and for
	// the same reason, and it answers here so a sweep does not need the JWT
	// secret either.
	if antivirus.RunSweepIfAsked() {
		return
	}
	// The process-behaviour watcher, its own unit and gate. It opens the database
	// like the file watcher, because it too is long-running with no parent, and
	// it answers here so it does not need the JWT secret.
	if antivirus.RunProcWatcherIfAsked() {
		return
	}
	// The IonCube Loader install for one PHP version, re-invoked by a PHP install
	// job so the loader is ready within the same detached job. It answers here for
	// the reason the workers do: fetching and verifying the loader needs the
	// archive URL and the interpreter path, not the JWT secret or the database.
	if phpext.RunIonCubeInstallIfAsked() {
		return
	}
	pinTempDir()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := secret.Init(cfg.SecretKey); err != nil {
		log.Fatalf("secret: %v", err)
	}
	d, err := db.Open(cfg.DBDsn)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer func() { _ = d.Close() }()

	// migrations
	runMigrations(d)
	// Hash any FTP passwords still stored as legacy cleartext, so the switch to
	// Pure-FTPd MYSQLCrypt=crypt does not lock out existing accounts. Idempotent.
	if n, err := credentials.BackfillCleartextPasswords(d); err != nil {
		log.Printf("ftp password backfill warn: %v", err)
	} else if n > 0 {
		log.Printf("ftp password backfill: hashed %d cleartext account(s)", n)
	}
	// Encrypt any database-account passwords still stored as legacy cleartext, so
	// a leaked panel dump does not expose them. Idempotent.
	if n, err := credentials.BackfillDBPasswords(d); err != nil {
		log.Printf("db password backfill warn: %v", err)
	} else if n > 0 {
		log.Printf("db password backfill: encrypted %d cleartext account(s)", n)
	}
	// Encrypt the remaining credentials that were stored before their column
	// gained encryption (GitHub PATs, remote backup passwords). Idempotent.
	datamigrate.EncryptStoredCredentials(context.Background(), d)
	provisioner.Init(d)
	// swap is the only buffer before the OOM-killer, which on a swapless host
	// killed MariaDB and took every site down (2026-08-22 incident). The drop-ins
	// that defend the DB are installed in provisioner.Init; this operator-facing
	// warning is raised here, because internal/notifications cannot be imported
	// from provisioner without an import cycle.
	warnIfNoSwap(context.Background(), d)
	// Reports only, and only on a panel upgraded from before system user names
	// were allocated uniquely. Two domains sharing one cannot be separated by
	// anything but an operator, because their files live in one home directory.
	provisioner.ReportSystemUserCollisions()
	// The scan lock lives in memory, so a restart frees it while the row stays
	// 'running' for good and the screen shows a scan that never ends.
	antivirus.HealRunningScans(d)
	// The same reason, for the same kind of lock: the site security sweep holds
	// its lock in memory, so a panel killed mid-scan would refuse every later
	// scan, scheduled or manual, for good.
	sitesecurity.HealRunningScans(d)
	// And again for the same reason: an installation runs in a goroutine, so a
	// panel killed mid-install leaves a row nothing will ever finish and a
	// spinner on the screen for good.
	appinstall.HealRunningInstalls(d)
	middleware.Init(d)
	if err := dns.SeedTemplateIfEmpty(context.Background(), d); err != nil {
		log.Printf("DNS template seed warn: %v", err)
	}
	// Right after the seed, because the seed only ever writes into an EMPTY
	// template: every server that already runs Servika would otherwise never
	// receive the AAAA rows added to the built-in set.
	datamigrate.BackfillDNSTemplateIPv6(context.Background(), d)
	if err := dns.HealZoneIncludes(context.Background(), d); err != nil {
		log.Printf("DNS zone include heal warn: %v", err)
	}

	ipv4 := config.PublicIPv4()
	ipv6 := config.PublicIPv6()
	log.Printf("server ipv4: %s ipv6: %q kernel ipv6: %t", ipv4, ipv6, config.HasIPv6())

	if err := domains.SeedIfEmpty(context.Background(), d, ipv4); err != nil {
		log.Printf("seed warn: %v", err)
	}
	if err := plans.SeedIfEmpty(context.Background(), d); err != nil {
		log.Printf("plans seed warn: %v", err)
	}
	if err := plans.SeedSync(context.Background(), d); err != nil {
		log.Printf("plans seed sync warn: %v", err)
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		resourcelimit.HealTenantFPM(ctx, d)
	}()
	go resourcelimit.SlowQueryWatchdog(context.Background(), d)
	// HealQuotaOnStartup: reassert XFS user quota (disk + inode, CloudLinux parity) for every
	// tenant on boot. When the root XFS has noquota (single reboot pending after GRUB update),
	// all tenants are silently skipped — never a hard error. Runs in a background goroutine so
	// panel boot is not blocked.
	go resourcelimit.HealQuotaOnStartup(context.Background(), d)
	mail.HealMailOnStartup(context.Background(), d)
	// Webmail outgoing-mail repair. It cannot live in servika-update: the
	// updater replaces itself, but the copy running through an update is the OLD
	// script, so a repair added there would only take effect one update later.
	// Startup is the first point that runs with the new release in place.
	mail.HealRoundcubeSMTP(context.Background())
	// The stock Dovecot PAM passdb delays every virtual mailbox login and lets
	// IMAP clients guess system account passwords. servika-mail-setup disables it
	// too, but it can exit before that step and this repair also has to reach
	// hosts that were installed before it existed.
	mail.HealDovecotAuth(context.Background())
	// The three Postfix delivery settings and the Dovecot listen line reach a
	// NEW install through servika-mail-setup; an existing one never reruns it,
	// so without this repair IPv6 mail would work only on hosts installed after
	// the change.
	mail.HealMailIPv6(context.Background())
	// Mail hostnames are served their own certificate through SNI. The map is
	// generated from the installed certificates, so this picks up a host that
	// already had them and drops one whose certificate has expired.
	mail.HealMailSNI(context.Background())
	// A mailbox migration runs in a goroutine, so a restart would leave its row
	// saying "running" for ever. The credential is sealed in the row, so the job
	// is put back on the queue and finished rather than thrown away; only one
	// whose credential will not open is closed as interrupted.
	mail.HealMigrationJobs(d)
	// Only after that resume: the workers claim queued rows, and one starting
	// first could take a row the resume is still moving. Four run at a time,
	// because each copy holds an IMAP session and a disk writer for hours and a
	// reseller can legitimately ask for hundreds at once.
	mail.StartMigrationQueue(context.Background(), d)
	// Panel-initiated webmail sessions authenticate as a Dovecot master user,
	// because the panel keeps only a hash of the mailbox password. Clearing the
	// master password withdraws the bypass, so this removes it as well as writes it.
	mail.HealMasterUser(context.Background())
	// Roundcube has no panel session, so the sign-in is carried by a plugin that
	// redeems the panel's token over the loopback. It is installed here rather
	// than by the updater, which runs as its own previous copy.
	mail.HealWebmailPlugin(context.Background())
	mail.StartPolicyServer(d, "127.0.0.1:10040")
	// Postfix writes one log for the whole server, so it cannot be shown to a
	// tenant as it stands. This drains it into per-domain rows in the background.
	mail.StartDeliveryLogCollector(d)
	// Blocklist state changes on the scale of hours and answers over someone
	// else's DNS, so it is measured in the background rather than per request.
	// The pool is empty on a default install, so the address every domain
	// actually sends from is passed in beside it: without that, a server that
	// never configured a pool had no blocklist monitoring at all.
	mail.StartPoolScanner(d, ipv4)
	// Every domain's _dmarc record already asks the world to send aggregate
	// reports to postmaster@. This reads them out of that mailbox without
	// writing to it; the mailbox belongs to the customer.
	mailreport.StartCollector(d)
	// Known vulnerabilities in what a tenant's site actually runs: its plugins,
	// its npm dependencies, its Composer dependencies. dnf updateinfo covers the
	// server's own packages and antivirus covers malware; this is the gap
	// between them, and it is where most real compromises come from.
	sitesecurity.StartCollector(d)
	// Every step of an MTA-STS publication after the customer presses the button
	// waits on the world: a DNS record to propagate, then a certificate to be
	// reissued with the policy host in it. Neither has a completion signal, so
	// the sequence is advanced by re-measuring rather than by a callback.
	mtasts.StartHeal(d)
	// The country database is the operator's own MaxMind download. With no
	// credentials this does nothing at all rather than failing once a day.
	geoip.StartUpdater(d)
	// Called synchronously: this publishes the running version to internal/system,
	// which /system/usage reports as panel_version. Only local file work happens
	// here; the 24-hour manifest poll starts its own goroutine.
	system.StartVersionCheck(version, buildDate)

	// Notifications have a writer that fires on every real-time detection, so
	// without a retention pass the table grows for the life of the installation.
	notifications.StartPrune(context.Background(), d)

	// The signed malware rule package, if this build carries a signing key. The
	// PANEL is the only process that fetches: the scan worker runs inside
	// servika-av.slice with nested deadlines and the watcher's unit is sandboxed
	// for reading tenant trees, so both read the disk copy written here. A build
	// with no key configured starts nothing at all.
	antivirus.StartRuleUpdater(context.Background())

	// Backfill customer panel accounts onto the multi-user model.
	// Idempotent: exits silently when there is no tenant to migrate. The
	// generated accounts have no password and therefore cannot log in until an
	// admin or reseller assigns one from the Customer Accounts screen.
	datamigrate.BackfillCustomerAccounts(context.Background(), d)

	customerH := &customer.Handlers{DB: d, Secret: cfg.JWTSecret}
	authH := &auth.Handlers{DB: d, Secret: cfg.JWTSecret, LifetimeSec: cfg.JWTLifetime}
	usersH := &users.Handlers{DB: d}
	domainsH := &domains.Handlers{DB: d, IPv4: ipv4}
	filesH := &files.Handlers{DB: d}
	cronH := &cron.Handlers{DB: d, SecretKey: cfg.SecretKey}
	logsH := &logs.Handlers{DB: d}
	plansH := &plans.Handlers{DB: d}
	dnsH := &dns.Handlers{DB: d}
	overviewH := &overview.Handlers{DB: d}
	accountsH := &accounts.Handlers{DB: d}
	backupsH := &backups.Handlers{DB: d}
	backups.StartScheduler(d)
	// The nightly malware sweep. It does nothing at all until an operator
	// turns it on, and it takes the same single scan slot a hand-started scan
	// does, so it waits for the next hour rather than running beside one.
	antivirus.StartScheduler(d)
	// Domain blocklist state. It queries nothing until an operator names a
	// zone, and it refreshes a table rather than answering a request, because
	// one query per zone per domain is not work an HTTP request can do.
	antivirus.StartReputationScanner(d)
	// nginx has no notion of time, so a maintenance window that ends by itself
	// needs something to re-render the vhost when its deadline passes.
	domains.StartMaintenanceScheduler(d)
	gitH := &git.Handlers{DB: d}
	githubH := &githubpkg.Handlers{DB: d, WebhookBase: "https://" + ipv4 + ":8443"}
	pmaH := &pma.Handlers{DB: d}
	autoconfigH := &autoconfig.Handlers{DB: d}
	phpH := &php.Handlers{DB: d}
	resourceH := &resource.Handlers{DB: d}
	monitorH := &monitor.Handlers{DB: d}
	// RerenderSubdomain is injected because internal/subdomain imports nginxset for
	// the settings type, so nginxset cannot call back into it directly.
	nginxsetH := &nginxset.Handlers{DB: d, RerenderSubdomain: subdomain.ReRender}
	sshH := &sshaccess.Handlers{DB: d, IPv4: ipv4}
	statH := &stats.Handlers{DB: d}
	perfH := &performance.Handlers{DB: d}
	slowQueryH := &slowquery.Handlers{DB: d}
	// The rebuild is handed over as a function: internal/firewall reads
	// internal/dbremote's table, so importing it the other way would close a
	// cycle.
	dbRemoteH := &dbremote.Handlers{DB: d, RebuildFirewall: func() error { return firewall.Reapply(d) }}
	compH := &composer.Handlers{DB: d}
	laravelH := &laravel.Handlers{DB: d}
	protectionH := &passwordprotect.Handlers{DB: d}
	avH := &antivirus.Handlers{DB: d}
	avSettingsH := &avsettings.Handlers{DB: d}
	chainsH := &chains.Handlers{DB: d}
	notificationsH := &notifications.Handlers{DB: d}
	// Write the antivirus resource slice from the stored settings at every
	// start.
	//
	// Nothing else creates the file: ApplyLimits used to run only when an
	// operator SAVED the settings screen, so on an installation where nobody
	// ever did, the file did not exist. Measured on real systemd: systemd then
	// creates the slice implicitly, reports CPUQuota, MemoryMax and TasksMax all
	// as infinity, and every scan the panel launches into it runs unlimited
	// while the screen shows the capacity-derived values it computed.
	//
	// ApplyWatcher and ApplyScheduleTimer are deliberately NOT called here.
	// Both start or restart a unit, and doing that at boot would interrupt the
	// watcher of an operator who changed nothing, on every panel restart.
	if s, err := avsettings.Read(context.Background(), d); err != nil {
		log.Printf("antivirus: the resource limits could not be read at startup: %v", err)
	} else if err := avsettings.ApplyLimits(s); err != nil {
		log.Printf("antivirus: the resource limits could not be applied at startup: %v", err)
	}
	copyH := &sitecopy.Handlers{DB: d}
	importH := &siteimport.Handlers{DB: d}
	wpH := &wordpress.Handlers{DB: d}
	fwH := &firewall.Handlers{DB: d}
	geoIPH := &geoip.Handlers{DB: d}
	wafH := &waf.Handlers{DB: d}
	redisH := &redis.Handlers{DB: d}
	// Tenants provisioned before scan/randomkey were denied can still enumerate
	// neighbour key names; withdraw those two commands from every tenant ACL.
	redis.HealScanACL()
	subH := &subdomain.Handlers{DB: d, IPv4: ipv4}
	// A subdomain on a per-tenant PHP-FPM account is served by the tenant's one
	// master whatever version was recorded for it. Bring the record back to what
	// is actually running, for rows written before the panel refused to record
	// anything else and for tenants that move to their own service later.
	subdomain.HealSubdomainPHPVersions(d)
	addonH := &addondomains.Handlers{DB: d, IPv4: ipv4}
	mailH := &mail.Handlers{DB: d}
	mailReportH := &mailreport.Handlers{DB: d}
	mtastsH := &mtasts.Handlers{DB: d, IPv4: ipv4}
	transfersH := &transfers.Handlers{DB: d, Domains: domainsH, Mail: mailH, Cron: cronH}
	domainBlockH := &domainblock.Handlers{DB: d}
	siteSecurityH := sitesecurity.NewHandlers(d)
	appInstallH := &appinstall.Handlers{DB: d}
	optimizeH := &optimize.Handlers{DB: d}
	serverIPH := &serverip.Handlers{DB: d}
	panelPortH := &panelport.Handlers{DB: d}
	hostAppH := &hostapps.Handlers{DB: d}
	// An install runs in this process, so a job still marked running after a
	// restart is one whose process is gone. Left alone it would show an install
	// that never finishes and refuse a second attempt for good.
	hostapps.HealRunningJobs(d)
	// The firewall is what makes a server application reachable, so every change
	// to its port policy has to re-render the ruleset. The hook is wired here
	// because internal/firewall reads the port table directly and a call in the
	// other direction would close an import cycle.
	hostapps.SetReapply(func() {
		if err := firewall.Reapply(d); err != nil {
			log.Printf("host application firewall reapply warn: %v", err)
		}
	})
	// A migration job cannot survive a restart, so close the leftovers and wipe
	// the source credentials they still hold.
	transfersH.HealMigrationsOnStartup()
	sshaccess.EnsureInfra()
	mail.EnsureInfra()
	phpExtH := &phpext.Handlers{DB: d}
	packagesH := &packages.Handlers{DB: d}
	panelSettingsH := &panelsettings.Handlers{DB: d, ServerIPv4: ipv4}
	phpVersionH := &phpversion.Handlers{DB: d}
	appRuntimeH := &appruntime.Handlers{DB: d}
	appsH := &apps.Handlers{DB: d}
	apps.RenderSubdomain = subdomain.ReRender
	apps.HealOnStartup(d)
	// The IonCube Loader is installed automatically. A hook rather than a direct
	// call, because internal/phpext imports internal/phpversion and a call the
	// other way would close the import cycle: a PHP install job appends a call to
	// the binary's hardened -ioncube-install mode so the loader is ready on a new
	// version within the same job.
	phpversion.IonCubePostInstall = phpext.IonCubeInstallShell
	// And the startup heal reaches every version already installed, plus a fresh
	// install: it downloads the archive once and installs the loader for each
	// version missing it, and returns without downloading anything when none are.
	// It runs in the background because it fetches over the network and execs php.
	go phpext.HealIonCube(context.Background())
	// Which malware rule set the scanner is on, for the antivirus settings
	// screen. A hook for the same reason as the line above: internal/antivirus
	// imports internal/avsettings to read the settings, so the dependency
	// cannot be reversed.
	avsettings.RuleSetInUse = func() any { return antivirus.RuleSetInUse() }
	// PERF: move PHP availability discovery (dnf) to a background sweeper so request-path
	// callers like /php/versions never block on a slow or locked dnf.
	phpversion.StartAvailabilitySweeper()
	pluginH := &plugin.Handlers{DB: d}
	go pluginH.HealthLoop(context.Background())

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	// Echo the request ID into the X-Request-Id response header so every response,
	// including error responses, carries a correlation ID for support and log matching.
	r.Use(middleware.RequestIDHeader)
	// Access logging: record request ID, route, status, latency, and client IP
	// for every request so incidents can be diagnosed from backend logs.
	r.Use(middleware.AccessLog)
	// RED metrics: record request rate, errors, and latency for every request.
	r.Use(metrics.Middleware)
	// NOTE: chimw.RealIP is NOT used — it blindly writes spoofable X-Forwarded-For /
	// X-Real-IP / True-Client-IP headers into r.RemoteAddr without a trusted-proxy check,
	// which would bypass login rate-limiting. The real client IP is obtained via
	// httpx.ClientIP (trusts X-Real-IP only from loopback/nginx peer).
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(300 * time.Second))
	r.Use(chimw.Compress(5, "application/json", "text/html", "text/css", "text/javascript", "application/javascript"))
	r.Use(middleware.CORS)
	r.Use(middleware.MaintenanceMode)
	r.Use(middleware.BodyLimit)

	// Public webhook: throttle per IP so a leaked URL cannot drive unbounded
	// repository pulls or unauthenticated DB lookups on invalid secrets.
	r.With(middleware.RateLimit("git-webhook", 30, time.Minute)).
		Post("/api/v1/git-webhook/{secret}", gitH.Webhook)
	r.Post("/api/v1/internal/pma-redeem", pmaH.Redeem)
	// A scheduled task's on-host reporter posts its outcome here over the loopback.
	// It has no panel session; a domain-bound HMAC token stands in for one, so a
	// tenant can only ever report for their own domain. Throttled per IP because it
	// is reachable from every tenant's crontab.
	r.With(middleware.RateLimit("cron-report", 120, time.Minute)).
		Post("/api/v1/internal/cron-report", cronH.Report)
	// Roundcube exchanges a signon token for the master credential over the
	// loopback. It has no panel session either, so the shared secret file and the
	// single-use token are what stand in for one.
	r.Post("/api/v1/internal/webmail-redeem", mailH.WebmailRedeem)

	// Mail client auto-configuration. These cannot sit behind RequireAuth: a mail
	// client has no panel session, which is the whole point of the endpoints. They
	// answer only with what the domain's MX record already reveals, and they are
	// throttled per IP because they are reachable from every tenant vhost.
	r.With(middleware.RateLimit("autoconfig", 60, time.Minute)).
		Get("/.well-known/autoconfig/mail/config-v1.1.xml", autoconfigH.Thunderbird)
	r.With(middleware.RateLimit("autoconfig", 60, time.Minute)).
		Post("/autodiscover/autodiscover.xml", autoconfigH.Outlook)
	// The MTA-STS policy, fetched by a SENDING mail server, which has no panel
	// session either. RFC 8461 fixes both the hostname and this path, so neither
	// is a choice; the vhost only proxies it once the certificate names the
	// policy host, so an unauthenticated request here is already TLS-verified.
	r.With(middleware.RateLimit("mtasts", 60, time.Minute)).
		Get("/.well-known/mta-sts.txt", mtastsH.Policy)
	r.Get("/api/v1/plugin-bundle/{name}/app.js", pluginH.Bundle)

	r.Get("/healthz", func(w http.ResponseWriter, req *http.Request) {
		// Readiness, not just liveness: verify the database dependency so update and
		// restore automation cannot mark a release healthy while DB-backed routes fail.
		ctx, cancel := context.WithTimeout(req.Context(), 3*time.Second)
		defer cancel()
		if err := d.PingContext(ctx); err != nil {
			httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status":  "down",
				"version": version,
				"time":    time.Now().UTC().Format(time.RFC3339),
			})
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"status":  "up",
			"version": version,
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	})

	r.Route("/api/v1", func(r chi.Router) {
		// Brute-force protection: login endpoints are IP rate-limited (see middleware.LoginRateLimit)
		r.With(middleware.LoginRateLimit).Post("/auth/login", authH.Login)
		r.With(middleware.LoginRateLimit).Post("/customer/login", customerH.Login)
		// Logout only clears the HttpOnly session cookie; it needs no auth and must
		// succeed even for an already-invalid session.
		r.With(middleware.LoginRateLimit).Post("/auth/logout", authH.Logout)
		// Server-default panel language — the login screen (no auth yet) reads this.
		r.Get("/public/language", panelSettingsH.Language)

		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth(cfg.JWTSecret))
			// Mounted after RequireAuth because the ceiling is per ACCOUNT: an
			// address can be changed to get a fresh allowance, an identity cannot.
			r.Use(middleware.UploadSlot)
			r.Get("/me", usersH.Me)
			// Language preference — open to EVERY authenticated role (including
			// role=user customers) so anyone can persist their own pref_lang. The
			// broader profile edit below stays ResellerOrAbove.
			r.Put("/me/language", authH.UpdateLanguage)
			// Own account — every panel user (admin + reseller) manages its own
			// profile, password and 2FA. No scope question here: the target is
			// always the token's own user.
			r.With(middleware.ResellerOrAbove).Put("/me", authH.UpdateProfile)
			r.With(middleware.ResellerOrAbove).Get("/dashboard-layout", authH.DashboardLayoutGet)
			r.With(middleware.ResellerOrAbove).Put("/dashboard-layout", authH.DashboardLayoutSave)
			r.With(middleware.ResellerOrAbove).Post("/me/password", authH.ChangePassword)
			r.With(middleware.ResellerOrAbove).Post("/me/sessions/revoke", authH.RevokeSessions)
			r.With(middleware.ResellerOrAbove).Get("/me/2fa/setup", authH.TwoFASetup)
			r.With(middleware.ResellerOrAbove).Post("/me/2fa/enable", authH.TwoFAEnable)
			r.With(middleware.ResellerOrAbove).Post("/me/2fa/disable", authH.TwoFADisable)
			// The notification bell. Deliberately NO role middleware: the whole
			// point is that a customer sees their own domain's alerts, and the
			// narrowing lives in the query, because a row-by-row ownership check
			// does not work on a list endpoint. A panel-wide notification names no
			// domain and is admin-only, which the query says and no middleware
			// tier could.
			r.Get("/notifications", notificationsH.List)
			r.Post("/notifications/read-all", notificationsH.MarkRead)
			r.Post("/notifications/{id}/read", notificationsH.MarkRead)
			// Attack chains are role-scoped inside the handler (admin=panel-wide,
			// reseller/customer=own domains), so no middleware tier here.
			r.Get("/antivirus/chains", chainsH.List)
			// NOTE: /domains can be opened to resellers only after the scope filter
			// (Phase 5D) lands — opening it unfiltered would show every domain.
			r.With(middleware.ResellerOrAbove).Get("/domains", domainsH.List)
			// Central DNS template read is open to resellers (to assign it when
			// adding a customer domain); editing the template is admin's product config.
			r.With(middleware.ResellerOrAbove).Get("/dns-template", dnsH.GetTemplate)
			r.With(middleware.AdminOnly).Put("/dns-template", dnsH.PutTemplate)
			// Shared nameserver pair, published as the NS records of every customer
			// domain. The reseller endpoints are reseller-only on purpose: an admin
			// row in reseller_nameservers would never be read, because a customer
			// managed directly by the admin has a NULL owner_user_id.
			r.With(middleware.AdminOnly).Get("/nameservers", dnsH.GetNameserver)
			r.With(middleware.AdminOnly).Put("/nameservers", dnsH.PutNameserver)
			r.With(middleware.AdminOnly).Post("/nameservers/migrate", dnsH.MigrateNameservers)
			// Adds the mail client discovery records to the template and to every
			// existing zone; the template alone only shapes zones created after it.
			r.With(middleware.AdminOnly).Post("/dns/mail-discovery/migrate", dnsH.MigrateMailDiscovery)
			r.With(middleware.RequireRole(middleware.RoleReseller)).Get("/reseller/nameservers", dnsH.GetResellerNameserver)
			r.With(middleware.RequireRole(middleware.RoleReseller)).Put("/reseller/nameservers", dnsH.PutResellerNameserver)
			// Server-wide read-only overview lists — the sidebar's DNS / SSL /
			// Mail / Databases pages read these. Editing still happens on the
			// domain-scoped endpoints.
			r.With(middleware.ResellerOrAbove).Get("/overview/dns", overviewH.DNS)
			r.With(middleware.ResellerOrAbove).Get("/overview/ssl", overviewH.SSL)
			r.With(middleware.ResellerOrAbove).Get("/overview/mail", overviewH.Mail)
			r.With(middleware.ResellerOrAbove).Get("/overview/databases", overviewH.Databases)
			r.With(middleware.CustomerScope).Get("/domains/{id}", domainsH.Get)
			// Read-only server status — visible so a reseller can offer support
			// (user decision, Phase 5 plan); mutating endpoints stay AdminOnly.
			r.With(middleware.ResellerOrAbove).Get("/system/usage", system.Handler)
			r.With(middleware.ResellerOrAbove).Get("/system/metrics", metrics.Handler)
			r.With(middleware.ResellerOrAbove).Get("/system/services", system.ServiceStatuses)
			r.With(middleware.AdminOnly).Post("/system/service-action", system.ServiceAction)
			r.With(middleware.AdminOnly).Post("/system/reboot", system.Reboot)
			r.With(middleware.AdminOnly).Get("/system/ipv6-addresses", domains.ServerIPv6Addresses)
			r.With(middleware.AdminOnly).Get("/system/hostname", system.HostnameStatus)
			r.With(middleware.AdminOnly).Put("/system/hostname", system.HostnameSave)
			r.With(middleware.AdminOnly).Get("/system/panel-domain", panelSettingsH.Status)
			r.With(middleware.AdminOnly).Post("/system/panel-domain", panelSettingsH.Save)
			r.With(middleware.AdminOnly).Delete("/system/panel-domain", panelSettingsH.Delete)
			r.With(middleware.AdminOnly).Put("/system/panel-language", panelSettingsH.SaveLanguage)
			// Server-wide idle timeout. Admin only: it decides when every other
			// operator's session ends, which is not a per-user preference.
			r.With(middleware.AdminOnly).Get("/system/session-idle", panelSettingsH.SessionIdleGet)
			r.With(middleware.AdminOnly).Put("/system/session-idle", panelSettingsH.SessionIdleSave)
			// The country database is a server-wide integration, so its credentials
			// and download live with the other system settings rather than on a
			// domain. The license key is never returned by any of these.
			r.With(middleware.AdminOnly).Get("/system/geoip", geoIPH.Status)
			r.With(middleware.AdminOnly).Put("/system/geoip/credentials", geoIPH.SaveCredentials)
			r.With(middleware.AdminOnly).Post("/system/geoip/update", geoIPH.Update)
			r.With(middleware.ResellerOrAbove).Get("/system/update", system.UpdateStatus)
			r.With(middleware.AdminOnly).Post("/system/update/start", system.StartUpdate)
			r.With(middleware.AdminOnly).Get("/system/update/log", system.UpdateLog)
			r.With(middleware.ResellerOrAbove).Get("/system/version-check", system.VersionCheckStatus)
			r.With(middleware.AdminOnly).Post("/system/version-check/refresh", system.VersionCheckRefresh)
			// Deliberately without a role: the footer names the panel version to
			// every signed-in account, customers included. It carries only this
			// installation's own version and build date, never the update or
			// announcement data /system/version-check holds.
			r.Get("/system/version", system.VersionInfo)
			r.With(middleware.ResellerOrAbove).Get("/system/optimize", system.OptimizeStatus)
			r.With(middleware.AdminOnly).Post("/system/optimize/start", system.OptimizeStart)
			r.With(middleware.AdminOnly).Get("/system/optimize/log", system.OptimizeLog)
			// The parameter-by-parameter surface sits BESIDE the whole-pass run
			// above rather than replacing it. The run applies everything and
			// tells the operator what it did; these let them agree to one line
			// at a time and put one line back.
			r.With(middleware.AdminOnly).Get("/system/optimize/proposals", optimizeH.Proposals)
			r.With(middleware.AdminOnly).Post("/system/optimize/apply", optimizeH.ApplyChosen)
			r.With(middleware.AdminOnly).Get("/system/optimize/history", optimizeH.ListHistory)
			r.With(middleware.AdminOnly).Post("/system/optimize/history/{id}/revert", optimizeH.RevertChange)
			// Additional server addresses. Admin only, and the list comes off
			// the HOST rather than the panel's table, so an address configured
			// outside the panel is shown and is not removable here.
			r.With(middleware.AdminOnly).Get("/system/ips", serverIPH.List)
			r.With(middleware.AdminOnly).Post("/system/ips", serverIPH.Add)
			r.With(middleware.AdminOnly).Delete("/system/ips/{id}", serverIPH.Remove)
			// The panel's own ports. Admin only, and a backend change is
			// answered 202: it restarts this process, so the verdict arrives
			// through the outcome file rather than through the response.
			r.With(middleware.AdminOnly).Get("/system/panel-port", panelPortH.Status)
			r.With(middleware.AdminOnly).Post("/system/panel-port", panelPortH.Change)
			r.With(middleware.AdminOnly).Get("/system/panel-port/history", panelPortH.History)
			// Server-level applications. Every route is AdminOnly and there is no
			// scoped variant: these belong to no customer, so there is no
			// ownership chain to narrow them by.
			r.With(middleware.AdminOnly).Get("/system/host-apps", hostAppH.List)
			r.With(middleware.AdminOnly).Post("/system/host-apps", hostAppH.Install)
			r.With(middleware.AdminOnly).Get("/system/host-apps/jobs", hostAppH.Jobs)
			r.With(middleware.AdminOnly).Put("/system/host-apps/enabled", hostAppH.SetEnabled)
			r.With(middleware.AdminOnly).Delete("/system/host-apps/{id}", hostAppH.Remove)
			r.With(middleware.AdminOnly).Post("/system/host-apps/{id}/action", hostAppH.Action)
			r.With(middleware.AdminOnly).Put("/system/host-apps/{id}/firewall", hostAppH.Firewall)
			r.With(middleware.AdminOnly).Get("/system/host-apps/{id}/logs", hostAppH.Logs)
			r.With(middleware.AdminOnly).Get("/system/ssh-security", system.SSHSecurity)
			r.With(middleware.AdminOnly).Get("/system/cve", system.CveStatus)
			r.With(middleware.AdminOnly).Post("/system/cve/update", system.CveUpdate)
			r.With(middleware.AdminOnly).Get("/system/cve/log", system.CveLog)
			r.With(middleware.AdminOnly).Get("/system/kernelcare", system.KernelcareStatusHandler)
			r.With(middleware.AdminOnly).Post("/system/kernelcare/patch", system.KernelcarePatch)
			pluginH.Routes(r)
			// Process list and system logs stay admin-only: they leak other
			// tenants' processes/logs, which is more than "server health".
			r.With(middleware.AdminOnly).Get("/system/processes", monitor.Processes)
			r.With(middleware.ResellerOrAbove).Get("/system/load-history", monitorH.LoadHistory)
			r.With(middleware.AdminOnly).Get("/admin/system/logs", monitorH.ServerLog)
			// Server-wide slow query shapes. AdminOnly, not ResellerOrAbove: the
			// list names every tenant on the host, and a reseller sees only its
			// own customers everywhere else.
			r.With(middleware.AdminOnly).Get("/admin/slow-queries", slowQueryH.List)
			r.With(middleware.AdminOnly).Get("/admin/slow-queries/status", slowQueryH.Status)
			r.With(middleware.AdminOnly).Put("/admin/slow-queries/settings", slowQueryH.Save)
			r.With(middleware.AdminOnly).Get("/admin/db-remote", dbRemoteH.ServerGet)
			r.With(middleware.AdminOnly).Put("/admin/db-remote", dbRemoteH.ServerSet)
			r.With(middleware.CustomerScope).Get("/domains/{id}/health", monitorH.Health)

			// Write + customer-scope routes — authorised per-route with AdminOnly/CustomerScope
			r.Group(func(r chi.Router) {
				r.With(middleware.ResellerOrAbove).Post("/domains", domainsH.Create)
				r.With(middleware.AdminOnly).Post("/domains/{id}/suspend", domainsH.Suspend)
				r.With(middleware.AdminOnly).Post("/domains/{id}/resume", domainsH.Resume)
				// The address a domain answers on over IPv6. Administrator-only
				// because it must be an address this server really carries, and
				// the operator is the only party who knows which those are.
				r.With(middleware.AdminOnly).Put("/domains/{id}/ipv6", domainsH.SetIPv6)
				// Deleting a whole subscription is destructive and irreversible, so it
				// requires an administrator; a customer token must not delete its own
				// domain, databases, Linux user, and service state without admin mediation.
				r.With(middleware.AdminOnly).Delete("/domains/{id}", domainsH.Delete)
				// A reseller may move a domain between its own customers. The
				// authorization is in the handler, not here: it has to narrow the
				// source domains by scope AND check the target customer, and only an
				// admin may detach a domain entirely.
				r.With(middleware.ResellerOrAbove).Post("/domains/bulk/owner", domainsH.BulkOwner)
				r.With(middleware.AdminOnly).Post("/domains/bulk/status", domainsH.BulkStatus)
				r.With(middleware.CustomerScope).Put("/domains/{id}/php", domainsH.SetPHP)
				r.With(middleware.CustomerScope).Get("/domains/{id}/ssh", sshH.Show)
				r.With(middleware.AdminOnly).Put("/domains/{id}/ssh", sshH.Configure)
				r.With(middleware.AdminOnly).Put("/domains/{id}/ssh/key", sshH.SaveKey)
				r.With(middleware.CustomerScope).Get("/domains/{id}/statistics", statH.Show)
				r.With(middleware.CustomerScope).Get("/domains/{id}/subdomain/{sid}/statistics", statH.Show)
				r.With(middleware.CustomerScope).Get("/domains/{id}/performance", perfH.Show)
				// A site owner sees their own slowest query shapes. The server-wide
				// view names every tenant, so it is admin-only and mounted below.
				r.With(middleware.CustomerScope).Get("/domains/{id}/slow-queries", slowQueryH.ListForDomain)
				r.With(middleware.CustomerScope).Get("/domains/{id}/db-remote", dbRemoteH.DomainList)
				r.With(middleware.CustomerScope).Post("/domains/{id}/db-remote", dbRemoteH.DomainAdd)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/db-remote/{hid}", dbRemoteH.DomainDelete)
				r.With(middleware.CustomerScope).Get("/domains/{id}/composer", compH.Status)
				r.With(middleware.CustomerScope).Post("/domains/{id}/composer", compH.Run)
				r.With(middleware.CustomerScope).Get("/domains/{id}/subdomain/{sid}/composer", compH.Status)
				r.With(middleware.CustomerScope).Post("/domains/{id}/subdomain/{sid}/composer", compH.Run)
				r.With(middleware.CustomerScope).Get("/domains/{id}/laravel", laravelH.Status)
				r.With(middleware.CustomerScope).Post("/domains/{id}/laravel/install", laravelH.Install)
				r.With(middleware.CustomerScope).Get("/domains/{id}/laravel/install/status", laravelH.InstallStatus)
				r.With(middleware.CustomerScope).Post("/domains/{id}/laravel/artisan", laravelH.Artisan)
				r.With(middleware.CustomerScope).Post("/domains/{id}/laravel/composer", laravelH.Composer)
				r.With(middleware.CustomerScope).Post("/domains/{id}/laravel/npm", laravelH.Npm)
				r.With(middleware.CustomerScope).Get("/domains/{id}/laravel/node", laravelH.NodeVersions)
				r.With(middleware.CustomerScope).Get("/domains/{id}/laravel/env", laravelH.EnvRead)
				r.With(middleware.CustomerScope).Put("/domains/{id}/laravel/env", laravelH.EnvWrite)
				r.With(middleware.CustomerScope).Post("/domains/{id}/laravel/maintenance", laravelH.Maintenance)
				r.With(middleware.CustomerScope).Post("/domains/{id}/laravel/deploy", laravelH.Deploy)
				r.With(middleware.CustomerScope).Get("/domains/{id}/laravel/deploy/status", laravelH.DeployStatus)
				r.With(middleware.CustomerScope).Get("/domains/{id}/laravel/app-candidates", laravelH.AppCandidates)
				r.With(middleware.CustomerScope).Put("/domains/{id}/laravel/app-root", laravelH.SetAppRoot)
				r.With(middleware.CustomerScope).Post("/domains/{id}/laravel/schedule", laravelH.Schedule)
				r.With(middleware.CustomerScope).Get("/domains/{id}/laravel/workers", laravelH.WorkerList)
				r.With(middleware.CustomerScope).Post("/domains/{id}/laravel/workers", laravelH.WorkerCreate)
				r.With(middleware.CustomerScope).Put("/domains/{id}/laravel/workers/{wid}", laravelH.WorkerUpdate)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/laravel/workers/{wid}", laravelH.WorkerDelete)
				r.With(middleware.CustomerScope).Post("/domains/{id}/laravel/workers/{wid}/restart", laravelH.WorkerRestart)
				r.With(middleware.CustomerScope).Get("/domains/{id}/laravel/workers/{wid}/log", laravelH.WorkerLog)
				r.With(middleware.CustomerScope).Get("/domains/{id}/redis", redisH.Status)
				r.With(middleware.CustomerScope).Post("/domains/{id}/redis", redisH.Open)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/redis", redisH.Close)
				r.With(middleware.CustomerScope).Get("/domains/{id}/mail/status", mailH.MailStatus)
				r.With(middleware.CustomerScope).Post("/domains/{id}/mail/enable", mailH.Enable)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/mail/enable", mailH.Disable)
				// Irreversible removal, mailboxes and stored messages included. A route of
				// its own, not a flag on the reversible one, so it cannot be reached by
				// accident. The static segment wins over /mail/{mid} below, exactly as
				// /mail/enable already does.
				r.With(middleware.CustomerScope).Delete("/domains/{id}/mail/service", mailH.Purge)
				r.With(middleware.CustomerScope).Get("/domains/{id}/mail", mailH.List)
				r.With(middleware.CustomerScope).Post("/domains/{id}/mail", mailH.Create)
				// Static segments again, so they win over /mail/{mid} below.
				//
				// Both reach a server the CALLER names. Discovery fans out into DNS
				// lookups, four HTTPS fetches and a round of TCP probes, and
				// verification performs a full IMAP sign-in with a username and
				// password the caller supplies. Without a cap the panel is a mail
				// password guesser that answers from the server's own address, which
				// is how that address ends up on a blocklist. A real migration needs
				// one verification, so these bounds are invisible to honest use.
				migrationProbe := middleware.RateLimit("mail-migration-discover", 20, time.Minute)
				migrationLogin := middleware.RateLimit("mail-migration-verify", 10, time.Minute)
				r.With(middleware.CustomerScope, migrationProbe).Post("/domains/{id}/mail/migration/discover", mailH.Discover)
				r.With(middleware.CustomerScope, migrationLogin).Post("/domains/{id}/mail/migration/verify", mailH.Verify)
				r.With(middleware.CustomerScope).Get("/domains/{id}/mail/aliases", mailH.ListAliases)
				r.With(middleware.CustomerScope).Post("/domains/{id}/mail/aliases", mailH.CreateAlias)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/mail/aliases/{aid}", mailH.DeleteAlias)
				r.With(middleware.CustomerScope).Post("/domains/{id}/mail/aliases/{aid}/status", mailH.SetAliasStatus)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/mail/{mid}", mailH.Delete)
				r.With(middleware.CustomerScope).Put("/domains/{id}/mail/{mid}/password", mailH.ResetPassword)
				r.With(middleware.CustomerScope).Post("/domains/{id}/mail/{mid}/status", mailH.SetStatus)
				r.With(middleware.CustomerScope).Get("/domains/{id}/mail/delivery-log", mailH.DeliveryLog)
				// Deliverability reports. Mounted beside /domains/{id}/mail rather
				// than under it, because every route there takes a {mid} mailbox
				// parameter and a literal segment next to that wildcard reads as a
				// mailbox named "reports".
				r.With(middleware.CustomerScope).Get("/domains/{id}/mail-reports", mailReportH.Status)
				r.With(middleware.CustomerScope).Get("/domains/{id}/mail-reports/dmarc", mailReportH.DMARC)
				r.With(middleware.CustomerScope).Get("/domains/{id}/mail-reports/tlsrpt", mailReportH.TLSRPT)
				// MTA-STS publication, mounted beside the reports for the same
				// reason. Enforce is refused on this write path, not only on the
				// screen that renders the control.
				r.With(middleware.CustomerScope).Get("/domains/{id}/mail-mtasts", mtastsH.Get)
				r.With(middleware.CustomerScope).Post("/domains/{id}/mail-mtasts", mtastsH.Post)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/mail-mtasts", mtastsH.Delete)
				r.With(middleware.CustomerScope).Get("/domains/{id}/mail/spam", mailH.SpamGet)
				r.With(middleware.CustomerScope).Put("/domains/{id}/mail/spam", mailH.SpamPut)
				r.With(middleware.AdminOnly).Get("/admin/mail/settings", mailH.ServerSettingsGet)
				r.With(middleware.AdminOnly).Put("/admin/mail/settings", mailH.ServerSettingsPut)
				r.With(middleware.AdminOnly).Get("/admin/mail/ip-pool", mailH.PoolList)
				r.With(middleware.AdminOnly).Post("/admin/mail/ip-pool", mailH.PoolAdd)
				r.With(middleware.AdminOnly).Put("/admin/mail/ip-pool/{pid}", mailH.PoolUpdate)
				r.With(middleware.AdminOnly).Delete("/admin/mail/ip-pool/{pid}", mailH.PoolDelete)
				// Which address a domain sends from is an operator decision, not a
				// customer one: it moves reputation between tenants.
				r.With(middleware.AdminOnly).Put("/domains/{id}/mail/outbound-ip", mailH.DomainOutboundPut)
				r.With(middleware.AdminOnly).Get("/admin/mail/filters", mailH.FilterListGet)
				r.With(middleware.AdminOnly).Post("/admin/mail/filters", mailH.FilterListCreate)
				r.With(middleware.AdminOnly).Delete("/admin/mail/filters/{fid}", mailH.FilterListDelete)
				r.With(middleware.AdminOnly).Get("/admin/mail/queue", mailH.QueueList)
				r.With(middleware.AdminOnly).Post("/admin/mail/queue", mailH.QueueAction)
				r.With(middleware.CustomerScope).Get("/domains/{id}/mail/{mid}/autoresponder", mailH.AutoresponderGet)
				r.With(middleware.CustomerScope).Put("/domains/{id}/mail/{mid}/autoresponder", mailH.AutoresponderPut)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/mail/{mid}/autoresponder", mailH.AutoresponderDelete)
				r.With(middleware.CustomerScope).Get("/domains/{id}/mail/filters", mailH.FilterList)
				r.With(middleware.CustomerScope).Post("/domains/{id}/mail/filters", mailH.FilterCreate)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/mail/filters/{fid}", mailH.FilterDelete)
				r.With(middleware.CustomerScope).Get("/domains/{id}/mail/{mid}/send-limits", mailH.SendLimitsGet)
				r.With(middleware.CustomerScope).Put("/domains/{id}/mail/{mid}/send-limits", mailH.SendLimitsPut)
				r.With(middleware.CustomerScope).Post("/domains/{id}/mail/{mid}/webmail-token", mailH.WebmailToken)
				r.With(middleware.CustomerScope).Get("/domains/{id}/mail/{mid}/connection", mailH.ConnectionSettings)
				r.With(middleware.CustomerScope).Get("/domains/{id}/mail/{mid}/export", mailH.Export)
				r.With(middleware.CustomerScope).Get("/domains/{id}/mail/{mid}/import", mailH.ImportFormats)
				r.With(middleware.CustomerScope).Post("/domains/{id}/mail/{mid}/import", mailH.Import)
				r.With(middleware.CustomerScope).Post("/domains/{id}/mail/{mid}/quota-recalc", mailH.QuotaRecalc)
				r.With(middleware.CustomerScope).Get("/domains/{id}/mail/{mid}/forwarding", mailH.ForwardingGet)
				r.With(middleware.CustomerScope).Put("/domains/{id}/mail/{mid}/forwarding", mailH.ForwardingPut)
				// Starting a copy signs in to the remote server before it records
				// anything, so a refused password here costs nothing and leaves no
				// row: the same guessing channel as /migration/verify, and it shares
				// that counter rather than getting a separate allowance.
				r.With(middleware.CustomerScope, migrationLogin).Post("/domains/{id}/mail/{mid}/migration", mailH.StartMigration)
				r.With(middleware.CustomerScope).Get("/domains/{id}/mail/{mid}/migration", mailH.MigrationStatus)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/mail/{mid}/migration", mailH.CancelMigration)
				// Maintenance mode. The site owner turns their own site off, so
				// this is CustomerScope like the other per-domain protections;
				// CustomerScope already refuses a suspended customer.
				r.With(middleware.CustomerScope).Get("/domains/{id}/maintenance", domainsH.MaintenanceStatus)
				r.With(middleware.CustomerScope).Put("/domains/{id}/maintenance", domainsH.MaintenanceSave)
				r.With(middleware.CustomerScope).Post("/domains/{id}/maintenance/ips", domainsH.MaintenanceIPAdd)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/maintenance/ips/{ipid}", domainsH.MaintenanceIPDelete)
				r.With(middleware.CustomerScope).Get("/domains/{id}/protection", protectionH.List)
				r.With(middleware.CustomerScope).Post("/domains/{id}/protection", protectionH.Add)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/protection/{kid}", protectionH.Delete)
				r.With(middleware.CustomerScope).Get("/domains/{id}/subdomain/{sid}/protection", protectionH.List)
				r.With(middleware.CustomerScope).Post("/domains/{id}/subdomain/{sid}/protection", protectionH.Add)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/subdomain/{sid}/protection/{kid}", protectionH.Delete)
				r.With(middleware.CustomerScope).Get("/domains/{id}/antivirus", avH.Status)
				r.With(middleware.CustomerScope).Post("/domains/{id}/antivirus/scan", avH.Scan)
				r.With(middleware.CustomerScope).Get("/domains/{id}/antivirus/scan/{sid}", avH.ScanStatus)
				r.With(middleware.CustomerScope).Get("/domains/{id}/antivirus/quarantine", avH.QuarantineList)
				r.With(middleware.CustomerScope).Post("/domains/{id}/antivirus/quarantine", avH.Quarantine)
				r.With(middleware.CustomerScope).Post("/domains/{id}/antivirus/quarantine/all", avH.QuarantineAll)
				r.With(middleware.CustomerScope).Post("/domains/{id}/antivirus/quarantine/{qid}/restore", avH.QuarantineRestore)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/antivirus/quarantine/{qid}", avH.QuarantineDelete)
				// Restoring used to be a blind decision: the screen offered to put a
				// file back without ever showing what was in it.
				r.With(middleware.CustomerScope).Get("/domains/{id}/antivirus/quarantine/{qid}/inspect", avH.QuarantineInspect)
				r.With(middleware.AdminOnly).Post("/domains/{id}/antivirus/update-signature", avH.UpdateSignature)
				// Generic import: a site archive, a SQL dump and the config rewrite
				// that points the imported application at its new database.
				r.With(middleware.CustomerScope).Post("/domains/{id}/import/archive", importH.UploadArchive)
				r.With(middleware.CustomerScope).Post("/domains/{id}/import/archive/apply", importH.ApplyArchive)
				r.With(middleware.CustomerScope).Post("/domains/{id}/import/sql", importH.UploadSQL)
				r.With(middleware.CustomerScope).Post("/domains/{id}/import/config", importH.RewriteConfig)
				r.With(middleware.CustomerScope).Get("/domains/{id}/copy", copyH.List)
				r.With(middleware.CustomerScope).Post("/domains/{id}/copy", copyH.Create)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/copy/{name}", copyH.Delete)
				r.With(middleware.CustomerScope).Get("/domains/{id}/wordpress", wpH.List)
				r.With(middleware.CustomerScope).Post("/domains/{id}/wordpress", wpH.Install)
				r.With(middleware.CustomerScope).Post("/domains/{id}/wordpress/update", wpH.Update)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/wordpress", wpH.Delete)
				// WordPress Toolkit — plugin/theme/user management + repair + tools
				r.With(middleware.CustomerScope).Get("/domains/{id}/wordpress/status", wpH.Status)
				r.With(middleware.CustomerScope).Get("/domains/{id}/wordpress/plugins", wpH.Plugins)
				r.With(middleware.CustomerScope).Post("/domains/{id}/wordpress/plugin", wpH.PluginAction)
				r.With(middleware.CustomerScope).Get("/domains/{id}/wordpress/themes", wpH.Themes)
				r.With(middleware.CustomerScope).Post("/domains/{id}/wordpress/theme", wpH.ThemeAction)
				r.With(middleware.CustomerScope).Get("/domains/{id}/wordpress/users", wpH.Users)
				r.With(middleware.CustomerScope).Post("/domains/{id}/wordpress/user-password", wpH.UserPassword)
				r.With(middleware.CustomerScope).Post("/domains/{id}/wordpress/repair", wpH.Repair)
				r.With(middleware.CustomerScope).Post("/domains/{id}/wordpress/verify", wpH.VerifyChecksums)
				r.With(middleware.CustomerScope).Post("/domains/{id}/wordpress/tool", wpH.ToolAction)
				r.With(middleware.ResellerOrAbove).Get("/wordpress/all", wpH.ListAll)

				// Subdomain-scoped WordPress: the same handlers resolve {sid} to the
				// subdomain's document root instead of the parent domain's public_html.
				r.With(middleware.CustomerScope).Get("/domains/{id}/subdomain/{sid}/wordpress", wpH.List)
				r.With(middleware.CustomerScope).Post("/domains/{id}/subdomain/{sid}/wordpress", wpH.Install)
				r.With(middleware.CustomerScope).Post("/domains/{id}/subdomain/{sid}/wordpress/update", wpH.Update)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/subdomain/{sid}/wordpress", wpH.Delete)
				r.With(middleware.CustomerScope).Get("/domains/{id}/subdomain/{sid}/wordpress/status", wpH.Status)
				r.With(middleware.CustomerScope).Get("/domains/{id}/subdomain/{sid}/wordpress/plugins", wpH.Plugins)
				r.With(middleware.CustomerScope).Post("/domains/{id}/subdomain/{sid}/wordpress/plugin", wpH.PluginAction)
				r.With(middleware.CustomerScope).Get("/domains/{id}/subdomain/{sid}/wordpress/themes", wpH.Themes)
				r.With(middleware.CustomerScope).Post("/domains/{id}/subdomain/{sid}/wordpress/theme", wpH.ThemeAction)
				r.With(middleware.CustomerScope).Get("/domains/{id}/subdomain/{sid}/wordpress/users", wpH.Users)
				r.With(middleware.CustomerScope).Post("/domains/{id}/subdomain/{sid}/wordpress/user-password", wpH.UserPassword)
				r.With(middleware.CustomerScope).Post("/domains/{id}/subdomain/{sid}/wordpress/repair", wpH.Repair)
				r.With(middleware.CustomerScope).Post("/domains/{id}/subdomain/{sid}/wordpress/tool", wpH.ToolAction)
				r.With(middleware.AdminOnly).Get("/firewall", fwH.List)
				r.With(middleware.AdminOnly).Post("/firewall", fwH.Add)
				r.With(middleware.AdminOnly).Post("/firewall/template", fwH.Template)
				r.With(middleware.AdminOnly).Delete("/firewall/{id}", fwH.Delete)
				r.With(middleware.AdminOnly).Post("/firewall/{id}/status", fwH.Status)
				// Server-wide country blocks. They drop at the packet level, so unlike
				// the per-domain rules they cover every port; nftables never sees a
				// Host header, so this cannot be scoped to one site.
				r.With(middleware.AdminOnly).Get("/firewall/geo", fwH.ListGeo)
				r.With(middleware.AdminOnly).Post("/firewall/geo", fwH.AddGeo)
				r.With(middleware.AdminOnly).Delete("/firewall/geo/{code}", fwH.DeleteGeo)
				r.With(middleware.ResellerOrAbove).Get("/subdomains", subH.ListAll)
				r.With(middleware.CustomerScope).Get("/domains/{id}/subdomain", subH.List)
				r.With(middleware.CustomerScope).Post("/domains/{id}/subdomain", subH.Create)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/subdomain/{sid}", subH.Delete)
				r.With(middleware.CustomerScope).Get("/domains/{id}/subdomain/{sid}", subH.Detail)
				r.With(middleware.CustomerScope).Put("/domains/{id}/subdomain/{sid}/php", subH.SetPHP)
				r.With(middleware.CustomerScope).Get("/domains/{id}/subdomain/{sid}/ssl", subH.SSLStatus)
				r.With(middleware.CustomerScope).Post("/domains/{id}/subdomain/{sid}/ssl", subH.SSLIssue)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/subdomain/{sid}/ssl", subH.SSLRemove)
				r.With(middleware.CustomerScope).Get("/domains/{id}/addon-domains", addonH.List)
				r.With(middleware.CustomerScope).Post("/domains/{id}/addon-domains", addonH.Create)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/addon-domains/{addonID}", addonH.Delete)
				r.With(middleware.CustomerScope).Get("/domains/{id}/redirect", domainsH.RedirectStatus)
				r.With(middleware.CustomerScope).Put("/domains/{id}/redirect", domainsH.SetRedirect)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/redirect", domainsH.DeleteRedirect)
				r.With(middleware.CustomerScope).Get("/domains/{id}/www-redirect", domainsH.WWWRedirectStatus)
				r.With(middleware.CustomerScope).Put("/domains/{id}/www-redirect", domainsH.SetWWWRedirect)
				r.With(middleware.CustomerScope).Get("/domains/{id}/web-backend", domainsH.GetWebBackend)
				r.With(middleware.CustomerScope).Put("/domains/{id}/web-backend", domainsH.SetWebBackend)
				r.With(middleware.CustomerScope).Get("/domains/{id}/subdomain/{sid}/web-backend", subH.GetWebBackend)
				r.With(middleware.CustomerScope).Put("/domains/{id}/subdomain/{sid}/web-backend", subH.SetWebBackend)
				r.With(middleware.CustomerScope).Get("/domains/{id}/web-root", domainsH.GetWebRoot)
				r.With(middleware.CustomerScope).Put("/domains/{id}/web-root", domainsH.SetWebRoot)
				r.With(middleware.CustomerScope).Put("/domains/{id}/ftp/password", domainsH.SetFTPPassword)
				r.With(middleware.CustomerScope).Get("/domains/{id}/ftp/password-show", domainsH.ShowFTPPassword)
				r.With(middleware.CustomerScope).Get("/domains/{id}/databases", domainsH.ListDatabases)
				r.With(middleware.CustomerScope).Post("/domains/{id}/databases", domainsH.CreateDatabase)
				r.With(middleware.AdminOnly).Delete("/databases/{dbid}", domainsH.DeleteDatabase)
				r.With(middleware.AdminOnly).Put("/databases/{dbid}/password", domainsH.SetDatabasePassword)
				r.With(middleware.AdminOnly).Post("/databases/{dbid}/optimize", domainsH.OptimizeDatabase)
				r.With(middleware.CustomerScope).Get("/domains/{id}/files", filesH.List)
				r.With(middleware.CustomerScope).Get("/domains/{id}/files/read", filesH.Read)
				r.With(middleware.CustomerScope).Get("/domains/{id}/files/download", filesH.Download)
				r.With(middleware.CustomerScope).Post("/domains/{id}/files/mkdir", filesH.Mkdir)
				r.With(middleware.CustomerScope).Post("/domains/{id}/files/upload", filesH.Upload)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/files", filesH.Delete)
				r.With(middleware.CustomerScope).Post("/domains/{id}/files/write", filesH.Write)
				r.With(middleware.CustomerScope).Post("/domains/{id}/files/rename", filesH.Rename)
				r.With(middleware.CustomerScope).Post("/domains/{id}/files/chmod", filesH.Chmod)
				r.With(middleware.CustomerScope).Post("/domains/{id}/files/reset-permissions", filesH.ResetPermissions)
				// Expensive file operations (recursive walks, archive extraction/creation,
				// du, find) are throttled per IP so a customer cannot exhaust CPU/disk/IO
				// by launching them in a tight loop. new-file stays unthrottled (cheap).
				fileHeavy := middleware.RateLimit("files-heavy", 60, time.Minute)
				r.With(middleware.CustomerScope, fileHeavy).Post("/domains/{id}/files/extract", filesH.Extract)
				r.With(middleware.CustomerScope).Get("/domains/{id}/files/extract-progress", filesH.ExtractProgress)
				r.With(middleware.CustomerScope, fileHeavy).Post("/domains/{id}/files/copy", filesH.Copy)
				r.With(middleware.CustomerScope, fileHeavy).Post("/domains/{id}/files/move", filesH.Move)
				r.With(middleware.CustomerScope, fileHeavy).Post("/domains/{id}/files/archive", filesH.Archive)
				r.With(middleware.CustomerScope).Post("/domains/{id}/files/new-file", filesH.NewFile)
				r.With(middleware.CustomerScope, fileHeavy).Get("/domains/{id}/files/size", filesH.CalculateSize)
				r.With(middleware.CustomerScope, fileHeavy).Get("/domains/{id}/files/search", filesH.Search)
				r.With(middleware.CustomerScope).Get("/domains/{id}/ssl", domainsH.SSLStatus)
				r.With(middleware.CustomerScope).Post("/domains/{id}/ssl/issue", domainsH.SSLIssue)
				r.With(middleware.CustomerScope).Get("/domains/{id}/ssl/progress", domainsH.SSLProgress)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/ssl", domainsH.SSLDisable)
				r.With(middleware.CustomerScope).Get("/domains/{id}/cron", cronH.List)
				r.With(middleware.CustomerScope).Post("/domains/{id}/cron", cronH.Create)
				r.With(middleware.CustomerScope).Put("/domains/{id}/cron/{idx}", cronH.Update)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/cron/{idx}", cronH.Delete)
				r.With(middleware.CustomerScope).Post("/domains/{id}/cron/{idx}/run", cronH.Run)
				r.With(middleware.CustomerScope).Get("/domains/{id}/logs", logsH.List)
				r.With(middleware.CustomerScope).Get("/domains/{id}/logs/read", logsH.Read)
				r.With(middleware.CustomerScope).Get("/domains/{id}/logs/live", logsH.Tail)
				r.With(middleware.CustomerScope).Get("/domains/{id}/subdomain/{sid}/logs", logsH.List)
				r.With(middleware.CustomerScope).Get("/domains/{id}/subdomain/{sid}/logs/read", logsH.Read)
				r.With(middleware.CustomerScope).Get("/domains/{id}/subdomain/{sid}/logs/live", logsH.Tail)
				r.With(middleware.CustomerScope).Post("/domains/{id}/calculate-disk", domainsH.CalculateDisk)
				// Plan read is open to resellers (so they can assign a plan to
				// their customer); plan create/edit is admin's product definition.
				r.With(middleware.ResellerOrAbove).Get("/plans", plansH.List)
				r.With(middleware.ResellerOrAbove).Get("/plans/{id}", plansH.Get)
				r.With(middleware.AdminOnly).Post("/plans", plansH.Create)
				r.With(middleware.AdminOnly).Put("/plans/{id}", plansH.Update)
				r.With(middleware.AdminOnly).Delete("/plans/{id}", plansH.Delete)
				r.With(middleware.AdminOnly).Get("/plans/{id}/domains", plansH.SearchDomains)
				r.With(middleware.AdminOnly).Put("/domains/{id}/plan", domainsH.SetPlan)
				r.With(middleware.CustomerScope).Get("/domains/{id}/dns", dnsH.List)
				r.With(middleware.CustomerScope).Post("/domains/{id}/dns", dnsH.Create)
				r.With(middleware.CustomerScope).Put("/domains/{id}/dns/{rid}", dnsH.Update)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/dns/{rid}", dnsH.Delete)
				r.With(middleware.CustomerScope).Post("/domains/{id}/dns/template", dnsH.ApplyTemplate)
				r.With(middleware.CustomerScope).Post("/domains/{id}/dns/bulk-delete", dnsH.BulkDelete)
				r.With(middleware.CustomerScope).Post("/domains/{id}/dns/bulk-status", dnsH.BulkStatus)
				r.With(middleware.CustomerScope).Get("/domains/{id}/nameservers", dnsH.GetDomainNameserver)
				r.With(middleware.CustomerScope).Get("/domains/{id}/dns/verify", dnsH.Verify)
				r.With(middleware.CustomerScope).Get("/domains/{id}/dns/soa", dnsH.GetSOA)
				r.With(middleware.CustomerScope).Put("/domains/{id}/dns/soa", dnsH.PutSOA)
				r.With(middleware.CustomerScope).Get("/domains/{id}/dns/dnssec", dnsH.GetDNSSEC)
				r.With(middleware.CustomerScope).Post("/domains/{id}/dns/dnssec", dnsH.PostDNSSEC)
				r.With(middleware.CustomerScope).Get("/domains/{id}/dns/export", dnsH.Export)  // BIND zone export
				r.With(middleware.CustomerScope).Post("/domains/{id}/dns/import", dnsH.Import) // BIND zone import
				// Security log (read-only) — audit_log has been written to for a
				// long time but had no read endpoint.
				// A reseller sees only entries scoped to its own reseller_id; an
				// admin sees every entry (scope filter applied inside the handler).
				r.With(middleware.ResellerOrAbove).Get("/audit", authH.AuditList)
				r.With(middleware.ResellerOrAbove).Get("/audit/actions", authH.AuditActions)
				// Panel accounts (admin + reseller). Scope narrowing lives inside
				// the handlers: a reseller only sees / manages the accounts below
				// it and may create accounts in the 'user' role only.
				r.With(middleware.ResellerOrAbove).Get("/users", usersH.List)
				r.With(middleware.ResellerOrAbove).Post("/users", usersH.Create)
				r.With(middleware.ResellerOrAbove).Put("/users/{id}", usersH.Update)
				r.With(middleware.ResellerOrAbove).Post("/users/{id}/password", usersH.ResetPassword)
				r.With(middleware.ResellerOrAbove).Post("/users/{id}/status", usersH.SetStatus)
				r.With(middleware.ResellerOrAbove).Delete("/users/{id}", usersH.Delete)
				// Reseller quotas: a reseller may not even read its own limit —
				// writing is privilege escalation and reading is the preparation
				// for it, so both stay AdminOnly.
				r.With(middleware.AdminOnly).Get("/users/{id}/limits", usersH.GetLimits)
				r.With(middleware.AdminOnly).Put("/users/{id}/limits", usersH.SaveLimits)
				r.With(middleware.ResellerOrAbove).Get("/customers", accountsH.ListCustomers)
				r.With(middleware.ResellerOrAbove).Post("/customers", accountsH.CreateCustomer)
				r.With(middleware.ResellerOrAbove).Put("/customers/{id}", accountsH.UpdateCustomer)
				r.With(middleware.ResellerOrAbove).Delete("/customers/{id}", accountsH.DeleteCustomer)
				r.With(middleware.CustomerScope).Get("/domains/{id}/backups", backupsH.List)
				// Manual backups are CPU/disk/IO heavy; throttle per IP (the handler also
				// rejects a second concurrent backup for the same domain).
				r.With(middleware.CustomerScope, middleware.RateLimit("backup-create", 20, time.Hour)).
					Post("/domains/{id}/backups", backupsH.Create)
				r.With(middleware.CustomerScope).Get("/domains/{id}/backups/{bid}/download", backupsH.Download)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/backups/{bid}", backupsH.Delete)
				r.With(middleware.CustomerScope).Get("/domains/{id}/backups/{bid}/contents", backupsH.Contents)
				r.With(middleware.CustomerScope).Post("/domains/{id}/backups/{bid}/restore", backupsH.Restore)
				r.With(middleware.CustomerScope).Get("/domains/{id}/backup-schedule", backupsH.GetSchedule)
				r.With(middleware.CustomerScope).Put("/domains/{id}/backup-schedule", backupsH.SetSchedule)
				r.With(middleware.AdminOnly).Post("/admin/backups/tick", backupsH.TickNow)
				r.With(middleware.AdminOnly).Post("/admin/traffic/tick", func(w http.ResponseWriter, _ *http.Request) {
					processed := stats.AggregateAll(d)
					httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "processed_domains": processed})
				})
				r.With(middleware.ResellerOrAbove).Get("/admin/backups/summary", backupsH.Summary)
				// Bulk backup/restore jobs. Scope is enforced inside the handlers, which
				// resolve the target domains through middleware.ScopeSQL.
				r.With(middleware.ResellerOrAbove).Post("/admin/backups/jobs", backupsH.StartBackupJob)
				r.With(middleware.ResellerOrAbove).Get("/admin/backups/jobs", backupsH.ListJobs)
				r.With(middleware.ResellerOrAbove).Get("/admin/backups/jobs/{jid}", backupsH.JobDetail)
				r.With(middleware.ResellerOrAbove).Post("/admin/backups/restore", backupsH.StartRestoreJob)
				r.With(middleware.AdminOnly).Post("/admin/transfers/analyze", transfersH.Analyze)
				r.With(middleware.AdminOnly).Post("/admin/transfers/import", transfersH.Import)
				// Live site migration from cPanel / Plesk / DirectAdmin. Admin only:
				// it provisions system accounts and writes into any tenant tree.
				r.With(middleware.AdminOnly).Post("/admin/migrations/test", transfersH.MigrationTest)
				r.With(middleware.AdminOnly).Post("/admin/migrations/discover", transfersH.MigrationDiscover)
				r.With(middleware.AdminOnly).Post("/admin/migrations", transfersH.MigrationStart)
				r.With(middleware.AdminOnly).Get("/admin/migrations", transfersH.MigrationList)
				r.With(middleware.AdminOnly).Get("/admin/migrations/sessions", transfersH.SessionList)
				r.With(middleware.AdminOnly).Get("/admin/migrations/sessions/{id}", transfersH.SessionGet)
				r.With(middleware.AdminOnly).Delete("/admin/migrations/sessions/{id}", transfersH.SessionDelete)
				r.With(middleware.AdminOnly).Get("/admin/migrations/{id}", transfersH.MigrationDetail)
				r.With(middleware.AdminOnly).Get("/admin/migrations/{id}/log", transfersH.MigrationLog)
				r.With(middleware.AdminOnly).Post("/admin/migrations/{id}/cancel", transfersH.MigrationCancel)
				// Malware sweep across every tenant tree, or the whole
				// filesystem. Admin only, with no scoped variant: there is no
				// ownership chain to narrow a sweep of the whole server by, and
				// its scope is a server-wide setting rather than a per-request
				// choice. Findings that land under a tenant home still reach that
				// tenant's own screen and quarantine.
				// What the scan inspects, what it may do about it, and what the
				// kernel lets it spend. Admin only: the resource limits belong to
				// the server rather than to any one customer.
				r.With(middleware.AdminOnly).Get("/admin/antivirus/settings", avSettingsH.Get)
				r.With(middleware.AdminOnly).Put("/admin/antivirus/settings", avSettingsH.Put)
				r.With(middleware.AdminOnly).Post("/admin/antivirus/sweep", avH.Sweep)
				r.With(middleware.AdminOnly).Get("/admin/antivirus/sweep", avH.SweepList)
				r.With(middleware.AdminOnly).Get("/admin/antivirus/sweep/{sid}", avH.SweepStatus)
				r.With(middleware.AdminOnly).Post("/admin/antivirus/sweep/finding/{fid}/quarantine", avH.SweepQuarantine)
				// The WordPress database scan. Admin only and deliberately not
				// scoped: it opens a connection to every tenant database on the
				// server, which no reseller's scope makes reasonable.
				r.With(middleware.AdminOnly).Post("/admin/antivirus/db-scan", avH.AdminDBScan)
				// Quarantine across every domain the caller may see. Not
				// AdminOnly: a sweep contains files across every tenant at
				// once, and a reseller reaching their own customers' held
				// files should not have to ask an admin. The narrowing is in
				// the QUERY (ScopeSQL on the joined domain), which is what
				// internal/sitesecurity already does for its cross-domain
				// list, so a row outside the caller's scope reads exactly like
				// one that does not exist.
				r.With(middleware.ResellerOrAbove).Get("/admin/antivirus/quarantine", avH.AdminQuarantineList)
				r.With(middleware.ResellerOrAbove).Post("/admin/antivirus/quarantine/{qid}/restore", avH.AdminQuarantineRestore)
				r.With(middleware.ResellerOrAbove).Delete("/admin/antivirus/quarantine/{qid}", avH.AdminQuarantineDelete)
				r.With(middleware.ResellerOrAbove).Get("/admin/antivirus/quarantine/{qid}/inspect", avH.AdminQuarantineInspect)
				// Every detection this server has recorded, whatever became of
				// the file. Scoped the same way and for the same reason: the
				// findings nobody contained are the ones somebody has to act
				// on, and they appeared on no screen but the detail of the one
				// sweep that produced them.
				r.With(middleware.ResellerOrAbove).Get("/admin/antivirus/history", avH.AdminHistory)
				// One row per domain with what the scanner knows about it, so
				// "which of my sites is infected" has a screen instead of being
				// answered by grouping a detection list by eye. Scoped like the
				// two lists around it. Scanning ONE domain needs no route here:
				// /domains/{id}/antivirus/scan already exists under CustomerScope,
				// which is wider than admin-only and is what this screen calls.
				r.With(middleware.ResellerOrAbove).Get("/admin/antivirus/domains", avH.AdminDomains)
				// Whether a domain is on a DNS blocklist. Reading is scoped the
				// same way, because a listing is the domain owner's problem to
				// act on. Changing the zone list is AdminOnly: it decides which
				// third-party service this server queries about every domain on
				// it, which is the operator's decision and not a per-scope one.
				r.With(middleware.ResellerOrAbove).Get("/admin/antivirus/reputation", avH.AdminReputation)
				r.With(middleware.AdminOnly).Put("/admin/antivirus/reputation/zones", avH.AdminReputationZonesSave)
				// Hostnames no tenant may add. Admin only: the list decides what
				// this server is willing to answer for, which is not a customer's
				// call.
				r.With(middleware.AdminOnly).Get("/admin/banned-domains", domainBlockH.List)
				r.With(middleware.AdminOnly).Post("/admin/banned-domains", domainBlockH.Add)
				r.With(middleware.AdminOnly).Post("/admin/banned-domains/remove", domainBlockH.Remove)
				// Known vulnerabilities in tenant sites. The list is ResellerOrAbove
				// and narrowed by ScopeSQL, so a reseller sees only their own
				// customers' findings. Starting a sweep is AdminOnly: it runs wp-cli
				// against every site on the server whatever scope the caller has.
				r.With(middleware.ResellerOrAbove).Get("/admin/site-security", siteSecurityH.List)
				r.With(middleware.ResellerOrAbove).Get("/admin/site-security/apps", siteSecurityH.Apps)
				r.With(middleware.ResellerOrAbove).Get("/admin/site-security/domains", siteSecurityH.Domains)
				r.With(middleware.ResellerOrAbove).Get("/admin/site-security/status", siteSecurityH.Status)
				r.With(middleware.AdminOnly).Post("/admin/site-security/scan", siteSecurityH.Scan)
				r.With(middleware.CustomerScopeParam("id")).Post("/admin/site-security/domain/{id}/scan", siteSecurityH.ScanDomain)
				r.With(middleware.CustomerScope).Get("/domains/{id}/site-security", siteSecurityH.DomainList)
				// One-click application installation. The catalog a customer sees is
				// filtered to entries the panel can actually verify; editing it is
				// AdminOnly, because a catalog row names where the panel fetches
				// executable code from and what digest it must have.
				r.With(middleware.CustomerScope).Get("/domains/{id}/app-installer", appInstallH.CatalogForDomain)
				r.With(middleware.CustomerScope).Get("/domains/{id}/app-installer/installs", appInstallH.Installs)
				r.With(middleware.CustomerScope).Post("/domains/{id}/app-installer/installs", appInstallH.Create)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/app-installer/installs/{aid}", appInstallH.Forget)
				r.With(middleware.AdminOnly).Get("/admin/app-catalog", appInstallH.AdminCatalog)
				r.With(middleware.AdminOnly).Put("/admin/app-catalog", appInstallH.AdminSave)
				r.With(middleware.AdminOnly).Delete("/admin/app-catalog/{code}", appInstallH.AdminDelete)
				r.With(middleware.CustomerScope).Get("/domains/{id}/backup-destination", backupsH.GetDestination)
				r.With(middleware.CustomerScope).Put("/domains/{id}/backup-destination", backupsH.PutDestination)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/backup-destination", backupsH.DeleteDestination)
				r.With(middleware.CustomerScope).Post("/domains/{id}/backup-destination/test", backupsH.TestDestination)
				r.With(middleware.CustomerScope).Get("/domains/{id}/git", gitH.Get)
				r.With(middleware.CustomerScope).Post("/domains/{id}/git", gitH.Connect)
				r.With(middleware.CustomerScope).Post("/domains/{id}/git/clone", gitH.Clone)
				r.With(middleware.CustomerScope).Post("/domains/{id}/git/pull", gitH.Pull)
				r.With(middleware.CustomerScope).Get("/domains/{id}/github", githubH.Get)
				r.With(middleware.CustomerScope).Post("/domains/{id}/github/connect", githubH.Connect)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/github", githubH.Disconnect)
				r.With(middleware.CustomerScope).Get("/domains/{id}/github/repos", githubH.ListRepos)
				r.With(middleware.CustomerScope).Get("/domains/{id}/github/branches", githubH.ListBranches)
				r.With(middleware.CustomerScope).Post("/domains/{id}/github/use", githubH.Use)
				r.Post("/databases/{dbId}/pma-token", pmaH.RequestToken)
				r.Get("/php/versions", phpH.Versions)
				r.With(middleware.CustomerScope).Get("/domains/{id}/php-settings", phpH.GetSettings)
				r.With(middleware.CustomerScope).Put("/domains/{id}/php-settings", phpH.PutSettings)
				// Same handlers, scoped to a subdomain by the optional {sid}.
				r.With(middleware.CustomerScope).Get("/domains/{id}/subdomain/{sid}/php-settings", phpH.GetSettings)
				r.With(middleware.CustomerScope).Put("/domains/{id}/subdomain/{sid}/php-settings", phpH.PutSettings)
				r.With(middleware.CustomerScope).Get("/domains/{id}/php/debug-log", phpH.GetDebugLog)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/php/debug-log", phpH.ClearDebugLog)
				r.With(middleware.CustomerScope).Get("/domains/{id}/resources", resourceH.Show)
				r.With(middleware.CustomerScope).Get("/domains/{id}/waf", wafH.Show)
				r.With(middleware.CustomerScope).Put("/domains/{id}/waf", wafH.Save)
				r.With(middleware.CustomerScope).Get("/domains/{id}/hotlink", domainsH.HotlinkStatus)
				r.With(middleware.CustomerScope).Put("/domains/{id}/hotlink", domainsH.SetHotlink)
				r.With(middleware.CustomerScope).Get("/domains/{id}/ip-rules", domainsH.ListIPRules)
				r.With(middleware.CustomerScope).Put("/domains/{id}/ip-rules/mode", domainsH.SetIPRulesMode)
				r.With(middleware.CustomerScope).Post("/domains/{id}/ip-rules", domainsH.AddIPRule)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/ip-rules/{ruleID}", domainsH.DeleteIPRule)
				// Country rules and the request ceiling sit beside the IP rules:
				// same screen, same scope, same re-render.
				r.With(middleware.CustomerScope).Get("/domains/{id}/geo", domainsH.GetGeo)
				r.With(middleware.CustomerScope).Put("/domains/{id}/geo", domainsH.SetGeo)
				r.With(middleware.CustomerScope).Get("/domains/{id}/rate-limit", domainsH.GetRateLimit)
				r.With(middleware.CustomerScope).Put("/domains/{id}/rate-limit", domainsH.SetRateLimit)
				r.With(middleware.CustomerScope).Get("/domains/{id}/nginx-settings", nginxsetH.Show)
				r.With(middleware.CustomerScope).Put("/domains/{id}/nginx-settings", nginxsetH.Save)
				// Same handlers, scoped to a subdomain by the optional {sid}.
				r.With(middleware.CustomerScope).Get("/domains/{id}/subdomain/{sid}/nginx-settings", nginxsetH.Show)
				r.With(middleware.CustomerScope).Put("/domains/{id}/subdomain/{sid}/nginx-settings", nginxsetH.Save)
				r.With(middleware.AdminOnly).Get("/domains/{id}/custom-vhost", nginxsetH.ShowCustomVhost)
				r.With(middleware.AdminOnly).Put("/domains/{id}/custom-vhost", nginxsetH.SaveCustomVhost)
				// The PHP version/module LIST is open to resellers (needed while
				// configuring a customer domain's PHP); install/remove mutates the server.
				r.With(middleware.ResellerOrAbove).Get("/php-extensions", phpExtH.List)
				r.With(middleware.AdminOnly).Put("/php-extensions/toggle", phpExtH.Toggle)
				r.With(middleware.AdminOnly).Post("/php-extensions/pecl-install", phpExtH.PECLInstall)
				r.With(middleware.AdminOnly).Get("/php-extensions/pecl-status", phpExtH.PECLStatus)
				r.With(middleware.AdminOnly).Post("/php-extensions/pecl-uninstall", phpExtH.PECLRemove)
				r.With(middleware.AdminOnly).Post("/php-extensions/ioncube-install", phpExtH.IonCubeInstall)
				r.With(middleware.AdminOnly).Post("/php-extensions/ioncube-remove", phpExtH.IonCubeRemove)
				r.With(middleware.AdminOnly).Get("/packages", packagesH.Search)
				r.With(middleware.AdminOnly).Get("/packages/installed", packagesH.Installed)
				r.With(middleware.AdminOnly).Get("/packages/info", packagesH.Info)
				r.With(middleware.AdminOnly).Get("/packages/status", packagesH.Status)
				r.With(middleware.AdminOnly).Post("/packages/install", packagesH.Install)
				r.With(middleware.AdminOnly).Post("/packages/remove", packagesH.Remove)
				r.With(middleware.AdminOnly).Post("/packages/update", packagesH.Update)
				r.With(middleware.ResellerOrAbove).Get("/php-versions", phpVersionH.List)
				r.With(middleware.AdminOnly).Post("/php-versions/install", phpVersionH.Install)
				r.With(middleware.AdminOnly).Post("/php-versions/remove", phpVersionH.Remove)
				// An install or removal runs detached, so the screen resumes it on
				// load and follows it here rather than holding the request open.
				r.With(middleware.AdminOnly).Get("/php-versions/status", phpVersionH.Status)
				r.With(middleware.AdminOnly).Get("/php-versions/log", phpVersionH.LogTail)
				// Node and Python interpreters. The list is readable by a reseller
				// because the application form offers it as a choice; installing
				// one changes the host, so that stays with the administrator.
				r.With(middleware.ResellerOrAbove).Get("/app-runtimes", appRuntimeH.List)
				r.With(middleware.AdminOnly).Post("/app-runtimes/install", appRuntimeH.Install)
				r.With(middleware.AdminOnly).Post("/app-runtimes/remove", appRuntimeH.Remove)
				r.With(middleware.AdminOnly).Get("/app-runtimes/status", appRuntimeH.Status)
				r.With(middleware.AdminOnly).Get("/app-runtimes/log", appRuntimeH.LogTail)
				r.With(middleware.ResellerOrAbove).Get("/app-runtimes/dotnet", appRuntimeH.DotnetList)
				r.With(middleware.AdminOnly).Post("/app-runtimes/dotnet/install", appRuntimeH.DotnetInstall)
				r.With(middleware.AdminOnly).Post("/app-runtimes/dotnet/remove", appRuntimeH.DotnetRemove)
				// Per-domain applications. CustomerScope settles the domain; the
				// {aid} lookup carries the domain in its own WHERE clause, so an
				// application on another domain is simply not found.
				r.With(middleware.CustomerScope).Get("/domains/{id}/apps", appsH.List)
				r.With(middleware.CustomerScope).Post("/domains/{id}/apps", appsH.Create)
				r.With(middleware.CustomerScope).Put("/domains/{id}/apps/{aid}", appsH.Update)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/apps/{aid}", appsH.Delete)
				r.With(middleware.CustomerScope).Post("/domains/{id}/apps/{aid}/action", appsH.Action)
				r.With(middleware.CustomerScope).Get("/domains/{id}/apps/{aid}/status", appsH.StatusOf)
				r.With(middleware.CustomerScope).Get("/domains/{id}/apps/{aid}/log", appsH.Log)
				r.With(middleware.CustomerScope).Get("/domains/{id}/apps/{aid}/env", appsH.EnvRead)
				r.With(middleware.CustomerScope).Put("/domains/{id}/apps/{aid}/env", appsH.EnvWrite)
				r.With(middleware.CustomerScope).Post("/domains/{id}/apps/{aid}/install", appsH.Install)
				r.With(middleware.CustomerScope).Delete("/domains/{id}/git", gitH.Delete)
			})
		})
	})

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		// These apply to EVERY endpoint, login included. At thirty minutes a
		// client dribbling one byte a second held a connection, and its file
		// descriptor, for half an hour per request. Six minutes leaves room above
		// the 300-second handler timeout above, and the handful of endpoints that
		// genuinely move gigabytes lift it for their own request with
		// httpx.ExtendDeadline.
		ReadTimeout:  6 * time.Minute,
		WriteTimeout: 6 * time.Minute,
		IdleTimeout:  120 * time.Second,
	}

	monitor.StartLoadSampler(d, 60*time.Second) // dashboard load-history sampler
	go chains.Start(d)                          // attack-chain correlator (EDR Phase 2)
	stats.StartTrafficAggregator(d, 5*time.Minute)
	slowquery.HealConfig(d)                    // ask MariaDB for the slow log, without restarting it
	slowquery.StartCollector(d)                // per-tenant slow query shapes, drained from the MariaDB slow log
	dbremote.HealBind(d)                       // realign the remote-access bind drop-in; never restarts MariaDB here
	laravel.StartJobReconciler(d, time.Minute) // finalize stuck async jobs without client polling
	laravel.HealOnStartup(d)                   // realign queue worker units, and remove the ones whose row is gone
	laravel.HealLogRotation()                  // rotate the worker and application logs, which grew without bound
	// The firewall's protected set has to follow the panel's own ports. Left
	// hardcoded it would go on guarding the numbers the panel used to be on and
	// leave the ones it is on now closeable from the firewall screen, which
	// locks the operator out weeks after the move with nothing connecting the
	// two events. The two packages do not import each other; the reader is
	// wired here, and a failed reading keeps the installed defaults.
	firewall.SetPanelPorts(func() []int {
		ports, err := panelport.Current()
		if err != nil {
			return []int{8080, 8443}
		}
		return []int{ports.Backend, ports.External}
	})
	// A detached port change ends with this process being replaced, so the
	// panel that started it is not the panel that learns how it went. Its
	// verdict is folded into the history table here.
	panelport.FoldOutcome(d)
	// The ops tools health-check the backend after a restart, and their URL used
	// to be written with a port of its own that a backend port change never
	// touched. servika-update then never saw the panel come up and restored the
	// previous binary, every release asset and the pre-update database dump, so a
	// healthy update rolled itself back on every attempt. The port change
	// restarts this process, which is why the repair belongs here.
	panelport.HealHealthURL()

	firewall.TakeOverFirewalld()
	if err := firewall.Reapply(d); err != nil {
		log.Printf("firewall reapply warn: %v", err)
	}

	go func() {
		log.Printf("servika %s listening on %s (env=%s)", version, cfg.ListenAddr, cfg.Env)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Printf("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

// runMigrations applies each migration file exactly once, tracked in the
// schema_migrations table. Each file runs inside a transaction: any statement
// error rolls the file back and stops startup (log.Fatalf) so the database can
// never reach a partially migrated state. Already-applied files are skipped.
func runMigrations(d *sql.DB) {
	dir := "/opt/servika/src/migrations"
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("migration directory could not be read: %v", err)
		return
	}
	if _, err := d.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		filename VARCHAR(255) NOT NULL PRIMARY KEY,
		applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`); err != nil {
		log.Fatalf("migrations: could not create schema_migrations: %v", err)
	}
	// Backward-compatible checksum column: existing installs recorded only the
	// filename, so add the column when missing and backfill legacy rows below.
	if _, err := d.Exec(`ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum CHAR(64) NOT NULL DEFAULT ''`); err != nil {
		log.Fatalf("migrations: could not add checksum column: %v", err)
	}
	applied := map[string]string{}
	rows, err := d.Query(`SELECT filename, checksum FROM schema_migrations`)
	if err != nil {
		log.Fatalf("migrations: could not read schema_migrations: %v", err)
	}
	for rows.Next() {
		var name, sum string
		if err := rows.Scan(&name, &sum); err != nil {
			log.Fatalf("migrations: scan applied row: %v", err)
		}
		applied[name] = sum
	}
	_ = rows.Close()

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
		body, err := os.ReadFile(dir + "/" + name)
		if err != nil {
			log.Fatalf("migrations: could not read %s: %v", name, err)
		}
		sum := sha256.Sum256(body)
		checksum := hex.EncodeToString(sum[:])
		if prev, ok := applied[name]; ok {
			// A blank stored checksum is a legacy row: backfill it once. A
			// non-blank mismatch means an applied migration file was edited,
			// which must never happen; stop startup rather than run on a schema
			// that no longer matches its recorded history.
			if prev == "" {
				if _, err := d.Exec(`UPDATE schema_migrations SET checksum=? WHERE filename=?`, checksum, name); err != nil {
					log.Fatalf("migrations: could not backfill checksum for %s: %v", name, err)
				}
			} else if prev != checksum {
				log.Fatalf("migrations: %s was already applied but its contents changed", name)
			}
			continue
		}
		log.Printf("migration: %s", name)
		applyMigration(d, name, string(body), checksum)
	}
}

// applyMigration runs one migration file's statements in a single transaction
// and records it as applied. Any error is fatal: the transaction is rolled back
// and startup stops so no later migration runs on a half-applied schema.
func applyMigration(d *sql.DB, name, body, checksum string) {
	var cleaned []string
	for line := range strings.SplitSeq(body, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "--") {
			continue
		}
		cleaned = append(cleaned, line)
	}
	tx, err := d.Begin()
	if err != nil {
		log.Fatalf("migrations: begin %s: %v", name, err)
	}
	for stmt := range strings.SplitSeq(strings.Join(cleaned, "\n"), ";") {
		s := strings.TrimSpace(stmt)
		if s == "" {
			continue
		}
		if _, err := tx.Exec(s); err != nil {
			_ = tx.Rollback()
			log.Fatalf("migrations: %s failed, rolled back: %v", name, err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(filename, checksum) VALUES(?,?)`, name, checksum); err != nil {
		_ = tx.Rollback()
		log.Fatalf("migrations: record %s: %v", name, err)
	}
	if err := tx.Commit(); err != nil {
		log.Fatalf("migrations: commit %s: %v", name, err)
	}
}

// warnIfNoSwap raises a panel-wide CRITICAL notification when the host has no
// swap, because swap is the only buffer before the OOM-killer. It is deduped to
// at most one row per week, evaluated by the database clock, so a restart loop
// does not spam the bell.
func warnIfNoSwap(ctx context.Context, db *sql.DB) {
	if db == nil || provisioner.SwapPresent() {
		return
	}
	const key = "system.noSwap"
	var recent int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM notifications
		 WHERE message_key = ? AND domain_id IS NULL AND created_at > (NOW() - INTERVAL 7 DAY)`,
		key).Scan(&recent); err != nil {
		log.Printf("no-swap warning: the dedup check failed: %v", err)
		return
	}
	if recent > 0 {
		return
	}
	if err := notifications.Write(ctx, db, notifications.Event{
		Level:    notifications.LevelCritical,
		Category: "system",
		Title:    "No swap configured",
		Message:  "This server has no swap space. If it runs out of memory the kernel kills the largest process, usually MariaDB, and every site goes down. Add a swap file.",
		Key:      key,
	}); err != nil {
		log.Printf("no-swap warning: the notification could not be written: %v", err)
	}
}
