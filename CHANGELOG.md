# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-08-29

### Added
- Malware protection is now a full engine rather than one in-process goroutine. A weighted-evidence scanner reports one finding per file from a total, so a single legitimate match no longer convicts; a nightly server-wide sweep runs under a kernel-enforced cgroup resource limit, on a systemd timer or the in-process scheduler; a real-time file watcher inspects a file the moment its writer is done, and a process-behaviour watcher catches a web process starting a shell. It decodes obfuscated payloads and rescans each layer, reads the function name an attacker split across concatenation, looks for malware in the database and against blocklist reputation where a file scan cannot see it, and checks WordPress core against the checksums the release shipped.
- Malware rules can now arrive between releases in a signed package, capped so a remote rule cannot reach a critical verdict alone, and the panel reports which rule set is actually running. File and process signals are correlated into attack chains with initial-access and persistence stages, drawn on a live screen, and a critical chain requires a causal link.
- The PHP & Server Wizard gathers the scattered PHP screens into one setup flow: pick PHP versions and bulk-install them, pick extensions from a curated catalog, and install .NET, Node.js and Python runtimes server-wide. The IonCube Loader installs on every PHP version automatically, a per-tenant OPcache switch renders into the pool, and new Remi PHP versions are discovered from dnf without a code change.
- Backups now capture database users and grants inside the archive, restore a deleted database, create a MySQL user for a database that has none, run asynchronously with a progress bar, and restore or download a backup whose only copy is off-site. A system-wide layer adds a master switch, a disk guard, an off-site destination, bit-rot detection, and a daily host disaster-recovery backup covering what the per-domain backup omits.
- A panel-wide notification stream every role can read, with a working bell, unread emphasis, a category icon, a relative time, a history page, and a sentence composed in the reader's language.
- `servika-verify` measures whether an installation actually works and stops the installer when it does not, verifying what the installation is made of and reporting a panel that is up on a binary it no longer runs. The journal is made persistent across the reboot the installer asks for.
- Site security findings for the whole server and for one domain, read from public feeds. The panel's own ports can be moved with proof that the panel came back; additional server addresses can be added and removed without losing the server; server tuning is proposed, applied and undone one parameter at a time; a packaged application installs into a tenant document root in one click; server software runs as its own account; hostnames the operator has banned are refused; and an administrator can end a session that has been sitting untouched.
- A shared SVG icon set replaces the emoji glyphs in the file manager and database rows, each database gets its own detail page, scheduled tasks gain a type, an enabled switch and an editor, large archives extract asynchronously with a progress bar, and the live SSH migration now moves a domain's mailboxes and mail data.

### Changed
- Twenty-four security fixes. phpMyAdmin secrets, htpasswd hashes and the backup root are closed to other tenants, and the phpMyAdmin trees get a label that survives a relabel. The downloaded IonCube loader must prove it is an object and its download is refused if it leaves TLS, and a downloaded archive can no longer read a file it was not given. The malware engine closes eleven shapes that escaped the rule set, stops a read limit and a directory-hiding trick being escapes, refuses to report an unlimited slice as a confined scan, and stops containment taking a WordPress core file away; the process watcher's `CAP_SYS_PTRACE` is disarmed and its unit sandboxed. `SHA256SUMS` is verified against a key that never touches the release host, the Go toolchain is raised off floors carrying reachable CVEs, and passwords are kept off the command line.
- The scan runs where the resource limit can reach it, yields to the sites it protects, inspects files in parallel with a disk-read ceiling, holds its slot across processes rather than only in memory, and stops re-reading the files last night already cleared. The per-domain PHP limits are raised from one source instead of four, and a reseller can no longer see another reseller's job.

### Fixed
- Malware detection stops a scan that ran out of files reporting itself as clean, stops auto-quarantining legitimate uploads, catches the webshell shapes the scan walked past, and reads a hidden directory rather than a dotted file name.
- Backups fetch an off-site archive atomically and verify its size, keep pruning when the backup itself fails, dump stored procedures, events and triggers, reject a truncated dump, and stop calling a zero-database restore a success.
- The installer creates the backup root instead of leaving it to 03:30, keeps the journal across the reboot it asks for, derives the health URL from the port the panel actually listens on, restarts the panel after replacing its binary, and runs the repair sections an existing server never receives.
- The FastCGI read timeout follows the PHP execution limit, a tenant PHP-FPM master is bounded and reloaded in parallel with a per-call timeout, a bundled PHP extension installs through the PECL screen too, and the code editor Save button is readable in dark mode.
- A hosting-less subdomain no longer inherits the main domain's web root, a forwarded message is sent from the mailbox's own address so it passes SPF, one panel CSP is served instead of three that can disagree, and the sysctl drop-in sorts last so a vendor file cannot override it on reboot.

## [1.3.0] - 2026-08-11

### Added
- Applications: a domain can now run a Node.js or Python process under the panel's supervision, on a loopback port the firewall closes to the internet, published by nginx under a path mount. Interpreter versions install and remove from the panel as detached work, and a plan decides how many applications an account may run.
- Laravel queue workers: a domain defines as many named workers as it needs, each with its own connection, queue list, process count, retry, timeout and memory ceiling, with a live log and a manual restart. A deploy now restarts them so the new code is what processes jobs.
- Country rules and a request ceiling per domain, plus a server-wide country block at the firewall. Address ranges come from a MaxMind GeoLite2 database the operator downloads with their own account, and both enforcement layers count an IPv6 client by the same unit.
- Maintenance mode: a site owner closes their own site behind a page that answers 503, keeps the certificate renewing, and reopens by itself when its deadline passes. Named addresses bypass it.
- Slow query visibility: MariaDB's slow query log is drained into normalised query shapes and attributed per account, so an administrator sees what is eating the server and a site owner sees their own. Only the shape is stored, never a literal value.
- Remote MySQL access: a site owner opens one database account to a named address from outside the server. The panel converts what was typed into a form MariaDB actually matches, derives both the grant and the firewall rule from it, and keeps every account a user answers on in step.
- Malware quarantine: a found file is taken away to a store outside the tenant's home and can be put back, in bulk or one at a time. WordPress core files are checked against the checksums the release shipped, and an extra file becomes an actionable finding.
- MTA-STS and TLS reporting: the panel publishes an MTA-STS policy through a guarded sequence that refuses enforcement until the certificate proves it, and reads the DMARC and TLS-RPT reports the domain's DNS record has always been asking for.
- IPv6 throughout: a domain answers on an assigned IPv6 address, its AAAA record is seeded and verified, mail is delivered over both address families with a correctly bound pool address, and the panel shows the server's IPv6 address beside its IPv4 one.

### Changed
- Two security fixes. Quarantine no longer takes the file path from the request: the endpoint takes a finding id and reads the path from the database, because `lstat` and `rename` follow symlinks in every component except the last, so a planted link moved an arbitrary host file out with root's hands. Rate limiting now counts an IPv6 client by its /64 rather than its address, since a client is handed the whole network and could otherwise present a fresh source on every request and reach no limit at all.
- Every domain now gets a system user of its own. The slug rule was not injective, so two different domain names could produce one identity and share a home directory; the database now refuses a second top-level domain on the same user, and an installation that already collided is named at startup rather than silently repaired.
- The nftables ruleset is now parsed by `nft` itself in CI, and the interpreter path for an application is decided in exactly one place.

### Fixed
- A broken application or queue worker restarted every five seconds for good and never reached `failed`, so the panel reported it as running: systemd was silently ignoring the restart rate limit because both keys sat in the wrong unit section.
- A deleted domain left its queue workers and its schedule cron running on the host, under an account that no longer existed.
- Four columns named after MariaDB reserved words were queried unquoted, so the traffic aggregator, its cursor, and the mail delivery log had been failing silently since they were written.
- A migration used a clause MariaDB refuses on a generated column, and another added an index that already existed, either of which stops the panel from starting.
- A malware scan that ran out of its budget was presented as a clean one.
- The slow query log could not be enabled at all, because MariaDB refuses the path when its parent directory is missing and does not create it.
- Application logs and Laravel worker logs grew without bound, with no rotation rule for either directory.
- A suspended account's applications kept running, and mail reputation was watched on an address other than the one the server sends from.

## [1.2.1] - 2026-08-08

### Added
- A complete email stack for every domain: mailboxes, aliases, forwarders with a keep-a-copy choice, per-mailbox usage measured against the plan's quota, an operator ceiling above the per-mailbox limits, and a per-sender spam-score override.
- Live mailbox migration from another provider over IMAP, with discovery of the old server, a password check before anything is copied, live progress, and a job that resumes after a panel restart instead of being lost.
- Mailbox import and export: Maildir, mbox and Outlook `.pst` in, a tar.gz archive out, and a converter installed with the panel where the distribution ships one.
- Mail clients now configure themselves: the panel answers the autoconfiguration and autodiscover hostnames, serves and certifies them, publishes the DNS records a client looks for, and reports which names the installed certificate actually covers.
- Each domain gets its own mail certificate served by SNI, its own webmail address, and a panel-initiated webmail sign-on that never replays the mailbox password.
- A domain's mail can now be turned off without deleting anything, told apart from purging it for good, and its old mail can be reclaimed as disk.
- Subdomains became first-class: their own PHP and web-server settings, their own certificate, their own PHP-FPM pool inside the parent tenant's unit, bulk selection and deletion from the domain list, and inclusion in the global search.
- Site import: move a site onto a domain that already exists from any panel, with archive inventory that skips a container directory.
- A shared nameserver pair replaces vanity nameservers, published as every zone's apex NS records, manageable from the panel, and shown when a domain is created.
- DNS verification checks a domain's published records, including the two that decide whether sent mail is accepted.
- One hostname can now be made canonical, with the other 301'd to it, chosen while creating a domain or on the addon domains page.
- A domain can be handed to a reseller as it is created, moved between a reseller's own customers, and transferred from the screen that lists domains.
- The server-wide database list gained the row actions the domain page already had: open phpMyAdmin, reveal and copy the password, reset it, delete the database.
- The panel replaced every browser dialog with one the browser cannot silence, and a new release is now announced on the dashboard.
- The sign-in screens let the visitor pick a language, and sign-in completes as soon as the six-digit second factor is typed.

### Changed
- Twenty-seven security fixes. The tenant file jail no longer has a path-string resolver anywhere in it: listing, search, size, archiving, document-root removal, WordPress and subdomain deletion all resolve through pinned directory descriptors, so a planted symlink can no longer redirect a root-run operation out of the tenant's tree. SQL dumps are applied as a temporary account granted on one schema instead of the panel's root connection. Backup destinations verify an SFTP host key, refuse an S3 endpoint pointing at the internal network, and keep their credentials out of `lftp`, `sshpass` and `curl` argv, as do the directory-protection and database passwords. Failed logins are counted per account as well as per address, server socket timeouts are bounded, a `du` scan a customer triggers has a ceiling, credentials left in the clear by older installs are encrypted at startup, the database DSN is required rather than defaulted, and the panel policy forbids plugin objects.
- Panel translations are fetched when a component asks for them instead of being compiled into the entry chunk. All twelve languages used to ship to every visitor; the first load dropped from 918 KB to about 149 KB gzipped.
- Every subprocess that reaches the network is bounded by a deadline: acme.sh, wp-cli, composer, git clone and fetch, the PECL and dnf extension installs, the MariaDB client, and the slow-query scan.
- Installing or removing a PHP version now runs as detached work with a status and log endpoint instead of holding the request open, and certificate issuance answers immediately with a job to poll.
- The panel now detects the port sshd actually serves and protects that one, warning while it is still the default.

### Fixed
- A failed Let's Encrypt issuance reported success and installed a self-signed certificate silently; it now says why it failed, returns a code rather than the CA's prose, and an imported or self-signed certificate is no longer described as one a browser trusts.
- The panel announced a mail hostname the installed certificate did not cover, and advertised mail ports the server does not serve.
- Webmail could not send mail, forced Turkish on every user, and signed in on an address other than the one the page advertised.
- A failed mailbox import left behind what it had already written; it is now rolled back.
- One pass of the mail delivery log could read an unbounded amount into memory, and all mailbox migrations ran at once instead of four at a time.
- An update could destroy a hand-edited panel vhost, and a tampered release bundle was treated as a network failure and retried against the mutable branch tarball.
- A re-run of the installer wiped secrets other tools had written, and the FTP password column was too narrow for an account to be created at all.
- Sessions dropped during a brief database outage, a plugin restart answered an error instead of being ridden out, and four domain handlers acted on a row they had failed to read.
- The file manager's errors disappeared, an archive of unknown size was reported as empty, and a server fault was reported as a path the tenant had got wrong.
- A domain could be created with a name already serving as a subdomain, and a PHP version the server cannot serve could be selected.
- The CI gate that validates the shipped nginx configuration failed on every commit because the runner may not bind port 80, reporting the sandbox rather than the files and blocking the release job behind it.

## [1.1.5] - 2026-08-04

### Changed
- Upgraded the panel to React 19 and React Router 8, closing a routing advisory that no 7.x release fixes, and patched a path traversal in the build-time postcss dependency.
- Panel pages no longer paint one frame of the previous domain's data when you switch domain, directory, log file, or filter: the file-manager selection, log tail, monitoring panels, audit-log spinner, and search deep links now settle in the same render as the change.
- Removed unreachable components and their translations, and added an ESLint gate over the whole frontend so this class of rendering defect is caught before it ships.

### Fixed
- The file editor marked a saved file as unsaved again right after saving, leaving the Save button enabled with nothing left to write.
- The antivirus page could leave a scan poll running after the scan finished or the page changed.
- The elapsed time and estimated remaining time of a finished site migration kept counting up instead of stopping where the job ended.
- The stored FTP and database password shown in the connection dialog, and the server status load error, stayed in the previous language after a language switch.

## [1.1.4] - 2026-08-02

### Added
- The release announcement in the update panel is now published per language and rendered in the language the panel is displaying, instead of always in English. Any language without its own text falls back to English.

## [1.1.3] - 2026-08-02

### Added
- Live site migration from cPanel, Plesk, and DirectAdmin over SSH: discovers every account and domain on the source server, then transfers files, databases, DNS records, and SSL in one job with a three-step wizard, live progress, and a cancellable background run.
- Granular backup restore with five modes (full, files only, databases only, a single file, a single database); a restore never deletes files missing from the backup by default, and selected files land in a separate folder instead of overwriting the live site.
- Every domain-owned database is now packaged in each backup together with a manifest, replacing the previous main-database-only archive.
- Bulk backup and restore now run as tracked jobs with live progress, per-domain results, and a job detail page.
- Ten further interface languages (German, French, Italian, Spanish, Portuguese, Brazilian Portuguese, Romanian, Japanese, Czech, and Simplified Chinese), bringing the panel to twelve.
- The update panel now shows the running build date.

### Changed
- Tenant nginx access and error logs are no longer readable by other tenants; the log directory and its files are closed on every startup.
- Tenant Redis accounts can no longer enumerate key names: scan and randomkey are denied for new accounts and withdrawn from existing ones at startup.
- The repair tool no longer loosens tenant home isolation to 0711/0755; it now enforces the same 0710/0750 model as the provisioner, with an nginx-group fallback for filesystems that ignore ACLs.
- Archive extraction rejects a crafted uncompressed-size header that could overflow the size limit.
- Operations scripts and long-running maintenance job logs are English only again, and the repository slug now points at ServikaPanel/servika.

### Fixed
- A domain served nothing (HTTP 403) on filesystems that silently ignore ACLs; nginx read access is now verified before the ACL model is trusted, and the group fallback carries the whole document root.
- The panel update card could spin forever when the service restart interrupted its status stream; the result is now also read from the update log, and a finished update reports whether it succeeded.
- Audit entries created by the panel itself were recorded as 127.0.0.1 and were indistinguishable from real visitors; they are now labelled as system.
- A missing SSH jail asset was ignored silently, leaving tenants with an unconfined shell and no record of it.
- Restored the literal update-count keys on the Chinese WordPress page.

## [1.1.2] - 2026-08-01

### Added
- Full Turkish/English localization across the panel (react-i18next), with a live language switcher, a per-user preference, and a server-default language chosen at install.
- Localized live logs for long-running maintenance jobs (update, optimize, CVE, KernelCare) and the `servika-update`/`servika-optimize` scripts, following the panel default language.
- Reseller multi-user panel accounts with a role-based sidebar, reseller-scoped management UI, and admin UI to view and edit reseller disk/traffic/customer/domain quotas.
- Reseller-scoped hosting endpoints and quota enforcement across domains, WordPress, and backup lists; reseller suspension now cascades to its customers' hosting.
- cPanel full-account import: web files, multiple databases, mailboxes and forwarders, cron jobs, and SSL certificates.
- Server-wide DNS/SSL/mail/database overview lists and a per-reseller-scoped security (audit) log.
- Mail spam filtering, Sieve rules, per-mailbox send limits, and Postfix queue management.
- S3 and Backblaze B2 remote backup destinations.
- BIND DNS zone import/export (backend and UI).
- Optional Let's Encrypt SSL when creating a domain; domain SSL indicator, open-in-new-tab, and reseller column.
- Global panel search in the top bar, admin server-hostname management, branded welcome and server-wide 404 pages, an inline nginx vhost editor, and auto-expanding file-manager directory tree.

### Changed
- Encrypt database account passwords at rest (AES-256-GCM) and store FTP/SSH credentials as yescrypt/SHA-512-crypt hashes instead of cleartext.
- Trust proxy IP headers only with the shared proxy secret; heal panel proxy trust and clean deprovision orphans on startup.
- Pre-scan the cPanel import archive with member validation before extraction; validate backup destinations and harden SFTP against ssh argument injection; reject dangerous nginx directives with quote-aware tokenization.
- Reject NUL in the root password before chpasswd and close a username timing side-channel on login.
- Verify release bundles against the published SHA256SUMS before install/update.
- Collapse to a single role-based token (drop the FTP login bridge), store client session state in cookies (never localStorage), convert user-text tables to utf8mb4, standardize page containers to full width, lazy-load route pages, and modernize internal code to current Go idioms.

### Fixed
- Revoke live sessions on credential and authorization changes; reject replayed GitHub webhook deliveries.
- Harden file uploads against disk exhaustion and quota bypass; symlink-safe permission reset for public_html; handle unix.Close errors on directory fd releases.
- Bound manual backup work and cap manual retention; fully tear down the systemd slice on delete; pin TMPDIR with a single-pass cPanel import and mail policy hardening.
- DNS-aware www SAN and guard PHP-FPM pool writes for deleted users; prevent addon domains from overwriting the parent vhost; allow safe tenant preview via CSP frame-ancestors and make the domain preview refreshable.
- Detect edits to already-applied migration files; resolve clean-install verification errors.

## [1.1.1] - 2026-07-27

### Changed
- Upgraded the chi router to v5.3.0 and edwards25519 to v1.1.1, clearing three dependency advisories reported by govulncheck (none on a reachable code path).
- Modernized internal code paths to current Go idioms (`min`, `maps.Copy`, `slices.ContainsFunc`, `strings.FieldsSeq`, `atomic.Int64`, `WaitGroup.Go`) with no change in behavior.

## [1.1.0] - 2026-07-26

### Added
- Subdomain management pages and a nested subdomain list under each domain.
- WordPress, Composer, and log tooling scoped to individual subdomains.
- Subdomain traffic aggregated into the parent domain statistics.
- Password-protected directories scoped to subdomains.
- Global subdomain list endpoint.
- Subdomain detail endpoint.
- Per-subdomain PHP version switching.

### Changed
- Adopted `SplitSeq` and integer range loops.
- Updated the installation and configuration guide.

### Fixed
- acme.sh now recovers from a rejected account contact address, which previously
  blocked certificate issuance for every domain on the host permanently.
- phpMyAdmin signon token expiry is evaluated with the MySQL clock, so tokens are
  no longer discarded instantly on hosts whose database timezone is not UTC.
- Laravel installs preserve the tenant inode quota and surface install failures.

## [1.0.3] - 2026-07-25

### Added
- Optional offsite upload for panel database backups over FTP/SFTP with remote retention.
- RED (Rate, Errors, Duration) metrics instrumentation for the HTTP API.

### Changed
- Release packaging is now gated on the full validation suite via a reusable CI workflow.
- Added unit-test coverage for validation helpers across critical backend modules.
- Metrics handler now checks response-writer write results.
- Removed the unused phpMyAdmin root accessor.
- Release notes are sourced from the matching CHANGELOG section.

### Fixed
- Update and restore now deploy immutable tagged release bundles instead of mutable branch snapshots.
- Scheduled domain backups run through a single authoritative runner, no longer duplicated by a root cron.
- Laravel install and deploy jobs are finalized server-side without depending on client polling.
- Subscription deletion now requires administrator authorization.
- Archive extraction enforces decompression-bomb size and member limits.
- Domain HTTPS health probes verify the TLS certificate chain and hostname.
- The build requires a patched Go toolchain and gates releases on a vulnerability scan.
- phpMyAdmin signon tokens are exchanged in a POST body instead of a URL query string.
- Request lifecycle logging added to the API middleware stack.
- Customer FTP passwords are no longer stored as cleartext at rest.
- Installer verifies third-party downloads before use.
- Panel CSP tightened to `script-src 'self'`, isolating phpMyAdmin and webmail.
- Session tokens are delivered via an HttpOnly cookie instead of localStorage.
- Update rollback restores every release-owned asset, not only the binary and database.
- Stored GitHub access tokens are encrypted at rest and kept out of repository URLs.
- Auto-registered GitHub webhooks require TLS verification.
- GitHub webhook HMAC signatures are verified before pulling.
- Migrations apply once each inside a transaction.
- Server-side JWT session revocation is supported.
- Remote backup destination credentials are encrypted at rest.
- CORS reflects only the same origin instead of a wildcard.
- Manual backup creation is rate-limited and serialized per domain.
- Expensive file-manager operations are throttled per IP.
- The public Git webhook endpoint is throttled.
- Every response carries a request id for error correlation.
- Raw exception details are hidden from end users.
- Load sampler failures are logged instead of discarded.
- The readiness probe verifies the database dependency.
- Laravel deploy jobs fail when a critical step fails.
- Orphaned tenant metadata is deleted on domain removal.
- File uploads are exempt from the JSON body limit.
- System operation error details are redacted from API responses.
- Download filenames are safely encoded in Content-Disposition.
- Repository credentials are redacted from API responses.
- Database plan limits are enforced atomically, including during WordPress install.
- Tenant file reads and archive extraction resolve through symlink-safe file descriptors.
- SSRF to internal targets from customer-controlled hosts is blocked.
- Suspension is enforced on phpMyAdmin signon token creation.
- A FastCGI cache key is defined for tenant vhosts.
- Restores fail when the database import fails.
- The inconsistent upload extension block was removed.

## [1.0.2] - 2026-07-24

### Changed
- CI now uses golangci-lint v2 for Go 1.25 compatibility.

### Fixed
- Subdomain, PHP extension, resource-limit, system, SSH, and Laravel handlers
  no longer report failed system applies as success.
- Credential and resource teardown failures (MySQL, Redis, Git) are now
  surfaced instead of silently swallowed.
- Safety-guard count checks in quota, accounts, plans, and PHP-version paths
  fail closed on query errors instead of proceeding as if the limit passed.
- DNS record mutations surface zone-write failures instead of reporting success.
- Backup dumps abort on mysqldump failure instead of archiving corrupt dumps.
- TOTP login fails closed when the replay-protection step cannot be persisted.
- safeio propagates write-path Close errors (e.g. ENOSPC) and checks all Close
  results; removed dead chown helpers.

## [1.0.1] - 2026-07-24

First tagged release. Servika is a self-hosted web hosting control panel for
AlmaLinux/RHEL 10, covering domains, mail, databases, PHP, DNS, TLS, tenant
isolation, and resource governance.

### Added
- Dashboard with drag-and-drop widget layout, live load/memory charts, CVE
  security widget, KernelCare integration, panel version footer, and
  click-to-copy server IP.
- Domain management: addon domains, redirects, per-domain access controls,
  raw custom nginx vhost overrides, and Laravel toolkit.
- Native mail stack: mailboxes, forwarder aliases, OpenDKIM, Postfix virtual
  mail, and Roundcube webmail.
- Per-domain PHP management: eight PHP-FPM versions for AlmaLinux 10, debug
  mode toggle with log panel, and isolated per-tenant PHP-FPM services.
- Databases: one DB user owning multiple databases and a MySQL query governor.
- Resource governance: absolute disk I/O limits, MariaDB governor, systemd
  slice enforcement, and XFS user quota with reboot-required sentinel.
- Security: ModSecurity + OWASP CRS WAF, native Go yescrypt auth, TOTP 2FA
  with QR and replay protection, per-IP login rate limiting, and POSIX ACL
  tenant home isolation.
- Anonymous version-check telemetry, panel self-update flow, maintenance mode,
  and a file manager with metadata, RAR archives, and web preview.
- Multi-arch release pipeline (linux amd64 + arm64) with CI and GitHub Release
  workflows, and a binary-release-based installer.

### Changed
- Centralized configuration path and production environment loading.
- Restructured build assets into a multi-arch directory layout and version
  injection via ldflags.

### Fixed
- Hardened file operations against TOCTOU and symlink attacks with openat2.
- Prevented chpasswd/lftp command injection and web-root PHP webshell uploads.
- Sealed username enumeration and heuristic caching of JSON API responses.
- Made schema migrations idempotent and restored tenant limits on startup heal.
