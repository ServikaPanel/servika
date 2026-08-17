# Servika

Deploy a production-ready web hosting platform on **AlmaLinux 10** with a single command. Automatically installs and configures Nginx, MariaDB, multiple PHP versions, Valkey (Redis), phpMyAdmin, ModSecurity WAF, and a secure firewall. Built for both **x86_64** and **ARM64 (aarch64)** systems.

## One-line installation

Run as **root** on a clean AlmaLinux 10 server with at least 2 GB of RAM:

```bash
curl -fsSL https://raw.githubusercontent.com/ServikaPanel/servika/main/install.sh | bash
```

Installation takes about 15 to 20 minutes while packages download. When finished, the panel address and credentials are displayed.

## After installation

- **Panel:** `https://SERVER_IP:8443` (accept the self-signed certificate warning)
- **Login:** username **`root`**, password = **the server's root password**
  (the panel verifies the administrator against the system root account via /etc/shadow; there is no separate panel password)

## What it installs

| Component       | Details                                                                                                     |
|-----------------|-------------------------------------------------------------------------------------------------------------|
| **Web**         | nginx (panel on :8443, customer sites on :80/:443)                                                          |
| **PHP**         | 7.4 / 8.0 / 8.1 / 8.2 / 8.4 / 8.5 / 8.6 (Remi) and 8.3 (AppStream or Remi), per-domain version selection and FPM pool |
| **Database**    | MariaDB from the AlmaLinux 10 AppStream (`panel` DB) with phpMyAdmin at `/pma/`                              |
| **Cache**       | Valkey (Redis 7.x compatible), isolated per-tenant object cache with automatic WordPress integration        |
| **Mail**        | Optional, installed on demand by `servika-mail-setup`: Postfix + Dovecot with MySQL-backed virtual mailboxes, Sieve, OpenDKIM, Rspamd filtering, and Roundcube webmail |
| **Security**    | nftables firewall, ModSecurity v3 + OWASP CRS WAF, SELinux enforcing support, ClamAV malware scanning       |
| **Performance** | Automatic MariaDB, nginx, and OPcache tuning (`servika-optimize`), XFS user quota with per-plan disk limits |

## Panel features

- Domain and subdomain management with DNS editing, templates, DNSSEC, and bulk operations
- One-click **WordPress** installation and WP-CLI toolkit for plugin, theme, user, and repair management
- Per-tenant **Redis object cache** with one-click enable, automatic WordPress drop-in, and ACL isolation
- **File manager** with code editor, archive extraction (ZIP, TAR, RAR), bulk copy/move, and search
- **Cron** job editor and **Git / GitHub** deployment with deploy keys and webhook auto-pull
- **SSL** via Let's Encrypt or self-signed, with LE rate-limit resilience (reuse-before-issue, never-drop-443)
- Per-domain **PHP versions** with independent settings, **PHP extensions** manager, and PECL support
- **FTP** accounts through Pure-FTPd with MySQL backend and per-user SSH chroot jails
- **Firewall** (nftables) with IP bans, allowlists, port blocking, and ready-made templates
- **WAF** (ModSecurity + OWASP CRS) per-domain or plan-default, with Detection and Blocking modes
- **Password-protected directories** via htpasswd with nginx integration
- **Mail** per domain: mailboxes, aliases and catch-all forwarders, per-mailbox forwarding with a keep-a-copy choice, auto-reply, Sieve filters, send limits, spam thresholds, delivery log, and Roundcube webmail with one-click sign-on
- **Mailbox migration and transfer**: live IMAP copy in from another provider with server discovery and a sign-in check before any copying starts, plus per-mailbox export and Maildir/mbox/`.pst` import
- **Mail auto-configuration** so Thunderbird and Outlook configure an account from the address alone, served over the domain's own certificate
- Backup manager with local retention, remote SFTP/FTP destinations, scheduling, and point-in-time restore
- Service plans with resource limits (CPU, RAM, disk, I/O, inodes, MariaDB governor, process caps)
- **Monitoring**, **statistics** (nginx traffic analysis), **system logs**, and **load history** charts
- **2FA** with TOTP and QR enrollment for administrator login

## System requirements

- **AlmaLinux 10** (also works on RHEL 10 and Rocky Linux 10)
- **x86_64** or **ARM64 (aarch64)** architecture
- At least **2 GB RAM** and 2 vCPUs
- Root access and internet connection

## Post-installation utilities

The installer places these tools under `/usr/local/bin`:

```bash
servika-update              # Safely update the panel from GitHub with pre-update DB dump and automatic rollback
servika-db-backup           # Back up the panel database with gzip integrity checks and 14-day retention
servika-optimize            # Retune MariaDB, nginx, and PHP-FPM for available server resources
servika-redis-setup         # Install or repair the Valkey (Redis) infrastructure
servika-wp-redis <domain>   # Connect or disconnect Redis cache for a domain's WordPress installations
servika-ftp-setup           # Install or repair the Pure-FTPd MySQL backend
servika-mail-setup          # Install or repair the mail stack: Postfix, Dovecot, OpenDKIM, Rspamd, Roundcube
servika-jail <user>         # Create a per-user chroot SSH jail with sshd Match group isolation
servika-repair              # Repair permissions, SELinux contexts, and ownership idempotently
servika-restore             # Restore core panel files from the canonical release with integrity verification
servika-waf-setup           # Install or repair ModSecurity v3 + OWASP CRS with nginx -t gating
```

## Updating from SSH

Run the updater as root on an installed server:

```bash
servika-update              # Download and apply the latest immutable release bundle
servika-update --dry-run    # Show what would change without applying it
servika-update --force      # Reapply even when the release hash is unchanged
servika-update --branch X   # Opt into a mutable branch tarball instead of a release bundle
```

By default the updater deploys the latest tagged release bundle (or `SERVIKA_RELEASE_TAG`); it falls back to a branch tarball only if a tag cannot be resolved, and `--branch` explicitly opts into the mutable branch. The updater preserves `/etc/servika/env` and `/home/c_*` customer sites. Before exposing migrations, it creates a full MariaDB `panel` database dump and aborts if the dump fails. It then updates the binary, frontend (atomic verified swap), migrations, operations tools, and systemd units before restarting Servika and verifying `/healthz`. If the new release fails the health check, the previous binary and pre-update database dump are restored automatically.

The update can also be started from **Tools and Settings > Panel Update**. If `servika-update` is missing from an older installation, the panel downloads it automatically.

## Version check and privacy

Servika checks a public version manifest to show update and announcement information in **Tools and Settings > Panel Update**. The check is an HTTPS `GET` request with two query values: anonymous installation ID (`id`) and current panel version (`v`). The installation ID is random. It is not derived from hostname, IP address, MAC address, customer data, email address, database content, or license data.

The request has no body. The `User-Agent` header also includes the current panel version. These values support aggregate active-installation counting when the selected endpoint counts distinct random IDs, not customer identification.

The manifest format is:

```json
{
  "latest": "1.3.0",
  "announcement": {
    "en": "",
    "tr": ""
  },
  "critical": false,
  "release_date": ""
}
```

`announcement` is keyed by the supported interface language codes (`en`, `tr`, `de`, `fr`, `it`, `pt`, `pt-BR`, `es`, `cs`, `ro`, `ja`, `zh`), so the update notice reads in the language the panel is displaying. The `en` entry is required: any language without its own text falls back to it. The panel sends its active language as the `lang` query value on its own `GET /api/v1/system/version-check` endpoint; the language is never sent to the public manifest endpoint.

If version checks are disabled, manual update from SSH and panel-triggered update still work.

## Environment variables

Production values live in `/etc/servika/env`. The systemd units and production operations tools load that file before using `SERVIKA_*` values. Keep the file owned by root with mode `0600` because it contains the database, JWT, secret-key, and Redis secrets. Re-running the installer preserves existing `SERVIKA_DB_PASS`/`SERVIKA_JWT_SECRET`/`SERVIKA_SECRET_KEY`/`SERVIKA_REDIS_ADMIN_PASS` values rather than rotating them.

Use `/etc/servika/env` as the canonical source for installed servers. Shell-provided `SERVIKA_*` values are reserved for development, isolated restore tests, and emergency recovery. Production tools load `/etc/servika/env` without overwriting an already exported shell value, so emergency overrides stay possible when they are intentional.

The installer writes every persistent production setting it owns into `/etc/servika/env`. Tenant application `.env` files, such as Laravel or WordPress files under `/home`, are separate customer application configuration and are not Servika runtime configuration.

### Runtime server variables

| Variable                   | Default                                                   | Purpose                                                                                                                                                                    |
|----------------------------|-----------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `SERVIKA_LISTEN`           | `:8080`                                                   | HTTP listen address for the Go server. The installer sets `127.0.0.1:8080` behind nginx.                                                                                   |
| `SERVIKA_DB_DSN`           | none, required                                            | MariaDB DSN for the `panel` database. There is no built-in default, so the server cannot start on a shared fallback credential.                                            |
| `SERVIKA_ENV`              | `production`                                              | Runtime environment label.                                                                                                                                                 |
| `SERVIKA_JWT_SECRET`       | none, required                                            | JWT signing secret. It must be at least 32 characters.                                                                                                                     |
| `SERVIKA_SECRET_KEY`       | none, required                                            | AES-256-GCM key (at least 32 characters) for encrypting credentials/tokens at rest (FTP, GitHub PAT, backup-destination passwords, and the source passwords of site and mailbox migrations, which are cleared once the job finishes). The server refuses to boot without it. |
| `SERVIKA_JWT_LIFETIME_SEC` | `28800`                                                   | JWT lifetime in seconds. The installer sets `43200`.                                                                                                                       |
| `SERVIKA_DB_MAX_CONNS`     | `NumCPU x 4`, at least 16 and at most 64                  | Ceiling for the panel's own MariaDB connections. The panel shares one server with every tenant site, and stock `max_connections` is 151 (`servika-optimize` raises it to 200), so the cap keeps the panel from starving the sites. A value outside 16-64 is logged and ignored rather than applied. |
| `SERVIKA_PUBLIC_IPV4`      | empty, server autodetects first non-loopback IPv4 address | Public IPv4 override for webhook URLs, SSH display, and DNS seed records.                                                                                                  |
| `SERVIKA_PUBLIC_IPV6`      | empty, server autodetects first global-unicast IPv6 address | Public IPv6 override for AAAA seed records and the `ip6:` SPF term. Autodetection ignores link-local (`fe80::/10`), unique-local (`fc00::/7`), loopback and IPv4-mapped addresses: none of them is reachable from the internet, and publishing one as a AAAA makes the site look dead to every IPv6 client. Leave it empty on a server with no routable IPv6 and no AAAA record is written at all. |
| `SERVIKA_MAINTENANCE_MODE` | empty                                                     | Returns HTTP 503 for most requests when set to `1` or `true`. Health and login endpoints stay available.                                                                   |
| `SERVIKA_VERSION_CHECK`    | enabled                                                   | Disables external version checks when set to `0`, `false`, or `no`.                                                                                                        |
| `SERVIKA_VERSION_ENDPOINT` | compiled public manifest URL                              | Overrides the version manifest endpoint. Example: `https://example.com/version.json`.                                                                                      |
| `SERVIKA_REDIS_ADMIN_PASS` | generated by the installer or Redis setup tool            | Valkey or Redis administrator password used by Redis features and performance checks.                                                                                      |

### Installer and operations variables

| Variable                    | Default                                                              | Used by                                                  | Purpose                                                                                               |
|-----------------------------|----------------------------------------------------------------------|----------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| `SERVIKA_DB_PASS`           | generated by the installer, parsed from `SERVIKA_DB_DSN` when absent | `servika-ftp-setup`                                      | Optional panel database password override for Pure-FTPd setup.                                        |
| `SERVIKA_MAIL_DB_PASS`      | generated by `servika-mail-setup` when absent                        | `servika-mail-setup`                                     | Read-only `mailro` database user password for Postfix and Dovecot SQL maps.                           |
| `SERVIKA_ROUNDCUBE_DB_PASS` | generated by `servika-mail-setup` when absent                        | `servika-mail-setup`                                     | Roundcube database user password for webmail preferences and address books.                           |
| `SERVIKA_ROUNDCUBE_DES_KEY` | generated by `servika-mail-setup` when absent                        | `servika-mail-setup`                                     | Roundcube encryption key for stored session and IMAP password data.                                   |
| `SERVIKA_SEED_PASSWORD`     | empty                                                                | `scripts/seed_admin.go`                                  | Administrator password fallback when `-password` is omitted.                                          |
| `SERVIKA_REPO`              | `ServikaPanel/servika`                                               | `install.sh`, `servika-update`, `servika-restore`        | GitHub repository used to download release bundles.                                                   |
| `SERVIKA_RELEASE_TAG`       | latest published release                                             | `install.sh`, `servika-update`, `servika-restore`        | Pin install/update/restore to a specific immutable release tag (e.g. `v1.0.3`) instead of the latest. |
| `SERVIKA_PREFIX`            | `/opt/servika`                                                       | `servika-update`, `servika-restore`                      | Root path for panel files.                                                                            |
| `SERVIKA_BIN`               | `$SERVIKA_PREFIX/bin/servika-server`                                 | `servika-update`, `servika-restore`                      | Target server binary path.                                                                            |
| `SERVIKA_SEED`              | `$SERVIKA_PREFIX/bin/servika-seed-admin`                             | `servika-update`, `servika-restore`                      | Target seed-admin binary path.                                                                        |
| `SERVIKA_FDIST`             | `$SERVIKA_PREFIX/frontend-dist`                                      | `servika-update`, `servika-restore`                      | Target frontend distribution path.                                                                    |
| `SERVIKA_MIGR`              | `$SERVIKA_PREFIX/src/migrations`                                     | `servika-update`, `servika-restore`                      | Target migrations path.                                                                               |
| `SERVIKA_SCRIPTS`           | `$SERVIKA_PREFIX/src/scripts`                                        | `servika-update`, `servika-restore`                      | Target build-time scripts path.                                                                       |
| `SERVIKA_OPSBIN`            | `/usr/local/bin`                                                     | `servika-update`, `servika-restore`                      | Target operations binary directory.                                                                   |
| `SERVIKA_SVC`               | `servika`                                                            | `servika-update`, `servika-restore`                      | systemd service name used during repair and health checks.                                            |
| `SERVIKA_HEALTH`            | `http://127.0.0.1:8080/healthz`                                      | `servika-update`, `servika-restore`                      | Health check URL used after restoring core files.                                                     |
| `SERVIKA_DBBK`              | `/usr/local/bin/servika-db-backup`                                   | `servika-update`, `servika-restore`                      | Panel database dump tool path.                                                                        |
| `SERVIKA_DBDIR`             | `/var/backups/servika/db`                                            | `servika-update`, `servika-restore`, `servika-db-backup` | Panel database dump directory.                                                                        |
| `SERVIKA_ASSETS_OVERRIDE`   | empty                                                                | `servika-restore`                                        | Local assets directory for isolated or offline restore tests.                                         |

### Binary and tool path variables

| Variable                 | Default                   | Purpose                                                          |
|--------------------------|---------------------------|------------------------------------------------------------------|
| `SERVIKA_COMPOSER_BIN`   | `/usr/local/bin/composer` | Composer binary used by Composer and Laravel features.           |
| `SERVIKA_WPCLI_BIN`      | `/usr/local/bin/wp`       | WP-CLI binary used by WordPress and Redis integration features.  |
| `SERVIKA_CLAMSCAN_BIN`   | `/usr/bin/clamscan`       | ClamAV scan binary used by antivirus operations.                 |
| `SERVIKA_FRESHCLAM_BIN`  | `/usr/bin/freshclam`      | ClamAV signature updater binary.                                 |
| `SERVIKA_PECL_BIN`       | `/usr/bin/pecl`           | Default PECL binary for PHP extension management.                |
| `SERVIKA_REMI_PECL_ROOT` | `/opt/remi`               | Root used to resolve Remi per-version PECL binaries.             |
| `SERVIKA_ACME_HOME`      | `/root/.acme.sh`          | acme.sh home directory used for certificate storage and renewal. |
| `SERVIKA_ACME_BIN`       | `/root/.acme.sh/acme.sh`  | acme.sh binary used for certificate issuance and installation.   |
| `SERVIKA_READPST_BIN`    | `/usr/bin/readpst`        | libpst converter used for `.pst` mailbox import. When it is absent the panel reports `.pst` as an unsupported format instead of failing an upload. |

### Application path variables

| Variable                        | Default                                            | Purpose                                                 |
|---------------------------------|----------------------------------------------------|---------------------------------------------------------|
| `SERVIKA_BACKUP_ROOT`           | `/var/backups/servika`                             | Root directory for customer domain backup archives.     |
| `SERVIKA_LARAVEL_LOG_DIR`       | `/var/log/servika-laravel`                         | Laravel install and deploy log directory.               |
| `SERVIKA_PLUGIN_ROOT`           | `/opt/servika/plugins`                             | Plugin bundle root.                                     |
| `SERVIKA_LOG_DIR`               | `/opt/servika/logs`                                | Shared panel operations log directory.                  |
| `SERVIKA_UPDATE_LOG`            | `/opt/servika/logs/update.log`                     | Panel update log path.                                  |
| `SERVIKA_KERNELCARE_LOG`        | `/opt/servika/logs/kernelcare-update.log`          | KernelCare update log path.                             |
| `SERVIKA_KERNELCARE_WRAPPER`    | `/opt/servika/kernelcare-update.sh`                | KernelCare systemd wrapper path.                        |
| `SERVIKA_CVE_LOG`               | `/opt/servika/logs/cve-update.log`                 | Security update log path.                               |
| `SERVIKA_PHPOP_LOG`             | `/opt/servika/logs/php-op.log`                     | PHP version install and removal log path.               |
| `SERVIKA_PHPOP_STATE`           | `/opt/servika/php-op.json`                         | Descriptor of the PHP version operation in progress.    |
| `SERVIKA_PHPOP_WRAPPER`         | `/opt/servika/php-op.sh`                           | PHP version operation systemd wrapper path.             |
| `SERVIKA_RUNTIMEOP_LOG`         | `/opt/servika/logs/runtime-op.log`                 | Node.js and Python runtime install and removal log path. |
| `SERVIKA_RUNTIMEOP_STATE`       | `/opt/servika/runtime-op.json`                     | Descriptor of the runtime operation in progress.        |
| `SERVIKA_RUNTIMEOP_WRAPPER`     | `/opt/servika/runtime-op.sh`                       | Runtime operation systemd wrapper path.                 |
| `SERVIKA_NODE_ROOT`             | `/usr/local/n/versions/node`                       | Root the `n` version manager keeps Node.js installs in. |
| `SERVIKA_APP_LOG_DIR`           | `/var/log/servika-apps`                            | Root-owned directory holding one log per application.   |
| `SERVIKA_APP_ENV_DIR`           | `/etc/servika/apps`                                | Directory of per-application 0600 `EnvironmentFile`s.   |
| `SERVIKA_FPM_LOG_DIR`           | `/var/log/servika-fpm`                             | Root-owned 0700 directory holding one PHP-FPM error log per tenant, kept out of `/var/log/php-fpm` so the distribution's rotation rule cannot claim it. |
| `SERVIKA_GEOIP_DIR`             | `/var/lib/servika/geoip`                           | Country database and the nginx include generated from it. |
| `SERVIKA_QUARANTINE_DIR`        | `/var/lib/servika/quarantine`                      | Files the malware scanner took out of a tenant tree, kept outside every home so the account they came from cannot reach them. |
| `SERVIKA_TUNING_BACKUP_DIR`     | `/var/lib/servika/tuning-backups`                  | Copies of the configuration files the tuning screen edits, taken before each change and restored by a revert. Kept outside every directory a daemon reads as configuration. |
| `SERVIKA_HOST_APP_ROOT`         | `/opt/servika-apps`                                | One directory per server-level application, outside `/home` so no tenant sweep, quota or backup schedule claims it. |
| `SERVIKA_HOST_APP_LOG_DIR`      | `/var/log/servika-hostapps`                        | Root-owned directory holding one log per server-level application. |
| `SERVIKA_HOST_APP_ENV_DIR`      | `/etc/servika/host-apps`                           | Directory of per-application 0600 `EnvironmentFile`s for server-level applications. |
| `SERVIKA_HOST_APP_BACKUP_DIR`   | `/var/lib/servika/host-app-backups`                | Archives of an application's data directory, taken before removal and kept outside the tree removal deletes. |
| `SERVIKA_INSTALLATION_ID`       | `/etc/servika/installation-id`                     | Random installation ID storage path for version checks. |
| `SERVIKA_VERSION_CACHE`         | `/opt/servika/version-cache.json`                  | Cached version manifest path.                           |
| `SERVIKA_PMA_TOKEN`             | `/etc/servika/pma-internal.token`                  | Internal phpMyAdmin signon token path.                  |
| `SERVIKA_PMA_SIGNON_DIR`        | `/opt/servika/pma-signon`                          | phpMyAdmin signon bridge directory.                     |
| `SERVIKA_PHPMYADMIN_ROOT`       | `/opt/phpmyadmin`                                  | phpMyAdmin installation root.                           |
| `SERVIKA_PHPMYADMIN_VAR_LIB`    | `/var/lib/phpmyadmin`                              | phpMyAdmin session and temporary directory, owned by the PHP-FPM pool user. |
| `SERVIKA_PHPMYADMIN_CONFIG`     | `/opt/phpmyadmin/config.inc.php`                   | phpMyAdmin config file path.                            |
| `SERVIKA_CERT_ROOT`             | `/etc/pki/servika`                                 | Domain certificate storage root.                        |
| `SERVIKA_NGINX_CACHE_DIR`       | `/var/cache/nginx/servikacache`                    | nginx FastCGI cache data directory.                     |
| `SERVIKA_NGINX_CACHE_CONF`      | `/etc/nginx/conf.d/servikacache.conf`              | nginx FastCGI cache zone config path.                   |
| `SERVIKA_NGINX_CACHE_TEMP_CONF` | `/etc/nginx/conf.d/00-servikacache-temporary.conf` | Temporary nginx cache bypass config path.               |
| `SERVIKA_NGINX_CACHE_LOG_CONF`  | `/etc/nginx/conf.d/00-servika-cache-log.conf`      | nginx cache log format config path.                     |
| `SERVIKA_NGINX_UPGRADE_MAP_CONF` | `/etc/nginx/conf.d/00-servika-upgrade-map.conf`   | nginx WebSocket upgrade map config path.                |
| `SERVIKA_MARIADB_SLOW_LOG`      | `/var/log/mariadb/servika-slow.log`                | MariaDB slow query log the panel writes and reads.      |
| `SERVIKA_MAIL_LOG`              | `/var/log/maillog`                                 | Postfix and Dovecot log file read by the delivery log.  |
| `SERVIKA_ROUNDCUBE_CONFIG`      | `/opt/roundcube/config/config.inc.php`             | Roundcube webmail config file path.                     |
| `SERVIKA_ROUNDCUBE_PLUGINS`     | `/opt/roundcube/plugins`                           | Roundcube plugin directory, used by the sign-on bridge. |

### External URL variables

| Variable                       | Default                                 | Purpose                                                                    |
|--------------------------------|-----------------------------------------|----------------------------------------------------------------------------|
| `SERVIKA_GITHUB_API`           | `https://api.github.com`                | GitHub API base URL used by repository integrations.                       |
| `SERVIKA_IONCUBE_URL`          | ionCube Linux x86-64 loader archive URL | ionCube loader download URL.                                               |
| `SERVIKA_UPDATE_BOOTSTRAP_URL` | public `servika-update` raw URL         | Update tool bootstrap URL used when the panel has to download the updater. |
| `SERVIKA_VERSION_ENDPOINT`     | public version manifest URL             | Version manifest endpoint used by the update checker.                      |
| `SERVIKA_DNS_VERIFY_RESOLVER`  | `1.1.1.1:53`                            | Recursive resolver used by the DNS verification screen. It is deliberately not the system resolver: this host runs an authoritative BIND for the domains it serves, so `/etc/resolv.conf` would answer from the local zone and hide the very mismatch the screen exists to find. |

Disable external version checks:

```bash
SERVIKA_VERSION_CHECK=0
```

Use another manifest endpoint:

```bash
SERVIKA_VERSION_ENDPOINT=https://example.com/version.json
```

To bootstrap the tool manually when the panel is unavailable:

```bash
curl -fsSL https://raw.githubusercontent.com/ServikaPanel/servika/main/assets/ops/servika-update \
  -o /usr/local/bin/servika-update && chmod +x /usr/local/bin/servika-update

servika-update
```

## Panel database backups

The `servika-db-backup.timer` unit runs daily at 03:30 with a randomized delay of up to five minutes. Backups are stored under `SERVIKA_DBDIR`, default `/var/backups/servika/db`, with directory mode `0700` and file mode `0600`. Dumps are retained for 14 days and receive their final filename only after gzip integrity and minimum-size checks pass.

Create a backup manually:

```bash
servika-db-backup
```

Restore a selected backup while the panel is stopped:

```bash
systemctl stop servika
gunzip -c /var/backups/servika/db/panel-YYYY-MM-DD-HHMMSS.sql.gz | mysql
systemctl start servika
```

### Offsite panel database backups

The panel database backup can also push each dump to a remote FTP/SFTP destination for offsite recovery. It is optional and best-effort: when unconfigured the local behavior is unchanged, and an upload failure never fails the local dump. Configure it in `/etc/servika/env`:

| Variable                  | Default                  | Purpose                                                                        |
|---------------------------|--------------------------|--------------------------------------------------------------------------------|
| `SERVIKA_DB_OFFSITE_TYPE` | empty (disabled)         | `ftp` or `sftp`. A non-empty value enables the offsite upload.                 |
| `SERVIKA_DB_OFFSITE_HOST` | empty                    | Destination hostname or IP. Rejected if it contains shell/lftp metacharacters. |
| `SERVIKA_DB_OFFSITE_PORT` | `21` (ftp) / `22` (sftp) | Destination port.                                                              |
| `SERVIKA_DB_OFFSITE_USER` | empty                    | Destination username.                                                          |
| `SERVIKA_DB_OFFSITE_PASS` | empty                    | Destination password.                                                          |
| `SERVIKA_DB_OFFSITE_DIR`  | `servika-db`             | Remote target directory.                                                       |
| `SERVIKA_DB_OFFSITE_KEEP` | `14`                     | Number of newest remote dumps to retain.                                       |

Panel database backups are separate from customer site and database backups, which the panel's built-in scheduler runs per domain according to each domain's configured frequency, hour, and retention. Customer backup archives are stored under `SERVIKA_BACKUP_ROOT`, default `/var/backups/servika`.

## Core repair

When core panel files become corrupted (0-byte frontend, missing binary), restore them from the canonical release without touching customer data:

```bash
servika-restore              # Restore core files from the canonical release
servika-restore --dry-run    # Diagnose only — show what is broken, touch nothing
servika-restore --no-restart # Repair files but do not restart the service
```

## Notes

- Re-running the installer preserves existing runtime secrets in `/etc/servika/env` (database, JWT, secret-key, Redis) and only generates them on first install. For routine maintenance prefer `servika-repair` or `servika-optimize`; use `servika-update` to move to a new release.
- The panel is served over HTTP/2 with self-signed SSL on port 8443. A real domain and Let's Encrypt certificate can be configured through the panel.
- ARM64 (aarch64) is fully supported. Remi provides complete package parity with x86_64 for EL10 (3100+ packages).

---

## Building from source and development

This project is fully **open source** under the MIT license. You can build and develop it from source instead of using the prebuilt binaries. Contributions are welcome.

### Requirements

- **Go 1.25+** for the backend (`go.mod` pins `toolchain go1.26.6`, which the Go toolchain fetches automatically)
- **Node.js 24** and **npm** for the frontend (matches CI)
- MariaDB/MySQL access for runtime execution; migrations and seed data are applied on startup

### Backend (Go)

Release binaries target `GOAMD64=v1` (amd64) and default `GOARM64` (arm64). Use `scripts/build-assets.sh <version>` when publishing release binaries; it requires a version argument, runs a govulncheck gate, and writes to `release/linux_amd64/` and `release/linux_arm64/`.

```bash
# Build a single static binary
CGO_ENABLED=0 GOAMD64=v1 go build -trimpath -o servika-server ./cmd/server

# Build for ARM64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o servika-server ./cmd/server

# Run with environment variables (both secrets are required at boot, ≥32 chars each)
SERVIKA_JWT_SECRET="$(openssl rand -hex 32)" \
SERVIKA_SECRET_KEY="$(openssl rand -hex 32)" \
SERVIKA_DB_DSN="root@unix(/var/lib/mysql/mysql.sock)/panel" \
./servika-server
```

The backend API is available under `/api/v1`, health check at `/healthz`. In production, administrator login verifies the system root account through /etc/shadow. For development, seed a separate administrator:

```bash
go run scripts/seed_admin.go -dsn '<DSN>' -username admin -password 'CHOOSE_A_PASSWORD' -email 'admin@example.com'
# Alternatively, use the SERVIKA_SEED_PASSWORD environment variable.
```

### Frontend (React + Vite + TypeScript)

```bash
cd frontend
npm install
npm run dev        # Development server on :5185, proxies /api to VITE_API_PROXY
npm run build      # Production build output in frontend/dist/
```

Set `VITE_API_PROXY` to the backend address (defaults to `http://localhost:8080`):

```bash
VITE_API_PROXY=http://localhost:8080 npm run dev
```

### Repository structure

```
cmd/server/       Go entry point (main); central chi router and startup sequence
internal/         Backend packages (domains, wordpress, dns, mail, redis, firewall, files, provisioner, ...)
frontend/src/     React interface (pages/, components/, lib/, store/)
migrations/       Numbered SQL schema migrations applied at startup
scripts/          Build-time tools only (build-assets.sh, seed_admin.go)
assets/           Static release inputs committed to the repo: ops/ (runtime scripts),
                  nginx/, php-fpm/, phpmyadmin/, systemd/, mail/ (no compiled binaries)
install.sh        One-line bootstrap that downloads the release bundle and runs servika-install.sh
.github/workflows/ CI (ci.yml), reusable gates (validate.yml), and release publishing (release.yml)
```

The repository does **not** commit compiled binaries. `scripts/build-assets.sh <version>` produces the Go binaries under `release/`, and CI (`.github/workflows/release.yml`, triggered by a `vX.Y.Z` tag) packages them together with the frontend and migrations archives into per-architecture GitHub Release bundles (`servika-<version>-<arch>.tar.gz`). `install.sh`, `servika-update`, and `servika-restore` download those immutable bundles. Bump the version in all five hardcoded copies with the `/version-update` workflow before tagging.

## Contributing and license

- Contributions through issues and pull requests are welcome.
- License: **MIT**. See [LICENSE](LICENSE).
