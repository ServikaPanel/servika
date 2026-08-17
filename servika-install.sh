#!/usr/bin/env bash
# servika-install turns a clean AlmaLinux 10 server into a complete Servika installation.
# It is idempotent and must run as root.
#
#   ./servika-install.sh [--admin-password <password>] [--admin-email <email>] [--panel-lang <en|tr|de|fr|it|pt|pt-BR|es|cs|ro|ja|zh>]
#
# The assets directory must be located next to this script:
#   linux_amd64/servika-server  linux_amd64/servika-seed-admin
#   linux_arm64/servika-server  linux_arm64/servika-seed-admin
#   frontend-dist.tar.gz  migrations.tar.gz  nginx/*  php-fpm/*  phpmyadmin/*  systemd/*  ops/*  mail/*
set -uo pipefail

# Detect host architecture for binary selection.
MACHINE=$(uname -m)
case "$MACHINE" in
  x86_64)  ARCH=linux_amd64 ;;
  aarch64) ARCH=linux_arm64 ;;
  *)       echo "unsupported architecture: $MACHINE (expected x86_64 or aarch64)" >&2; exit 1 ;;
esac

HERE="$(cd "$(dirname "$0")" && pwd)"
A="$HERE/assets"
ADMIN_PASSWORD=""; ADMIN_EMAIL="admin@local"; PANEL_LANG="${SERVIKA_PANEL_LANG:-en}"
while [ $# -gt 0 ]; do case "$1" in
  --admin-password) shift; ADMIN_PASSWORD="$1" ;;
  --admin-email) shift; ADMIN_EMAIL="$1" ;;
  --panel-lang) shift; PANEL_LANG="$1" ;;
  *) echo "unknown option: $1"; exit 2 ;;
esac; shift; done
# Server-default panel language shown on the login screen. English is the primary
# language; an unsupported code falls back to it. A signed-in user's own preference
# always overrides this. Keep this set in sync with internal/config/lang.go.
#
# Canonicalize first, exactly as internal/config.canonLang does: trim surrounding
# whitespace (a trailing CR from a CRLF env file counts), lowercase the base subtag
# and uppercase the region. Without this the panel accepts "TR" and "pt-br" while
# the installer silently wrote English into panel_settings.default_lang.
PANEL_LANG="$(printf '%s' "$PANEL_LANG" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
case "$PANEL_LANG" in
  *-*) PANEL_LANG="$(printf '%s' "${PANEL_LANG%%-*}" | tr 'A-Z' 'a-z')-$(printf '%s' "${PANEL_LANG#*-}" | tr 'a-z' 'A-Z')" ;;
  *)   PANEL_LANG="$(printf '%s' "$PANEL_LANG" | tr 'A-Z' 'a-z')" ;;
esac
case "$PANEL_LANG" in
  en|tr|de|fr|it|pt|pt-BR|es|cs|ro|ja|zh) ;;
  *) PANEL_LANG="en" ;;
esac

c_g="\033[32m"; c_y="\033[33m"; c_r="\033[31m"; c_b="\033[1;34m"; c_0="\033[0m"
[ -t 1 ] || { c_g=; c_y=; c_r=; c_b=; c_0=; }
step(){ echo -e "\n${c_b}══ $* ══${c_0}"; }
ok(){ echo -e "  ${c_g}✓${c_0} $*"; }
warn(){ echo -e "  ${c_y}!${c_0} $*"; }
die(){ echo -e "  ${c_r}✗ $*${c_0}"; exit 1; }
# verify_sha256 <file> <expected_hex>: succeeds only when the file's sha256 matches.
# Used to gate every third-party download before it is executed or extracted.
verify_sha256(){ [ "$(sha256sum "$1" 2>/dev/null | awk '{print $1}')" = "$2" ]; }
# download <url> <out>: fetch a URL to a file. Some VPS networks advertise an
# AAAA record but have no working IPv6 egress; when curl picks IPv6 first the
# download hangs or silently produces an empty file. Try normally, then fall
# back to forcing IPv4 so first-boot fetches do not stall.
download(){
  curl -fsSL --retry 3 --connect-timeout 15 -o "$2" "$1" ||
    curl -4fsSL --retry 3 --connect-timeout 15 -o "$2" "$1"
}

[ "$(id -u)" = 0 ] || die "root is required"
[ -d "$A" ] || die "assets/ was not found ($A)"
grep -qiE "AlmaLinux|Rocky|Red Hat|CentOS" /etc/os-release || warn "AlmaLinux/RHEL 10 was expected, continuing anyway"

PHP_VERS="74 80 81 82 83 84 85"
PHP_EXT="fpm cli mysqlnd mbstring bcmath intl gd soap opcache pdo xml zip pgsql ldap"

# ============ 1) REPOSITORIES ============
step "1) Repositories (EPEL + Remi + CRB)"
dnf install -y epel-release >/dev/null 2>&1 && ok "EPEL"
rpm -q remi-release >/dev/null 2>&1 || dnf install -y https://rpms.remirepo.net/enterprise/remi-release-10.rpm >/dev/null 2>&1
rpm -q remi-release >/dev/null 2>&1 && ok "Remi" || die "Remi could not be added"
dnf config-manager --set-enabled crb >/dev/null 2>&1 && ok "CRB"

# ============ 2) BASE PACKAGES ============
step "2) Base packages"
dnf install -y nginx httpd mariadb-server valkey certbot python3-certbot-nginx \
  clamav clamav-update httpd-tools mod_proxy_html tar openssl policycoreutils-python-utils \
  setools-console jq bind bind-utils nftables unzip zip cronie xfsprogs sudo \
  acl libarchive bubblewrap rsync git curl nodejs npm lftp sshpass >/dev/null 2>&1 \
  && ok "nginx, httpd, mariadb, valkey, certbot, clamav, bind, nftables, archives, ACL, bubblewrap, git, nodejs, npm, lftp, sshpass, utilities" || die "base package installation"
command -v unar >/dev/null 2>&1 || dnf install -y unar >/dev/null 2>&1 || warn "unar could not be installed; RAR support will use bsdtar when available"

# ============ 2b) Disk quota (XFS user quota - CloudLinux parity) ============
# Per-tenant disk + inode quota is enforced via XFS *user* quota (files are owned
# c_<sk>:c_<sk> → user quota maps exactly + escape-protected). The root XFS quota
# can only be enabled at MOUNT time (live remount cannot activate it) → GRUB
# `rootflags=uquota` is written. On a fresh install a post-install reboot brings
# the quota ACTIVE.
step "2b) Disk quota (XFS user quota)"
dnf install -y quota xfsprogs >/dev/null 2>&1 && ok "quota + xfsprogs" || warn "quota packages skipped"
ROOTFS_TYPE=$(findmnt -no FSTYPE / 2>/dev/null || echo "")
ROOTFS_OPTS=$(findmnt -no OPTIONS / 2>/dev/null || echo "")
if [ "$ROOTFS_TYPE" != "xfs" ]; then
  warn "root filesystem is not XFS ($ROOTFS_TYPE) — XFS disk quota skipped"
elif echo "$ROOTFS_OPTS" | grep -qwE 'usrquota|uquota|quota'; then
  ok "root XFS user quota already active"
else
  if grep -q 'rootflags=uquota' /etc/default/grub 2>/dev/null; then
    ok "GRUB rootflags=uquota already present"
  else
    if grep -q '^GRUB_CMDLINE_LINUX=' /etc/default/grub 2>/dev/null; then
      sed -i 's/^\(GRUB_CMDLINE_LINUX="[^"]*\)"/\1 rootflags=uquota"/' /etc/default/grub
    else
      echo 'GRUB_CMDLINE_LINUX="rootflags=uquota"' >> /etc/default/grub
    fi
    # Update existing boot entries (BLS) + regenerate grub.cfg (BIOS + EFI).
    command -v grubby >/dev/null 2>&1 && grubby --update-kernel=ALL --args="rootflags=uquota" >/dev/null 2>&1 || true
    grub2-mkconfig -o /boot/grub2/grub.cfg >/dev/null 2>&1 || true
    for cfg in /boot/efi/EFI/*/grub.cfg; do [ -f "$cfg" ] && grub2-mkconfig -o "$cfg" >/dev/null 2>&1 || true; done
    ok "GRUB rootflags=uquota added (root XFS)"
  fi
  warn "Disk quota requires a SINGLE reboot to become active (root filesystem cannot be remounted with quota)."
fi

# ============ 2c) FIREWALL, disable firewalld so Servika owns nftables ============
step "2c) Firewall (disable firewalld, Servika takes over)"
if systemctl cat firewalld.service >/dev/null 2>&1; then
  systemctl disable --now firewalld >/dev/null 2>&1 || true
  systemctl mask firewalld >/dev/null 2>&1 || true
  ok "firewalld stopped and masked (single firewall = Servika nftables)"
else
  ok "firewalld is not installed (Servika nftables is the single firewall)"
fi

# ============ 3) PHP (8 versions + base + wp-cli) ============
step "3) PHP versions (8 Remi + base) + wp-cli"
# Disable dnf automatic timers before batch install to prevent lock contention.
# Managed panel updates handle patching on their own schedule.
systemctl disable --now dnf-automatic.timer dnf-makecache.timer >/dev/null 2>&1 || true
BASE_PKGS="php php-fpm php-cli php-mysqlnd php-mbstring php-json php-intl php-xml php-gd php-pecl-zip php-pecl-redis6"
dnf install -y $BASE_PKGS >/dev/null 2>&1 && ok "base php + php-redis"
for v in $PHP_VERS; do
  pkgs=""; for e in $PHP_EXT; do pkgs="$pkgs php$v-php-$e"; done
  dnf install -y $pkgs php$v-php-pecl-redis6 >/dev/null 2>&1 && ok "php$v (+redis)" || warn "some php$v packages were skipped"
done
# wp-cli is pinned to a fixed release and verified against its published sha256
# before it is made executable, so a compromised CDN cannot place arbitrary PHP
# on a root-run path. Bump WP_CLI_VER + WP_CLI_SHA256 together to upgrade.
WP_CLI_VER="2.12.0"
WP_CLI_SHA256="ce34ddd838f7351d6759068d09793f26755463b4a4610a5a5c0a97b68220d85c"
if [ ! -x /usr/local/bin/wp ]; then
  TMP=$(mktemp -d)
  if curl -fsSL -o "$TMP/wp.phar" "https://github.com/wp-cli/wp-cli/releases/download/v${WP_CLI_VER}/wp-cli-${WP_CLI_VER}.phar" 2>/dev/null \
     && verify_sha256 "$TMP/wp.phar" "$WP_CLI_SHA256"; then
    install -m 0755 "$TMP/wp.phar" /usr/local/bin/wp && ok "wp-cli $WP_CLI_VER (sha256 verified)"
  else warn "wp-cli download failed or checksum mismatch (required for WordPress features)"; fi
  rm -rf "$TMP"
else ok "wp-cli (existing)"; fi

# ============ 4) MARIADB ============
step "4) MariaDB"
systemctl enable --now mariadb >/dev/null 2>&1; sleep 2
systemctl is-active --quiet mariadb || die "MariaDB did not start"

# my.cnf security hardening: MySQL bound to loopback only + LOCAL INFILE disabled.
# Panel and customer sites connect via 127.0.0.1; port 3306 is never exposed externally.
cat > /etc/my.cnf.d/zz-servika-security.cnf <<'MYCNF'
# Servika security hardening (installer)
[mysqld]
bind-address = 127.0.0.1
local-infile = 0
MYCNF
systemctl restart mariadb >/dev/null 2>&1; sleep 2
systemctl is-active --quiet mariadb || die "MariaDB (after security hardening) did not start"
ok "MariaDB security: 3306 bound to loopback + local-infile disabled"

ENVF=/etc/servika/env
# env_value <key>: the value already stored in the environment file, or empty.
env_value(){ [ -s "$ENVF" ] && sed -n "s/^$1=//p" "$ENVF" | tail -n 1; }

if [ -s "$ENVF" ]; then
  DBPASS=$(env_value SERVIKA_DB_PASS)
  [ -n "${DBPASS:-}" ] || DBPASS=$(sed -n 's/^SERVIKA_DB_DSN=panel:\([^@]*\)@.*/\1/p' "$ENVF" | tail -n 1)
  JWT=$(env_value SERVIKA_JWT_SECRET)
  RADMIN=$(env_value SERVIKA_REDIS_ADMIN_PASS)
  SECRETKEY=$(env_value SERVIKA_SECRET_KEY)
fi
[ -n "${DBPASS:-}" ] || DBPASS=$(openssl rand -hex 16)
[ -n "${JWT:-}" ] || JWT=$(openssl rand -hex 32)
[ -n "${RADMIN:-}" ] || RADMIN=$(openssl rand -hex 24)
[ -n "${SECRETKEY:-}" ] || SECRETKEY=$(openssl rand -hex 32)
mysql -u root <<SQL
CREATE DATABASE IF NOT EXISTS panel CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'panel'@'127.0.0.1' IDENTIFIED BY '$DBPASS';
ALTER USER 'panel'@'127.0.0.1' IDENTIFIED BY '$DBPASS';
GRANT ALL PRIVILEGES ON panel.* TO 'panel'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL
# "ALTER USER did not fail" is not proof that the panel can log in. Connect as the
# panel user with the password that is about to be written into the environment
# file; without this check a mismatch surfaces much later, as a service that
# starts and then cannot reach its own database. The password goes through a
# 0600 defaults file rather than the command line, because /proc/<pid>/cmdline is
# world-readable.
DBCHECK=$(mktemp); chmod 600 "$DBCHECK"
printf '[client]\nuser=panel\npassword=%s\nhost=127.0.0.1\n' "$DBPASS" > "$DBCHECK"
if mysql --defaults-extra-file="$DBCHECK" -e 'SELECT 1' panel >/dev/null 2>&1; then
  rm -f "$DBCHECK"
  ok "panel DB + user (panel@127.0.0.1) — connection verified"
else
  rm -f "$DBCHECK"
  die "the panel database user could not be verified with the stored password; installation stopped before writing the environment file"
fi

# ============ 5) DIRECTORIES + ENV ============
step "5) Directories + environment"
mkdir -p /opt/servika/bin /opt/servika/frontend-dist /opt/servika/src/migrations \
         /opt/servika/src/mail-templates /opt/servika/src/scripts /opt/servika/pma-signon /etc/servika /etc/ssl/servika
# Values the panel or its operations tools write LATER, and settings an operator
# may have tuned. A re-run used to blank every one of them: servika-mail-setup
# stores the Postfix/Dovecot and Roundcube database passwords and the Roundcube
# DES key here, so wiping them leaves those services holding credentials the
# environment file no longer knows, and rotating the DES key invalidates stored
# Roundcube sessions. Carry the existing value over whenever there is one.
LISTEN_ADDR=$(env_value SERVIKA_LISTEN);            [ -n "${LISTEN_ADDR:-}" ] || LISTEN_ADDR=127.0.0.1:8080
JWT_LIFETIME=$(env_value SERVIKA_JWT_LIFETIME_SEC); [ -n "${JWT_LIFETIME:-}" ] || JWT_LIFETIME=43200
VERSION_CHECK=$(env_value SERVIKA_VERSION_CHECK);   [ -n "${VERSION_CHECK:-}" ] || VERSION_CHECK=1
PUBLIC_IPV4=$(env_value SERVIKA_PUBLIC_IPV4)
MAINT_MODE=$(env_value SERVIKA_MAINTENANCE_MODE)
MAIL_DB_PASS=$(env_value SERVIKA_MAIL_DB_PASS)
RC_DB_PASS=$(env_value SERVIKA_ROUNDCUBE_DB_PASS)
RC_DES_KEY=$(env_value SERVIKA_ROUNDCUBE_DES_KEY)
MAIL_MASTER_PASS=$(env_value SERVIKA_MAIL_MASTER_PASS)
SEED_PASSWORD=$(env_value SERVIKA_SEED_PASSWORD)
ASSETS_OVERRIDE=$(env_value SERVIKA_ASSETS_OVERRIDE)

# Keys this block owns. Anything else already in the file belongs to the operator
# (or to a future release) and is carried over verbatim rather than dropped.
ENV_MANAGED='SERVIKA_LISTEN|SERVIKA_ENV|SERVIKA_DB_DSN|SERVIKA_DB_PASS|SERVIKA_JWT_SECRET|SERVIKA_SECRET_KEY|SERVIKA_JWT_LIFETIME_SEC|SERVIKA_PUBLIC_IPV4|SERVIKA_MAINTENANCE_MODE|SERVIKA_VERSION_CHECK|SERVIKA_VERSION_ENDPOINT|SERVIKA_REDIS_ADMIN_PASS|SERVIKA_MAIL_DB_PASS|SERVIKA_ROUNDCUBE_DB_PASS|SERVIKA_ROUNDCUBE_DES_KEY|SERVIKA_MAIL_MASTER_PASS|SERVIKA_SEED_PASSWORD|SERVIKA_REPO|SERVIKA_PREFIX|SERVIKA_BIN|SERVIKA_SEED|SERVIKA_FDIST|SERVIKA_MIGR|SERVIKA_SCRIPTS|SERVIKA_OPSBIN|SERVIKA_SVC|SERVIKA_HEALTH|SERVIKA_DBBK|SERVIKA_DBDIR|SERVIKA_ASSETS_OVERRIDE|SERVIKA_COMPOSER_BIN|SERVIKA_WPCLI_BIN|SERVIKA_CLAMSCAN_BIN|SERVIKA_FRESHCLAM_BIN|SERVIKA_PECL_BIN|SERVIKA_REMI_PECL_ROOT|SERVIKA_ACME_HOME|SERVIKA_ACME_BIN|SERVIKA_BACKUP_ROOT|SERVIKA_LARAVEL_LOG_DIR|SERVIKA_PLUGIN_ROOT|SERVIKA_LOG_DIR|SERVIKA_UPDATE_LOG|SERVIKA_KERNELCARE_LOG|SERVIKA_KERNELCARE_WRAPPER|SERVIKA_CVE_LOG|SERVIKA_INSTALLATION_ID|SERVIKA_VERSION_CACHE|SERVIKA_PMA_TOKEN|SERVIKA_PMA_SIGNON_DIR|SERVIKA_PHPMYADMIN_ROOT|SERVIKA_PHPMYADMIN_CONFIG|SERVIKA_CERT_ROOT|SERVIKA_NGINX_CACHE_DIR|SERVIKA_NGINX_CACHE_CONF|SERVIKA_NGINX_CACHE_TEMP_CONF|SERVIKA_NGINX_CACHE_LOG_CONF|SERVIKA_GITHUB_API|SERVIKA_IONCUBE_URL|SERVIKA_UPDATE_BOOTSTRAP_URL'
ENV_EXTRA=""
if [ -s "$ENVF" ]; then
  ENV_EXTRA=$(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$ENVF" | grep -vE "^(${ENV_MANAGED})=" || true)
fi

# Written to a sibling temporary file and renamed into place. A truncating
# redirect leaves a half-written file if this step dies, and the server refuses
# to boot without SERVIKA_DB_DSN, SERVIKA_JWT_SECRET and SERVIKA_SECRET_KEY, so
# an interrupted write used to mean a panel that would not come back.
ENVTMP=$(mktemp /etc/servika/.env.XXXXXX) || die "could not create a temporary environment file"
chmod 600 "$ENVTMP"
cat > "$ENVTMP" <<ENV
SERVIKA_LISTEN=${LISTEN_ADDR}
SERVIKA_ENV=production
SERVIKA_DB_DSN=panel:${DBPASS}@tcp(127.0.0.1:3306)/panel?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci
SERVIKA_DB_PASS=${DBPASS}
SERVIKA_JWT_SECRET=${JWT}
SERVIKA_SECRET_KEY=${SECRETKEY}
SERVIKA_JWT_LIFETIME_SEC=${JWT_LIFETIME}
SERVIKA_PUBLIC_IPV4=${PUBLIC_IPV4}
SERVIKA_MAINTENANCE_MODE=${MAINT_MODE}
SERVIKA_VERSION_CHECK=${VERSION_CHECK}
SERVIKA_VERSION_ENDPOINT=https://raw.githubusercontent.com/ServikaPanel/servika/main/version.json
SERVIKA_REDIS_ADMIN_PASS=${RADMIN}
SERVIKA_MAIL_DB_PASS=${MAIL_DB_PASS}
SERVIKA_ROUNDCUBE_DB_PASS=${RC_DB_PASS}
SERVIKA_ROUNDCUBE_DES_KEY=${RC_DES_KEY}
SERVIKA_MAIL_MASTER_PASS=${MAIL_MASTER_PASS}
SERVIKA_SEED_PASSWORD=${SEED_PASSWORD}
SERVIKA_REPO=ServikaPanel/servika
SERVIKA_PREFIX=/opt/servika
SERVIKA_BIN=/opt/servika/bin/servika-server
SERVIKA_SEED=/opt/servika/bin/servika-seed-admin
SERVIKA_FDIST=/opt/servika/frontend-dist
SERVIKA_MIGR=/opt/servika/src/migrations
SERVIKA_SCRIPTS=/opt/servika/src/scripts
SERVIKA_OPSBIN=/usr/local/bin
SERVIKA_SVC=servika
SERVIKA_HEALTH=http://127.0.0.1:8080/healthz
SERVIKA_DBBK=/usr/local/bin/servika-db-backup
SERVIKA_DBDIR=/var/backups/servika/db
SERVIKA_ASSETS_OVERRIDE=${ASSETS_OVERRIDE}
SERVIKA_COMPOSER_BIN=/usr/local/bin/composer
SERVIKA_WPCLI_BIN=/usr/local/bin/wp
SERVIKA_CLAMSCAN_BIN=/usr/bin/clamscan
SERVIKA_FRESHCLAM_BIN=/usr/bin/freshclam
SERVIKA_PECL_BIN=/usr/bin/pecl
SERVIKA_REMI_PECL_ROOT=/opt/remi
SERVIKA_ACME_HOME=/root/.acme.sh
SERVIKA_ACME_BIN=/root/.acme.sh/acme.sh
SERVIKA_BACKUP_ROOT=/var/backups/servika
SERVIKA_LARAVEL_LOG_DIR=/var/log/servika-laravel
SERVIKA_PLUGIN_ROOT=/opt/servika/plugins
SERVIKA_LOG_DIR=/opt/servika/logs
SERVIKA_UPDATE_LOG=/opt/servika/logs/update.log
SERVIKA_KERNELCARE_LOG=/opt/servika/logs/kernelcare-update.log
SERVIKA_KERNELCARE_WRAPPER=/opt/servika/kernelcare-update.sh
SERVIKA_CVE_LOG=/opt/servika/logs/cve-update.log
SERVIKA_INSTALLATION_ID=/etc/servika/installation-id
SERVIKA_VERSION_CACHE=/opt/servika/version-cache.json
SERVIKA_PMA_TOKEN=/etc/servika/pma-internal.token
SERVIKA_PMA_SIGNON_DIR=/opt/servika/pma-signon
SERVIKA_PHPMYADMIN_ROOT=/opt/phpmyadmin
SERVIKA_PHPMYADMIN_CONFIG=/opt/phpmyadmin/config.inc.php
SERVIKA_CERT_ROOT=/etc/pki/servika
SERVIKA_NGINX_CACHE_DIR=/var/cache/nginx/servikacache
SERVIKA_NGINX_CACHE_CONF=/etc/nginx/conf.d/servikacache.conf
SERVIKA_NGINX_CACHE_TEMP_CONF=/etc/nginx/conf.d/00-servikacache-temporary.conf
SERVIKA_NGINX_CACHE_LOG_CONF=/etc/nginx/conf.d/00-servika-cache-log.conf
SERVIKA_GITHUB_API=https://api.github.com
SERVIKA_IONCUBE_URL=https://downloads.ioncube.com/loader_downloads/ioncube_loaders_lin_x86-64.tar.gz
SERVIKA_UPDATE_BOOTSTRAP_URL=https://raw.githubusercontent.com/ServikaPanel/servika/main/assets/ops/servika-update
ENV
if [ -n "$ENV_EXTRA" ]; then printf '%s\n' "$ENV_EXTRA" >> "$ENVTMP"; fi
mv -f "$ENVTMP" "$ENVF" || die "could not put the environment file in place"
chmod 600 "$ENVF"
ENV_EXTRA_COUNT=0
if [ -n "$ENV_EXTRA" ]; then ENV_EXTRA_COUNT=$(printf '%s\n' "$ENV_EXTRA" | wc -l | tr -d ' '); fi
ok "$ENVF (secrets and operator settings preserved; $ENV_EXTRA_COUNT additional key(s) carried over)"

# ============ 6) ARTIFACT DEPLOYMENT ============
step "6) Panel binary + frontend + migrations"
install -m 0755 "$A/$ARCH/servika-server" /opt/servika/bin/servika-server
[ -f "$A/$ARCH/servika-seed-admin" ] && install -m 0755 "$A/$ARCH/servika-seed-admin" /opt/servika/bin/servika-seed-admin
tar xzf "$A/frontend-dist.tar.gz" -C /opt/servika/frontend-dist && ok "frontend-dist"
tar xzf "$A/migrations.tar.gz" -C /opt/servika/src/migrations && ok "migrations ($(ls /opt/servika/src/migrations/*.sql 2>/dev/null | wc -l) SQL)"
if [ -d "$A/mail" ]; then
  rm -rf /opt/servika/src/mail-templates/*
  cp -a "$A/mail/." /opt/servika/src/mail-templates/
  ok "mail templates (postfix, dovecot, opendkim, roundcube)"
fi
# Operations tools and phpMyAdmin signon
for t in "$A"/ops/*; do
  bn=$(basename "$t"); nm="${bn%.sh}"
  install -m 0755 "$t" "/usr/local/bin/$nm" 2>/dev/null
done
cp "$A/ops/"* /opt/servika/src/scripts/ 2>/dev/null
ok "operations tools (/usr/local/bin: update, db-backup, optimize, redis-setup, ftp-setup, mail-setup, repair, jail, wp-redis)"

# ============ 7) PANEL SSL (self-signed) ============
step "7) Panel SSL (:8443 self-signed)"
if [ ! -f /etc/ssl/servika/panel.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout /etc/ssl/servika/panel.key -out /etc/ssl/servika/panel.crt \
    -subj "/CN=servika" >/dev/null 2>&1
fi
chmod 600 /etc/ssl/servika/panel.key
ok "panel.crt / panel.key"

# ============ 8) NGINX ============
step "8) nginx (panel vhost + phpMyAdmin + perf)"
# Apply the HTTP-level client_max_body_size setting idempotently.
# Do not add server_names_hash_bucket_size because servika-optimize already defines it
# in 00-perf.conf, and defining it here would make nginx -t report a duplicate directive.
grep -q "client_max_body_size 10240m" /etc/nginx/nginx.conf || \
  sed -i '/^http {/a\    client_max_body_size 10240m;' /etc/nginx/nginx.conf
cp "$A/nginx/_panel.conf"      /etc/nginx/conf.d/_panel.conf
cp "$A/nginx/_default80.conf"  /etc/nginx/conf.d/_default80.conf
cp "$A/nginx/_default443.conf" /etc/nginx/conf.d/_default443.conf
cp "$A/nginx/php-fpm.conf"     /etc/nginx/conf.d/php-fpm.conf 2>/dev/null
# Suppress the default server block shipped by AlmaLinux nginx.rpm (conflicts with _default80.conf).
if grep -q "^\s*server_name\s*_;\s*$" /etc/nginx/nginx.conf; then
  line=$(grep -n "^\s*server_name\s*_;\s*$" /etc/nginx/nginx.conf | cut -d: -f1 | head -1)
  if [ -n "$line" ]; then
    start=$((line - 2))
    end=$((line + 8))
    sed -i "${start},${end}s/^/    #/" /etc/nginx/nginx.conf
    ok "nginx default server block disabled (replaced by _default80.conf)"
  fi
fi
# Raise nginx worker file-descriptor limit (otherwise setrlimit RLIMIT_NOFILE fails).
mkdir -p /etc/systemd/system/nginx.service.d
	cat > /etc/systemd/system/nginx.service.d/servika-nofile.conf <<'NFEOF'
[Service]
LimitNOFILE=65535
NFEOF
systemctl daemon-reload 2>/dev/null
nginx -t >/dev/null 2>&1 && ok "nginx -t OK" || { nginx -t; die "nginx configuration error"; }

# ============ 9) phpMyAdmin ============
step "9) phpMyAdmin"
mkdir -p /opt/phpmyadmin   # Create this first so extraction with strip-components succeeds.
# phpMyAdmin is pinned to a fixed release and verified against its published
# sha256 before extraction; a moving "latest" tarball or compromised CDN cannot
# inject arbitrary PHP into the panel origin. Bump PMA_VER + PMA_SHA256 together.
PMA_VER="5.2.2"
PMA_SHA256="8551c8bf3b166f232d5cf64bac877472e9d0cb8f2fe1858fab24f975e7d765b6"
if [ ! -f /opt/phpmyadmin/index.php ]; then
  TMP=$(mktemp -d)
  if curl -fsSL -o "$TMP/pma.tar.gz" "https://files.phpmyadmin.net/phpMyAdmin/${PMA_VER}/phpMyAdmin-${PMA_VER}-all-languages.tar.gz" \
     && verify_sha256 "$TMP/pma.tar.gz" "$PMA_SHA256" \
     && tar xzf "$TMP/pma.tar.gz" -C /opt/phpmyadmin --strip-components=1; then
    ok "phpMyAdmin $PMA_VER (sha256 verified + extracted)"
  else warn "phpMyAdmin download failed or checksum mismatch, run servika-repair manually later"; fi
  rm -rf "$TMP"
fi
if [ -f "$A/phpmyadmin/config.inc.php" ]; then
  BLOWFISH=$(openssl rand -hex 16)           # Generate a fresh production secret.
  PMACTRL=$(openssl rand -hex 16)            # Generate a fresh control-user password.
  # The umask is applied at creation so the file is never world-readable, not
  # even for the moment between the redirection and a later chmod. It carries
  # the blowfish secret, which encrypts the MySQL credentials phpMyAdmin puts in
  # the visitor's cookie, and the control-user password for an account holding
  # ALL PRIVILEGES on the phpmyadmin schema. Every c_* tenant has a shell here.
  ( umask 027; sed -e "s/BLOWFISH_SECRET_PLACEHOLDER/$BLOWFISH/g" -e "s/PMA_CONTROL_PASS_PLACEHOLDER/$PMACTRL/g" \
    "$A/phpmyadmin/config.inc.php" > /opt/phpmyadmin/config.inc.php )
  # Create the control user, phpMyAdmin database, and pmadb tables for advanced features.
  mysql -u root <<SQL 2>/dev/null
CREATE DATABASE IF NOT EXISTS phpmyadmin;
CREATE USER IF NOT EXISTS 'pma'@'127.0.0.1' IDENTIFIED BY '$PMACTRL';
CREATE USER IF NOT EXISTS 'pma'@'localhost' IDENTIFIED BY '$PMACTRL';
ALTER USER 'pma'@'127.0.0.1' IDENTIFIED BY '$PMACTRL';
ALTER USER 'pma'@'localhost' IDENTIFIED BY '$PMACTRL';
GRANT ALL PRIVILEGES ON phpmyadmin.* TO 'pma'@'127.0.0.1', 'pma'@'localhost';
FLUSH PRIVILEGES;
SQL
  [ -f /opt/phpmyadmin/sql/create_tables.sql ] && mysql -u root phpmyadmin < /opt/phpmyadmin/sql/create_tables.sql 2>/dev/null
fi
[ -f "$A/phpmyadmin/pma-signon.php" ] && cp "$A/phpmyadmin/pma-signon.php" /opt/servika/pma-signon/ 2>/dev/null
openssl rand -hex 32 > /etc/servika/pma-internal.token
chown root:apache /etc/servika/pma-internal.token
chmod 0640 /etc/servika/pma-internal.token
cp "$A/php-fpm/phpmyadmin.conf" /etc/php-fpm.d/phpmyadmin.conf
[ -f "$A/php-fpm/roundcube.conf" ] && cp "$A/php-fpm/roundcube.conf" /etc/php-fpm.d/roundcube.conf
mkdir -p /var/lib/phpmyadmin/{tmp,sessions} /var/lib/roundcube/{temp,sessions}
# The phpMyAdmin pool runs as apache (assets/php-fpm/phpmyadmin.conf), so the
# tree belongs to apache and not to nginx. Owning it as nginx made phpMyAdmin
# work only because the files were world-readable, which handed config.inc.php
# to every account on the host. These modes match assets/ops/servika-repair and
# the startup heal in internal/provisioner/pma_heal.go; all three must agree.
chown -R root:apache /opt/phpmyadmin 2>/dev/null
chown root:apache /opt/phpmyadmin/config.inc.php 2>/dev/null
chmod 0640 /opt/phpmyadmin/config.inc.php || warn "could not restrict config.inc.php; it holds the phpMyAdmin secrets"
chown -R apache:apache /var/lib/phpmyadmin 2>/dev/null
chmod 0755 /var/lib/phpmyadmin /var/lib/phpmyadmin/tmp
# A session file holds the credentials of whoever is signed in.
chmod 0700 /var/lib/phpmyadmin/sessions || warn "could not restrict the phpMyAdmin session directory"
chown -R apache:apache /var/lib/roundcube 2>/dev/null
restorecon -R /opt/phpmyadmin /var/lib/phpmyadmin /var/lib/roundcube >/dev/null 2>&1
setsebool -P httpd_can_network_connect_db 1 >/dev/null 2>&1
ok "phpMyAdmin and Roundcube pools + phpMyAdmin configuration + permissions"

# ============ 10) systemd + services ============
step "10) systemd + services"
cp "$A/systemd/servika.service" /etc/systemd/system/servika.service
for unit in servika-db-backup.service servika-db-backup.timer; do
  [ -f "$A/systemd/$unit" ] && cp "$A/systemd/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
if [ -f /etc/systemd/system/servika-db-backup.timer ]; then
  systemctl enable --now servika-db-backup.timer >/dev/null 2>&1
  systemctl is-active --quiet servika-db-backup.timer \
    && ok "daily panel database backup active (03:30, 14-day retention)" \
    || warn "database backup timer could not be started"
fi
systemctl enable --now php-fpm >/dev/null 2>&1
for v in $PHP_VERS; do systemctl enable --now php$v-php-fpm >/dev/null 2>&1; done
ok "php-fpm (base + 5 versions)"

# ---- named authoritative DNS server for hosted domains ----
NC=/etc/named.conf
if [ -f "$NC" ]; then
  cp -a "$NC" "$NC.servika-bak" 2>/dev/null || true
  # Listen on every interface so external clients can query authoritative zones.
  sed -i -E 's/listen-on port 53 \{[^}]*\}/listen-on port 53 { any; }/' "$NC"
  sed -i -E 's/listen-on-v6 port 53 \{[^}]*\}/listen-on-v6 port 53 { any; }/' "$NC"
  # Disable recursion to prevent an open resolver and DNS amplification abuse.
  sed -i -E 's/recursion yes/recursion no/' "$NC"
  # Add the panel-managed zone include idempotently; WriteZone populates it.
  grep -q 'servika-zones.conf' "$NC" || \
    echo 'include "/etc/named/servika-zones.conf";' >> "$NC"
fi
# Initialize the panel-managed zone include; domain provisioning populates it.
mkdir -p /etc/named
[ -f /etc/named/servika-zones.conf ] || \
  printf '// servika, generated automatically\n' > /etc/named/servika-zones.conf
chown root:named /etc/named/servika-zones.conf 2>/dev/null || true
chmod 640 /etc/named/servika-zones.conf 2>/dev/null || true
# Zone files under /var/named require the SELinux named_zone_t context.
restorecon -R /var/named /etc/named >/dev/null 2>&1 || true
if named-checkconf >/dev/null 2>&1; then
  systemctl enable --now named >/dev/null 2>&1 && ok "named (authoritative DNS, :53 open, recursion disabled)" || warn "named could not be started"
else
  warn "named-checkconf error, DNS must be checked manually"
fi

# ---- acme.sh for Let's Encrypt SSL; the panel invokes /root/.acme.sh/acme.sh ----
# Let's Encrypt requires a valid email address; register without contact information otherwise.
AEMAIL="$ADMIN_EMAIL"; echo "$AEMAIL" | grep -qE '@[^@]+\.[^@]+$' || AEMAIL=""
# acme.sh is installed from a pinned git tag over TLS instead of piping the
# mutable get.acme.sh endpoint straight into a root shell. Cloning a fixed tag
# gives a reproducible, reviewable source tree; the installer then runs offline
# from that checkout. Bump ACME_VER to upgrade.
ACME_VER="3.1.4"
if [ ! -x /root/.acme.sh/acme.sh ]; then
  TMP=$(mktemp -d)
  if git clone --depth 1 --branch "$ACME_VER" https://github.com/acmesh-official/acme.sh.git "$TMP/acme" >/dev/null 2>&1; then
    if [ -n "$AEMAIL" ]; then (cd "$TMP/acme" && ./acme.sh --install -m "$AEMAIL" >/dev/null 2>&1) || true
    else (cd "$TMP/acme" && ./acme.sh --install >/dev/null 2>&1) || true; fi
  else warn "acme.sh $ACME_VER could not be cloned"; fi
  rm -rf "$TMP"
fi
if [ -x /root/.acme.sh/acme.sh ]; then
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1
  # Register the account now so certificate issuance does not fail later.
  # The "@ + dot" check above still accepts addresses Let's Encrypt rejects (admin@test.local
  # and other non-public-suffix TLDs). acme.sh persists such an address in BOTH
  # account.conf (ACCOUNT_EMAIL) and ca/*/directory/ca.conf (CA_EMAIL) even when
  # registration fails, and reads CA_EMAIL first on every later call, so a plain retry
  # reuses the broken address and the host can never obtain a certificate. When
  # registration with the address fails, clear both files and retry without a contact.
  if [ -n "$AEMAIL" ] && ! /root/.acme.sh/acme.sh --register-account -m "$AEMAIL" --server letsencrypt >/dev/null 2>&1; then
    sed -i "s/^ACCOUNT_EMAIL=.*/ACCOUNT_EMAIL=''/" /root/.acme.sh/account.conf 2>/dev/null || true
    sed -i "s/^CA_EMAIL=.*/CA_EMAIL=''/" /root/.acme.sh/ca/*/directory/ca.conf 2>/dev/null || true
    /root/.acme.sh/acme.sh --register-account --server letsencrypt >/dev/null 2>&1
  elif [ -z "$AEMAIL" ]; then
    /root/.acme.sh/acme.sh --register-account --server letsencrypt >/dev/null 2>&1
  fi
  ok "acme.sh (Let's Encrypt CA + account registered + automatic renewal cron)"
else
  warn "acme.sh could not be installed, install it manually for Let's Encrypt SSL: curl https://get.acme.sh | sh"
fi

# ---- httpd backend for web_backend=apache, with nginx as the reverse proxy ----
# Apache listens on 127.0.0.1:10080 because nginx owns port 80.
if [ -f /etc/httpd/conf/httpd.conf ]; then
  if grep -qE "^Listen 80$" /etc/httpd/conf/httpd.conf; then
    sed -i "s/^Listen 80$/Listen 127.0.0.1:10080/" /etc/httpd/conf/httpd.conf
  elif ! grep -qE "^Listen 127.0.0.1:10080" /etc/httpd/conf/httpd.conf; then
    echo "Listen 127.0.0.1:10080" >> /etc/httpd/conf/httpd.conf
  fi
  semanage port -l 2>/dev/null | grep -qE "http_port_t.*\b10080\b" || \
    semanage port -a -t http_port_t -p tcp 10080 2>/dev/null || \
    semanage port -m -t http_port_t -p tcp 10080 2>/dev/null
  if apachectl configtest >/dev/null 2>&1; then
    systemctl enable --now httpd >/dev/null 2>&1 && ok "httpd (Apache backend :10080, mod_proxy_fcgi)" || warn "httpd could not be started"
  else warn "httpd configtest error, check the Apache backend manually"; fi
fi

# ---- Composer for per-domain PHP dependency management ----
# Composer is installed via its official signature-verified path: the installer
# is downloaded to disk and its sha384 is compared against the signature
# published on composer.github.io (a different host than getcomposer.org) before
# it is ever executed, instead of piping the network straight into php.
if [ ! -x /usr/local/bin/composer ]; then
  TMP=$(mktemp -d)
  download https://composer.github.io/installer.sig "$TMP/installer.sig" || true
  EXPECTED=$(tr -d '[:space:]' < "$TMP/installer.sig" 2>/dev/null)
  if download https://getcomposer.org/installer "$TMP/composer-setup.php" \
     && [ -n "$EXPECTED" ] \
     && [ "$(php -r "echo hash_file('sha384', '$TMP/composer-setup.php');" 2>/dev/null)" = "$EXPECTED" ]; then
    php "$TMP/composer-setup.php" --install-dir=/usr/local/bin --filename=composer >/dev/null 2>&1
  else warn "composer installer signature mismatch, skipped"; fi
  rm -rf "$TMP"
fi
[ -x /usr/local/bin/composer ] && ok "composer ($(/usr/local/bin/composer --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1))" || warn "composer could not be installed"

# ---- crond for tenant cron jobs ----
# Scheduled domain backups run inside the panel process, which honors each domain's
# frequency, hour, and retention. Remove any legacy standalone backup cron so a domain
# is not backed up twice.
rm -f /etc/cron.d/servika-backup /usr/local/bin/servika-backup-all
# Enable and start crond now because the AlmaLinux preset does not start it before reboot.
# crond is required for tenant crontab entries. The enable --now operation is idempotent.
systemctl enable --now crond >/dev/null 2>&1
systemctl is-active --quiet crond && ok "crond ACTIVE (tenant cron jobs)" || warn "crond could not be started, tenant cron jobs may not run"

# SELinux
setsebool -P httpd_can_network_connect 1 >/dev/null 2>&1 && ok "SELinux httpd_can_network_connect"
setsebool -P httpd_enable_homedirs=on httpd_read_user_content=on >/dev/null 2>&1 \
  && ok "SELinux HTTP access to tenant home content"
if command -v getenforce >/dev/null 2>&1 \
  && [ "$(getenforce)" != "Disabled" ] \
  && command -v semanage >/dev/null 2>&1; then
  fcontext_list=$(semanage fcontext -l 2>/dev/null || true)
  case "$fcontext_list" in
    *'/run/php-fpm-['*) ;;
    *) semanage fcontext -a -t httpd_var_run_t '/run/php-fpm-[^/]+(/.*)?' >/dev/null 2>&1 || true ;;
  esac
  ok "SELinux fcontext for per-tenant PHP-FPM sockets"
fi
restorecon -R /opt/servika/bin /opt/servika/frontend-dist >/dev/null 2>&1

# ============ 11) Valkey + optimization ============
step "11) Valkey (Redis) + performance tuning"
command -v servika-redis-setup >/dev/null 2>&1 && servika-redis-setup >/dev/null 2>&1 && ok "servika-redis-setup" || warn "redis-setup skipped"
# WAF (ModSecurity + OWASP CRS) infrastructure — idempotent, per-domain opt-in (module loading is harmless).
# On first install the connector compilation may take several minutes; failure does not stop the installation.
command -v servika-waf-setup >/dev/null 2>&1 && servika-waf-setup >/dev/null 2>&1 && ok "servika-waf-setup (ModSecurity+CRS)" || warn "waf-setup skipped (panel WAF runs gracefully without the module)"
command -v servika-optimize >/dev/null 2>&1 && servika-optimize >/dev/null 2>&1 && ok "servika-optimize" || warn "optimization skipped"

# ============ 12) START PANEL; MIGRATIONS RUN AT STARTUP ============
step "12) Starting panel"
systemctl enable --now servika >/dev/null 2>&1; sleep 3
systemctl enable --now nginx >/dev/null 2>&1; systemctl restart nginx >/dev/null 2>&1
if systemctl is-active --quiet firewalld 2>/dev/null; then
  firewall-cmd --add-port={80,443,8443}/tcp --permanent >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1 && ok "firewalld: port 80/tcp + 443/tcp + 8443/tcp opened"
fi
if systemctl is-active --quiet servika; then ok "servika ACTIVE"; else journalctl -u servika --no-pager -n 20; die "panel did not start"; fi

# ---- Run the Pure-FTPd setup after migrations create the ftp_accounts table ----
# Running this in step 11 would make GRANT SELECT fail because the table does not exist yet.
sleep 2
command -v servika-ftp-setup >/dev/null 2>&1 && servika-ftp-setup >/dev/null 2>&1 && ok "servika-ftp-setup (Pure-FTPd, MySQL backend)" || warn "ftp-setup skipped"
# Mail setup needs the mail tables created by startup migrations.
command -v servika-mail-setup >/dev/null 2>&1 && servika-mail-setup >/dev/null 2>&1 && ok "servika-mail-setup (Postfix, Dovecot, OpenDKIM, Roundcube)" || warn "mail-setup skipped"

# ============ 13) ADMINISTRATOR ACCESS ============
# Panel administrator login authenticates the server's root account through PAM and shadow.
# There is no separate panel password; use root and the server's root password.
step "13) Administrator access (root + PAM)"
DSN="panel:${DBPASS}@tcp(127.0.0.1:3306)/panel?parseTime=true"
if [ -x /opt/servika/bin/servika-seed-admin ]; then
  # Seed the users record for ownership and audit; login still uses root through PAM.
  if [ -z "$ADMIN_PASSWORD" ]; then
    ADMIN_PASSWORD="$(openssl rand -hex 16)"
  fi
  /opt/servika/bin/servika-seed-admin -dsn "$DSN" -username root \
    -password "$ADMIN_PASSWORD" -email "$ADMIN_EMAIL" -lang "$PANEL_LANG" >/dev/null 2>&1 \
    && ok "administrator record ready" || warn "seed skipped (not critical)"
fi
# Server-default panel language for the pre-login screen (admin can change it later).
mysql panel -e "UPDATE panel_settings SET default_lang='${PANEL_LANG}' WHERE id=1;" >/dev/null 2>&1 \
  && ok "panel default language: ${PANEL_LANG}" || warn "panel language default skipped"
# Clear seed defaults so the root profile starts empty and can be completed in the profile page.
mysql panel -e "UPDATE users SET email='', full_name='' WHERE username='root' AND email='admin@local';" >/dev/null 2>&1 || true
ok "Login: user 'root' + this server's root password"

# ============ 14) PERMISSION REPAIR ============
step "14) Permission/SELinux repair"
command -v servika-repair >/dev/null 2>&1 && servika-repair --quiet >/dev/null 2>&1 && ok "servika-repair" || warn "repair skipped"

# ============ 15) VERIFICATION ============
step "15) Verification"
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
CODE=$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/ 2>/dev/null)
API=$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/api/v1/domains 2>/dev/null)
echo -e "  services: $(systemctl is-active mariadb nginx valkey php-fpm named pure-ftpd postfix dovecot opendkim servika crond | tr '\n' ' ')"
echo -e "  panel :8443 → HTTP $CODE   ·   API (auth) → HTTP $API   ·   DNS :53 → $(systemctl is-active named)   ·   FTP :21 → $(systemctl is-active pure-ftpd)   ·   mail SMTP/IMAP → $(systemctl is-active postfix)/$(systemctl is-active dovecot)"
echo -e "  utilities: SSL/acme.sh $([ -x /root/.acme.sh/acme.sh ] && echo ✓ || echo ✗)   ·   firewall/nft $(command -v nft >/dev/null && echo ✓ || echo ✗)   ·   unzip/zip $(command -v unzip >/dev/null && command -v zip >/dev/null && echo ✓ || echo ✗)   ·   composer $(command -v composer >/dev/null && echo ✓ || echo ✗)   ·   apache/httpd $(systemctl is-active httpd)"
echo -e "  isolation: plan-driven cgroup limits + per-tenant PHP-FPM ready   ·   bubblewrap $(command -v bwrap >/dev/null && echo ✓ || echo ✗)"
echo
echo -e "${c_g}═══════════════════════════════════════════════${c_0}"
echo -e "${c_g} ✓ Servika installation complete${c_0}"
echo -e "   Panel:  ${c_b}https://${IP:-SERVER_IP}:8443${c_0}"
echo -e "   User: ${c_b}root${c_0}   Password: ${c_b}this server's root password${c_0}"
echo -e "   (panel administrator login authenticates the server's root account through PAM)"
if [ "$(findmnt -no FSTYPE / 2>/dev/null)" = "xfs" ] && ! findmnt -no OPTIONS / 2>/dev/null | grep -qwE 'usrquota|uquota|quota'; then
  echo -e "   ${c_y}Disk quota: GRUB rootflags=uquota written — a SINGLE reboot is required to activate.${c_0}"
fi
echo -e "${c_g}═══════════════════════════════════════════════${c_0}"
