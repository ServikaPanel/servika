#!/usr/bin/env bash
# servika-redis-setup installs isolated per-tenant Redis infrastructure using Valkey.
# It is idempotent, runs during installation, and supports the panel's Redis Cache feature.
set -uo pipefail

# Parse in the C locale. Under tr_TR.UTF-8 the ranges `a-z` and `A-Z` do NOT
# contain `i` or `I`, so every character-range parse is cut at the first one
# (measured: `grep -oE '[a-zA-Z0-9_]+'` answers `aud` for `audit_log`). The
# brand name SERVIKA carries an I, so this reaches the environment loader too.
export LC_ALL=C

ENV_FILE=/etc/servika/env

load_servika_env() {
  [ -f "$ENV_FILE" ] || return 0
  [ "$(stat -c %u "$ENV_FILE" 2>/dev/null)" = 0 ] || { echo "insecure environment file owner" >&2; exit 1; }
  mode=$(stat -c %a "$ENV_FILE" 2>/dev/null) || { echo "could not read environment file mode" >&2; exit 1; }
  [ $((8#$mode & 077)) -eq 0 ] || { echo "insecure environment file mode" >&2; exit 1; }

  while IFS= read -r line || [ -n "$line" ]; do
    # POSIX classes, never `A-Za-z0-9`: a range is collation-ordered and under
    # tr_TR.UTF-8 it excludes `i`, which silently skipped SERVIKA_LISTEN.
    [[ "$line" =~ ^[[:space:]]*(SERVIKA_[[:alnum:]_]*)=(.*)$ ]] || continue
    key=${BASH_REMATCH[1]}
    value=${BASH_REMATCH[2]%$'\r'}
    if [[ "$value" == \"*\" && "$value" == *\" ]]; then value=${value:1:${#value}-2}; fi
    if [[ "$value" == \'*\' && "$value" == *\' ]]; then value=${value:1:${#value}-2}; fi
    if [ -z "${!key+x}" ]; then
      printf -v "$key" '%s' "$value"
      export "${key?}"
    fi
  done < "$ENV_FILE"
}

ensure_env_file() {
  mkdir -p "$(dirname "$ENV_FILE")"
  touch "$ENV_FILE"
  chown root:root "$ENV_FILE" 2>/dev/null || true
  chmod 600 "$ENV_FILE"
}

set_env_value() {
  key=$1
  value=$2
  ensure_env_file
  tmp=$(mktemp)
  if [ -f "$ENV_FILE" ]; then
    grep -v -E "^${key}=" "$ENV_FILE" > "$tmp" 2>/dev/null || true
  fi
  printf '%s=%s\n' "$key" "$value" >> "$tmp"
  install -m 600 -o root -g root "$tmp" "$ENV_FILE"
  rm -f "$tmp"
}

log(){ printf '  %s\n' "$*"; }
load_servika_env

echo "════ Valkey + php-redis installation ════"
PHP_REDIS_PKGS=""
for v in php74 php80 php81 php82 php83 php84 php85; do
  [ -d "/etc/opt/remi/$v" ] && PHP_REDIS_PKGS="$PHP_REDIS_PKGS ${v}-php-pecl-redis6"
done
dnf install -y valkey php-pecl-redis6 $PHP_REDIS_PKGS >/tmp/redis-setup.log 2>&1 \
  && log "valkey + php-redis installed" || { log "installation warning (some packages may already be installed)"; }

echo "════ Administrator password + ACL file ════"
ADMIN=${SERVIKA_REDIS_ADMIN_PASS:-}
if [ -z "$ADMIN" ]; then
  ADMIN=$(openssl rand -hex 24)
  set_env_value SERVIKA_REDIS_ADMIN_PASS "$ADMIN"
  export SERVIKA_REDIS_ADMIN_PASS="$ADMIN"
  log "administrator password generated and added to the environment file"
fi
# Add the default administrator entry when absent while preserving tenant ACLs.
ACLF=/etc/valkey/users.acl
if [ ! -f "$ACLF" ] || ! grep -q '^user default ' "$ACLF"; then
  printf 'user default on >%s ~* &* +@all\n' "$ADMIN" > "$ACLF"
  log "users.acl created"
fi
chown valkey:valkey "$ACLF" 2>/dev/null; chmod 640 "$ACLF"

echo "════ valkey.conf cache tuning ════"
CONF=/etc/valkey/valkey.conf
if ! grep -q 'servika-cache' "$CONF"; then
cat >> "$CONF" <<VK

# ===== servika-cache =====
maxmemory 256mb
maxmemory-policy allkeys-lru
save ""
appendonly no
aclfile /etc/valkey/users.acl
VK
  log "valkey.conf tuning added"
fi
sed -i '/^requirepass /d' "$CONF"   # requirepass conflicts with aclfile.

echo "════ SELinux (php-fpm -> redis TCP) ════"
setsebool -P httpd_can_network_connect 1 2>/dev/null && log "httpd_can_network_connect=1"

echo "════ valkey enable + (re)start ════"
systemctl enable valkey >/dev/null 2>&1
systemctl restart valkey; sleep 2
if systemctl is-active --quiet valkey && REDISCLI_AUTH="$ADMIN" valkey-cli PING 2>/dev/null | grep -q PONG; then
  log "✓ valkey ACTIVE + admin auth OK"
else
  log "✗ valkey could not be started; journalctl -u valkey"
  exit 1
fi
echo "════════ ✓ Redis infrastructure ready ════════"
