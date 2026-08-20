#!/usr/bin/env bash
# servika-wp-redis attaches or detaches an isolated per-tenant Valkey object cache
# for a domain user's WordPress installations. It is idempotent and runs as root.
#
#   servika-wp-redis <system_user>        # Attach
#   servika-wp-redis <system_user> off    # Detach
#
# This uses the same configuration as the panel's Redis Cache feature:
#   ACL user with the ~<system_user>:* key prefix, @dangerous disabled, and info/dbsize enabled
#   WordPress with phpredis, selective flush, array credentials, and a copied drop-in
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

SYSTEM_USER="${1:?usage: $0 <system_user> [off]}"
ACTION="${2:-on}"
HOST=127.0.0.1; PORT=6379

# --- Guards ---
# POSIX classes, never `a-z0-9`: under tr_TR.UTF-8 the range excludes `i`, so
# every tenant whose system user carries one was refused as invalid.
if ! [[ "$SYSTEM_USER" =~ ^[[:lower:][:digit:]_]{1,32}$ ]]; then echo "invalid user name: $SYSTEM_USER"; exit 1; fi
[ "$(id -u)" = 0 ] || { echo "root is required"; exit 1; }
load_servika_env
ADMIN=${SERVIKA_REDIS_ADMIN_PASS:-}
WPCLI_BIN="${SERVIKA_WPCLI_BIN:-/usr/local/bin/wp}"
case "$WPCLI_BIN" in
  /*) ;;
  *) echo "SERVIKA_WPCLI_BIN must be an absolute path: $WPCLI_BIN"; exit 1 ;;
esac
[ -z "$ADMIN" ] && { echo "SERVIKA_REDIS_ADMIN_PASS is absent; run servika-redis-setup first"; exit 1; }
id "$SYSTEM_USER" >/dev/null 2>&1 || { echo "system user not found: $SYSTEM_USER"; exit 1; }

vc(){ REDISCLI_AUTH="$ADMIN" valkey-cli "$@"; }
wpc(){ runuser -u "$SYSTEM_USER" -- env HOME="/home/$SYSTEM_USER" /usr/bin/php -d memory_limit=512M "$WPCLI_BIN" "$@"; }
say(){ printf '  %s\n' "$*"; }

# Resolve domain_id for the panel database record.
DID=$(mysql -u root panel -N -e "SELECT id FROM domains WHERE system_user='$SYSTEM_USER' LIMIT 1;" 2>/dev/null)
[[ "$DID" =~ ^[0-9]+$ ]] || DID=""

# Find WordPress installations in public_html and one level below.
DIRS=()
for d in "/home/$SYSTEM_USER/public_html" "/home/$SYSTEM_USER/public_html"/*/; do
  d="${d%/}"; [ -f "$d/wp-config.php" ] && DIRS+=("$d")
done

# ================= OFF =================
if [ "$ACTION" = "off" ]; then
  echo "==== Detaching Redis: $SYSTEM_USER ===="
  for dir in "${DIRS[@]}"; do
    runuser -u "$SYSTEM_USER" -- rm -f "$dir/wp-content/object-cache.php"
    for config_key in WP_REDIS_HOST WP_REDIS_PORT WP_REDIS_USERNAME WP_REDIS_PASSWORD WP_REDIS_PREFIX \
             WP_REDIS_SELECTIVE_FLUSH WP_REDIS_CLIENT WP_CACHE; do
      wpc config delete "$config_key" --path="$dir" >/dev/null 2>&1
    done
    say "detached: $dir"
  done
  vc ACL DELUSER "$SYSTEM_USER" >/dev/null; vc ACL SAVE >/dev/null
  [ -n "$DID" ] && mysql -u root panel -e "DELETE FROM domain_redis WHERE domain_id=$DID;" 2>/dev/null
  say "ACL user and database record deleted"
  exit 0
fi

# ================= ON =================
echo "==== Attaching Redis: $SYSTEM_USER ===="
[ ${#DIRS[@]} -eq 0 ] && { echo "  WARNING: no WordPress installation found under /home/$SYSTEM_USER/public_html"; }

# Reuse the password from the database record or generate a new one.
PASS=""
if [ -n "$DID" ]; then
  PASS=$(mysql -u root panel --batch --raw --skip-column-names -e "SELECT redis_pass FROM domain_redis WHERE domain_id=$DID AND enabled=1;" 2>/dev/null)
fi
[[ "$PASS" =~ ^[a-f0-9]{36}$ ]] || PASS=$(openssl rand -hex 18)

# 1) Isolated ACL user with @dangerous disabled and read-only diagnostics enabled
vc ACL SETUSER "$SYSTEM_USER" on ">$PASS" resetkeys "~$SYSTEM_USER:*" resetchannels "&$SYSTEM_USER:*" \
   +@all -@dangerous -@admin +info +dbsize +command +ping +echo "+client|no-evict" >/dev/null
vc ACL SAVE >/dev/null
say "ACL user ready: $SYSTEM_USER (~$SYSTEM_USER:*)"

# 2) Panel database record used to report the feature as active
if [ -n "$DID" ]; then
  mysql -u root panel 2>/dev/null <<SQL
INSERT INTO domain_redis (domain_id, system_user, redis_pass, enabled) VALUES ($DID,'$SYSTEM_USER','$PASS',1)
  ON DUPLICATE KEY UPDATE system_user=VALUES(system_user), redis_pass=VALUES(redis_pass), enabled=1;
SQL
  say "panel database record updated (domain #$DID)"
fi

# 3) Configure each WordPress installation.
CONNECTED=0
for dir in "${DIRS[@]}"; do
  say "WP: $dir"
  set_(){ local a=(config set "$1" "$2" --type=constant --path="$dir"); [ "${3:-}" = raw ] && a+=(--raw); wpc "${a[@]}" >/dev/null 2>&1; }
  set_ WP_REDIS_HOST "$HOST"
  set_ WP_REDIS_PORT "$PORT" raw
  set_ WP_REDIS_PASSWORD "array('$SYSTEM_USER','$PASS')" raw    # ACL credentials use [username, password].
  set_ WP_REDIS_PREFIX "$SYSTEM_USER:"
  set_ WP_REDIS_SELECTIVE_FLUSH true raw
  set_ WP_REDIS_CLIENT phpredis
  set_ WP_CACHE true raw
  wpc config delete WP_REDIS_USERNAME --path="$dir" >/dev/null 2>&1  # Remove the obsolete incorrect value.

  wpc plugin install redis-cache --activate --path="$dir" >/dev/null 2>&1
  # Copy the drop-in directly because wp redis enable stalls on flushdb.
  runuser -u "$SYSTEM_USER" -- cp -f "$dir/wp-content/plugins/redis-cache/includes/object-cache.php" \
                            "$dir/wp-content/object-cache.php" 2>/dev/null

  ST=$(wpc redis status --path="$dir" 2>&1)
  if grep -q "Connected" <<<"$ST"; then
    say "  -> Connected (object cache enabled)"
    CONNECTED=$((CONNECTED+1))
  else
    say "  -> CONNECTION FAILED:"; grep -iE "status|error" <<<"$ST" | head -2 | sed 's/^/     /'
  fi
done

echo "==== Summary ===="
say "connected WordPress installations: $CONNECTED / ${#DIRS[@]}"
say "user=$SYSTEM_USER  prefix=$SYSTEM_USER:  server=$HOST:$PORT"
