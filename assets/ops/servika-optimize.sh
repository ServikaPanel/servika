#!/usr/bin/env bash
# servika-optimize tunes MariaDB and nginx for the available server resources.
# It is resource-aware, idempotent, and uses validation with rollback.
#
# Usage:
#   servika-optimize                # Calculate and apply, including a MariaDB restart
#   servika-optimize --no-restart   # Write config and apply dynamic values without restart
#   servika-optimize --dry-run      # Display only the calculated values
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

load_servika_env

NO_RESTART=0; DRY=0
for a in "$@"; do case "$a" in --no-restart) NO_RESTART=1;; --dry-run) DRY=1;; esac; done

log(){ printf '  %s\n' "$*"; }
error(){ printf '  ✗ %s\n' "$*" >&2; }

# ---------- Resource detection ----------
RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
CPU=$(nproc)
[ -z "$RAM_MB" ] && RAM_MB=2048
[ -z "$CPU" ] && CPU=1

# ---------- Resource-aware MariaDB values ----------
# Use a conservative buffer-pool ratio on small hosts shared with ClamAV, nginx, and PHP.
if   [ "$RAM_MB" -lt 2048 ]; then BP_PCT=20
elif [ "$RAM_MB" -lt 4096 ]; then BP_PCT=25
elif [ "$RAM_MB" -lt 8192 ]; then BP_PCT=40
else                              BP_PCT=50
fi
BP_MB=$(( RAM_MB * BP_PCT / 100 ))
BP_MB=$(( (BP_MB / 256) * 256 ))          # Round to 256 MiB for instance alignment.
[ "$BP_MB" -lt 256 ] && BP_MB=256
BP_INST=$(( BP_MB / 1024 )); [ "$BP_INST" -lt 1 ] && BP_INST=1; [ "$BP_INST" -gt 8 ] && BP_INST=8
# Size the redo log near one third of the buffer pool, bounded to 128–512 MiB.
LOG_MB=$(( BP_MB / 3 )); LOG_MB=$(( (LOG_MB / 128) * 128 ))
[ "$LOG_MB" -lt 128 ] && LOG_MB=128; [ "$LOG_MB" -gt 512 ] && LOG_MB=512
THREAD_CACHE=$(( CPU * 16 )); [ "$THREAD_CACHE" -gt 100 ] && THREAD_CACHE=100
IO_THREADS=$CPU; [ "$IO_THREADS" -gt 8 ] && IO_THREADS=8; [ "$IO_THREADS" -lt 4 ] && IO_THREADS=4

# ---------- nginx values ----------
NGX_CONN=4096; [ "$RAM_MB" -lt 2048 ] && NGX_CONN=2048

echo "════════ Calculated values (RAM=${RAM_MB}MB, CPU=${CPU}) ════════"
log "MariaDB: buffer_pool=${BP_MB}M (${BP_PCT}%, ${BP_INST} instance) · redo_log=${LOG_MB}M · thread_cache=${THREAD_CACHE} · io_threads=${IO_THREADS}"
log "MariaDB: flush_log_at_trx_commit=2 (performance) · io_capacity=1000/2000 (SSD) · skip_name_resolve=ON · utf8mb4"
log "nginx: worker_connections=${NGX_CONN} · worker_rlimit_nofile=65535 · multi_accept+epoll · HTTP tuning"
[ "$DRY" = 1 ] && { echo "  (dry-run; no changes made)"; exit 0; }

TS=$(date +%s)

# ================= MARIADB =================
echo "════════ MariaDB ════════"
MYSQL_CNF=/etc/my.cnf.d/servika-tuning.cnf
[ -f "$MYSQL_CNF" ] && cp -a "$MYSQL_CNF" "${MYSQL_CNF}.bak.${TS}"
cat > "$MYSQL_CNF" <<CNF
# Servika tuning, generated automatically for RAM=${RAM_MB}MB and CPU=${CPU}. Regenerate with servika-optimize.
[mysqld]
# --- InnoDB buffer pool, the primary cache using ${BP_PCT}% of RAM ---
innodb_buffer_pool_size          = ${BP_MB}M
innodb_buffer_pool_instances     = ${BP_INST}
innodb_buffer_pool_dump_at_shutdown = ON
innodb_buffer_pool_load_at_startup  = ON

# --- InnoDB writes and logging ---
innodb_log_file_size             = ${LOG_MB}M
innodb_log_buffer_size           = 32M
innodb_flush_log_at_trx_commit   = 2
innodb_flush_method              = O_DIRECT
innodb_flush_neighbors           = 0
innodb_stats_on_metadata         = OFF

# --- Disk I/O for SSD or NVMe storage ---
innodb_io_capacity               = 1000
innodb_io_capacity_max           = 2000
innodb_read_io_threads           = ${IO_THREADS}
innodb_write_io_threads          = ${IO_THREADS}

# --- Connections and threads ---
max_connections                  = 200
thread_cache_size                = ${THREAD_CACHE}
skip_name_resolve                = ON

# --- Large SQL dumps, imports, and uploads for phpMyAdmin and WordPress ---
max_allowed_packet               = 256M
wait_timeout                     = 31536000
open_files_limit                 = 4294967295

# --- Table cache ---
table_open_cache                 = 4000
table_definition_cache           = 2000

# --- Temporary tables and per-connection buffers, kept small because they scale with max_connections ---
tmp_table_size                   = 64M
max_heap_table_size              = 64M
sort_buffer_size                 = 2M
join_buffer_size                 = 2M
read_buffer_size                 = 1M
read_rnd_buffer_size             = 1M

# --- Modern character set for WordPress ---
character-set-server             = utf8mb4
collation-server                 = utf8mb4_unicode_ci

# --- Query cache disabled for modern MariaDB ---
query_cache_type                 = 0
query_cache_size                 = 0
CNF
log "written: $MYSQL_CNF"

# Apply dynamic values immediately so they remain active even if a restart fails.
mysql -u root 2>/dev/null <<SQL
SET GLOBAL innodb_io_capacity          = 1000;
SET GLOBAL innodb_io_capacity_max      = 2000;
SET GLOBAL innodb_flush_log_at_trx_commit = 2;
SET GLOBAL thread_cache_size           = ${THREAD_CACHE};
SET GLOBAL table_open_cache            = 4000;
SET GLOBAL table_definition_cache      = 2000;
SET GLOBAL innodb_stats_on_metadata    = OFF;
SET GLOBAL max_allowed_packet          = 268435456;
SET GLOBAL wait_timeout                = 31536000;
SET GLOBAL innodb_buffer_pool_dump_at_shutdown = ON;
SET GLOBAL innodb_buffer_pool_load_at_startup  = ON;
SQL
log "dynamic settings applied with SET GLOBAL (without restart)"

# systemd LimitNOFILE is required for open_files_limit=4294967295 to take effect.
# Do not use infinity because MariaDB can reduce open_files_limit to 64; use a high integer.
LIMITS_DIR=/etc/systemd/system/mariadb.service.d
mkdir -p "$LIMITS_DIR"
cat > "$LIMITS_DIR/servika-limits.conf" <<LIM
[Service]
LimitNOFILE=1048576
LIM
systemctl daemon-reload
log "systemd LimitNOFILE=1048576 (for open_files_limit)"

if [ "$NO_RESTART" = 0 ]; then
  # A restart fully applies buffer_pool, redo_log, and skip_name_resolve.
  log "Restarting MariaDB to activate buffer_pool, redo_log, and skip_name_resolve..."
  if systemctl restart mariadb && sleep 3 && systemctl is-active --quiet mariadb && mysql -u root -e "SELECT 1" >/dev/null 2>&1; then
    log "✓ MariaDB restart OK ($(mysql -u root -N -e "SELECT CONCAT(ROUND(@@innodb_buffer_pool_size/1048576),'M buffer_pool, ',@@innodb_flush_log_at_trx_commit,' flush, skip_name_resolve=',@@skip_name_resolve)" 2>/dev/null))"
  else
    error "MariaDB restart FAILED; rolling back tuning"
    rm -f "$MYSQL_CNF"; [ -f "${MYSQL_CNF}.bak.${TS}" ] && cp -a "${MYSQL_CNF}.bak.${TS}" "$MYSQL_CNF"
    systemctl restart mariadb; sleep 3
    systemctl is-active --quiet mariadb && log "restored the previous configuration" || error "MariaDB is STILL DOWN; manual intervention required!"
    exit 1
  fi
else
  log "(--no-restart) configuration written; buffer_pool, redo_log, and skip_name_resolve will activate on the next restart"
fi

# ================= NGINX =================
echo "════════ nginx ════════"
NGINX_CONF=/etc/nginx/nginx.conf
NGX_PERF=/etc/nginx/conf.d/00-servika-perf.conf
cp -a "$NGINX_CONF" "${NGINX_CONF}.bak.${TS}"

# 1) Idempotent main and events settings that belong in nginx.conf
sed -i -E "s/^([[:space:]]*)worker_connections[[:space:]]+[0-9]+;/\1worker_connections ${NGX_CONN};/" "$NGINX_CONF"
grep -q 'worker_rlimit_nofile' "$NGINX_CONF" || sed -i '/^worker_processes/a worker_rlimit_nofile 65535;' "$NGINX_CONF"
grep -q 'multi_accept' "$NGINX_CONF" || sed -i '/worker_connections/a\    multi_accept on;\n    use epoll;' "$NGINX_CONF"

# 2) HTTP-level tuning loaded through conf.d for directives absent from nginx.conf
# client_max_body_size and types_hash_max_size already exist in nginx.conf and must not
# be repeated here, otherwise nginx -t fails with a duplicate directive error.
cat > "$NGX_PERF" <<'NGX'
# Servika nginx performance tuning, generated automatically. Regenerate with servika-optimize.
server_tokens off;
tcp_nodelay on;
reset_timedout_connection on;
keepalive_requests 1000;
client_body_timeout 15s;
client_header_timeout 15s;
send_timeout 15s;
server_names_hash_bucket_size 128;
# PHP-FPM response buffers reduce 502 and 504 errors under load and allow per-location overrides.
fastcgi_buffers 16 16k;
fastcgi_buffer_size 32k;
fastcgi_busy_buffers_size 32k;
# Global HTTP gzip compression applies to the panel and every tenant virtual host.
# nginx compresses text/html implicitly; compression level 5 balances size and CPU usage.
gzip on;
gzip_vary on;
gzip_comp_level 5;
gzip_min_length 256;
gzip_proxied any;
gzip_types text/plain text/css text/xml text/javascript application/javascript application/json application/xml application/xml+rss application/rss+xml application/atom+xml application/wasm application/vnd.ms-fontobject application/x-font-ttf font/ttf font/otf font/woff font/woff2 image/svg+xml image/x-icon;
# Cache static-file descriptors to reduce open operations and I/O.
# Do not cache lookup errors because domains and files are created dynamically.
# Keep validation short so file changes become visible quickly.
open_file_cache max=10000 inactive=60s;
open_file_cache_valid 30s;
open_file_cache_min_uses 2;
open_file_cache_errors off;
NGX

# 3) Validate and roll back on failure.
if nginx -t >/dev/null 2>&1; then
  systemctl reload nginx
  log "✓ nginx -t OK, reloaded (worker_connections=${NGX_CONN}, HTTP tuning active)"
else
  error "nginx -t FAILED; rolling back"
  cp -a "${NGINX_CONF}.bak.${TS}" "$NGINX_CONF"; rm -f "$NGX_PERF"
  nginx -t >/dev/null 2>&1 && systemctl reload nginx && log "restored the previous nginx configuration" || error "nginx configuration is still invalid!"
  exit 1
fi

# ================= PHP =================
# Apply max_input_vars=10000 to all PHP versions and the phpMyAdmin pool
# so large forms and imports do not fail.
echo "════════ PHP ════════"
PHP_DROPIN='; Servika: prevents stalls during large forms and imports (phpMyAdmin, WordPress)
max_input_vars = 10000'
PHP_RESTART=0
# OPcache tuning for PHP-heavy workloads
OPC_COMMON='; Servika OPcache tuning for PHP-heavy workloads
opcache.memory_consumption=256
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=32531
opcache.max_wasted_percentage=10
opcache.validate_timestamps=1
opcache.revalidate_freq=2
opcache.save_comments=1
opcache.enable_file_override=0
opcache.fast_shutdown=1'
# Installed Remi versions
for d in /etc/opt/remi/php*/php.d; do
  [ -d "$d" ] || continue
  printf '%s\n' "$PHP_DROPIN" > "$d/99-servika-input.ini"
  printf '%s\n' "$OPC_COMMON" > "$d/99-servika-opcache.ini"
  # Keep OPcache JIT disabled because it conflicts with opcode-handler extensions on
  # some hosts and adds noisy warnings to wp-cli. Memory and file tuning provide the gain.
  PHP_RESTART=1
done
# Base PHP-FPM used by phpMyAdmin
if [ -d /etc/php.d ]; then
  printf '%s\n' "$PHP_DROPIN" > /etc/php.d/99-servika-input.ini
  printf '%s\n' "$OPC_COMMON" > /etc/php.d/99-servika-opcache.ini
  PHP_RESTART=1
fi
# Explicit php_value entry for the phpMyAdmin pool
PMA_POOL=/etc/php-fpm.d/phpmyadmin.conf
if [ -f "$PMA_POOL" ] && ! grep -q 'max_input_vars' "$PMA_POOL"; then
  cp -a "$PMA_POOL" "${PMA_POOL}.bak.${TS}"
  if grep -q 'php_value\[memory_limit\]' "$PMA_POOL"; then
    sed -i '/php_value\[memory_limit\]/a php_value[max_input_vars]      = 10000' "$PMA_POOL"
  else
    printf '\nphp_value[max_input_vars] = 10000\n' >> "$PMA_POOL"
  fi
fi
# Reload active FPM services.
if [ "$PHP_RESTART" = 1 ]; then
  for svc in php-fpm php74-php-fpm php80-php-fpm php81-php-fpm php82-php-fpm php83-php-fpm php84-php-fpm php85-php-fpm; do
    systemctl is-active --quiet "$svc" 2>/dev/null && systemctl reload-or-restart "$svc" 2>/dev/null
  done
  log "✓ PHP max_input_vars=10000 applied to all versions and phpMyAdmin"
fi

echo "════════ ✓ Optimization complete ════════"
