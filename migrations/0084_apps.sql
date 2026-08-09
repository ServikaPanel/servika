-- 0084_apps.sql - Long-running tenant applications (Node.js, Python).
--
-- Until now a domain could only pick a web BACKEND (php-fpm, apache, static);
-- none of those runs a process the tenant owns. Anyone deploying Node or Python
-- had to open SSH and build their own screen/nohup arrangement, which the panel
-- could not see, restart, resource-limit, log, or put TLS in front of.
--
-- An app is a systemd unit under the tenant's own slice, listening on a
-- loopback port, published by nginx under a path mount. Several apps can share
-- one domain, and the domain's PHP site keeps working alongside them.

CREATE TABLE apps (
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain_id       BIGINT UNSIGNED NOT NULL,

  -- NULL means the domain itself. A subdomain has its own vhost, so an app
  -- attached to one is published there instead.
  subdomain_id    INT NULL,

  name            VARCHAR(64)  NOT NULL,
  runtime         ENUM('node','python') NOT NULL,

  -- Empty means "whatever the host ships". A specific value is resolved
  -- against the installed runtimes at render time, never trusted as a path.
  runtime_version VARCHAR(16)  NOT NULL DEFAULT '',

  -- public_html-relative, validated and symlink-checked before every use.
  app_root        VARCHAR(255) NOT NULL,

  -- Split into argv by the panel and passed without a shell.
  start_command   VARCHAR(512) NOT NULL,

  mount_path      VARCHAR(128) NOT NULL DEFAULT '/',

  -- Loopback port. The range sits BELOW the default ephemeral range
  -- (net.ipv4.ip_local_port_range = 32768 60999) so an outgoing connection can
  -- never squat on a port an app is meant to hold.
  port            SMALLINT UNSIGNED NOT NULL,

  enabled         TINYINT(1)   NOT NULL DEFAULT 1,
  created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  -- Two apps cannot hold the same port. The allocator picks a candidate and
  -- lets this constraint decide, rather than checking first: two creations
  -- arriving together would both pass such a check.
  UNIQUE KEY uq_apps_port (port),

  -- One app per mount point per scope. subdomain_id is nullable so the foreign
  -- key below can cascade, but NULLs do not collide in a UNIQUE index, which
  -- would let "/" be claimed on the same domain any number of times. The
  -- generated column carries the NULL case as 0 so the constraint holds.
  --
  -- It carries no NOT NULL clause: MariaDB refuses one on a generated column in
  -- every position, and a migration that fails stops the panel from starting.
  -- COALESCE cannot return NULL anyway, so the constraint holds regardless.
  subdomain_key   INT GENERATED ALWAYS AS (COALESCE(subdomain_id, 0)) PERSISTENT,
  UNIQUE KEY uq_apps_mount (domain_id, subdomain_key, mount_path),

  KEY ix_apps_domain (domain_id),
  CONSTRAINT fk_apps_domain FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
  CONSTRAINT fk_apps_subdomain FOREIGN KEY (subdomain_id) REFERENCES subdomains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Application environment. Values hold database passwords and API keys, so they
-- are stored encrypted (internal/secret) and only ever reach the host as a
-- root-owned 0640 EnvironmentFile: systemd's Environment= directive is visible
-- to any local user through `systemctl show`.
CREATE TABLE app_env (
  id      BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  app_id  BIGINT UNSIGNED NOT NULL,
  name    VARCHAR(128) NOT NULL,
  value   TEXT NOT NULL,
  UNIQUE KEY uq_app_env (app_id, name),
  CONSTRAINT fk_app_env_app FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 0 means unlimited, matching max_domain / max_db / max_email / max_ftp.
ALTER TABLE service_plans ADD COLUMN max_app INT NOT NULL DEFAULT 0;
