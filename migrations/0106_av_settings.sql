-- The antivirus platform: what it inspects, what it may do about it, and what
-- the kernel lets it spend doing so.
--
-- Three changes, and each one exists because of something the current schema
-- cannot express.
--
-- 1) domain_id becomes nullable on both tables. A sweep of /home or / has no
--    domain, so a server-wide scan could not be recorded at all. Existing rows
--    keep the value they have; nothing here reinterprets them.
--
-- 2) av_scans.confined records whether the scan really ran under the resource
--    limits. A child process started by a service joins the SERVICE's cgroup,
--    not a slice, so writing a slice file confines nothing on its own: the
--    scan has to be launched into the slice with systemd-run. Where that is not
--    available (a development machine, a container without systemd) the scan
--    still runs, unconfined, and this column is what stops the panel reporting
--    a limit it did not apply. "I wrote the limit" and "the kernel enforced it"
--    are different claims and the whole feature is built on keeping them apart.
--
-- 3) av_settings holds one row, id=1, seeded HERE. The application must never
--    fall back to "no row, use defaults": that path makes the panel show one
--    set of values while the scanner reads another, which is exactly the defect
--    the PHP defaults had before internal/phpdefaults was written.
--
-- Only settings with a CONSUMER are stored. A real-time fanotify watcher, a
-- worker-thread count and a files-per-second ceiling all appear in the upstream
-- this came from and none of the three is read by any code there or here, so
-- they are absent rather than stored: a value that is written and never read is
-- a claim the next reader will believe.
--
-- `scope`, `confined`, `level` and `rules` are all usable unquoted on MariaDB
-- 10.11 (measured in CREATE, ALTER, INSERT, SELECT and WHERE).
ALTER TABLE av_scans
  MODIFY COLUMN domain_id INT NULL,
  ADD COLUMN scope VARCHAR(16) NOT NULL DEFAULT 'domain' AFTER domain_id,
  ADD COLUMN confined TINYINT(1) NOT NULL DEFAULT 0 AFTER engine;

ALTER TABLE av_findings
  MODIFY COLUMN domain_id INT NULL;

CREATE TABLE IF NOT EXISTS av_settings (
  id                  TINYINT UNSIGNED NOT NULL PRIMARY KEY DEFAULT 1,

  -- Detection layers. Each one is skipped entirely when off, not run and
  -- filtered: filtering would throw away the only concrete benefit of turning
  -- a layer off, which is the CPU it does not spend.
  rule_engine         TINYINT(1)  NOT NULL DEFAULT 1,
  location_heuristics TINYINT(1)  NOT NULL DEFAULT 1,
  wp_integrity        TINYINT(1)  NOT NULL DEFAULT 1,

  -- The score at which a file is reported as critical rather than suspicious.
  -- The suspicious threshold is deliberately NOT configurable: the two numbers
  -- were chosen together so that no single rule can produce a finding on its
  -- own, and moving the lower one breaks that guarantee.
  critical_threshold  INT         NOT NULL DEFAULT 100,

  -- Action. Default 0, and that is not a statement about readiness. An
  -- installation that has been running for a year has a behaviour its operator
  -- relies on, and a panel update must not start moving their files. The same
  -- reason panel_settings.host_apps_enabled and session_idle_minutes default
  -- to off.
  auto_quarantine     TINYINT(1)  NOT NULL DEFAULT 0,

  -- Scope: 'host' = /home only (tenant trees), 'server' = the whole filesystem
  -- with the exclusion list applied. 'host' is the default because a scanner
  -- walking /var/lib/mysql is both useless (data files) and expensive.
  scope               VARCHAR(16) NOT NULL DEFAULT 'host',
  excluded_paths      TEXT        NOT NULL,

  -- Resource limits, enforced by the kernel through a systemd slice.
  -- 0 = automatic (derived from the server's measured capacity).
  cpu_percent         INT         NOT NULL DEFAULT 0,
  ram_mb              INT         NOT NULL DEFAULT 0,
  io_weight           INT         NOT NULL DEFAULT 50,

  -- Scheduling.
  scheduled_scan      TINYINT(1)  NOT NULL DEFAULT 0,
  scheduled_hour      INT         NOT NULL DEFAULT 4,

  updated_at          TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The quarantine store is excluded for a reason of its own: a file already
-- taken out of a site lives there, and scanning it would report the same
-- webshell a second time, as a finding nobody can act on.
INSERT INTO av_settings (id, excluded_paths) VALUES (1,
  '/proc\n/sys\n/dev\n/run\n/var/lib/mysql\n/var/lib/containers\n/var/cache\n/var/backups\n/var/lib/servika/quarantine\n/opt/servika\n.git/\nnode_modules/\n/wp-content/cache/\n/wp-content/uploads/cache/'
) ON DUPLICATE KEY UPDATE id = id;
