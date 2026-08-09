-- Per-tenant slow query visibility.
--
-- The panel already KILLS a query that runs past its plan's limit
-- (resourcelimit.SlowQueryWatchdog), but it records nothing, and it samples
-- information_schema.PROCESSLIST every five seconds, so it only ever sees a
-- query that lasts longer than the poll interval. What actually eats a shared
-- server is usually the opposite shape: a two-second query running forty
-- thousand times an hour. That has been completely invisible.

-- The switch, its threshold, and what the collector last managed to do.
--
-- The threshold is DECIMAL rather than a float because it is rendered straight
-- into a MariaDB configuration line and into SET GLOBAL long_query_time, and a
-- binary float would print as 1.9999999.
ALTER TABLE panel_settings
  ADD COLUMN slow_query_enabled TINYINT(1) NOT NULL DEFAULT 1,
  ADD COLUMN slow_query_seconds DECIMAL(5,3) NOT NULL DEFAULT 2.000,
  -- Carries a non-empty string so a screen can tell "nothing has been collected
  -- yet" apart from "the collector could not read the log".
  ADD COLUMN slow_query_last_error VARCHAR(255) NOT NULL DEFAULT '',
  ADD COLUMN slow_query_collected_at DATETIME NULL DEFAULT NULL;

-- One row per (query shape, hour, database account).
--
-- The rows are AGGREGATED rather than one row per logged query, because the
-- question this table answers is "which shape is spending the server's time",
-- and a shape that ran forty thousand times is one answer, not forty thousand.
--
-- normalized_sql holds the shape, never the query as it was executed: literals
-- are replaced with `?` before the digest is taken. A slow query log carries
-- whatever a WHERE clause compared against, so storing it raw would copy
-- customer e-mail addresses and password hashes into the panel's own database
-- and from there into every panel backup.
CREATE TABLE slow_query_stats (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  -- NULL means the account could not be matched to a tenant: the panel's own
  -- connection, root, or MariaDB's internal work. Those rows are admin-only.
  domain_id BIGINT UNSIGNED NULL,
  db_user VARCHAR(64) NOT NULL DEFAULT '',
  schema_name VARCHAR(64) NOT NULL DEFAULT '',
  digest CHAR(32) CHARACTER SET ascii NOT NULL,
  bucket_hour DATETIME NOT NULL,
  normalized_sql TEXT NOT NULL,
  calls INT UNSIGNED NOT NULL DEFAULT 0,
  total_time_ms BIGINT UNSIGNED NOT NULL DEFAULT 0,
  max_time_ms INT UNSIGNED NOT NULL DEFAULT 0,
  lock_time_ms BIGINT UNSIGNED NOT NULL DEFAULT 0,
  rows_sent BIGINT UNSIGNED NOT NULL DEFAULT 0,
  rows_examined BIGINT UNSIGNED NOT NULL DEFAULT 0,
  full_scan_calls INT UNSIGNED NOT NULL DEFAULT 0,
  -- The merge key names db_user, NOT domain_id. A UNIQUE index treats every
  -- NULL as distinct, so keying on a nullable domain_id would stop the
  -- unattributed rows from ever merging and let them accumulate one row per
  -- collector pass. db_accounts.db_user is NOT globally unique (0036 dropped
  -- that index so one user can own several databases), but it does determine
  -- domain_id through its c_<system user>_ prefix, and it is NOT NULL here.
  UNIQUE KEY uq_slow_bucket (digest, bucket_hour, db_user),
  KEY ix_slow_domain_bucket (domain_id, bucket_hour),
  KEY ix_slow_bucket (bucket_hour),
  CONSTRAINT fk_slow_domain FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- How far into the slow query log the collector has read.
--
-- One row, like panel_settings: there is one slow query log. The offset and the
-- size are stored together so a rotation is detectable: a file smaller than the
-- offset, or smaller than it was, is a new file and reading resumes at zero.
--
-- Both column names are backticked because OFFSET is a RESERVED word in
-- MariaDB 10.6 and later, which is every version AlmaLinux 10 ships. A bare
-- `offset` is a parse error, and a migration that fails is fatal to startup.
CREATE TABLE slow_query_cursor (
  id TINYINT UNSIGNED NOT NULL PRIMARY KEY DEFAULT 1,
  `offset` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `size` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT INTO slow_query_cursor (id) VALUES (1);
