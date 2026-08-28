-- migration_sessions persists a half-configured site migration so a page reload
-- resumes it without re-entering the source server details, the credentials, or
-- re-running discovery. It is a SEPARATE table from migration_jobs on purpose:
-- a session is ephemeral wizard state, so keeping it out of migration_jobs means
-- the job list never has to exclude a "session" status and a job query cannot
-- accidentally read one.
--
-- The credentials are AES-256-GCM sealed and bound to source_host (the same
-- host-bound encryption migration_jobs uses), so a stored blob cannot be moved
-- to another host and decrypted. They are decrypted SERVER-SIDE at start; the
-- password is NEVER returned to the browser.
--
-- expires_at is the TTL. Every recency and expiry comparison is done with the
-- database clock (NOW()), never a Go time, because the driver writes a Go time
-- as UTC while NOW() answers in the session timezone.
CREATE TABLE IF NOT EXISTS migration_sessions (
  id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  source_type      ENUM('cpanel','plesk','directadmin') NOT NULL,
  source_host      VARCHAR(253) NOT NULL,
  source_port      INT NOT NULL DEFAULT 22,
  source_user      VARCHAR(64) NOT NULL DEFAULT 'root',
  source_password  VARCHAR(1024) NULL,
  source_key       TEXT NULL,
  discovery_json   MEDIUMTEXT NULL,
  selection_json   TEXT NULL,
  started_by       VARCHAR(64) NULL,
  last_used        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at       DATETIME NOT NULL,
  PRIMARY KEY (id),
  KEY ix_migration_sessions_host_user (source_host, source_user),
  KEY ix_migration_sessions_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
