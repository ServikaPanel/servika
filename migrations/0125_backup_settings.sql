-- 0125 - system-wide backup settings (singleton row id=1).
--
-- backup_destinations is PER DOMAIN (domain_id NOT NULL, UNIQUE per domain), so
-- there was no way to express three server-wide policies at all:
--   * a master switch that turns every automatic backup off at once,
--   * a disk guard (min_free_gb / max_store_gb) that refuses to write a backup
--     when the root disk is low, so backups cannot fill the disk and take the
--     panel and every site down,
--   * ONE off-site destination that every domain's backup is copied to, with an
--     option to delete the local copy once the off-site copy is verified.
--
-- remote_password is stored encrypted at rest by internal/secret, exactly like
-- backup_destinations.password. remote_host_key pins the SFTP host key on first
-- use (trust-on-first-use), because the singleton row has no per-domain row to
-- carry it.
CREATE TABLE IF NOT EXISTS backup_settings (
  id              TINYINT UNSIGNED NOT NULL DEFAULT 1,
  enabled         TINYINT NOT NULL DEFAULT 1,
  min_free_gb     INT NOT NULL DEFAULT 10,
  max_store_gb    INT NOT NULL DEFAULT 0,
  remote_enabled  TINYINT NOT NULL DEFAULT 0,
  remote_type     VARCHAR(8)    NOT NULL DEFAULT 'sftp',
  remote_host     VARCHAR(253)  NOT NULL DEFAULT '',
  remote_port     INT NOT NULL DEFAULT 22,
  remote_username VARCHAR(128)  NOT NULL DEFAULT '',
  remote_password VARCHAR(512)  NOT NULL DEFAULT '',
  remote_dir      VARCHAR(255)  NOT NULL DEFAULT '/',
  remote_host_key VARCHAR(2048) NOT NULL DEFAULT '',
  delete_local    TINYINT NOT NULL DEFAULT 0,
  last_upload     TIMESTAMP NULL DEFAULT NULL,
  last_status     VARCHAR(32)  NOT NULL DEFAULT '',
  last_error      VARCHAR(512) NOT NULL DEFAULT '',
  updated_at      TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO backup_settings (id) VALUES (1);
