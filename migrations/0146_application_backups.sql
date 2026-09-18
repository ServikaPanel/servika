-- 0146_application_backups.sql - On-demand backups for both application kinds.
--
-- Until now the only archive either kind produced was the one internal/hostapps
-- takes on the way out, during a removal. Nothing could be taken before an
-- upgrade and nothing could be put back: a Gitea that came up broken after an
-- update had no route back to the tree that worked an hour earlier.
--
-- Both tables carry the digest of the file they name. The archive lives on disk
-- and the row lives in MariaDB, and the two drift: a truncated file, a disk that
-- filled mid-write, an operator who copied an archive by hand. A restore that
-- unpacks such a file over a working tree destroys it, so the digest is checked
-- before the unit is stopped and before anything is deleted.

-- One row per archive of a tenant's own application.
CREATE TABLE app_backups (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  app_id       BIGINT UNSIGNED NOT NULL,

  -- Carried alongside app_id so a list can be narrowed to one domain without a
  -- join, which is what the ownership check needs on every read.
  domain_id    BIGINT UNSIGNED NOT NULL,

  archive_path VARCHAR(512) NOT NULL,
  size_bytes   BIGINT UNSIGNED NOT NULL DEFAULT 0,

  -- Hex SHA-256 of the archive as it was written.
  sha256       CHAR(64) NOT NULL DEFAULT '',

  -- What the operator was doing when they took it ("before the 2.4 upgrade").
  note         VARCHAR(255) NOT NULL DEFAULT '',

  -- The account that asked for it. NULL when the row outlives the account, so a
  -- deleted user does not take the archive's row with them.
  created_by   BIGINT UNSIGNED NULL DEFAULT NULL,
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

  KEY ix_app_backups_app (app_id, id),
  KEY ix_app_backups_domain (domain_id),
  CONSTRAINT fk_app_backups_app FOREIGN KEY (app_id)
    REFERENCES apps(id) ON DELETE CASCADE,
  CONSTRAINT fk_app_backups_domain FOREIGN KEY (domain_id)
    REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- host_app_backups predates this and holds only removal archives, which were
-- never verified because nothing read them back. An existing row keeps an empty
-- digest and stays listed; a restore of one is refused rather than attempted,
-- because an unverifiable archive is exactly the case this guards against.
ALTER TABLE host_app_backups
  ADD COLUMN IF NOT EXISTS sha256 CHAR(64) NOT NULL DEFAULT '' AFTER size_bytes;

ALTER TABLE host_app_backups
  ADD COLUMN IF NOT EXISTS note VARCHAR(255) NOT NULL DEFAULT '' AFTER sha256;

ALTER TABLE host_app_backups
  ADD COLUMN IF NOT EXISTS created_by BIGINT UNSIGNED NULL DEFAULT NULL AFTER note;
