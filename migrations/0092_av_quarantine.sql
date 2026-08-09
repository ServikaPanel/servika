-- 0092 - what the panel took out of a tenant's tree, so it can be put back.
--
-- Quarantine used to be a one-way move into the tenant's own home: nothing
-- listed it, nothing restored it, and the directory belonged to the tenant, so
-- a false positive could not be undone from the panel while a real webshell
-- could be carried back by the account that planted it. The file now lives
-- under SERVIKA_QUARANTINE_DIR, root-owned and outside the home, and this table
-- is the only record of where it came from.
--
-- orig_rel is stored RELATIVE to the tenant home, because that is what safeio
-- takes; deriving it again at restore time would break every row the day the
-- home layout changed.
--
-- finding_id carries no foreign key on purpose: an old scan may be pruned, and
-- losing the quarantine record with it would strand the file with no way back.
-- It is nullable for the same reason, so it stays OUT of the unique key, whose
-- columns are both NOT NULL (a UNIQUE index treats every NULL as distinct).
CREATE TABLE av_quarantine (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain_id BIGINT UNSIGNED NOT NULL,
  finding_id INT NULL DEFAULT NULL,
  system_user VARCHAR(64) NOT NULL,
  orig_rel VARCHAR(512) NOT NULL,
  stored_name VARCHAR(128) NOT NULL,
  size_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
  signature VARCHAR(255) NOT NULL DEFAULT '',
  engine VARCHAR(32) NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  restored_at DATETIME NULL DEFAULT NULL,
  UNIQUE KEY uq_av_quarantine_stored (system_user, stored_name),
  KEY ix_av_quarantine_domain (domain_id),
  CONSTRAINT fk_av_quarantine_domain FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
