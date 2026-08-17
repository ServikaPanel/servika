-- 0098 - what the tuning screen changed, so it can be put back.
--
-- assets/ops/servika-optimize.sh already computes and applies a whole tuning
-- pass and verifies MariaDB comes back. What it cannot do is let an operator
-- see one parameter, agree to that one, and undo that one: it is all or
-- nothing, and on a server somebody else configured, all is a hard sell.
--
-- Each row is one file this panel replaced, with the copy it replaced. The
-- backup is a PATH rather than the content, because a MariaDB drop-in and an
-- nginx include are files the operator may also be editing by hand, and a copy
-- on disk beside them is something they can read and diff. The row is what
-- names it.
--
-- reverted is a flag rather than a deletion, so an operator can see that a
-- change was made and undone rather than never made at all. That distinction is
-- the whole reason somebody opens this screen after an incident.
CREATE TABLE optimize_backups (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  service ENUM('mariadb','nginx','php-fpm','sysctl') NOT NULL,
  param VARCHAR(64) NOT NULL,
  target_path VARCHAR(512) NOT NULL,
  backup_path VARCHAR(512) NOT NULL,
  old_value VARCHAR(255) NOT NULL DEFAULT '',
  new_value VARCHAR(255) NOT NULL DEFAULT '',
  actor_uid BIGINT UNSIGNED NULL DEFAULT NULL,
  reverted TINYINT(1) NOT NULL DEFAULT 0,
  reverted_at DATETIME NULL DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY ix_optimize_backups_param (service, param),
  KEY ix_optimize_backups_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
