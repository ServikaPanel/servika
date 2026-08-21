-- 0111 - the panel's own notification stream, and who started a scan.
--
-- Nothing in the panel ever told anybody that something happened. The bell in
-- the top bar had no click handler and nothing behind it, so a nightly sweep
-- that found three webshells on a customer's site was recorded in av_findings
-- and reached no one until somebody happened to open the antivirus page.
--
-- domain_id NULL means the notification is panel-wide and belongs to admins
-- alone. That rule cannot be expressed by an ownership condition, so the
-- visibility test in Go is this rule ANDed with middleware.ScopeCondition.
--
-- The read flag is NOT a column on the notification. One domain notification has
-- up to THREE viewers here: the customer, the reseller who owns them, and an
-- admin. A single flag means whoever opens it first marks it read for everyone,
-- so an admin dismissing a notice hides it from the customer who has to act on
-- it. notification_reads carries one row per (notification, reader) instead.
CREATE TABLE notifications (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  level VARCHAR(16) NOT NULL DEFAULT 'info',
  category VARCHAR(32) NOT NULL DEFAULT '',
  title VARCHAR(200) NOT NULL,
  message TEXT NOT NULL,
  domain_id BIGINT UNSIGNED NULL DEFAULT NULL,
  ref_type VARCHAR(24) NOT NULL DEFAULT '',
  ref_id BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY ix_notifications_domain (domain_id),
  KEY ix_notifications_created (created_at),
  CONSTRAINT fk_notifications_domain FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE notification_reads (
  notification_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  read_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (notification_id, user_id),
  KEY ix_notification_reads_user (user_id),
  CONSTRAINT fk_notification_reads_notification FOREIGN KEY (notification_id) REFERENCES notifications(id) ON DELETE CASCADE,
  CONSTRAINT fk_notification_reads_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- av_scans.scope already says WHAT was scanned (domain, home, host, realtime).
-- It cannot say WHO started it, so a sweep an operator ran by hand and one the
-- scheduler ran overnight are drawn identically, and the only way to see that
-- the nightly job really ran is to compare timestamps by eye.
--
-- The default is 'unknown' rather than 'manual': nothing knows who started a row
-- written before this column existed, and "not measured" is a different claim
-- from "started by hand". Every write site names its own value explicitly.
ALTER TABLE av_scans
  ADD COLUMN source VARCHAR(16) NOT NULL DEFAULT 'unknown' AFTER scope;
