-- Per-domain mail delivery history.
--
-- The panel could show the live Postfix queue, which only says what has not been
-- delivered yet. "Did my invoice reach the customer?" was unanswerable without
-- shell access to the mail log, and that log is one file for the whole server,
-- so it cannot be shown to a tenant as it stands.
CREATE TABLE mail_delivery_log (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain_id BIGINT UNSIGNED NOT NULL,
  ts DATETIME NOT NULL,
  -- Which side of the delivery this domain was on. A message between two hosted
  -- domains produces one row for each.
  direction ENUM('in','out') NOT NULL,
  sender VARCHAR(320) NOT NULL,
  recipient VARCHAR(320) NOT NULL,
  status ENUM('sent','deferred','bounced','expired','rejected') NOT NULL,
  -- The server's own words for why, already stripped of control characters.
  reason VARCHAR(255) NOT NULL DEFAULT '',
  queue_id VARCHAR(32) NOT NULL DEFAULT '',
  KEY ix_mail_delivery_domain_ts (domain_id, ts),
  CONSTRAINT fk_mail_delivery_domain FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- One cursor for the whole server, because Postfix writes one log for every
-- domain. size detects a rotation: a file that shrank is a new file, and reading
-- on from the old offset would skip its beginning.
--
-- Both names are backticked because OFFSET is a RESERVED word from MariaDB 10.6
-- onward, which is every version AlmaLinux 10 ships. A bare `offset` column does
-- not parse, and a migration that fails stops the panel from starting at all.
CREATE TABLE mail_log_cursor (
  id TINYINT UNSIGNED PRIMARY KEY,
  `offset` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `size` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
