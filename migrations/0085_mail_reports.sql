-- Mail deliverability reporting: DMARC aggregate reports, TLS-RPT, MTA-STS.
--
-- The panel already asks the world for DMARC reports: the DNS template writes
-- `rua=mailto:postmaster@<domain>` into every `_dmarc` record. Nothing has ever
-- read them, so the one source of truth about who sends mail as a customer has
-- been arriving and going nowhere.

-- One row per aggregate report a reporting organisation sent.
--
-- The UNIQUE key is the deduplication boundary, and it has to be, because the
-- reports are read out of a mailbox the panel never writes to: Dovecot renames
-- a Maildir file when its flags change, so a filename cannot identify a message
-- twice. (org_name, report_id) is what RFC 7489 makes unique per reporter.
CREATE TABLE dmarc_reports (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain_id BIGINT UNSIGNED NOT NULL,
  org_name VARCHAR(255) NOT NULL,
  report_id VARCHAR(255) NOT NULL,
  date_begin DATETIME NOT NULL,
  date_end DATETIME NOT NULL,
  -- The policy the reporter SAW published, which is not necessarily the one
  -- published now: a report covers a window that may predate a policy change.
  policy_p VARCHAR(16) NOT NULL DEFAULT '',
  policy_adkim CHAR(1) NOT NULL DEFAULT '',
  policy_aspf CHAR(1) NOT NULL DEFAULT '',
  received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_dmarc_report (domain_id, org_name, report_id),
  KEY ix_dmarc_domain_date (domain_id, date_begin),
  CONSTRAINT fk_dmarc_domain FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- One row per source address inside a report. This is the table the dashboard
-- answers "which IPs send mail as you" from.
CREATE TABLE dmarc_report_rows (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  report_row_id BIGINT UNSIGNED NOT NULL,
  source_ip VARCHAR(45) NOT NULL,
  message_count INT UNSIGNED NOT NULL DEFAULT 0,
  disposition VARCHAR(16) NOT NULL DEFAULT '',
  dkim_result VARCHAR(16) NOT NULL DEFAULT '',
  spf_result VARCHAR(16) NOT NULL DEFAULT '',
  header_from VARCHAR(255) NOT NULL DEFAULT '',
  KEY ix_dmarc_rows_report (report_row_id),
  KEY ix_dmarc_rows_source (source_ip),
  CONSTRAINT fk_dmarc_rows FOREIGN KEY (report_row_id) REFERENCES dmarc_reports(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- TLS-RPT (RFC 8460) reports arrive the same way and are deduplicated the same
-- way. They are separate tables rather than a type column because the two
-- formats share no row shape: DMARC counts messages per source address, TLS-RPT
-- counts sessions per failure reason.
CREATE TABLE tlsrpt_reports (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain_id BIGINT UNSIGNED NOT NULL,
  org_name VARCHAR(255) NOT NULL,
  report_id VARCHAR(255) NOT NULL,
  date_begin DATETIME NOT NULL,
  date_end DATETIME NOT NULL,
  policy_type VARCHAR(16) NOT NULL DEFAULT '',
  success_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
  failure_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
  received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_tlsrpt_report (domain_id, org_name, report_id),
  KEY ix_tlsrpt_domain_date (domain_id, date_begin),
  CONSTRAINT fk_tlsrpt_domain FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE tlsrpt_failures (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  report_row_id BIGINT UNSIGNED NOT NULL,
  result_type VARCHAR(64) NOT NULL DEFAULT '',
  sending_mta_ip VARCHAR(45) NOT NULL DEFAULT '',
  receiving_mx_hostname VARCHAR(253) NOT NULL DEFAULT '',
  failed_session_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
  KEY ix_tlsrpt_failures_report (report_row_id),
  CONSTRAINT fk_tlsrpt_failures FOREIGN KEY (report_row_id) REFERENCES tlsrpt_reports(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Where the collector left off, per domain.
--
-- last_message_epoch is the leading epoch second of a Maildir unique name. That
-- prefix survives the renames Dovecot performs when flags change, so it is a
-- safe cheap filter for "messages newer than the last pass"; correctness still
-- rests on the UNIQUE keys above, not on this value.
--
-- last_error carries a reason string rather than a boolean so a screen can tell
-- "no reports yet" apart from "the mailbox could not be read", which look
-- identical from an empty result.
CREATE TABLE mail_report_cursor (
  domain_id BIGINT UNSIGNED PRIMARY KEY,
  mailbox_local VARCHAR(64) NOT NULL DEFAULT 'postmaster',
  last_scan_at DATETIME NULL DEFAULT NULL,
  last_message_epoch BIGINT NOT NULL DEFAULT 0,
  last_error VARCHAR(255) NOT NULL DEFAULT '',
  CONSTRAINT fk_report_cursor FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- MTA-STS state per mail domain.
--
-- It is a state machine rather than a flag because publishing a policy requires
-- a DNS record, then a certificate that covers mta-sts.<domain>, then the vhost
-- and the TXT record, in that order. 'withdrawing' is a real state: removing an
-- MTA-STS policy means publishing `mode: none` and continuing to serve it until
-- the cached max_age expires. Deleting the record instead leaves senders
-- applying a cached enforce policy against a server that no longer proves it.
--
-- mtasts_id is the value in the `_mta-sts` TXT record. A sender caches the
-- policy against it, so it MUST change whenever the policy changes or the
-- change is never noticed.
ALTER TABLE mail_domains
  ADD COLUMN mtasts_mode ENUM('off','pending_dns','pending_cert','testing','enforce','withdrawing')
      NOT NULL DEFAULT 'off',
  ADD COLUMN mtasts_id VARCHAR(32) NOT NULL DEFAULT '',
  ADD COLUMN mtasts_changed_at DATETIME NULL DEFAULT NULL;

-- Blocklist state for the server's own primary sending address.
--
-- The existing scan walks mail_ip_pool, which is empty on a default install, so
-- a server that never configured a pool had no blocklist monitoring at all. The
-- result lives here rather than as a synthetic pool row: the pool is the
-- operator's own list of addresses to rotate between, and a row nobody added
-- would invite being deleted.
--
-- primary_dnsbl_scanned separates "scanned and clean" from "not scanned",
-- which an IPv6-only address always is: a blocklist is queried by reversing an
-- IPv4 address under the zone, and reporting an unqueried address as clean
-- would be a false assurance.
ALTER TABLE mail_server_settings
  ADD COLUMN primary_ip VARCHAR(45) NOT NULL DEFAULT '',
  ADD COLUMN primary_ptr_name VARCHAR(253) NOT NULL DEFAULT '',
  ADD COLUMN primary_ptr_ok TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN primary_dnsbl_scanned TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN primary_dnsbl_zones VARCHAR(512) NOT NULL DEFAULT '',
  ADD COLUMN primary_scan_at DATETIME NULL DEFAULT NULL;
