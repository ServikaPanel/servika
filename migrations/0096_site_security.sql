-- 0096 - known vulnerabilities in what a tenant's site actually runs.
--
-- The panel could already see three things and not this one: dnf updateinfo
-- covers the SERVER's own packages, internal/antivirus looks for malware, and
-- wordpress/checksums.go checks core integrity. A tenant's outdated plugin or
-- npm dependency with a published CVE was invisible, and that is where most
-- real compromises come from.
--
-- The rows are ADVISORY. Version matching against a third-party feed is not
-- exact, so nothing here may suspend an account, delete a file or bill anybody.
-- A wrong row is a support call; a wrong suspension is an outage.
--
-- finding_key is the merge key, computed in Go rather than by the database.
-- The natural key (domain_id, install_path, package_name, cve_id) is 831
-- characters, which is 3324 bytes in utf8mb4 and over InnoDB's 3072-byte index
-- limit, so it cannot be indexed directly. A prefix index would merge two paths
-- that share their first 150 characters, which is exactly the shape a deep
-- node_modules tree produces. There is one write site, so one hash there is
-- simpler than a generated column and can be tested without a database.
--
-- first_seen and last_seen are separate so a finding that has been present for
-- months reads differently from one that appeared today, and so a re-scan
-- refreshes the row instead of duplicating it.
CREATE TABLE security_findings (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  finding_key CHAR(64) NOT NULL,
  domain_id BIGINT UNSIGNED NOT NULL,
  app_type ENUM('wordpress','nodejs','php-composer') NOT NULL,
  install_path VARCHAR(512) NOT NULL,
  package_name VARCHAR(255) NOT NULL,
  installed_version VARCHAR(64) NOT NULL DEFAULT '',
  cve_id VARCHAR(64) NOT NULL,
  severity VARCHAR(16) NOT NULL DEFAULT '',
  cvss DECIMAL(3,1) NULL DEFAULT NULL,
  title VARCHAR(512) NOT NULL DEFAULT '',
  fixed_in VARCHAR(64) NOT NULL DEFAULT '',
  source VARCHAR(255) NOT NULL DEFAULT '',
  first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_security_findings (finding_key),
  KEY ix_security_findings_domain (domain_id),
  KEY ix_security_findings_severity (severity),
  CONSTRAINT fk_security_findings_domain FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- One row, id=1, describing the last or current sweep.
--
-- state is the whole answer; there is no separate running flag, because two
-- columns describing one thing drift. It is reset at startup: the in-process
-- lock lives only in memory, so a panel that was killed mid-scan would
-- otherwise answer "already running" for good.
--
-- unparsed counts packages whose version string could not be compared. A sweep
-- that could not judge forty packages is not the same as one that found nothing,
-- and reporting the second when it was the first is the worst answer this
-- screen can give.
CREATE TABLE security_scan_status (
  id TINYINT UNSIGNED NOT NULL PRIMARY KEY DEFAULT 1,
  state ENUM('idle','running','finished','failed') NOT NULL DEFAULT 'idle',
  started_at DATETIME NULL DEFAULT NULL,
  finished_at DATETIME NULL DEFAULT NULL,
  scanned_domains INT UNSIGNED NOT NULL DEFAULT 0,
  scanned_packages INT UNSIGNED NOT NULL DEFAULT 0,
  unparsed_packages INT UNSIGNED NOT NULL DEFAULT 0,
  finding_count INT UNSIGNED NOT NULL DEFAULT 0,
  last_error VARCHAR(512) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT INTO security_scan_status (id) VALUES (1);
