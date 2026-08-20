-- 0103 - what the site security sweep actually looked at.
--
-- security_findings records a vulnerability. It records nothing at all about an
-- installation that has none, so on the screen "every site is clean" and "the
-- sweep never ran" were the same picture: an empty list. security_scan_status
-- carries only server-wide totals, so it cannot say WHICH domain was covered
-- either. A silent failure therefore read as reassurance, which is the one thing
-- a security screen must never do.
--
-- One row per installation the sweep inspected, written whether or not anything
-- was found. finding_count of 0 is the valuable case: it is the difference
-- between proven good news and no news.
--
-- The rows are ADVISORY, the same as security_findings: nothing here may suspend
-- an account, delete a file or bill anybody.
--
-- domain_id is BIGINT UNSIGNED because domains.id is, and a foreign key whose
-- type differs by so much as signedness is refused with errno 150.
--
-- The merge key is the natural one here, unlike security_findings, which had to
-- hash it: that key carried package_name and cve_id as well and came to 3324
-- bytes in utf8mb4, over InnoDB's 3072-byte index limit. This one is 8 + 1 +
-- 2050 bytes, so it can simply be indexed.
CREATE TABLE security_apps (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain_id BIGINT UNSIGNED NOT NULL,
  app_type ENUM('wordpress','nodejs','php-composer') NOT NULL,
  install_path VARCHAR(512) NOT NULL,
  app_version VARCHAR(64) NOT NULL DEFAULT '',
  package_count INT UNSIGNED NOT NULL DEFAULT 0,
  finding_count INT UNSIGNED NOT NULL DEFAULT 0,
  last_scanned TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_security_apps (domain_id, app_type, install_path),
  KEY ix_security_apps_type (app_type),
  CONSTRAINT fk_security_apps_domain FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
