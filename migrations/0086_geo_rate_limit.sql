-- Country-based blocking and per-domain request rate limiting.
--
-- Two independent surfaces share one country database: a customer blocks or
-- allows countries for their own site (nginx, HTTP only), and an operator
-- blocks a country for the whole server (nftables, every port).
--
-- The country IP ranges themselves are NOT stored here. They live as generated
-- files under the GeoIP data directory, because a country database is upwards
-- of half a million networks and nothing in the panel ever queries one row of
-- it: the only consumer is a file generator that reads the whole set.

-- geo_mode is the domain's country policy and rate_limit_rps its request
-- ceiling. Both default to inactive, so an existing domain renders exactly the
-- vhost it rendered before.
ALTER TABLE domains
  ADD COLUMN geo_mode ENUM('off','allow','deny') NOT NULL DEFAULT 'off',
  ADD COLUMN rate_limit_rps INT NOT NULL DEFAULT 0;

-- The countries one domain names. The mode decides whether the list means
-- "refuse these" or "refuse everything else".
CREATE TABLE domain_geo_rules (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain_id BIGINT UNSIGNED NOT NULL,
  country_code CHAR(2) NOT NULL,
  created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_domain_country (domain_id, country_code),
  CONSTRAINT fk_domain_geo_domain FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The countries the operator blocks for the whole server. This is a separate
-- table from domain_geo_rules rather than a nullable domain_id on one table,
-- because the two are enforced by different subsystems (nftables versus nginx)
-- and a row that belongs to neither owner is not a state worth being able to
-- represent.
CREATE TABLE firewall_geo_rules (
  id INT AUTO_INCREMENT PRIMARY KEY,
  country_code CHAR(2) NOT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_firewall_country (country_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- MaxMind credentials and the state of the downloaded country database.
--
-- The license key is sealed by internal/secret, so the column holds a prefixed
-- ciphertext string and is sized for it rather than for the key. The account id
-- is not a secret on its own and is stored as it was entered, because the
-- download needs both and an operator has to be able to see which account a
-- panel is using.
--
-- geoip_last_error carries a non-empty string so a screen can tell "no database
-- has been downloaded yet" apart from "the download failed".
ALTER TABLE panel_settings
  ADD COLUMN maxmind_account_id VARCHAR(32) NOT NULL DEFAULT '',
  ADD COLUMN maxmind_license_key TEXT NULL,
  ADD COLUMN geoip_build_date VARCHAR(32) NOT NULL DEFAULT '',
  ADD COLUMN geoip_updated_at DATETIME NULL DEFAULT NULL,
  ADD COLUMN geoip_last_error VARCHAR(255) NOT NULL DEFAULT '';
