-- Per-domain maintenance mode.
--
-- A customer takes their own site offline for a while and puts a page in front
-- of it. This is distinct from suspension, which an administrator applies and
-- which says the account is suspended, and from the WordPress mu-plugin
-- maintenance switch, which only ever affects WordPress.
--
-- The response is 503, never 200 or 403. A maintenance page served with 200
-- gets indexed as the site's real content, and 403 reads as removed; 503 is the
-- only code that says "temporary" without damaging the site's indexing.

-- maintenance_enabled is the switch and maintenance_until is when it lifts by
-- itself. A NULL until means the mode lasts until someone turns it off, which
-- is the ordinary state for an unplanned outage.
--
-- The page fields are what the panel renders the HTML from. They are stored as
-- entered and escaped at render time rather than escaped on the way in, so the
-- customer sees their own text back in the editor exactly as they typed it.
ALTER TABLE domains
  ADD COLUMN maintenance_enabled TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN maintenance_until DATETIME NULL DEFAULT NULL,
  ADD COLUMN maintenance_title VARCHAR(160) NOT NULL DEFAULT '',
  ADD COLUMN maintenance_message VARCHAR(600) NOT NULL DEFAULT '',
  ADD COLUMN maintenance_accent VARCHAR(7) NOT NULL DEFAULT '',
  ADD COLUMN maintenance_logo_url VARCHAR(512) NOT NULL DEFAULT '';

-- The addresses that reach the real site while maintenance is on.
--
-- This is deliberately NOT domain_ip_rules. That table belongs to the access
-- control feature (domains.ip_access_mode) and sharing it would mean turning
-- maintenance off also deleted the customer's access rules, which are a
-- separate policy with a separate lifetime.
--
-- VARCHAR(45) holds a full IPv6 address. Only exact addresses are stored: the
-- vhost matches them with one regex, so no CIDR range appears here.
CREATE TABLE domain_maintenance_ips (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain_id BIGINT UNSIGNED NOT NULL,
  ip VARCHAR(45) NOT NULL,
  note VARCHAR(120) NOT NULL DEFAULT '',
  created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_maintenance_ip (domain_id, ip),
  CONSTRAINT fk_maintenance_ip_domain FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
