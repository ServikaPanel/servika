-- Per-user remote MySQL access.
--
-- Every account the panel creates is 'user'@'localhost', and the installer pins
-- MariaDB to bind-address = 127.0.0.1, so nothing outside the server has ever
-- been able to reach a customer database. A customer who wants to point a local
-- client, a separate application server or a CI job at their database has had no
-- answer at all.
--
-- Remote access is three things that must agree: a MariaDB account whose HOST
-- component matches the caller, a listening socket, and a firewall rule. This
-- migration holds the panel's record of the first and the switch for the second.

-- The server-wide switch.
--
-- It is server-wide and admin-only because turning it on rewrites the bind
-- address and RESTARTS MariaDB, which drops every site's open connections. A
-- customer's own checkbox must never be able to do that, so the per-user
-- allowlist below is refused while this is 0.
ALTER TABLE panel_settings
  ADD COLUMN db_remote_enabled TINYINT(1) NOT NULL DEFAULT 0,
  -- Carries a non-empty string so a screen can tell "never applied" apart from
  -- "the apply failed and the bind was rolled back".
  ADD COLUMN db_remote_last_error VARCHAR(255) NOT NULL DEFAULT '',
  ADD COLUMN db_remote_applied_at DATETIME NULL DEFAULT NULL;

-- One row per (database user, allowed source address).
--
-- The unit is the USER, not the db_accounts row: migration 0036 dropped the
-- db_user UNIQUE index so one user can own several databases, and remote access
-- is a property of the account that authenticates, not of a single schema.
--
-- Two representations of the same address are stored side by side, because they
-- are not interchangeable and both were MEASURED against MariaDB 10.11:
--
--   host_cidr   what the customer entered, canonicalised. 10.0.0.0/24
--   mysql_host  what CREATE USER received.               10.0.0.0/255.255.255.0
--
-- MariaDB accepts BOTH strings in a host component without any error, but only
-- the dotted-netmask form ever matches a connecting client; the CIDR form
-- authenticates nobody, silently. Deriving mysql_host again at DROP time would
-- leave an undroppable account the day that conversion changes, so the value
-- that was actually used is kept.
CREATE TABLE db_remote_hosts (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain_id BIGINT UNSIGNED NOT NULL,
  db_user VARCHAR(64) NOT NULL,
  host_cidr VARCHAR(64) NOT NULL,
  mysql_host VARCHAR(80) NOT NULL,
  label VARCHAR(64) NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  -- Both key columns are NOT NULL. A UNIQUE index treats every NULL as
  -- distinct, so a nullable column in the key would stop it from constraining
  -- anything for exactly the rows it was meant to constrain.
  UNIQUE KEY uq_db_remote (db_user, host_cidr),
  KEY ix_db_remote_domain (domain_id),
  -- The cascade removes the panel's record when the domain goes, but it cannot
  -- remove the MariaDB account. The delete path drops the accounts FIRST; the
  -- cascade is the backstop, not the teardown.
  CONSTRAINT fk_db_remote_domain FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
