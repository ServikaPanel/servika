-- 0094 - hostnames a tenant may not add to this server.
--
-- Owning DNS is not what decides whether a vhost gets rendered here: a tenant
-- can ask the panel for login.example-bank.com, get a server_name and a
-- certificate for it, and point traffic at it from anywhere they control a
-- resolver. Nothing in the panel refused that name before this table existed.
--
-- match_subdomains is per row and defaults to 1 because a phisher hides the
-- brand one label down: banning example-bank.com while leaving
-- login.example-bank.com free closes nothing. It is a column rather than a
-- global setting so an operator can ban one exact host (a name they own and
-- serve themselves) without banning everything under it.
--
-- The list is consulted on the CREATION paths only. Nothing here suspends or
-- removes a domain that already exists: adding a name to this table must not
-- take a live site down, and it must not stop that site's certificate from
-- renewing. Removing an existing domain stays a separate, explicit action.
--
-- created_by keeps the ban when the administrator who wrote it is deleted, so
-- the foreign key sets it NULL instead of cascading the row away.
CREATE TABLE banned_domains (
  domain VARCHAR(253) NOT NULL PRIMARY KEY,
  description VARCHAR(255) NOT NULL DEFAULT '',
  match_subdomains TINYINT(1) NOT NULL DEFAULT 1,
  created_by BIGINT UNSIGNED NULL DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_banned_domains_user FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
