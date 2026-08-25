-- Whether a domain on this server is on a DNS blocklist.
--
-- The state is STORED rather than queried when a screen is drawn. One query
-- per zone per domain, at a few seconds each when a blocklist is slow, is 500
-- domains times up to 8 zones on one HTTP request. A scheduler refreshes the
-- table and the endpoint reads it.
--
-- `queried` is a column of its own because an empty zone list and a clean
-- domain both leave `listed` empty. Folding them together turns a domain
-- nothing could check into a domain reported clean, which is the one answer a
-- reputation screen must not invent.
CREATE TABLE domain_reputation (
  domain_id    BIGINT UNSIGNED NOT NULL PRIMARY KEY,
  -- The zones that list this domain, space separated. Empty when nothing does.
  listed       VARCHAR(512) NOT NULL DEFAULT '',
  -- The zones that were asked, so a stored row says what it is an answer about.
  zones        VARCHAR(512) NOT NULL DEFAULT '',
  -- 0 when no zone could be asked at all: the setting is empty, or the name is
  -- not one a blocklist can be asked about.
  queried      TINYINT(1) NOT NULL DEFAULT 0,
  last_scan_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_domain_reputation_domain FOREIGN KEY (domain_id)
    REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- The blocklist zones a domain is checked against, space separated.
--
-- The default is EMPTY, which is OFF. A panel update must not start querying a
-- third-party service about every domain on an operator's server, and a host
-- resolving through a public resolver gets 127.255.255.254 from Spamhaus for
-- every name anyway, so the operator has to name a zone their resolver can
-- actually query before this reports anything.
ALTER TABLE panel_settings
  ADD COLUMN domain_dnsbl_zones VARCHAR(512) NOT NULL DEFAULT '';
