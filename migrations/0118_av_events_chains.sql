-- Attack Chain Engine (EDR Phase 2). The file scan and the process watcher each
-- produce SINGLE signals; an attack is a CHAIN (a webshell is written, then a
-- web process execs a shell, then a payload is fetched). Both detectors write a
-- stage-classified row to av_events, and a background correlator groups a
-- tenant's recent events into an av_chains row with a confidence score.
--
-- Neither table carries a reseller_id: authorization is always resolved from the
-- ownership chain (domains.customer_id -> customers -> owner_user_id), and a
-- copied reseller_id would drift the day a domain is transferred. A future list
-- endpoint narrows by domain_id through middleware.ScopeSQL.
CREATE TABLE IF NOT EXISTS av_events (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain_id  BIGINT UNSIGNED NULL,
  source     VARCHAR(16)  NOT NULL,                     -- file | process | api | network
  stage      VARCHAR(24)  NOT NULL,                     -- entry|file_write|execution|c2|persistence
  level      VARCHAR(16)  NOT NULL DEFAULT 'warning',
  summary    VARCHAR(255) NOT NULL DEFAULT '',
  ref_type   VARCHAR(24)  NOT NULL DEFAULT '',
  ref_id     BIGINT       NOT NULL DEFAULT 0,
  created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_events_dom_time (domain_id, created_at),
  KEY idx_events_time (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS av_chains (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain_id   BIGINT UNSIGNED NULL,
  stages      VARCHAR(128) NOT NULL,                    -- "file_write>execution>c2"
  confidence  INT          NOT NULL DEFAULT 0,          -- 0-99
  event_count INT          NOT NULL DEFAULT 0,
  signature   VARCHAR(64)  NOT NULL,                    -- dedup: sha256(domain|stages)[:32]
  created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_chains_dom (domain_id),
  KEY idx_chains_sig (signature),
  KEY idx_chains_time (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
