-- Windows agents the panel talks to over a pinned TLS connection.
--
-- The panel runs on Linux and manages the host directly. A Windows host cannot
-- be managed that way, so it runs an agent and the panel keeps a row here for
-- each one.
--
-- `token_encrypted` is sealed with the row's own address as AAD, so a
-- ciphertext copied into another row fails to open. `fingerprint` is the
-- SHA-256 of the agent's leaf certificate, learned on first contact and
-- enforced on every call afterwards; an empty value means the row predates the
-- pin and must be re-probed before the panel will talk to it.
CREATE TABLE IF NOT EXISTS windows_agents (
  id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name            VARCHAR(64)  NOT NULL,
  address         VARCHAR(255) NOT NULL,
  token_encrypted TEXT         NOT NULL,
  fingerprint     CHAR(64)     NOT NULL DEFAULT '',
  version         VARCHAR(32)  NOT NULL DEFAULT '',
  channel         VARCHAR(32)  NOT NULL DEFAULT '',
  capabilities    INT UNSIGNED NOT NULL DEFAULT 0,
  state           VARCHAR(32)  NOT NULL DEFAULT 'unknown',
  last_seen       DATETIME     NULL DEFAULT NULL,
  created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY ux_windows_agents_address (address),
  KEY ix_windows_agents_state (state)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
