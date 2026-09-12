-- Record what happens in the BROWSER, which no table holds today.
--
-- WHY: 0140 made the server side queryable, but the panel is a single-page
-- application. Moving between screens changes no URL the server sees, so
-- request_logs holds no row for it, and a button that was pressed without the
-- request it should have made leaves no trace anywhere. A customer reporting
-- "I pressed save and nothing happened" cannot be answered from any log the
-- panel keeps.
--
-- Two surfaces, kept apart from the three that already exist. ui_events is what
-- the interface DID: a route change, a search, a significant button, a client
-- side error. replay_sessions and replay_events hold an rrweb recording of the
-- same session, so the same minute can be watched rather than read.
--
-- session_id is minted in the browser, one per tab, and both surfaces carry it.
-- request_id joins a ui_events row to the request_logs, audit_log and app_logs
-- rows for the same call.

CREATE TABLE ui_events (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ts         TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  user_id    BIGINT UNSIGNED NULL,
  username   VARCHAR(64)  NOT NULL DEFAULT '',
  session_id VARCHAR(64)  NOT NULL DEFAULT '',
  request_id VARCHAR(64)  NOT NULL DEFAULT '',
  event_type VARCHAR(32)  NOT NULL,
  path       VARCHAR(255) NOT NULL DEFAULT '',
  event_data JSON NULL,
  KEY ix_ui_events_ts      (ts),
  KEY ix_ui_events_user    (user_id, ts),
  KEY ix_ui_events_session (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- user_id carries no foreign key to users, for the same reason request_logs
-- does not: a deleted operator must not take their history with them.

CREATE TABLE replay_sessions (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  session_id VARCHAR(64) NOT NULL,
  user_id    BIGINT UNSIGNED NULL,
  username   VARCHAR(64)  NOT NULL DEFAULT '',
  page_url   VARCHAR(255) NOT NULL DEFAULT '',
  started_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  batches    INT UNSIGNED NOT NULL DEFAULT 0,
  UNIQUE KEY ux_replay_session (session_id),
  KEY ix_replay_user (user_id, started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- session_id is UNIQUE so a batch that arrives while the first one is still in
-- flight joins the session it belongs to instead of opening a second one.

CREATE TABLE replay_events (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  session_id BIGINT UNSIGNED NOT NULL,
  seq        INT UNSIGNED NOT NULL,
  batch      LONGTEXT NOT NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY ux_replay_seq            (session_id, seq),
  KEY        ix_replay_events_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Each batch is its OWN row. Appending into one growing JSON array rewrites the
-- whole value on every write, so a session of a few thousand events would cost
-- O(n^2) bytes written and hold the row lock for the length of each rewrite.
--
-- batch is LONGTEXT and not JSON on purpose: the server never reads inside it.
-- It stores what the browser sent and returns it unchanged to the player, so
-- parsing it on every INSERT would buy nothing, and one malformed batch would
-- then be refused by the column rather than handled by the reader.
--
-- (session_id, seq) is UNIQUE because the browser retries a batch it could not
-- confirm, and beforeunload can send the same one the interval already sent.
-- Without it the replay would play those seconds twice.

ALTER TABLE panel_settings
  ADD COLUMN session_replay_enabled TINYINT(1) NOT NULL DEFAULT 0;

-- Default 0. An update must not start recording anybody's screen on an
-- installation that never asked for it.

ALTER TABLE users
  ADD COLUMN replay_consent_at TIMESTAMP NULL DEFAULT NULL;

-- NULL means this account has not agreed to be recorded, and the ingest refuses
-- its batches. Consent is stored per account rather than in a cookie, so it
-- survives a new browser and can be withdrawn from any of them.
