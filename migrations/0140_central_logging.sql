-- Make the panel's own logs queryable, in three tables that answer three
-- different questions.
--
-- WHY: the panel logged in three places and none of them could be asked a
-- question. middleware.AccessLog wrote one journald line per request with the
-- method, route, status and latency, but not the body, the user agent or the
-- error. audit_log recorded that an action happened, as a free-text action plus
-- target, but not which row of which table moved from which value to which. And
-- internal/logx wrote only to journald, so nothing the panel logged about itself
-- was readable from the panel.
--
-- The three stay apart on purpose. request_logs is the HTTP surface: one row per
-- API request, whoever made it. audit_log is the data surface: what a mutation
-- did to a row. app_logs is the application surface: what the panel said about
-- itself, including from a background job or a startup path where no request
-- exists. Merging them would mean every reader filtering out two thirds of the
-- table, and app_logs would have no request to hang from at all.
--
-- request_id is what joins them. middleware.RequestID already mints one per
-- request and RequestIDHeader returns it to the client, so an operator holding
-- an X-Request-Id from a support ticket can find the request, the rows it
-- changed and the lines the panel logged while serving it.
--
-- These tables grow with traffic, so panel_settings carries the number of days
-- they are kept and a sweep deletes what is older. The panel's MariaDB is the
-- same server the customer sites run on; an unbounded log table there is a disk
-- the operator loses without being told.

CREATE TABLE request_logs (
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ts              TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  request_id      VARCHAR(64)  NOT NULL DEFAULT '',
  user_id         BIGINT UNSIGNED NULL,
  username        VARCHAR(64)  NOT NULL DEFAULT '',
  ip              VARCHAR(45)  NOT NULL DEFAULT '',
  user_agent      VARCHAR(255) NOT NULL DEFAULT '',
  method          VARCHAR(8)   NOT NULL,
  endpoint        VARCHAR(255) NOT NULL,
  module          VARCHAR(64)  NOT NULL DEFAULT '',
  action          VARCHAR(64)  NOT NULL DEFAULT '',
  query_params    JSON NULL,
  request_body    JSON NULL,
  response_status SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  response_ms     INT UNSIGNED NOT NULL DEFAULT 0,
  error_message   VARCHAR(512) NOT NULL DEFAULT '',
  KEY ix_request_logs_ts     (ts),
  KEY ix_request_logs_reqid  (request_id),
  KEY ix_request_logs_user   (user_id),
  KEY ix_request_logs_status (response_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- user_id is nullable because the login, the git webhook and the mail
-- auto-configuration endpoints are logged too and have no session at all. It
-- carries no foreign key to users: a deleted operator must not take their
-- request history with them, which is the whole point of keeping it.

CREATE TABLE app_logs (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ts          TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  level       ENUM('INFO','WARN','ERROR') NOT NULL,
  logger_name VARCHAR(128) NOT NULL DEFAULT '',
  message     TEXT NOT NULL,
  context     JSON NULL,
  request_id  VARCHAR(64) NOT NULL DEFAULT '',
  KEY ix_app_logs_ts    (ts),
  KEY ix_app_logs_level (level),
  KEY ix_app_logs_reqid (request_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The three levels are exactly logx's three. Debug is absent there because the
-- panel has no verbosity setting to turn it on with, so it is absent here too.
-- request_id is empty for every line a background job or a startup path wrote,
-- which is most of them; it is never required.

ALTER TABLE audit_log
  ADD COLUMN request_id     VARCHAR(64) NOT NULL DEFAULT '',
  ADD COLUMN action_type    ENUM('INSERT','UPDATE','DELETE','BULK') NULL,
  ADD COLUMN table_name     VARCHAR(64) NOT NULL DEFAULT '',
  ADD COLUMN record_id      VARCHAR(64) NOT NULL DEFAULT '',
  ADD COLUMN affected_count INT UNSIGNED NULL,
  ADD COLUMN old_values     JSON NULL,
  ADD COLUMN new_values     JSON NULL,
  ADD KEY ix_audit_reqid (request_id);

-- Every new column takes a default or is nullable, so auth.WriteAuditScoped's
-- existing INSERT keeps working unchanged and every audit row written before
-- today stays readable. A row that names no table is a security event (a login,
-- a permission refusal), not a missing value.

ALTER TABLE panel_settings
  ADD COLUMN log_retention_days SMALLINT UNSIGNED NOT NULL DEFAULT 30;
