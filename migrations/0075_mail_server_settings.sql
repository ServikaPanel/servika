-- Server-wide mail settings.
--
-- Send limits existed only per mailbox, so one compromised account under a plan
-- with a generous limit could still saturate the server's reputation, and there
-- was no ceiling an operator could put across the whole machine. The message
-- size and the DNSBL list were only reachable by editing Postfix by hand.
CREATE TABLE mail_server_settings (
  id TINYINT UNSIGNED PRIMARY KEY,
  -- 0 keeps whatever Postfix is already configured with, so installing this
  -- release does not change the size limit of a running server.
  max_message_size_mb INT NOT NULL DEFAULT 0,
  -- Hourly ceilings enforced by the policy service. 0 means no ceiling, which
  -- is what every server did before this table existed.
  domain_send_limit_hour INT NOT NULL DEFAULT 0,
  client_send_limit_hour INT NOT NULL DEFAULT 0,
  -- Space-separated DNSBL zones for smtpd_client_restrictions. Empty leaves the
  -- restriction out entirely rather than writing an empty one.
  dnsbl_zones VARCHAR(1024) NOT NULL DEFAULT '',
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO mail_server_settings(id) VALUES(1);

-- The per-client ceiling needs the address the mail came from, which the send
-- log never recorded. Rows written before this column exists count towards the
-- per-mailbox and per-domain windows as they always did, and simply do not
-- match any client.
--
-- ix_sendlog_domain_ts is NOT created here: 0059_mail_send_limits.sql already
-- adds it. Adding it a second time is `Duplicate key name`, which fails this
-- whole migration and stops the panel from starting.
ALTER TABLE mail_send_log
  ADD COLUMN client_ip VARCHAR(45) NOT NULL DEFAULT '',
  ADD KEY ix_sendlog_client_ts (client_ip, ts);
