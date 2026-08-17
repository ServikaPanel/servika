-- 0099 - the addresses the panel itself put on this server.
--
-- A hosting server usually needs more than one address: a domain that sends
-- mail from its own address, a customer who bought a dedicated one, a
-- certificate that has to answer on a second address. Adding one with "ip addr
-- add" is a runtime change and does not survive a reboot, so the panel has to
-- remember what it added.
--
-- The table is a RECORD of the panel's own work, never a description of the
-- server. The host is asked what addresses it has; this answers only which of
-- them the panel is responsible for putting back after a reboot and which it
-- may therefore take away again. An address added outside the panel is absent
-- here and stays untouched, which is the whole point: the primary address the
-- provider configured is what an operator reaches this server through.
--
-- `label` is what the kernel was told to name the address, and it is what makes
-- the distinction above readable off the host rather than only out of this
-- table. A restored database can be missing a row for an address that is on the
-- host, and a reinstalled host can be missing an address this table names, so
-- neither side is trusted alone.
--
-- IPv4 only, and not as a scope decision: the kernel silently DISCARDS the
-- label on an IPv6 address (measured, AlmaLinux 10), so there is no way to tell
-- a panel-added IPv6 address from one the provider configured, and the rule
-- that only the panel's own addresses may be removed cannot exist for it.
CREATE TABLE server_ips (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ip VARCHAR(45) NOT NULL,
  interface VARCHAR(32) NOT NULL,
  prefix_length TINYINT UNSIGNED NOT NULL DEFAULT 32,
  label VARCHAR(15) NOT NULL,
  note VARCHAR(255) NOT NULL DEFAULT '',
  created_by BIGINT UNSIGNED NULL DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_server_ips_ip (ip),
  UNIQUE KEY uq_server_ips_label (label),
  CONSTRAINT fk_server_ips_user FOREIGN KEY (created_by)
    REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
