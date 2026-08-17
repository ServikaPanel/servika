-- 0100 - every attempt to move the panel's own ports.
--
-- This is the one change in the panel that can take the panel away. The backend
-- port lives in SERVIKA_LISTEN and the systemd unit restarts to pick it up; the
-- external port is the nginx listen line an operator's browser connects to.
-- Getting either wrong means the screen that would fix it is the screen that is
-- gone.
--
-- The table is a LOG, not a setting. The current ports are read from the files
-- that actually hold them, never from here, so the panel and the server cannot
-- drift apart: a row that says 9443 while nginx says 8443 would send an
-- operator to a port nothing answers on.
--
-- succeeded and rolled_back are separate columns because they answer separate
-- questions. A change that failed and was put back is a working server with a
-- failed change; a change that failed and could NOT be put back is a server
-- somebody has to reach another way, and those two must never look alike in a
-- log somebody reads after an incident.
CREATE TABLE panel_port_history (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  kind ENUM('backend','external') NOT NULL,
  old_port SMALLINT UNSIGNED NOT NULL,
  new_port SMALLINT UNSIGNED NOT NULL,
  succeeded TINYINT(1) NOT NULL DEFAULT 0,
  rolled_back TINYINT(1) NOT NULL DEFAULT 0,
  last_error VARCHAR(512) NOT NULL DEFAULT '',
  actor_uid BIGINT UNSIGNED NULL DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at DATETIME NULL DEFAULT NULL,
  KEY ix_panel_port_history_created (created_at),
  CONSTRAINT fk_panel_port_history_user FOREIGN KEY (actor_uid)
    REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
