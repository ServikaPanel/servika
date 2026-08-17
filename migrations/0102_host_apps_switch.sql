-- The switch that offers server-level applications at all.
--
-- It defaults to 0, which is the opposite of the feature being ready: it is
-- ready. The default is off because a panel update must not change what an
-- existing installation does. An operator who has never asked for this gets a
-- server that downloads nothing, creates no accounts and opens no ports until
-- they say so, which is the same reason panel_settings.session_idle_minutes
-- defaults to 0 rather than to the value the feature was designed around.
--
-- Turning it OFF later does NOT stop or expose anything already installed. The
-- units keep running, the firewall keeps whatever the operator opened, and the
-- rows stay. The alternative reading, that switching off tears the applications
-- down, would make a settings checkbox delete a Gitea installation and every
-- repository in it; and the other alternative, dropping the firewall rules
-- while the processes keep listening, would silently PUBLISH every application
-- on a server whose operator had just asked for the feature to be off. What the
-- switch controls is whether the panel offers the feature: the screen, the
-- catalog and every operation that changes the host.
ALTER TABLE panel_settings
  ADD COLUMN host_apps_enabled TINYINT(1) NOT NULL DEFAULT 0;
