-- process_monitor turns the process-behaviour watcher on. It is a SEPARATE
-- feature from realtime (the fanotify file watcher): one watches files as they
-- are written, the other watches the exec chain (php-fpm starting a shell) via
-- the netlink proc connector. It runs as its own unit, servika-proc-watch.service.
--
-- It defaults to 0 (off), the same rule every new antivirus layer follows: a
-- panel update must not change what an existing installation does, and turning
-- this on starts a service that subscribes to every exec on the host.
ALTER TABLE av_settings
  ADD COLUMN process_monitor TINYINT(1) NOT NULL DEFAULT 0 AFTER file_rate_per_sec;
