-- Three antivirus settings that now have a consumer.
--
-- These were deliberately left out when av_settings was created, because
-- nothing read them and a column written but never consumed is a claim the
-- next reader believes. Each of the three gets its consumer in the same change
-- that adds it here, which is the condition that was missing before.
--
-- 1) realtime turns the fanotify watcher on. It is a SEPARATE question from
--    scheduled_scan: the scheduler sweeps what is already on disk once a night,
--    the watcher inspects a file at the moment it is finished being written.
--    Default 0, because a panel update must not start a new long-running
--    process on an installation whose operator did not ask for one, which is
--    the same rule host_apps_enabled and session_idle_minutes follow.
--
-- 2) scan_workers is how many files the sweep inspects at once. 0 means the
--    panel resolves it from the core count. It is bounded well below the
--    slice's TasksMax, or systemd refuses the workers rather than the scan
--    slowing down, which is a failure that reads as nothing at all.
--
-- 3) file_rate_per_sec is a ceiling on files inspected per second. 0 means no
--    ceiling. The cgroup CPU quota does not cover this: a scan is mostly DISK
--    reads, and cgroup v2 io.weight is a RELATIVE share rather than an absolute
--    cap (an absolute one is io.max, which is written per device and needs the
--    device). So a scan can be inside its CPU quota and still be the reason a
--    busy server's disk has nothing left for the sites it is protecting.
--
-- All three default to off or automatic, so an existing installation behaves
-- exactly as it did before this migration ran.
ALTER TABLE av_settings
  ADD COLUMN realtime TINYINT(1) NOT NULL DEFAULT 0 AFTER scheduled_hour,
  ADD COLUMN scan_workers INT NOT NULL DEFAULT 0 AFTER realtime,
  ADD COLUMN file_rate_per_sec INT NOT NULL DEFAULT 0 AFTER scan_workers;
