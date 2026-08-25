-- The scan's CPU share, which is a different question from its CPU ceiling.
--
-- servika-av.slice already carries CPUQuota, an ABSOLUTE cap: the scan gets the
-- same 1.5 cores on an idle server and on a busy one, so when real traffic
-- arrives the scan takes its quota out of that traffic. The slice has never
-- written cpu.weight, so it sits at the kernel default of 100, which is exactly
-- what every tenant slice sits at. The scan competes with the sites it is
-- protecting on equal footing.
--
-- A weight is a RELATIVE share, so it costs nothing when nobody else wants the
-- CPU. Measured on cgroup v2 with both groups pinned to one core: a group at
-- weight 10 running alone took 99% of that core, and the same group against a
-- weight-100 group took 9% while the other took 90%. That is the whole point:
-- the scan keeps filling an idle machine and yields the moment a site needs the
-- processor.
--
-- 0 means automatic, resolved by the panel, so an installation that never opens
-- the antivirus screen behaves exactly as it did before this migration ran.
ALTER TABLE av_settings
  ADD COLUMN cpu_weight INT NOT NULL DEFAULT 0 AFTER io_weight;
