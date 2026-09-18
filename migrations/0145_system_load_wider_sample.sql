-- 0145 — record CPU, disk, swap and network beside the load average.
--
-- 0020 stored one sample per minute with the load average and the memory
-- percentage. Everything else the dashboard shows is LIVE only: /system/usage
-- reads it on each poll and nothing keeps it, so the frontend holds sixty
-- in-memory points and loses them on a reload. An operator who wanted to know
-- what the CPU or the uplink was doing during last night's incident had nothing
-- to look at.
--
-- The rates are stored as bytes PER SECOND, not as the raw interface counters.
-- A counter resets when the interface is renamed or the host reboots, and a
-- reader differencing two rows would then draw a negative spike or, worse, a
-- gigantic positive one on the wrap. The sampler already differences against its
-- own previous reading and clamps a backwards counter to zero, so the value
-- stored here is directly plottable.
--
-- Every column defaults to 0, so the rows 0020 wrote keep reading: they render
-- as a flat line before the upgrade rather than as a gap or a scan error.

ALTER TABLE system_load
  ADD COLUMN IF NOT EXISTS cpu_percent  FLOAT  NOT NULL DEFAULT 0 AFTER mem_percent,
  ADD COLUMN IF NOT EXISTS swap_percent FLOAT  NOT NULL DEFAULT 0 AFTER cpu_percent,
  ADD COLUMN IF NOT EXISTS disk_percent FLOAT  NOT NULL DEFAULT 0 AFTER swap_percent,
  ADD COLUMN IF NOT EXISTS net_rx_bps   BIGINT NOT NULL DEFAULT 0 AFTER disk_percent,
  ADD COLUMN IF NOT EXISTS net_tx_bps   BIGINT NOT NULL DEFAULT 0 AFTER net_rx_bps;
