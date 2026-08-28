-- Attack-chain causality. Purely temporal correlation (tenant + window) launders
-- two INDEPENDENT false positives into one "critical attack chain". The path (the
-- written file, or the executed binary) and the pid let the correlator require a
-- CAUSAL link: the SAME full path (a dropped file was executed) or the SAME pid.
-- Without a causal link a chain stays a warning rather than escalating to
-- critical. Same-directory is deliberately NOT causal, because a tenant document
-- root holds many files and two unrelated detections would share it.
ALTER TABLE av_events
  ADD COLUMN path VARCHAR(512) NOT NULL DEFAULT '' AFTER summary,
  ADD COLUMN pid  INT          NOT NULL DEFAULT 0  AFTER path;
