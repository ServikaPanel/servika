-- What automatic containment actually did, recorded beside the scan that
-- triggered it.
--
-- av_findings.quarantined already says which files were taken. It says nothing
-- at all about the ones that were NOT: a containment that failed leaves the row
-- exactly as a finding nobody tried to contain, so a run that left three
-- webshells in place reads identically to one that found three and was never
-- asked to act. That is the reading this whole feature exists to prevent, and
-- it is the same rule QuarantineAll already follows by answering with a taken
-- count and a failed count rather than a success.
--
-- Both default to 0, which is what every existing row means: automatic
-- containment did not exist when they were written, so nothing was taken and
-- nothing failed.
ALTER TABLE av_scans
  ADD COLUMN auto_quarantined INT NOT NULL DEFAULT 0 AFTER confined,
  ADD COLUMN auto_quarantine_failed INT NOT NULL DEFAULT 0 AFTER auto_quarantined;
