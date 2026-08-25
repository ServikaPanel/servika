-- Files a sweep did not read because the previous sweep found them clean and
-- nothing about them has changed since.
--
-- It is a separate column from `scanned` because the two are separate claims:
-- one is what this sweep inspected, the other is what it took on an earlier
-- sweep's word. Adding them together would hide how much of the tree was
-- actually read, which is the one thing a scan report must not do.
ALTER TABLE av_scans
  ADD COLUMN skipped INT NOT NULL DEFAULT 0 AFTER scanned;
