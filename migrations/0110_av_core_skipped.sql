-- The WordPress core files automatic containment deliberately left in place.
--
-- 0107 records what was taken and what failed. A core file is neither: moving
-- wp-includes/pluggable.php out of the tree turns a compromised site into a
-- dead one, so the finding is reported and the file stays where it is, and the
-- repair that puts the official file back is `wp core download --force`, a
-- different action the panel already offers.
--
-- Without its own column that outcome has nowhere to go. Counting it as taken
-- claims a containment that did not happen; counting it as failed sends an
-- operator looking for a fault that is not there; counting it nowhere leaves a
-- pass that left two infected core files in place reading as a clean sweep,
-- which is the reading 0107 exists to prevent.
--
-- The default is 0, which is what every existing row means: the exception did
-- not exist when they were written, so nothing was skipped for this reason.
ALTER TABLE av_scans
  ADD COLUMN auto_quarantine_core_skipped INT NOT NULL DEFAULT 0 AFTER auto_quarantine_failed;
