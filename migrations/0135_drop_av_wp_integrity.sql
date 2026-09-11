-- Drop av_settings.wp_integrity, a switch that nothing ever read.
--
-- WHY: migration 0106 created three detection-layer columns under the comment
-- "Each one is skipped entirely when off, not run and filtered". That was true
-- of rule_engine and location_heuristics, which reach the scan through
-- ScanRequest. It was never true of wp_integrity: no ScanRequest field, no
-- branch in the sweep, the per-domain scan or the real-time watcher. WordPress
-- core verification was implemented later as its own domain-scoped endpoint
-- (POST /domains/{id}/wordpress/verify) which does not consult av_settings at
-- all, so the column, the struct field, the JSON field and the checkbox were a
-- complete pipe with no consumer at the end of it.
--
-- That is worse than a missing feature. An administrator who unticked the box
-- got a saved setting and no change in behaviour, and one who left it ticked
-- believed core integrity was part of the nightly sweep. It was not: a modified
-- wp-includes/pluggable.php was only ever found by pressing the per-domain
-- button by hand.
--
-- Removing the column is the honest repair. The per-domain check is unchanged
-- and stays where it is. avsettings.Settings already carries the rule this
-- violated: "Every field here has a consumer; see the migration for why the
-- three upstream settings that had none are absent."
--
-- MariaDB 10.0+ supports IF EXISTS here, so a host that already lost the column
-- (or an install newer than this file) migrates without failing.

ALTER TABLE av_settings
  DROP COLUMN IF EXISTS wp_integrity;
