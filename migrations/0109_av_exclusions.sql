-- Remove the RELATIVE entries this panel seeded into the malware exclusion list.
--
-- 0106 seeded `.git/`, `node_modules/`, `/wp-content/cache/` and
-- `/wp-content/uploads/cache/` as a convenience. They were an escape.
--
-- The matcher used a substring test, so `node_modules/` excluded any path
-- containing it. Measured against the seeded list:
--
--   /home/c_x/public_html/wp-content/uploads/node_modules/shell.php  -> EXCLUDED
--
-- A tenant who can write a directory anywhere under their document root hid a
-- webshell from the nightly sweep AND from the real-time watcher by running
-- `mkdir node_modules`. Nothing reported it, because an excluded file is not a
-- file that was inspected and found clean.
--
-- avsettings.PathExcluded now matches a relative entry against WHOLE segments,
-- which closes the `notnode_modulesbar` half. It does NOT close this half: a
-- real `node_modules` segment is still excluded wherever it sits, so the
-- entries themselves have to go. They buy nothing either way, because the
-- scanner's extension gate already skips the .js, .map and .gz files that fill
-- those directories, and a .php file under node_modules is not something a
-- package manager put there.
--
-- 0106 is NOT edited. The migration runner tracks an applied migration by
-- checksum and calls log.Fatalf on a mismatch, so editing it stops the panel
-- from starting at all.
--
-- Only the four entries this panel seeded are removed, matched as WHOLE lines.
-- A path the operator added themselves is left exactly as they typed it, even
-- when it looks like one of these.
UPDATE av_settings
SET excluded_paths = TRIM(BOTH '\n' FROM REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
  CONCAT('\n', excluded_paths, '\n'),
  '\n.git/\n', '\n'),
  '\nnode_modules/\n', '\n'),
  '\n/wp-content/cache/\n', '\n'),
  '\n/wp-content/uploads/cache/\n', '\n'),
  '\n\n', '\n'))
WHERE id = 1;
