-- Drop domains.is_demo, the flag behind a read-only policy that was never whole.
--
-- WHY: the column was meant to mark a demo subscription and hold it read-only.
-- Roughly a hundred handlers read it and refused, but the set was assembled by
-- hand, one endpoint at a time, and it was never complete. The panel never
-- offered a way to SET the flag: there is no create option, no edit field and no
-- API that writes it, so every INSERT wrote the literal 0 and the column held 0
-- on every row of every installation. Nothing turned it on, so nothing was ever
-- refused.
--
-- A policy that is only enforced in the places somebody remembered, and whose
-- switch does not exist, is not a weak control. It is a control an operator can
-- read in the code and believe in. Both halves of the repair belong together:
-- the guards go, and so does the column that made them look deliberate.
--
-- Dropping the column also removes the trap the half-set left behind. Where a
-- handler read is_demo from the same row as the identifiers it then used, a
-- swallowed read error left the flag at 0 and the guard passed; a future writer
-- of the flag would have shipped a policy with holes it could not see.
--
-- MariaDB 10.0+ supports IF EXISTS here, so a host that already lost the column
-- (or an install newer than this file) migrates without failing.

ALTER TABLE domains
  DROP COLUMN IF EXISTS is_demo;
