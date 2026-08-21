-- Malware findings carry evidence weight, not just a name.
--
-- Every heuristic used to write its own row the moment it matched, so a rule
-- that is only evidence (an ini_set that disables a guard, a chr() chain) could
-- not be added at all: it would report every legitimate use as an infection.
-- Weighing the evidence and reporting one row PER FILE is what makes those
-- rules possible, and it also closes a defect in bulk cleanup, where a file
-- matching three rules produced three rows, the first was quarantined and the
-- other two then failed with "file missing" against a file that was already
-- contained.
--
-- The defaults are the CRITICAL end deliberately. Existing rows were written by
-- a model with no threshold, so every one of them was an unconditional finding;
-- recording them as anything weaker would reinterpret what the panel already
-- told its operators. It is also the safe direction for a caller that forgets
-- the column: an over-reported finding is read by a person, an under-reported
-- one is not read at all.
--
-- `level`, `score` and `rules` are all usable unquoted on MariaDB 10.11
-- (measured in CREATE, INSERT, SELECT and WHERE), so they are written bare like
-- the rest of this table.
ALTER TABLE av_findings
  ADD COLUMN score INT NOT NULL DEFAULT 100 AFTER engine,
  ADD COLUMN level VARCHAR(16) NOT NULL DEFAULT 'critical' AFTER score,
  ADD COLUMN rules TEXT NULL AFTER level;
