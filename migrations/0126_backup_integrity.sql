-- 0126 - backup integrity: detect a stored archive that rotted or disappeared.
--
-- There was no way to know a backup was corrupt until a restore failed. sha256
-- is the archive's checksum, computed once when the backup is written; a periodic
-- scan re-computes it and compares, so silent bit-rot (a flipped bit on disk) and
-- a missing/unreadable file are caught before somebody needs the backup.
--
-- verification records the last scan verdict: '' not yet scanned, 'ok' matches,
-- 'corrupt' the file rotted or cannot be read, 'remote' the local copy was
-- deleted after a verified off-site upload (by design, not a fault).
ALTER TABLE backups ADD COLUMN sha256 VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE backups ADD COLUMN verification VARCHAR(16) NOT NULL DEFAULT '';
