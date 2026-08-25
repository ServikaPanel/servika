-- 0113 - give notifications.params the default 0112 says it has.
--
-- 0112's own header states the contract: "Both default to empty rather than
-- NULL, so 'no key' is one value rather than two, and a writer that supplies
-- only English is still valid." `message_key` got `DEFAULT ''`; `params` did
-- not, and MariaDB refuses an INSERT that omits a NOT NULL column with no
-- default: `ERROR 1364 (HY000): Field 'params' doesn't have a default value`.
--
-- So the second half of that sentence was false. `notifications.Write` always
-- supplies the column, which is why nothing in the panel broke, but any writer
-- that carries only the English text is refused at runtime rather than stored,
-- and that is the shape a future caller will reach for first.
--
-- Measured on MariaDB 10.11: a TEXT column accepts DEFAULT '' and an INSERT
-- that omits it then stores the empty string. 0112 cannot be edited, because
-- the runner tracks every applied file by checksum and calls log.Fatalf on a
-- mismatch, so the panel would stop starting.
ALTER TABLE notifications
  MODIFY COLUMN params TEXT NOT NULL DEFAULT '';
