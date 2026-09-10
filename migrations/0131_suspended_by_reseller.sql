-- Record which suspensions the reseller cascade itself applied.
--
-- WHY: suspending a reseller cascades to every sub-account and every domain
-- underneath it, and resuming the reseller cascaded back the same way. Neither
-- write recorded what it changed and neither read the previous state, so a
-- resume also lifted a suspension an administrator had applied individually for
-- abuse or non-payment. A site taken down for hosting malware came back with its
-- FTP, mail and tenant runtime restarted, and nothing in the panel said so.
--
-- The suspension state is a single boolean with no record of who set it, which
-- is why the cascade could not tell its own effect from a pre-existing one.
-- These two columns are that record.

ALTER TABLE domains
  ADD COLUMN suspended_by_reseller TINYINT(1) NOT NULL DEFAULT 0;

ALTER TABLE users
  ADD COLUMN suspended_by_reseller TINYINT(1) NOT NULL DEFAULT 0;

-- No backfill. No existing row can be identified as the cascade's own work,
-- because that information was never written. The 0 default says "the cascade
-- did not close this", and erring in that direction is the safe one: the next
-- reseller resume leaves those rows alone, and an operator can open any of them
-- individually.
