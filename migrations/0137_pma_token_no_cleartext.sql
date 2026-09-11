-- Stop storing a tenant's database password in a phpMyAdmin signon token.
--
-- WHY: RequestToken decrypted db_accounts.db_pass_plain and then INSERTed the
-- plaintext into pma_tokens.db_pass, a plain VARCHAR. That defeats the at-rest
-- encryption of db_pass_plain for every database whose owner ever opened
-- phpMyAdmin, and every panel database dump (which the backup tool also uploads
-- off-site) carried a reusable cleartext tenant database password.
--
-- The cleanup made it durable. The only DELETE was issued inside RequestToken
-- itself, so a used or expired row was removed only when somebody requested the
-- NEXT token: on a panel where nobody does, the last row survives indefinitely.
--
-- The token now holds a REFERENCE to the account rather than a copy of the
-- credential. Redeem re-reads and decrypts db_accounts at redemption time,
-- which also means it hands phpMyAdmin the CURRENT password rather than the one
-- that was current two minutes earlier.
--
-- Existing rows are deleted rather than migrated. They are two-minute tokens,
-- the panel is restarting anyway (migrations run before it listens), and
-- deleting them is what removes the stored cleartext from this installation
-- immediately, which is the point of the change.

DELETE FROM pma_tokens;

ALTER TABLE pma_tokens
  ADD COLUMN IF NOT EXISTS db_account_id BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER domain_id;

ALTER TABLE pma_tokens
  DROP COLUMN IF EXISTS db_pass;
