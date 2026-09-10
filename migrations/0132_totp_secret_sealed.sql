-- Widen users.totp_secret so the sealed form fits.
--
-- WHY: the column held the raw base32 TOTP seed, while every other stored
-- credential in the panel is sealed with AES-256-GCM under SERVIKA_SECRET_KEY.
-- A seed is all that is needed to generate valid codes indefinitely, so any read
-- of the users table handed over a working second factor for every administrator
-- and reseller who enabled 2FA. The precondition is a database read rather than
-- host root, and the panel creates that read itself: servika-db-backup and
-- servika-system-backup write panel dumps to disk and the system backup can be
-- copied off-site. Beside the password hashes in the same dump, the factor that
-- is supposed to survive a password compromise did not.
--
-- The seal is `enc:v1:` plus base64 of a 12-byte nonce, the seed and a 16-byte
-- tag, which is about 87 characters for a 32-character seed. varchar(64) would
-- truncate it, and a truncated ciphertext never opens again: the account would
-- be locked out of its own second factor.
--
-- The backfill itself is in Go (internal/datamigrate), not here, because the
-- seal binds the user id as associated data so a ciphertext cannot be copied
-- from one users row into another.

ALTER TABLE users
  MODIFY COLUMN totp_secret VARCHAR(255) NOT NULL DEFAULT '';
