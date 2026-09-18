-- 0144 — stop keeping the git webhook URL token in plaintext.
--
-- 0136 gave the webhook its own HMAC signing key, so learning the delivery URL
-- no longer lets anyone forge a signature. The token itself stayed in the clear:
-- git_repos.webhook_secret held the exact path segment, and the receiver matched
-- an incoming delivery with `WHERE webhook_secret=?`. Anyone who could read the
-- panel database, or a dump of it, therefore held every repository's delivery
-- URL and could drive `git fetch` plus `git reset --hard` against the tenant's
-- document root as often as they liked.
--
-- The token is now sealed at rest by internal/secret and matched through a
-- separate SHA-256 column. The seal is non-deterministic, so it cannot be
-- searched; the hash can, and it reveals nothing, because a 40-character random
-- token is not guessable from its digest.
--
-- The hash column is indexed: the receiver looks a delivery up by it on every
-- push, and without the index that is a full scan of git_repos.
--
-- No backfill here. internal/datamigrate fills the hash and seals the token at
-- startup, where it has the key, and it is idempotent so a half-finished run
-- resumes.

ALTER TABLE git_repos
  ADD COLUMN IF NOT EXISTS webhook_secret_hash CHAR(64) NOT NULL DEFAULT '' AFTER webhook_secret;

ALTER TABLE git_repos
  ADD KEY IF NOT EXISTS ix_git_repos_webhook_hash (webhook_secret_hash);
