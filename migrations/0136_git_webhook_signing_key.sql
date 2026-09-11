-- Give the git webhook its own HMAC key, separate from the URL path token.
--
-- WHY: git_repos.webhook_secret served two roles at once. It was the path
-- segment of the delivery URL (/api/v1/git-webhook/<secret>) AND the HMAC-SHA256
-- key handed to GitHub as config.secret, and the receiver verified
-- X-Hub-Signature-256 against that same column. Anyone who learned the URL
-- therefore held the signing key and could forge a valid signature for any
-- body, so the signature check added nothing over the URL it exists to backstop.
--
-- That matters because the URL is not a secret in practice: nginx records the
-- full request line for every delivery in its access log, so the value was
-- written to disk on every push and reached anything that ships, archives or
-- backs up /var/log. A holder could drive an unbounded number of `git fetch`
-- plus `git reset --hard` cycles against the tenant's document root.
--
-- The backfill sets the new column to the CURRENT secret rather than to a fresh
-- value. A fresh key here would be correct in isolation and wrong in practice:
-- the webhook already registered at GitHub (or at whatever provider the operator
-- configured by hand) still signs with the old value, so every delivery would
-- start failing signature verification with nothing on screen to explain it.
-- Rotating is the operator's call, and reconnecting the repository now
-- generates an independent pair.
--
-- MariaDB 10.0+ supports IF NOT EXISTS here, so a host that already has the
-- column migrates without failing.

ALTER TABLE git_repos
  ADD COLUMN IF NOT EXISTS webhook_signing_key VARCHAR(64) NOT NULL DEFAULT '' AFTER webhook_secret;

UPDATE git_repos
   SET webhook_signing_key = webhook_secret
 WHERE webhook_signing_key = '';
