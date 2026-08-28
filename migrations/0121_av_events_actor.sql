-- The entry (Initial Access) stage. A panel brute-force success is detected from
-- audit_log and recorded as an av_events row with stage 'entry' and a NULL
-- domain_id, because a login belongs to an ACCOUNT, not one domain. actor_user_id
-- holds the brute-forced account's user id, so the correlator can link the entry
-- to exactly the domains that account owns (a reseller through customers.owner_user_id,
-- a customer through customers.user_id), resolved live from the ownership chain.
-- It is NULL for every other event.
ALTER TABLE av_events
  ADD COLUMN actor_user_id BIGINT UNSIGNED NULL AFTER domain_id;
