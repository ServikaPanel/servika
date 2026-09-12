-- Let a logout end the session on the server, not just in the browser.
--
-- WHY: signing out called only ClearSessionCookie, so the JWT the browser had
-- just stopped sending stayed valid for the rest of its lifetime (8 hours by
-- default for an operator, and the customer login used to hand out 24). Anyone
-- who had already captured that cookie kept a working session, and pressing
-- "sign out" on a shared machine protected nothing on the server side.
--
-- The coarse control already existed: users.token_version, bumped by
-- POST /me/sessions/revoke. It is the wrong tool for a logout, because it kills
-- every session the account holds. Closing a laptop lid at the office must not
-- sign the same person out of their phone.
--
-- So the token now carries a per-session identifier (the JWT jti claim) and a
-- logout records that ONE identifier here. RequireAuth refuses a token whose
-- jti is listed. token_version stays exactly as it was for the all-devices case.
--
-- expires_at is the token's own exp. Nothing needs the row after that instant,
-- because the token is refused on its expiry anyway, so a sweep deletes it. The
-- table therefore holds at most the sessions signed out inside one token
-- lifetime, not a growing log.
--
-- A session opened BEFORE this migration carries no jti. Such a token keeps
-- working until it expires: refusing it would sign every operator out the moment
-- the panel restarted, and there is nothing to record for it either way.

CREATE TABLE IF NOT EXISTS revoked_sessions (
  jti        VARCHAR(64) NOT NULL,
  expires_at DATETIME    NOT NULL,
  revoked_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (jti),
  KEY idx_revoked_sessions_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
