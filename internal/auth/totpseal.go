package auth

import (
	"strconv"

	"servika/internal/secret"
)

// The TOTP seed is a credential at rest, like every other one the panel stores.
// It used to sit in users.totp_secret as raw base32, so any read of that table
// yielded a working second factor for every administrator and reseller who
// enabled 2FA, and a seed generates valid codes indefinitely. The precondition
// is a database read rather than host root, and the panel creates that read
// itself: the database and system backup tools write panel dumps to disk, and
// the system backup can be copied off-site.
//
// The AAD binds the seal to one users row. Without it a ciphertext could be
// copied from one row into another, and whoever holds the source account's
// authenticator would then satisfy the target account's second factor.
func totpAAD(userID int64) string {
	return "users.totp_secret:" + strconv.FormatInt(userID, 10)
}

// SealTOTPSecret seals a TOTP seed for one user.
func SealTOTPSecret(seed string, userID int64) (string, error) {
	return secret.EncryptWith(seed, totpAAD(userID))
}

// OpenTOTPSecret returns the usable seed for one user.
//
// A value with no encryption prefix is returned unchanged, which is what keeps a
// row written before the seal existed usable until the backfill converts it.
// Anything else that fails to open is an error: the caller must deny rather than
// verify a code against a value it could not read.
func OpenTOTPSecret(stored string, userID int64) (string, error) {
	return secret.DecryptWith(stored, totpAAD(userID))
}
