package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// sessionID mints the per-session identifier carried in the jti claim.
//
// It is what makes a logout able to end ONE session. users.token_version can
// only end all of them at once, which is right for "revoke every session" and
// wrong for closing a laptop while the phone stays signed in.
//
// 16 random bytes, base64url without padding, so the value is 22 characters and
// fits revoked_sessions.jti. crypto/rand.Read cannot fail on any platform this
// panel runs on; if it ever did, the error is returned rather than issuing a
// token whose identifier is predictable.
func sessionID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

type Claims struct {
	UserID       int64  `json:"uid"`
	Username     string `json:"usr"`
	Role         string `json:"role"`
	TokenVersion int64  `json:"tv"`
	jwt.RegisteredClaims
}

func Issue(secret []byte, lifetimeSec int, uid int64, username, role string, tokenVersion int64) (string, error) {
	jti, err := sessionID()
	if err != nil {
		return "", err
	}
	now := time.Now()
	c := Claims{
		UserID:       uid,
		Username:     username,
		Role:         role,
		TokenVersion: tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(lifetimeSec) * time.Second)),
			Issuer:    "servika",
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return tok.SignedString(secret)
}

func Parse(secret []byte, raw string) (*Claims, error) {
	if raw == "" {
		return nil, errors.New("empty token")
	}
	c := &Claims{}
	tok, err := jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing algorithm")
		}
		return secret, nil
	})
	if err != nil || !tok.Valid {
		return nil, errors.New("invalid token")
	}
	if c.Issuer != "servika" || c.Role == "" {
		return nil, errors.New("not an administrator token")
	}
	return c, nil
}
