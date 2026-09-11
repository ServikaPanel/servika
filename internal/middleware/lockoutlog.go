package middleware

import (
	"log"
	"strings"
	"sync"
	"time"

	"servika/internal/auth"
)

// The rate limiter was written as a pure in-memory gate: it returns 429 before
// next.ServeHTTP, so the login handler never runs and the audit rows it writes
// for a failed login are never reached. The moment the lock engages, the attack
// becomes invisible.
//
// Two concrete losses. An online attack appears in the audit log as exactly
// five failures from an address and then nothing, so a screen reports an attack
// that ran for hours as five attempts that stopped. And the per-account lock is
// documented as a weapon anyone can fire, since anyone can send deliberately
// wrong passwords to keep an operator out; when it fired against a real
// operator, nothing recorded which account was locked or from where.
//
// The TRANSITION is audited, once. The blocked attempts that follow are logged
// on a throttle, which is what separates an attack that stopped from one that
// is still running without writing a row per packet.

// lockoutActionAddress and lockoutActionAccount are the audit actions. They sit
// beside auth.login, which is where an operator already looks.
const (
	lockoutActionAddress = "auth.lockout.address"
	lockoutActionAccount = "auth.lockout.account"
)

// auditNameLimit matches audit_log.actor_username. The attempted name is
// attacker-controlled and bounded only by the login body limit, so it is cut
// here rather than truncated by MariaDB.
const auditNameLimit = 64

// blockedComplainInterval bounds one line per kind of blocked attempt. A locked
// address can be retried as fast as the attacker likes.
const blockedComplainInterval = 60 * time.Second

var (
	blockedMu   sync.Mutex
	lastBlocked = map[string]time.Time{}
)

// safeName makes an attacker-supplied account name safe to store and to log:
// control characters out, length bounded.
func safeName(value string) string {
	var out strings.Builder
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			continue
		}
		out.WriteRune(r)
		if out.Len() >= auditNameLimit {
			break
		}
	}
	return out.String()
}

// recordLockout writes the audit row for a lock that has just engaged.
//
// The actor id is 0: there is no authenticated identity, the login failed. The
// username is the account that was being tried, which is the only identifying
// thing the request carried, and the address is the one the limiter keyed on.
func recordLockout(action, account, address, target string) {
	name := safeName(account)
	if scopeDB != nil {
		auth.WriteAudit(scopeDB, 0, name, address, action, safeName(target), false)
	}
	// #nosec G706 -- the account and target are passed through safeName, which strips every control character; the address comes from httpx.RateLimitKey.
	log.Printf("login lockout: %s engaged for %q from %s", action, safeName(target), address)
}

// noteBlocked logs a throttled line for an attempt refused by an existing lock.
// kind separates the address lock, the account lock and the generic limiter, so
// one cannot silence another.
func noteBlocked(kind, subject, address string) {
	blockedMu.Lock()
	now := time.Now()
	if previous, seen := lastBlocked[kind]; seen && now.Sub(previous) < blockedComplainInterval {
		blockedMu.Unlock()
		return
	}
	lastBlocked[kind] = now
	blockedMu.Unlock()
	// #nosec G706 -- subject is passed through safeName and address comes from httpx.RateLimitKey.
	log.Printf("login lockout: still refusing %s for %q from %s", kind, safeName(subject), address)
}

// resetLockoutLog drops the throttle. Tests call it so one case cannot decide
// the outcome of the next.
func resetLockoutLog() {
	blockedMu.Lock()
	lastBlocked = map[string]time.Time{}
	blockedMu.Unlock()
}
