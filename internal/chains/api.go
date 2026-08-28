package chains

// The entry (Initial Access) stage. It detects a panel brute-force SUCCESS from
// audit_log and records it as an av_events row so the correlator can add the
// "entry" end to a domain's kill chain.
//
// The finding is "a flood of failed logins FOLLOWED BY a successful one", never
// the failed flood alone. This is the false-positive gate: an account-level
// login has no path or pid, so it can never form a causal link, and its only
// contribution to a chain is one more distinct stage. If a bare failed flood
// counted, a bot hammering a stale password would stamp a permanent entry on
// every domain its target account owns, quietly turning the correlator's "two
// coincidences" floor into "one coincidence". Requiring a SUCCESS closes it: a
// bot or an unknown-username spray never succeeds, so it never earns an entry,
// while a real panel-vector takeover (a login is required to upload a shell)
// does.
//
// Both panel logins are scanned: auth.login (admin and reseller) and
// customer.login (a domain owner). A failed login writes actor_user_id 0
// whether or not the username exists, so failures are grouped by actor_username;
// the SUCCESS row carries the real user id, which keys the entry to that
// account's domains.

import (
	"database/sql"
	"fmt"
	"log"
	"net"
)

// entryThreshold is the failed-login count in the window that, together with a
// subsequent success, marks a brute-force success.
const entryThreshold = 5

type loginBurst struct {
	actorUID int64
	fails    int
	ip       string
	distinct int // distinct source IPs, a distributed-versus-single signal
}

// apiScan writes an entry event for every account brute-forced in the window.
func apiScan(db *sql.DB) {
	bursts := detectBursts(db)
	for _, b := range bursts {
		if entryRecent(db, b.actorUID) {
			continue // deduped: an entry for this account was written recently
		}
		if _, err := db.Exec(`INSERT INTO av_events (domain_id, actor_user_id, source, stage, level, summary, path, pid)
			VALUES (NULL, ?, 'api', 'entry', 'warning', ?, '', 0)`, b.actorUID, entrySummary(b)); err != nil {
			log.Printf("attack chain: the entry event for user %d could not be recorded: %v", b.actorUID, err)
			continue
		}
		log.Printf("ATTACK CHAIN entry [user=%d] %d failed logins then a success (%d distinct IPs, last %s)",
			b.actorUID, b.fails, b.distinct, safeIP(b.ip))
	}
}

// detectBursts returns every account with a failed-login flood followed by a
// success in the window. A query error is LOGGED, never swallowed, because a
// schema drift that breaks it would make the detector report zero entries on a
// real attack and read as clean.
func detectBursts(db *sql.DB) []loginBurst {
	rows, err := db.Query(`SELECT s.actor_user_id, f.n, f.ip, f.ipn
		FROM (
			SELECT actor_username, COUNT(*) n,
			       SUBSTRING_INDEX(GROUP_CONCAT(ip ORDER BY ts DESC SEPARATOR ','), ',', 1) ip,
			       COUNT(DISTINCT ip) ipn,
			       MIN(ts) first_fail
			FROM audit_log
			WHERE action IN ('auth.login','customer.login') AND ok=0
			  AND ts >= (NOW() - INTERVAL ? MINUTE)
			GROUP BY actor_username HAVING COUNT(*) >= ?
		) f
		JOIN (
			SELECT actor_username, actor_user_id, MAX(ts) last_ok
			FROM audit_log
			WHERE action IN ('auth.login','customer.login') AND ok=1 AND actor_user_id > 0
			  AND ts >= (NOW() - INTERVAL ? MINUTE)
			GROUP BY actor_username, actor_user_id
		) s ON s.actor_username = f.actor_username AND s.last_ok >= f.first_fail`,
		windowMin, entryThreshold, windowMin)
	if err != nil {
		log.Printf("attack chain: the entry detector query failed (it may be reporting no entries on a real attack): %v", err)
		return nil
	}
	defer func() { _ = rows.Close() }()
	var out []loginBurst
	for rows.Next() {
		var b loginBurst
		var ip sql.NullString
		if err := rows.Scan(&b.actorUID, &b.fails, &ip, &b.distinct); err != nil {
			log.Printf("attack chain: an entry detector row could not be read: %v", err)
			continue
		}
		b.ip = ip.String
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		log.Printf("attack chain: the entry detector result set broke: %v", err)
	}
	return out
}

// entrySummary is the operator-facing text. The IP is VALIDATED, because a
// client can inject X-Forwarded-For; an invalid one reads as "unknown".
func entrySummary(b loginBurst) string {
	extra := ""
	if b.distinct > 1 {
		extra = fmt.Sprintf(" +%d more IPs", b.distinct-1)
	}
	return fmt.Sprintf("%d failed logins then a successful panel login (IP %s%s)", b.fails, safeIP(b.ip), extra)
}

func safeIP(s string) string {
	if net.ParseIP(s) == nil {
		return "unknown"
	}
	return s
}

// entryRecent reports whether an entry event for this account was written inside
// the re-dedup window. On a query error it FAILS SAFE by returning true (suppress
// the write): counting zero and writing would open an INSERT flood every tick.
// The error is logged so the guard is never silently measuring nothing.
func entryRecent(db *sql.DB, actorUID int64) bool {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM av_events
		WHERE stage='entry' AND actor_user_id = ? AND created_at >= (NOW() - INTERVAL ? MINUTE)`,
		actorUID, entryRededupMin).Scan(&n); err != nil {
		log.Printf("attack chain: the entry dedup query failed for user %d (fail-safe: suppressed): %v", actorUID, err)
		return true
	}
	return n > 0
}
