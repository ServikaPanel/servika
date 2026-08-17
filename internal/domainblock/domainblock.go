// Package domainblock answers one question: may this hostname be added to this
// server?
//
// Owning the DNS for a name is not what decides whether the panel renders a
// vhost for it. A tenant can ask for login.example-bank.com, receive a
// server_name and a certificate, and then point traffic at it from any resolver
// they control. The banned_domains table is the operator's list of names that
// must not be served here, and this package is the only reader of it.
//
// The answer is consulted on the CREATION paths only. A name added to the list
// later does not take a live site down and does not stop its certificate from
// renewing; removing an existing domain stays a separate, explicit action.
package domainblock

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"time"
)

// cacheTTL is how long a read of the whole table is reused.
//
// The list is consulted on every domain creation and is written by hand a few
// times a year, so re-reading it per request buys nothing. Writes call
// Invalidate, so an operator never waits out this window to see a new ban take
// effect; the window only bounds how long an edit made OUTSIDE the panel (in
// the database directly) goes unnoticed.
const cacheTTL = 60 * time.Second

// Rule is one row of banned_domains.
type Rule struct {
	Domain          string
	Description     string
	MatchSubdomains bool
}

var (
	mu       sync.RWMutex
	cached   []Rule
	cachedAt time.Time
)

// Invalidate drops the cache so the next question re-reads the table. Every
// write path calls it.
func Invalidate() {
	mu.Lock()
	cached, cachedAt = nil, time.Time{}
	mu.Unlock()
}

// Normalize puts a hostname in the form the table stores and compares.
func Normalize(hostname string) string {
	h := strings.ToLower(strings.TrimSpace(hostname))
	return strings.TrimSuffix(h, ".")
}

// Matches reports whether hostname falls under rule, and is the whole matching
// decision.
//
// The subdomain test carries the leading dot so it can only match on a label
// boundary: without it "example-bank.com" would also ban "notexample-bank.com",
// which is a different registration and usually somebody else's.
func Matches(rule Rule, hostname string) bool {
	name := Normalize(rule.Domain)
	if name == "" {
		return false
	}
	if hostname == name {
		return true
	}
	return rule.MatchSubdomains && strings.HasSuffix(hostname, "."+name)
}

// List returns every rule, from the cache when it is fresh.
func List(ctx context.Context, db *sql.DB) ([]Rule, error) {
	mu.RLock()
	if cachedAt.After(time.Now().Add(-cacheTTL)) {
		rules := cached
		mu.RUnlock()
		return rules, nil
	}
	mu.RUnlock()

	rows, err := db.QueryContext(ctx,
		`SELECT domain, description, match_subdomains FROM banned_domains`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var rules []Rule
	for rows.Next() {
		var r Rule
		var match int
		if err := rows.Scan(&r.Domain, &r.Description, &match); err != nil {
			return nil, err
		}
		r.MatchSubdomains = match != 0
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	mu.Lock()
	cached, cachedAt = rules, time.Now()
	mu.Unlock()
	return rules, nil
}

// Blocked reports whether hostname may not be added, and which rule refused it.
//
// It FAILS CLOSED: a table that cannot be read returns the error, and every
// caller turns that into a refusal. The alternative would let a database
// hiccup wave through exactly the name the operator wrote the list to stop,
// and nothing is lost by refusing, because the creation the caller is about to
// perform needs that same database anyway.
func Blocked(ctx context.Context, db *sql.DB, hostname string) (bool, Rule, error) {
	name := Normalize(hostname)
	if name == "" {
		return false, Rule{}, nil
	}
	rules, err := List(ctx, db)
	if err != nil {
		return false, Rule{}, err
	}
	for _, rule := range rules {
		if Matches(rule, name) {
			return true, rule, nil
		}
	}
	return false, Rule{}, nil
}
