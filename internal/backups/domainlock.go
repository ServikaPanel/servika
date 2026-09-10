package backups

import (
	"errors"
	"sync"
)

// One domain's home directory and its schemas are the resources every backup and
// every restore mutates, and nothing serialized them.
//
// The two HTTP handlers guarded themselves with progressActive/progressStart,
// which is a UI record rather than a lock: it is a check followed by a separate
// write, so two callers can both find it free, and the bulk-job and scheduler
// paths never set it at all. A bulk restore could therefore run while the
// customer's own backup was tarring the same tree, while the single-domain
// restore endpoint rewrote it, or while a second bulk restore of the same domain
// did the same. Two rsync passes (with --delete on a clean restore) and two SQL
// imports into one schema leave the document root and the database in an
// undefined mixed state, and a backup taken during a restore captures a
// half-rewritten tree while being recorded as a normal, checksum-verified
// archive: the recovery point the customer would fall back to is itself corrupt.
// Both operations report success.
//
// This is the lock. It is taken at the chokepoints every producer goes through,
// so a path added later is covered by construction rather than by remembering.
var domainOperations sync.Map // domainID (int64) -> struct{}

// ErrDomainBusy means another backup or restore holds the domain.
var ErrDomainBusy = errors.New("an operation is already running for this domain")

// lockDomain claims a domain for one mutating operation.
//
// The claim is atomic: LoadOrStore decides and stores in one step, so two
// callers arriving together cannot both win. release is safe to call once,
// through defer, and is nil when the claim failed.
func lockDomain(domainID int64) (release func(), ok bool) {
	if _, loaded := domainOperations.LoadOrStore(domainID, struct{}{}); loaded {
		return nil, false
	}
	var once sync.Once
	return func() { once.Do(func() { domainOperations.Delete(domainID) }) }, true
}

// domainLocked reports whether an operation holds the domain. It answers the
// HTTP handlers' early 409 and is NOT a substitute for lockDomain: between this
// answer and a later claim, another caller can take it.
func domainLocked(domainID int64) bool {
	_, held := domainOperations.Load(domainID)
	return held
}
