package provisioner

import "sync"

// nginxMu serialises every sequence that writes nginx configuration, validates
// it and reloads it.
//
// The thing protected is the HOST, not a handler instance. `nginx -t` validates
// the whole /etc/nginx/conf.d tree, and the http-context files the render writes
// are server-global, so two sequences at once break each other in both
// directions. One observes the other's half-written vhost, fails, and rolls back
// its OWN valid change while reporting `nginx -t failed` to its operator. The
// other captured the shared files before the first sequence committed, and its
// rollback then reverts that committed country-block and rate-limit
// configuration with nothing saying so.
//
// The rollback design rests on the captured content still being the correct
// previous content at the moment the rollback runs, which is true only while no
// other sequence is in flight. This is what makes that true.
//
// Two operators are not needed to reach it: internal/domains'
// maintenance scheduler re-renders a vhost from a background timer.
var nginxMu sync.Mutex

// LockNginx and UnlockNginx let an nginx writer OUTSIDE this package take the
// same lock. They are exported rather than shared through a third package for
// the reason internal/panelport gives for its own pair: the callers are few and
// a package whose only content is a mutex explains less than this comment does.
//
// Every request-driven writer takes it. A startup heal does not, because it runs
// before the server listens and so races nothing.
func LockNginx() { nginxMu.Lock() }

// UnlockNginx releases the lock LockNginx took.
func UnlockNginx() { nginxMu.Unlock() }
