package quota

import (
	"context"
	"database/sql/driver"
	"testing"
	"time"
)

func lockScript(customer int64) *script {
	return &script{
		rows: map[string][]driver.Value{"customer_id FROM domains": {customer}},
		fail: map[string]error{},
	}
}

// Every quota gate is a COUNT followed by a separate INSERT, and the unique keys
// on the tables involved constrain identity rather than the per-customer count.
// Without serialization, N concurrent creates all read the same total and all
// insert, so a plan allowing M resources yields N.
func TestTheCustomerLockSerializesTwoCreatesForOneCustomer(t *testing.T) {
	db := scriptedDB(t, lockScript(7))

	unlock := LockCustomerForDomain(context.Background(), db, 1)
	second := make(chan struct{})
	go func() {
		release := LockCustomerForDomain(context.Background(), db, 1)
		close(second)
		release()
	}()

	select {
	case <-second:
		t.Fatal("a second create for the same customer ran while the first held the lock")
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	select {
	case <-second:
	case <-time.After(5 * time.Second):
		t.Fatal("the second create never acquired the lock after it was released")
	}
}

// The lock is per CUSTOMER, so one busy customer must not serialize the whole
// panel. A global lock would pass the test above and fail this one.
func TestTheCustomerLockDoesNotBlockAnotherCustomer(t *testing.T) {
	first := scriptedDB(t, lockScript(7))
	other := scriptedDB(t, lockScript(8))

	unlock := LockCustomerForDomain(context.Background(), first, 1)
	defer unlock()

	done := make(chan struct{})
	go func() {
		release := LockCustomerForDomain(context.Background(), other, 2)
		close(done)
		release()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a create for a different customer was blocked by the first customer's lock")
	}
}

// A domain with no customer belongs to an administrator, who has no plan to be
// limited by, so there is nothing to serialize and the caller must not deadlock
// waiting for a lock nobody will release.
func TestADomainWithNoCustomerTakesNoLock(t *testing.T) {
	s := lockScript(0)
	s.rows["customer_id FROM domains"] = []driver.Value{nil}
	db := scriptedDB(t, s)

	unlock := LockCustomerForDomain(context.Background(), db, 1)
	defer unlock()

	done := make(chan struct{})
	go func() {
		release := LockCustomerForDomain(context.Background(), db, 1)
		close(done)
		release()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("an administrator-owned domain blocked a second caller")
	}
}
