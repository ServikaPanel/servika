package domains

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

// A recording driver, as used elsewhere in this package: the repository carries
// no sqlmock dependency, and what matters is which row the handler looked for.
type refRecorder struct {
	mu sync.Mutex
	// present decides which ids the database claims to hold.
	customerExists bool
	planExists     bool
	// ownerRole and ownerStatus describe the users row the owner id points at.
	// An empty ownerRole means no such user.
	//
	// They are modelled as a ROW rather than as a "does the lookup succeed"
	// boolean so the query text decides the answer. A test that answered
	// regardless of the conditions would keep passing if `role='reseller'` or
	// `status='active'` were dropped from the SQL, which is exactly the mistake
	// it is there to catch.
	ownerRole   string
	ownerStatus string
	// nameHeldBy names the query fragment whose table already carries the name
	// under test. Empty means the name is free everywhere.
	nameHeldBy string
	// failOn makes the matching lookup return a driver error instead of rows.
	failOn     string
	statements []string
}

func (r *refRecorder) saw(fragment string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, statement := range r.statements {
		if strings.Contains(statement, fragment) {
			return true
		}
	}
	return false
}

var (
	refStateMu sync.Mutex
	refState   = map[string]*refRecorder{}
)

type refDriver struct{}

func (refDriver) Open(name string) (driver.Conn, error) {
	refStateMu.Lock()
	defer refStateMu.Unlock()
	rec, ok := refState[name]
	if !ok {
		return nil, fmt.Errorf("no recorder registered for %q", name)
	}
	return &refConn{rec: rec}, nil
}

func init() { sql.Register("domains_ref_recorder", refDriver{}) }

type refConn struct{ rec *refRecorder }

func (c *refConn) Prepare(string) (driver.Stmt, error) {
	return nil, fmt.Errorf("prepare is not used by this test")
}
func (c *refConn) Close() error { return nil }
func (c *refConn) Begin() (driver.Tx, error) {
	return nil, fmt.Errorf("transactions are not used here")
}

var errRefLookup = errors.New("the database is unavailable")

func (c *refConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.rec.mu.Lock()
	c.rec.statements = append(c.rec.statements, query)
	failOn := c.rec.failOn
	customer, plan := c.rec.customerExists, c.rec.planExists
	ownerRole, ownerStatus := c.rec.ownerRole, c.rec.ownerStatus
	nameHeldBy := c.rec.nameHeldBy
	c.rec.mu.Unlock()

	if failOn != "" && strings.Contains(query, failOn) {
		return nil, errRefLookup
	}
	if nameHeldBy != "" && strings.Contains(query, nameHeldBy) {
		return &idRow{found: true}, nil
	}
	switch {
	case strings.Contains(query, "FROM customers WHERE id=?"):
		return &idRow{found: customer}, nil
	case strings.Contains(query, "FROM service_plans WHERE id=?"):
		return &idRow{found: plan}, nil
	case strings.Contains(query, "FROM users WHERE id=?"):
		return &idRow{found: ownerRowMatches(query, ownerRole, ownerStatus)}, nil
	}
	return &idRow{}, nil
}

// ownerRowMatches applies the query's own conditions to the row the recorder
// holds, so dropping a condition from the SQL changes what the test sees.
func ownerRowMatches(query, role, status string) bool {
	if role == "" {
		return false // no such user
	}
	if strings.Contains(query, "role='reseller'") && role != "reseller" {
		return false
	}
	if strings.Contains(query, "status='active'") && status != "active" {
		return false
	}
	return true
}

type idRow struct {
	found bool
	done  bool
}

func (r *idRow) Columns() []string { return []string{"id"} }
func (r *idRow) Close() error      { return nil }
func (r *idRow) Next(dest []driver.Value) error {
	if !r.found || r.done {
		return io.EOF
	}
	dest[0] = int64(7)
	r.done = true
	return nil
}

func refHarness(t *testing.T, rec *refRecorder) *Handlers {
	t.Helper()
	name := t.Name()
	refStateMu.Lock()
	refState[name] = rec
	refStateMu.Unlock()
	t.Cleanup(func() {
		refStateMu.Lock()
		delete(refState, name)
		refStateMu.Unlock()
	})

	db, err := sql.Open("domains_ref_recorder", name)
	if err != nil {
		t.Fatalf("open the recording database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Handlers{DB: db}
}

func id(v int64) *int64 { return new(v) }

// domains.customer_id has no foreign key, so an id matching nothing is written
// verbatim and the domain hangs off a customer ScopeSQL can never find: an
// administrator still sees it while the reseller and the customer it was meant
// for never do.
func TestACustomerThatDoesNotExistIsRefused(t *testing.T) {
	handlers := refHarness(t, &refRecorder{customerExists: false, planExists: true})
	reason, err := handlers.referencedAccountsExist(context.Background(), id(42), id(1), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reason != reasonCustomerNotFound {
		t.Errorf("reason = %q, want %q", reason, reasonCustomerNotFound)
	}
}

func TestAPlanThatDoesNotExistIsRefused(t *testing.T) {
	handlers := refHarness(t, &refRecorder{customerExists: true, planExists: false})
	reason, err := handlers.referencedAccountsExist(context.Background(), id(42), id(99), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reason != reasonPlanNotFound {
		t.Errorf("reason = %q, want %q", reason, reasonPlanNotFound)
	}
}

func TestRealIdsAreAccepted(t *testing.T) {
	handlers := refHarness(t, &refRecorder{customerExists: true, planExists: true})
	reason, err := handlers.referencedAccountsExist(context.Background(), id(42), id(1), nil)
	if err != nil || reason != "" {
		t.Errorf("reason = %q, err = %v, want both empty", reason, err)
	}
}

// Omitting either id is how a domain is created unattached, which is the
// default. Looking rows up anyway would refuse the ordinary case.
func TestOmittedIdsAreNotLookedUp(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		customerID, planID   *int64
		wantCustomerLookedUp bool
		wantPlanLookedUp     bool
	}{
		{name: "neither given"},
		{name: "zero is treated as absent", customerID: id(0), planID: id(0)},
		{name: "only a plan", planID: id(1), wantPlanLookedUp: true},
		{name: "only a customer", customerID: id(42), wantCustomerLookedUp: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &refRecorder{customerExists: true, planExists: true}
			handlers := refHarness(t, recorder)
			reason, err := handlers.referencedAccountsExist(context.Background(), tc.customerID, tc.planID, nil)
			if err != nil || reason != "" {
				t.Fatalf("reason = %q, err = %v, want both empty", reason, err)
			}
			if got := recorder.saw("FROM customers WHERE id=?"); got != tc.wantCustomerLookedUp {
				t.Errorf("customer looked up = %v, want %v", got, tc.wantCustomerLookedUp)
			}
			if got := recorder.saw("FROM service_plans WHERE id=?"); got != tc.wantPlanLookedUp {
				t.Errorf("plan looked up = %v, want %v", got, tc.wantPlanLookedUp)
			}
		})
	}
}

// A lookup that FAILED is not evidence the row is missing. Reporting it as
// "not found" would turn a database hiccup into a refusal the caller cannot
// tell apart from a genuinely wrong id, and reporting it as success would
// provision against an id nobody checked.
func TestAFailedLookupIsAnErrorAndNotAVerdict(t *testing.T) {
	for _, failOn := range []string{"FROM customers WHERE id=?", "FROM service_plans WHERE id=?"} {
		t.Run(failOn, func(t *testing.T) {
			handlers := refHarness(t, &refRecorder{customerExists: true, planExists: true, failOn: failOn})
			reason, err := handlers.referencedAccountsExist(context.Background(), id(42), id(1), nil)
			if err == nil {
				t.Fatalf("a failed lookup returned reason %q and no error", reason)
			}
			if reason != "" {
				t.Errorf("reason = %q, want empty so the caller cannot mistake it for a verdict", reason)
			}
		})
	}
}

// customers.owner_user_id is one half of the ownership chain. Only an active
// reseller belongs there: an administrator or a customer would build a chain no
// role resolves, and a suspended reseller is one an operator deliberately took
// out of service, so handing it a fresh domain would quietly put it back to
// work.
func TestOnlyAnActiveResellerMayOwnANewCustomer(t *testing.T) {
	for _, tc := range []struct {
		name       string
		role       string
		status     string
		wantReason string
	}{
		{name: "no such user", wantReason: reasonOwnerNotReseller},
		{name: "an administrator", role: "admin", status: "active", wantReason: reasonOwnerNotReseller},
		{name: "a customer", role: "user", status: "active", wantReason: reasonOwnerNotReseller},
		{name: "a suspended reseller", role: "reseller", status: "suspended", wantReason: reasonOwnerNotReseller},
		{name: "an active reseller", role: "reseller", status: "active"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handlers := refHarness(t, &refRecorder{
				planExists:  true,
				ownerRole:   tc.role,
				ownerStatus: tc.status,
			})
			reason, err := handlers.referencedAccountsExist(context.Background(), nil, id(1), id(9))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}

// The two fields express different intents: "attach to this existing customer"
// and "open a new customer under this reseller". An existing customer already
// has an owner, and moving it is a transfer with its own endpoint, so honouring
// one and dropping the other would report a placement that never happened.
func TestAnOwnerAndACustomerTogetherAreRefused(t *testing.T) {
	recorder := &refRecorder{customerExists: true, planExists: true, ownerRole: "reseller", ownerStatus: "active"}
	handlers := refHarness(t, recorder)
	reason, err := handlers.referencedAccountsExist(context.Background(), id(42), id(1), id(9))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reason != reasonOwnerWithCustomer {
		t.Errorf("reason = %q, want %q", reason, reasonOwnerWithCustomer)
	}
	if recorder.saw("FROM users WHERE id=?") {
		t.Error("the owner was looked up for a request that was refused on its shape alone")
	}
}

// No owner is the ordinary case: every create before this field existed, and
// every one the interface sends unless an administrator picks a reseller.
func TestAnOmittedOwnerIsNotLookedUp(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ownerID *int64
	}{
		{name: "omitted"},
		{name: "zero is treated as absent", ownerID: id(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &refRecorder{customerExists: true, planExists: true}
			handlers := refHarness(t, recorder)
			reason, err := handlers.referencedAccountsExist(context.Background(), id(42), id(1), tc.ownerID)
			if err != nil || reason != "" {
				t.Fatalf("reason = %q, err = %v, want both empty", reason, err)
			}
			if recorder.saw("FROM users WHERE id=?") {
				t.Error("an owner nobody asked for was looked up")
			}
		})
	}
}

// Same rule as the other two lookups: a failed query is not evidence the
// reseller is wrong, and answering "not a reseller" would turn a database
// hiccup into a refusal the caller cannot tell apart from a genuinely bad id.
func TestAFailedOwnerLookupIsAnErrorAndNotAVerdict(t *testing.T) {
	handlers := refHarness(t, &refRecorder{
		planExists:  true,
		ownerRole:   "reseller",
		ownerStatus: "active",
		failOn:      "FROM users WHERE id=?",
	})
	reason, err := handlers.referencedAccountsExist(context.Background(), nil, id(1), id(9))
	if err == nil {
		t.Fatalf("a failed lookup returned reason %q and no error", reason)
	}
	if reason != "" {
		t.Errorf("reason = %q, want empty so the caller cannot mistake it for a verdict", reason)
	}
}

// nginx answers two server blocks carrying the same server_name with whichever
// it loaded first, so a name that is already serving as somebody's subdomain
// cannot be handed out again as a domain. The subdomain side has always checked
// both tables; this side checked only its own.
func TestANameAlreadyServedIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name       string
		holder     string
		wantTaken  bool
		wantLookup string
	}{
		{name: "free", wantLookup: "FROM subdomains WHERE fqdn=?"},
		{name: "held by a domain", holder: "FROM domains WHERE domain_name=?", wantTaken: true},
		{name: "held by a subdomain", holder: "FROM subdomains WHERE fqdn=?", wantTaken: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &refRecorder{nameHeldBy: tc.holder}
			handlers := refHarness(t, recorder)
			taken, err := handlers.nameAlreadyServed(context.Background(), "blog.example.com")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if taken != tc.wantTaken {
				t.Errorf("taken = %v, want %v", taken, tc.wantTaken)
			}
			// A free name must have been looked for in BOTH tables. Stopping after
			// the first is what let the second one through.
			if tc.wantLookup != "" && !recorder.saw(tc.wantLookup) {
				t.Errorf("%s was never queried", tc.wantLookup)
			}
		})
	}
}

// A lookup that failed says nothing about whether the name is free, and
// answering "free" turns a database hiccup into a duplicate server block.
func TestAFailedNameLookupIsAnErrorAndNotAVerdict(t *testing.T) {
	for _, failOn := range []string{"FROM domains WHERE domain_name=?", "FROM subdomains WHERE fqdn=?"} {
		t.Run(failOn, func(t *testing.T) {
			handlers := refHarness(t, &refRecorder{failOn: failOn})
			taken, err := handlers.nameAlreadyServed(context.Background(), "blog.example.com")
			if err == nil {
				t.Fatalf("a failed lookup reported taken=%v and no error", taken)
			}
			if taken {
				t.Error("taken = true, want false so the caller cannot mistake it for a verdict")
			}
		})
	}
}
