package addondomains

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
)

// Creating an addon domain writes a real domains row, takes the per-customer
// lock, applies two ceilings, builds a document root under a tenant home,
// renders a vhost and writes a zone. None of that was reachable in a test, so
// only the source text of the handler was pinned. These tests run the handler
// against a scripted database and the package's own seams.

// addonScript answers queries by matching a fragment of their text.
type addonScript struct {
	mu sync.Mutex
	// rows answers a matching query with one row.
	rows map[string][]driver.Value
	// noRows answers a matching query with no row (sql.ErrNoRows).
	noRows map[string]bool
	// queryErr fails a matching query.
	queryErr map[string]error
	// execErr fails a matching statement.
	execErr  map[string]error
	execs    []string
	execArgs map[string][]driver.Value
}

func (s *addonScript) answer(query string) (driver.Rows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for fragment, err := range s.queryErr {
		if strings.Contains(query, fragment) {
			return nil, err
		}
	}
	for fragment := range s.noRows {
		if strings.Contains(query, fragment) {
			return &addonRows{done: true}, nil
		}
	}
	for fragment, values := range s.rows {
		if strings.Contains(query, fragment) {
			return &addonRows{values: values}, nil
		}
	}
	return nil, fmt.Errorf("the test script has no answer for: %s", query)
}

func (s *addonScript) record(query string, args []driver.NamedValue) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execs = append(s.execs, query)
	if s.execArgs == nil {
		s.execArgs = map[string][]driver.Value{}
	}
	values := make([]driver.Value, 0, len(args))
	for _, a := range args {
		values = append(values, a.Value)
	}
	s.execArgs[query] = values
	for fragment, err := range s.execErr {
		if strings.Contains(query, fragment) {
			return err
		}
	}
	return nil
}

func (s *addonScript) wrote(fragment string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, query := range s.execs {
		if strings.Contains(query, fragment) {
			return true
		}
	}
	return false
}

func (s *addonScript) argsOf(fragment string) []driver.Value {
	s.mu.Lock()
	defer s.mu.Unlock()
	for query, values := range s.execArgs {
		if strings.Contains(query, fragment) {
			return values
		}
	}
	return nil
}

type addonRows struct {
	values []driver.Value
	done   bool
}

func (r *addonRows) Columns() []string { return make([]string, len(r.values)) }
func (r *addonRows) Close() error      { return nil }
func (r *addonRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, r.values)
	return nil
}

type addonConn struct{ script *addonScript }

func (c addonConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c addonConn) Driver() driver.Driver                        { return addonDriver{} }
func (c addonConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c addonConn) Close() error                                 { return nil }
func (c addonConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c addonConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	return c.script.answer(query)
}

func (c addonConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.script.record(query, args); err != nil {
		return nil, err
	}
	return addonResult{}, nil
}

type addonResult struct{}

func (addonResult) LastInsertId() (int64, error) { return 99, nil }
func (addonResult) RowsAffected() (int64, error) { return 1, nil }

type addonDriver struct{}

func (addonDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// The query fragments the handler and its quota gates run.
const (
	qParent    = "AND parent_domain_id IS NULL"
	qLock      = "SELECT customer_id FROM domains WHERE id=?"
	qPlan      = "SELECT plan_id FROM customers"
	qMaxDomain = "SELECT max_domain FROM service_plans"
	qOwner     = "SELECT owner_user_id FROM customers"
	qNameTaken = "SELECT id FROM domains WHERE domain_name=?"
	qFQDNTaken = "SELECT id FROM subdomains WHERE fqdn=?"
	qCreated   = "COALESCE(parked,0)"
)

// happyScript answers every step of a create that goes through: a parent owned
// by customer 5 on no plan and under no reseller, and a free domain name.
func happyScript() *addonScript {
	return &addonScript{
		rows: map[string][]driver.Value{
			qParent:  {int64(1), "parent.example", "c_par", "8.3", "", int64(5), int64(2)},
			qLock:    {int64(5)},
			qPlan:    {nil},
			qOwner:   {nil},
			qCreated: {int64(99), "addon.example", int64(0), "/home/c_par/domains/addon.example", "8.3", int64(0), "2026-01-02 03:04"},
		},
		noRows: map[string]bool{qNameTaken: true, qFQDNTaken: true},
	}
}

// calls records what each seam was asked to do.
type calls struct {
	prepared  []string
	rendered  []int64
	seeded    []int64
	zoned     []int64
	cleaned   []int64
	order     []string
	blocked   bool
	prepErr   error
	renderErr error
	dnsErr    error
}

// standIn replaces every seam that leaves the panel for the length of the test.
func standIn(t *testing.T, c *calls) {
	t.Helper()
	previousBlocked, previousPrepare := refuseIfBlocked, prepareRoot
	previousRender, previousSeed := renderVhost, seedDNS
	previousZone, previousCleanup := writeZone, cleanupAddon
	t.Cleanup(func() {
		refuseIfBlocked, prepareRoot = previousBlocked, previousPrepare
		renderVhost, seedDNS = previousRender, previousSeed
		writeZone, cleanupAddon = previousZone, previousCleanup
	})

	refuseIfBlocked = func(w http.ResponseWriter, _ *http.Request, _ *sql.DB, _ string) bool {
		if c.blocked {
			w.WriteHeader(http.StatusForbidden)
		}
		return c.blocked
	}
	prepareRoot = func(docroot, _, _ string) error {
		c.prepared = append(c.prepared, docroot)
		c.order = append(c.order, "prepare")
		return c.prepErr
	}
	renderVhost = func(_ *sql.DB, id int64) error {
		c.rendered = append(c.rendered, id)
		c.order = append(c.order, "render")
		return c.renderErr
	}
	seedDNS = func(_ context.Context, _ *sql.DB, id int64, _, _ string) (int, error) {
		c.seeded = append(c.seeded, id)
		c.order = append(c.order, "seed")
		return 0, c.dnsErr
	}
	writeZone = func(_ context.Context, _ *sql.DB, id int64) error {
		c.zoned = append(c.zoned, id)
		c.order = append(c.order, "zone")
		return c.dnsErr
	}
	cleanupAddon = func(_ context.Context, _ *sql.DB, id int64) (string, error) {
		c.cleaned = append(c.cleaned, id)
		c.order = append(c.order, "cleanup")
		return "", nil
	}
}

// createAddon runs the handler for parent id 1 with the given body.
func createAddon(t *testing.T, script *addonScript, c *calls, body string) *httptest.ResponseRecorder {
	t.Helper()
	standIn(t, c)
	db := sql.OpenDB(addonConn{script: script})
	t.Cleanup(func() { _ = db.Close() })

	request := httptest.NewRequest(http.MethodPost, "/domains/1/addons", strings.NewReader(body))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", "1")
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeCtx))

	recorder := httptest.NewRecorder()
	(&Handlers{DB: db, IPv4: "203.0.113.9"}).Create(recorder, request)
	return recorder
}

// A parent that is not there, or that cannot be read, stops the create before
// anything else runs.
func TestAnUnusableParentStopsTheCreate(t *testing.T) {
	missing := &addonScript{noRows: map[string]bool{qParent: true}}
	recorder := createAddon(t, missing, &calls{}, `{"domain_name":"addon.example"}`)
	if recorder.Code != http.StatusNotFound {
		t.Errorf("a missing parent answered %d, want 404: %s", recorder.Code, recorder.Body)
	}

	unreadable := &addonScript{queryErr: map[string]error{qParent: errors.New("read failed")}}
	recorder = createAddon(t, unreadable, &calls{}, `{"domain_name":"addon.example"}`)
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("an unreadable parent answered %d, want 500: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "database read failed") {
		t.Errorf("message = %s", recorder.Body)
	}
}

// Every refusal that comes before the lock, in one table. None of them may
// write a row or build a directory.
func TestTheRefusalsBeforeTheLock(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		blocked bool
		status  int
		want    string
	}{
		{name: "not json", body: `{`, status: http.StatusBadRequest, want: "invalid request body"},
		{name: "no name", body: `{"domain_name":""}`, status: http.StatusBadRequest, want: "invalid domain name"},
		{name: "not a domain", body: `{"domain_name":"not a domain"}`, status: http.StatusBadRequest, want: "invalid domain name"},
		{name: "blocked", body: `{"domain_name":"addon.example"}`, blocked: true, status: http.StatusForbidden},
		{name: "the parent itself", body: `{"domain_name":"PARENT.example"}`, status: http.StatusConflict, want: "addon domain cannot match the parent domain"},
	} {
		script := happyScript()
		c := &calls{blocked: tc.blocked}

		recorder := createAddon(t, script, c, tc.body)

		if recorder.Code != tc.status {
			t.Errorf("%s: status = %d, want %d: %s", tc.name, recorder.Code, tc.status, recorder.Body)
		}
		if tc.want != "" && !strings.Contains(recorder.Body.String(), tc.want) {
			t.Errorf("%s: message = %s, want %q", tc.name, recorder.Body, tc.want)
		}
		if script.wrote("INSERT INTO domains") || len(c.prepared) > 0 {
			t.Errorf("%s: the refusal still wrote a row or built a document root", tc.name)
		}
	}
}

// Both ceilings refuse with their own message, and neither an unreadable
// ceiling nor an unreadable reseller is treated as room.
func TestBothCeilingsRefuseAndFailClosed(t *testing.T) {
	atPlanLimit := happyScript()
	atPlanLimit.rows[qPlan] = []driver.Value{int64(2)}
	atPlanLimit.rows[qMaxDomain] = []driver.Value{int64(1)}
	atPlanLimit.rows["COUNT(*) FROM domains WHERE customer_id=?"] = []driver.Value{int64(1)}
	recorder := createAddon(t, atPlanLimit, &calls{}, `{"domain_name":"addon.example"}`)
	if recorder.Code != http.StatusForbidden {
		t.Errorf("the plan ceiling answered %d, want 403: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "plan limit exceeded: maximum 1 domains") {
		t.Errorf("message = %s", recorder.Body)
	}

	atResellerLimit := happyScript()
	atResellerLimit.rows[qOwner] = []driver.Value{int64(8)}
	atResellerLimit.rows["FROM reseller_limits"] = []driver.Value{int64(3)}
	atResellerLimit.rows["JOIN customers c ON c.id = d.customer_id"] = []driver.Value{int64(3)}
	recorder = createAddon(t, atResellerLimit, &calls{}, `{"domain_name":"addon.example"}`)
	if recorder.Code != http.StatusForbidden {
		t.Errorf("the reseller ceiling answered %d, want 403: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "reseller limit reached: at most 3 domains") {
		t.Errorf("message = %s", recorder.Body)
	}

	unreadablePlan := happyScript()
	unreadablePlan.queryErr = map[string]error{qPlan: errors.New("read failed")}
	recorder = createAddon(t, unreadablePlan, &calls{}, `{"domain_name":"addon.example"}`)
	if recorder.Code != http.StatusInternalServerError ||
		!strings.Contains(recorder.Body.String(), "could not verify plan limit") {
		t.Errorf("an unreadable plan answered %d: %s", recorder.Code, recorder.Body)
	}

	unreadableOwner := happyScript()
	unreadableOwner.queryErr = map[string]error{qOwner: errors.New("read failed")}
	recorder = createAddon(t, unreadableOwner, &calls{}, `{"domain_name":"addon.example"}`)
	if recorder.Code != http.StatusInternalServerError ||
		!strings.Contains(recorder.Body.String(), "could not verify reseller limit") {
		t.Errorf("an unreadable reseller answered %d: %s", recorder.Code, recorder.Body)
	}
}

// A name already registered, as a domain or as a subdomain, is refused with its
// own message. A lookup that fails is not proof the name is free.
func TestANameThatIsAlreadyRegisteredIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(*addonScript)
		status   int
		contains string
	}{
		{
			name:     "a domain",
			mutate:   func(s *addonScript) { delete(s.noRows, qNameTaken); s.rows[qNameTaken] = []driver.Value{int64(4)} },
			status:   http.StatusConflict,
			contains: "this domain name is already registered",
		},
		{
			name:     "a subdomain",
			mutate:   func(s *addonScript) { delete(s.noRows, qFQDNTaken); s.rows[qFQDNTaken] = []driver.Value{int64(4)} },
			status:   http.StatusConflict,
			contains: "already registered as a subdomain",
		},
		{
			name:     "an unreadable domain lookup",
			mutate:   func(s *addonScript) { s.queryErr = map[string]error{qNameTaken: errors.New("read failed")} },
			status:   http.StatusInternalServerError,
			contains: "database read failed",
		},
		{
			name:     "an unreadable subdomain lookup",
			mutate:   func(s *addonScript) { s.queryErr = map[string]error{qFQDNTaken: errors.New("read failed")} },
			status:   http.StatusInternalServerError,
			contains: "database read failed",
		},
	} {
		script := happyScript()
		tc.mutate(script)
		c := &calls{}

		recorder := createAddon(t, script, c, `{"domain_name":"addon.example"}`)

		if recorder.Code != tc.status {
			t.Errorf("%s: status = %d, want %d: %s", tc.name, recorder.Code, tc.status, recorder.Body)
		}
		if !strings.Contains(recorder.Body.String(), tc.contains) {
			t.Errorf("%s: message = %s", tc.name, recorder.Body)
		}
		if script.wrote("INSERT INTO domains") || len(c.prepared) > 0 {
			t.Errorf("%s: the refusal still wrote a row or built a document root", tc.name)
		}
	}
}

// A parked addon domain serves the parent's own document root and builds
// nothing. An unparked one gets its own directory under the tenant home.
func TestAParkedAddonBuildsNoDocumentRoot(t *testing.T) {
	parked := happyScript()
	c := &calls{}

	recorder := createAddon(t, parked, c, `{"domain_name":"addon.example","parked":true}`)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", recorder.Code, recorder.Body)
	}
	if len(c.prepared) != 0 {
		t.Errorf("a parked addon built %v", c.prepared)
	}
	args := parked.argsOf("INSERT INTO domains")
	if len(args) != 11 {
		t.Fatalf("insert arguments = %v", args)
	}
	if args[6] != "/home/c_par/public_html" {
		t.Errorf("document root = %v, want the parent's", args[6])
	}
	if args[10] != int64(1) {
		t.Errorf("parked = %v, want 1", args[10])
	}
}

// The unparked path builds the addon's own document root before the row is
// written, and the row carries it.
func TestAnUnparkedAddonGetsItsOwnDocumentRoot(t *testing.T) {
	script := happyScript()
	c := &calls{}

	recorder := createAddon(t, script, c, `{"domain_name":"Addon.Example"}`)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", recorder.Code, recorder.Body)
	}
	if len(c.prepared) != 1 || c.prepared[0] != "/home/c_par/domains/addon.example" {
		t.Fatalf("prepared %v", c.prepared)
	}
	args := script.argsOf("INSERT INTO domains")
	if len(args) != 11 {
		t.Fatalf("insert arguments = %v", args)
	}
	for i, want := range []driver.Value{
		"addon.example", "c_par", "8.3", "203.0.113.9", "203.0.113.9", "c_par",
		"/home/c_par/domains/addon.example", int64(5), int64(2), int64(1), int64(0),
	} {
		if args[i] != want {
			t.Errorf("insert argument %d = %v, want %v", i, args[i], want)
		}
	}
	if c.order[0] != "prepare" {
		t.Errorf("order = %v, want the document root first", c.order)
	}
}

// A document root that cannot be built stops the create, because a row with no
// directory renders a vhost that serves nothing.
func TestAFailedDocumentRootStopsTheCreate(t *testing.T) {
	script := happyScript()
	c := &calls{prepErr: errors.New("mkdir failed")}

	recorder := createAddon(t, script, c, `{"domain_name":"addon.example"}`)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "document root creation failed") {
		t.Errorf("message = %s", recorder.Body)
	}
	if script.wrote("INSERT INTO domains") {
		t.Fatal("a row was written although the document root was not built")
	}
}

// A row that cannot be written is reported, and nothing downstream runs.
func TestAFailedInsertStopsTheCreate(t *testing.T) {
	script := happyScript()
	script.execErr = map[string]error{"INSERT INTO domains": errors.New("write failed")}
	c := &calls{}

	recorder := createAddon(t, script, c, `{"domain_name":"addon.example"}`)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "addon domain record creation failed") {
		t.Errorf("message = %s", recorder.Body)
	}
	if len(c.rendered) != 0 {
		t.Error("the vhost was rendered for a row that was not written")
	}
}

// A vhost that fails to render takes the row back out, or the panel keeps an
// addon domain nginx never learned about.
func TestAFailedVhostTakesTheRowBackOut(t *testing.T) {
	script := happyScript()
	c := &calls{renderErr: errors.New("nginx refused")}

	recorder := createAddon(t, script, c, `{"domain_name":"addon.example"}`)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "virtual host update failed") {
		t.Errorf("message = %s", recorder.Body)
	}
	if len(c.cleaned) != 1 || c.cleaned[0] != 99 {
		t.Errorf("cleaned up %v, want the new row", c.cleaned)
	}
	if len(c.seeded) != 0 || len(c.zoned) != 0 {
		t.Error("DNS was written for an addon domain that was taken back out")
	}
}

// DNS is written after the row and the vhost, and a DNS failure is logged
// rather than answered: the addon domain is already serving.
func TestAFailedZoneStillReturnsTheAddonDomain(t *testing.T) {
	script := happyScript()
	c := &calls{dnsErr: errors.New("named refused")}

	recorder := createAddon(t, script, c, `{"domain_name":"addon.example"}`)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", recorder.Code, recorder.Body)
	}
	if len(c.cleaned) != 0 {
		t.Error("a DNS failure took the addon domain back out")
	}
}

// The order of the whole create, and the answer it returns.
func TestAnAcceptedCreateRunsInOrderAndReturnsTheRow(t *testing.T) {
	script := happyScript()
	c := &calls{}

	recorder := createAddon(t, script, c, `{"domain_name":"addon.example"}`)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", recorder.Code, recorder.Body)
	}
	if got := strings.Join(c.order, ","); got != "prepare,render,seed,zone" {
		t.Errorf("order = %s", got)
	}
	body := recorder.Body.String()
	for _, want := range []string{`"id":99`, `"domain_name":"addon.example"`, `"parked":false`, `"php_version":"8.3"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the answer does not carry %s: %s", want, body)
		}
	}
}
