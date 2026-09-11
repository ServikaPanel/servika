package domains

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"servika/internal/auth"
	"servika/internal/httpx"
	"servika/internal/provisioner"
	"servika/internal/quota"
	"servika/internal/tenantaccount"
)

// hostCalls records the calls a handler made through the package seams, in
// order.
type hostCalls struct {
	mu    sync.Mutex
	steps []string
}

func (c *hostCalls) record(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.steps = append(c.steps, fmt.Sprintf(format, args...))
}

func (c *hostCalls) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.steps...)
}

// assertSteps fails the test unless the recorded calls are exactly want.
func assertSteps(t *testing.T, calls *hostCalls, want ...string) {
	t.Helper()
	if got := calls.all(); !reflect.DeepEqual(got, want) {
		t.Errorf("host calls =\n%q\nwant\n%q", got, want)
	}
}

// idText renders an optional id for a recorded step.
func idText(id *int64) string {
	if id == nil {
		return "nil"
	}
	return strconv.FormatInt(*id, 10)
}

// waitForID receives the id a background step reported, and fails the test
// when it does not arrive.
func waitForID(t *testing.T, ids <-chan int64, want int64) {
	t.Helper()
	select {
	case got := <-ids:
		if got != want {
			t.Fatalf("the background step ran for domain %d, want %d", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the background step never ran")
	}
}

// assertExecArgs fails the test unless the statements holding fragment ran with
// exactly the argument lists in want, in order.
func assertExecArgs(t *testing.T, s *sqlScript, fragment string, want ...[]driver.Value) {
	t.Helper()
	var got [][]driver.Value
	for _, statement := range s.execsContaining(fragment) {
		got = append(got, statement.args)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("statements holding %q ran with\n%v\nwant\n%v", fragment, got, want)
	}
}

const exampleIPv4 = "203.0.113.10"

// createFakes stands in for everything Create reaches outside its database.
type createFakes struct {
	hostCalls
	blocked      bool
	owns         bool
	domainErr    error
	diskErr      error
	trafficErr   error
	planErr      error
	provisionErr error
	account      tenantaccount.Result
	accountErr   error
	socketErr    error
	ftpErr       error
	seedErr      error
	zoneErr      error
	limitsErr    error
	nameservers  bool
	limits       chan int64
	ftpPassword  string
	dbPassword   string
}

func newCreateFakes(t *testing.T) *createFakes {
	t.Helper()
	f := &createFakes{account: tenantaccount.Result{CustomerID: 5}, limits: make(chan int64, 1)}
	setForTest(t, &refuseIfBlocked, f.refuse)
	setForTest(t, &resellerOwnsCustomer, f.ownsCustomer)
	setForTest(t, &checkResellerDomainAllowed, f.resellerDomains)
	setForTest(t, &checkResellerDiskAllowed, f.resellerDisk)
	setForTest(t, &checkResellerTrafficAllowed, f.resellerTraffic)
	setForTest(t, &checkDomainAllowed, f.planGate)
	setForTest(t, &provisionTenant, f.provision)
	setForTest(t, &deprovisionTenant, f.deprovision)
	setForTest(t, &ensureTenantAccount, f.ensure)
	setForTest(t, &phpSocketFor, f.socket)
	setForTest(t, &applyVhostForDomain, f.vhost)
	setForTest(t, &createFTPAccount, f.ftp)
	setForTest(t, &mysqlCreateDB, f.mysql)
	setForTest(t, &seedDNSDefaults, f.seed)
	setForTest(t, &writeDNSZone, f.zone)
	setForTest(t, &applyResourceLimits, f.resourceLimits)
	setForTest(t, &nameserversConfigured, f.configured)
	setForTest(t, &readNameserverPair, f.pair)
	return f
}

func (f *createFakes) refuse(w http.ResponseWriter, _ *http.Request, _ *sql.DB, hostname string) bool {
	f.record("blocked? %s", hostname)
	if f.blocked {
		httpx.WriteError(w, http.StatusForbidden, "blocked")
	}
	return f.blocked
}

func (f *createFakes) ownsCustomer(_ *http.Request, reseller, customer int64) bool {
	f.record("owns %d %d", reseller, customer)
	return f.owns
}

func (f *createFakes) resellerDomains(_ context.Context, _ *sql.DB, reseller int64) error {
	f.record("reseller domains %d", reseller)
	return f.domainErr
}

func (f *createFakes) resellerDisk(_ context.Context, _ *sql.DB, reseller int64) error {
	f.record("reseller disk %d", reseller)
	return f.diskErr
}

func (f *createFakes) resellerTraffic(_ context.Context, _ *sql.DB, reseller int64) error {
	f.record("reseller traffic %d", reseller)
	return f.trafficErr
}

func (f *createFakes) planGate(_ context.Context, _ *sql.DB, customer *int64) error {
	f.record("plan gate %s", idText(customer))
	return f.planErr
}

func (f *createFakes) provision(name, php string) (*provisioner.Result, error) {
	f.record("provision %s %s", name, php)
	if f.provisionErr != nil {
		return nil, f.provisionErr
	}
	return &provisioner.Result{SystemUser: "c_example", WebRoot: "/home/c_example/public_html"}, nil
}

func (f *createFakes) deprovision(name, systemUser string) error {
	f.record("deprovision %s %s", name, systemUser)
	return nil
}

func (f *createFakes) ensure(_ context.Context, _ *sql.DB, systemUser, name string, owner *int64) (tenantaccount.Result, error) {
	f.record("account %s %s %s", systemUser, name, idText(owner))
	return f.account, f.accountErr
}

func (f *createFakes) socket(systemUser, php string) (string, error) {
	f.record("socket %s %s", systemUser, php)
	return "/run/php-fpm/" + systemUser + ".sock", f.socketErr
}

func (f *createFakes) vhost(_ *sql.DB, id int64, socket, php string) error {
	f.record("vhost %d %s %s", id, socket, php)
	return nil
}

func (f *createFakes) ftp(_ *sql.DB, id int64, systemUser, password string, uid, gid int) error {
	f.record("ftp %d %s %d %d", id, systemUser, uid, gid)
	f.ftpPassword = password
	return f.ftpErr
}

func (f *createFakes) mysql(_ *sql.DB, id int64, name, user, password string) error {
	f.record("mysql %d %s %s", id, name, user)
	f.dbPassword = password
	return nil
}

func (f *createFakes) seed(_ context.Context, _ *sql.DB, id int64, name, ipv4 string) (int, error) {
	f.record("dns seed %d %s %s", id, name, ipv4)
	return 0, f.seedErr
}

func (f *createFakes) zone(_ context.Context, _ *sql.DB, id int64) error {
	f.record("zone %d", id)
	return f.zoneErr
}

// resourceLimits runs on the handler's background goroutine, so it reports on a
// channel rather than in the ordered steps.
func (f *createFakes) resourceLimits(_ context.Context, _ *sql.DB, id int64) error {
	f.limits <- id
	return f.limitsErr
}

func (f *createFakes) configured(context.Context, *sql.DB) bool {
	f.record("nameservers?")
	return f.nameservers
}

func (f *createFakes) pair(_ context.Context, _ *sql.DB, id int64, name string) (string, string) {
	f.record("pair %d %s", id, name)
	return "ns1.host.example", "ns2.host.example"
}

// createScript answers the reads every create makes when nothing is wrong: no
// default plan, a free name, and a domain row that is not found on read-back.
func createScript() *sqlScript {
	s := newScript()
	s.insertID = 42
	s.rows["WHERE is_default=1"] = nil
	s.rows["SELECT id FROM domains WHERE domain_name=?"] = nil
	s.rows["SELECT id FROM subdomains WHERE fqdn=?"] = nil
	s.rows["LEFT JOIN service_plans p ON p.id=d.plan_id"] = nil
	return s
}

// domainRow is the read-back of one domain in selectAll's column order.
func domainRow(id int64, name, systemUser string) [][]driver.Value {
	return [][]driver.Value{{
		id, name, systemUser, "8.3", int64(0), "", "active", exampleIPv4, exampleIPv4, systemUser,
		"localhost", systemUser + "_db", systemUser + "_main", "/home/" + systemUser + "/public_html",
		int64(0), int64(0), "", "2026-09-12", nil, "", int64(0), int64(0), "", "php", "", "", int64(0),
	}}
}

type createCase struct {
	name    string
	actor   *auth.Claims
	body    string
	script  func(*sqlScript)
	fakes   func(*createFakes)
	status  int
	message string
	steps   []string
	limits  bool
}

// runCreate runs one create against a scripted database and the fakes.
func runCreate(t *testing.T, tc createCase) (*httptest.ResponseRecorder, *sqlScript, *createFakes) {
	t.Helper()
	script := createScript()
	fakes := newCreateFakes(t)
	if tc.script != nil {
		tc.script(script)
	}
	if tc.fakes != nil {
		tc.fakes(fakes)
	}
	handlers := &Handlers{DB: scriptDB(t, script), IPv4: exampleIPv4}
	recorder := httptest.NewRecorder()
	// A nil actor travels as a nil *auth.Claims, which ClaimsFrom reads as no
	// session at all.
	handlers.Create(recorder, ownerRequest(tc.actor, tc.body))
	if tc.limits {
		waitForID(t, fakes.limits, 42)
	}
	return recorder, script, fakes
}

// assertOutcome checks the status and, when want names one, the error message.
func assertOutcome(t *testing.T, recorder *httptest.ResponseRecorder, status int, message string) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("status = %d, want %d (%s)", recorder.Code, status, recorder.Body.String())
	}
	if message == "" {
		return
	}
	if got := errorMessage(t, recorder); got != message {
		t.Errorf("error = %q, want %q", got, message)
	}
}

func decodeCreated(t *testing.T, recorder *httptest.ResponseRecorder) createResp {
	t.Helper()
	var resp createResp
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode the create response %q: %v", recorder.Body.String(), err)
	}
	return resp
}

const (
	stepBlocked   = "blocked? example.com"
	stepOwns      = "owns 9 5"
	stepDomains   = "reseller domains 9"
	stepDisk      = "reseller disk 9"
	stepTraffic   = "reseller traffic 9"
	stepProvision = "provision example.com 8.3"
	bodyExample   = `{"domain_name":"example.com"}`
	bodyCustomer  = `{"domain_name":"example.com","customer_id":5}`
)

var errLostRace = errors.New("error 1062: duplicate entry 'c_example' for key 'uq_domains_system_user_top'")

// Every refusal answers before the host is touched, or tears down what it built.
func TestCreateRefusesBeforeItBuildsATenant(t *testing.T) {
	limited := func(message string) error { return &quota.LimitError{Message: message} }
	cases := []createCase{
		{name: "an unreadable body", actor: adminActor, body: `{`,
			status: http.StatusBadRequest, message: "invalid request body"},
		{name: "an invalid name", actor: adminActor, body: `{"domain_name":"not a name"}`,
			status: http.StatusBadRequest, message: "invalid domain name"},
		{name: "a blocked name", actor: adminActor, body: bodyExample,
			fakes:  func(f *createFakes) { f.blocked = true },
			status: http.StatusForbidden, message: "blocked", steps: []string{stepBlocked}},
		{name: "a name check that fails", actor: adminActor, body: bodyExample,
			script: func(s *sqlScript) { s.fail["SELECT id FROM domains WHERE domain_name=?"] = errScripted },
			status: http.StatusInternalServerError, message: "could not verify the domain name", steps: []string{stepBlocked}},
		{name: "a name already served", actor: adminActor, body: bodyExample,
			script: func(s *sqlScript) { s.rows["SELECT id FROM subdomains WHERE fqdn=?"] = [][]driver.Value{{int64(3)}} },
			status: http.StatusConflict, message: "this domain name is already registered", steps: []string{stepBlocked}},
		{name: "an owner named by a reseller", actor: resellerActor, body: `{"domain_name":"example.com","customer_id":5,"owner_user_id":9}`,
			status: http.StatusForbidden, message: reasonOwnerNotAllowed, steps: []string{stepBlocked}},
		{name: "an owner named with no claims", body: `{"domain_name":"example.com","owner_user_id":9}`,
			status: http.StatusForbidden, message: reasonOwnerNotAllowed, steps: []string{stepBlocked}},
		{name: "a reseller naming no customer", actor: resellerActor, body: bodyExample,
			status: http.StatusBadRequest, message: "a domain must be attached to a customer", steps: []string{stepBlocked}},
		{name: "a reseller naming a customer it does not own", actor: resellerActor, body: bodyCustomer,
			status: http.StatusForbidden, message: "no access to this customer", steps: []string{stepBlocked, stepOwns}},
		{name: "a reseller over its domain limit", actor: resellerActor, body: bodyCustomer,
			fakes:  func(f *createFakes) { f.owns, f.domainErr = true, limited("domain limit reached") },
			status: http.StatusForbidden, message: "domain limit reached", steps: []string{stepBlocked, stepOwns, stepDomains}},
		{name: "a reseller domain limit that cannot be read", actor: resellerActor, body: bodyCustomer,
			fakes:  func(f *createFakes) { f.owns, f.domainErr = true, errScripted },
			status: http.StatusInternalServerError, message: "could not verify reseller limit", steps: []string{stepBlocked, stepOwns, stepDomains}},
		{name: "a reseller over its disk quota", actor: resellerActor, body: bodyCustomer,
			fakes:  func(f *createFakes) { f.owns, f.diskErr = true, limited("disk quota reached") },
			status: http.StatusForbidden, message: "disk quota reached", steps: []string{stepBlocked, stepOwns, stepDomains, stepDisk}},
		{name: "a reseller disk quota that cannot be read", actor: resellerActor, body: bodyCustomer,
			fakes:  func(f *createFakes) { f.owns, f.diskErr = true, errScripted },
			status: http.StatusInternalServerError, message: "could not verify reseller disk quota", steps: []string{stepBlocked, stepOwns, stepDomains, stepDisk}},
		{name: "a reseller over its traffic quota", actor: resellerActor, body: bodyCustomer,
			fakes:  func(f *createFakes) { f.owns, f.trafficErr = true, limited("traffic quota reached") },
			status: http.StatusForbidden, message: "traffic quota reached", steps: []string{stepBlocked, stepOwns, stepDomains, stepDisk, stepTraffic}},
		{name: "a reseller traffic quota that cannot be read", actor: resellerActor, body: bodyCustomer,
			fakes:  func(f *createFakes) { f.owns, f.trafficErr = true, errScripted },
			status: http.StatusInternalServerError, message: "could not verify reseller traffic quota", steps: []string{stepBlocked, stepOwns, stepDomains, stepDisk, stepTraffic}},
		{name: "a referenced account lookup that fails", actor: resellerActor, body: bodyCustomer,
			script: func(s *sqlScript) { s.fail["SELECT id FROM customers WHERE id=?"] = errScripted },
			fakes:  func(f *createFakes) { f.owns = true },
			status: http.StatusInternalServerError, message: "could not verify the selected account", steps: []string{stepBlocked, stepOwns, stepDomains, stepDisk, stepTraffic}},
		{name: "a customer that does not exist", actor: adminActor, body: bodyCustomer,
			script: func(s *sqlScript) { s.rows["SELECT id FROM customers WHERE id=?"] = nil },
			status: http.StatusBadRequest, message: reasonCustomerNotFound, steps: []string{stepBlocked}},
		{name: "a customer over its plan's domain limit", actor: adminActor, body: bodyExample,
			fakes:  func(f *createFakes) { f.planErr = limited("plan limit reached") },
			status: http.StatusForbidden, message: "plan limit reached", steps: []string{stepBlocked, "plan gate nil"}},
		{name: "a plan limit that cannot be read", actor: adminActor, body: bodyExample,
			fakes:  func(f *createFakes) { f.planErr = errScripted },
			status: http.StatusInternalServerError, message: "could not verify plan limit", steps: []string{stepBlocked, "plan gate nil"}},
		{name: "provisioning that fails", actor: adminActor, body: bodyExample,
			fakes:  func(f *createFakes) { f.provisionErr = errScripted },
			status: http.StatusInternalServerError, message: "domain provisioning failed", steps: []string{stepBlocked, "plan gate nil", stepProvision}},
		{name: "an insert that lost the system user race", actor: adminActor, body: bodyExample,
			script: func(s *sqlScript) { s.fail["INSERT INTO domains("] = errLostRace },
			status: http.StatusConflict, message: "another domain took this system user name; try again",
			steps: []string{stepBlocked, "plan gate nil", stepProvision, "deprovision example.com c_example"}},
		{name: "an insert that fails", actor: adminActor, body: bodyExample,
			script: func(s *sqlScript) { s.fail["INSERT INTO domains("] = errScripted },
			status: http.StatusInternalServerError, message: "domain record creation failed",
			steps: []string{stepBlocked, "plan gate nil", stepProvision, "deprovision example.com c_example"}},
		{name: "an attach write that fails", actor: adminActor, body: bodyCustomer,
			script: func(s *sqlScript) {
				s.rows["SELECT id FROM customers WHERE id=?"] = [][]driver.Value{{int64(5)}}
				s.fail["UPDATE domains SET customer_id=?, plan_id=?"] = errScripted
			},
			status: http.StatusInternalServerError, message: "the domain was created but could not be attached to the selected account",
			steps: []string{stepBlocked, "plan gate 5", stepProvision}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder, _, fakes := runCreate(t, tc)
			assertOutcome(t, recorder, tc.status, tc.message)
			assertSteps(t, &fakes.hostCalls, tc.steps...)
		})
	}
}

// An unattached domain gets a customer account of its own, an FTP account, a
// database, a DNS zone and its resource limits, and the passwords come back once.
func TestCreateOpensAnUnattachedDomain(t *testing.T) {
	recorder, script, fakes := runCreate(t, createCase{
		actor: adminActor, body: `{"domain_name":" Example.COM "}`, limits: true,
	})
	assertOutcome(t, recorder, http.StatusCreated, "")
	assertSteps(t, &fakes.hostCalls, stepBlocked, "plan gate nil", stepProvision,
		"account c_example example.com nil", "ftp 42 c_example 0 0",
		"mysql 42 c_example_main c_example_db", "dns seed 42 example.com "+exampleIPv4, "zone 42", "nameservers?")
	assertExecArgs(t, script, "INSERT INTO domains(", []driver.Value{
		"example.com", "c_example", "8.3", exampleIPv4, exampleIPv4, "c_example",
		"c_example_db", "c_example_main", "/home/c_example/public_html", "php",
	})
	assertExecArgs(t, script, "UPDATE domains SET customer_id=? WHERE id=?", []driver.Value{int64(5), int64(42)})
	resp := decodeCreated(t, recorder)
	if resp.CreatedPasswords.FTP == "" || resp.CreatedPasswords.FTP != fakes.ftpPassword {
		t.Errorf("the FTP password returned is %q, the one created %q", resp.CreatedPasswords.FTP, fakes.ftpPassword)
	}
	if resp.CreatedPasswords.DB == "" || resp.CreatedPasswords.DB != fakes.dbPassword {
		t.Errorf("the database password returned is %q, the one created %q", resp.CreatedPasswords.DB, fakes.dbPassword)
	}
	if resp.Nameservers != nil || resp.Warning != "" {
		t.Errorf("nameservers = %v, warning = %q, want neither", resp.Nameservers, resp.Warning)
	}
}

// The default plan is used when none is named, and its PHP version and nginx
// defaults reach the new domain.
func TestCreateInheritsTheDefaultPlan(t *testing.T) {
	recorder, script, fakes := runCreate(t, createCase{
		actor: adminActor, body: bodyCustomer, limits: true,
		script: func(s *sqlScript) {
			s.rows["WHERE is_default=1"] = [][]driver.Value{{int64(3)}}
			s.rows["SELECT php_version FROM service_plans"] = [][]driver.Value{{"8.2"}}
			s.rows["SELECT id FROM customers WHERE id=?"] = [][]driver.Value{{int64(5)}}
			s.rows["SELECT id FROM service_plans WHERE id=?"] = [][]driver.Value{{int64(3)}}
			s.rows["SELECT fastcgi_cache, client_max_body_mb"] = [][]driver.Value{{int64(1), int64(64), "gzip on;"}}
		},
	})
	assertOutcome(t, recorder, http.StatusCreated, "")
	assertSteps(t, &fakes.hostCalls, stepBlocked, "plan gate 5", "provision example.com 8.2",
		"socket c_example 8.2", "vhost 42 /run/php-fpm/c_example.sock 8.2", "ftp 42 c_example 0 0",
		"mysql 42 c_example_main c_example_db", "dns seed 42 example.com "+exampleIPv4, "zone 42", "nameservers?")
	assertExecArgs(t, script, "UPDATE domains SET customer_id=?, plan_id=?", []driver.Value{int64(5), int64(3), int64(42)})
	assertExecArgs(t, script, "INSERT INTO nginx_settings", []driver.Value{int64(42), int64(1), "gzip on;", "64m"})
}

// The plan defaults stop at the first step that fails, and the create goes on.
func TestCreateStopsThePlanDefaultsAtTheFirstFailure(t *testing.T) {
	const body = `{"domain_name":"example.com","plan_id":3,"php_version":"8.1"}`
	tail := []string{"ftp 42 c_example 0 0", "mysql 42 c_example_main c_example_db",
		"dns seed 42 example.com " + exampleIPv4, "zone 42", "nameservers?"}
	head := []string{stepBlocked, "plan gate nil", "provision example.com 8.1", "account c_example example.com nil"}
	planRow := func(s *sqlScript) {
		s.rows["SELECT id FROM service_plans WHERE id=?"] = [][]driver.Value{{int64(3)}}
		s.rows["SELECT fastcgi_cache, client_max_body_mb"] = [][]driver.Value{{int64(0), int64(0), "  "}}
	}
	cases := []createCase{
		{name: "an unreadable plan", script: func(s *sqlScript) {
			planRow(s)
			s.fail["SELECT fastcgi_cache, client_max_body_mb"] = errScripted
		}, steps: append(append([]string{}, head...), tail...)},
		{name: "an nginx settings write that fails", script: func(s *sqlScript) {
			planRow(s)
			s.fail["INSERT INTO nginx_settings"] = errScripted
		}, steps: append(append([]string{}, head...), tail...)},
		{name: "a PHP socket that cannot be found", script: planRow,
			fakes: func(f *createFakes) { f.socketErr = errScripted },
			steps: append(append(append([]string{}, head...), "socket c_example 8.1"), tail...)},
		{name: "a blank plan", script: planRow,
			steps: append(append(append([]string{}, head...), "socket c_example 8.1", "vhost 42 /run/php-fpm/c_example.sock 8.1"), tail...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.actor, tc.body, tc.limits = adminActor, body, true
			recorder, _, fakes := runCreate(t, tc)
			assertOutcome(t, recorder, http.StatusCreated, "")
			assertSteps(t, &fakes.hostCalls, tc.steps...)
		})
	}
}

// Everything after the domain row is best-effort: a failure is logged and the
// create still answers 201. A static site opens no database at all.
func TestCreateKeepsGoingPastTheBestEffortSteps(t *testing.T) {
	recorder, _, fakes := runCreate(t, createCase{
		actor: adminActor, body: `{"domain_name":"example.com","site_type":"static"}`, limits: true,
		script: func(s *sqlScript) { s.fail["WHERE is_default=1"] = errScripted },
		fakes: func(f *createFakes) {
			f.accountErr, f.ftpErr, f.seedErr, f.zoneErr, f.limitsErr = errScripted, errScripted, errScripted, errScripted, errScripted
		},
	})
	assertOutcome(t, recorder, http.StatusCreated, "")
	assertSteps(t, &fakes.hostCalls, stepBlocked, "plan gate nil", stepProvision,
		"account c_example example.com nil", "ftp 42 c_example 0 0",
		"dns seed 42 example.com "+exampleIPv4, "zone 42", "nameservers?")
	if resp := decodeCreated(t, recorder); resp.CreatedPasswords.DB != "" {
		t.Errorf("a static site returned a database password %q", resp.CreatedPasswords.DB)
	}
}

// A reseller named for a tenant that already had a customer record is not
// applied, and the response says so.
func TestCreateReportsAnOwnerThatWasNotApplied(t *testing.T) {
	recorder, _, fakes := runCreate(t, createCase{
		actor: adminActor, body: `{"domain_name":"example.com","owner_user_id":9}`, limits: true,
		script: func(s *sqlScript) {
			s.rows["FROM users WHERE id=?"] = [][]driver.Value{{int64(9)}}
			s.fail["UPDATE domains SET customer_id=? WHERE id=?"] = errScripted
		},
		fakes: func(f *createFakes) { f.account = tenantaccount.Result{CustomerID: 5, Reused: true} },
	})
	assertOutcome(t, recorder, http.StatusCreated, "")
	assertSteps(t, &fakes.hostCalls, stepBlocked, "plan gate nil", stepProvision,
		"account c_example example.com 9", "ftp 42 c_example 0 0",
		"mysql 42 c_example_main c_example_db", "dns seed 42 example.com "+exampleIPv4, "zone 42", "nameservers?")
	if resp := decodeCreated(t, recorder); resp.Warning != warningOwnerNotApplied {
		t.Errorf("warning = %q, want %q", resp.Warning, warningOwnerNotApplied)
	}
}

// A configured nameserver pair is read for the domain row the create wrote.
func TestCreateHandsOverARealNameserverPair(t *testing.T) {
	recorder, _, fakes := runCreate(t, createCase{
		actor: adminActor, body: bodyExample, limits: true,
		script: func(s *sqlScript) {
			s.rows["LEFT JOIN service_plans p ON p.id=d.plan_id"] = domainRow(42, "example.com", "c_example")
		},
		fakes: func(f *createFakes) { f.nameservers = true },
	})
	assertOutcome(t, recorder, http.StatusCreated, "")
	steps := fakes.all()
	if got := steps[len(steps)-1]; got != "pair 42 example.com" {
		t.Errorf("the last host call = %q, want the pair read for domain 42", got)
	}
	resp := decodeCreated(t, recorder)
	if resp.Nameservers == nil || resp.Nameservers.NS1 != "ns1.host.example" || resp.Nameservers.NS2 != "ns2.host.example" {
		t.Errorf("nameservers = %+v, want the configured pair", resp.Nameservers)
	}
	if resp.ID != 42 || resp.DomainName != "example.com" {
		t.Errorf("the response carries domain %d %q, want the row read back", resp.ID, resp.DomainName)
	}
}
