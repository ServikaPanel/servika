package panelsettings

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Save is the endpoint that moves the panel onto an operator's own domain. It
// runs acme.sh, replaces the certificate the panel serves and rewrites an nginx
// vhost, so every one of its steps reaches the host. The seams in seams.go let
// the endpoint run here, and these tests pin what it stores and what it warns
// about before the function is split.

const (
	theServerIP = "203.0.113.10"
	theDomain   = "panel.example.com"
	updSettings = "UPDATE panel_settings SET custom_domain"
)

// panelScript records the statements the handler runs.
type panelScript struct {
	mu       sync.Mutex
	execErr  error
	execs    []string
	execArgs map[string][]driver.Value
}

func (s *panelScript) record(query string, args []driver.NamedValue) error {
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
	return s.execErr
}

func (s *panelScript) argsOf(fragment string) []driver.Value {
	s.mu.Lock()
	defer s.mu.Unlock()
	for query, values := range s.execArgs {
		if strings.Contains(query, fragment) {
			return values
		}
	}
	return nil
}

type panelConn struct{ script *panelScript }

func (c panelConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c panelConn) Driver() driver.Driver                        { return panelDriver{} }
func (c panelConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c panelConn) Close() error                                 { return nil }
func (c panelConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c panelConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return nil, errors.New("the test script answers no query")
}

func (c panelConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.script.record(query, args); err != nil {
		return nil, err
	}
	return panelResult{}, nil
}

type panelResult struct{}

func (panelResult) LastInsertId() (int64, error) { return 1, nil }
func (panelResult) RowsAffected() (int64, error) { return 1, nil }

type panelDriver struct{}

func (panelDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// hostStub answers for the host and records what the endpoint asked it to do.
type hostStub struct {
	ips         []string
	lookupErr   error
	issueErr    error
	expiry      time.Time
	haveExpiry  bool
	portlessErr error

	looked   []string
	issued   []string
	written  []string
	restored int
	removed  int
}

func (s *hostStub) install(t *testing.T) {
	t.Helper()
	lookupWas, issueWas, restoreWas := lookupHost, issueCert, restoreSelf
	expiryWas, writeWas, removeWas, ipWas := certExpiry, writePortless, removePortless, publicIPv4
	t.Cleanup(func() {
		lookupHost, issueCert, restoreSelf = lookupWas, issueWas, restoreWas
		certExpiry, writePortless, removePortless, publicIPv4 = expiryWas, writeWas, removeWas, ipWas
	})
	lookupHost = func(host string) ([]string, error) {
		s.looked = append(s.looked, host)
		return s.ips, s.lookupErr
	}
	issueCert = func(domain string) error {
		s.issued = append(s.issued, domain)
		return s.issueErr
	}
	restoreSelf = func() { s.restored++ }
	certExpiry = func(string, string) (time.Time, bool) { return s.expiry, s.haveExpiry }
	writePortless = func(domain string) error {
		s.written = append(s.written, domain)
		return s.portlessErr
	}
	removePortless = func() { s.removed++ }
	// A machine running these tests has its own interface address, so the
	// fallback must be pinned too or "no address" is not reachable.
	publicIPv4 = func() string { return "" }
}

// pointedHere is a domain whose A record already names this server and a
// certificate that installs and expires on a known date.
func pointedHere() *hostStub {
	return &hostStub{
		ips:        []string{theServerIP},
		expiry:     time.Date(2027, 3, 4, 12, 0, 0, 0, time.UTC),
		haveExpiry: true,
	}
}

func saveAs(t *testing.T, serverIP string, stub *hostStub, script *panelScript, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	stub.install(t)
	db := sql.OpenDB(panelConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	h := &Handlers{DB: db, ServerIPv4: serverIP}
	w := httptest.NewRecorder()
	h.Save(w, httptest.NewRequest(http.MethodPost, "/api/v1/panel-settings", strings.NewReader(body)))
	var decoded map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &decoded)
	return w, decoded
}

func save(t *testing.T, stub *hostStub, script *panelScript, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	return saveAs(t, theServerIP, stub, script, body)
}

func TestSaveRefusesABodyItCannotRead(t *testing.T) {
	w, decoded := save(t, pointedHere(), &panelScript{}, "{")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if decoded["error"] != "invalid request body" {
		t.Fatalf("error = %v, want invalid request body", decoded["error"])
	}
}

func TestSaveRefusesADomainThatIsNotValid(t *testing.T) {
	stub := pointedHere()
	w, decoded := save(t, stub, &panelScript{}, `{"domain":"not a domain"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if decoded["error"] != "invalid domain name" {
		t.Fatalf("error = %v, want invalid domain name", decoded["error"])
	}
	if len(stub.issued) != 0 {
		t.Fatalf("a certificate was issued for a refused domain: %v", stub.issued)
	}
}

// The domain is lowercased and trimmed before anything else uses it, so the
// name that reaches DNS and acme.sh is the stored one.
func TestSaveNormalisesTheRequestedDomain(t *testing.T) {
	stub := pointedHere()
	script := &panelScript{}
	w, _ := save(t, stub, script, `{"domain":"  Panel.Example.COM  "}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if len(stub.looked) != 1 || stub.looked[0] != theDomain {
		t.Fatalf("looked up %v, want [%s]", stub.looked, theDomain)
	}
	if args := script.argsOf(updSettings); len(args) == 0 || args[0] != theDomain {
		t.Fatalf("stored domain = %v, want %s", args, theDomain)
	}
}

func TestSaveRefusesWhenNoServerAddressIsKnown(t *testing.T) {
	stub := pointedHere()
	w, decoded := saveAs(t, "", stub, &panelScript{}, `{"domain":"`+theDomain+`"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	if decoded["error"] != "server IPv4 address could not be detected" {
		t.Fatalf("error = %v", decoded["error"])
	}
	if len(stub.looked) != 0 {
		t.Fatalf("DNS was queried without a server address: %v", stub.looked)
	}
}

// Issuance runs against a webroot on THIS server, so a domain resolving
// elsewhere would fail the ACME challenge and take the panel certificate down
// with it. The check is before the issuance for that reason.
func TestSaveRefusesADomainThatResolvesElsewhere(t *testing.T) {
	stub := pointedHere()
	stub.ips = []string{"198.51.100.7"}
	w, decoded := save(t, stub, &panelScript{}, `{"domain":"`+theDomain+`"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", w.Code)
	}
	if decoded["error"] != "domain A record must point to this server before certificate issuance" {
		t.Fatalf("error = %v", decoded["error"])
	}
	if len(stub.issued) != 0 {
		t.Fatalf("a certificate was issued for a domain pointing elsewhere: %v", stub.issued)
	}
}

func TestSaveRefusesADomainThatDoesNotResolve(t *testing.T) {
	stub := pointedHere()
	stub.ips, stub.lookupErr = nil, errors.New("no such host")
	w, _ := save(t, stub, &panelScript{}, `{"domain":"`+theDomain+`"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", w.Code)
	}
	if len(stub.issued) != 0 {
		t.Fatalf("a certificate was issued for an unresolvable domain: %v", stub.issued)
	}
}

func TestSaveStoresTheIssuedCertificate(t *testing.T) {
	stub := pointedHere()
	script := &panelScript{}
	w, decoded := save(t, stub, script, `{"domain":"`+theDomain+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if decoded["ssl_status"] != "active" || decoded["custom_domain"] != theDomain {
		t.Fatalf("response = %v", decoded)
	}
	if _, ok := decoded["warning"]; ok {
		t.Fatalf("a successful save carried a warning: %v", decoded["warning"])
	}
	args := script.argsOf(updSettings)
	want := []driver.Value{theDomain, "active", nil, "2027-03-04"}
	if len(args) != len(want) {
		t.Fatalf("stored %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("stored argument %d = %v, want %v", i, args[i], want[i])
		}
	}
	if len(stub.written) != 1 || stub.written[0] != theDomain {
		t.Fatalf("portless vhost written for %v, want [%s]", stub.written, theDomain)
	}
}

// A certificate the panel cannot read leaves the expiry column empty rather
// than failing the save; the domain is still on the new certificate.
func TestSaveStoresNoExpiryWhenTheCertificateCannotBeRead(t *testing.T) {
	stub := pointedHere()
	stub.haveExpiry = false
	script := &panelScript{}
	w, _ := save(t, stub, script, `{"domain":"`+theDomain+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	args := script.argsOf(updSettings)
	if len(args) != 4 || args[1] != "active" || args[3] != nil {
		t.Fatalf("stored %v, want an active row with no expiry", args)
	}
}

// A failed issuance must put the previous certificate back, or the panel is
// left serving a certificate that was never installed.
func TestSaveRestoresTheSelfSignedCertificateWhenIssuanceFails(t *testing.T) {
	stub := pointedHere()
	stub.issueErr = errors.New("acme issue failed")
	script := &panelScript{}
	w, decoded := save(t, stub, script, `{"domain":"`+theDomain+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if stub.restored != 1 {
		t.Fatalf("restored %d times, want 1", stub.restored)
	}
	if stub.removed != 1 || len(stub.written) != 0 {
		t.Fatalf("removed=%d written=%v, want the portless vhost removed and none written", stub.removed, stub.written)
	}
	if decoded["ssl_status"] != "failed" {
		t.Fatalf("ssl_status = %v, want failed", decoded["ssl_status"])
	}
	if decoded["warning"] != "The domain was saved, but Let's Encrypt certificate issuance failed. The panel remains available with the existing certificate." {
		t.Fatalf("warning = %v", decoded["warning"])
	}
	args := script.argsOf(updSettings)
	if len(args) != 4 || args[1] != "failed" || args[2] != "certificate issuance failed" || args[3] != nil {
		t.Fatalf("stored %v, want a failed row carrying the issuance error", args)
	}
}

func TestSaveWarnsWhenThePortlessVhostCannotBeWritten(t *testing.T) {
	stub := pointedHere()
	stub.portlessErr = errors.New("nginx configuration test failed")
	w, decoded := save(t, stub, &panelScript{}, `{"domain":"`+theDomain+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if decoded["ssl_status"] != "active" {
		t.Fatalf("ssl_status = %v, want active", decoded["ssl_status"])
	}
	if decoded["warning"] != "The certificate was installed, but portless panel access could not be configured. The panel remains available on port 8443." {
		t.Fatalf("warning = %v", decoded["warning"])
	}
	if stub.removed != 0 {
		t.Fatal("the portless vhost was removed after a successful issuance")
	}
}

func TestSaveFailsWhenTheRowCannotBeUpdated(t *testing.T) {
	stub := pointedHere()
	script := &panelScript{execErr: errors.New("connection refused")}
	w, decoded := save(t, stub, script, `{"domain":"`+theDomain+`"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	if decoded["error"] != "panel settings could not be saved" {
		t.Fatalf("error = %v", decoded["error"])
	}
	if len(stub.written) != 0 {
		t.Fatalf("the vhost was written for a row that was not stored: %v", stub.written)
	}
}
