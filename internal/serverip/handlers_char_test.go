package serverip

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"servika/internal/auth"

	"github.com/go-chi/chi/v5"
)

// The two write handlers reach "ip addr", /proc/net/tcp and a systemd unit in
// /etc, so neither had a test. seams.go routes those calls through package
// variables; these tests replace them and leave the handlers untouched.

// hostCall records one call to the host seams.
type hostCall struct {
	name    string
	ip      string
	prefix  int
	device  string
	label   string
	address Address
}

// fakeHost answers the four host seams from a fixed set of addresses and
// records every write.
type fakeHost struct {
	addresses []Address
	bound     map[string]bool
	readErr   error
	boundErr  error
	addErr    error
	removeErr error
	persistNo error
	calls     []hostCall
}

func (f *fakeHost) install(t *testing.T) {
	t.Helper()
	setForTest(t, &readHostAddresses, func(context.Context) ([]Address, error) {
		return f.addresses, f.readErr
	})
	setForTest(t, &readBoundAddresses, func() (map[string]bool, error) {
		return f.bound, f.boundErr
	})
	setForTest(t, &addToHost, func(_ context.Context, ip net.IP, prefix int, device, label string) error {
		f.calls = append(f.calls, hostCall{
			name: "add", ip: ip.String(), prefix: prefix, device: device, label: label,
		})
		return f.addErr
	})
	setForTest(t, &removeFromHost, func(_ context.Context, address Address) error {
		f.calls = append(f.calls, hostCall{name: "remove", address: address})
		return f.removeErr
	})
	setForTest(t, &writePersistence, func(context.Context, *sql.DB) error {
		f.calls = append(f.calls, hostCall{name: "persist"})
		return f.persistNo
	})
}

// did reports whether the named host call was made.
func (f *fakeHost) did(name string) bool {
	for _, call := range f.calls {
		if call.name == name {
			return true
		}
	}
	return false
}

// eth0 is the primary address every case starts from: the provider's own, with
// no panel label.
var eth0 = Address{Interface: "eth0", IP: "203.0.113.10", Prefix: 24, Label: "eth0", Scope: "global"}

// panelAddress is one this panel added, which is the only kind it may remove.
var panelAddress = Address{
	Interface: "eth0", IP: "203.0.113.20", Prefix: 32,
	Label: "panel-0001", Scope: "global", PanelAdded: true,
}

// addRequest posts one add body.
func addRequest(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/system/ips", strings.NewReader(body))
}

// removeRequest addresses one id, the way chi hands it to the handler.
func removeRequest(id string) *http.Request {
	r := httptest.NewRequest(http.MethodDelete, "/system/ips/"+id, nil)
	routes := chi.NewRouteContext()
	routes.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, routes))
}

// answer runs one handler and decodes what it wrote.
func answer(t *testing.T, handler http.HandlerFunc, r *http.Request) (int, map[string]any) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler(recorder, r)
	var decoded map[string]any
	if body := recorder.Body.Bytes(); len(body) > 0 {
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatalf("the response is not JSON: %v (%s)", err, body)
		}
	}
	return recorder.Code, decoded
}

// assertRefusal checks the status and the stable reason code beside the
// message, which is what the screen renders in twelve languages.
func assertRefusal(t *testing.T, status int, body map[string]any, wantStatus int, wantReason string) {
	t.Helper()
	if status != wantStatus {
		t.Errorf("status = %d, want %d (%v)", status, wantStatus, body)
	}
	if got, _ := body["reason"].(string); got != wantReason {
		t.Errorf("reason = %q, want %q", got, wantReason)
	}
}

func TestAnAddedAddressIsRecordedThenPutOnTheHost(t *testing.T) {
	host := &fakeHost{addresses: []Address{eth0}}
	host.install(t)
	script := newScript()
	handlers := &Handlers{DB: scriptDB(t, script)}

	status, body := answer(t, handlers.Add,
		addRequest(`{"ip":"203.0.113.20","prefix":32,"interface":"eth0","note":"mail"}`))

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%v)", status, body)
	}
	if body["ip"] != "203.0.113.20" || body["interface"] != "eth0" || body["label"] != "panel-0001" {
		t.Errorf("response = %v, want the address, its interface and its new label", body)
	}
	// The row is written FIRST so the label is claimed, then the host change,
	// then the boot script.
	assertSteps(t, script, host, []string{"INSERT INTO server_ips", "add", "persist"})

	args := argsOf(t, script, "INSERT INTO server_ips")
	want := []driver.Value{"203.0.113.20", "eth0", int64(32), "panel-0001", "mail", nil}
	if len(args) != len(want) {
		t.Fatalf("insert arguments = %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("insert arguments = %v, want %v", args, want)
		}
	}
}

// assertSteps checks the statements in the order they ran, and then the host
// calls in the order they ran. Each sequence is the rollback story of its own
// half: a row written after the host change would leave an address nobody
// recorded, and a boot script rewritten after a failed change would put back an
// address that is not there.
func assertSteps(t *testing.T, script *sqlScript, host *fakeHost, want []string) {
	t.Helper()
	var got []string
	for _, step := range script.steps {
		got = append(got, firstLine(step))
	}
	for _, call := range host.calls {
		got = append(got, call.name)
	}
	if len(got) != len(want) {
		t.Fatalf("steps = %v, want %v", got, want)
	}
	for i := range want {
		if !strings.Contains(got[i], want[i]) {
			t.Fatalf("steps = %v, want %v", got, want)
		}
	}
}

func firstLine(text string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(text), "\n")
	return line
}

// argsOf returns the arguments of the one statement holding the fragment.
func argsOf(t *testing.T, script *sqlScript, fragment string) []driver.Value {
	t.Helper()
	for _, exec := range script.execs {
		if strings.Contains(exec.query, fragment) {
			return exec.args
		}
	}
	t.Fatalf("no statement holds %q", fragment)
	return nil
}

// An empty interface takes the device carrying the first routable address,
// which is where a second address almost always belongs.
func TestAnAddWithNoInterfaceTakesTheRoutableOne(t *testing.T) {
	host := &fakeHost{addresses: []Address{
		{Interface: "lo", IP: "127.0.0.1", Prefix: 8, Scope: "host"},
		eth0,
	}}
	host.install(t)
	handlers := &Handlers{DB: scriptDB(t, newScript())}

	status, body := answer(t, handlers.Add, addRequest(`{"ip":"203.0.113.20"}`))
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%v)", status, body)
	}
	if body["interface"] != "eth0" {
		t.Errorf("interface = %v, want eth0", body["interface"])
	}
	// A missing prefix is a single address, not a whole network.
	if host.calls[0].prefix != 32 {
		t.Errorf("prefix = %d, want 32", host.calls[0].prefix)
	}
}

func TestAnAddRefusesWhatItCannotPutOnThisHost(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		addresses []Address
		status    int
		reason    string
	}{
		{"not an address", `{"ip":"nonsense"}`, []Address{eth0}, http.StatusConflict, ReasonNotIPv4},
		{"IPv6", `{"ip":"2001:db8::1"}`, []Address{eth0}, http.StatusConflict, ReasonNotIPv4},
		{"a reserved address", `{"ip":"127.0.0.5"}`, []Address{eth0}, http.StatusConflict, ReasonReserved},
		{"a prefix outside IPv4", `{"ip":"203.0.113.20","prefix":33}`, []Address{eth0},
			http.StatusConflict, ReasonBadPrefix},
		{"an interface this host has not", `{"ip":"203.0.113.20","interface":"eth9"}`, []Address{eth0},
			http.StatusConflict, ReasonUnknownIface},
		{"an interface name that is a flag", `{"ip":"203.0.113.20","interface":"-r"}`, []Address{eth0},
			http.StatusConflict, ReasonUnknownIface},
		{"an address the host already carries", `{"ip":"203.0.113.10","interface":"eth0"}`, []Address{eth0},
			http.StatusConflict, ReasonAlreadyOnHost},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host := &fakeHost{addresses: tc.addresses}
			host.install(t)
			script := newScript()
			handlers := &Handlers{DB: scriptDB(t, script)}

			status, body := answer(t, handlers.Add, addRequest(tc.body))
			assertRefusal(t, status, body, tc.status, tc.reason)
			if len(script.execs) != 0 {
				t.Errorf("a refused add still wrote %v", script.execs)
			}
			if len(host.calls) != 0 {
				t.Errorf("a refused add still touched the host: %v", host.calls)
			}
		})
	}
}

func TestAnUnreadableRequestBodyIsABadRequest(t *testing.T) {
	host := &fakeHost{addresses: []Address{eth0}}
	host.install(t)
	handlers := &Handlers{DB: scriptDB(t, newScript())}

	status, body := answer(t, handlers.Add, addRequest(`{"ip":`))
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (%v)", status, body)
	}
}

// A host that cannot be read stops the add, because the host is what proves the
// address is not already there.
func TestAnAddStopsWhenTheHostCannotBeRead(t *testing.T) {
	host := &fakeHost{readErr: refuse(ReasonUnreadable, "the host's addresses could not be read: x")}
	host.install(t)
	script := newScript()
	handlers := &Handlers{DB: scriptDB(t, script)}

	status, body := answer(t, handlers.Add, addRequest(`{"ip":"203.0.113.20"}`))
	assertRefusal(t, status, body, http.StatusConflict, ReasonUnreadable)
	if len(script.execs) != 0 {
		t.Errorf("the row was written anyway: %v", script.execs)
	}
}

// The row is taken back out when the host change fails. A row for an address
// the server does not have would put that address on at the next reboot.
func TestAFailedHostChangeTakesTheRowBackOut(t *testing.T) {
	host := &fakeHost{
		addresses: []Address{eth0},
		addErr:    refuse(ReasonUnreadable, "the address could not be added: RTNETLINK"),
	}
	host.install(t)
	script := newScript()
	handlers := &Handlers{DB: scriptDB(t, script)}

	status, body := answer(t, handlers.Add, addRequest(`{"ip":"203.0.113.20"}`))
	assertRefusal(t, status, body, http.StatusConflict, ReasonUnreadable)
	assertSteps(t, script, host, []string{"INSERT INTO server_ips", "DELETE FROM server_ips", "add"})
	if host.did("persist") {
		t.Error("the boot script was rewritten for an address that was never added")
	}
}

// The address IS live when only the boot script failed, so the answer says so
// rather than reporting a failure the operator would find out about at the next
// restart.
func TestAFailedBootScriptStillReportsTheLiveAddress(t *testing.T) {
	host := &fakeHost{addresses: []Address{eth0}, persistNo: errors.New("read-only file system")}
	host.install(t)
	handlers := &Handlers{DB: scriptDB(t, newScript())}

	status, body := answer(t, handlers.Add, addRequest(`{"ip":"203.0.113.20"}`))
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%v)", status, body)
	}
	warning, _ := body["warning"].(string)
	if !strings.Contains(warning, "active") || !strings.Contains(warning, "reboot") {
		t.Errorf("warning = %q, want it to say the address is active but not persisted", warning)
	}
}

// A note longer than the column is cut rather than refused.
func TestALongNoteIsCutToTheColumn(t *testing.T) {
	host := &fakeHost{addresses: []Address{eth0}}
	host.install(t)
	script := newScript()
	handlers := &Handlers{DB: scriptDB(t, script)}

	long := strings.Repeat("n", 400)
	if status, body := answer(t, handlers.Add,
		addRequest(`{"ip":"203.0.113.20","note":"`+long+`"}`)); status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%v)", status, body)
	}
	note, _ := argsOf(t, script, "INSERT INTO server_ips")[4].(string)
	if len(note) != 255 {
		t.Errorf("stored note length = %d, want 255", len(note))
	}
}

// The row records WHO added the address, and an unauthenticated request writes
// NULL rather than a user id nobody holds.
func TestTheAddedRowNamesTheAdministrator(t *testing.T) {
	host := &fakeHost{addresses: []Address{eth0}}
	host.install(t)
	script := newScript()
	handlers := &Handlers{DB: scriptDB(t, script)}

	r := addRequest(`{"ip":"203.0.113.20"}`)
	r = r.WithContext(auth.WithClaims(r.Context(),
		&auth.Claims{UserID: 12, Username: "root", Role: "admin"}))
	if status, body := answer(t, handlers.Add, r); status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%v)", status, body)
	}
	if actor := argsOf(t, script, "INSERT INTO server_ips")[5]; actor != int64(12) {
		t.Errorf("created_by = %v, want 12", actor)
	}
}

// A duplicate row is the one insert failure this expects, so it answers as a
// conflict rather than as a server failure.
func TestAnAddressAlreadyRecordedIsAConflict(t *testing.T) {
	host := &fakeHost{addresses: []Address{eth0}}
	host.install(t)
	script := newScript()
	script.fail["INSERT INTO server_ips"] = errors.New("Duplicate entry")
	handlers := &Handlers{DB: scriptDB(t, script)}

	status, body := answer(t, handlers.Add, addRequest(`{"ip":"203.0.113.20"}`))
	if status != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (%v)", status, body)
	}
	if len(host.calls) != 0 {
		t.Errorf("the host was changed for a row that was never written: %v", host.calls)
	}
}

// Every label the panel can generate being taken is a refusal with its own
// reason, not a label reused on a second address.
func TestAnExhaustedLabelSetIsRefused(t *testing.T) {
	host := &fakeHost{addresses: []Address{eth0}}
	for index := 1; index <= 9999; index++ {
		host.addresses = append(host.addresses,
			Address{Interface: "eth0", Label: labelFor(index)})
	}
	host.install(t)
	script := newScript()
	handlers := &Handlers{DB: scriptDB(t, script)}

	status, body := answer(t, handlers.Add, addRequest(`{"ip":"203.0.113.20"}`))
	assertRefusal(t, status, body, http.StatusConflict, ReasonNoLabelLeft)
	if len(script.execs) != 0 {
		t.Errorf("a row was written without a label: %v", script.execs)
	}
}

func labelFor(index int) string {
	return fmt.Sprintf("%s%04d", labelPrefix, index)
}

// ---------------------------------------------------------------------------
// Remove
// ---------------------------------------------------------------------------

const removeLookup = "SELECT ip, interface, prefix_length FROM server_ips WHERE id=?"

// rowFor scripts the lookup one remove starts with.
func rowFor(address Address) *sqlScript {
	script := newScript()
	script.rows[removeLookup] = [][]driver.Value{
		{address.IP, address.Interface, int64(address.Prefix)},
	}
	return script
}

// noRow scripts the lookup with an empty result set, which is what makes
// QueryRow report sql.ErrNoRows.
func noRow() *sqlScript {
	script := newScript()
	script.rows[removeLookup] = nil
	return script
}

func TestARemovedAddressLeavesTheHostThenTheTable(t *testing.T) {
	host := &fakeHost{addresses: []Address{eth0, panelAddress}, bound: map[string]bool{}}
	host.install(t)
	script := rowFor(panelAddress)
	handlers := &Handlers{DB: scriptDB(t, script)}

	status, body := answer(t, handlers.Remove, removeRequest("4"))
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%v)", status, body)
	}
	if body["removed"] != float64(4) {
		t.Errorf("removed = %v, want 4", body["removed"])
	}
	assertSteps(t, script, host,
		[]string{removeLookup, "DELETE FROM server_ips", "remove", "persist"})
	// The address is taken off the host exactly as the HOST reported it, not as
	// the row described it.
	if got := host.calls[0].address; got != panelAddress {
		t.Errorf("removed %+v, want the address the host reported", got)
	}
}

func TestARemoveRefusesWhatIsNotItsToRemove(t *testing.T) {
	cases := []struct {
		name   string
		id     string
		script *sqlScript
		host   *fakeHost
		status int
		reason string
	}{
		{
			name: "an id that is not a number", id: "abc", script: newScript(),
			host: &fakeHost{}, status: http.StatusBadRequest,
		},
		{
			name: "an id no row carries", id: "9", script: noRow(),
			host: &fakeHost{}, status: http.StatusNotFound, reason: ReasonNotFound,
		},
		{
			name: "an address the panel did not add", id: "4", script: rowFor(eth0),
			host:   &fakeHost{addresses: []Address{eth0}, bound: map[string]bool{}},
			status: http.StatusConflict, reason: ReasonNotOurs,
		},
		{
			name: "the address the panel is listening on", id: "4", script: rowFor(panelAddress),
			host: &fakeHost{
				addresses: []Address{panelAddress},
				bound:     map[string]bool{panelAddress.IP: true},
			},
			status: http.StatusConflict, reason: ReasonBound,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.host.install(t)
			handlers := &Handlers{DB: scriptDB(t, tc.script)}

			status, body := answer(t, handlers.Remove, removeRequest(tc.id))
			if tc.reason == "" {
				if status != tc.status {
					t.Errorf("status = %d, want %d (%v)", status, tc.status, body)
				}
			} else {
				assertRefusal(t, status, body, tc.status, tc.reason)
			}
			if tc.host.did("remove") {
				t.Error("a refused remove still changed the host")
			}
		})
	}
}

// A lookup that fails is a server failure, not a missing address: answering
// "no such address" would tell an operator their row is gone when it is not.
func TestAFailedLookupIsNotReportedAsAMissingAddress(t *testing.T) {
	host := &fakeHost{}
	host.install(t)
	script := newScript()
	script.fail[removeLookup] = errors.New("connection refused")
	handlers := &Handlers{DB: scriptDB(t, script)}

	status, body := answer(t, handlers.Remove, removeRequest("4"))
	if status != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (%v)", status, body)
	}
	if got, _ := body["reason"].(string); got != "" {
		t.Errorf("reason = %q, want none: this is not a refusal", got)
	}
}

// The host is what proves what may be removed, so a host that cannot be read
// stops the removal.
func TestARemoveStopsWhenTheHostCannotBeRead(t *testing.T) {
	host := &fakeHost{readErr: refuse(ReasonUnreadable, "the host's addresses could not be read: x")}
	host.install(t)
	handlers := &Handlers{DB: scriptDB(t, rowFor(panelAddress))}

	status, body := answer(t, handlers.Remove, removeRequest("4"))
	assertRefusal(t, status, body, http.StatusConflict, ReasonUnreadable)
	if host.did("remove") {
		t.Error("the address was removed without reading the host")
	}
}

// The row of an absent address goes even when the boot script cannot be
// rewritten, because the row is what would put the address back.
func TestAnAbsentAddressIsForgottenEvenWhenTheScriptFails(t *testing.T) {
	host := &fakeHost{
		addresses: []Address{eth0}, bound: map[string]bool{},
		persistNo: errors.New("read-only file system"),
	}
	host.install(t)
	script := rowFor(panelAddress)
	handlers := &Handlers{DB: scriptDB(t, script)}

	status, body := answer(t, handlers.Remove, removeRequest("4"))
	if status != http.StatusOK || body["was_absent"] != true {
		t.Fatalf("status = %d, body = %v, want 200 and was_absent", status, body)
	}
	assertSteps(t, script, host, []string{removeLookup, "DELETE FROM server_ips", "persist"})
}

// An unreadable socket table permits every removal if it is read as an empty
// set, so it fails CLOSED instead.
func TestARemoveStopsWhenTheSocketTableCannotBeRead(t *testing.T) {
	host := &fakeHost{
		addresses: []Address{panelAddress},
		boundErr:  refuse(ReasonUnreadable, "/proc/net/tcp could not be read: x"),
	}
	host.install(t)
	handlers := &Handlers{DB: scriptDB(t, rowFor(panelAddress))}

	status, body := answer(t, handlers.Remove, removeRequest("4"))
	assertRefusal(t, status, body, http.StatusConflict, ReasonUnreadable)
	if host.did("remove") {
		t.Error("the address was removed on an unreadable socket table")
	}
}

// An address somebody already took off by hand leaves the row and the boot
// script as the whole remaining job.
func TestARemoveOfAnAbsentAddressStillClearsTheRowAndTheScript(t *testing.T) {
	host := &fakeHost{addresses: []Address{eth0}, bound: map[string]bool{}}
	host.install(t)
	script := rowFor(panelAddress)
	handlers := &Handlers{DB: scriptDB(t, script)}

	status, body := answer(t, handlers.Remove, removeRequest("4"))
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%v)", status, body)
	}
	if body["was_absent"] != true {
		t.Errorf("was_absent = %v, want true", body["was_absent"])
	}
	assertSteps(t, script, host, []string{removeLookup, "DELETE FROM server_ips", "persist"})
}

// A host that refuses the change keeps the row: the address is still there.
func TestAFailedHostRemovalKeepsTheRow(t *testing.T) {
	host := &fakeHost{
		addresses: []Address{panelAddress}, bound: map[string]bool{},
		removeErr: refuse(ReasonUnreadable, "the address could not be removed: x"),
	}
	host.install(t)
	script := rowFor(panelAddress)
	handlers := &Handlers{DB: scriptDB(t, script)}

	status, body := answer(t, handlers.Remove, removeRequest("4"))
	assertRefusal(t, status, body, http.StatusConflict, ReasonUnreadable)
	for _, exec := range script.execs {
		if strings.Contains(exec.query, "DELETE FROM server_ips") {
			t.Error("the row was deleted for an address the host still carries")
		}
	}
}

// The address is gone when only the boot script failed, and the answer says
// which half did not happen.
func TestAFailedBootScriptAfterARemovalIsReported(t *testing.T) {
	host := &fakeHost{
		addresses: []Address{panelAddress}, bound: map[string]bool{},
		persistNo: errors.New("read-only file system"),
	}
	host.install(t)
	handlers := &Handlers{DB: scriptDB(t, rowFor(panelAddress))}

	status, body := answer(t, handlers.Remove, removeRequest("4"))
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%v)", status, body)
	}
	warning, _ := body["warning"].(string)
	if !strings.Contains(warning, "gone") || !strings.Contains(warning, "reboot") {
		t.Errorf("warning = %q, want it to say the address is gone but not the script", warning)
	}
}
