package dbremote

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Opening a database port is the one action in the panel that can publish a
// customer's data to the internet, so the ORDER of its steps is the behaviour
// worth pinning: validate, grant, record, then open the port, and the reverse
// when withdrawing. Both handlers leave the machine part way through, through
// the three seams in seams.go, so every step below is measured by what the
// handler asked for rather than by what a host did.

// hostCalls records what the handler asked the machine to do.
type hostCalls struct {
	applied  []bool
	granted  []string
	revoked  []string
	rebuilds int

	applyErr   error
	grantErr   error
	revokeErr  error
	rebuildErr error
}

// fakeHost substitutes the three host seams for the length of one test and
// returns the recorder.
func fakeHost(t *testing.T) *hostCalls {
	t.Helper()
	calls := &hostCalls{}
	previousApply, previousGrant, previousRevoke := applySwitch, grantRemote, revokeRemote
	t.Cleanup(func() {
		applySwitch, grantRemote, revokeRemote = previousApply, previousGrant, previousRevoke
	})
	applySwitch = func(_ context.Context, _ *sql.DB, enable bool) error {
		calls.applied = append(calls.applied, enable)
		return calls.applyErr
	}
	grantRemote = func(dbUser, mysqlHost, password string, databases []string) error {
		calls.granted = append(calls.granted,
			dbUser+"@"+mysqlHost+" "+password+" "+strings.Join(databases, ","))
		return calls.grantErr
	}
	revokeRemote = func(dbUser, mysqlHost string) error {
		calls.revoked = append(calls.revoked, dbUser+"@"+mysqlHost)
		return calls.revokeErr
	}
	return calls
}

// withRebuild gives the handler a firewall rebuild that records itself.
func withRebuild(calls *hostCalls) func() error {
	return func() error {
		calls.rebuilds++
		return calls.rebuildErr
	}
}

// answerOf decodes the error shape both handlers answer with.
func answerOf(t *testing.T, response *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("the answer is not JSON: %s", response.Body.String())
	}
	return body
}

// setSwitch calls the admin switch with a body.
func setSwitch(h *Handlers, body string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	h.ServerSet(response, httptest.NewRequest(http.MethodPut, "/admin/db-remote", strings.NewReader(body)))
	return response
}

// addHost calls the domain add endpoint for domain 1.
func addHost(h *Handlers, body string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/domains/1/db-remote", strings.NewReader(body))
	h.DomainAdd(response, withDomainParam(request, "1"))
	return response
}

// A request the handler cannot read is refused before anything reaches the
// host.
func TestTheSwitchRefusesARequestItCannotRead(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		message string
	}{
		{name: "not JSON", body: "{", message: "invalid request body"},
		{name: "no decision", body: `{}`, message: "enabled is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := fakeHost(t)
			h := &Handlers{DB: statusDB(t, &statusRecorder{}), RebuildFirewall: withRebuild(calls)}

			response := setSwitch(h, tc.body)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", response.Code, response.Body)
			}
			if got := answerOf(t, response)["error"]; got != tc.message {
				t.Errorf("message = %q, want %q", got, tc.message)
			}
			if len(calls.applied) != 0 {
				t.Error("MariaDB was restarted for a request the handler could not read")
			}
		})
	}
}

// The conflicting-rule check is a read, and a read that fails is not an answer:
// opening the port on a maybe is what leaves every connection dropped while the
// screen says remote access is on.
func TestTheSwitchStopsWhenTheFirewallRulesCannotBeRead(t *testing.T) {
	calls := fakeHost(t)
	h := &Handlers{
		DB: statusDB(t, &statusRecorder{queryErr: map[string]error{
			"COUNT(*) FROM firewall_rules": errors.New("lost connection"),
		}}),
		RebuildFirewall: withRebuild(calls),
	}

	response := setSwitch(h, `{"enabled":true}`)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", response.Code, response.Body)
	}
	if got := answerOf(t, response)["error"]; got != "could not check the firewall rules" {
		t.Errorf("message = %q", got)
	}
	if len(calls.applied) != 0 {
		t.Error("the switch was applied without knowing about a conflicting rule")
	}
}

// A failed apply changes nothing, records why, and names the missing key pair as
// its own refusal: opening the port without one publishes the plain MySQL
// protocol, which an operator must not read as a restart failure.
func TestAFailedApplyRecordsWhyAndSavesNothing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		reason string
	}{
		{
			name:   "the certificate could not be prepared",
			err:    ErrTLSUnavailable,
			reason: reasonTLSUnavailable,
		},
		{
			name:   "MariaDB did not come back",
			err:    errors.New("systemctl restart mariadb: failed"),
			reason: reasonApplyFailed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := fakeHost(t)
			calls.applyErr = tc.err
			recorder := &statusRecorder{}
			h := &Handlers{DB: statusDB(t, recorder), RebuildFirewall: withRebuild(calls)}

			response := setSwitch(h, `{"enabled":true}`)

			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500: %s", response.Code, response.Body)
			}
			if got := answerOf(t, response)["reason"]; got != tc.reason {
				t.Errorf("reason = %q, want %q", got, tc.reason)
			}
			args, ran := recorder.execArgsOf("db_remote_last_error=?")
			if !ran {
				t.Fatal("the failure was not recorded, so the screen cannot say what happened")
			}
			if message, _ := args[0].(string); !strings.Contains(message, tc.err.Error()) {
				t.Errorf("recorded %q, want the apply failure", message)
			}
			if _, saved := recorder.execArgsOf("SET db_remote_enabled=?"); saved {
				t.Error("the setting was saved although nothing was applied")
			}
			if calls.rebuilds != 0 {
				t.Error("the firewall was rebuilt for a switch that did not move")
			}
		})
	}
}

// The setting is what every later boot reads, so a save that fails is reported
// rather than answered with the screen.
func TestTheSwitchReportsASettingItCouldNotSave(t *testing.T) {
	calls := fakeHost(t)
	h := &Handlers{
		DB: statusDB(t, &statusRecorder{execErr: map[string]error{
			"SET db_remote_enabled=?": errors.New("read-only server"),
		}}),
		RebuildFirewall: withRebuild(calls),
	}

	response := setSwitch(h, `{"enabled":true}`)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", response.Code, response.Body)
	}
	if got := answerOf(t, response)["error"]; got != "could not save the remote access setting" {
		t.Errorf("message = %q", got)
	}
}

// The accepted path: MariaDB is applied, the setting is stored as the switch
// position, the firewall follows, and the answer is the admin view.
func TestAnAcceptedSwitchAppliesThenSavesThenRebuilds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		body  string
		want  bool
		saved int64
	}{
		{name: "on", body: `{"enabled":true}`, want: true, saved: 1},
		{name: "off", body: `{"enabled":false}`, want: false, saved: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := fakeHost(t)
			recorder := &statusRecorder{}
			h := &Handlers{DB: statusDB(t, recorder), RebuildFirewall: withRebuild(calls)}

			response := setSwitch(h, tc.body)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", response.Code, response.Body)
			}
			if len(calls.applied) != 1 || calls.applied[0] != tc.want {
				t.Fatalf("applied %v, want one %v", calls.applied, tc.want)
			}
			args, ran := recorder.execArgsOf("SET db_remote_enabled=?")
			if !ran || args[0] != tc.saved {
				t.Errorf("saved %v, want %d", args, tc.saved)
			}
			if calls.rebuilds != 1 {
				t.Errorf("the firewall was rebuilt %d times, want once", calls.rebuilds)
			}
		})
	}
}

// A firewall rebuild that fails does not undo an applied switch: the setting is
// stored and the screen is answered, because the port state is repaired at the
// next boot while a half-saved switch is not.
func TestAFailedRebuildDoesNotUndoAnAppliedSwitch(t *testing.T) {
	calls := fakeHost(t)
	calls.rebuildErr = errors.New("nft: no such table")
	recorder := &statusRecorder{}
	h := &Handlers{DB: statusDB(t, recorder), RebuildFirewall: withRebuild(calls)}

	response := setSwitch(h, `{"enabled":true}`)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body)
	}
	if _, saved := recorder.execArgsOf("SET db_remote_enabled=?"); !saved {
		t.Error("the switch was not saved")
	}
}

// A request the add handler cannot use is refused before the grant.
func TestAnAddIsRefusedBeforeTheGrant(t *testing.T) {
	for _, tc := range []struct {
		name     string
		domainID string
		body     string
		enabled  bool
		status   int
		reason   string
		message  string
	}{
		{
			name: "the domain id is not a number", domainID: "abc", body: `{}`,
			status: http.StatusBadRequest, message: "invalid domain id",
		},
		{
			name: "the body is not JSON", domainID: "1", body: "{",
			status: http.StatusBadRequest, message: "invalid request body",
		},
		{
			name: "an IPv6 range", domainID: "1", enabled: true,
			body:   `{"db_user":"c_site_app","host":"2001:db8::/64"}`,
			status: http.StatusBadRequest, reason: reasonIPv6Range,
		},
		{
			name: "a range covering the internet", domainID: "1", enabled: true,
			body:   `{"db_user":"c_site_app","host":"0.0.0.0/0"}`,
			status: http.StatusBadRequest, reason: reasonHostTooBroad,
		},
		{
			name: "a wildcard", domainID: "1", enabled: true,
			body:   `{"db_user":"c_site_app","host":"%"}`,
			status: http.StatusBadRequest, reason: reasonHostInvalid,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := fakeHost(t)
			h := &Handlers{
				DB:              statusDB(t, &statusRecorder{enabled: tc.enabled}),
				RebuildFirewall: withRebuild(calls),
			}

			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/domains/x/db-remote", strings.NewReader(tc.body))
			h.DomainAdd(response, withDomainParam(request, tc.domainID))

			if response.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, tc.status, response.Body)
			}
			body := answerOf(t, response)
			if tc.reason != "" && body["reason"] != tc.reason {
				t.Errorf("reason = %q, want %q", body["reason"], tc.reason)
			}
			if tc.message != "" && body["error"] != tc.message {
				t.Errorf("message = %q, want %q", body["error"], tc.message)
			}
			if len(calls.granted) != 0 {
				t.Errorf("a grant was made anyway: %v", calls.granted)
			}
		})
	}
}

// A grant MariaDB refuses leaves no row behind: a row without a grant shows a
// customer an access that does not exist.
func TestARefusedGrantWritesNoRow(t *testing.T) {
	calls := fakeHost(t)
	calls.grantErr = errors.New("ERROR 1045 (28000)")
	recorder := &statusRecorder{enabled: true}
	h := &Handlers{DB: statusDB(t, recorder), RebuildFirewall: withRebuild(calls)}

	response := addHost(h, `{"db_user":"c_site_app","host":"203.0.113.7"}`)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", response.Code, response.Body)
	}
	if got := answerOf(t, response)["reason"]; got != reasonApplyFailed {
		t.Errorf("reason = %q, want %q", got, reasonApplyFailed)
	}
	if _, wrote := recorder.execArgsOf("INSERT INTO db_remote_hosts"); wrote {
		t.Error("the address was recorded although MariaDB refused the account")
	}
	if calls.rebuilds != 0 {
		t.Error("the port was opened for an account that does not exist")
	}
}

// A row that cannot be written undoes the grant: an account reachable from an
// address the panel has no record of is a credential nobody can find.
func TestARowThatCannotBeWrittenUndoesTheGrant(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		reason string
	}{
		{
			name:   "the address is already allowed",
			err:    errors.New("Error 1062: Duplicate entry 'x' for key 'uniq'"),
			status: http.StatusConflict,
			reason: reasonDuplicate,
		},
		{
			name:   "the write failed for another reason",
			err:    errors.New("read-only server"),
			status: http.StatusInternalServerError,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := fakeHost(t)
			h := &Handlers{
				DB: statusDB(t, &statusRecorder{enabled: true, execErr: map[string]error{
					"INSERT INTO db_remote_hosts": tc.err,
				}}),
				RebuildFirewall: withRebuild(calls),
			}

			response := addHost(h, `{"db_user":"c_site_app","host":"203.0.113.7"}`)

			if response.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, tc.status, response.Body)
			}
			if tc.reason != "" {
				if got := answerOf(t, response)["reason"]; got != tc.reason {
					t.Errorf("reason = %q, want %q", got, tc.reason)
				}
			}
			if len(calls.revoked) != 1 {
				t.Errorf("revoked %v, want the grant undone once", calls.revoked)
			}
		})
	}
}

// The port is the last step, and a firewall that could not be updated is
// reported: the row exists but the address cannot reach anything, and an
// operator told nothing would read the screen as success.
func TestAFailedRebuildIsReportedByTheAdd(t *testing.T) {
	calls := fakeHost(t)
	calls.rebuildErr = errors.New("nft: no such table")
	h := &Handlers{DB: statusDB(t, &statusRecorder{enabled: true}), RebuildFirewall: withRebuild(calls)}

	response := addHost(h, `{"db_user":"c_site_app","host":"203.0.113.7"}`)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", response.Code, response.Body)
	}
	if got := answerOf(t, response)["reason"]; got != reasonApplyFailed {
		t.Errorf("reason = %q, want %q", got, reasonApplyFailed)
	}
}

// The accepted path, in order: grant, then the row, then the port. The label is
// cut to the column width rather than refused.
func TestAnAcceptedAddGrantsThenRecordsThenOpensThePort(t *testing.T) {
	calls := fakeHost(t)
	recorder := &statusRecorder{enabled: true}
	h := &Handlers{DB: statusDB(t, recorder), RebuildFirewall: withRebuild(calls)}

	long := strings.Repeat("l", 100)
	response := addHost(h, `{"db_user":"c_site_app","host":"203.0.113.7","label":"`+long+`"}`)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want the refreshed list: %s", response.Code, response.Body)
	}
	if len(calls.granted) != 1 || !strings.HasPrefix(calls.granted[0], "c_site_app@203.0.113.7 ") {
		t.Fatalf("granted %v, want the account for the address", calls.granted)
	}
	if !strings.HasSuffix(calls.granted[0], " c_site_app_db") {
		t.Errorf("granted %v, want every database the account owns", calls.granted)
	}
	args, wrote := recorder.execArgsOf("INSERT INTO db_remote_hosts")
	if !wrote {
		t.Fatal("the address was not recorded")
	}
	label, _ := args[4].(string)
	if len(label) != 64 {
		t.Errorf("stored label is %d characters, want it cut to 64", len(label))
	}
	if calls.rebuilds != 1 {
		t.Errorf("the firewall was rebuilt %d times, want once", calls.rebuilds)
	}
	if len(calls.revoked) != 0 {
		t.Errorf("an accepted add revoked the grant: %v", calls.revoked)
	}
}

// Withdrawing runs in the reverse order: the row goes, then the port closes,
// then MariaDB loses the account. Anything else leaves a window in which the
// credential still works from an address the panel says is gone.
func TestWithdrawingClosesThePortBeforeDroppingTheAccount(t *testing.T) {
	calls := fakeHost(t)
	recorder := &statusRecorder{enabled: true, hostRow: []driver.Value{"c_site_app", "203.0.113.7"}}
	h := &Handlers{DB: statusDB(t, recorder), RebuildFirewall: withRebuild(calls)}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/domains/1/db-remote/4", nil)
	h.DomainDelete(response, withHostParam(withDomainParam(request, "1"), "4"))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want the refreshed list: %s", response.Code, response.Body)
	}
	if _, removed := recorder.execArgsOf("DELETE FROM db_remote_hosts"); !removed {
		t.Error("the row survived the withdrawal")
	}
	if calls.rebuilds != 1 {
		t.Errorf("the firewall was rebuilt %d times, want once", calls.rebuilds)
	}
	// The stored mysql_host is used verbatim, because deriving it again would
	// fail to drop an account written under an earlier conversion.
	if len(calls.revoked) != 1 || calls.revoked[0] != "c_site_app@203.0.113.7" {
		t.Errorf("revoked %v, want the stored account", calls.revoked)
	}
}

// An entry that is not there is a 404, and an account MariaDB still holds after
// the row is gone is reported rather than hidden.
func TestWithdrawingReportsWhatItCouldNotFinish(t *testing.T) {
	for _, tc := range []struct {
		name     string
		recorder *statusRecorder
		revoke   error
		status   int
	}{
		{
			name:     "the entry is not there",
			recorder: &statusRecorder{enabled: true},
			status:   http.StatusNotFound,
		},
		{
			name:     "MariaDB still holds the account",
			recorder: &statusRecorder{enabled: true, hostRow: []driver.Value{"c_site_app", "203.0.113.7"}},
			revoke:   errors.New("ERROR 1045 (28000)"),
			status:   http.StatusInternalServerError,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := fakeHost(t)
			calls.revokeErr = tc.revoke
			h := &Handlers{DB: statusDB(t, tc.recorder), RebuildFirewall: withRebuild(calls)}

			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodDelete, "/domains/1/db-remote/4", nil)
			h.DomainDelete(response, withHostParam(withDomainParam(request, "1"), "4"))

			if response.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, tc.status, response.Body)
			}
		})
	}
}
