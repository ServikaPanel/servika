package dbremote

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Every refusal a screen has to distinguish carries a stable CODE. The API is
// English and the panel renders twelve languages, so a screen that matched the
// message would break on the first wording change.
func TestEveryReasonCodeIsStable(t *testing.T) {
	source, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`reasonServerDisabled   = "db_remote_server_disabled"`,
		`reasonHostInvalid      = "db_remote_host_invalid"`,
		`reasonIPv6Range        = "db_remote_ipv6_range_unsupported"`,
		`reasonHostTooBroad     = "db_remote_host_too_broad"`,
		`reasonPortRuleConflict = "db_remote_port_rule_conflict"`,
		`reasonDuplicate        = "db_remote_duplicate"`,
		`reasonApplyFailed      = "db_remote_apply_failed"`,
		`reasonUnknownUser      = "db_remote_unknown_user"`,
	} {
		if !strings.Contains(string(source), want) {
			t.Errorf("the reason code changed or went missing: %s", want)
		}
	}
}

// A range MariaDB cannot express is not a typo, so it must not be reported as
// one: the customer would go looking for a mistake that is not there.
func TestAnIPv6RangeIsReportedAsItsOwnLimitation(t *testing.T) {
	_, _, err := ParseHost("2001:db8::/64")
	if got := hostReason(err); got != reasonIPv6Range {
		t.Errorf("hostReason = %q, want %q", got, reasonIPv6Range)
	}
	_, _, err = ParseHost("0.0.0.0/0")
	if got := hostReason(err); got != reasonHostTooBroad {
		t.Errorf("hostReason = %q, want %q", got, reasonHostTooBroad)
	}
	_, _, err = ParseHost("%")
	if got := hostReason(err); got != reasonHostInvalid {
		t.Errorf("hostReason = %q, want %q", got, reasonHostInvalid)
	}
}

// The switch is refused while an operator's own rule targets the same port,
// because that rule is rendered ABOVE this feature's block and wins. Storing
// the switch anyway would leave the screen saying remote access is on while
// every connection was dropped.
func TestTheSwitchIsRefusedWhileAFirewallRuleTargetsThePort(t *testing.T) {
	handlers := &Handlers{DB: statusDB(t, &statusRecorder{portRules: 1})}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/admin/db-remote",
		strings.NewReader(`{"enabled":true}`))
	handlers.ServerSet(recorder, request)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", recorder.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["reason"] != reasonPortRuleConflict {
		t.Errorf("reason = %q, want %q", body["reason"], reasonPortRuleConflict)
	}
}

// Turning the switch OFF is never refused by that check: an operator has to be
// able to close remote access whatever else is configured.
func TestTurningTheSwitchOffIsNeverBlockedByAPortRule(t *testing.T) {
	handlers := &Handlers{DB: statusDB(t, &statusRecorder{portRules: 1})}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/admin/db-remote",
		strings.NewReader(`{"enabled":false}`))
	handlers.ServerSet(recorder, request)

	if recorder.Code == http.StatusConflict {
		t.Errorf("closing remote access was refused because of a firewall rule: %s", recorder.Body)
	}
}

// Adding an address while the server switch is off must be refused with the
// code that says so, rather than silently creating an account nothing can reach.
func TestAddingAnAddressIsRefusedWhileTheServerSwitchIsOff(t *testing.T) {
	handlers := &Handlers{DB: statusDB(t, &statusRecorder{})}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/domains/1/db-remote",
		strings.NewReader(`{"db_user":"c_site_app","host":"203.0.113.7"}`))
	handlers.DomainAdd(recorder, withDomainParam(request, "1"))

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", recorder.Code, recorder.Body)
	}
	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["reason"] != reasonServerDisabled {
		t.Errorf("reason = %q, want %q", body["reason"], reasonServerDisabled)
	}
}

// The account must belong to the domain in the URL. The route is CustomerScope,
// so the caller owns that domain; without this check they could still name a
// neighbour's database user and open it to an address of their choosing.
func TestANeighboursDatabaseUserCannotBeOpened(t *testing.T) {
	// The account is real and belongs to ANOTHER domain, so only the query's own
	// narrowing keeps it out of reach. A fixture where the user simply does not
	// exist would pass with the ownership check deleted.
	handlers := &Handlers{DB: statusDB(t, &statusRecorder{
		enabled:  true,
		accounts: map[string]int64{"c_other_app": 2},
	})}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/domains/1/db-remote",
		strings.NewReader(`{"db_user":"c_other_app","host":"203.0.113.7"}`))
	handlers.DomainAdd(recorder, withDomainParam(request, "1"))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body)
	}
	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["reason"] != reasonUnknownUser {
		t.Errorf("reason = %q, want %q", body["reason"], reasonUnknownUser)
	}
}

// The domain-scoped list is narrowed in the QUERY, because a row-by-row check
// cannot secure a list endpoint.
func TestTheDomainListIsNarrowedInTheQuery(t *testing.T) {
	recorder := &statusRecorder{enabled: true}
	handlers := &Handlers{DB: statusDB(t, recorder)}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/domains/7/db-remote", nil)
	handlers.DomainList(response, withDomainParam(request, "7"))

	if !recorder.saw("WHERE h.domain_id = ?") {
		t.Errorf("the list was not narrowed by domain:\n%s", strings.Join(recorder.queries, "\n"))
	}
}
