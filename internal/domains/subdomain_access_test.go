package domains

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The four IP access handlers act on the domain or on one of its subdomains,
// decided by the {sid} URL parameter. These tests pin which table each scope
// reads and writes, and that a {sid} belonging to another domain is refused.

const (
	domainLookupQuery = "SELECT system_user, COALESCE(php_version"
	subOwnerQuery     = "FROM subdomains WHERE id=? AND domain_id=?"
)

// accessScript answers the domain lookup every access handler starts with.
func accessScript() *sqlScript {
	script := newScript()
	script.rows[domainLookupQuery] = [][]driver.Value{{"c_example_com", "8.3"}}
	return script
}

// ranWith reports whether the script ran a statement holding the fragment.
func ranWith(script *sqlScript, fragment string) bool {
	script.mu.Lock()
	defer script.mu.Unlock()
	for _, step := range script.steps {
		if strings.Contains(step, fragment) {
			return true
		}
	}
	return false
}

// noRerender stands in for subdomain.ReRender, which the handler calls after a
// change. It records that the subdomain's vhost was republished.
func noRerender(republished *int64) func(*sql.DB, int64) error {
	return func(_ *sql.DB, subdomainID int64) error {
		*republished = subdomainID
		return nil
	}
}

func TestTheSubdomainScopeReadsItsOwnRules(t *testing.T) {
	script := accessScript()
	script.rows[subOwnerQuery] = [][]driver.Value{{int64(7)}}
	script.rows["FROM subdomain_ip_access"] = [][]driver.Value{{"allow"}}
	script.rows["FROM subdomain_ip_rules"] = [][]driver.Value{{int64(1), "203.0.113.7", "2026-01-01 10:00"}}

	h := &Handlers{DB: scriptDB(t, script)}
	recorder := httptest.NewRecorder()
	h.ListIPRules(recorder, requestWithParams(http.MethodGet, "", map[string]string{"id": "4", "sid": "7"}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Mode  string `json:"mode"`
		Rules []struct {
			IPCIDR string `json:"ip_cidr"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode the response: %v", err)
	}
	if body.Mode != "allow" || len(body.Rules) != 1 || body.Rules[0].IPCIDR != "203.0.113.7" {
		t.Errorf("response = %+v, want the subdomain's own mode and rule", body)
	}
	if ranWith(script, "FROM domain_ip_rules") {
		t.Error("the subdomain scope read the domain's rules")
	}
}

// A {sid} that belongs to another domain must not reach that subdomain's rules
// through this domain's URL.
func TestASubdomainOfAnotherDomainIsRefused(t *testing.T) {
	script := accessScript()
	script.rows[subOwnerQuery] = [][]driver.Value{}

	h := &Handlers{DB: scriptDB(t, script)}
	recorder := httptest.NewRecorder()
	h.ListIPRules(recorder, requestWithParams(http.MethodGet, "", map[string]string{"id": "4", "sid": "9"}))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
	if ranWith(script, "FROM subdomain_ip_rules") {
		t.Error("a refused subdomain still had its rules read")
	}
}

// Saving a mode writes the subdomain's own row and republishes that
// subdomain's vhost, not the parent domain's.
func TestSavingASubdomainModeRepublishesThatSubdomain(t *testing.T) {
	script := accessScript()
	script.rows[subOwnerQuery] = [][]driver.Value{{int64(7)}}
	var republished int64
	h := &Handlers{DB: scriptDB(t, script), RerenderSubdomain: noRerender(&republished)}

	recorder := httptest.NewRecorder()
	h.SetIPRulesMode(recorder,
		requestWithParams(http.MethodPut, `{"mode":"allow"}`, map[string]string{"id": "4", "sid": "7"}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", recorder.Code, recorder.Body.String())
	}
	if !ranWith(script, "INSERT INTO subdomain_ip_access") {
		t.Errorf("the subdomain access row was not written; statements = %v", script.steps)
	}
	if ranWith(script, "UPDATE domains SET ip_access_mode") {
		t.Error("the parent domain's mode was changed")
	}
	if republished != 7 {
		t.Errorf("republished subdomain = %d, want 7", republished)
	}
}

// Adding a rule to a subdomain writes the subdomain table. The domain scope is
// the negative half: the same handler must still write the domain table when no
// {sid} is present.
func TestAddingARuleFollowsTheScope(t *testing.T) {
	sub := accessScript()
	sub.rows[subOwnerQuery] = [][]driver.Value{{int64(7)}}
	var republished int64
	h := &Handlers{DB: scriptDB(t, sub), RerenderSubdomain: noRerender(&republished)}
	recorder := httptest.NewRecorder()
	h.AddIPRule(recorder,
		requestWithParams(http.MethodPost, `{"ip_cidr":"203.0.113.7"}`, map[string]string{"id": "4", "sid": "7"}))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("subdomain status = %d, body %s", recorder.Code, recorder.Body.String())
	}
	if !ranWith(sub, "INSERT INTO subdomain_ip_rules") {
		t.Errorf("the subdomain rule was not written; statements = %v", sub.steps)
	}

	domain := accessScript()
	h = &Handlers{DB: scriptDB(t, domain)}
	recorder = httptest.NewRecorder()
	h.AddIPRule(recorder,
		requestWithParams(http.MethodPost, `{"ip_cidr":"203.0.113.7"}`, map[string]string{"id": "4"}))
	if !ranWith(domain, "INSERT INTO domain_ip_rules") {
		t.Errorf("the domain rule was not written; statements = %v", domain.steps)
	}
}
