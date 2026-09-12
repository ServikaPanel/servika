package firewall

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A template writes several rules in one request. Both database errors it can
// meet used to be the skip path, so a run that stored nothing still answered
// 200 with ok:true and the operator was told the firewall carried a protection
// it did not carry. These tests measure what the answer says about what was
// stored, and that the rules that WERE stored still reach nftables.

// applyTemplate posts one template and returns the response.
func applyTemplate(h *Handlers, name string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	body := strings.NewReader(`{"template":"` + name + `"}`)
	h.Template(response, httptest.NewRequest(http.MethodPost, "/firewall/template", body))
	return response
}

// addedOf reads the stored-rule count out of an accepted answer.
func addedOf(t *testing.T, response *httptest.ResponseRecorder) float64 {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("the answer is not JSON: %s", response.Body.String())
	}
	added, ok := body["added"].(float64)
	if !ok {
		t.Fatalf("the answer carries no rule count: %s", response.Body.String())
	}
	return added
}

// countStatements returns how many executed statements carry the fragment.
func countStatements(script *fwScript, fragment string) int {
	total := 0
	for _, statement := range script.execs {
		if strings.Contains(statement, fragment) {
			total++
		}
	}
	return total
}

// The plain path: every rule of the template is stored once and counted.
func TestATemplateStoresEveryRuleItCarries(t *testing.T) {
	stubSSHPorts(t, []int{22})
	stubPanelPorts(t, []int{8080, 8443})
	_, _ = fakeHost(t)
	script := &fwScript{}
	h := &Handlers{DB: fwDB(t, script)}

	response := applyTemplate(h, "close_mail")

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body)
	}
	if got := addedOf(t, response); got != 5 {
		t.Errorf("added = %v, want the five mail rules", got)
	}
	if got := countStatements(script, "INSERT INTO firewall_rules"); got != 5 {
		t.Errorf("%d rules were stored, want five", got)
	}
}

// A rule that is already there is not stored twice, and the answer says so.
func TestATemplateAppliedTwiceStoresNothingMore(t *testing.T) {
	stubSSHPorts(t, []int{22})
	stubPanelPorts(t, []int{8080, 8443})
	_, _ = fakeHost(t)
	script := &fwScript{templateCount: 1}
	h := &Handlers{DB: fwDB(t, script)}

	response := applyTemplate(h, "close_mail")

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body)
	}
	if got := addedOf(t, response); got != 0 {
		t.Errorf("added = %v, want nothing", got)
	}
	if got := countStatements(script, "INSERT INTO firewall_rules"); got != 0 {
		t.Errorf("%d rules were stored again", got)
	}
}

// A rule the table would not take is reported. Answering 200 here told the
// operator the mail ports were closed while every one of them was still open.
func TestATemplateThatCouldNotStoreARuleIsReported(t *testing.T) {
	stubSSHPorts(t, []int{22})
	stubPanelPorts(t, []int{8080, 8443})
	calls, _ := fakeHost(t)
	script := &fwScript{execErr: map[string]error{
		"INSERT INTO firewall_rules": errors.New("read-only server"),
	}}
	h := &Handlers{DB: fwDB(t, script)}

	response := applyTemplate(h, "close_mail")

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", response.Code, response.Body)
	}
	want := "the template was applied only in part; some rules could not be stored"
	if got := errorOf(t, response); got != want {
		t.Errorf("message = %q, want %q", got, want)
	}
	// The rules written before the failure still have to reach nftables: a row
	// the packet filter never received would be applied later by an unrelated
	// rebuild that nobody connected to this template.
	if len(calls.applied) != 1 {
		t.Errorf("nft applied %d rulesets, want one", len(calls.applied))
	}
}

// A duplicate check that failed left the count at zero, which reads as "the
// rule is not there", so the template stored a second copy of a rule that was
// already stored. The failure is now reported and nothing is written after it.
func TestATemplateStopsWhenItCannotReadTheStoredRules(t *testing.T) {
	stubSSHPorts(t, []int{22})
	stubPanelPorts(t, []int{8080, 8443})
	_, _ = fakeHost(t)
	script := &fwScript{queryErr: map[string]error{
		"SELECT COUNT(*) FROM firewall_rules": errors.New("connection reset"),
	}}
	h := &Handlers{DB: fwDB(t, script)}

	response := applyTemplate(h, "close_mail")

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", response.Code, response.Body)
	}
	if got := countStatements(script, "INSERT INTO firewall_rules"); got != 0 {
		t.Errorf("%d rules were stored although the duplicate check failed", got)
	}
}
