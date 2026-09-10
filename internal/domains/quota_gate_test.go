package domains

import (
	"os"
	"strings"
	"testing"
)

// Create provisions a Linux user, an nginx vhost and an FPM pool, so it cannot
// be executed here without a host to build them on. What these assertions pin is
// which customer the plan gate is asked about and where in the sequence it runs,
// which is exactly where the ceiling went missing.
//
// CheckDomainAllowed's own behaviour is proven against a scripted database in
// internal/quota.
func createBody(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	start := strings.Index(body, "func (h *Handlers) Create(w http.ResponseWriter, r *http.Request) {")
	if start < 0 {
		t.Fatal("Create was renamed; these assertions have to follow it")
	}
	end := strings.Index(body[start:], "\nfunc ")
	if end < 0 {
		return body[start:]
	}
	return body[start : start+end]
}

// The gate has to name the customer the domain is being attached to.
//
// CheckDomainAllowed returns on its first branch when the id is nil, because an
// administrator creating an unattached domain has no plan to be limited by.
// Calling it with a literal nil therefore read no plan at all, and a customer on
// a plan allowing one domain could be given any number of them.
func TestTheDomainPlanGateAsksAboutTheRequestedCustomer(t *testing.T) {
	body := createBody(t)
	if !strings.Contains(body, "quota.CheckDomainAllowed(r.Context(), h.DB, req.CustomerID)") {
		t.Error("Create does not check the plan limit against the customer the request names")
	}
	if strings.Contains(body, "quota.CheckDomainAllowed(r.Context(), h.DB, nil)") {
		t.Error("Create passes a literal nil, which short-circuits the plan limit to unlimited")
	}
}

// Order matters in both directions. Before Provision, or a refused request
// leaves a Linux user, a vhost and an FPM pool behind. After
// referencedAccountsExist, or an id naming no customer is answered as a failed
// quota read instead of as a bad request.
func TestTheDomainPlanGateRunsBetweenValidationAndProvisioning(t *testing.T) {
	body := createBody(t)
	validation := strings.Index(body, "h.referencedAccountsExist(")
	gate := strings.Index(body, "quota.CheckDomainAllowed(")
	provision := strings.Index(body, "provisioner.Provision(")
	if validation < 0 || gate < 0 || provision < 0 {
		t.Fatal("one of the three steps is missing from Create")
	}
	if gate < validation {
		t.Error("the plan gate runs before the referenced ids are validated")
	}
	if gate > provision {
		t.Error("the plan gate runs after provisioning, so a refusal leaves a half-built domain")
	}
}
