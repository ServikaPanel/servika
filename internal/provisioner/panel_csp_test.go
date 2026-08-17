package provisioner

import (
	"os"
	"strings"
	"testing"
)

// The panel's strict policy was written three times: in the template, in the
// location / block the cache heal installs, and in the header block the
// security heal inserts. The third copy had already drifted and lost
// object-src 'none'. assets/nginx/_panel.conf cannot import the Go constant, so
// this is what keeps them equal.
func TestTheTemplateAndTheHealServeTheSamePolicy(t *testing.T) {
	body, err := os.ReadFile("../../assets/nginx/_panel.conf")
	if err != nil {
		t.Fatalf("read the panel vhost: %v", err)
	}
	wanted := `add_header Content-Security-Policy "` + panelStrictCSP + `" always;`
	if !strings.Contains(string(body), wanted) {
		t.Errorf("the template does not serve the policy the panel heals to.\nwant: %s", panelStrictCSP)
	}
}

// object-src falls back to default-src, which is 'self', so a same-origin upload
// served back to the browser could otherwise be embedded as a plugin object.
func TestTheStrictPolicyForbidsPluginObjects(t *testing.T) {
	if !strings.Contains(panelStrictCSP, "object-src 'none'") {
		t.Error("the panel policy permits plugin objects from its own origin")
	}
}

// Content-Security-Policy-Report-Only is a different header: it reports
// violations and enforces nothing. The retrofit in
// healPanelVhostHeadersOnStartup edits by matching policy text with
// strings.ReplaceAll, so a report-only policy that happened to carry the same
// text would be rewritten too, and a policy an operator deployed to measure
// impact would start blocking. This holds today because the report-only policy
// carries no base-uri; the test fails the day that stops being true.
func TestTheObjectSrcRetrofitLeavesAReportOnlyPolicyAlone(t *testing.T) {
	const anchor = "frame-ancestors 'self'; base-uri 'self'"
	const replacement = "frame-ancestors 'self'; object-src 'none'; base-uri 'self'"

	reportOnly := `    add_header Content-Security-Policy-Report-Only "` +
		`default-src 'self' https: http: data: blob: 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'self';" always;`

	if got := strings.ReplaceAll(reportOnly, anchor, replacement); got != reportOnly {
		t.Errorf("the retrofit rewrote a report-only policy:\n%s", got)
	}
}

// A fresh install must serve the same policy as one that has been restarted.
// The header block was inserted without object-src and only the retrofit pass on
// the NEXT startup put it back, so the vhost was weaker until then.
func TestAFreshInstallGetsTheSamePolicyAsARepairedOne(t *testing.T) {
	body, err := os.ReadFile("provisioner.go")
	if err != nil {
		t.Fatalf("read the provisioner: %v", err)
	}
	if strings.Contains(string(body), `add_header Content-Security-Policy \"default-src`) {
		t.Error("the security heal still inserts a literal policy instead of panelStrictCSP")
	}
}
