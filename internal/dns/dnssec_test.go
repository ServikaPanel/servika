package dns

import (
	"context"
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The refusal the customer reads when the zone cannot be rewritten. The acronym
// is the first word of the sentence, and a lowercased "d" moved into the middle
// of it is what the DNSSEC screen shows at the moment the change is refused.
func TestTheDNSSECRefusalNamesTheAcronymCorrectly(t *testing.T) {
	script := newScript()
	script.rows[domainLookup] = [][]driver.Value{{"example.com"}}
	script.rows["COALESCE(dnssec_active,0)"] = [][]driver.Value{{int64(0)}}
	zoneWriteReturns(t, errScripted)

	handlers := &Handlers{DB: scriptDB(t, script)}
	recorder := httptest.NewRecorder()
	handlers.PostDNSSEC(recorder, dnsRequest(http.MethodPost, "/api/v1/domains/7/dns/dnssec", `{"active":true}`, "7"))

	assertResponse(t, recorder, http.StatusInternalServerError, "DNS zone could not be updated")
	if strings.Contains(recorder.Body.String(), "dNS") {
		t.Errorf("the acronym is broken in the message: %s", recorder.Body.String())
	}
}

func TestDNSCommandUsesExplicitArgumentsAndEnvironment(t *testing.T) {
	t.Setenv("SERVIKA_JWT_SECRET", "must-not-leak")
	command := dnsCommand(context.Background(), "dig", "+short", "@127.0.0.1", "example.com", "DNSKEY")
	wantArgs := []string{"dig", "+short", "@127.0.0.1", "example.com", "DNSKEY"}
	if strings.Join(command.Args, "\x00") != strings.Join(wantArgs, "\x00") {
		t.Fatalf("dnsCommand() args = %q, want %q", command.Args, wantArgs)
	}
	environment := strings.Join(command.Env, "\n")
	if strings.Contains(environment, "SERVIKA_JWT_SECRET") {
		t.Fatal("dnsCommand() inherited a panel secret")
	}
	if !strings.Contains(environment, "PATH=/usr/sbin:/usr/bin:/sbin:/bin") {
		t.Fatalf("dnsCommand() environment = %q", command.Env)
	}
}
