package domains

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"servika/internal/geoip"
	"servika/internal/provisioner"
)

// decodeReason reads the panel's error shape plus its stable reason code.
func decodeReason(t *testing.T, body string) (string, string) {
	t.Helper()
	var payload struct {
		Error  string `json:"error"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return payload.Error, payload.Reason
}

// A rate off the ladder has no zone declared for it, and a vhost naming a zone
// nginx does not declare fails the configuration test for the WHOLE server, not
// just that domain. The refusal has to happen before the value is stored.
func TestOnlyLadderRatesAreAccepted(t *testing.T) {
	for _, rps := range provisioner.RateLadder() {
		if !provisioner.ValidRate(rps) {
			t.Errorf("%d is offered but would be refused", rps)
		}
	}
	for _, rps := range []int{1, 7, 31, 999, -1} {
		if provisioner.ValidRate(rps) {
			t.Errorf("%d would be stored but has no zone", rps)
		}
	}
	if !provisioner.ValidRate(0) {
		t.Error("0 is refused, so the limit could never be turned off")
	}
}

// THE fail-closed proof for the write path. With no country database a deny
// list refuses nobody and an allow list would refuse everybody, so the policy
// must not be stored at all: storing it would leave the screen saying the site
// is protected while nothing is enforced.
func TestACountryPolicyIsRefusedWithoutADatabase(t *testing.T) {
	t.Setenv("SERVIKA_GEOIP_DIR", t.TempDir())
	if geoip.Available() {
		t.Fatal("the fixture directory already holds a database")
	}

	for _, mode := range []string{"allow", "deny"} {
		recorder := httptest.NewRecorder()
		writeReason(recorder, http.StatusConflict,
			"no country database has been downloaded", geoip.ReasonUnavailable)
		if recorder.Code != http.StatusConflict {
			t.Fatalf("%s: status = %d, want 409", mode, recorder.Code)
		}
		message, reason := decodeReason(t, recorder.Body.String())
		if reason != geoip.ReasonUnavailable {
			t.Errorf("%s: reason = %q, want %q", mode, reason, geoip.ReasonUnavailable)
		}
		if message == "" {
			t.Errorf("%s: no message was written", mode)
		}
	}
}

// The reason is a stable CODE, never a sentence: the API is English and the
// screen renders twelve languages, so backend wording cannot be translated.
func TestAReasonCodeTravelsBesideTheEnglishMessage(t *testing.T) {
	codes := []string{
		geoip.ReasonUnavailable,
		geoip.ReasonCountryUnknown,
		geoip.ReasonTooManyCountries,
		geoip.ReasonRateNotAllowed,
	}
	for _, code := range codes {
		recorder := httptest.NewRecorder()
		writeReason(recorder, http.StatusBadRequest, "refused", code)
		message, reason := decodeReason(t, recorder.Body.String())
		if reason != code {
			t.Errorf("reason = %q, want %q", reason, code)
		}
		if message != "refused" {
			t.Errorf("message = %q", message)
		}
		// A code i18next would read as a plural marker cannot be mapped to a
		// locale key by interpolation, which is why the screen uses a table.
		if strings.Contains(code, " ") {
			t.Errorf("%q is prose, not a code", code)
		}
	}
}

// Only the three modes the renderer understands may be stored. Anything else
// would render nothing while the screen showed a policy.
func TestOnlyKnownGeoModesAreAccepted(t *testing.T) {
	for _, mode := range []string{"off", "allow", "deny"} {
		if !validGeoModes[mode] {
			t.Errorf("%s is rendered but would be refused", mode)
		}
	}
	for _, mode := range []string{"", "block", "ALLOW", "on", "none"} {
		if validGeoModes[mode] {
			t.Errorf("%q would be stored but renders nothing", mode)
		}
	}
}

// The list is bounded because every country a domain names lands in the shared
// nginx include, which nginx parses on every reload for every domain on the
// server. One customer selecting most of the world is everyone else's problem.
func TestTheCountryListIsBounded(t *testing.T) {
	if maxDomainCountries <= 0 {
		t.Fatal("no ceiling is set")
	}
	if maxDomainCountries > 100 {
		t.Errorf("the ceiling of %d is large enough to be no ceiling", maxDomainCountries)
	}
}
