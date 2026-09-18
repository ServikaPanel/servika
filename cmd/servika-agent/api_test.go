package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"servika/internal/platform"
)

// fakeProvider stands in for the host so the API's shape can be measured
// anywhere, not only on Windows.
type fakeProvider struct {
	caps      platform.Capability
	verifyErr error
}

func (f fakeProvider) Name() string                      { return "windows" }
func (f fakeProvider) Capabilities() platform.Capability { return f.caps }
func (f fakeProvider) Verify() error                     { return f.verifyErr }

func (f fakeProvider) CreateSite(platform.SiteRequest) (platform.SiteResult, error) {
	return platform.SiteResult{}, platform.ErrUnsupported
}
func (f fakeProvider) DeleteSite(platform.SiteID) error { return platform.ErrUnsupported }
func (f fakeProvider) IssueSSL(platform.SSLRequest) (platform.Certificate, error) {
	return platform.Certificate{}, platform.ErrUnsupported
}

// callHealth runs the health handler and returns the decoded answer.
func callHealth(t *testing.T, p platform.Provider) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	healthHandler(p)(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("health answered %d", rec.Code)
	}
	var got map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("the health answer could not be decoded: %v", err)
	}
	return got
}

func TestTheHealthAnswerCarriesEveryFieldThePanelReads(t *testing.T) {
	// internal/winagent decodes platform, version, channel, capabilities and
	// env_error. A missing field reads as an empty value and the panel records
	// an agent it cannot use.
	got := callHealth(t, fakeProvider{caps: platform.CapSite | platform.CapEventLog})
	for _, field := range []string{"platform", "version", "channel", "capabilities", "env_error", "selftested"} {
		if _, found := got[field]; !found {
			t.Errorf("the health answer has no %q field", field)
		}
	}
	if got["platform"] != "windows" {
		t.Fatalf("the panel refuses anything but windows; this answered %v", got["platform"])
	}
	if got["version"] != platform.Version || got["channel"] != platform.Channel {
		t.Fatalf("the version or channel does not match the build: %v", got)
	}
}

func TestABrokenEnvironmentIsReportedRatherThanHidden(t *testing.T) {
	// The panel has to tell "unreachable" apart from "reachable but not ready".
	got := callHealth(t, fakeProvider{verifyErr: errors.New("IIS is not installed")})
	if got["env_error"] != "IIS is not installed" {
		t.Fatalf("the environment failure read as %v", got["env_error"])
	}
	// A failing environment still answers 200: a host that cannot serve a site
	// is not the same as a host nobody can reach.
	if got["selftested"] != false {
		t.Fatalf("an unsealed host reported itself selftested: %v", got["selftested"])
	}
}

func TestAHealthyHostReportsNoEnvironmentFailure(t *testing.T) {
	got := callHealth(t, fakeProvider{caps: platform.CapSite})
	if got["env_error"] != "" {
		t.Fatalf("a healthy host reported %v", got["env_error"])
	}
	if got["selftested"] != true {
		t.Fatal("a host with site management open did not report itself selftested")
	}
}

func TestTheCapabilityBitsTravelAsANumber(t *testing.T) {
	// The panel stores them in an INT UNSIGNED column, so the wire form has to
	// be the numeric mask rather than a list of names.
	caps := platform.CapSite | platform.CapMSSQL
	got := callHealth(t, fakeProvider{caps: caps})
	value, ok := got["capabilities"].(float64)
	if !ok {
		t.Fatalf("the capabilities came through as %T", got["capabilities"])
	}
	if uint32(value) != uint32(caps) {
		t.Fatalf("the capability mask read %d, expected %d", uint32(value), uint32(caps))
	}
}

func TestARequestWithoutTheRightTokenIsRefused(t *testing.T) {
	var reached bool
	handler := authorized("the-real-token", func(http.ResponseWriter, *http.Request) { reached = true })
	for _, given := range []string{"", "the-real-tokeX", "the-real-toke", "the-real-token2", "THE-REAL-TOKEN"} {
		reached = false
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		if given != "" {
			req.Header.Set(tokenHeader, given)
		}
		handler(rec, req)
		if reached {
			t.Fatalf("the token %q reached the handler", given)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("the token %q answered %d", given, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set(tokenHeader, "the-real-token")
	handler(rec, req)
	if !reached {
		t.Fatal("the right token was refused")
	}
}

func TestTheTokenIsReadFromTheHeaderThePanelSends(t *testing.T) {
	// internal/winagent sends X-Servika-Token. A rename on one side alone breaks
	// every agent already paired.
	if tokenHeader != "X-Servika-Token" {
		t.Fatalf("the token header is %q, which the panel does not send", tokenHeader)
	}
	handler := authorized("t", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Authorization", "Bearer t") // the wrong carrier on purpose
	handler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatal("the token was accepted from the Authorization header, which the panel never uses")
	}
}

func TestABodyLargerThanTheLimitIsRefused(t *testing.T) {
	// Every request this API takes is a small JSON object.
	body := `{"domain":"` + strings.Repeat("a", requestLimit*2) + `"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/site", strings.NewReader(body))
	var into struct {
		Domain string `json:"domain"`
	}
	if readRequest(rec, req, &into) {
		t.Fatal("an oversized body was accepted")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an oversized body answered %d", rec.Code)
	}
}

func TestAnOrdinaryBodyIsRead(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/site", strings.NewReader(`{"domain":"shop.example.com"}`))
	var into struct {
		Domain string `json:"domain"`
	}
	if !readRequest(rec, req, &into) {
		t.Fatalf("an ordinary body was refused: %s", rec.Body.String())
	}
	if into.Domain != "shop.example.com" {
		t.Fatalf("the body read as %+v", into)
	}
}
