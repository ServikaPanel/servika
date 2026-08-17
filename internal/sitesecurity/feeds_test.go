package sitesecurity

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// collectorAgainst points a Collector at a test server.
//
// The client is a plain one: the production client carries
// netguard.DialControl, which refuses the loopback address an httptest server
// listens on, and that refusal is the whole point of it being there.
func collectorAgainst(t *testing.T, handler http.Handler) *Collector {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &Collector{
		client:           server.Client(),
		wpFeedBase:       server.URL,
		osvQueryURL:      server.URL + "/v1/query",
		osvQueryBatchURL: server.URL + "/v1/querybatch",
	}
}

// The real record shape, taken from the live feed for contact-form-7. Three
// fields spell "closed" with three different JSON types in one document, and
// operator.unfixed is the STRING "0": decoding it into a bool fails and would
// drop every record.
const wpLiveRecord = `{
  "error": 0,
  "message": null,
  "data": {
    "name": "Contact Form 7",
    "closed": 0,
    "latest": "1778813700",
    "vulnerability": [
      {
        "uuid": "69f4e580612c835bfea455eb87c0aa010b02c26489b2edccc6a5d9b1154113dc",
        "name": "Contact Form 7 [contact-form-7] < 5.3.2",
        "description": null,
        "closed": null,
        "operator": {
          "min_version": null, "min_operator": null,
          "max_version": "5.3.2", "max_operator": "lt",
          "unfixed": "0", "closed": "0"
        },
        "impact": {"cvss3": {"score": 10.0, "severity": "critical"}},
        "source": [
          {"id": "7391118e", "name": "wpscan", "link": "https://wpscan.com/x"},
          {"id": "CVE-2020-35489", "name": "CVE-2020-35489", "link": "https://www.cve.org/CVERecord?id=CVE-2020-35489"}
        ]
      }
    ]
  },
  "updated": 1781708619
}`

func TestTheLiveWordPressRecordDecodesAndMatches(t *testing.T) {
	collector := collectorAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, wpLiveRecord)
	}))

	advisories, judged, err := collector.WordPressAdvisories(context.Background(), "plugin", "contact-form-7", "5.3.1")
	if err != nil {
		t.Fatalf("advisories: %v", err)
	}
	if !judged {
		t.Error("the record could not be judged")
	}
	if len(advisories) != 1 {
		t.Fatalf("got %d advisories, want 1", len(advisories))
	}
	got := advisories[0]
	// The CVE is preferred over the feed's own uuid: it is the identifier an
	// operator can look up anywhere else, and it is half the merge key.
	if got.ID != "CVE-2020-35489" {
		t.Errorf("id is %q, want the CVE", got.ID)
	}
	if got.Severity != "critical" || got.CVSS != 10.0 {
		t.Errorf("severity %q / cvss %v, want critical / 10", got.Severity, got.CVSS)
	}
	// "lt" is the one operator that names a fixed release.
	if got.FixedIn != "5.3.2" {
		t.Errorf("fixed_in is %q, want 5.3.2", got.FixedIn)
	}
	if !strings.Contains(got.Source, "cve.org") {
		t.Errorf("source is %q, want the CVE link", got.Source)
	}
}

// The installed version above the range gets no finding, from the same record.
func TestAPatchedInstallationGetsNoFinding(t *testing.T) {
	collector := collectorAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, wpLiveRecord)
	}))
	advisories, judged, err := collector.WordPressAdvisories(context.Background(), "plugin", "contact-form-7", "5.9.1")
	if err != nil {
		t.Fatalf("advisories: %v", err)
	}
	if !judged {
		t.Error("the record could not be judged")
	}
	if len(advisories) != 0 {
		t.Errorf("got %d advisories for a patched version, want 0", len(advisories))
	}
}

// A slug the feed does not know answers HTTP 200 with error 0 and a NULL
// vulnerability list (measured). Neither the status nor the error field says so,
// and treating it as a failure would mark most sweeps failed.
func TestAnUnknownSlugIsEmptyRatherThanAnError(t *testing.T) {
	const body = `{"error":0,"message":null,"data":{"name":null,"plugin":"zzz","link":null,"latest":null,"closed":null,"vulnerability":null},"updated":1}`
	collector := collectorAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	advisories, judged, err := collector.WordPressAdvisories(context.Background(), "plugin", "zzz", "1.0")
	if err != nil {
		t.Fatalf("an unknown slug was reported as an error: %v", err)
	}
	if !judged {
		t.Error("an unknown slug was counted as unjudged")
	}
	if len(advisories) != 0 {
		t.Errorf("got %d advisories, want 0", len(advisories))
	}
}

// A version the comparison cannot order must be COUNTED as unjudged rather than
// quietly dropped, or a sweep that could judge nothing reads as a clean one.
func TestAnUnjudgeableVersionIsReportedAsSuch(t *testing.T) {
	collector := collectorAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, wpLiveRecord)
	}))
	advisories, judged, err := collector.WordPressAdvisories(context.Background(), "plugin", "contact-form-7", "5.3.1-rc.2")
	if err != nil {
		t.Fatalf("advisories: %v", err)
	}
	if judged {
		t.Error("a pre-release version was reported as judged")
	}
	if len(advisories) != 0 {
		t.Errorf("got %d advisories from an unjudged record, want 0", len(advisories))
	}
}

// The slug reaches a URL path. It is a directory name wp-cli reported, so
// anything outside that character set is refused rather than escaped.
func TestASlugThatIsNotAComponentNameIsRefused(t *testing.T) {
	collector := collectorAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the feed was contacted for a refused slug")
	}))
	for _, slug := range []string{"", "../../etc", "a/b", "a b", "a?b", "..", strings.Repeat("a", 200)} {
		if _, _, err := collector.WordPressAdvisories(context.Background(), "plugin", slug, "1.0"); err == nil {
			t.Errorf("the slug %q was accepted", slug)
		}
	}
}

// A response past the ceiling is refused, and refused AS oversized.
//
// The LimitReader alone would truncate it and the decode would fail, which is
// also an error but the wrong one: an operator reading "invalid character" in
// the log goes looking for a broken feed rather than one that changed shape.
// The message is what this pins, because that is the only difference the
// explicit check makes.
func TestAnOversizedResponseIsRefusedAsOversized(t *testing.T) {
	collector := collectorAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"error":0,"data":{"vulnerability":[`)
		chunk := strings.Repeat(`{"uuid":"x","name":"`+strings.Repeat("y", 900)+`"},`, 1200)
		for range 6 {
			_, _ = io.WriteString(w, chunk)
		}
		_, _ = io.WriteString(w, `{"uuid":"z","name":"z"}]}}`)
	}))
	_, _, err := collector.WordPressAdvisories(context.Background(), "plugin", "big", "1.0")
	if err == nil {
		t.Fatal("an oversized response was accepted")
	}
	if !strings.Contains(err.Error(), "over") || !strings.Contains(err.Error(), "bytes") {
		t.Errorf("the failure reads %q, which does not say the response was too big", err)
	}
}

// The real OSV record shape, taken from the live API for lodash@4.17.15.
const osvLiveRecord = `{"vulns":[{
  "id": "GHSA-29mw-wpgm-hmr9",
  "summary": "Regular Expression Denial of Service (ReDoS) in lodash",
  "aliases": ["CVE-2020-28500"],
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}],
  "database_specific": {"severity": "MODERATE"},
  "references": [
    {"type": "WEB", "url": "https://example.test/web"},
    {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-29mw-wpgm-hmr9"}
  ],
  "affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "4.0.0"}, {"fixed": "4.17.21"}]}]}]
}]}`

// OSV's severity[] carries a CVSS VECTOR, not a base score. Turning that string
// into a number here would be inventing a value the feed did not give, so the
// score stays zero and only the word is taken.
func TestTheOSVVectorIsNotTurnedIntoAScore(t *testing.T) {
	collector := collectorAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, osvLiveRecord)
	}))
	advisories, err := collector.Advisories(context.Background(), ecosystemNPM, Package{Name: "lodash", Version: "4.17.15"})
	if err != nil {
		t.Fatalf("advisories: %v", err)
	}
	if len(advisories) != 1 {
		t.Fatalf("got %d advisories, want 1", len(advisories))
	}
	got := advisories[0]
	if got.CVSS != 0 {
		t.Errorf("cvss is %v; the feed gave a vector, not a score", got.CVSS)
	}
	// GitHub says MODERATE where everything else says medium; the screen sorts
	// on one vocabulary.
	if got.Severity != "medium" {
		t.Errorf("severity is %q, want medium", got.Severity)
	}
	if got.ID != "CVE-2020-28500" {
		t.Errorf("id is %q, want the CVE alias", got.ID)
	}
	if got.FixedIn != "4.17.21" {
		t.Errorf("fixed_in is %q, want 4.17.21", got.FixedIn)
	}
	if !strings.Contains(got.Source, "advisories") {
		t.Errorf("source is %q, want the ADVISORY reference", got.Source)
	}
}

// The batch endpoint answers per query, in order. A short array would shift
// every answer onto the wrong package, which is a finding filed against a
// package that is fine, so it is refused rather than zipped as far as it goes.
func TestAShortBatchAnswerIsRefusedRatherThanMisaligned(t *testing.T) {
	collector := collectorAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"results":[{"vulns":[{"id":"GHSA-x"}]}]}`)
	}))
	_, err := collector.AffectedPackages(context.Background(), ecosystemNPM, []Package{
		{Name: "a", Version: "1.0.0"},
		{Name: "b", Version: "2.0.0"},
	})
	if err == nil {
		t.Error("a short batch answer was accepted")
	}
}

// The batch pass exists to keep a lockfile with hundreds of dependencies from
// becoming hundreds of full requests. It must return exactly the packages whose
// slot carried vulnerabilities.
func TestOnlyThePackagesWithVulnsComeBack(t *testing.T) {
	collector := collectorAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Queries []osvQuery `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode the batch request: %v", err)
		}
		results := make([]map[string]any, 0, len(body.Queries))
		for _, query := range body.Queries {
			if query.Package.Name == "vulnerable" {
				results = append(results, map[string]any{"vulns": []map[string]string{{"id": "GHSA-x"}}})
				continue
			}
			results = append(results, map[string]any{})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	}))

	got, err := collector.AffectedPackages(context.Background(), ecosystemNPM, []Package{
		{Name: "clean-a", Version: "1.0.0"},
		{Name: "vulnerable", Version: "2.0.0"},
		{Name: "clean-b", Version: "3.0.0"},
	})
	if err != nil {
		t.Fatalf("affected packages: %v", err)
	}
	if len(got) != 1 || got[0].Name != "vulnerable" || got[0].Version != "2.0.0" {
		t.Errorf("got %+v, want only vulnerable@2.0.0", got)
	}
}

// The merge key is what stops a re-scan duplicating every finding, and what
// stops two different findings collapsing into one row.
func TestTheMergeKeySeparatesWhatItShould(t *testing.T) {
	base := findingKey(1, "/shop", "plugin:woocommerce", "CVE-2024-1")
	same := findingKey(1, "/shop", "plugin:woocommerce", "CVE-2024-1")
	if base != same {
		t.Error("the same finding produced two keys, so a re-scan would duplicate it")
	}
	for _, other := range []string{
		findingKey(2, "/shop", "plugin:woocommerce", "CVE-2024-1"),
		findingKey(1, "/blog", "plugin:woocommerce", "CVE-2024-1"),
		findingKey(1, "/shop", "plugin:jetpack", "CVE-2024-1"),
		findingKey(1, "/shop", "plugin:woocommerce", "CVE-2024-2"),
	} {
		if other == base {
			t.Error("two different findings produced one key")
		}
	}
	// The NUL separator is what stops adjacent fields running together: without
	// it ("a","bc") and ("ab","c") are one string and one key.
	if findingKey(1, "/x", "a", "bc") == findingKey(1, "/x", "ab", "c") {
		t.Error("adjacent fields ran together into one key")
	}
}
