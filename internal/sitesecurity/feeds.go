package sitesecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"servika/internal/netguard"
)

// Everything a feed returns is third-party input. It is read with the same
// discipline internal/mailreport applies to a DMARC report: a ceiling on the
// response, a ceiling on how many records are taken from it, and a decode
// failure that drops the PACKAGE rather than the sweep.
const (
	// maxResponseBytes bounds one feed response. A plugin with a long history
	// answers in tens of kilobytes; a megabyte is already a feed that has
	// changed shape.
	maxResponseBytes = 4 << 20

	// maxRecordsPerPackage bounds how many advisories are taken from one
	// response. A package with more than this is either extraordinary or the
	// feed is broken, and either way the screen cannot show them all.
	maxRecordsPerPackage = 100

	// feedTimeout is one request's budget.
	feedTimeout = 20 * time.Second
)

// osvBatchSize is how many packages one querybatch request carries.
//
// The batch endpoint answers only ids, so it is used to find WHICH packages
// have anything at all, and the full record is fetched only for those. A
// lockfile carries hundreds of packages and almost none of them have an
// advisory, so the alternative is hundreds of full requests for nothing.
const osvBatchSize = 200

// Feed endpoints. They are constants rather than settings: an operator who
// could point this at another host would be choosing where a list of every
// package their customers run gets sent. A Collector copies them into its own
// fields at construction so a test can aim at an httptest server without any
// of them becoming writable at run time.
const (
	defaultOSVQueryURL      = "https://api.osv.dev/v1/query"
	defaultOSVQueryBatchURL = "https://api.osv.dev/v1/querybatch"
	defaultWPFeedBase       = "https://www.wpvulnerability.net"
)

// Ecosystem names as the OSV API accepts them.
//
// The published OSV schema also documents "WordPress", "WordPress:Plugin" and
// "WordPress:Theme", but the running API REFUSES all three with
// {"code":3,"message":"invalid ecosystem"} (measured against api.osv.dev). That
// is why WordPress components go to a separate feed instead of through here,
// and why this list is written out rather than derived from the schema.
const (
	ecosystemNPM       = "npm"
	ecosystemPackagist = "Packagist"
)

// newFeedClient builds the client every feed call uses.
//
// netguard.DialControl runs AFTER resolution with the concrete address, so a
// resolver on this host that answered a feed name with a private address, by
// compromise or by a wildcard search domain, cannot turn a vulnerability lookup
// into a request against the panel's own network.
func newFeedClient() *http.Client {
	return &http.Client{
		Timeout: feedTimeout,
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 8 * time.Second, Control: netguard.DialControl}).DialContext,
			TLSHandshakeTimeout: 8 * time.Second,
			Proxy:               http.ProxyFromEnvironment,
		},
	}
}

// readCapped decodes a JSON response under the size ceiling.
func readCapped(response *http.Response, into any) error {
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxResponseBytes {
		return fmt.Errorf("feed response is over %d bytes", maxResponseBytes)
	}
	return json.Unmarshal(body, into)
}

// Advisory is one vulnerability as this package records it, whichever feed it
// came from.
type Advisory struct {
	// ID is the CVE when the feed names one, otherwise the feed's own
	// identifier. It is half the merge key, so it is never empty.
	ID string
	// Title is a single line for the screen.
	Title string
	// Severity is a word (critical/high/medium/low), lowercased.
	Severity string
	// CVSS is a base score, or 0 when the feed gave no NUMBER. A CVSS vector
	// string is not a score and is never converted into one here.
	CVSS float64
	// FixedIn is the first release that is not affected, when the feed says so.
	FixedIn string
	// Source is a link to the advisory.
	Source string
}

// ---------------------------------------------------------------------------
// WordPress: wpvulnerability.net
// ---------------------------------------------------------------------------

// wpResponse is the envelope, measured against the live API.
//
// Three fields that mean "closed" have three different JSON types in one
// document: data.closed is a NUMBER, vulnerability[].closed is null, and
// operator.closed / operator.unfixed are STRINGS ("0"). Only the string pair is
// read here, and it is typed as a string, because decoding "0" into a bool
// fails and would drop every record.
//
// An unknown slug answers HTTP 200 with error 0 and data.vulnerability null, so
// neither the status code nor the error field distinguishes "no such package"
// from "no vulnerabilities". Both are simply an empty list, which is the right
// answer for both.
type wpResponse struct {
	Error   int `json:"error"`
	Data    *wpData
	Updated any `json:"updated"`
}

type wpData struct {
	Vulnerability []wpVulnerability `json:"vulnerability"`
}

type wpVulnerability struct {
	UUID     string `json:"uuid"`
	Name     string `json:"name"`
	Operator struct {
		MinVersion  string `json:"min_version"`
		MinOperator string `json:"min_operator"`
		MaxVersion  string `json:"max_version"`
		MaxOperator string `json:"max_operator"`
		Unfixed     string `json:"unfixed"`
	} `json:"operator"`
	Impact struct {
		CVSS3 struct {
			Score    float64 `json:"score"`
			Severity string  `json:"severity"`
		} `json:"cvss3"`
	} `json:"impact"`
	Source []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Link string `json:"link"`
	} `json:"source"`
}

// wpSlugPattern is what a plugin or theme directory may be called. It reaches a
// URL path, so it is checked rather than escaped: a slug is a directory name
// wp-cli reported, and anything outside this set is not one.
func validWPSlug(slug string) bool {
	if slug == "" || len(slug) > 128 {
		return false
	}
	for _, r := range slug {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	// A slug of dots would climb the feed's path.
	return !strings.Contains(slug, "..")
}

// WordPressAdvisories returns the advisories that apply to one installed
// component, plus whether every record could be judged.
//
// kind is "plugin", "theme" or "core"; for core the slug is the version.
func (c *Collector) WordPressAdvisories(ctx context.Context, kind, slug, installed string) ([]Advisory, bool, error) {
	if !validWPSlug(slug) {
		return nil, false, fmt.Errorf("slug is not a component name")
	}
	endpoint := c.wpFeedBase + "/" + url.PathEscape(kind) + "/" + url.PathEscape(slug) + "/"

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, false, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("feed answered %s", response.Status)
	}

	var decoded wpResponse
	if err := readCapped(response, &decoded); err != nil {
		return nil, false, err
	}
	if decoded.Data == nil || len(decoded.Data.Vulnerability) == 0 {
		return nil, true, nil
	}

	records := decoded.Data.Vulnerability
	if len(records) > maxRecordsPerPackage {
		records = records[:maxRecordsPerPackage]
	}

	out := make([]Advisory, 0, len(records))
	judgedAll := true
	for _, record := range records {
		matched, judged := InRange(installed,
			record.Operator.MinVersion, record.Operator.MinOperator,
			record.Operator.MaxVersion, record.Operator.MaxOperator)
		if !judged {
			judgedAll = false
			continue
		}
		if !matched {
			continue
		}
		out = append(out, wpAdvisory(record))
	}
	return out, judgedAll, nil
}

// wpAdvisory turns one feed record into an Advisory.
func wpAdvisory(record wpVulnerability) Advisory {
	advisory := Advisory{
		ID:       record.UUID,
		Title:    record.Name,
		Severity: strings.ToLower(record.Impact.CVSS3.Severity),
		CVSS:     record.Impact.CVSS3.Score,
	}
	// Prefer the CVE, because that is the identifier an operator can look up
	// anywhere else. The feed's own uuid is only a fallback.
	for _, source := range record.Source {
		if strings.HasPrefix(source.ID, "CVE-") {
			advisory.ID = source.ID
			advisory.Source = source.Link
			break
		}
	}
	if advisory.Source == "" && len(record.Source) > 0 {
		advisory.Source = record.Source[0].Link
	}
	// "lt" means every version below this one is affected, so this one is the
	// fix. No other operator names a fixed release, and unfixed says outright
	// that there is none.
	if record.Operator.MaxOperator == "lt" && record.Operator.Unfixed != "1" {
		advisory.FixedIn = record.Operator.MaxVersion
	}
	return advisory
}

// ---------------------------------------------------------------------------
// npm and Composer: OSV
// ---------------------------------------------------------------------------

// Package names one dependency read out of a lockfile.
type Package struct {
	Name    string
	Version string
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

type osvVuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	Affected []struct {
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

type osvQueryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

// AffectedPackages returns which of the given packages OSV has anything on.
//
// This is the cheap pass. The batch endpoint answers only identifiers, so a
// lockfile with hundreds of dependencies costs a handful of requests instead of
// one full request per package, and the expensive pass then runs only for the
// few that matched.
func (c *Collector) AffectedPackages(ctx context.Context, ecosystem string, packages []Package) ([]Package, error) {
	var affected []Package
	for start := 0; start < len(packages); start += osvBatchSize {
		end := min(start+osvBatchSize, len(packages))
		batch := packages[start:end]

		queries := make([]osvQuery, 0, len(batch))
		for _, pkg := range batch {
			queries = append(queries, osvQuery{
				Package: osvPackage{Name: pkg.Name, Ecosystem: ecosystem},
				Version: pkg.Version,
			})
		}
		var decoded osvBatchResponse
		if err := c.postJSON(ctx, c.osvQueryBatchURL, map[string]any{"queries": queries}, &decoded); err != nil {
			return nil, err
		}
		// A short results array would silently shift every answer onto the
		// wrong package, so it is refused rather than zipped as far as it goes.
		if len(decoded.Results) != len(batch) {
			return nil, fmt.Errorf("feed answered %d results for %d queries", len(decoded.Results), len(batch))
		}
		for i, result := range decoded.Results {
			if len(result.Vulns) > 0 {
				affected = append(affected, batch[i])
			}
		}
	}
	return affected, nil
}

// Advisories returns the full records for one package.
func (c *Collector) Advisories(ctx context.Context, ecosystem string, pkg Package) ([]Advisory, error) {
	var decoded osvQueryResponse
	body := osvQuery{Package: osvPackage{Name: pkg.Name, Ecosystem: ecosystem}, Version: pkg.Version}
	if err := c.postJSON(ctx, c.osvQueryURL, body, &decoded); err != nil {
		return nil, err
	}
	records := decoded.Vulns
	if len(records) > maxRecordsPerPackage {
		records = records[:maxRecordsPerPackage]
	}
	out := make([]Advisory, 0, len(records))
	for _, record := range records {
		out = append(out, osvAdvisory(record))
	}
	return out, nil
}

// osvAdvisory turns one OSV record into an Advisory.
//
// The CVSS field is left at zero on purpose. OSV's severity[] carries a CVSS
// VECTOR string, not a base score (measured: "CVSS:3.1/AV:N/AC:L/..."), and
// computing a score from a vector here would be inventing a number the feed did
// not give. The word comes from database_specific.severity, which GitHub
// advisories carry and other sources do not.
func osvAdvisory(record osvVuln) Advisory {
	advisory := Advisory{
		ID:       record.ID,
		Title:    strings.TrimSpace(record.Summary),
		Severity: strings.ToLower(record.DatabaseSpecific.Severity),
	}
	// moderate is GitHub's word for what everything else calls medium; the
	// screen sorts on one vocabulary.
	if advisory.Severity == "moderate" {
		advisory.Severity = "medium"
	}
	for _, alias := range record.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			advisory.ID = alias
			break
		}
	}
	for _, reference := range record.References {
		if reference.Type == "ADVISORY" {
			advisory.Source = reference.URL
			break
		}
	}
	if advisory.Source == "" {
		advisory.Source = "https://osv.dev/vulnerability/" + record.ID
	}
	for _, affected := range record.Affected {
		for _, versionRange := range affected.Ranges {
			for _, event := range versionRange.Events {
				if event.Fixed != "" {
					advisory.FixedIn = event.Fixed
				}
			}
		}
	}
	return advisory
}

// postJSON sends one JSON request and decodes the capped response.
func (c *Collector) postJSON(ctx context.Context, endpoint string, body, into any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("feed answered %s", response.Status)
	}
	return readCapped(response, into)
}
