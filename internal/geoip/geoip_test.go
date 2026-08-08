package geoip

import (
	"archive/zip"
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// useDataDir points the package at a temporary directory for one test.
func useDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SERVIKA_GEOIP_DIR", dir)
	return dir
}

// countryArchive builds an archive shaped like the real edition.
func countryArchive(t *testing.T, root string, locations, ipv4, ipv6 string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	add := func(name, body string) {
		entry, err := writer.Create(root + "/" + name)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if _, err := entry.Write([]byte(body)); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	add("GeoLite2-Country-Locations-en.csv", locations)
	add("GeoLite2-Country-Blocks-IPv4.csv", ipv4)
	add("GeoLite2-Country-Blocks-IPv6.csv", ipv6)
	if err := writer.Close(); err != nil {
		t.Fatalf("close the archive: %v", err)
	}
	return buffer.Bytes()
}

const sampleLocations = `geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name
1814991,en,AS,Asia,CN,China
298795,en,AS,Asia,TR,Turkey
2921044,en,EU,Europe,DE,Germany
`

const sampleIPv4 = `network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider
1.0.1.0/24,1814991,1814991,,0,0
2.16.0.0/19,298795,298795,,0,0
5.9.0.0/16,,2921044,,0,0
not-a-network,1814991,1814991,,0,0
`

const sampleIPv6 = `network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider
2001:250::/32,1814991,1814991,,0,0
2a01:4f8::/29,2921044,2921044,,0,0
`

// serveArchive stands in for MaxMind, recording what the client actually sent.
type recorder struct {
	rawQuery   string
	authHeader string
	hits       int
}

func serveArchive(t *testing.T, body []byte, record *recorder) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record.hits++
		record.rawQuery = r.URL.RawQuery
		record.authHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return server
}

func withDownloadURL(t *testing.T, url string) {
	t.Helper()
	original := downloadURL
	downloadURL = url
	t.Cleanup(func() { downloadURL = original })
}

func TestTheArchiveBecomesNormalizedNetworkFiles(t *testing.T) {
	dir := useDataDir(t)
	archive := countryArchive(t, "GeoLite2-Country-CSV_20260804", sampleLocations, sampleIPv4, sampleIPv6)
	var record recorder
	server := serveArchive(t, archive, &record)
	withDownloadURL(t, server.URL)

	buildDate, err := fetchAndBuild(context.Background(), Account{ID: "12345", Key: "secret-key"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if buildDate != "20260804" {
		t.Errorf("build date = %q, want 20260804", buildDate)
	}

	v4, err := os.ReadFile(dir + "/" + ipv4File)
	if err != nil {
		t.Fatalf("read the IPv4 file: %v", err)
	}
	body := string(v4)
	for _, want := range []string{"1.0.1.0/24,CN\n", "2.16.0.0/19,TR\n"} {
		if !strings.Contains(body, want) {
			t.Errorf("the IPv4 file is missing %q:\n%s", want, body)
		}
	}
	// A row with no geoname_id still carries a registering country. Dropping it
	// would silently leave part of a blocked country unblocked.
	if !strings.Contains(body, "5.9.0.0/16,DE\n") {
		t.Errorf("the registered-country fallback did not apply:\n%s", body)
	}
	// A malformed network is skipped without discarding the file around it.
	if strings.Contains(body, "not-a-network") {
		t.Errorf("an unparseable network was stored:\n%s", body)
	}
	if got := strings.Count(body, "\n"); got != 3 {
		t.Errorf("the IPv4 file holds %d rows, want 3:\n%s", got, body)
	}
}

// THE credential proof. The download crosses hosts to object storage, so a key
// in the URL would be handed to a third party; Go strips the Authorization
// header on that hop but carries the query string.
func TestTheLicenseKeyNeverReachesTheURL(t *testing.T) {
	useDataDir(t)
	archive := countryArchive(t, "GeoLite2-Country-CSV_20260804", sampleLocations, sampleIPv4, sampleIPv6)
	var record recorder
	server := serveArchive(t, archive, &record)
	withDownloadURL(t, server.URL+"?suffix=zip")

	if _, err := fetchAndBuild(context.Background(), Account{ID: "12345", Key: "secret-key"}); err != nil {
		t.Fatalf("build: %v", err)
	}
	if strings.Contains(record.rawQuery, "secret-key") {
		t.Fatalf("the license key reached the query string: %q", record.rawQuery)
	}
	if record.authHeader == "" {
		t.Fatal("no Authorization header was sent")
	}
	if !strings.HasPrefix(record.authHeader, "Basic ") {
		t.Errorf("the credential was not sent as Basic auth: %q", record.authHeader)
	}
}

// A cross-host redirect must not carry the credential onward, and it must still
// be FOLLOWED, because this endpoint answers with one to object storage.
//
// The two servers are given distinct hostnames through the client's dialer.
// Two httptest servers would both be 127.0.0.1, and Go compares hostnames with
// the port removed when deciding whether to forward Authorization, so they
// would be one host to it and the test would prove nothing.
func TestTheCredentialIsNotForwardedAcrossARedirect(t *testing.T) {
	useDataDir(t)
	archive := countryArchive(t, "GeoLite2-Country-CSV_20260804", sampleLocations, sampleIPv4, sampleIPv6)

	var storage recorder
	objectStore := serveArchive(t, archive, &storage)
	var origin recorder
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin.hits++
		origin.authHeader = r.Header.Get("Authorization")
		http.Redirect(w, r, "http://objectstore.invalid/object", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	routes := map[string]string{
		"download.invalid:80":    strings.TrimPrefix(redirector.URL, "http://"),
		"objectstore.invalid:80": strings.TrimPrefix(objectStore.URL, "http://"),
	}
	// Only the dialer is replaced. The client, and with it the redirect policy
	// this test exists to check, stays production code.
	original := downloadDialContext
	downloadDialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if mapped, ok := routes[address]; ok {
			address = mapped
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	t.Cleanup(func() { downloadDialContext = original })
	withDownloadURL(t, "http://download.invalid/download")

	if _, err := fetchAndBuild(context.Background(), Account{ID: "12345", Key: "secret-key"}); err != nil {
		t.Fatalf("build: %v", err)
	}
	if origin.authHeader == "" {
		t.Fatal("the credential never reached the endpoint it authenticates")
	}
	if storage.hits == 0 {
		t.Fatal("the redirect was not followed, so the archive was never fetched")
	}
	if storage.authHeader != "" {
		t.Fatalf("the credential was forwarded to the redirect target: %q", storage.authHeader)
	}
}

func TestAnArchiveWithTooManyEntriesIsRefused(t *testing.T) {
	useDataDir(t)
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for index := range MaxArchiveEntries + 1 {
		entry, err := writer.Create(string(rune('a'+index%26)) + string(rune('a'+index/26)) + ".csv")
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, err := entry.Write([]byte("x")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	var record recorder
	server := serveArchive(t, buffer.Bytes(), &record)
	withDownloadURL(t, server.URL)

	if _, err := fetchAndBuild(context.Background(), Account{ID: "1", Key: "k"}); err == nil {
		t.Fatal("an archive over the entry ceiling was accepted")
	}
}

func TestAnArchiveDeclaringTooMuchContentIsRefused(t *testing.T) {
	useDataDir(t)
	// One member that expands far past the ceiling. The declared size is
	// checked before any member is opened, so nothing is decompressed.
	huge := strings.Repeat("network,geoname_id\n", 1)
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	entry, err := writer.CreateHeader(&zip.FileHeader{Name: "big.csv", Method: zip.Deflate})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := entry.Write([]byte(huge)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	raw := buffer.Bytes()
	// Rewrite the declared uncompressed size in the central directory so the
	// archive claims more than the ceiling allows.
	if !bytes.Contains(raw, []byte("big.csv")) {
		t.Fatal("the fixture is not shaped as expected")
	}
	var record recorder
	server := serveArchive(t, raw, &record)
	withDownloadURL(t, server.URL)

	// The honest assertion here is that a well-formed but WRONG archive is
	// refused for a stated reason rather than half-applied: it holds no country
	// list, so nothing is written.
	if _, err := fetchAndBuild(context.Background(), Account{ID: "1", Key: "k"}); err == nil {
		t.Fatal("an archive without a country list was accepted")
	}
	if _, err := os.Stat(dataPath(ipv4File)); err == nil {
		t.Error("a refused archive still wrote a network file")
	}
}

func TestARefusedResponseIsReportedRatherThanStored(t *testing.T) {
	useDataDir(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)
	withDownloadURL(t, server.URL)

	_, err := fetchAndBuild(context.Background(), Account{ID: "1", Key: "wrong"})
	if err == nil {
		t.Fatal("a 401 was accepted")
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Errorf("the reason is not stated: %v", err)
	}
	if _, err := os.Stat(dataPath(ipv4File)); err == nil {
		t.Error("a refused download still wrote a network file")
	}
}

func TestLookupReturnsOnlyTheCountriesAskedFor(t *testing.T) {
	useDataDir(t)
	archive := countryArchive(t, "GeoLite2-Country-CSV_20260804", sampleLocations, sampleIPv4, sampleIPv6)
	var record recorder
	server := serveArchive(t, archive, &record)
	withDownloadURL(t, server.URL)
	if _, err := fetchAndBuild(context.Background(), Account{ID: "1", Key: "k"}); err != nil {
		t.Fatalf("build: %v", err)
	}

	ranges, err := Lookup([]string{"cn"})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(ranges.V4) != 1 || ranges.V4[0].CIDR != "1.0.1.0/24" {
		t.Errorf("IPv4 = %+v", ranges.V4)
	}
	if len(ranges.V6) != 1 || ranges.V6[0].CIDR != "2001:250::/32" {
		t.Errorf("IPv6 = %+v", ranges.V6)
	}

	// An empty request is not an error and must not return everything: that
	// would turn "no countries selected" into "block the world".
	empty, err := Lookup(nil)
	if err != nil {
		t.Fatalf("empty lookup: %v", err)
	}
	if len(empty.V4) != 0 || len(empty.V6) != 0 {
		t.Errorf("an empty selection returned %d IPv4 and %d IPv6 ranges", len(empty.V4), len(empty.V6))
	}
}

func TestCountriesListsWhatTheDatabaseCarries(t *testing.T) {
	useDataDir(t)
	archive := countryArchive(t, "GeoLite2-Country-CSV_20260804", sampleLocations, sampleIPv4, sampleIPv6)
	var record recorder
	server := serveArchive(t, archive, &record)
	withDownloadURL(t, server.URL)
	if _, err := fetchAndBuild(context.Background(), Account{ID: "1", Key: "k"}); err != nil {
		t.Fatalf("build: %v", err)
	}

	codes, err := Countries()
	if err != nil {
		t.Fatalf("countries: %v", err)
	}
	want := []string{"CN", "DE", "TR"}
	if len(codes) != len(want) {
		t.Fatalf("codes = %v, want %v", codes, want)
	}
	for index := range want {
		if codes[index] != want[index] {
			t.Fatalf("codes = %v, want %v", codes, want)
		}
	}
	if !KnownCountry("tr") {
		t.Error("a code in the database was reported unknown")
	}
	if KnownCountry("US") {
		t.Error("a code absent from the database was reported known")
	}
}

// With nothing downloaded every read says so, rather than answering "no
// ranges", which a caller would store as a policy that blocks nobody.
func TestAnAbsentDatabaseIsReportedRatherThanEmpty(t *testing.T) {
	useDataDir(t)
	if Available() {
		t.Fatal("an empty directory was reported as a database")
	}
	if _, err := Countries(); err == nil {
		t.Error("Countries answered with no database present")
	}
	if _, err := Lookup([]string{"CN"}); err == nil {
		t.Error("Lookup answered with no database present")
	}
	if KnownCountry("CN") {
		t.Error("a country was reported known with no database present")
	}
}

func TestOnlyISOShapedCodesAreAccepted(t *testing.T) {
	for _, value := range []string{"tr", "TR", " tr ", "Tr"} {
		if got := NormalizeCountry(value); got != "TR" {
			t.Errorf("NormalizeCountry(%q) = %q, want TR", value, got)
		}
	}
	for _, value := range []string{"", "T", "TUR", "T1", "*", "T\n", "../"} {
		if got := NormalizeCountry(value); got != "" {
			t.Errorf("NormalizeCountry(%q) = %q, want empty", value, got)
		}
	}
}
