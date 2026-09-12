package geoip

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

// The archive is a tenant-independent but still UNTRUSTED input: it comes off
// the network. Every refusal below is a shape the real edition never has, and
// each one has its own message so an operator reading the panel knows whether
// the download, the archive or the data was wrong.

// readerFor opens an archive built in memory.
func readerFor(t *testing.T, archive []byte) *zip.Reader {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatalf("open the built archive: %v", err)
	}
	return reader
}

// archiveOf builds an archive from named members, so a case can leave one out
// or give it the wrong shape.
func archiveOf(t *testing.T, members map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, body := range members {
		entry, err := writer.Create("GeoLite2-Country-CSV_20260804/" + name)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if _, err := entry.Write([]byte(body)); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close the archive: %v", err)
	}
	return buffer.Bytes()
}

func TestTheCountryListIsRefusedWhenItCannotBeRead(t *testing.T) {
	cases := []struct {
		name    string
		members map[string]string
		want    string
	}{
		{
			name:    "no country list at all",
			members: map[string]string{"GeoLite2-Country-Blocks-IPv4.csv": sampleIPv4},
			want:    "the archive holds no country list",
		},
		{
			name:    "an empty country list",
			members: map[string]string{"GeoLite2-Country-Locations-en.csv": ""},
			want:    "read the country list header",
		},
		{
			name: "a country list with no geoname_id column",
			members: map[string]string{
				"GeoLite2-Country-Locations-en.csv": "locale_code,country_iso_code\nen,TR\n",
			},
			want: "the country list is missing a required column",
		},
		{
			name: "a country list with no country code column",
			members: map[string]string{
				"GeoLite2-Country-Locations-en.csv": "geoname_id,locale_code\n1,en\n",
			},
			want: "the country list is missing a required column",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readLocations(readerFor(t, archiveOf(t, tc.members)))
			if err == nil {
				t.Fatal("the country list was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error is %q, want it to hold %q", err, tc.want)
			}
		})
	}
}

// A row the country list cannot place is skipped, not refused: the edition
// carries continents and other rows with no country code of their own.
func TestUnplaceableCountryRowsAreSkipped(t *testing.T) {
	const locations = `geoname_id,locale_code,country_iso_code
6255148,en,
,en,TR
298795,en,TR
2921044,en,DE
`
	countries, err := readLocations(readerFor(t, archiveOf(t,
		map[string]string{"GeoLite2-Country-Locations-en.csv": locations})))
	if err != nil {
		t.Fatalf("readLocations: %v", err)
	}
	if len(countries) != 2 {
		t.Fatalf("countries = %v, want only the two rows carrying both halves", countries)
	}
	if countries["298795"] != "TR" || countries["2921044"] != "DE" {
		t.Errorf("countries = %v, want 298795=TR and 2921044=DE", countries)
	}
}

// A row shorter than the columns the header declared is skipped rather than
// read out of range.
func TestAShortCountryRowIsSkipped(t *testing.T) {
	const locations = "geoname_id,locale_code,country_iso_code\n298795\n2921044,en,DE\n"
	countries, err := readLocations(readerFor(t, archiveOf(t,
		map[string]string{"GeoLite2-Country-Locations-en.csv": locations})))
	if err != nil {
		t.Fatalf("readLocations: %v", err)
	}
	if len(countries) != 1 || countries["2921044"] != "DE" {
		t.Errorf("countries = %v, want only 2921044=DE", countries)
	}
}

func TestTheBlocksFileIsRefusedWhenItCannotBeRead(t *testing.T) {
	countries := map[string]string{"298795": "TR"}
	cases := []struct {
		name    string
		members map[string]string
		want    string
	}{
		{
			name:    "no blocks file at all",
			members: map[string]string{"GeoLite2-Country-Locations-en.csv": sampleLocations},
			want:    "the archive holds no GeoLite2-Country-Blocks-IPv4.csv",
		},
		{
			name:    "an empty blocks file",
			members: map[string]string{"GeoLite2-Country-Blocks-IPv4.csv": ""},
			want:    "read the GeoLite2-Country-Blocks-IPv4.csv header",
		},
		{
			name: "a blocks file with no network column",
			members: map[string]string{
				"GeoLite2-Country-Blocks-IPv4.csv": "geoname_id,registered_country_geoname_id\n298795,298795\n",
			},
			want: "GeoLite2-Country-Blocks-IPv4.csv is missing a required column",
		},
		{
			name: "a blocks file with no geoname_id column",
			members: map[string]string{
				"GeoLite2-Country-Blocks-IPv4.csv": "network\n2.16.0.0/19\n",
			},
			want: "GeoLite2-Country-Blocks-IPv4.csv is missing a required column",
		},
		{
			name: "a blocks file whose every network is unusable",
			members: map[string]string{
				"GeoLite2-Country-Blocks-IPv4.csv": "network,geoname_id\nnot-a-network,298795\n" +
					"2.16.0.0/19,99999\n",
			},
			want: "GeoLite2-Country-Blocks-IPv4.csv produced no usable network",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useDataDir(t)
			err := writeNetworks(readerFor(t, archiveOf(t, tc.members)),
				"GeoLite2-Country-Blocks-IPv4.csv", ipv4File, countries)
			if err == nil {
				t.Fatal("the blocks file was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error is %q, want it to hold %q", err, tc.want)
			}
		})
	}
}

// A short row is skipped rather than read out of range, and the rows around it
// still land in the file.
func TestAShortNetworkRowIsSkipped(t *testing.T) {
	dir := useDataDir(t)
	const blocks = "network,geoname_id,registered_country_geoname_id\n\n2.16.0.0/19,298795,298795\n"
	err := writeNetworks(readerFor(t, archiveOf(t,
		map[string]string{"GeoLite2-Country-Blocks-IPv4.csv": blocks})),
		"GeoLite2-Country-Blocks-IPv4.csv", ipv4File, map[string]string{"298795": "TR"})
	if err != nil {
		t.Fatalf("writeNetworks: %v", err)
	}
	if body := readData(t, dir, ipv4File); body != "2.16.0.0/19,TR\n" {
		t.Errorf("file = %q, want only the usable row", body)
	}
}

// A malformed row is skipped in both readers, because this is a third-party
// file and discarding the whole edition for one bad line means no country
// blocking at all until the next release.
func TestAMalformedRowIsSkippedInBothReaders(t *testing.T) {
	dir := useDataDir(t)
	// A bare quote inside an unquoted field is what encoding/csv reports as a
	// record-level problem.
	const locations = "geoname_id,country_iso_code\n298795,T\"R\n2921044,DE\n"
	const blocks = "network,geoname_id\n2.16.0.0/19,29\"8795\n2a01:4f8::/29,2921044\n"

	countries, err := readLocations(readerFor(t, archiveOf(t,
		map[string]string{"GeoLite2-Country-Locations-en.csv": locations})))
	if err != nil {
		t.Fatalf("readLocations: %v", err)
	}
	if len(countries) != 1 || countries["2921044"] != "DE" {
		t.Fatalf("countries = %v, want only the well-formed row", countries)
	}

	if err := writeNetworks(readerFor(t, archiveOf(t,
		map[string]string{"GeoLite2-Country-Blocks-IPv4.csv": blocks})),
		"GeoLite2-Country-Blocks-IPv4.csv", ipv4File, countries); err != nil {
		t.Fatalf("writeNetworks: %v", err)
	}
	if body := readData(t, dir, ipv4File); body != "2a01:4f8::/29,DE\n" {
		t.Errorf("file = %q, want only the well-formed row", body)
	}
}

// A row shorter than the network column is skipped rather than read out of
// range.
func TestARowShorterThanTheNetworkColumnIsSkipped(t *testing.T) {
	dir := useDataDir(t)
	const blocks = "geoname_id,extra,network\n298795,x\n298795,x,2.16.0.0/19\n"
	if err := writeNetworks(readerFor(t, archiveOf(t,
		map[string]string{"GeoLite2-Country-Blocks-IPv4.csv": blocks})),
		"GeoLite2-Country-Blocks-IPv4.csv", ipv4File,
		map[string]string{"298795": "TR"}); err != nil {
		t.Fatalf("writeNetworks: %v", err)
	}
	if body := readData(t, dir, ipv4File); body != "2.16.0.0/19,TR\n" {
		t.Errorf("file = %q, want only the complete row", body)
	}
}

// A data directory that cannot be created stops the build before any file is
// written, so a half-written pair of network files is never left behind.
func TestABuildStopsWhenTheDataDirectoryCannotBeCreated(t *testing.T) {
	blocker := t.TempDir() + "/not-a-directory"
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write the blocking file: %v", err)
	}
	t.Setenv("SERVIKA_GEOIP_DIR", blocker+"/geoip")

	var record recorder
	server := serveArchive(t, countryArchive(t, "GeoLite2-Country-CSV_20260804",
		sampleLocations, sampleIPv4, sampleIPv6), &record)
	withDownloadURL(t, server.URL)

	_, err := fetchAndBuild(context.Background(), Account{ID: "12345", Key: "k"})
	if err == nil {
		t.Fatal("the build ran with no data directory")
	}
	if !strings.Contains(err.Error(), "create the data directory") {
		t.Errorf("error is %q, want it to name the directory", err)
	}
}

func readData(t *testing.T, dir, name string) string {
	t.Helper()
	body, err := os.ReadFile(dir + "/" + name) // #nosec G304 -- a path this test created.
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(body)
}

// The whole build refuses an archive that is not the edition, and each refusal
// names what was wrong with it.
func TestTheBuildRefusesAnArchiveThatIsNotTheEdition(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		want string
	}{
		{
			name: "a body that is not a zip",
			body: []byte("this is not an archive"),
			want: "open the archive",
		},
		{
			name: "an archive naming no country",
			body: func() []byte {
				return archiveOf(t, map[string]string{
					"GeoLite2-Country-Locations-en.csv": "geoname_id,country_iso_code\n",
					"GeoLite2-Country-Blocks-IPv4.csv":  sampleIPv4,
					"GeoLite2-Country-Blocks-IPv6.csv":  sampleIPv6,
				})
			}(),
			want: "the archive names no country",
		},
		{
			name: "an archive with a country list but no blocks",
			body: func() []byte {
				return archiveOf(t, map[string]string{
					"GeoLite2-Country-Locations-en.csv": sampleLocations,
				})
			}(),
			want: "the archive holds no GeoLite2-Country-Blocks-IPv4.csv",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useDataDir(t)
			var record recorder
			server := serveArchive(t, tc.body, &record)
			withDownloadURL(t, server.URL)

			_, err := fetchAndBuild(context.Background(), Account{ID: "12345", Key: "k"})
			if err == nil {
				t.Fatal("the archive was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error is %q, want it to hold %q", err, tc.want)
			}
		})
	}
}

// The entry count is checked BEFORE any member is opened, so an archive built
// to exhaust the reader never gets a member decompressed at all.
func TestAnArchiveWithTooManyEntriesIsRefusedBeforeItIsRead(t *testing.T) {
	useDataDir(t)
	members := make(map[string]string, MaxArchiveEntries+1)
	for index := range MaxArchiveEntries + 1 {
		members[padName(index)] = "x"
	}
	var record recorder
	server := serveArchive(t, archiveOf(t, members), &record)
	withDownloadURL(t, server.URL)

	_, err := fetchAndBuild(context.Background(), Account{ID: "12345", Key: "k"})
	if err == nil {
		t.Fatal("an archive past the entry ceiling was accepted")
	}
	if !strings.Contains(err.Error(), "entries") {
		t.Errorf("error is %q, want it to name the entry count", err)
	}
}

func padName(index int) string {
	return fmt.Sprintf("member-%04d.csv", index)
}
