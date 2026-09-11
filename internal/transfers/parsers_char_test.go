package transfers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"servika/internal/phpversion"
)

// A zone as a source BIND server writes it: a multi-line SOA, indented records
// that inherit the previous owner, split and parenthesised TXT data, and every
// record the parser has to drop.
func TestParseZoneFileKeepsTheMigratableRecords(t *testing.T) {
	zone := strings.Join([]string{
		"$TTL 3600",
		"@ IN SOA ns1.example.com. admin.example.com. (",
		"  2024010101 ; serial",
		"  3600 )",
		"example.com. 3600 IN A 203.0.113.10",
		"www IN A 203.0.113.10",
		"\tIN TXT \"v=spf1 include:_spf.example.net ~all\"",
		"mail 300 IN MX 10 mx.example.net.",
		"_dmarc IN TXT \"v=DMARC1; p=none\"",
		"dkim._domainkey IN TXT ( \"v=DKIM1; k=rsa; \" \"p=MIGf\" )",
		"_sip._tcp IN SRV 5 0 5060 sip.example.com.",
		"@ IN NS ns1.example.com.",
		"\tIN A 203.0.113.11",
		"multi IN TXT ( \"part1\"",
		"  \"part2\" )",
		"short IN",
		"ttlonly IN 300",
		"empty IN A",
		"\tIN CNAME target.example.com.",
		"mx2 IN MX 20",
		"mx3 IN MX mail.example.net.",
		"long IN TXT \"" + strings.Repeat("x", 501) + "\"",
		strings.Repeat("n", 101) + " IN A 192.0.2.1",
		"sub.example.com. IN A 198.51.100.1",
		"; a comment line",
	}, "\n")
	want := []zoneRecord{
		{"@", "A", "203.0.113.10", 3600, 0},
		{"www", "A", "203.0.113.10", 3600, 0},
		{"www", "TXT", "v=spf1 include:_spf.example.net ~all", 3600, 0},
		{"mail", "MX", "mx.example.net.", 300, 10},
		{"_dmarc", "TXT", "v=DMARC1; p=none", 3600, 0},
		{"dkim._domainkey", "TXT", "v=DKIM1; k=rsa; p=MIGf", 3600, 0},
		{"_sip._tcp", "SRV", "0 5060 sip.example.com.", 3600, 5},
		{"@", "A", "203.0.113.11", 3600, 0},
		{"empty", "CNAME", "target.example.com.", 3600, 0},
		{"mx3", "MX", "mail.example.net.", 3600, 0},
		{"sub", "A", "198.51.100.1", 3600, 0},
	}
	if got := parseZoneFile(zone, "example.com"); !reflect.DeepEqual(got, want) {
		t.Fatalf("records =\n%+v\nwant\n%+v", got, want)
	}
}

// Plesk prints one record per line; the parser keeps the migratable types with
// their priority and drops what is short, empty, oversized or not migratable.
func TestParsePleskDNSKeepsTheMigratableRecords(t *testing.T) {
	raw := strings.Join([]string{
		"example.com. A 203.0.113.10",
		"www.example.com. CNAME example.com.",
		"example.com. MX 10 mail.example.com.",
		"example.com. MX 10",
		"_sip._tcp.example.com. SRV 5 0 5060 sip.example.com.",
		"_x._tcp.example.com. SRV 5 0 5060",
		"example.com. TXT v=spf1 a mx ~all",
		"example.com. NS ns1.example.com.",
		"short A",
		"empty.example.com. CNAME .",
		"big.example.com. TXT " + strings.Repeat("x", 2049),
		strings.Repeat("n", 101) + ".example.com. A 192.0.2.1",
		"example.com. caa 0 issue letsencrypt.org",
	}, "\n")
	want := []zoneRecord{
		{"@", "A", "203.0.113.10", 3600, 0},
		{"www", "CNAME", "example.com", 3600, 0},
		{"@", "MX", "mail.example.com", 3600, 10},
		{"_sip._tcp", "SRV", "0 5060 sip.example.com", 3600, 5},
		{"@", "TXT", "v=spf1 a mx ~all", 3600, 0},
		{"@", "CAA", "0 issue letsencrypt.org", 3600, 0},
	}
	if got := parsePleskDNS(raw, "example.com"); !reflect.DeepEqual(got, want) {
		t.Fatalf("records =\n%+v\nwant\n%+v", got, want)
	}
}

// Discovery output is hostile: an account, domain, path or database that fails
// its allowlist is dropped, and the account's databases go to its main domain
// only.
func TestParseDiscoveryBlocksKeepsOnlyValidAccounts(t *testing.T) {
	out := strings.Join([]string{
		"###USER:acme",
		"###DB:acme_wp,acme_shop, ,information_schema,bad name",
		"###DOM:Example.com.|/home/acme/public_html|ea-php81|120|main",
		"###DOM:addon.example.org|/home/acme/addon|8.2.1|abc|addon",
		"###DOM:nodot|/home/acme/x|8.1|1|addon",
		"###DOM:bad path.com|/home/acme/y|8.1|1|addon",
		"###DOM:ok.example.net|relative/path|8.1|1|addon",
		"###DOM:short.example.net|/home/acme|8.1",
		"###USER:-bad",
		"###DOM:orphan.example.com|/home/x|8.1|1|main",
		"###USER:second",
		"###DOM:second.example.com|/home/second/public_html||0|main",
		"garbage line",
	}, "\n")
	want := []RemoteAccount{
		{SourceAccount: "acme", DomainName: "example.com", WebRoot: "/home/acme/public_html",
			PHPVersion: "8.1", SizeMB: 120, Databases: []string{"acme_wp", "acme_shop"}},
		{SourceAccount: "acme", DomainName: "addon.example.org", WebRoot: "/home/acme/addon",
			PHPVersion: "8.2", Note: "addon domain — the database migrates with the main domain"},
		{SourceAccount: "second", DomainName: "second.example.com", WebRoot: "/home/second/public_html"},
	}
	if got := parseDiscoveryBlocks(out); !reflect.DeepEqual(got, want) {
		t.Fatalf("accounts =\n%+v\nwant\n%+v", got, want)
	}
}

// loadedPHP answers the PHP version list: each named version is installed, and
// 5.5 is always present but not loaded.
func loadedPHP(t *testing.T, versions ...string) {
	t.Helper()
	list := []phpversion.Version{{VersionMetadata: phpversion.VersionMetadata{Version: "5.5"}}}
	for _, v := range versions {
		list = append(list, phpversion.Version{VersionMetadata: phpversion.VersionMetadata{Version: v}, Loaded: true})
	}
	setForTest(t, &phpVersions, func() []phpversion.Version { return list })
}

// The closest installed PHP is the same major release first, upwards before
// downwards, and only then another major release, higher before lower.
func TestInstalledPHPOrClosestPrefersTheSameMajorRelease(t *testing.T) {
	cases := []struct {
		name      string
		installed []string
		requested string
		want      string
	}{
		{"nothing loaded", nil, "8.1", "8.1"},
		{"nothing requested", []string{"8.3"}, "", ""},
		{"the exact version", []string{"8.1", "8.3"}, "8.3", "8.3"},
		{"the lowest newer minor", []string{"8.4", "8.2", "8.3"}, "8.1", "8.2"},
		{"the highest older minor", []string{"7.3", "7.4"}, "7.9", "7.4"},
		{"the lowest newer major", []string{"8.2", "8.0"}, "7.4", "8.0"},
		{"the highest older major", []string{"5.6", "7.0"}, "8.1", "7.0"},
		{"a bare major version", []string{"9.0", "8.5"}, "7", "8.5"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			loadedPHP(t, c.installed...)
			if got := installedPHPOrClosest(c.requested); got != c.want {
				t.Fatalf("installedPHPOrClosest(%q) = %q, want %q", c.requested, got, c.want)
			}
		})
	}
}

// Every refusal Validate gives, and what it normalises on success.
func TestRemoteSourceValidate(t *testing.T) {
	const address = "source server address is invalid"
	const user = "SSH user name is invalid"
	cases := []struct {
		name   string
		source RemoteSource
		want   string
	}{
		{"an unknown panel", RemoteSource{Type: "ispconfig", Host: "src.example.com", Port: 22, Password: "pw"}, "invalid source panel type"},
		{"an empty host", RemoteSource{Type: "cpanel", Host: " ", Port: 22, Password: "pw"}, address},
		{"a host read as a flag", RemoteSource{Type: "cpanel", Host: "-oProxyCommand=x", Port: 22, Password: "pw"}, address},
		{"a host past 253", RemoteSource{Type: "cpanel", Host: strings.Repeat("a", 254), Port: 22, Password: "pw"}, address},
		{"a host that is not a name", RemoteSource{Type: "cpanel", Host: "bad host", Port: 22, Password: "pw"}, address},
		{"a zero port", RemoteSource{Type: "cpanel", Host: "src.example.com", Port: 0, Password: "pw"}, "SSH port is invalid"},
		{"a port past 65535", RemoteSource{Type: "cpanel", Host: "src.example.com", Port: 65536, Password: "pw"}, "SSH port is invalid"},
		{"a user read as a flag", RemoteSource{Type: "cpanel", Host: "src.example.com", Port: 22, User: "-x", Password: "pw"}, user},
		{"a user that is not a name", RemoteSource{Type: "cpanel", Host: "src.example.com", Port: 22, User: "bad user", Password: "pw"}, user},
		{"no credential", RemoteSource{Type: "cpanel", Host: "src.example.com", Port: 22, Key: " "}, "a password or an SSH key is required"},
		{"a password with a line break", RemoteSource{Type: "cpanel", Host: "src.example.com", Port: 22, Password: "a\nb"}, "the password contains an invalid character"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.source.Validate(); err == nil || err.Error() != c.want {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

// A valid source is trimmed, and an empty user becomes root.
func TestRemoteSourceValidateNormalisesAnAcceptedSource(t *testing.T) {
	source := RemoteSource{Type: "plesk", Host: " 203.0.113.5 ", Port: 2222, Key: "-----BEGIN KEY-----"}
	if err := source.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if source.Host != "203.0.113.5" || source.User != "root" {
		t.Fatalf("source = %+v", source)
	}
}

// A catch-all keeps an empty local part, an invalid local part is dropped, and an
// empty destination between commas is skipped.
func TestParseAliasBodyHandlesCatchAllsAndEmptyDestinations(t *testing.T) {
	body := []byte("*: catchall@example.com\nBad Local!: x@y.com\nteam: a@example.com,,b\n")
	want := []aliasImport{
		{Local: "", Destination: "catchall@new.com"},
		{Local: "team", Destination: "a@new.com,b@new.com"},
	}
	if got := parseAliasBody(body, "example.com", "new.com"); !reflect.DeepEqual(got, want) {
		t.Fatalf("aliases = %+v, want %+v", got, want)
	}
}

// A configuration the panel may stat but not read is skipped, and the next one
// still answers.
func TestConfigDBNamesSkipsAnUnreadableConfiguration(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file whatever its mode")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"), []byte("<?php define('DB_NAME', 'hidden_wp');\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("DB_DATABASE=acme_app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := configDBNames(root); !reflect.DeepEqual(got, []string{"acme_app"}) {
		t.Fatalf("names = %v", got)
	}
}

// rawArchiveFile writes a gzip stream built by write, which may leave the tar
// unfinished on purpose.
func rawArchiveFile(t *testing.T, write func(tw *tar.Writer)) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	write(tar.NewWriter(gz))
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "raw.tar.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Every way reading the small members can fail is returned, and asking for
// nothing reads nothing.
func TestReadSmallTarMembersFailures(t *testing.T) {
	const member = "backup-demo/va/example.com"
	cases := map[string]func(*testing.T) string{
		"a missing archive":       func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.tar.gz") },
		"a file that is not gzip": func(t *testing.T) string { return writeFile(t, "plain.tar.gz", []byte("plain text")) },
		"a stream that is not tar": func(t *testing.T) string {
			return writeFile(t, "garbage.tar.gz", gzipBytes(t, bytes.Repeat([]byte{'x'}, 100)))
		},
		"a member past the metadata limit": func(t *testing.T) string {
			return rawArchiveFile(t, func(tw *tar.Writer) {
				_ = tw.WriteHeader(&tar.Header{Name: member, Mode: 0o600, Size: maxMetadataBytes + 1, Typeflag: tar.TypeReg})
			})
		},
		"a member cut short": func(t *testing.T) string {
			return rawArchiveFile(t, func(tw *tar.Writer) {
				_ = tw.WriteHeader(&tar.Header{Name: member, Mode: 0o600, Size: 10, Typeflag: tar.TypeReg})
				_, _ = tw.Write([]byte("abc"))
			})
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := readSmallTarMembers(build(t), []string{member}); err == nil {
				t.Fatal("the failure was not returned")
			}
		})
	}
	if got, err := readSmallTarMembers("/nonexistent", []string{""}); err != nil || len(got) != 0 {
		t.Fatalf("asking for nothing = %v, %v", got, err)
	}
}

// An archive that cannot be read, is too large, or is not a cPanel backup is
// refused with the error a caller can tell apart.
func TestAnalyzeCPanelRefusals(t *testing.T) {
	huge := rawArchiveBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "backup-demo/homedir/big", Mode: 0o600, Size: maxExpandedBytes + 1, Typeflag: tar.TypeReg})
	})
	cases := []struct {
		name string
		body []byte
		want string
	}{
		{"a stream that is not gzip", []byte("plain"), "could not open gzip stream"},
		{"a stream cut inside a tar header", gzipBytes(t, bytes.Repeat([]byte{'x'}, 100)), "could not read tar stream"},
		{"an archive past the inventory limit", huge, ErrArchiveTooLarge.Error()},
		{"an archive that is not cPanel", archiveBytes(t, testEntry{name: "backup-demo/other/file", body: "x"}), ErrNotCPanel.Error()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := AnalyzeCPanel(bytes.NewReader(c.body))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to hold %q", err, c.want)
			}
		})
	}
}

// gzipBytes compresses data as one gzip stream, whatever data holds.
func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func rawArchiveBytes(t *testing.T, write func(tw *tar.Writer)) []byte {
	t.Helper()
	data, err := os.ReadFile(rawArchiveFile(t, write))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func archiveBytes(t *testing.T, entries ...testEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(archive(t, entries...)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Without account metadata the username comes from cp/backup_user and the
// primary domain from the first DNS zone, each with the warning that says so.
func TestAnalyzeCPanelInfersWhatTheMetadataLacks(t *testing.T) {
	inferred, err := AnalyzeCPanel(archive(t,
		testEntry{name: "backup-demo/cp/backup_user", body: "demo2\n"},
		testEntry{name: "backup-demo/dnszones/zeta.example.com.db", body: "$TTL 3600"},
		testEntry{name: "backup-demo/dnszones/alpha.example.com.db", body: "$TTL 3600"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if inferred.Username != "demo2" || inferred.PrimaryDomain != "zeta.example.com" {
		t.Fatalf("inventory = %+v", inferred)
	}
	assertWarnings(t, inferred.Warnings, "inferred from a DNS zone", "No web files were found")

	unknown, err := AnalyzeCPanel(archive(t, testEntry{name: "backup-demo/cp/username", body: "demo3"}))
	if err != nil {
		t.Fatal(err)
	}
	assertWarnings(t, unknown.Warnings, "could not be determined automatically")
}

func assertWarnings(t *testing.T, warnings []string, want ...string) {
	t.Helper()
	joined := strings.Join(warnings, " | ")
	for _, fragment := range want {
		if !strings.Contains(joined, fragment) {
			t.Errorf("warnings %q lack %q", joined, fragment)
		}
	}
}
