package backups

import (
	"os"
	"strings"
	"testing"
)

// An SFTP destination is reached at the address netguard vetted, so lftp cannot
// resolve the name a second time and land somewhere the panel never approved.
func TestTheSFTPURLCarriesThePinnedAddress(t *testing.T) {
	d := &Destination{Type: "sftp", Host: "backup.example.com", Port: 2222, dialHost: "203.0.113.5"}
	if got := lftpURL(d); got != "sftp://203.0.113.5:2222" {
		t.Errorf("lftpURL() = %q, want the pinned address", got)
	}
}

// An IPv6 address has to be bracketed in a URL authority and bare everywhere
// else, so the two renderings are kept apart.
func TestAnIPv6PinIsBracketedInTheURLAndBareForSSH(t *testing.T) {
	d := &Destination{Type: "sftp", Host: "backup.example.com", Port: 22, dialHost: "2001:db8::1"}
	if got := lftpURL(d); got != "sftp://[2001:db8::1]:22" {
		t.Errorf("lftpURL() = %q, want the address bracketed", got)
	}
	if got := dialTarget(d); got != "2001:db8::1" {
		t.Errorf("dialTarget() = %q, want the bare address ssh takes", got)
	}
}

// FTP is deliberately NOT pinned: it is reached with ssl-force plus
// verify-certificate, and a certificate names a host rather than an address, so
// dialing the IP would mean turning the hostname check off. That trades a blind
// TCP probe for a weaker transport.
func TestTheFTPURLKeepsTheHostname(t *testing.T) {
	d := &Destination{Type: "ftp", Host: "backup.example.com", Port: 21}
	if got := lftpURL(d); got != "ftp://backup.example.com:21" {
		t.Errorf("lftpURL() = %q, want the hostname", got)
	}
	if err := pinDialTarget(d); err != nil {
		t.Skipf("the host could not be vetted in this environment: %v", err)
	}
	if d.dialHost != "" {
		t.Errorf("an FTP destination was pinned to %q", d.dialHost)
	}
}

// Without a pin the configured host is used, which is what an operator running
// with SERVIKA_ALLOW_PRIVATE_TARGETS gets.
func TestAnUnpinnedDestinationUsesItsConfiguredHost(t *testing.T) {
	d := &Destination{Type: "sftp", Host: "backup.internal", Port: 22}
	if got := dialTarget(d); got != "backup.internal" {
		t.Errorf("dialTarget() = %q, want the configured host", got)
	}
}

// Every lftp path has to vet the destination through the one helper. A path that
// still called netguard.CheckHost would keep the second resolution alive for
// itself while the others were closed.
func TestEveryRemotePathVetsThroughThePinningHelper(t *testing.T) {
	source, err := os.ReadFile("destination.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	// The helper holds the only remaining CheckHost, for the FTP branch.
	if strings.Count(body, "netguard.CheckHost(") != 1 {
		t.Errorf("destination.go calls netguard.CheckHost %d times, want only the one inside pinDialTarget",
			strings.Count(body, "netguard.CheckHost("))
	}
	for _, fn := range []string{
		"func uploadToRemote(", "func fetchRemoteInto(", "func remoteSize(",
		"func deleteFromRemote(", "func testConnection(",
	} {
		start := strings.Index(body, fn)
		if start < 0 {
			t.Errorf("%s is missing from destination.go", fn)
			continue
		}
		end := strings.Index(body[start:], "\nfunc ")
		if end < 0 {
			end = len(body) - start
		}
		if !strings.Contains(body[start:start+end], "pinDialTarget(d)") {
			t.Errorf("%s does not vet its destination through pinDialTarget", fn)
		}
	}
}

// The connection test drives ssh itself, so it is a THIRD resolution of the same
// name and the path a customer can trigger at will.
func TestTheConnectionTestDialsThePinnedAddressUnderTheNamesAlias(t *testing.T) {
	source, err := os.ReadFile("destination.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	start := strings.Index(body, "func testConnection(")
	if start < 0 {
		t.Fatal("testConnection is missing from destination.go")
	}
	end := strings.Index(body[start:], "\nfunc ")
	if end < 0 {
		end = len(body) - start
	}
	test := body[start : start+end]
	if !strings.Contains(test, `sshHostKeyOptions(knownHosts, d.Host)`) {
		t.Error("the connection test does not pin the key under the configured name")
	}
	if !strings.Contains(test, `"--", dialTarget(d), "true"`) {
		t.Error("the connection test still hands ssh the name to resolve for itself")
	}
}
