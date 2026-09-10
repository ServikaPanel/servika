package git

import (
	"os"
	"strings"
	"testing"
)

// netguard.CheckGitURL resolves the host and hands the URL onward unchanged; git
// then resolves the same name again when it connects. A low-TTL record under the
// customer's control can answer with a public address for the check and an
// internal one for the connection.
//
// http.curloptResolve maps the NAME to the vetted address inside libcurl, so the
// URL keeps its hostname and TLS still validates the certificate against it.
func TestAnHTTPSRemoteIsPinnedToTheVettedAddress(t *testing.T) {
	// example.com resolves publicly; a host that cannot be resolved here would
	// make the test about DNS rather than about the pin.
	args, err := gitResolveArgs("https://example.com/acme/site.git")
	if err != nil {
		t.Skipf("the remote could not be vetted in this environment: %v", err)
	}
	if len(args) != 2 || args[0] != "-c" {
		t.Fatalf("gitResolveArgs() = %v, want a -c option pair", args)
	}
	if !strings.HasPrefix(args[1], "http.curloptResolve=example.com:443:") {
		t.Errorf("gitResolveArgs() = %q, want the name mapped to an address on 443", args[1])
	}
	if strings.HasSuffix(args[1], ":") {
		t.Errorf("gitResolveArgs() = %q, want a concrete address after the port", args[1])
	}
}

// A non-default port has to be carried, or libcurl maps a mapping that never
// applies and git resolves the name itself after all.
func TestTheRemotePortIsCarriedIntoThePin(t *testing.T) {
	args, err := gitResolveArgs("https://example.com:8443/acme/site.git")
	if err != nil {
		t.Skipf("the remote could not be vetted in this environment: %v", err)
	}
	if len(args) != 2 || !strings.HasPrefix(args[1], "http.curloptResolve=example.com:8443:") {
		t.Errorf("gitResolveArgs() = %v, want the configured port in the mapping", args)
	}
}

// An ssh:// or git@ remote gets no pin: that path currently disables host key
// verification for github.com, so there is no pin for an alias to preserve. It
// still has to be VETTED, which is what CheckGitURL does.
func TestAnSSHRemoteIsVettedButNotPinned(t *testing.T) {
	for _, remote := range []string{
		"ssh://git@example.com/acme/site.git",
		"git@example.com:acme/site.git",
	} {
		args, err := gitResolveArgs(remote)
		if err != nil {
			t.Skipf("the remote could not be vetted in this environment: %v", err)
		}
		if args != nil {
			t.Errorf("gitResolveArgs(%q) = %v, want no pin for an ssh remote", remote, args)
		}
	}
}

// An internal target is refused before any argument is built.
func TestAnInternalRemoteIsRefused(t *testing.T) {
	for _, remote := range []string{
		"https://127.0.0.1/acme/site.git",
		"https://169.254.169.254/latest/meta-data",
		"https://10.0.0.1/acme/site.git",
		"ssh://git@192.168.1.1/acme/site.git",
	} {
		if _, err := gitResolveArgs(remote); err == nil {
			t.Errorf("gitResolveArgs(%q) = nil error, want a refusal", remote)
		}
	}
}

// An address literal is already what would be dialed, so there is no second
// resolution to pin and no mapping to add.
func TestAnAddressLiteralNeedsNoPin(t *testing.T) {
	args, err := gitResolveArgs("https://203.0.113.5/acme/site.git")
	if err != nil {
		t.Fatalf("gitResolveArgs() = %v, want a public literal to pass", err)
	}
	if args != nil {
		t.Errorf("gitResolveArgs() = %v, want no mapping for an address literal", args)
	}
}

// Both network paths have to carry the pin. A fetch reaching the remote without
// it would leave the rebind open on every deployment after the first.
func TestBothNetworkPathsCarryThePin(t *testing.T) {
	source, err := os.ReadFile("git.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	for _, fn := range []string{"func gitClone(", "func gitPull("} {
		start := strings.Index(body, fn)
		if start < 0 {
			t.Errorf("%s is missing from git.go", fn)
			continue
		}
		end := strings.Index(body[start:], "\nfunc ")
		if end < 0 {
			end = len(body) - start
		}
		if !strings.Contains(body[start:start+end], "gitResolveArgs(repoURL)") {
			t.Errorf("%s does not pin its remote", fn)
		}
	}
	// The old upfront-only check must not survive beside the pin, or a path could
	// vet without pinning and read as guarded.
	if strings.Count(body, "netguard.CheckGitURL(") != 2 {
		t.Errorf("netguard.CheckGitURL appears %d times, want the one in gitResolveArgs and the one on the create path",
			strings.Count(body, "netguard.CheckGitURL("))
	}
}
