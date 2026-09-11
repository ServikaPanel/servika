package laravel

import (
	"os"
	"strings"
	"testing"

	"servika/internal/netguard"
)

// The remote install handed a customer-named repository URL straight to
// `git clone`. The only validation was an ARGUMENT filter: it refuses shell
// metacharacters and a non-Git scheme and never looks at the host.
//
// A caller with scope on the domain could therefore make the panel host open a
// connection to any address, including ones a reseller has no other way to
// reach: the panel's own API, MariaDB and Valkey on loopback, tenant and host
// applications on their port ranges, RFC1918 neighbours, and the cloud metadata
// endpoint. `git clone` over https issues a GET and the ssh forms open a raw
// handshake, so arbitrary TCP ports were probeable, with the failure text
// returned by the install-status endpoint as the oracle.
//
// internal/git guards both of its clone paths with the same call; the guard was
// never carried across when this second entry point grew its own clone.
func TestTheRemoteInstallRefusesAnInternalRepositoryHost(t *testing.T) {
	t.Setenv("SERVIKA_ALLOW_PRIVATE_TARGETS", "")
	for _, url := range []string{
		"https://127.0.0.1:8443/x.git",
		"https://169.254.169.254/latest/meta-data/",
		"https://10.0.0.5/repo.git",
		"ssh://git@192.168.1.10/repo.git",
	} {
		// The argument filter passes these: it is not a destination check.
		if !validRepoURL(url) {
			t.Errorf("validRepoURL already refuses %q; this test no longer measures the guard", url)
			continue
		}
		if err := netguard.CheckGitURL(url); err == nil {
			t.Errorf("the network guard allows %q", url)
		}
	}
}

// A public repository still clones, or the guard refuses the feature rather
// than the attack.
func TestAPublicRepositoryIsStillAllowed(t *testing.T) {
	t.Setenv("SERVIKA_ALLOW_PRIVATE_TARGETS", "")
	for _, url := range []string{
		"https://github.com/laravel/laravel.git",
		"git@github.com:laravel/laravel.git",
	} {
		if !validRepoURL(url) {
			t.Errorf("validRepoURL refuses the public repository %q", url)
		}
		if err := netguard.CheckGitURL(url); err != nil {
			t.Errorf("the network guard refuses the public repository %q: %v", url, err)
		}
	}
}

// And the handler actually calls it, before the clone is scripted.
func TestTheInstallHandlerGuardsTheRepositoryHost(t *testing.T) {
	body, err := os.ReadFile("install.go") // #nosec G304 -- a file of this package.
	if err != nil {
		t.Fatalf("read install.go: %v", err)
	}
	source := string(body)
	guard := strings.Index(source, "netguard.CheckGitURL(req.RepoURL)")
	script := strings.Index(source, "remoteInstallScript(appDir, req.RepoURL")
	if guard < 0 {
		t.Fatal("the remote install does not check the repository host")
	}
	if script >= 0 && guard > script {
		t.Error("the host check runs after the clone is scripted")
	}
}
