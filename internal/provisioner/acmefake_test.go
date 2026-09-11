package provisioner

import (
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// issueFixture runs a certificate issuance in temporary directories: no file is
// handed to root, no database is reachable, openssl and acme.sh are answered by
// an acmeScript, and renders are recorded.
type issueFixture struct {
	certRoot string
	acmeHome string
	capture  *renderCapture
	commands *commandRecorder
}

// withRootlessCertificates lets the certificate paths run without root: tenant
// homes and units are temporary, no file is handed to root, a certificate the
// test wrote counts as the tenant's own, and acme.sh keeps its store in a
// temporary home, which is returned.
func withRootlessCertificates(t *testing.T) string {
	t.Helper()
	withTenantHome(t)
	withTenantUnits(t)
	setForTest(t, &chown, func(string, int, int) error { return nil })
	setForTest(t, &fileChown, func(*os.File, int, int) error { return nil })
	setForTest(t, &certificateSourceOwner, os.Getuid())
	acmeHome := t.TempDir()
	t.Setenv("SERVIKA_ACME_HOME", acmeHome)
	return acmeHome
}

func withIssuance(t *testing.T, acme *acmeScript) *issueFixture {
	t.Helper()
	acmeHome := withRootlessCertificates(t)
	withoutDatabase(t)
	sandboxWebroot(t)
	return &issueFixture{
		certRoot: certRoot(t),
		acmeHome: acmeHome,
		capture:  withRenderCapture(t),
		commands: withCommandScript(t, acme.respond),
	}
}

// acmeScript answers the commands an issuance runs. --issue is answered by
// issue with the names it was asked for; --install-cert writes certPEM and keyPEM
// to the paths it names unless installExit is non-zero or installSkips is set;
// openssl writes the files it names.
type acmeScript struct {
	issue         func(hosts []string) (output string, exitCode int)
	installExit   int
	installSkips  bool
	certPEM       []byte
	keyPEM        []byte
	issuedFor     [][]string
	installedWith [][]string
}

// newACMEScript issues successfully and installs a real certificate for names.
func newACMEScript(t *testing.T, names ...string) *acmeScript {
	t.Helper()
	certPath, keyPath := writeSANCertificate(t, names...)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return &acmeScript{
		issue:   func([]string) (string, int) { return "", 0 },
		certPEM: certPEM,
		keyPEM:  keyPEM,
	}
}

func (a *acmeScript) respond(argv []string) (string, int) {
	switch {
	case slices.Contains(argv, "--issue"):
		hosts := argvValues(argv, "-d")
		a.issuedFor = append(a.issuedFor, hosts)
		return a.issue(hosts)
	case slices.Contains(argv, "--install-cert"):
		a.installedWith = append(a.installedWith, argv)
		if a.installExit != 0 {
			return "install-cert failed", a.installExit
		}
		if a.installSkips {
			return "", 0
		}
		for flag, body := range map[string][]byte{"--cert-file": a.certPEM, "--key-file": a.keyPEM} {
			for _, path := range argvValues(argv, flag) {
				if err := os.WriteFile(path, body, 0o600); err != nil {
					return err.Error(), 1
				}
			}
		}
		return "", 0
	case len(argv) > 0 && argv[0] == "openssl":
		return writeOpenSSLOutputs(argv)
	}
	return "", 0
}

// argvValues returns every value that follows flag in argv.
func argvValues(argv []string, flag string) []string {
	var values []string
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == flag {
			values = append(values, argv[i+1])
		}
	}
	return values
}

// ranWith reports whether any recorded argv carries flag.
func (r *commandRecorder) ranWith(flag string) bool {
	for _, argv := range r.argvs() {
		if slices.Contains(argv, flag) {
			return true
		}
	}
	return false
}

// answerChallenges serves every token the probe wrote, except on the hosts named,
// which answer 404.
func answerChallenges(t *testing.T, failing ...string) {
	t.Helper()
	stubProbe(t, func(url string) (int, string, error) {
		for _, host := range failing {
			if strings.Contains(url, "://"+host+"/") {
				return http.StatusNotFound, "", nil
			}
		}
		token := url[strings.LastIndex(url, "/")+1:]
		body, err := os.ReadFile(filepath.Join(acmeWebrootDir, ".well-known", "acme-challenge", token))
		if err != nil {
			return http.StatusNotFound, "", nil
		}
		return http.StatusOK, string(body), nil
	})
}

// resolveEverythingHere answers every name with the same address, so every
// optional name is eligible for the certificate.
func resolveEverythingHere(t *testing.T) {
	t.Helper()
	stubResolver(t, func(string) ([]string, error) { return []string{"203.0.113.10"}, nil })
}

// resolveNothing answers no name at all.
func resolveNothing(t *testing.T) {
	t.Helper()
	stubResolver(t, func(string) ([]string, error) { return nil, os.ErrNotExist })
}
