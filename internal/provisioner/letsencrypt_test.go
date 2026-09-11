package provisioner

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// EnableLetsEncrypt reuses a valid real certificate before ordering, refuses to
// order for a name that cannot pass validation, retries a failed order for the
// apex alone, and keeps 443 alive with a fail-safe certificate whenever the order
// cannot complete. These tests pin which of those paths each situation takes and
// what the caller is told.

const letsEncryptDomain = "example.com"

func enableExample() (string, string, IssueOutcome, error) {
	return EnableLetsEncrypt(letsEncryptDomain, "c_example_com", "8.3", "php-fpm")
}

// systemCertificatePaths is where an installed web certificate for the domain lives.
func (f *issueFixture) systemCertificatePaths() (string, string) {
	dir := filepath.Join(f.certRoot, letsEncryptDomain)
	return filepath.Join(dir, letsEncryptDomain+".crt"), filepath.Join(dir, letsEncryptDomain+".key")
}

func (f *issueFixture) assertRendered(t *testing.T, source string) {
	t.Helper()
	if len(f.capture.opts) != 1 || f.capture.opts[0].SSLSource != source {
		t.Fatalf("renders = %+v, want one %s render", f.capture.opts, source)
	}
}

func TestAnInvalidDomainIsRefusedBeforeAnyIssuance(t *testing.T) {
	f := withIssuance(t, newACMEScript(t, letsEncryptDomain))

	if _, _, _, err := EnableLetsEncrypt("bad name", "c_example_com", "8.3", "php-fpm"); err == nil {
		t.Fatal("EnableLetsEncrypt() accepted an invalid domain")
	}
	if len(f.commands.argvs()) != 0 || len(f.capture.opts) != 0 {
		t.Errorf("an invalid domain ran %q and rendered %d times", f.commands.argvs(), len(f.capture.opts))
	}
}

func TestACertificateRootThatCannotBeCreatedStopsTheIssuance(t *testing.T) {
	f := withIssuance(t, newACMEScript(t, letsEncryptDomain))
	blocker := filepath.Join(t.TempDir(), "a-file")
	writeFixture(t, blocker, "not a directory")
	t.Setenv("SERVIKA_CERT_ROOT", filepath.Join(blocker, "certs"))

	if _, _, _, err := enableExample(); err == nil || !strings.Contains(err.Error(), "create certificate directory") {
		t.Fatalf("EnableLetsEncrypt() error = %v, want the directory failure", err)
	}
	if len(f.capture.opts) != 0 {
		t.Errorf("rendered %d times after the directory failed", len(f.capture.opts))
	}
}

// A real certificate with more than 30 days left is installed and served
// without placing an order, which is what protects the CA rate limit.
func TestAValidRealCertificateIsReusedWithoutOrdering(t *testing.T) {
	acme := newACMEScript(t, letsEncryptDomain)
	f := withIssuance(t, acme)
	resolveNothing(t)
	writeCertificateFixture(t,
		filepath.Join(f.acmeHome, letsEncryptDomain, "fullchain.cer"),
		filepath.Join(f.acmeHome, letsEncryptDomain, letsEncryptDomain+".key"),
		letsEncryptDomain, false)

	certPath, keyPath, outcome, err := enableExample()

	if err != nil || !outcome.Real {
		t.Fatalf("EnableLetsEncrypt() = %+v, %v; want a reused real certificate", outcome, err)
	}
	wantCert, wantKey := f.systemCertificatePaths()
	if certPath != wantCert || keyPath != wantKey {
		t.Errorf("paths = %q, %q; want %q, %q", certPath, keyPath, wantCert, wantKey)
	}
	for _, path := range []string{wantCert, wantKey} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Errorf("%s was not installed: %v", filepath.Base(path), statErr)
		}
	}
	if len(acme.issuedFor) != 0 {
		t.Errorf("an order was placed for %v although a valid certificate existed", acme.issuedFor)
	}
	f.assertRendered(t, "letsencrypt")
}

// A reused certificate whose vhost cannot be rendered is reported as the render
// failure; it does not fall through to placing an order.
func TestAReusedCertificateWhoseVhostCannotBeRenderedIsAnError(t *testing.T) {
	acme := newACMEScript(t, letsEncryptDomain)
	f := withIssuance(t, acme)
	resolveNothing(t)
	writeCertificateFixture(t,
		filepath.Join(f.acmeHome, letsEncryptDomain, "fullchain.cer"),
		filepath.Join(f.acmeHome, letsEncryptDomain, letsEncryptDomain+".key"),
		letsEncryptDomain, false)
	f.capture.err = errors.New("nginx rejected the configuration")

	if _, _, _, err := enableExample(); !errors.Is(err, f.capture.err) {
		t.Fatalf("EnableLetsEncrypt() error = %v, want the render failure", err)
	}
	if len(acme.issuedFor) != 0 {
		t.Errorf("ordered for %v after the reused certificate failed to render", acme.issuedFor)
	}
}

func TestADomainThatDoesNotResolveKeeps443WithASelfSignedCertificate(t *testing.T) {
	acme := newACMEScript(t, letsEncryptDomain)
	f := withIssuance(t, acme)
	resolveNothing(t)

	certPath, _, outcome, err := enableExample()

	if err != nil || outcome.Real || outcome.Reason != sslReasonDNSUnresolved {
		t.Fatalf("EnableLetsEncrypt() = %+v, %v; want the %s fail-safe", outcome, err, sslReasonDNSUnresolved)
	}
	if wantCert, _ := f.systemCertificatePaths(); certPath != wantCert {
		t.Errorf("certificate = %q, want the self-signed one at %q", certPath, wantCert)
	}
	if !f.commands.ran("openssl", "req", "-x509") || len(acme.issuedFor) != 0 {
		t.Errorf("want a self-signed certificate and no order, ran %q", f.commands.argvs())
	}
	f.assertRendered(t, "self-signed")
}

// An apex that cannot answer the challenge is not ordered at all; the reason the
// probe found is the one the caller is given.
func TestAnApexThatCannotAnswerTheChallengeIsNotOrdered(t *testing.T) {
	acme := newACMEScript(t, letsEncryptDomain)
	f := withIssuance(t, acme)
	resolveEverythingHere(t)
	answerChallenges(t, letsEncryptDomain)

	_, _, outcome, err := enableExample()

	if err != nil || outcome.Reason != string(reasonWrongStatus) {
		t.Fatalf("EnableLetsEncrypt() = %+v, %v; want the %s fail-safe", outcome, err, reasonWrongStatus)
	}
	if len(acme.issuedFor) != 0 {
		t.Errorf("ordered for %v although the apex cannot answer", acme.issuedFor)
	}
	f.assertRendered(t, "self-signed")
}

func TestASuccessfulOrderInstallsTheCertificateAndReportsTheNamesLeftOut(t *testing.T) {
	acme := newACMEScript(t, letsEncryptDomain)
	f := withIssuance(t, acme)
	resolveEverythingHere(t)
	answerChallenges(t, "www."+letsEncryptDomain)

	certPath, keyPath, outcome, err := enableExample()

	if err != nil || !outcome.Real {
		t.Fatalf("EnableLetsEncrypt() = %+v, %v; want a real certificate", outcome, err)
	}
	if want := map[string]string{"www." + letsEncryptDomain: string(reasonWrongStatus)}; !reflect.DeepEqual(outcome.Skipped, want) {
		t.Errorf("skipped = %v, want %v", outcome.Skipped, want)
	}
	if len(acme.issuedFor) != 1 || slices.Contains(acme.issuedFor[0], "www."+letsEncryptDomain) {
		t.Errorf("ordered for %v, want one order without the name that cannot answer", acme.issuedFor)
	}
	if wantCert, wantKey := f.systemCertificatePaths(); certPath != wantCert || keyPath != wantKey {
		t.Errorf("paths = %q, %q; want %q, %q", certPath, keyPath, wantCert, wantKey)
	}
	f.assertRendered(t, "letsencrypt")
}

// One failing optional name fails the whole order, so a failed order with more
// than one name is retried for the apex alone before falling back.
func TestAFailedOrderWithSeveralNamesIsRetriedForTheApexAlone(t *testing.T) {
	acme := newACMEScript(t, letsEncryptDomain)
	acme.issue = func(hosts []string) (string, int) {
		if len(hosts) > 1 {
			return "urn:ietf:params:acme:error:unauthorized", 1
		}
		return "", 0
	}
	f := withIssuance(t, acme)
	resolveEverythingHere(t)
	answerChallenges(t)

	_, _, outcome, err := enableExample()

	if err != nil || !outcome.Real {
		t.Fatalf("EnableLetsEncrypt() = %+v, %v; want the apex-only retry to succeed", outcome, err)
	}
	if len(acme.issuedFor) != 2 || !reflect.DeepEqual(acme.issuedFor[1], []string{letsEncryptDomain}) {
		t.Errorf("ordered for %v, want the full set and then the apex alone", acme.issuedFor)
	}
	f.assertRendered(t, "letsencrypt")
}

func TestAnOrderThatCannotCompleteFallsBackWithItsReason(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(acme *acmeScript)
		reason  string
	}{
		{"the CA rate-limits the order", func(acme *acmeScript) {
			acme.issue = func([]string) (string, int) { return "too many certificates already issued", 1 }
		}, sslReasonRateLimited},
		{"install-cert fails", func(acme *acmeScript) {
			acme.installExit = 1
		}, sslReasonInstallFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			acme := newACMEScript(t, letsEncryptDomain)
			tc.prepare(acme)
			f := withIssuance(t, acme)
			resolveEverythingHere(t)
			answerChallenges(t)

			_, _, outcome, err := enableExample()

			if err != nil || outcome.Real || outcome.Reason != tc.reason {
				t.Fatalf("EnableLetsEncrypt() = %+v, %v; want the %s fail-safe", outcome, err, tc.reason)
			}
			f.assertRendered(t, "self-signed")
		})
	}
}

// acme.sh exits 2 when the store already holds a valid certificate for the
// names; that is not a failure and is not retried.
func TestARenewSkipInstallsTheStoredCertificateWithoutARetry(t *testing.T) {
	acme := newACMEScript(t, letsEncryptDomain)
	acme.issue = func([]string) (string, int) { return "Skipping. Next renewal time is ...", 2 }
	f := withIssuance(t, acme)
	resolveEverythingHere(t)
	answerChallenges(t)

	_, _, outcome, err := enableExample()

	if err != nil || !outcome.Real {
		t.Fatalf("EnableLetsEncrypt() = %+v, %v; want the stored certificate installed", outcome, err)
	}
	if len(acme.issuedFor) != 1 || len(acme.installedWith) != 1 {
		t.Errorf("orders %v, installs %d; want one of each", acme.issuedFor, len(acme.installedWith))
	}
	f.assertRendered(t, "letsencrypt")
}

// A failure after the certificate was issued is returned as an error rather than
// hidden behind the fail-safe.
func TestAFailureAfterIssuanceIsReturned(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(f *issueFixture)
	}{
		{"the certificate cannot be handed to root", func(*issueFixture) {
			chown = func(path string, _, _ int) error {
				if strings.HasSuffix(path, ".crt") {
					return errors.New("operation not permitted")
				}
				return nil
			}
		}},
		{"the vhost cannot be rendered", func(f *issueFixture) {
			f.capture.err = errors.New("nginx rejected the configuration")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withIssuance(t, newACMEScript(t, letsEncryptDomain))
			resolveEverythingHere(t)
			answerChallenges(t)
			tc.prepare(f)

			if _, _, _, err := enableExample(); err == nil {
				t.Fatal("EnableLetsEncrypt() hid a failure after issuance")
			}
			if f.commands.ran("openssl") {
				t.Error("a failure after issuance fell back to a self-signed certificate")
			}
		})
	}
}
