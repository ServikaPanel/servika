package mail

import (
	"strings"
	"testing"
)

var coveredExample = map[string][]string{
	"example.com": {"mail.example.com", "smtp.example.com"},
	"acme.test":   {"mail.acme.test"},
}

// Dovecot matches the name the client asked for, so every covered hostname needs
// its own block; one block per DOMAIN would leave smtp. on the shared
// certificate and the client would still warn.
func TestDovecotSNIHasABlockForEveryCoveredName(t *testing.T) {
	got := renderDovecotSNI(coveredExample)
	for _, host := range []string{"mail.example.com", "smtp.example.com", "mail.acme.test"} {
		if !strings.Contains(got, "local_name "+host+" {") {
			t.Errorf("no local_name block for %s:\n%s", host, got)
		}
	}
	if strings.Count(got, "local_name ") != 3 {
		t.Errorf("block count = %d, want 3", strings.Count(got, "local_name "))
	}
	// Dovecot reads a file into a setting with the "<" prefix; without it the
	// path itself is used as the certificate and Dovecot refuses to start.
	if !strings.Contains(got, "ssl_cert = </") || !strings.Contains(got, "ssl_key = </") {
		t.Errorf("certificate settings are not file references:\n%s", got)
	}
}

// postmap -F stores the CONTENT of the named file, and Postfix wants a chain
// that starts with the private key. That is the chain file, never the bare
// certificate, which has no key in it.
func TestPostfixSNITablePointsAtTheChainFile(t *testing.T) {
	got := renderPostfixSNI(coveredExample)
	for line := range strings.SplitSeq(got, "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("line %q is not a two-column table entry", line)
		}
		if !strings.HasSuffix(fields[1], "mail-chain.pem") {
			t.Errorf("entry %q does not point at the chain file", line)
		}
	}
	if !strings.Contains(got, "mail.example.com\t") {
		t.Errorf("the table has no entry for mail.example.com:\n%s", got)
	}
}

// Both files are generated, and a host with no mail certificate at all must
// produce an empty table rather than a broken one.
func TestSNIRenderingIsEmptyWithoutCertificates(t *testing.T) {
	for name, got := range map[string]string{
		"dovecot": renderDovecotSNI(nil),
		"postfix": renderPostfixSNI(nil),
	} {
		for line := range strings.SplitSeq(got, "\n") {
			if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "#") {
				t.Errorf("%s rendering emitted %q with no certificates installed", name, line)
			}
		}
	}
}

// The output is ordered by domain so an unchanged set of certificates renders
// byte for byte the same, which is what lets ApplySNI skip the reload.
func TestSNIRenderingIsStable(t *testing.T) {
	// Go randomises map iteration, so rendering the same map twice is a real
	// test that the output is sorted rather than emitted in map order.
	firstDovecot, secondDovecot := renderDovecotSNI(coveredExample), renderDovecotSNI(coveredExample)
	if firstDovecot != secondDovecot {
		t.Errorf("the Dovecot rendering is not stable:\n%s\n---\n%s", firstDovecot, secondDovecot)
	}
	firstPostfix, secondPostfix := renderPostfixSNI(coveredExample), renderPostfixSNI(coveredExample)
	if firstPostfix != secondPostfix {
		t.Errorf("the Postfix rendering is not stable:\n%s\n---\n%s", firstPostfix, secondPostfix)
	}
}
