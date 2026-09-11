package domains

import (
	"database/sql/driver"
	"reflect"
	"testing"
	"time"

	"servika/internal/provisioner"
)

// sslFakes stands in for the certificate calls runSSLInstall makes.
type sslFakes struct {
	hostCalls
	certErr  error
	outcome  provisioner.IssueOutcome
	mailCert provisioner.MailCertificate
	mailErr  error
	sniErr   error
}

func newSSLFakes(t *testing.T) *sslFakes {
	t.Helper()
	f := &sslFakes{outcome: provisioner.IssueOutcome{Real: true}}
	setForTest(t, &enableSelfSigned, f.selfSigned)
	setForTest(t, &enableLetsEncrypt, f.letsEncrypt)
	setForTest(t, &issueMailCertificate, f.mail)
	setForTest(t, &applyMailSNI, f.sni)
	return f
}

func (f *sslFakes) selfSigned(domain, user, php, backend string) (string, string, error) {
	f.record("self-signed %s %s %s %s", domain, user, php, backend)
	return "/etc/ssl/self.crt", "/etc/ssl/self.key", f.certErr
}

func (f *sslFakes) letsEncrypt(domain, user, php, backend string) (string, string, provisioner.IssueOutcome, error) {
	f.record("letsencrypt %s %s %s %s", domain, user, php, backend)
	return "/etc/ssl/le.crt", "/etc/ssl/le.key", f.outcome, f.certErr
}

func (f *sslFakes) mail(domain string) (provisioner.MailCertificate, error) {
	f.record("mail certificate %s", domain)
	return f.mailCert, f.mailErr
}

func (f *sslFakes) sni() error {
	f.record("mail sni")
	return f.sniErr
}

type sslStepWant struct{ name, state, reason string }

type sslCase struct {
	name    string
	req     sslIssueReq
	script  func(*sqlScript)
	fakes   func(*sslFakes)
	state   string
	reason  string
	steps   []sslStepWant
	calls   []string
	result  map[string]any
	expires time.Duration
}

// runSSL runs one installation for domain 7 to its end and returns its view.
func runSSL(t *testing.T, tc sslCase) (SSLProgressView, *sqlScript, *sslFakes) {
	t.Helper()
	resetSSLJobs(t)
	script := newScript()
	fakes := newSSLFakes(t)
	if tc.script != nil {
		tc.script(script)
	}
	if tc.fakes != nil {
		tc.fakes(fakes)
	}
	job, _ := claimSSLJob(7, "example.com")
	(&Handlers{DB: scriptDB(t, script)}).runSSLInstall(job, 7, tc.req, "example.com", "c_example", "8.3", "php-fpm")
	return job.view(), script, fakes
}

// assertSSLSteps compares the recorded steps by name, state and reason.
func assertSSLSteps(t *testing.T, view SSLProgressView, want []sslStepWant) {
	t.Helper()
	got := make([]sslStepWant, 0, len(view.Steps))
	for _, step := range view.Steps {
		got = append(got, sslStepWant{step.Name, step.State, step.Reason})
	}
	if !reflect.DeepEqual(got, append([]sslStepWant{}, want...)) {
		t.Errorf("steps = %+v, want %+v", got, want)
	}
}

// assertSSLResult compares the result map, with the expiry date checked apart
// because it is computed from the clock.
func assertSSLResult(t *testing.T, view SSLProgressView, want map[string]any, expires time.Duration) {
	t.Helper()
	got := map[string]any{}
	for key, value := range view.Result {
		got[key] = value
	}
	if expires > 0 {
		assertExpiryDate(t, got["expires_at"], expires)
		delete(got, "expires_at")
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("result = %#v, want %#v", got, want)
	}
}

func assertExpiryDate(t *testing.T, value any, expires time.Duration) {
	t.Helper()
	before := time.Now().Add(expires - time.Minute).Format("2006-01-02")
	after := time.Now().Add(expires + time.Minute).Format("2006-01-02")
	if value != before && value != after {
		t.Errorf("expires_at = %v, want %s", value, before)
	}
}

const letsEncryptCall = "letsencrypt example.com c_example 8.3 php-fpm"

func TestSSLInstallRecordsEachStep(t *testing.T) {
	done := func(name string) sslStepWant { return sslStepWant{name, sslStateDone, ""} }
	leResult := func(extra map[string]any) map[string]any {
		result := map[string]any{"requested_type": SSLSourceLetsEncrypt, "type": SSLSourceLetsEncrypt,
			"cert": "/etc/ssl/le.crt", "key": "/etc/ssl/le.key"}
		for key, value := range extra {
			result[key] = value
		}
		return result
	}
	letsEncrypt := sslIssueReq{Type: SSLSourceLetsEncrypt}
	withMail := sslIssueReq{Type: SSLSourceLetsEncrypt, MailSSL: true}
	mailHosts := provisioner.MailCertificate{Hosts: []string{"mail.example.com"}, ExpiresAt: "2026-12-01"}
	cases := []sslCase{
		{name: "a self-signed certificate", req: sslIssueReq{Type: SSLSourceSelfSigned, MailSSL: true},
			state: sslJobDone, steps: []sslStepWant{done(sslStepCertificate), done(sslStepRecord)},
			calls: []string{"self-signed example.com c_example 8.3 php-fpm"},
			result: map[string]any{"requested_type": SSLSourceSelfSigned, "type": SSLSourceSelfSigned,
				"cert": "/etc/ssl/self.crt", "key": "/etc/ssl/self.key"},
			expires: 365 * 24 * time.Hour},
		{name: "a certificate that cannot be installed", req: letsEncrypt,
			fakes: func(f *sslFakes) { f.certErr = errScripted },
			state: sslJobFailed, reason: "ssl_install_failed",
			steps:  []sslStepWant{{sslStepCertificate, sslStateFailed, "ssl_install_failed"}},
			calls:  []string{letsEncryptCall},
			result: map[string]any{"requested_type": SSLSourceLetsEncrypt}},
		{name: "a record that cannot be written", req: letsEncrypt,
			script: func(s *sqlScript) { s.fail["UPDATE domains SET ssl_enabled=1"] = errScripted },
			state:  sslJobFailed, reason: "database_update_failed",
			steps:  []sslStepWant{done(sslStepCertificate), {sslStepRecord, sslStateFailed, "database_update_failed"}},
			calls:  []string{letsEncryptCall},
			result: map[string]any{"requested_type": SSLSourceLetsEncrypt}},
		{name: "a real certificate that left names out", req: letsEncrypt,
			fakes: func(f *sslFakes) { f.outcome.Skipped = map[string]string{"www.example.com": "dns_not_here"} },
			state: sslJobDone, steps: []sslStepWant{done(sslStepCertificate), done(sslStepRecord)},
			calls:   []string{letsEncryptCall},
			result:  leResult(map[string]any{"web_ssl_skipped": map[string]string{"www.example.com": "dns_not_here"}}),
			expires: 90 * 24 * time.Hour},
		{name: "a fallback to the self-signed certificate", req: withMail,
			fakes: func(f *sslFakes) { f.outcome = provisioner.IssueOutcome{Reason: "acme_refused"} },
			state: sslJobDone,
			steps: []sslStepWant{{sslStepCertificate, sslStateWarning, "acme_refused"}, done(sslStepRecord)},
			calls: []string{letsEncryptCall},
			result: map[string]any{"requested_type": SSLSourceLetsEncrypt, "type": SSLSourceSelfSigned,
				"cert": "/etc/ssl/le.crt", "key": "/etc/ssl/le.key", "warning": "letsencrypt_fallback", "reason": "acme_refused"},
			expires: 365 * 24 * time.Hour},
		{name: "a fallback with no reason", req: letsEncrypt,
			fakes: func(f *sslFakes) { f.outcome = provisioner.IssueOutcome{} },
			state: sslJobDone,
			steps: []sslStepWant{{sslStepCertificate, sslStateWarning, ""}, done(sslStepRecord)},
			calls: []string{letsEncryptCall},
			result: map[string]any{"requested_type": SSLSourceLetsEncrypt, "type": SSLSourceSelfSigned,
				"cert": "/etc/ssl/le.crt", "key": "/etc/ssl/le.key", "warning": "letsencrypt_fallback"},
			expires: 365 * 24 * time.Hour},
		{name: "a mail certificate that fails", req: withMail,
			fakes: func(f *sslFakes) {
				f.mailErr, f.mailCert = errScripted, provisioner.MailCertificate{Skipped: map[string]string{"imap.example.com": "dns_not_here"}}
			},
			state: sslJobDone,
			steps: []sslStepWant{done(sslStepCertificate), done(sslStepRecord),
				{sslStepMailCertificate, sslStateWarning, "mail_certificate_failed"}},
			calls: []string{letsEncryptCall, "mail certificate example.com"},
			result: leResult(map[string]any{"mail_ssl_skipped": map[string]string{"imap.example.com": "dns_not_here"},
				"mail_ssl_error": "mail_certificate_failed"}),
			expires: 90 * 24 * time.Hour},
		{name: "a mail certificate that covers no host", req: withMail,
			state:   sslJobDone,
			steps:   []sslStepWant{done(sslStepCertificate), done(sslStepRecord), done(sslStepMailCertificate)},
			calls:   []string{letsEncryptCall, "mail certificate example.com"},
			result:  leResult(map[string]any{"mail_ssl": map[string]any{"hosts": []string(nil), "expires_at": ""}}),
			expires: 90 * 24 * time.Hour},
		{name: "a mail certificate nothing serves yet", req: withMail,
			fakes: func(f *sslFakes) { f.mailCert, f.sniErr = mailHosts, errScripted },
			state: sslJobDone,
			steps: []sslStepWant{done(sslStepCertificate), done(sslStepRecord), done(sslStepMailCertificate),
				{sslStepMailSNI, sslStateWarning, "mail_sni_apply_failed"}},
			calls: []string{letsEncryptCall, "mail certificate example.com", "mail sni"},
			result: leResult(map[string]any{"mail_ssl": map[string]any{"hosts": []string{"mail.example.com"}, "expires_at": "2026-12-01"},
				"mail_ssl_error": "mail_sni_apply_failed"}),
			expires: 90 * 24 * time.Hour},
		{name: "a mail certificate that is served", req: withMail,
			fakes:   func(f *sslFakes) { f.mailCert = mailHosts },
			state:   sslJobDone,
			steps:   []sslStepWant{done(sslStepCertificate), done(sslStepRecord), done(sslStepMailCertificate), done(sslStepMailSNI)},
			calls:   []string{letsEncryptCall, "mail certificate example.com", "mail sni"},
			result:  leResult(map[string]any{"mail_ssl": map[string]any{"hosts": []string{"mail.example.com"}, "expires_at": "2026-12-01"}}),
			expires: 90 * 24 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			view, _, fakes := runSSL(t, tc)
			if view.State != tc.state || view.Reason != tc.reason {
				t.Errorf("job = %s/%q, want %s/%q", view.State, view.Reason, tc.state, tc.reason)
			}
			assertSSLSteps(t, view, tc.steps)
			assertSteps(t, &fakes.hostCalls, tc.calls...)
			assertSSLResult(t, view, tc.result, tc.expires)
		})
	}
}

// The record names the certificate that was really installed, and its expiry.
func TestSSLInstallRecordsTheInstalledCertificate(t *testing.T) {
	_, script, _ := runSSL(t, sslCase{req: sslIssueReq{Type: SSLSourceLetsEncrypt},
		fakes: func(f *sslFakes) { f.outcome = provisioner.IssueOutcome{} }})
	writes := script.execsContaining("UPDATE domains SET ssl_enabled=1, ssl_source=?")
	if len(writes) != 1 {
		t.Fatalf("%d certificate records were written, want 1", len(writes))
	}
	args := writes[0].args
	expiry, isTime := args[3].(time.Time)
	if !isTime || !reflect.DeepEqual([]driver.Value{args[0], args[1], args[2], args[4]},
		[]driver.Value{SSLSourceSelfSigned, "/etc/ssl/le.crt", "/etc/ssl/le.key", int64(7)}) {
		t.Fatalf("the record was written with %v", args)
	}
	if left := time.Until(expiry); left < 364*24*time.Hour || left > 366*24*time.Hour {
		t.Errorf("a self-signed fallback expires in %v, want a year", left)
	}
}
