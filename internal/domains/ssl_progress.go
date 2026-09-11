package domains

// Installing a certificate without holding the request open.
//
// A Let's Encrypt order measures every name in the SAN before asking the CA for
// it, and the mail certificate is a second order on top, so the work runs for
// minutes rather than seconds. Held on the request that started it, that meant
// three separate problems: the browser gave up before the work did, the customer
// could not see which part was slow, and closing the tab cancelled the request
// while the certificate was already half installed.
//
// The work therefore runs on a context of its own and records each step as it
// goes. The page polls a progress endpoint, so it can be closed and reopened and
// still show where the installation got to.
//
// Every step name and every reason is a stable CODE. The panel is English and
// the interface ships twelve languages, so a sentence produced here could not be
// translated.

import (
	"context"
	"log"
	"maps"
	"net/http"
	"strconv"
	"sync"
	"time"

	"servika/internal/httpx"
	"servika/internal/provisioner"

	"github.com/go-chi/chi/v5"
)

// Step names, in the order they run.
const (
	sslStepCertificate     = "certificate"
	sslStepRecord          = "record"
	sslStepMailCertificate = "mail_certificate"
	sslStepMailSNI         = "mail_sni"
)

// Step outcomes. A warning means the step did not do what was asked but the work
// continues, which is the mail certificate's contract: the site is already
// secured and failing the whole installation would misreport that.
const (
	sslStateRunning = "running"
	sslStateDone    = "done"
	sslStateWarning = "warning"
	sslStateFailed  = "failed"
)

// Job outcomes. "idle" is only ever returned by the endpoint, for a domain that
// has no session at all.
const (
	sslJobIdle    = "idle"
	sslJobRunning = "running"
	sslJobDone    = "done"
	sslJobFailed  = "failed"
)

// sslJobRetention bounds how long a finished session stays readable. It has to
// outlast a page reload so the customer can still see what happened, and it has
// to end, because the registry lives in memory.
const sslJobRetention = 30 * time.Minute

// sslJobTimeout is the ceiling for one installation. Two ACME orders with a
// per-name pre-flight each is the slowest real case; past this the job is
// abandoned rather than left running for the life of the process.
const sslJobTimeout = 20 * time.Minute

// SSLStep is one recorded step of an installation.
type SSLStep struct {
	Name    string  `json:"name"`
	State   string  `json:"state"`
	Reason  string  `json:"reason,omitempty"`
	Seconds float64 `json:"seconds"`
}

// sslJob is one domain's installation session.
type sslJob struct {
	mu       sync.Mutex
	domainID int64
	domain   string
	state    string
	reason   string
	steps    []SSLStep
	result   map[string]any
	started  time.Time
	finished time.Time
}

// SSLProgressView is the JSON shape the panel polls.
type SSLProgressView struct {
	State    string         `json:"state"`
	Reason   string         `json:"reason,omitempty"`
	Domain   string         `json:"domain,omitempty"`
	Steps    []SSLStep      `json:"steps"`
	Result   map[string]any `json:"result,omitempty"`
	Started  string         `json:"started_at,omitempty"`
	Finished string         `json:"finished_at,omitempty"`
}

func (j *sslJob) view() SSLProgressView {
	j.mu.Lock()
	defer j.mu.Unlock()
	steps := make([]SSLStep, len(j.steps))
	copy(steps, j.steps)
	result := make(map[string]any, len(j.result))
	maps.Copy(result, j.result)
	view := SSLProgressView{
		State:  j.state,
		Reason: j.reason,
		Domain: j.domain,
		Steps:  steps,
		Result: result,
	}
	if !j.started.IsZero() {
		view.Started = j.started.UTC().Format(time.RFC3339)
	}
	if !j.finished.IsZero() {
		view.Finished = j.finished.UTC().Format(time.RFC3339)
	}
	return view
}

// step runs one phase and records its outcome.
//
// The callback returns a reason code and whether the phase merely warned. A
// returned error ends the installation; a warning does not.
func (j *sslJob) step(name string, run func() (reason string, warned bool, err error)) error {
	j.mu.Lock()
	j.steps = append(j.steps, SSLStep{Name: name, State: sslStateRunning})
	index := len(j.steps) - 1
	j.mu.Unlock()

	started := time.Now()
	reason, warned, err := run()
	seconds := time.Since(started).Seconds()

	j.mu.Lock()
	j.steps[index].Seconds = seconds
	j.steps[index].Reason = reason
	switch {
	case err != nil:
		j.steps[index].State = sslStateFailed
	case warned:
		j.steps[index].State = sslStateWarning
	default:
		j.steps[index].State = sslStateDone
	}
	j.mu.Unlock()

	if err != nil {
		log.Printf("ssl install %s: step %s failed: %v", j.domain, name, err)
	}
	return err
}

func (j *sslJob) set(key string, value any) {
	j.mu.Lock()
	j.result[key] = value
	j.mu.Unlock()
}

func (j *sslJob) finish(state, reason string) {
	j.mu.Lock()
	j.state, j.reason, j.finished = state, reason, time.Now()
	j.mu.Unlock()
}

var (
	sslJobsMu sync.Mutex
	sslJobs   = map[int64]*sslJob{}
)

// sslJobFor returns the session for a domain, or nil.
func sslJobFor(id int64) *sslJob {
	sslJobsMu.Lock()
	defer sslJobsMu.Unlock()
	return sslJobs[id]
}

// claimSSLJob registers a new session unless one is already running for the
// domain.
//
// Refusing rather than replacing is what keeps a double click from placing two
// ACME orders for the same name, which spends the CA's per-domain allowance and
// can leave the second order overwriting the first one's files mid-install.
func claimSSLJob(id int64, domain string) (*sslJob, bool) {
	sslJobsMu.Lock()
	defer sslJobsMu.Unlock()
	if existing, ok := sslJobs[id]; ok {
		existing.mu.Lock()
		running := existing.state == sslJobRunning
		existing.mu.Unlock()
		if running {
			return existing, false
		}
	}
	pruneSSLJobsLocked()
	job := &sslJob{
		domainID: id,
		domain:   domain,
		state:    sslJobRunning,
		result:   map[string]any{},
		started:  time.Now(),
	}
	sslJobs[id] = job
	return job, true
}

// pruneSSLJobsLocked drops finished sessions nobody is going to read. The caller
// holds sslJobsMu.
func pruneSSLJobsLocked() {
	cutoff := time.Now().Add(-sslJobRetention)
	for id, job := range sslJobs {
		job.mu.Lock()
		expired := job.state != sslJobRunning && !job.finished.IsZero() && job.finished.Before(cutoff)
		job.mu.Unlock()
		if expired {
			delete(sslJobs, id)
		}
	}
}

// runSSLInstall performs the installation the request asked for.
//
// It is deliberately the same sequence the synchronous handler used to run, so
// the outcome a customer sees does not change: only who waits for it does.
func (h *Handlers) runSSLInstall(job *sslJob, id int64, req sslIssueReq, domainName, systemUser, phpVersion, backend string) {
	ctx, cancel := context.WithTimeout(context.Background(), sslJobTimeout)
	defer cancel()

	// What was ASKED for, kept beside what was installed. A page reopened after
	// the fact has no memory of the request, and the two differ whenever the
	// fail-safe took over.
	job.set("requested_type", req.Type)

	install := &sslInstall{h: h, job: job, id: id, req: req, domainName: domainName,
		systemUser: systemUser, phpVersion: phpVersion, backend: backend, actualType: req.Type}
	if err := job.step(sslStepCertificate, install.certificate); err != nil {
		job.finish(sslJobFailed, "ssl_install_failed")
		return
	}

	install.expiresAt = time.Now().Add(365 * 24 * time.Hour)
	if install.actualType == SSLSourceLetsEncrypt {
		install.expiresAt = time.Now().Add(90 * 24 * time.Hour)
	}

	if err := job.step(sslStepRecord, func() (string, bool, error) { return install.record(ctx) }); err != nil {
		// The certificate is installed and nginx is serving it, so the state on
		// disk is ahead of the state in the database. Saying so is the only
		// honest report; the startup heal reconciles it.
		job.finish(sslJobFailed, "database_update_failed")
		return
	}

	install.report()

	// The mail certificate is a SEPARATE order, so it cannot regress the web
	// certificate that was just installed. A failure here is reported as its own
	// step rather than failing the installation: the site is already secured, and
	// saying otherwise would be a lie about work that succeeded.
	if req.MailSSL && install.actualType == SSLSourceLetsEncrypt {
		install.mailCertificate()
	}

	job.finish(sslJobDone, "")
}

// sslInstall is one installation: what it was asked for and what it has
// installed so far.
type sslInstall struct {
	h                                           *Handlers
	job                                         *sslJob
	id                                          int64
	req                                         sslIssueReq
	domainName, systemUser, phpVersion, backend string

	certPath, keyPath string
	outcome           provisioner.IssueOutcome
	actualType        string
	expiresAt         time.Time
}

// certificate installs the web certificate the request asked for.
func (s *sslInstall) certificate() (string, bool, error) {
	var e error
	switch s.req.Type {
	case SSLSourceSelfSigned:
		s.certPath, s.keyPath, e = enableSelfSigned(s.domainName, s.systemUser, s.phpVersion, s.backend)
	default:
		s.certPath, s.keyPath, s.outcome, e = enableLetsEncrypt(s.domainName, s.systemUser, s.phpVersion, s.backend)
		if !s.outcome.Real {
			s.actualType = SSLSourceSelfSigned
		}
	}
	if e != nil {
		return "ssl_install_failed", false, e
	}
	// A Let's Encrypt request that ends on the self-signed fail-safe kept
	// port 443 serving, so it is not a failure; it is also not what was
	// asked for, and saying nothing here is what used to let the panel
	// report a certificate the browser refuses.
	if s.req.Type == SSLSourceLetsEncrypt && !s.outcome.Real {
		return s.outcome.Reason, true, nil
	}
	return "", false, nil
}

// record writes the installed certificate to the domain row.
func (s *sslInstall) record(ctx context.Context) (string, bool, error) {
	writeCtx, cancelWrite := context.WithTimeout(ctx, 15*time.Second)
	defer cancelWrite()
	if _, e := s.h.DB.ExecContext(writeCtx,
		`UPDATE domains SET ssl_enabled=1, ssl_source=?, cert_path=?, key_path=?, ssl_expiry=?
			 WHERE id=?`, s.actualType, s.certPath, s.keyPath, s.expiresAt, s.id); e != nil {
		return "database_update_failed", false, e
	}
	return "", false, nil
}

// report records on the job what was installed, and why it differs from what
// was asked for.
func (s *sslInstall) report() {
	s.job.set("type", s.actualType)
	s.job.set("cert", s.certPath)
	s.job.set("key", s.keyPath)
	s.job.set("expires_at", s.expiresAt.Format("2006-01-02"))
	if len(s.outcome.Skipped) > 0 {
		s.job.set("web_ssl_skipped", s.outcome.Skipped)
	}
	if s.req.Type == SSLSourceLetsEncrypt && s.actualType != SSLSourceLetsEncrypt {
		s.job.set("warning", "letsencrypt_fallback")
		if s.outcome.Reason != "" {
			s.job.set("reason", s.outcome.Reason)
		}
	}
}

// mailCertificate orders the mail certificate and, when it covers a host,
// serves it to mail clients through SNI.
func (s *sslInstall) mailCertificate() {
	var mailCert provisioner.MailCertificate
	mailIssued := s.job.step(sslStepMailCertificate, func() (string, bool, error) {
		return s.issueMail(&mailCert)
	}) == nil && len(mailCert.Hosts) > 0

	if mailIssued {
		_ = s.job.step(sslStepMailSNI, s.serveMail)
	}
}

// issueMail orders the mail certificate. A failure warns rather than fails.
func (s *sslInstall) issueMail(mailCert *provisioner.MailCertificate) (string, bool, error) {
	var mailErr error
	*mailCert, mailErr = issueMailCertificate(s.domainName)
	if len(mailCert.Skipped) > 0 {
		s.job.set("mail_ssl_skipped", mailCert.Skipped)
	}
	if mailErr != nil {
		s.job.set("mail_ssl_error", "mail_certificate_failed")
		log.Printf("mail certificate for %s: %v", s.domainName, mailErr)
		return "mail_certificate_failed", true, nil
	}
	s.job.set("mail_ssl", map[string]any{
		"hosts":      mailCert.Hosts,
		"expires_at": mailCert.ExpiresAt,
	})
	return "", false, nil
}

// serveMail applies the mail SNI configuration. A failure warns rather than
// fails.
func (s *sslInstall) serveMail() (string, bool, error) {
	if e := applyMailSNI(); e != nil {
		// The certificate exists but nothing serves it yet, which is
		// a different situation from not having one.
		s.job.set("mail_ssl_error", "mail_sni_apply_failed")
		log.Printf("applying the mail SNI configuration for %s: %v", s.domainName, e)
		return "mail_sni_apply_failed", true, nil
	}
	return "", false, nil
}

// SSLProgress reports the installation session for a domain.
// GET /domains/{id}/ssl/progress
func (h *Handlers) SSLProgress(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	job := sslJobFor(id)
	if job == nil {
		httpx.WriteJSON(w, http.StatusOK, SSLProgressView{State: sslJobIdle, Steps: []SSLStep{}})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, job.view())
}
