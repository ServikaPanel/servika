package domains

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// resetSSLJobs clears the registry so one test cannot see another's session.
func resetSSLJobs(t *testing.T) {
	t.Helper()
	sslJobsMu.Lock()
	sslJobs = map[int64]*sslJob{}
	sslJobsMu.Unlock()
	t.Cleanup(func() {
		sslJobsMu.Lock()
		sslJobs = map[int64]*sslJob{}
		sslJobsMu.Unlock()
	})
}

// The guard this exists for: a double click used to place a second ACME order
// for the same name, which spends the CA's per-domain allowance and can have the
// second order overwrite the first one's files while it is still installing.
func TestASecondInstallIsRefusedWhileOneIsRunning(t *testing.T) {
	resetSSLJobs(t)

	first, started := claimSSLJob(7, "example.com")
	if !started {
		t.Fatal("the first installation was refused")
	}
	second, started := claimSSLJob(7, "example.com")
	if started {
		t.Fatal("a second installation started while the first was running")
	}
	if second != first {
		t.Error("the refusal returned a different session from the running one")
	}

	// Once it ends, a fresh installation is allowed again.
	first.finish(sslJobDone, "")
	third, started := claimSSLJob(7, "example.com")
	if !started {
		t.Fatal("a new installation was refused after the previous one finished")
	}
	if third == first {
		t.Error("the finished session was reused instead of a new one being started")
	}
}

// Two domains install independently; the guard is per domain, not global.
func TestInstallsForDifferentDomainsDoNotBlockEachOther(t *testing.T) {
	resetSSLJobs(t)
	if _, started := claimSSLJob(1, "one.example"); !started {
		t.Fatal("the first domain was refused")
	}
	if _, started := claimSSLJob(2, "two.example"); !started {
		t.Fatal("a second domain was refused while another was installing")
	}
}

// A step records what happened without ending the job for a warning: the mail
// certificate failing must not report the web certificate as not installed.
func TestAWarningStepDoesNotEndTheInstallation(t *testing.T) {
	resetSSLJobs(t)
	job, _ := claimSSLJob(3, "example.com")

	if err := job.step(sslStepCertificate, func() (string, bool, error) {
		return "", false, nil
	}); err != nil {
		t.Fatalf("a successful step returned %v", err)
	}
	if err := job.step(sslStepMailCertificate, func() (string, bool, error) {
		return "mail_certificate_failed", true, nil
	}); err != nil {
		t.Fatalf("a warning step returned %v", err)
	}
	if err := job.step(sslStepRecord, func() (string, bool, error) {
		return "database_update_failed", false, errors.New("connection refused")
	}); err == nil {
		t.Fatal("a failing step did not report an error")
	}

	view := job.view()
	want := []struct {
		name  string
		state string
	}{
		{sslStepCertificate, sslStateDone},
		{sslStepMailCertificate, sslStateWarning},
		{sslStepRecord, sslStateFailed},
	}
	if len(view.Steps) != len(want) {
		t.Fatalf("steps = %d, want %d", len(view.Steps), len(want))
	}
	for i, expected := range want {
		if view.Steps[i].Name != expected.name || view.Steps[i].State != expected.state {
			t.Errorf("step %d = %s/%s, want %s/%s",
				i, view.Steps[i].Name, view.Steps[i].State, expected.name, expected.state)
		}
	}
	if view.Steps[1].Reason != "mail_certificate_failed" {
		t.Errorf("the warning reason = %q, want mail_certificate_failed", view.Steps[1].Reason)
	}
}

// Every code the panel renders has to be usable as a translation key: the API is
// English and the interface ships twelve languages.
func TestStepNamesAndStatesAreLookupKeys(t *testing.T) {
	for _, code := range []string{
		sslStepCertificate, sslStepRecord, sslStepMailCertificate, sslStepMailSNI,
		sslStateRunning, sslStateDone, sslStateWarning, sslStateFailed,
		sslJobIdle, sslJobRunning, sslJobDone, sslJobFailed,
	} {
		if code == "" || strings.ContainsAny(code, " :.\n") {
			t.Errorf("%q is not usable as a translation key", code)
		}
	}
}

// The view is a copy. A poll landing while a step is being recorded must not
// hand the caller the slice the job is still appending to.
func TestTheProgressViewIsACopy(t *testing.T) {
	resetSSLJobs(t)
	job, _ := claimSSLJob(4, "example.com")
	_ = job.step(sslStepCertificate, func() (string, bool, error) { return "", false, nil })
	job.set("type", "letsencrypt")

	view := job.view()
	view.Steps[0].State = "tampered"
	view.Result["type"] = "tampered"

	fresh := job.view()
	if fresh.Steps[0].State != sslStateDone {
		t.Error("mutating the returned steps changed the session")
	}
	if fresh.Result["type"] != "letsencrypt" {
		t.Error("mutating the returned result changed the session")
	}
}

// Concurrent polling while the job records steps must not race.
func TestPollingDuringAnInstallIsSafe(t *testing.T) {
	resetSSLJobs(t)
	job, _ := claimSSLJob(5, "example.com")

	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		for range 200 {
			_ = job.step(sslStepCertificate, func() (string, bool, error) { return "", false, nil })
			job.set("type", "letsencrypt")
		}
	}()
	go func() {
		defer wait.Done()
		for range 200 {
			_ = job.view()
		}
	}()
	wait.Wait()
}

// A finished session stays readable so a reopened page can still show what
// happened, and is dropped once nobody is going to read it.
func TestFinishedSessionsArePrunedOnceTheyAreOld(t *testing.T) {
	resetSSLJobs(t)
	stale, _ := claimSSLJob(6, "old.example")
	stale.finish(sslJobDone, "")
	stale.mu.Lock()
	stale.finished = time.Now().Add(-sslJobRetention - time.Minute)
	stale.mu.Unlock()

	// Claiming for another domain is what triggers the sweep.
	if _, started := claimSSLJob(8, "new.example"); !started {
		t.Fatal("the new installation was refused")
	}
	if sslJobFor(6) != nil {
		t.Error("a session older than the retention window is still held")
	}
}

// A domain nobody has installed for answers "idle", not 404: the page polls
// before it knows whether anything is running.
func TestProgressForADomainWithNoSessionIsIdle(t *testing.T) {
	resetSSLJobs(t)
	handlers := &Handlers{}
	recorder := httptest.NewRecorder()
	handlers.SSLProgress(recorder, requestWithParams(http.MethodGet, "", map[string]string{"id": "99"}))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), `"state":"idle"`) {
		t.Errorf("body = %s, want an idle state", recorder.Body.String())
	}
}
