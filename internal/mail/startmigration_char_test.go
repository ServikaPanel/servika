package mail

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"servika/internal/middleware"
	"servika/internal/secret"
)

const (
	migrationInsert = "INSERT INTO mail_migration_jobs"
	remoteBody      = `{"host":" IMAP.Example.com ","port":993,"security":"ssl","username":"someone@example.com","password":"remote-secret"}`
)

type loginAttempt struct {
	host                         string
	port                         int
	security, username, password string
}

// answerLogin stands in for the remote sign-in and records each attempt.
func answerLogin(t *testing.T, accepted bool, reason string) *[]loginAttempt {
	t.Helper()
	var attempts []loginAttempt
	setForTest(t, &verifyRemoteLogin, func(_ context.Context, host string, port int, security, username, password string) (bool, string) {
		attempts = append(attempts, loginAttempt{host, port, security, username, password})
		return accepted, reason
	})
	return &attempts
}

func migrationScript(t *testing.T) *sqlScript {
	t.Helper()
	if err := secret.Init([]byte(strings.Repeat("k", 32))); err != nil {
		t.Fatalf("initialise the encryption: %v", err)
	}
	drainMigrationQueue()
	t.Cleanup(drainMigrationQueue)
	s := handlerScript()
	s.insertID = 41
	return s
}

func startMigration(t *testing.T, s *sqlScript, role, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := mailRequest(http.MethodPost, "/domains/1/mail/2/migration", body, role,
		map[string]string{"id": "1", "mid": "2"})
	(&Handlers{DB: scriptDB(t, s)}).StartMigration(recorder, request)
	return recorder
}

// Every refusal StartMigration gives, with the status and the text or reason a
// caller sees.
func TestStartMigrationRefusals(t *testing.T) {
	const address = "invalid server address"
	admin := middleware.RoleAdmin
	cases := []struct {
		name, role, body string
		setup            func(*sqlScript)
		accepted         bool
		status           int
		text             string
	}{
		{"an unknown domain", admin, remoteBody, func(s *sqlScript) { s.rows[domainLookup] = nil }, true, http.StatusNotFound, "domain not found"},
		{"a caller without a session", "", remoteBody, noSetup, true, http.StatusUnauthorized, "authorization required"},
		{"a body that is not JSON", admin, `{`, noSetup, true, http.StatusBadRequest, "invalid request"},
		{"a host that is not a hostname", admin, `{"host":"bad host","port":993,"username":"u","password":"p"}`, noSetup, true, http.StatusBadRequest, address},
		{"a port out of range", admin, `{"host":"imap.example.com","port":0,"username":"u","password":"p"}`, noSetup, true, http.StatusBadRequest, address},
		{"no password", admin, `{"host":"imap.example.com","port":993,"username":"u"}`, noSetup, true, http.StatusBadRequest, "credentials are required"},
		{"a refused sign-in", admin, remoteBody, noSetup, false, http.StatusBadRequest, `"reason":"auth_failed"`},
		{"a mailbox already migrating", admin, remoteBody, func(s *sqlScript) {
			s.fail[migrationInsert] = errors.New("Error 1062: Duplicate entry '2' for key 'active_mailbox'")
		}, true, http.StatusConflict, `"reason":"migration_already_running"`},
		{"a job that cannot be written", admin, remoteBody, func(s *sqlScript) { s.fail[migrationInsert] = errScripted }, true, http.StatusInternalServerError, "could not start the migration"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			script := migrationScript(t)
			c.setup(script)
			answerLogin(t, c.accepted, ReasonAuthFailed)
			assertAnswer(t, startMigration(t, script, c.role, c.body), c.status, c.text)
		})
	}
}

// The mailbox check runs after the suspension gate and before the body is read.
func TestStartMigrationRefusesAnotherDomainsMailbox(t *testing.T) {
	script := migrationScript(t)
	script.rows[mailboxOwned] = nil
	answerLogin(t, true, "")
	assertAnswer(t, startMigration(t, script, middleware.RoleAdmin, remoteBody), http.StatusNotFound, "mailbox not found")
}

// A full wait list refuses the start with its own reason.
func TestStartMigrationRefusesWhenTheWaitListIsFull(t *testing.T) {
	script := migrationScript(t)
	answerLogin(t, true, "")
	for i := range maxQueuedMigrations {
		migrationQueue <- pendingMigration{id: int64(i)}
	}
	assertAnswer(t, startMigration(t, script, middleware.RoleAdmin, remoteBody), http.StatusTooManyRequests, `"reason":"too_many_migrations"`)
}

// A verified sign-in is queued under the lower-cased host, answered with 202 and
// audited.
func TestStartMigrationQueuesAVerifiedCopy(t *testing.T) {
	script := migrationScript(t)
	attempts := answerLogin(t, true, "")

	recorder := startMigration(t, script, middleware.RoleAdmin, remoteBody)
	assertAnswer(t, recorder, http.StatusAccepted, `"status":"queued"`)
	if body := jsonBody(t, recorder); body["id"] != float64(41) {
		t.Fatalf("answer = %v", body)
	}
	want := loginAttempt{"imap.example.com", 993, "ssl", "someone@example.com", "remote-secret"}
	if len(*attempts) != 1 || (*attempts)[0] != want {
		t.Fatalf("sign-in attempts = %+v, want %+v", *attempts, want)
	}
	select {
	case job := <-migrationQueue:
		if job.id != 41 || job.mailboxID != 2 || job.remote.Host != "imap.example.com" {
			t.Fatalf("queued job = %+v", job)
		}
	default:
		t.Fatal("nothing was queued")
	}
	if actions := auditActions(script); !slices.Equal(actions, []string{"mail.migration.start"}) {
		t.Fatalf("audit actions = %v", actions)
	}
}
