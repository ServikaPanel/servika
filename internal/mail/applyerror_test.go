package mail

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// captureApplyLog redirects the standard logger for one test and returns what
// the handler wrote to it.
func captureApplyLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previousOutput, previousFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousOutput)
		log.SetFlags(previousFlags)
	})
	return &buf
}

// The apply step used to put err.Error() into the response body. Every route
// that reaches it carries middleware.CustomerScope, so the lowest-privilege
// role was told the panel's schema identifiers, the host's mail storage layout,
// the rspamd configuration path, and, through the rspamd generator's own
// validation branch, a neighbouring tenant's domain name.
func TestAnApplyFailureTellsTheCallerNothingAboutTheHost(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		secret string
	}{
		{
			name:   "the panel schema",
			err:    errors.New("Error 1054 (42S22): Unknown column 'body_text' in 'field list'"),
			secret: "Unknown column",
		},
		{
			name:   "the mail storage layout",
			err:    errors.New("open /var/vmail/example.com/ali/.dovecot.sieve.new: permission denied"),
			secret: "/var/vmail/",
		},
		{
			name:   "the Sieve compiler output",
			err:    errors.New("sievec: /tmp/servika-sieve-9/.dovecot.sieve.new: line 7: unknown command"),
			secret: "unknown command",
		},
		{
			name:   "the rspamd configuration path",
			err:    errors.New("configtest: /etc/rspamd/local.d/settings.conf: syntax error"),
			secret: "/etc/rspamd/",
		},
		{
			// ApplyRspamdSettings spans EVERY enabled domain on the server, so
			// this branch names a domain the caller does not own.
			name:   "a neighbouring tenant",
			err:    fmt.Errorf("invalid domain: %q", "neighbour.example"),
			secret: "neighbour.example",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			logged := captureApplyLog(t)
			recorder := httptest.NewRecorder()

			writeApplyFailure(recorder, "apply sieve mailbox", 7, "could not apply the mail rules", c.err)

			body := recorder.Body.String()
			if strings.Contains(body, c.secret) {
				t.Errorf("the caller was told %q: %s", c.secret, body)
			}
			if !strings.Contains(body, "could not apply the mail rules") {
				t.Errorf("the caller was not told the operation failed: %s", body)
			}
			// The operator still needs the reason, or closing the leak just
			// makes the failure unfixable.
			if !strings.Contains(logged.String(), c.secret) {
				t.Errorf("the reason did not reach the log either: %s", logged.String())
			}
		})
	}
}

// A host that simply lacks the component is the one apply failure worth
// naming: the customer opens a ticket instead of retrying a save that can
// never work.
func TestAMissingComponentIsStillNamedToTheCaller(t *testing.T) {
	for _, sentinel := range []error{ErrSieveUnavailable, ErrRspamdUnavailable} {
		recorder := httptest.NewRecorder()
		writeApplyFailure(recorder, "apply sieve mailbox", 7, "could not apply the mail rules", sentinel)
		if !strings.Contains(recorder.Body.String(), sentinel.Error()) {
			t.Errorf("%v was replaced by a message the caller cannot act on: %s",
				sentinel, recorder.Body.String())
		}
	}
}

// sievec quotes the generated script back, and the script carries the mailbox
// owner's own filter match value, which nothing validates for CR or LF. Writing
// that to the log unfiltered lets the mailbox owner forge log lines.
func TestTheLoggedReasonCannotForgeALogLine(t *testing.T) {
	logged := captureApplyLog(t)
	forged := errors.New("sievec: line 3: \"x\"\npanel: root logged in from 10.0.0.1")

	writeApplyFailure(httptest.NewRecorder(), "apply sieve mailbox", 7, "could not apply the mail rules", forged)

	written := strings.TrimSuffix(logged.String(), "\n")
	if strings.ContainsAny(written, "\r\n") {
		t.Errorf("one failure produced more than one log line: %q", written)
	}
}

// A future call site that concatenates the error back in is the same defect
// under another name, so the files are checked as a whole. A 400 is exempt:
// there the error is the package's own validation text (validateFilter,
// validateSpamSettings), not the host's.
func TestNoMailHandlerPutsAHostErrorInTheResponse(t *testing.T) {
	for _, name := range []string{"sieve.go", "spam.go", "queue.go"} {
		body, err := os.ReadFile(name) // #nosec G304 -- a file of this package.
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(body), "\n") {
			if !strings.Contains(line, "httpx.WriteError(") || !strings.Contains(line, "err.Error()") {
				continue
			}
			if strings.Contains(line, "StatusServiceUnavailable") || strings.Contains(line, "StatusInternalServerError") {
				t.Errorf("%s:%d hands the host's own error to the caller: %s",
					name, i+1, strings.TrimSpace(line))
			}
		}
	}
}
