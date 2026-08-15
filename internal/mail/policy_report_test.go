package mail

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

// capturePolicyLog runs fn with the standard logger redirected and returns what
// it wrote. The policy handler reports through log.Printf, so this is what the
// operator would actually see.
func capturePolicyLog(t *testing.T, fn func(client net.Conn)) string {
	t.Helper()

	var buf bytes.Buffer
	previousOutput := log.Writer()
	previousFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousOutput)
		log.SetFlags(previousFlags)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		server, e := listener.Accept()
		if e != nil {
			return
		}
		// A nil database is safe here: every request below leaves sasl_username
		// empty, and evaluateSendPolicy answers DUNNO before it touches the DB.
		handlePolicyConnection(nil, server)
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	fn(client)
	_ = client.Close()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the handler did not return")
	}
	return buf.String()
}

// Postfix applies smtpd_policy_service_default_action=DUNNO when this service
// does not answer, so a request that is received and never answered means the
// send limit did not apply to that mail. That must not pass silently.
func TestAnUnansweredRequestIsReported(t *testing.T) {
	output := capturePolicyLog(t, func(client net.Conn) {
		// Attributes, then a close instead of the blank line that asks for a
		// verdict.
		_, _ = fmt.Fprint(client, "request=smtpd\nsasl_username=\nsize=1024\n")
	})

	if !strings.Contains(output, "the send limit did not apply to that mail") {
		t.Errorf("an unanswered request was not reported; log was:\n%s", output)
	}
	if !strings.Contains(output, "3 attributes") {
		t.Errorf("the report does not say how much was pending; log was:\n%s", output)
	}
}

// A line past bufio.MaxScanTokenSize stops the scanner for good. The handler
// then closes without answering, which is the same silent non-enforcement.
func TestAReadErrorIsReported(t *testing.T) {
	output := capturePolicyLog(t, func(client net.Conn) {
		_, _ = fmt.Fprint(client, "k="+strings.Repeat("x", 70*1024)+"\n")
	})

	if !strings.Contains(output, "mail policy read:") {
		t.Errorf("a read error was not reported; log was:\n%s", output)
	}
	if !strings.Contains(output, bufio.ErrTooLong.Error()) {
		t.Errorf("the report does not name the error; log was:\n%s", output)
	}
}

// The ordinary exchange must stay silent, or the report is noise an operator
// learns to ignore. Postfix keeps a policy connection open across mails, so the
// second request also has to be answered on the same connection.
func TestAnAnsweredRequestIsNotReported(t *testing.T) {
	output := capturePolicyLog(t, func(client net.Conn) {
		reader := bufio.NewReader(client)
		for i := range 2 {
			_, _ = fmt.Fprint(client, "request=smtpd\nsasl_username=\n\n")
			verdict, err := reader.ReadString('\n')
			if err != nil {
				t.Errorf("request %d went unanswered: %v", i+1, err)
				return
			}
			if strings.TrimSpace(verdict) != "action=DUNNO" {
				t.Errorf("request %d answered %q", i+1, strings.TrimSpace(verdict))
			}
			// Consume the blank line that terminates the reply.
			_, _ = reader.ReadString('\n')
		}
	})

	if output != "" {
		t.Errorf("a healthy exchange wrote to the log:\n%s", output)
	}
}
