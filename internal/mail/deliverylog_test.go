package mail

import (
	"bufio"
	"strings"
	"testing"
	"time"
)

// Postfix spreads one delivery across two lines joined by the queue ID. Reading
// only the smtp line loses the sender; reading only the qmgr line loses the
// outcome.
func TestParsesTheTwoHalvesOfADelivery(t *testing.T) {
	reference := time.Date(2026, time.August, 6, 12, 0, 0, 0, time.UTC)
	qmgr := "Aug  6 07:12:32 host postfix/qmgr[1200]: A1B2C3D4: from=<sender@example.com>, size=1234, nrcpt=1 (queue active)"
	smtp := "Aug  6 07:12:33 host postfix/smtp[1234]: A1B2C3D4: to=<user@example.net>, relay=mx.example.net[1.2.3.4]:25, delay=1.2, dsn=2.0.0, status=sent (250 2.0.0 OK)"

	queueID, sender, ok := parseSender(qmgr)
	if !ok {
		t.Fatal("the qmgr line was not recognised")
	}
	if queueID != "A1B2C3D4" || sender != "sender@example.com" {
		t.Errorf("qmgr line = %q/%q, want A1B2C3D4/sender@example.com", queueID, sender)
	}

	record, ok := parseDelivery(smtp, reference)
	if !ok {
		t.Fatal("the smtp line was not recognised")
	}
	assertParsedDelivery(t, record, queueID)
}

// assertParsedDelivery checks the smtp half against the qmgr half it belongs to.
func assertParsedDelivery(t *testing.T, record deliveryRecord, queueID string) {
	t.Helper()
	if record.QueueID != queueID {
		t.Errorf("queue ID = %q, want %q", record.QueueID, queueID)
	}
	if record.Recipient != "user@example.net" || record.Status != "sent" {
		t.Errorf("delivery = %q/%q, want user@example.net/sent", record.Recipient, record.Status)
	}
	if record.Reason != "250 2.0.0 OK" {
		t.Errorf("reason = %q, want the server's reply", record.Reason)
	}
	if record.At.Hour() != 7 || record.At.Minute() != 12 {
		t.Errorf("timestamp = %v, want 07:12", record.At)
	}
}

// Newer rsyslog writes RFC3339. A parser that only understood the traditional
// format would silently store nothing on such a host.
func TestParsesTheRFC3339LogFormat(t *testing.T) {
	line := "2026-08-06T07:12:33.451+03:00 host postfix/smtp[1234]: A1B2C3D4: to=<user@example.net>, status=bounced (550 5.1.1 unknown)"
	record, ok := parseDelivery(line, time.Now())
	if !ok {
		t.Fatal("the RFC3339 line was not recognised")
	}
	if record.Status != "bounced" || record.Recipient != "user@example.net" {
		t.Errorf("delivery = %q/%q", record.Recipient, record.Status)
	}
	if record.At.Year() != 2026 || record.At.Month() != time.August {
		t.Errorf("timestamp = %v, want August 2026", record.At)
	}
}

// The traditional format carries no year. Filing a December line read in January
// under the current year would put it eleven months in the future, where nobody
// looking at "recent deliveries" would ever see it.
func TestUndatedTimestampRollsBackOverNewYear(t *testing.T) {
	reference := time.Date(2027, time.January, 2, 3, 0, 0, 0, time.UTC)
	at, ok := parseTimestamp("Dec 31 23:59:00", reference)
	if !ok {
		t.Fatal("the timestamp was not parsed")
	}
	if at.Year() != 2026 || at.Month() != time.December {
		t.Errorf("timestamp = %v, want December 2026", at)
	}
}

// A remote peer chooses its own envelope addresses and the text Postfix quotes
// back from it. Storing that verbatim would let it write its own lines into any
// view that renders the value.
//
// The escape and bell characters below matter more than the CR/LF: splitting the
// line into fields already drops those two, but nothing else strips a terminal
// escape sequence, and that is what turns a log view into a place where a remote
// server chooses what the operator reads.
func TestControlCharactersAreStrippedFromLogValues(t *testing.T) {
	line := "Aug  6 07:12:33 host postfix/smtp[1234]: A1B2C3D4: to=<user@example.net>, " +
		"status=deferred (450 4.7.1 \x1b[2Jcleared\x07 try\r\nagain later)"
	record, ok := parseDelivery(line, time.Now())
	if !ok {
		t.Fatal("the line was not recognised")
	}
	for _, r := range record.Reason {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("the reason still carries control character %q: %q", r, record.Reason)
		}
	}
	if !strings.Contains(record.Reason, "cleared") {
		t.Errorf("stripping removed the readable text too: %q", record.Reason)
	}
	if len(record.Reason) > maxReasonLen {
		t.Errorf("the reason is %d characters, over the %d column width", len(record.Reason), maxReasonLen)
	}
}

// A reason longer than its column has to be cut rather than rejected, so one
// pathological line does not lose the whole delivery record.
func TestOverlongReasonIsTruncatedNotDropped(t *testing.T) {
	long := strings.Repeat("x", maxReasonLen*2)
	line := "Aug  6 07:12:33 host postfix/smtp[1234]: A1B2C3D4: to=<user@example.net>, status=bounced (" + long + ")"
	record, ok := parseDelivery(line, time.Now())
	if !ok {
		t.Fatal("an overlong line was dropped instead of being truncated")
	}
	if len(record.Reason) > maxReasonLen {
		t.Errorf("the reason is %d characters, over the %d column width", len(record.Reason), maxReasonLen)
	}
}

// The status column is an enum. A value Postfix emits that the column has no
// room for must be skipped, not stored under a guessed name that would then be
// filtered on and never match.
func TestUnknownStatusIsSkipped(t *testing.T) {
	line := "Aug  6 07:12:33 host postfix/smtp[1234]: A1B2C3D4: to=<user@example.net>, status=softbounce (450 try later)"
	if record, ok := parseDelivery(line, time.Now()); ok {
		t.Errorf("an unknown status was accepted as %q", record.Status)
	}
}

// A message between two hosted domains concerns both customers, and neither
// should have to read the other's view to find it.
func TestDeliveryBetweenTwoHostedDomainsIsFiledOnBothSides(t *testing.T) {
	hosted := map[string]int64{"example.com": 1, "example.net": 2}
	record := deliveryRecord{Sender: "a@example.com", Recipient: "b@example.net", Status: "sent"}

	got := matchDomains(record, hosted)
	if len(got) != 2 {
		t.Fatalf("matchDomains returned %d rows, want 2", len(got))
	}
	if got[0].DomainID != 1 || got[0].Direction != "out" {
		t.Errorf("the sender side = domain %d/%s, want 1/out", got[0].DomainID, got[0].Direction)
	}
	if got[1].DomainID != 2 || got[1].Direction != "in" {
		t.Errorf("the recipient side = domain %d/%s, want 2/in", got[1].DomainID, got[1].Direction)
	}
}

// A delivery that touches no hosted domain belongs to nobody here. Storing it
// would put another server's correspondence in a customer's view.
func TestDeliveryForAnUnhostedDomainIsNotStored(t *testing.T) {
	hosted := map[string]int64{"example.com": 1}
	record := deliveryRecord{Sender: "a@elsewhere.test", Recipient: "b@another.test"}
	if got := matchDomains(record, hosted); len(got) != 0 {
		t.Errorf("matchDomains returned %d rows for an unhosted delivery", len(got))
	}
}

// A search term is put into a LIKE pattern. Without escaping, "%" would mean
// "match everything" instead of the character the user typed.
func TestSearchWildcardsAreEscaped(t *testing.T) {
	if got := escapeLike("a%b_c"); got != `a\%b\_c` {
		t.Errorf("escapeLike = %q, want a\\%%b\\_c", got)
	}
	if got := escapeLike(`a\b`); got != `a\\b` {
		t.Errorf("escapeLike = %q, want a\\\\b", got)
	}
}

// bufio's ReadString does not stop at the buffer size: it grows until it finds
// the delimiter. A file with no newline in it would therefore be read into
// memory whole, so the reader carries its own ceiling.
func TestAnOverlongLogLineIsSkippedWholeRatherThanReadIn(t *testing.T) {
	giant := strings.Repeat("x", maxLogLineBytes+1024)
	real := "Aug  6 07:12:33 host postfix/smtp[1234]: A1B2C3D4: to=<user@example.net>, status=sent (250 2.0.0 OK)"
	reader := bufio.NewReaderSize(strings.NewReader(giant+"\n"+real+"\n"), 256*1024)

	line, read, status, err := readLogLine(reader)
	if err != nil {
		t.Fatalf("readLogLine: %v", err)
	}
	if status != lineOversize {
		t.Errorf("status = %v, want lineOversize", status)
	}
	if line != "" {
		t.Errorf("an oversize line returned %d bytes of content", len(line))
	}
	// It is still CONSUMED: the cursor has to move past it or the next pass
	// reads the same line again for ever.
	if read != int64(len(giant)+1) {
		t.Errorf("consumed = %d, want the whole oversize line (%d)", read, len(giant)+1)
	}

	// The other direction, and the point of skipping rather than failing: the
	// ordinary line after it must still arrive intact.
	line, _, status, err = readLogLine(reader)
	if err != nil {
		t.Fatalf("readLogLine after the oversize line: %v", err)
	}
	if status != lineComplete {
		t.Errorf("status = %v, want lineComplete", status)
	}
	if strings.TrimRight(line, "\n") != real {
		t.Errorf("the line after the oversize one was not read whole: %q", line)
	}
	if record, ok := parseDelivery(line, time.Now()); !ok || record.Status != "sent" {
		t.Errorf("the recovered line no longer parses: %+v, ok=%v", record, ok)
	}
}

// The ceiling must not touch a real line. rsyslog truncates at 8 KiB by
// default, so anything Postfix writes is far below it.
func TestAnOrdinaryLogLineIsNeverTruncated(t *testing.T) {
	line := "Aug  6 07:12:33 host postfix/smtp[1234]: A1B2C3D4: to=<user@example.net>, " +
		"relay=mx.example.net[1.2.3.4]:25, status=sent (" + strings.Repeat("z", 4096) + ")"
	reader := bufio.NewReaderSize(strings.NewReader(line+"\n"), 256*1024)

	got, read, status, err := readLogLine(reader)
	if err != nil {
		t.Fatalf("readLogLine: %v", err)
	}
	if status != lineComplete {
		t.Fatalf("status = %v, want lineComplete", status)
	}
	if strings.TrimRight(got, "\n") != line {
		t.Error("an ordinary line was altered")
	}
	if read != int64(len(line)+1) {
		t.Errorf("consumed = %d, want %d", read, len(line)+1)
	}
}

// A final line without a newline is still being written. Reporting it as
// complete would parse half a record and move the cursor past it, so the rest
// would never be read.
func TestALineStillBeingWrittenIsNotConsumed(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader("Aug  6 07:12:33 host postfix/smtp[1234]: A1B2"), 256*1024)

	if _, _, status, _ := readLogLine(reader); status != lineIncomplete {
		t.Errorf("status = %v, want lineIncomplete", status)
	}
}
