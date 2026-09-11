package mail

import (
	"context"
	"database/sql/driver"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	cursorRead    = "FROM mail_log_cursor WHERE id = 1"
	hostedRead    = "SELECT domain_name, domain_id FROM mail_domains"
	deliveryStore = "INSERT INTO mail_delivery_log(domain_id, ts, direction"
	cursorSave    = "INSERT INTO mail_log_cursor(id, `offset`, `size`)"
	deliveryPrune = "DELETE FROM mail_delivery_log WHERE ts < NOW() - INTERVAL ? DAY"

	senderLine    = "Aug  6 07:12:32 host postfix/qmgr[1200]: A1B2C3D4: from=<sender@example.com>, size=1234, nrcpt=1 (queue active)\n"
	outboundLine  = "Aug  6 07:12:33 host postfix/smtp[1234]: A1B2C3D4: to=<user@example.net>, relay=mx.example.net[1.2.3.4]:25, delay=1.2, dsn=2.0.0, status=sent (250 2.0.0 OK)\n"
	inboundSender = "Aug  6 07:13:32 host postfix/qmgr[1200]: C1C2C3C4: from=<outside@elsewhere.test>, size=99, nrcpt=1 (queue active)\n"
	inboundLine   = "Aug  6 07:13:33 host postfix/lmtp[1234]: C1C2C3C4: to=<info@example.com>, status=sent (250 2.0.0 Saved)\n"
	unhostedLine  = "Aug  6 07:12:34 host postfix/smtp[1234]: B1B2C3D4: to=<x@elsewhere.test>, status=sent (250 OK)\n"
)

func collectScript(offset, size int64) *sqlScript {
	s := newScript()
	s.rows[cursorRead] = [][]driver.Value{{offset, size}}
	s.rows[hostedRead] = [][]driver.Value{{"example.com", int64(1)}}
	return s
}

func writeMailLog(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "maillog")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write the mail log: %v", err)
	}
	t.Setenv("SERVIKA_MAIL_LOG", path)
	return path
}

// A host without a mail log is a host without mail, not a fault.
func TestCollectDeliveryLogWithoutALogDoesNothing(t *testing.T) {
	t.Setenv("SERVIKA_MAIL_LOG", filepath.Join(t.TempDir(), "absent"))
	script := collectScript(0, 0)
	if err := CollectDeliveryLog(context.Background(), scriptDB(t, script)); err != nil {
		t.Fatalf("CollectDeliveryLog: %v", err)
	}
	if script.stepIndex("") >= 0 {
		t.Fatal("the database was touched without a log")
	}
}

// One pass stores the hosted delivery, skips the rest, and moves the cursor past
// the last whole line in the same transaction, then prunes.
func TestCollectDeliveryLogStoresTheNewDeliveries(t *testing.T) {
	complete := senderLine + outboundLine + unhostedLine + strings.Repeat("x", maxLogLineBytes+10) + "\n"
	content := complete + "Aug  6 07:14:00 host postfix/smtp[1234]: D1"
	writeMailLog(t, content)
	logged := captureApplyLog(t)
	script := collectScript(0, 0)

	if err := CollectDeliveryLog(context.Background(), scriptDB(t, script)); err != nil {
		t.Fatalf("CollectDeliveryLog: %v", err)
	}
	store := script.onlyExec(t, deliveryStore)
	if got := slices.Delete(slices.Clone(store.args), 1, 2); !slices.Equal(got,
		[]driver.Value{int64(1), "out", "sender@example.com", "user@example.net", "sent", "250 2.0.0 OK", "A1B2C3D4"}) {
		t.Fatalf("stored %#v", store.args)
	}
	if cursor := script.onlyExec(t, cursorSave); !slices.Equal(cursor.args, []driver.Value{int64(len(complete)), int64(len(content))}) {
		t.Fatalf("cursor %#v, want %d/%d", cursor.args, len(complete), len(content))
	}
	for _, pair := range [][2]string{{"BEGIN", deliveryStore}, {deliveryStore, cursorSave}, {cursorSave, "COMMIT"}, {"COMMIT", deliveryPrune}} {
		stepsInOrder(pair[0], pair[1])(t, script)
	}
	if !strings.Contains(logged.String(), "skipped 1 line(s) longer than") {
		t.Fatalf("log = %q", logged.String())
	}
}

// The cursor decides where reading starts: past what was stored, from the top of
// a rotated file, or nowhere at all when nothing was appended.
func TestCollectDeliveryLogFollowsItsCursor(t *testing.T) {
	first := senderLine + outboundLine
	content := first + inboundSender + inboundLine
	cases := []struct {
		name         string
		offset       int64
		wantDirected []driver.Value
	}{
		{"appended lines only", int64(len(first)), []driver.Value{"in"}},
		{"a rotated file from the top", int64(len(content) + 100), []driver.Value{"out", "in"}},
		{"nothing appended", int64(len(content)), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			writeMailLog(t, content)
			script := collectScript(c.offset, c.offset)
			if err := CollectDeliveryLog(context.Background(), scriptDB(t, script)); err != nil {
				t.Fatalf("CollectDeliveryLog: %v", err)
			}
			var directions []driver.Value
			for _, store := range script.execsContaining(deliveryStore) {
				directions = append(directions, store.args[2])
			}
			if !slices.Equal(directions, c.wantDirected) || len(script.execsContaining(deliveryPrune)) != 1 {
				t.Fatalf("directions = %v, prunes = %d", directions, len(script.execsContaining(deliveryPrune)))
			}
		})
	}
}

// A pass longer than one batch writes the batch as soon as it fills, and the
// final write still moves the cursor.
func TestCollectDeliveryLogFlushesInBatches(t *testing.T) {
	writeMailLog(t, senderLine+strings.Repeat(outboundLine, maxPendingDeliveries))
	script := collectScript(0, 0)
	if err := CollectDeliveryLog(context.Background(), scriptDB(t, script)); err != nil {
		t.Fatalf("CollectDeliveryLog: %v", err)
	}
	if stores, cursors := len(script.execsContaining(deliveryStore)), len(script.execsContaining(cursorSave)); stores != maxPendingDeliveries || cursors != 2 {
		t.Fatalf("stores = %d, cursor writes = %d", stores, cursors)
	}
}

// Every failure of a pass is returned.
func TestCollectDeliveryLogFailures(t *testing.T) {
	cases := map[string]struct {
		content string
		setup   func(*sqlScript)
	}{
		"the hosted domains cannot be read": {senderLine + outboundLine, func(s *sqlScript) { s.fail[hostedRead] = errScripted }},
		"the batch cannot open":             {senderLine + outboundLine, func(s *sqlScript) { s.failBegin = errScripted }},
		"a full batch cannot open":          {senderLine + strings.Repeat(outboundLine, maxPendingDeliveries), func(s *sqlScript) { s.failBegin = errScripted }},
		"the insert cannot be prepared":     {senderLine + outboundLine, func(s *sqlScript) { s.prepareFail[deliveryStore] = errScripted }},
		"a delivery cannot be stored":       {senderLine + outboundLine, func(s *sqlScript) { s.fail[deliveryStore] = errScripted }},
		"the cursor cannot be saved":        {senderLine + outboundLine, func(s *sqlScript) { s.fail[cursorSave] = errScripted }},
		"the commit fails":                  {senderLine + outboundLine, func(s *sqlScript) { s.failCommit = errScripted }},
		"the prune fails":                   {senderLine + outboundLine, func(s *sqlScript) { s.fail[deliveryPrune] = errScripted }},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			writeMailLog(t, c.content)
			script := collectScript(0, 0)
			c.setup(script)
			if err := CollectDeliveryLog(context.Background(), scriptDB(t, script)); err == nil {
				t.Fatal("the failure was not returned")
			}
		})
	}
}

// A log the panel may stat but not open is an error, not an empty pass.
func TestCollectDeliveryLogReportsALogItCannotOpen(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens a file whatever its mode")
	}
	path := writeMailLog(t, senderLine+outboundLine)
	if err := os.Chmod(path, 0); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := CollectDeliveryLog(context.Background(), scriptDB(t, collectScript(0, 0))); err == nil {
		t.Fatal("an unreadable log was not reported")
	}
}
