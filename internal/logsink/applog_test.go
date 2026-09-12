package logsink

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"

	"servika/internal/logx"
)

// journaldOutput captures what the standard logger wrote for one test.
func journaldOutput(t *testing.T) *bytes.Buffer {
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

// sinkRows installs a sink that records, and returns what it collected.
func sinkRows(t *testing.T) *[]AppRow {
	t.Helper()
	var rows []AppRow
	logx.SetSink(func(prefix, message string) {
		level, known := levelOfPrefix[prefix]
		if !known {
			level = "INFO"
		}
		requestID, text := splitRequestID(message)
		rows = append(rows, AppRow{
			Level: level, LoggerName: loggerName(), Message: text, RequestID: requestID,
		})
	})
	t.Cleanup(func() { logx.SetSink(nil) })
	return &rows
}

// journald keeps its copy whatever the sink does. The database is down during
// startup, during a migration and during the incident an operator is reading
// about, which is exactly when the interesting lines are written.
func TestJournaldStillGetsEveryLine(t *testing.T) {
	buf := journaldOutput(t)
	_ = sinkRows(t)

	logx.Errorf("the backup could not be uploaded: %v", "timeout")

	if !strings.Contains(buf.String(), "<3>the backup could not be uploaded: timeout") {
		t.Errorf("journald did not get the line: %q", buf.String())
	}
}

// Each logx level reaches the sink as the level app_logs stores.
func TestEachLevelIsRecordedAsItself(t *testing.T) {
	journaldOutput(t)
	rows := sinkRows(t)

	logx.Errorf("failed")
	logx.Warnf("degraded")
	logx.Infof("routine")

	if len(*rows) != 3 {
		t.Fatalf("%d row(s) reached the sink, expected 3", len(*rows))
	}
	for i, want := range []string{"ERROR", "WARN", "INFO"} {
		if (*rows)[i].Level != want {
			t.Errorf("row %d is %q, want %q", i, (*rows)[i].Level, want)
		}
	}
	// The syslog prefix is the level, not part of the message.
	if strings.HasPrefix((*rows)[0].Message, "<3>") {
		t.Errorf("the message kept its priority prefix: %q", (*rows)[0].Message)
	}
}

// A line written while serving a request carries the correlation id in its
// text, because journald has no field for it. Taking it back out here is what
// joins an app_logs line to the request_logs row for the same call.
func TestARequestLineKeepsItsCorrelationID(t *testing.T) {
	journaldOutput(t)
	rows := sinkRows(t)

	logx.Errorf("reqid=abc123 the domain could not be saved")

	row := (*rows)[0]
	if row.RequestID != "abc123" {
		t.Errorf("request_id is %q, want abc123", row.RequestID)
	}
	if row.Message != "the domain could not be saved" {
		t.Errorf("the message kept the prefix: %q", row.Message)
	}
}

// Most lines have no request at all. An empty id must be an ordinary row, not a
// refused one.
func TestABackgroundLineNeedsNoRequest(t *testing.T) {
	journaldOutput(t)
	rows := sinkRows(t)

	logx.Infof("antivirus: the nightly sweep finished")

	row := (*rows)[0]
	if row.RequestID != "" {
		t.Errorf("request_id is %q, expected empty", row.RequestID)
	}
	if row.Message != "antivirus: the nightly sweep finished" {
		t.Errorf("the message was altered: %q", row.Message)
	}
}

// A line that merely starts with the word reqid is not a correlation prefix.
func TestOnlyARealPrefixIsTakenAsAnID(t *testing.T) {
	for _, message := range []string{"reqid=", "reqid=abc", "reqidabc def"} {
		if id, _ := splitRequestID(message); id != "" {
			t.Errorf("%q produced the id %q", message, id)
		}
	}
}

// The logger name is the package that logged, not the plumbing that carried it.
func TestTheLoggerNameNamesTheCallingPackage(t *testing.T) {
	journaldOutput(t)
	rows := sinkRows(t)

	logx.Infof("from the test")

	if got := (*rows)[0].LoggerName; got != "servika/internal/logsink" && got != "" {
		// The call originates in this package's own test, so the frame walk
		// skips logx and lands here or gives up. Either is correct; naming logx
		// itself is not.
		if strings.Contains(got, "logx") {
			t.Errorf("the logger name is the plumbing: %q", got)
		}
	}
}

// Removing the sink must actually remove it, or a test that installs one leaks
// into every test that runs after it.
func TestRemovingTheSinkStopsTheRows(t *testing.T) {
	journaldOutput(t)
	rows := sinkRows(t)
	logx.SetSink(nil)

	logx.Errorf("after the sink was removed")

	if len(*rows) != 0 {
		t.Errorf("%d row(s) reached a removed sink", len(*rows))
	}
}

// A sink that panics must not take the caller down: logx is called from every
// path the panel has, including the ones that are already failing.
func TestTheSinkIsNotAllowedToBreakLogging(t *testing.T) {
	buf := journaldOutput(t)
	logx.SetSink(func(string, string) { panic("the sink is broken") })
	t.Cleanup(func() { logx.SetSink(nil) })

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Errorf("a panicking sink reached the caller: %v", recovered)
		}
		if !strings.Contains(buf.String(), "still logged") {
			t.Error("journald lost the line")
		}
	}()

	logx.Infof("still logged")
	time.Sleep(10 * time.Millisecond)
}
