package logx

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

// captureLog redirects the standard logger for one test.
func captureLog(t *testing.T) *bytes.Buffer {
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

// journald reads the priority off the START of the line. A prefix anywhere else
// is text, so the whole point of the level is the position.
func TestEachLevelLeadsItsLineWithItsSyslogPriority(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func()
		want  string
	}{
		{name: "error", write: func() { Errorf("nginx -t refused %s", "the vhost") }, want: "<3>nginx -t refused the vhost"},
		{name: "warn", write: func() { Warnf("kept the stale %s", "settings") }, want: "<4>kept the stale settings"},
		{name: "info", write: func() { Infof("watching %s", "/home") }, want: "<6>watching /home"},
		{name: "error, unformatted", write: func() { Error("the socket closed") }, want: "<3>the socket closed"},
		{name: "warn, unformatted", write: func() { Warn("events were dropped") }, want: "<4>events were dropped"},
		{name: "info, unformatted", write: func() { Info("listening") }, want: "<6>listening"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logged := captureLog(t)

			tc.write()

			if got := strings.TrimRight(logged.String(), "\n"); got != tc.want {
				t.Errorf("logged %q, want %q", got, tc.want)
			}
		})
	}
}

// The line still goes through the standard logger, which is what every test in
// the panel that reads its own log output depends on.
func TestTheLineGoesThroughTheStandardLogger(t *testing.T) {
	logged := captureLog(t)

	Infof("one")
	log.Printf("two")

	if got := logged.String(); got != "<6>one\ntwo\n" {
		t.Errorf("the two writers disagree: %q", got)
	}
}
