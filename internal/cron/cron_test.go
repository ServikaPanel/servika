package cron

import (
	"strings"
	"testing"
)

// testSecret signs the reporter token in tests; its exact bytes do not matter,
// only that serialize and the token check use the same value.
var testSecret = []byte("0123456789abcdef0123456789abcdef")

// A crontab written by the panel must read back into the same tasks: the
// schedule, the command, the comment, and the rich fields (type, PHP version,
// enabled) that ride in the metadata comment.
func TestSerializeParseRoundTrip(t *testing.T) {
	in := []Task{
		{Minute: "0", Hour: "3", Day: "*", Month: "*", Week: "*", Command: "/usr/bin/php /home/c_site/cron.php", Comment: "nightly", Enabled: true, Type: TypeCommand},
		{Minute: "*/5", Hour: "*", Day: "*", Month: "*", Week: "*", Command: "curl -fsS -o /dev/null --max-time 300 'https://example.com/ping'", Enabled: false, Type: TypeURL},
		{Minute: "30", Hour: "2", Day: "1", Month: "*", Week: "*", Command: "/opt/remi/php83/root/usr/bin/php -q '/home/c_site/run.php'", Enabled: true, Type: TypePHP, PHPVersion: "8.3"},
	}
	data := serializeCrontab("c_site", 1, testSecret, in)
	out, err := parseCrontab(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("parseCrontab: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("got %d tasks, want %d\n%s", len(out), len(in), data)
	}
	for i := range in {
		w, g := in[i], out[i]
		if g.Minute != w.Minute || g.Hour != w.Hour || g.Day != w.Day || g.Month != w.Month || g.Week != w.Week {
			t.Errorf("task %d schedule = %v, want %v", i, g, w)
		}
		if g.Command != w.Command {
			t.Errorf("task %d command = %q, want %q", i, g.Command, w.Command)
		}
		if g.Comment != w.Comment {
			t.Errorf("task %d comment = %q, want %q", i, g.Comment, w.Comment)
		}
		if g.Enabled != w.Enabled {
			t.Errorf("task %d enabled = %v, want %v", i, g.Enabled, w.Enabled)
		}
		if g.Type != w.Type {
			t.Errorf("task %d type = %q, want %q", i, g.Type, w.Type)
		}
		if g.PHPVersion != w.PHPVersion {
			t.Errorf("task %d php_version = %q, want %q", i, g.PHPVersion, w.PHPVersion)
		}
	}
}

// A disabled task's cron line is commented out with a leading '#' so crond never
// runs it, but the panel still parses it back.
func TestDisabledTaskIsCommentedButStillParsed(t *testing.T) {
	data := serializeCrontab("c_site", 1, testSecret, []Task{
		{Minute: "0", Hour: "0", Day: "*", Month: "*", Week: "*", Command: "backup.sh", Enabled: false, Type: TypeCommand},
	})
	if !strings.Contains(string(data), "#0 0 * * * backup.sh") {
		t.Errorf("disabled task line is not commented out:\n%s", data)
	}
	out, err := parseCrontab(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("parseCrontab: %v", err)
	}
	if len(out) != 1 || out[0].Enabled {
		t.Fatalf("disabled task not parsed back as disabled: %+v", out)
	}
	if out[0].Command != "backup.sh" {
		t.Errorf("disabled task command = %q", out[0].Command)
	}
}

// A human comment that is not a cron schedule stays a comment, never a task.
func TestHumanCommentIsNotReadAsATask(t *testing.T) {
	const crontab = "# servika cron: managed\n# just a note\n0 5 * * * daily.sh\n"
	out, err := parseCrontab(strings.NewReader(crontab))
	if err != nil {
		t.Fatalf("parseCrontab: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d tasks, want 1: %+v", len(out), out)
	}
	if out[0].Comment != "just a note" {
		t.Errorf("comment = %q, want %q", out[0].Comment, "just a note")
	}
}

// buildCommand turns a URL task into a curl command and refuses a URL that
// carries a shell metacharacter, because the URL is interpolated into a
// single-quoted argument.
func TestBuildCommandURL(t *testing.T) {
	cmd, err := buildCommand(taskInput{Task: Task{Type: TypeURL}, URL: "https://example.com/cron.php"})
	if err != nil {
		t.Fatalf("buildCommand: %v", err)
	}
	if !strings.Contains(cmd, "curl ") || !strings.Contains(cmd, "'https://example.com/cron.php'") {
		t.Errorf("unexpected command: %q", cmd)
	}
	if _, err := buildCommand(taskInput{Task: Task{Type: TypeURL}, URL: "https://example.com/'; rm -rf /"}); err == nil {
		t.Error("buildCommand accepted a URL with a shell metacharacter")
	}
	if _, err := buildCommand(taskInput{Task: Task{Type: TypeURL}, URL: "ftp://example.com"}); err == nil {
		t.Error("buildCommand accepted a non-http URL")
	}
}

// A command-type task passes its command through unchanged.
func TestBuildCommandPassThrough(t *testing.T) {
	cmd, err := buildCommand(taskInput{Task: Task{Type: TypeCommand, Command: "/usr/bin/php x.php | tee log"}})
	if err != nil {
		t.Fatalf("buildCommand: %v", err)
	}
	if cmd != "/usr/bin/php x.php | tee log" {
		t.Errorf("command was altered: %q", cmd)
	}
}

// A notifying task's cron line runs the reporter, but the panel reads back the
// ORIGINAL command and the notify mode, because the original is stored base64'd
// in the metadata comment.
func TestNotifyWrapsTheLineAndReconstructsTheCommand(t *testing.T) {
	in := []Task{
		{Minute: "*/5", Hour: "*", Day: "*", Month: "*", Week: "*", Command: "/usr/bin/php /home/c_site/cron.php", Enabled: true, Type: TypeCommand, Notify: NotifyErrors},
	}
	data := serializeCrontab("c_site", 42, testSecret, in)
	// The rendered cron line runs the reporter, not the raw command.
	if !strings.Contains(string(data), "servika-cron-report 42 errors ") {
		t.Fatalf("cron line does not run the reporter:\n%s", data)
	}
	if strings.Contains(string(data), "*/5 * * * * /usr/bin/php /home/c_site/cron.php\n") {
		t.Fatalf("cron line runs the raw command instead of the reporter:\n%s", data)
	}
	out, err := parseCrontab(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("parseCrontab: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d tasks, want 1", len(out))
	}
	if out[0].Command != in[0].Command {
		t.Errorf("command = %q, want %q", out[0].Command, in[0].Command)
	}
	if out[0].Notify != NotifyErrors {
		t.Errorf("notify = %q, want %q", out[0].Notify, NotifyErrors)
	}
}

// A task with no notification wraps nothing: the cron line runs the command
// directly and no reporter token is written.
func TestNoNotifyLeavesTheLineBare(t *testing.T) {
	data := serializeCrontab("c_site", 1, testSecret, []Task{
		{Minute: "0", Hour: "3", Day: "*", Month: "*", Week: "*", Command: "backup.sh", Enabled: true, Type: TypeCommand},
	})
	if strings.Contains(string(data), "servika-cron-report") {
		t.Fatalf("a non-notifying task wrapped the reporter:\n%s", data)
	}
}

// The reporter token is domain-bound and deterministic: the same domain always
// yields the same token, and a different domain yields a different one, so a
// tenant can only ever authenticate their own domain.
func TestReportTokenIsDomainBound(t *testing.T) {
	a := reportToken(testSecret, 1)
	if a == "" || a != reportToken(testSecret, 1) {
		t.Fatalf("token is not stable for one domain: %q", a)
	}
	if a == reportToken(testSecret, 2) {
		t.Error("two domains produced the same token")
	}
	if a == reportToken([]byte("a-different-secret-key-of-32-bytes"), 1) {
		t.Error("a different secret produced the same token")
	}
}

func TestLooksCron(t *testing.T) {
	cases := map[string]bool{
		"0 3 * * * backup.sh":      true,
		"*/5 * * * * ping.sh":      true,
		"just a note here for you": false,
		"0 3 * * *":                false, // no command
		"@reboot something":        false, // @reboot is not the five-field form
	}
	for line, want := range cases {
		if got := looksCron(line); got != want {
			t.Errorf("looksCron(%q) = %v, want %v", line, got, want)
		}
	}
}
