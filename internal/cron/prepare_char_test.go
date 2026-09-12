package cron

import (
	"strings"
	"testing"

	"servika/internal/phpversion"
)

// setForTest replaces a package variable for one test.
func setForTest[T any](t *testing.T, target *T, value T) {
	t.Helper()
	previous := *target
	*target = value
	t.Cleanup(func() { *target = previous })
}

// installedPHP is one entry of what the host reports. loaded is the field
// phpBinFor insists on, because a version that is present but not loaded runs
// nothing.
func installedPHP(version, bin string, loaded bool) phpversion.Version {
	return phpversion.Version{
		VersionMetadata: phpversion.VersionMetadata{Version: version},
		Loaded:          loaded,
		PHPBin:          bin,
	}
}

// withPHP makes the host report one installed interpreter.
func withPHP(t *testing.T, versions ...phpversion.Version) {
	t.Helper()
	setForTest(t, &installedVersions, func() []phpversion.Version { return versions })
}

// validate is the gate every write goes through, and each refusal below is a
// different way a crontab line could be broken in two.
func TestValidateRefusesWhatCannotBeWrittenAsOneLine(t *testing.T) {
	tooLong := validTask()
	tooLong.Command = strings.Repeat("a", maxCommandLength+1)

	noMinute := validTask()
	noMinute.Minute = ""

	noWeek := validTask()
	noWeek.Week = ""

	noCommand := validTask()
	noCommand.Command = ""

	semicolon := validTask()
	semicolon.Minute = "0;evil"

	brokenCommand := validTask()
	brokenCommand.Command = "backup.sh\n0 3 * * * evil"

	cases := []struct {
		name string
		task Task
		want string
	}{
		{"a schedule field left empty", noMinute, "all schedule fields are required"},
		{"the last schedule field left empty", noWeek, "all schedule fields are required"},
		{"an empty command", noCommand, "command cannot be empty"},
		{"a command past the length limit", tooLong, "command is too long"},
		{"a shell separator in a schedule field", semicolon, "invalid character in schedule fields"},
		{"a line break in the command", brokenCommand, "command cannot contain line breaks"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validate(tc.task)
			if err == nil {
				t.Fatal("the task was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error is %q, want it to hold %q", err, tc.want)
			}
		})
	}
	// A command exactly at the limit passes, so the check is the limit and not
	// the length.
	atLimit := validTask()
	atLimit.Command = strings.Repeat("a", maxCommandLength)
	if err := validate(atLimit); err != nil {
		t.Errorf("a command at the limit was refused: %v", err)
	}
}

// A PHP task runs the interpreter of the version it names, discovered on the
// host. Falling back to /usr/bin/php would run the wrong one silently.
func TestAPHPTaskRunsTheInterpreterOfItsOwnVersion(t *testing.T) {
	withPHP(t,
		installedPHP("8.2", "/opt/remi/php82/root/usr/bin/php", true),
		installedPHP("8.3", "/opt/remi/php83/root/usr/bin/php", true),
	)

	command, err := buildCommand(taskInput{
		Task:   Task{Type: TypePHP, PHPVersion: "8.3"},
		Script: "/home/c_site/run.php",
	})
	if err != nil {
		t.Fatalf("buildCommand: %v", err)
	}
	if want := "/opt/remi/php83/root/usr/bin/php -q '/home/c_site/run.php'"; command != want {
		t.Errorf("command = %q, want %q", command, want)
	}
}

// The arguments are appended after the quoted script path, and they are checked
// against the same metacharacter set for the same reason.
func TestPHPArgumentsAreAppendedAndChecked(t *testing.T) {
	withPHP(t, installedPHP("8.3", "/usr/bin/php83", true))

	command, err := buildCommand(taskInput{
		Task:   Task{Type: TypePHP, PHPVersion: "8.3"},
		Script: "/home/c_site/run.php",
		Args:   "--force --queue=mail",
	})
	if err != nil {
		t.Fatalf("buildCommand: %v", err)
	}
	if want := "/usr/bin/php83 -q '/home/c_site/run.php' --force --queue=mail"; command != want {
		t.Errorf("command = %q, want %q", command, want)
	}
	if _, err := buildCommand(taskInput{
		Task:   Task{Type: TypePHP, PHPVersion: "8.3"},
		Script: "/home/c_site/run.php",
		Args:   "--force `id`",
	}); err == nil {
		t.Error("arguments carrying a shell metacharacter were accepted")
	}
}

func TestAPHPTaskIsRefusedWhenItCannotBeRun(t *testing.T) {
	cases := []struct {
		name    string
		loaded  []phpversion.Version
		input   taskInput
		want    string
		version string
	}{
		{
			name:   "an empty script path",
			loaded: []phpversion.Version{installedPHP("8.3", "/usr/bin/php83", true)},
			input:  taskInput{Task: Task{Type: TypePHP, PHPVersion: "8.3"}, Script: "  "},
			want:   "PHP file path cannot be empty",
		},
		{
			name:   "a script path breaking out of the quoting",
			loaded: []phpversion.Version{installedPHP("8.3", "/usr/bin/php83", true)},
			input: taskInput{
				Task: Task{Type: TypePHP, PHPVersion: "8.3"}, Script: "/home/c_site/x.php'; id #",
			},
			want: "PHP file path contains an invalid character",
		},
		{
			name:   "a version this host does not have",
			loaded: []phpversion.Version{installedPHP("8.2", "/usr/bin/php82", true)},
			input:  taskInput{Task: Task{Type: TypePHP, PHPVersion: "8.3"}, Script: "/home/c_site/x.php"},
			want:   "PHP 8.3 is not installed",
		},
		{
			name:   "a version that is present but not loaded",
			loaded: []phpversion.Version{installedPHP("8.3", "/usr/bin/php83", false)},
			input:  taskInput{Task: Task{Type: TypePHP, PHPVersion: "8.3"}, Script: "/home/c_site/x.php"},
			want:   "PHP 8.3 is not installed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withPHP(t, tc.loaded...)
			_, err := buildCommand(tc.input)
			if err == nil {
				t.Fatal("the input was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error is %q, want it to hold %q", err, tc.want)
			}
		})
	}
}

func TestAnEmptyURLIsRefused(t *testing.T) {
	if _, err := buildCommand(taskInput{Task: Task{Type: TypeURL}, URL: "   "}); err == nil {
		t.Error("an empty URL was accepted")
	}
}

// prepare is what a write actually calls: it fills the default type, generates
// the command and validates the result.
func TestPrepareFillsTheDefaultTypeAndTheGeneratedCommand(t *testing.T) {
	task, err := prepare(taskInput{
		Task: Task{Minute: "0", Hour: "3", Day: "*", Month: "*", Week: "*", Command: "backup.sh"},
	})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if task.Type != TypeCommand {
		t.Errorf("type = %q, want %q", task.Type, TypeCommand)
	}
	if task.Command != "backup.sh" {
		t.Errorf("command = %q, want it unchanged", task.Command)
	}
}

// The RAW url never reaches the crontab; only the generated command does, and
// the validation runs on that generated command.
func TestPrepareValidatesTheGeneratedCommand(t *testing.T) {
	task, err := prepare(taskInput{
		Task: Task{Minute: "0", Hour: "3", Day: "*", Month: "*", Week: "*", Type: TypeURL},
		URL:  "https://example.com/ping",
	})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if !strings.HasPrefix(task.Command, "curl ") {
		t.Errorf("command = %q, want the generated curl line", task.Command)
	}

	if _, err := prepare(taskInput{
		Task: Task{Minute: "", Hour: "3", Day: "*", Month: "*", Week: "*", Type: TypeURL},
		URL:  "https://example.com/ping",
	}); err == nil {
		t.Error("a task with no minute was accepted")
	}
	if _, err := prepare(taskInput{
		Task: Task{Minute: "0", Hour: "3", Day: "*", Month: "*", Week: "*", Type: TypeURL},
		URL:  "ftp://example.com",
	}); err == nil {
		t.Error("a URL that generates no command was accepted")
	}
}
