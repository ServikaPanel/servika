package optimize

import (
	"strings"
	"testing"
)

// The rule this whole file exists for. The upstream this design came from
// looked a directive up in nginx.conf and, when it was not there, wrote it into
// the events block: of 28 directives handled that way, 16 produced "directive
// is not allowed here" and nginx refused to start. An nginx directive is valid
// only in the contexts its module declares, and nothing in the file's text says
// which those are.
func TestADirectiveThatIsNotDefinedIsRefusedRatherThanPlaced(t *testing.T) {
	text := readTestdata(t, "almalinux10-nginx.conf")

	// worker_connections IS defined in the shipped file, so it is replaced.
	edited, err := SetNginxDirective(text, "worker_connections", "4096")
	if err != nil {
		t.Fatalf("worker_connections is defined in the shipped file: %v", err)
	}
	if got := parseNginxDirective(edited, "worker_connections"); got != "4096" {
		t.Errorf("after the edit the file reads %q", got)
	}

	// These are NOT in the shipped nginx.conf. Each must be refused, not placed.
	for _, directive := range []string{"client_max_body_size", "worker_rlimit_nofile", "multi_accept"} {
		edited, err := SetNginxDirective(text, directive, "1")
		if err == nil {
			t.Errorf("%s is absent from the shipped file but was written anyway:\n%s",
				directive, edited)
		}
	}
}

// The replacement keeps the line where it was, with its indentation, so the
// file stays a file somebody can still read and diff.
func TestTheDirectiveIsReplacedInPlace(t *testing.T) {
	text := readTestdata(t, "almalinux10-nginx.conf")
	edited, err := SetNginxDirective(text, "worker_connections", "4096")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(edited, "    worker_connections 4096;") {
		t.Error("the replacement lost the original indentation")
	}
	if strings.Count(edited, "worker_connections") != strings.Count(text, "worker_connections") {
		t.Error("the edit changed how many times the directive appears")
	}
	// Nothing else moved.
	if len(strings.Split(edited, "\n")) != len(strings.Split(text, "\n")) {
		t.Error("the edit changed the line count")
	}
}

// A php-fpm pool has sections, so a value appended past the end of [www]
// belongs to whatever section follows it.
func TestAPoolSettingThatIsNotDefinedIsRefused(t *testing.T) {
	text := readTestdata(t, "almalinux10-www.conf")

	edited, err := SetPoolValues(text, map[string]string{
		"pm.max_children": "51", "pm.start_servers": "12",
		"pm.min_spare_servers": "6", "pm.max_spare_servers": "25",
	})
	if err != nil {
		t.Fatalf("all four are defined in the shipped pool: %v", err)
	}
	values := parseFPMPool(edited)
	for name, want := range map[string]string{
		"pm.max_children": "51", "pm.start_servers": "12",
		"pm.min_spare_servers": "6", "pm.max_spare_servers": "25",
	} {
		if values[name] != want {
			t.Errorf("%s reads %q after the edit, want %q", name, values[name], want)
		}
	}

	// pm.max_requests is COMMENTED OUT in the shipped pool, so it is not
	// defined and must not be written.
	if _, err := SetPoolValues(text, map[string]string{"pm.max_requests": "500"}); err == nil {
		t.Error("pm.max_requests is commented out in the shipped pool but was written as if defined")
	}
}

// The commented default a few lines above the live setting must stay commented.
// Rewriting it would leave the file reading as if the value were set twice.
func TestTheCommentedDefaultIsLeftAlone(t *testing.T) {
	text := readTestdata(t, "almalinux10-www.conf")
	edited, err := SetPoolValues(text, map[string]string{"pm.max_children": "51"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(edited, "\n") != strings.Count(text, "\n") {
		t.Error("the edit changed the line count")
	}
	for line := range strings.SplitSeq(edited, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ";pm.max_children") && strings.Contains(trimmed, "51") {
			t.Errorf("a commented line was rewritten: %q", trimmed)
		}
	}
}

// The panel's own drop-in keeps what a previous apply wrote. Losing it would
// silently undo a change the operator still sees on the screen as applied.
func TestTheDropInKeepsWhatAnEarlierApplyWrote(t *testing.T) {
	existing := "[mysqld]\ninnodb_buffer_pool_size = 4096M\nmax_connections = 300\n"
	merged := MergeDropIn(existing, "[mysqld]", map[string]string{"table_open_cache": "8000"})

	for _, want := range []string{
		"innodb_buffer_pool_size = 4096M",
		"max_connections = 300",
		"table_open_cache = 8000",
	} {
		if !strings.Contains(merged, want) {
			t.Errorf("%q is missing from:\n%s", want, merged)
		}
	}
	if strings.Count(merged, "[mysqld]") != 1 {
		t.Errorf("the section header was duplicated:\n%s", merged)
	}
}

// Writing the same parameter again replaces it rather than adding a second
// line. MariaDB takes the LAST of a repeated setting, so a duplicate is not
// wrong so much as unreadable, and the file is what an operator diffs.
func TestRewritingAParameterDoesNotDuplicateIt(t *testing.T) {
	existing := "[mysqld]\nmax_connections = 300\n"
	merged := MergeDropIn(existing, "[mysqld]", map[string]string{"max_connections": "500"})
	if strings.Count(merged, "max_connections") != 1 {
		t.Errorf("the parameter appears more than once:\n%s", merged)
	}
	if !strings.Contains(merged, "max_connections = 500") {
		t.Errorf("the new value is missing:\n%s", merged)
	}
}

// A sysctl drop-in has no sections, so it gets no header line. Writing
// "[mysqld]" into /etc/sysctl.d makes sysctl report it as a malformed setting.
func TestASysctlDropInCarriesNoSectionHeader(t *testing.T) {
	merged := MergeDropIn("", "", map[string]string{"fs.file-max": "2097152"})
	if strings.Contains(merged, "[") {
		t.Errorf("a section header reached a sysctl file:\n%s", merged)
	}
	if !strings.Contains(merged, "fs.file-max = 2097152") {
		t.Errorf("the setting is missing:\n%s", merged)
	}
}
