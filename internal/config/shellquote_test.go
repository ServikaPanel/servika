package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A real shell is the only thing that can settle this. The rule under test is
// what bash does with a single-quoted word, not what the panel believes it
// does, and the hostile cases are exactly the ones a hand-written expectation
// gets wrong.
//
// internal/transfers builds a remote command line from values an
// attacker-controlled server returned, so a value that escapes its quotes here
// is command execution on the host.
func TestBashReadsAQuotedValueBackUnchanged(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("bash is not on the PATH: %v", err)
	}
	for _, value := range []string{
		"",
		"plain",
		"/tmp/it's here",
		"'",
		"''",
		`'; rm -rf / ; echo '`,
		`$(id)`,
		"`id`",
		`${HOME}`,
		"a b\tc",
		"line\nbreak",
		`back\slash`,
		"quote'and$dollar",
		"türkçe ığşç",
	} {
		out, err := exec.Command(bash, "-c", "printf %s "+ShellQuote(value)).Output()
		if err != nil {
			t.Fatalf("bash refused the quoted form of %q: %v", value, err)
		}
		if string(out) != value {
			t.Errorf("bash read %q back as %q", value, string(out))
		}
	}
}

// A quoted value must be ONE word, or a path with a space becomes two arguments
// and the command acts on something nobody asked for.
func TestAQuotedValueStaysOneArgument(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("bash is not on the PATH: %v", err)
	}
	out, err := exec.Command(bash, "-c", `set -- `+ShellQuote("/var/www/my site/it's")+`; echo $#`).Output()
	if err != nil {
		t.Fatalf("bash: %v", err)
	}
	if strings.TrimSpace(string(out)) != "1" {
		t.Errorf("the quoted path became %s arguments, want 1", strings.TrimSpace(string(out)))
	}
}

// localQuoter matches a package-local reimplementation of this function: any
// function whose name ends in a shell-quote word and does not start with Test.
//
// Six packages each carried a byte-identical copy, only one of which had a
// test, and the untested set included the one processing values from an
// attacker-controlled remote server. A hardening change to the rule had to be
// made in six places to take effect. This test is what stops the seventh copy.
var localQuoter = regexp.MustCompile(`func\s+([A-Za-z_]\w*)\s*\(\w+\s+string\)\s+string`)

// skipDir names a tree that is not this module's Go source.
func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "frontend", "release", "helper-projects":
		return true
	}
	return false
}

// quotersIn returns every shell-quoter definition in one file.
func quotersIn(path, body string) []string {
	// This file's own definition is the one every package uses.
	if strings.HasSuffix(path, filepath.Join("internal", "config", "paths.go")) {
		return nil
	}
	var found []string
	for _, match := range localQuoter.FindAllStringSubmatch(body, -1) {
		name := strings.ToLower(match[1])
		if strings.Contains(name, "quote") && strings.Contains(name, "shell") {
			found = append(found, path+": "+match[0])
		}
	}
	return found
}

func TestNoPackageKeepsItsOwnShellQuoter(t *testing.T) {
	var found []string
	err := filepath.WalkDir(filepath.Join("..", ".."), func(path string, entry os.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case entry.IsDir() && skipDir(entry.Name()):
			return filepath.SkipDir
		// A test may name a quoter to talk about it; only a definition counts.
		case entry.IsDir(), !strings.HasSuffix(path, ".go"), strings.HasSuffix(path, "_test.go"):
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		found = append(found, quotersIn(path, string(body))...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk the tree: %v", err)
	}
	if len(found) > 0 {
		t.Errorf("a package defined its own shell quoter instead of using config.ShellQuote:\n%s",
			strings.Join(found, "\n"))
	}
}
