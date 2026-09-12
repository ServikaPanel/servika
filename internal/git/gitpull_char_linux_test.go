package git

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// gitPull resolves the target through openat2 before it touches anything, which
// is Linux only, so these tests skip elsewhere and the repository runs the suite
// in a Linux container.

func skipOffLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("safeio is Linux-only; the stub refuses everything")
	}
}

// checkout plants a home with a directory that looks like a clone in it.
func checkout(t *testing.T, targetDir string, withGit bool) string {
	t.Helper()
	root := t.TempDir()
	setForTest(t, &tenantHomeRoot, root)
	full := filepath.Join(root, "c_acme", targetDir)
	if err := os.MkdirAll(full, 0o755); err != nil {
		t.Fatal(err)
	}
	if withGit {
		if err := os.MkdirAll(filepath.Join(full, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// gitRuns records the git commands a pull issues.
type gitRuns struct {
	ran      []string
	failFrom string
}

// install points the command seams at the recorder and stops the pin from
// resolving a real host.
func (g *gitRuns) install(t *testing.T) {
	t.Helper()
	setForTest(t, &resolveArgsFor, func(string) ([]string, error) {
		return []string{"-c", "http.curloptResolve=github.com:443:140.82.121.4"}, nil
	})
	run := func(_ context.Context, _, _ string, _ []string, name string, args ...string) (string, error) {
		line := strings.Join(append([]string{name}, args...), " ")
		g.ran = append(g.ran, line)
		if g.failFrom != "" && strings.Contains(line, g.failFrom) {
			return "fatal: " + g.failFrom + " refused", errors.New("exit status 128")
		}
		return "output of " + name + "\n", nil
	}
	setForTest(t, &runUserCtx, run)
	setForTest(t, &runUser, func(systemUser, cwd string, env []string, name string, args ...string) (string, error) {
		if name == "git" && len(args) > 2 && args[2] == "rev-parse" {
			return "1a2b3c4d5e\n", nil
		}
		return run(context.Background(), systemUser, cwd, env, name, args...)
	})
}

// A pull fetches the branch, resets onto it, and reports the commit it landed
// on. The pin travels with the fetch, because that reaches the same remote the
// clone did.
func TestAPullFetchesResetsAndReportsTheCommit(t *testing.T) {
	skipOffLinux(t)
	checkout(t, "public_html", true)
	recorder := &gitRuns{}
	recorder.install(t)

	sha, log, err := gitPull("c_acme", "https://github.com/acme/site.git", "public_html", "main", "")

	if err != nil {
		t.Fatalf("gitPull: %v", err)
	}
	if sha != "1a2b3c4d5e" {
		t.Errorf("sha = %q", sha)
	}
	if !strings.Contains(log, "output of git") {
		t.Errorf("log = %q", log)
	}
	if len(recorder.ran) != 2 {
		t.Fatalf("commands = %v, want the fetch and the reset", recorder.ran)
	}
	if !strings.Contains(recorder.ran[0], "http.curloptResolve=") ||
		!strings.HasSuffix(recorder.ran[0], "fetch origin main") {
		t.Errorf("the fetch was %q", recorder.ran[0])
	}
	if !strings.HasSuffix(recorder.ran[1], "reset --hard origin/main") {
		t.Errorf("the reset was %q", recorder.ran[1])
	}
}

// A failed fetch is not followed by a reset, so a repository is never moved onto
// a ref that was never fetched.
func TestAFailedFetchDoesNotReset(t *testing.T) {
	skipOffLinux(t)
	checkout(t, "public_html", true)
	recorder := &gitRuns{failFrom: "fetch"}
	recorder.install(t)

	sha, log, err := gitPull("c_acme", "https://github.com/acme/site.git", "public_html", "main", "")

	if err == nil {
		t.Fatal("a failed fetch was accepted")
	}
	if sha != "" || !strings.Contains(log, "refused") {
		t.Errorf("sha = %q, log = %q", sha, log)
	}
	if len(recorder.ran) != 1 {
		t.Errorf("commands = %v, want only the fetch", recorder.ran)
	}
}

func TestAPullRefusesATargetItCannotTrust(t *testing.T) {
	skipOffLinux(t)
	cases := []struct {
		name       string
		prepare    func(t *testing.T) string
		targetDir  string
		branch     string
		repoURL    string
		message    string
		wantNoRuns bool
	}{
		{
			name:      "a directory that is not a repository",
			prepare:   func(t *testing.T) string { return checkout(t, "public_html", false) },
			targetDir: "public_html", branch: "main", repoURL: "https://github.com/acme/site.git",
			message: "not a Git repository", wantNoRuns: true,
		},
		{
			name:      "a directory that is not there",
			prepare:   func(t *testing.T) string { return checkout(t, "public_html", true) },
			targetDir: "elsewhere", branch: "main", repoURL: "https://github.com/acme/site.git",
			message: "not safe", wantNoRuns: true,
		},
		{
			name:      "a target that leaves the home",
			prepare:   func(t *testing.T) string { return checkout(t, "public_html", true) },
			targetDir: "../../etc", branch: "main", repoURL: "https://github.com/acme/site.git",
			message: "invalid target directory", wantNoRuns: true,
		},
		{
			name:      "a branch name that is not one",
			prepare:   func(t *testing.T) string { return checkout(t, "public_html", true) },
			targetDir: "public_html", branch: "main;id", repoURL: "https://github.com/acme/site.git",
			message: "invalid branch", wantNoRuns: true,
		},
		{
			name:      "a remote that is not a repository URL",
			prepare:   func(t *testing.T) string { return checkout(t, "public_html", true) },
			targetDir: "public_html", branch: "main", repoURL: "file:///etc/passwd",
			message: "invalid repository URL", wantNoRuns: true,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.prepare(t)
			recorder := &gitRuns{}
			recorder.install(t)

			_, _, err := gitPull("c_acme", testCase.repoURL, testCase.targetDir, testCase.branch, "")

			if err == nil || !strings.Contains(err.Error(), testCase.message) {
				t.Fatalf("err = %v, want %q", err, testCase.message)
			}
			if testCase.wantNoRuns && len(recorder.ran) != 0 {
				t.Errorf("commands = %v, want none", recorder.ran)
			}
		})
	}
}

// A symlinked target is refused rather than followed: git runs as the tenant, so
// DAC bounds the damage, but a symlinked component would silently point the pull
// at an unrelated directory.
func TestASymlinkedTargetIsRefused(t *testing.T) {
	skipOffLinux(t)
	root := checkout(t, "public_html", true)
	elsewhere := t.TempDir()
	if err := os.MkdirAll(filepath.Join(elsewhere, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(root, "c_acme", "linked")); err != nil {
		t.Fatal(err)
	}
	recorder := &gitRuns{}
	recorder.install(t)

	_, _, err := gitPull("c_acme", "https://github.com/acme/site.git", "linked", "main", "")

	if err == nil || !strings.Contains(err.Error(), "not safe") {
		t.Fatalf("err = %v, want the refusal", err)
	}
	if len(recorder.ran) != 0 {
		t.Errorf("commands = %v, want none", recorder.ran)
	}
}
