package domains

import (
	"go/scanner"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The panel used to carry a read-only policy keyed off a domains column: about
// a hundred handlers read the flag and refused the request when it was set.
// Nothing ever set it. There was no create option, no edit field and no API
// that wrote the column, so every INSERT wrote the literal 0 and the column
// held 0 on every row of every installation.
//
// That is the failure this test guards. A control nothing can switch on is not
// a weak control, it is one an operator reads in the code and believes in, and
// the half-built set of guards made it look deliberate. Both halves were
// removed together: the guards and the column behind them.
//
// The check is on the SOURCE rather than on behaviour, because the defect is
// the presence of the code, not what it does. A reintroduced read would compile
// and pass every functional test in this package exactly as the removed one
// did.
//
// The flag's name is assembled at run time. Written out, the literal would
// match this file's own source and the scan would report itself.
var deadPolicyColumn = "is" + "_" + "demo"

// deadPolicyIdentifiers are the Go spellings the removed guards used.
var deadPolicyIdentifiers = []string{"isDemo", "IsDemo"}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for range 8 {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("go.mod is not above this package")
	return ""
}

// goFileMentions reports whether a Go file names the removed policy in code.
// It reads TOKENS, so a comment that explains why the policy is gone does not
// count as a reintroduction.
func goFileMentions(t *testing.T, path string) bool {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- a repository source file.
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fileSet := token.NewFileSet()
	file := fileSet.AddFile(path, fileSet.Base(), len(body))
	var scan scanner.Scanner
	scan.Init(file, body, nil, 0) // 0: comments are skipped.
	for {
		_, tok, literal := scan.Scan()
		switch tok {
		case token.EOF:
			return false
		case token.STRING:
			if strings.Contains(literal, deadPolicyColumn) {
				return true
			}
		case token.IDENT:
			if slices.Contains(deadPolicyIdentifiers, literal) {
				return true
			}
		}
	}
}

func TestTheUnsettableReadOnlyPolicyIsNotBack(t *testing.T) {
	root := repositoryRoot(t)
	var offenders []string

	for _, dir := range []string{"cmd", "internal"} {
		walkErr := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			// This file names the identifiers on purpose.
			if strings.HasSuffix(path, "deadpolicy_test.go") {
				return nil
			}
			if goFileMentions(t, path) {
				rel, _ := filepath.Rel(root, path)
				offenders = append(offenders, rel)
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walk %s: %v", dir, walkErr)
		}
	}

	sort.Strings(offenders)
	for _, name := range offenders {
		t.Errorf("%s reads a column no code path can ever set; the guard refuses nothing "+
			"and reads as a policy the panel does not have", name)
	}
}

// The column goes with the guards. Leaving it in the schema invites the next
// writer to enforce it again, one endpoint at a time, and to ship the same
// incomplete policy. Migration 0002 created it and stays untouched, because an
// applied migration cannot be edited; the drop is its own numbered file.
func TestTheColumnIsDroppedByAMigration(t *testing.T) {
	root := repositoryRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "migrations"))
	if err != nil {
		t.Fatalf("read the migrations directory: %v", err)
	}
	created, dropped := "", ""
	for _, entry := range entries {
		path := filepath.Join(root, "migrations", entry.Name())
		body, readErr := os.ReadFile(path) // #nosec G304 -- a repository migration file.
		if readErr != nil {
			t.Fatalf("read %s: %v", entry.Name(), readErr)
		}
		text := string(body)
		if strings.Contains(text, "DROP COLUMN IF EXISTS "+deadPolicyColumn) {
			dropped = entry.Name()
			continue
		}
		if strings.Contains(text, deadPolicyColumn) && strings.Contains(text, "CREATE TABLE") {
			created = entry.Name()
		}
	}
	if created == "" {
		t.Fatal("no migration creates the column, so this test proves nothing")
	}
	if dropped == "" {
		t.Fatalf("%s creates the column and nothing drops it", created)
	}
	if dropped <= created {
		t.Errorf("%s drops the column but %s creates it afterwards", dropped, created)
	}
}
