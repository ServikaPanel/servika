package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// The panel process carries SERVIKA_JWT_SECRET, SERVIKA_SECRET_KEY and
// SERVIKA_DB_DSN, so a subprocess handed os.Environ() publishes the signing key,
// the at-rest encryption key and the database DSN in its /proc/<pid>/environ.
// Several of those subprocesses are spawned by customer-triggered requests.
//
// Three packages carry a comment stating this rule; this is the check that keeps
// it true. Every exec site in the tree builds its own explicit environment
// instead, the way internal/redis/cli does for valkey-cli.
//
// The check runs on the AST, not on the text, so the comments that state the rule
// do not trip it.
func TestNoSubprocessInheritsThePanelEnvironment(t *testing.T) {
	roots := []string{"..", "../../cmd"}
	var offenders []string

	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				// helper-projects is not this repository's code.
				if name := entry.Name(); name == "helper-projects" || name == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			offenders = append(offenders, environCallsIn(t, path)...)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	if len(offenders) > 0 {
		t.Fatalf("these call os.Environ(), handing a child the panel's secrets:\n%s",
			strings.Join(offenders, "\n"))
	}
}

// environCallsIn returns "file:line" for every os.Environ() call in one file.
func environCallsIn(t *testing.T, path string) []string {
	t.Helper()
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var found []string
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Environ" {
			return true
		}
		pkg, ok := selector.X.(*ast.Ident)
		if !ok || pkg.Name != "os" {
			return true
		}
		found = append(found, fileSet.Position(call.Pos()).String())
		return true
	})
	return found
}
