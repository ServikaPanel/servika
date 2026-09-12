package logx

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The severity only answers "show me the panel's failures" while EVERY line
// carries one. One log.Printf left behind writes an unmarked line that a
// priority filter silently drops, and nothing about that line says it is
// missing. This walks cmd/ and internal/ and fails on any standard-logger write
// outside this package.
//
// scripts/ is deliberately out of scope: those are terminal tools a person runs
// by hand, and a visible <3> in their output would be noise, not a priority.
func TestNothingWritesToTheStandardLoggerAnyMore(t *testing.T) {
	var sites []string
	for _, tree := range []string{"cmd", "internal"} {
		sites = append(sites, standardLoggerSites(t, tree)...)
	}
	sort.Strings(sites)
	for _, site := range sites {
		t.Errorf("%s writes through the standard logger; use logx (or httpx.LogR on a request path)", site)
	}
}

// standardLoggerSites returns every log.Print/Printf/Println/Fatal call under a
// tree, as file:line.
func standardLoggerSites(t *testing.T, tree string) []string {
	t.Helper()
	fileSet := token.NewFileSet()
	root := repositoryRoot(t)
	var sites []string
	err := filepath.WalkDir(filepath.Join(root, tree), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		parsed, perr := parser.ParseFile(fileSet, path, nil, 0)
		if perr != nil {
			return perr
		}
		rel, _ := filepath.Rel(root, path)
		if filepath.Dir(rel) == filepath.Join("internal", "logx") {
			return nil
		}
		for _, pos := range standardLoggerCalls(parsed) {
			sites = append(sites, fmt.Sprintf("%s:%d", rel, fileSet.Position(pos).Line))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", tree, err)
	}
	return sites
}

// standardLoggerCalls returns the position of every write through the log
// package. SetOutput and SetFlags are not writes and are left alone.
func standardLoggerCalls(file *ast.File) []token.Pos {
	writes := map[string]bool{
		"Print": true, "Printf": true, "Println": true,
		"Fatal": true, "Fatalf": true, "Fatalln": true,
		"Panic": true, "Panicf": true, "Panicln": true,
	}
	var found []token.Pos
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !writes[selector.Sel.Name] {
			return true
		}
		if pkg, ok := selector.X.(*ast.Ident); ok && pkg.Name == "log" {
			found = append(found, call.Lparen)
		}
		return true
	})
	return found
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for range 8 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
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
