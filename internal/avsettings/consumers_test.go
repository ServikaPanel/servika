package avsettings

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// plumbing names the declarations that move a settings field WITHOUT deciding
// anything with it. A field that appears only here is stored, served and drawn,
// and changes nothing.
var plumbing = map[string]bool{"Read": true, "writeRow": true, "Settings": true}

// The rule this package states about itself: "Every field here has a consumer."
// wp_integrity broke it for a long time and nothing caught it. It had a column,
// a struct field, a SELECT, an UPDATE, a JSON field and a checkbox; what it did
// not have was a single branch anywhere in the scanner. An administrator who
// unticked it got a saved setting and no change in behaviour, and one who left
// it ticked believed core integrity was part of the nightly sweep.
//
// This test reads the repository rather than the settings, because the defect
// was never visible from inside this package.
func TestEverySettingIsReadOutsideTheStoragePlumbing(t *testing.T) {
	root := repositoryRoot(t)
	seen := map[string]bool{}
	for _, name := range identifiersUnder(t, root) {
		seen[name] = true
	}

	for field := range reflect.TypeFor[Settings]().Fields() {
		if !seen[field.Name] {
			t.Errorf("Settings.%s is stored and served but nothing decides anything with it; "+
				"wire it to a consumer or remove the field, the column and the control that offers it",
				field.Name)
		}
	}
}

// repositoryRoot walks up from this package to the directory holding go.mod.
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

// identifiersUnder collects every identifier named in internal/ and cmd/,
// skipping _test.go files and the storage plumbing above. Counting a field as
// read when its NAME appears anywhere else is deliberately generous: the point
// is to catch a field with no mention at all, not to prove the mention is a
// genuine branch.
func identifiersUnder(t *testing.T, root string) []string {
	t.Helper()
	var names []string
	fileSet := token.NewFileSet()
	for _, tree := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, tree), func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !goSourceFile(path) {
				return err
			}
			found, parseErr := identifiersIn(fileSet, path)
			if parseErr != nil {
				return parseErr
			}
			names = append(names, found...)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", tree, err)
		}
	}
	return names
}

// goSourceFile reports whether the path is Go source the panel ships.
func goSourceFile(path string) bool {
	return strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go")
}

// identifiersIn collects every identifier one file names, outside the storage
// plumbing.
func identifiersIn(fileSet *token.FileSet, path string) ([]string, error) {
	parsed, err := parser.ParseFile(fileSet, path, nil, 0)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, decl := range parsed.Decls {
		if isPlumbing(decl) {
			continue
		}
		ast.Inspect(decl, func(node ast.Node) bool {
			if ident, ok := node.(*ast.Ident); ok {
				names = append(names, ident.Name)
			}
			return true
		})
	}
	return names, nil
}

// isPlumbing reports whether a declaration is one of the storage helpers or the
// struct definition itself.
func isPlumbing(decl ast.Decl) bool {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		return plumbing[d.Name.Name]
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			if typeSpec, ok := spec.(*ast.TypeSpec); ok && plumbing[typeSpec.Name.Name] {
				return true
			}
		}
	}
	return false
}
