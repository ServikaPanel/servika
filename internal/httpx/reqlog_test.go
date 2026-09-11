package httpx

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	chimw "github.com/go-chi/chi/v5/middleware"
)

func captureReqLog(t *testing.T) *bytes.Buffer {
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

func requestWithID(id string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/domains/7", nil)
	if id == "" {
		return request
	}
	return request.WithContext(context.WithValue(request.Context(), chimw.RequestIDKey, id))
}

// The correlation id used to reach the access-log summary line, the response
// header and nothing else, so an operator handed an id could find that one line
// and then had to match the actual cause by timestamp proximity.
func TestTheRequestIDReachesTheLine(t *testing.T) {
	logged := captureReqLog(t)

	LogR(requestWithID("abc123"), "backup destination %d: %v", 7, fmt.Errorf("connection refused"))

	line := logged.String()
	if !strings.HasPrefix(line, "reqid=abc123 ") {
		t.Errorf("the line does not carry the correlation id: %q", line)
	}
	if !strings.Contains(line, "backup destination 7: connection refused") {
		t.Errorf("the caller's own message was changed: %q", line)
	}
}

// A request with no id logs without a prefix rather than with an empty one: a
// background caller passing a synthetic request, or a handler invoked directly
// in a test, must not produce "reqid= ".
func TestARequestWithoutAnIDLogsWithoutAPrefix(t *testing.T) {
	logged := captureReqLog(t)

	LogR(requestWithID(""), "nothing to correlate")
	LogR(nil, "and a nil request does not panic")

	body := logged.String()
	if strings.Contains(body, "reqid=") {
		t.Errorf("an empty id was printed as a prefix: %q", body)
	}
	if !strings.Contains(body, "nothing to correlate") || !strings.Contains(body, "does not panic") {
		t.Errorf("a line was lost: %q", body)
	}
}

// The rule, enforced rather than documented: anything reachable from an HTTP
// handler logs through LogR, so every line a request produces can be tied to
// the access-log line that summarises it.
//
// The check is scoped to functions and closures that actually HAVE the request:
// a helper with no *http.Request parameter has nothing to correlate with, and
// demanding one there would mean threading a parameter through for the sake of
// a log line.
func TestNoHandlerLogsWithoutTheRequestID(t *testing.T) {
	var bare []string
	fileSet := token.NewFileSet()
	root := repositoryRoot(t)
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		parsed, perr := parser.ParseFile(fileSet, path, nil, 0)
		if perr != nil {
			return perr
		}
		rel, _ := filepath.Rel(root, path)
		for _, call := range bareLogCallsInHandlers(parsed) {
			bare = append(bare, fmt.Sprintf("%s:%d", rel, fileSet.Position(call).Line))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal: %v", err)
	}
	// The access-log summary line is the one exemption: it already carries the
	// id as a named field, and the helper's prefix would print it twice.
	bare = without(bare, "internal/middleware/accesslog.go")
	sort.Strings(bare)
	for _, site := range bare {
		t.Errorf("%s logs from a handler without the request id; use httpx.LogR(r, ...)", site)
	}
}

func without(sites []string, prefix string) []string {
	kept := sites[:0]
	for _, site := range sites {
		if !strings.HasPrefix(site, prefix) {
			kept = append(kept, site)
		}
	}
	return kept
}

// bareLogCallsInHandlers returns the position of every log.Printf call sitting
// inside a function or closure that carries an (http.ResponseWriter,
// *http.Request) pair.
func bareLogCallsInHandlers(file *ast.File) []token.Pos {
	var found []token.Pos
	var walk func(n ast.Node, hasRequest bool)
	walk = func(n ast.Node, hasRequest bool) {
		ast.Inspect(n, func(inner ast.Node) bool {
			if inner == nil || inner == n {
				return true
			}
			switch d := inner.(type) {
			case *ast.FuncDecl:
				if requestParam(d.Type) != "" {
					hasRequest = true
				}
			case *ast.FuncLit:
				if requestParam(d.Type) != "" && d.Body != nil {
					walk(d.Body, true)
					return false
				}
			case *ast.CallExpr:
				if hasRequest && isLogPrintf(d) {
					found = append(found, d.Lparen)
				}
			}
			return true
		})
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		walk(fn.Body, requestParam(fn.Type) != "")
	}
	return found
}

func isLogPrintf(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Printf" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "log"
}

// requestParam returns the name of the *http.Request parameter when the
// signature also takes an http.ResponseWriter, and "" otherwise.
func requestParam(t *ast.FuncType) string {
	if t.Params == nil {
		return ""
	}
	hasWriter, req := false, ""
	for _, field := range t.Params.List {
		switch expr := field.Type.(type) {
		case *ast.SelectorExpr:
			if expr.Sel.Name == "ResponseWriter" {
				hasWriter = true
			}
		case *ast.StarExpr:
			sel, ok := expr.X.(*ast.SelectorExpr)
			if ok && sel.Sel.Name == "Request" && len(field.Names) > 0 {
				req = field.Names[0].Name
			}
		}
	}
	if hasWriter && req != "" && req != "_" {
		return req
	}
	return ""
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
