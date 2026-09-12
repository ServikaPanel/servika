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

	// The severity token comes first, because journald reads the priority off
	// the start of the line; the correlation id follows it.
	line := logged.String()
	if !strings.HasPrefix(line, "<3>reqid=abc123 ") {
		t.Errorf("the line does not carry the severity and the correlation id: %q", line)
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
	reportSites(t, "logs from a handler without the request id; use httpx.LogR(r, ...)",
		func(parsed *ast.File, rel string, at func(token.Pos) int) []string {
			// The access-log summary line is the one exemption: it already carries
			// the id as a named field, and the helper's prefix would print it twice.
			if rel == "internal/middleware/accesslog.go" {
				return nil
			}
			return sitesAt(rel, at, bareLogCallsInHandlers(parsed))
		})
}

// reportSites walks internal/, gathers the sites a check objects to, and
// reports each one against the same message.
func reportSites(t *testing.T, message string, collect func(parsed *ast.File, rel string, at func(token.Pos) int) []string) {
	t.Helper()
	var sites []string
	forEachInternalFile(t, func(parsed *ast.File, rel string, at func(token.Pos) int) {
		sites = append(sites, collect(parsed, rel, at)...)
	})
	sort.Strings(sites)
	for _, site := range sites {
		t.Errorf("%s %s", site, message)
	}
}

// sitesAt renders each position as a file:line the terminal can open.
func sitesAt(rel string, at func(token.Pos) int, positions []token.Pos) []string {
	sites := make([]string, 0, len(positions))
	for _, pos := range positions {
		sites = append(sites, fmt.Sprintf("%s:%d", rel, at(pos)))
	}
	return sites
}

// bareLogCallsInHandlers returns the position of every log.Printf call sitting
// inside a function or closure that carries an (http.ResponseWriter,
// *http.Request) pair.
func bareLogCallsInHandlers(file *ast.File) []token.Pos {
	var finder logSiteFinder
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		finder.walk(fn.Body, requestParam(fn.Type) != "")
	}
	return finder.found
}

// logSiteFinder collects the positions as it walks. A closure carrying its own
// request parameter is walked separately, so a handler nested inside a function
// that has none is still found.
type logSiteFinder struct{ found []token.Pos }

func (f *logSiteFinder) walk(n ast.Node, hasRequest bool) {
	ast.Inspect(n, func(inner ast.Node) bool {
		if inner == nil || inner == n {
			return true
		}
		return f.visit(inner, &hasRequest)
	})
}

// visit reports whether the walk continues into this node.
func (f *logSiteFinder) visit(inner ast.Node, hasRequest *bool) bool {
	switch d := inner.(type) {
	case *ast.FuncDecl:
		if requestParam(d.Type) != "" {
			*hasRequest = true
		}
	case *ast.FuncLit:
		if requestParam(d.Type) != "" && d.Body != nil {
			f.walk(d.Body, true)
			return false
		}
	case *ast.CallExpr:
		if *hasRequest && logsWithoutTheRequest(d) {
			f.found = append(f.found, d.Lparen)
		}
	}
	return true
}

// logsWithoutTheRequest reports whether a call writes a log line that carries no
// correlation id: the standard logger, or logx, which adds the severity but
// knows nothing about the request.
func logsWithoutTheRequest(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	switch pkg.Name {
	case "log":
		return sel.Sel.Name == "Printf" || sel.Sel.Name == "Print" || sel.Sel.Name == "Println"
	case "logx":
		return true
	}
	return false
}

// requestParam returns the name of the *http.Request parameter when the
// signature also takes an http.ResponseWriter, and "" otherwise.
func requestParam(t *ast.FuncType) string {
	if t.Params == nil {
		return ""
	}
	hasWriter, req := false, ""
	for _, field := range t.Params.List {
		if isResponseWriter(field.Type) {
			hasWriter = true
		}
		if name := requestName(field); name != "" {
			req = name
		}
	}
	if hasWriter && req != "" && req != "_" {
		return req
	}
	return ""
}

// isResponseWriter reports whether a parameter type is an http.ResponseWriter.
func isResponseWriter(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "ResponseWriter"
}

// requestName returns the name a *http.Request parameter carries, or "".
func requestName(field *ast.Field) string {
	star, ok := field.Type.(*ast.StarExpr)
	if !ok {
		return ""
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Request" || len(field.Names) == 0 {
		return ""
	}
	return field.Names[0].Name
}

// forEachInternalFile parses every non-test Go file under internal/ and hands it
// to visit with its repository-relative path and a line resolver.
func forEachInternalFile(t *testing.T, visit func(parsed *ast.File, rel string, at func(token.Pos) int)) {
	t.Helper()
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
		visit(parsed, rel, func(pos token.Pos) int { return fileSet.Position(pos).Line })
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal: %v", err)
	}
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
