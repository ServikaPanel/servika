package httpx

import (
	"go/ast"
	"go/token"
	"mime"
	"net/http/httptest"
	"strings"
	"testing"
)

// WriteJSON marks every JSON answer no-store, and the handlers that stream a
// file write the response themselves, so they used to answer with no freshness
// directive at all. What they stream is a backup archive with its database
// dump, a tenant file, a mailbox export and a DNS zone.
func TestAnAttachmentIsNotCacheable(t *testing.T) {
	recorder := httptest.NewRecorder()

	Attachment(recorder, "application/gzip", "backup.tar.gz")

	header := recorder.Header()
	if got := header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := header.Get("Content-Type"); got != "application/gzip" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := header.Get("Content-Disposition"); !strings.Contains(got, "backup.tar.gz") {
		t.Errorf("Content-Disposition = %q, want the filename in it", got)
	}
}

// The filename reaches this from a tenant in two of the four handlers, so it is
// encoded rather than interpolated: a quote closes the parameter and everything
// after it would be read as another one.
func TestAFilenameCannotAddASecondParameter(t *testing.T) {
	recorder := httptest.NewRecorder()

	Attachment(recorder, "application/octet-stream", `x"; filename*=UTF-8''evil`)

	disposition := recorder.Header().Get("Content-Disposition")
	kind, params, err := mime.ParseMediaType(disposition)
	if err != nil {
		t.Fatalf("Content-Disposition = %q is not parseable: %v", disposition, err)
	}
	if kind != "attachment" || len(params) != 1 {
		t.Errorf("Content-Disposition = %q parsed as %q with %d parameters, want attachment with one",
			disposition, kind, len(params))
	}
}

// The rule, enforced rather than documented: a handler that streams a file goes
// through Attachment. Setting the header by hand is how all four downloads came
// to answer without Cache-Control in the first place.
func TestNoHandlerWritesItsOwnContentDisposition(t *testing.T) {
	reportSites(t, "sets Content-Disposition itself; use httpx.Attachment",
		func(parsed *ast.File, rel string, at func(token.Pos) int) []string {
			if strings.HasPrefix(rel, "internal/httpx/") {
				return nil
			}
			return sitesAt(rel, at, dispositionWrites(parsed))
		})
}

// dispositionWrites returns the position of every Header().Set call naming
// Content-Disposition.
func dispositionWrites(file *ast.File) []token.Pos {
	var found []token.Pos
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 || !isHeaderSet(call) {
			return true
		}
		if literal, ok := call.Args[0].(*ast.BasicLit); ok &&
			strings.EqualFold(literal.Value, `"Content-Disposition"`) {
			found = append(found, call.Lparen)
		}
		return true
	})
	return found
}

// isHeaderSet reports whether a call is x.Header().Set(...).
func isHeaderSet(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Set" {
		return false
	}
	inner, ok := selector.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	header, ok := inner.Fun.(*ast.SelectorExpr)
	return ok && header.Sel.Name == "Header"
}
