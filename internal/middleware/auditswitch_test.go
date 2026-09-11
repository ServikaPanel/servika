package middleware

import (
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// serverSwitches names the handler that flips each server-wide switch, beside
// the file it lives in. Each one writes a setting that decides whether a
// protection runs or whether a port is open, and none of them recorded who did
// it: the row carries an updated_at and no actor column at all, so the panel
// retained nothing beyond a timestamp.
//
// internal/chains reconstructs an initial-access kill chain from audit_log
// logins. The follow-on actions that matter most left it nothing to correlate:
// adding /home to the scanner's exclusion list, turning auto-quarantine and
// real-time off, opening port 3306 to the internet.
var serverSwitches = []struct{ file, handler string }{
	{"internal/dbremote/handlers.go", "ServerSet"},
	{"internal/hostapps/handlers.go", "SetEnabled"},
	{"internal/avsettings/handlers.go", "Put"},
	{"internal/panelsettings/sessionidle.go", "SessionIdleSave"},
	{"internal/domainblock/handlers.go", "Add"},
	{"internal/domainblock/handlers.go", "Remove"},
	{"internal/firewall/geo.go", "AddGeo"},
	{"internal/firewall/geo.go", "DeleteGeo"},
}

func TestEveryServerWideSwitchRecordsWhoFlippedIt(t *testing.T) {
	root := repositoryRootFrom(t)
	var silent []string
	for _, sw := range serverSwitches {
		body, err := os.ReadFile(filepath.Join(root, sw.file)) // #nosec G304 -- a repository source file.
		if err != nil {
			t.Fatalf("read %s: %v", sw.file, err)
		}
		handler, ok := functionBody(string(body), sw.handler)
		if !ok {
			t.Errorf("%s no longer defines %s; this list is out of date", sw.file, sw.handler)
			continue
		}
		if !callsRecordAudit(sw.file, handler) {
			silent = append(silent, sw.file+":"+sw.handler)
		}
	}
	sort.Strings(silent)
	for _, name := range silent {
		t.Errorf("%s changes a server-wide setting without an audit entry; "+
			"the panel keeps no record of who did it", name)
	}
}

// A failed flip is recorded too. An attempt that was refused is exactly what a
// reader of the log wants to see, and recording only the successes hides the
// ones that were tried.
func TestAFailedFlipIsRecordedAsWell(t *testing.T) {
	root := repositoryRootFrom(t)
	for _, sw := range []struct{ file, handler string }{
		{"internal/dbremote/handlers.go", "ServerSet"},
		{"internal/hostapps/handlers.go", "SetEnabled"},
		{"internal/avsettings/handlers.go", "Put"},
		{"internal/panelsettings/sessionidle.go", "SessionIdleSave"},
	} {
		body, err := os.ReadFile(filepath.Join(root, sw.file)) // #nosec G304 -- a repository source file.
		if err != nil {
			t.Fatalf("read %s: %v", sw.file, err)
		}
		handler, ok := functionBody(string(body), sw.handler)
		if !ok {
			t.Fatalf("%s no longer defines %s", sw.file, sw.handler)
		}
		if !strings.Contains(handler, ", false)") {
			t.Errorf("%s:%s records only the flips that worked", sw.file, sw.handler)
		}
	}
}

// functionBody returns one handler's source, from its signature to the closing
// brace in the first column.
func functionBody(source, name string) (string, bool) {
	at := strings.Index(source, ") "+name+"(w http.ResponseWriter")
	if at < 0 {
		return "", false
	}
	body, _, found := strings.Cut(source[at:], "\n}\n")
	return body, found
}

// callsRecordAudit reports whether the handler calls the shared recorder. It
// reads TOKENS, so a comment naming the function does not satisfy the check.
func callsRecordAudit(path, handler string) bool {
	fileSet := token.NewFileSet()
	file := fileSet.AddFile(path, fileSet.Base(), len(handler))
	var scan scanner.Scanner
	scan.Init(file, []byte(handler), nil, 0) // 0: comments are skipped.
	for {
		_, tok, literal := scan.Scan()
		switch tok {
		case token.EOF:
			return false
		case token.IDENT:
			if literal == "RecordAudit" || literal == "WriteAudit" {
				return true
			}
		}
	}
}
