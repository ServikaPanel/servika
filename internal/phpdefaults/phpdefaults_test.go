package phpdefaults

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The five values in this package are the panel's half of a pair. The other
// half is the DEFAULT clause on the php_settings column, which decides what a
// domain with no row of its own actually gets. When the two drift, the panel
// reports one limit while the interpreter enforces another, and nothing in
// either file says which is right. That is the defect this package exists to
// close, so the pairing is asserted rather than described in a comment.
//
// The migrations are replayed IN ORDER and the LAST default wins, exactly as a
// server sees them: 0011 creates the columns and a later ALTER moves them.
var (
	tableStart   = regexp.MustCompile(`(?i)^\s*(?:CREATE|ALTER)\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?` + "`?" + `(\w+)` + "`?")
	columnDefarg = regexp.MustCompile(`(?i)^\s*(?:MODIFY\s+COLUMN\s+|ADD\s+COLUMN\s+)?` + "`?" + `(\w+)` + "`?" + `\s+\S.*\bDEFAULT\s+('[^']*'|\S+?)\s*,?\s*;?\s*$`)
)

// migrationDefaults replays every migration and answers the last DEFAULT seen
// for each named column of the named table.
func migrationDefaults(t *testing.T, table string, columns []string) map[string]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "migrations", "*.sql"))
	if err != nil {
		t.Fatalf("list migrations: %v", err)
	}
	if len(files) == 0 {
		// A glob that matched nothing would make every assertion below vacuous.
		t.Fatal("no migration files were found, so nothing was compared")
	}
	wanted := make(map[string]bool, len(columns))
	for _, name := range columns {
		wanted[name] = true
	}

	found := map[string]string{}
	for _, file := range files {
		body, err := os.ReadFile(file) // #nosec G304 -- test-only read of a repository path built from a fixed glob.
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		current := ""
		for raw := range strings.SplitSeq(string(body), "\n") {
			// Strip the line comment FIRST. 0104's header lists the same column
			// names and the old values beside them, so a parser that reads the
			// raw text records the wrong default and still reports success.
			line := raw
			if at := strings.Index(line, "--"); at >= 0 {
				line = line[:at]
			}
			if match := tableStart.FindStringSubmatch(line); match != nil {
				current = strings.ToLower(match[1])
			}
			if current == table {
				if match := columnDefarg.FindStringSubmatch(line); match != nil {
					if column := strings.ToLower(match[1]); wanted[column] {
						found[column] = strings.Trim(match[2], "'")
					}
				}
			}
			// A statement ends at the semicolon, and the next statement may name
			// a different table.
			if strings.HasSuffix(strings.TrimSpace(line), ";") {
				current = ""
			}
		}
	}
	return found
}

func TestTheMigrationsAgreeWithTheseConstants(t *testing.T) {
	want := map[string]string{
		"memory_limit":        MemoryLimit,
		"max_execution_time":  strconv.Itoa(MaxExecutionTime),
		"max_input_time":      strconv.Itoa(MaxInputTime),
		"post_max_size":       PostMaxSize,
		"upload_max_filesize": UploadMaxFilesize,
	}
	columns := make([]string, 0, len(want))
	for column := range want {
		columns = append(columns, column)
	}

	got := migrationDefaults(t, "php_settings", columns)
	for column, expected := range want {
		actual, ok := got[column]
		if !ok {
			// Not the same finding as a mismatch: one is a value to fix, the
			// other means the parser never saw the column and every other
			// assertion here is worth nothing.
			t.Fatalf("no DEFAULT for php_settings.%s was found in any migration", column)
		}
		if actual != expected {
			t.Errorf("php_settings.%s DEFAULT is %q in the migrations but %q in this package; a domain with no row would get one limit while the panel reports the other",
				column, actual, expected)
		}
	}
}
