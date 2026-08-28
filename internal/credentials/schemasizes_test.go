package credentials

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// stubRootQuery replaces the privileged read-only client with a script that
// records the query it received on stdin and prints a fixed tab-separated
// result, so a test can inspect what was sent and what parsing does with the
// reply.
func stubRootQuery(t *testing.T, output string) (queryPath string) {
	t.Helper()
	dir := t.TempDir()
	queryPath = filepath.Join(dir, "query")
	script := filepath.Join(dir, "mysql-stub")
	body := "#!/bin/sh\n" +
		"cat > \"" + queryPath + "\"\n" +
		"printf '%s' " + shSingleQuote(output) + "\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatalf("write stub client: %v", err)
	}
	original := rootQueryCommand
	rootQueryCommand = func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, script)
	}
	t.Cleanup(func() { rootQueryCommand = original })
	return queryPath
}

func shSingleQuote(s string) string {
	out := "'"
	for _, r := range s {
		if r == '\'' {
			out += `'\''`
			continue
		}
		out += string(r)
	}
	return out + "'"
}

// SchemaSizes parses the client's tab-separated reply into a size map and sends
// the query on STDIN. A schema absent from the reply is 0.
func TestSchemaSizesParsesTheReply(t *testing.T) {
	queryPath := stubRootQuery(t, "c_site_wp\t11894784\nc_site_shop\t2048\n")

	sizes, err := SchemaSizes(context.Background(), []string{"c_site_wp", "c_site_shop", "c_site_empty"})
	if err != nil {
		t.Fatalf("SchemaSizes: %v", err)
	}
	if sizes["c_site_wp"] != 11894784 {
		t.Errorf("c_site_wp size = %d, want 11894784", sizes["c_site_wp"])
	}
	if sizes["c_site_shop"] != 2048 {
		t.Errorf("c_site_shop size = %d, want 2048", sizes["c_site_shop"])
	}
	if _, ok := sizes["c_site_empty"]; ok {
		t.Errorf("a schema absent from the reply must not appear: %v", sizes)
	}

	query, err := os.ReadFile(queryPath)
	if err != nil {
		t.Fatalf("read query: %v", err)
	}
	if got := string(query); got == "" {
		t.Fatal("the query did not travel on stdin")
	}
}

// An invalid schema name (one that could carry SQL) is never interpolated,
// because information_schema takes no placeholder where a schema name goes.
func TestSchemaSizesRefusesAnInvalidName(t *testing.T) {
	queryPath := stubRootQuery(t, "c_site_wp\t10\n")

	_, err := SchemaSizes(context.Background(), []string{"c_site_wp", "bad'; DROP SCHEMA x; --"})
	if err != nil {
		t.Fatalf("SchemaSizes: %v", err)
	}
	query, err := os.ReadFile(queryPath)
	if err != nil {
		t.Fatalf("read query: %v", err)
	}
	q := string(query)
	if !strings.Contains(q, "'c_site_wp'") {
		t.Errorf("the valid name was not in the query: %q", q)
	}
	if strings.Contains(q, "DROP SCHEMA") {
		t.Errorf("an invalid name reached the query: %q", q)
	}
}

// With no valid name the client is never run, so an all-invalid input returns
// an empty map rather than an error.
func TestSchemaSizesWithNoValidNameRunsNothing(t *testing.T) {
	sizes, err := SchemaSizes(context.Background(), []string{"bad name", "'; DROP"})
	if err != nil {
		t.Fatalf("SchemaSizes: %v", err)
	}
	if len(sizes) != 0 {
		t.Errorf("want an empty map, got %v", sizes)
	}
}
