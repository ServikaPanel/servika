package credentials

import (
	"strings"
	"testing"
)

// GrantSchema makes `_` and `%` literal, because MariaDB reads the schema
// position of a GRANT as a pattern even inside backticks. A name without either
// character comes back unchanged, so the escape adds nothing where it is not
// needed.
func TestGrantSchemaEscapesTheWildcardCharacters(t *testing.T) {
	cases := map[string]string{
		"c_acme_wp": `c\_acme\_wp`,
		"acme":      "acme",
		"a%b":       `a\%b`,
		"a_b%c":     `a\_b\%c`,
	}
	for in, want := range cases {
		if got := GrantSchema(in); got != want {
			t.Errorf("GrantSchema(%q) = %q, want %q", in, got, want)
		}
	}
}

// needsEscape decides which mysql.db rows the heal rewrites. It must accept an
// unescaped panel grant and refuse everything else, or the heal either misses
// the vulnerable rows or rewrites grants it does not own.
func TestNeedsEscapeSelectsOnlyTheUnrepairedRows(t *testing.T) {
	refused := []grantRow{
		{schema: `c_acme\_wp`, user: "c_acme_wp", host: "localhost"}, // already escaped
		{schema: "acme", user: "acme", host: "localhost"},            // no wildcard
		{schema: "c_acme_wp", user: "c_acme_wp", host: "evil host"},  // host not a pattern this package writes
		{schema: "c'acme_wp", user: "c_acme_wp", host: "localhost"},  // name outside the identifier allowlist
	}
	for _, g := range refused {
		if needsEscape(g) {
			t.Errorf("needsEscape(%+v) = true, want false", g)
		}
	}
	accepted := []grantRow{
		{schema: "c_acme_wp", user: "c_acme_wp", host: "localhost"},
		{schema: "c_acme_wp", user: "c_acme_wp", host: "203.0.113.7"},
	}
	for _, g := range accepted {
		if !needsEscape(g) {
			t.Errorf("needsEscape(%+v) = false, want true", g)
		}
	}
}

// repairGrant revokes the pattern exactly as mysql.db stores it and grants the
// escaped one back, so the vulnerable row is replaced rather than joined by a
// second one.
func TestRepairGrantReplacesTheUnescapedRow(t *testing.T) {
	_, stdinPath := stubRootSQL(t, 0)
	if err := repairGrant(grantRow{schema: "c_acme_wp", user: "c_acme_wp", host: "localhost"}); err != nil {
		t.Fatalf("repairGrant: %v", err)
	}
	text := readStub(t, stdinPath)
	if !strings.Contains(text, "REVOKE ALL PRIVILEGES ON `c_acme_wp`.* FROM 'c_acme_wp'@'localhost';") {
		t.Errorf("the unescaped grant was not revoked; got:\n%s", text)
	}
	if !strings.Contains(text, "GRANT ALL PRIVILEGES ON `c\\_acme\\_wp`.* TO 'c_acme_wp'@'localhost';") {
		t.Errorf("the escaped grant was not issued; got:\n%s", text)
	}
}

// wildcardGrantRows reads the grant table through the privileged client and
// keeps only the rows still carrying an unescaped wildcard.
func TestWildcardGrantRowsKeepsOnlyTheVulnerableRows(t *testing.T) {
	stubRootQuery(t, "c_acme_wp\tc_acme_wp\tlocalhost\n"+
		"c_acme\\_shop\tc_acme_shop\tlocalhost\n"+
		"plain\tplain\tlocalhost\n")
	rows, err := wildcardGrantRows(t.Context())
	if err != nil {
		t.Fatalf("wildcardGrantRows: %v", err)
	}
	if len(rows) != 1 || rows[0].schema != "c_acme_wp" {
		t.Fatalf("got %+v, want only the unescaped c_acme_wp row", rows)
	}
}
