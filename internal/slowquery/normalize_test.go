package slowquery

import (
	"strings"
	"testing"
)

// THE privacy rule. A slow log records whatever a WHERE clause compared against,
// so a literal that survives normalisation is customer data copied into the
// panel's own database and from there into every panel backup.
func TestNoLiteralSurvivesNormalisation(t *testing.T) {
	secrets := []string{"gizli@ornek.com", "$2y$10$abcdefghijklmnop", "4111111111111111"}
	sql := "SELECT * FROM wp_users WHERE user_email='" + secrets[0] +
		"' AND user_pass=\"" + secrets[1] + "\" AND card=" + secrets[2] + " LIMIT 10;"

	normalized, _ := Normalize(sql)

	for _, secret := range secrets {
		if strings.Contains(normalized, secret) {
			t.Errorf("%q survived normalisation: %s", secret, normalized)
		}
	}
	// The shape itself has to remain readable, or the screen shows nothing
	// actionable.
	for _, want := range []string{"wp_users", "user_email", "user_pass"} {
		if !strings.Contains(normalized, want) {
			t.Errorf("the shape lost %q: %s", want, normalized)
		}
	}
}

// Escaped and doubled quotes must not end a literal early, or the tail of the
// customer's own value is stored as if it were SQL.
func TestEscapedQuotesDoNotEndALiteralEarly(t *testing.T) {
	cases := map[string]string{
		"backslash": `SELECT * FROM t WHERE name='O\'Brien secret@x.com';`,
		"doubled":   `SELECT * FROM t WHERE name='O''Brien secret@x.com';`,
	}
	for name, sql := range cases {
		normalized, _ := Normalize(sql)
		if strings.Contains(normalized, "secret@x.com") || strings.Contains(normalized, "Brien") {
			t.Errorf("%s: the literal ended early: %s", name, normalized)
		}
	}
}

// A quoted IDENTIFIER is a name, not a value, so it survives; collapsing it
// would merge two different tables into one shape.
func TestAQuotedIdentifierIsNotAValue(t *testing.T) {
	one, digestOne := Normalize("SELECT * FROM `wp_posts` WHERE id=1;")
	_, digestTwo := Normalize("SELECT * FROM `wp_options` WHERE id=1;")

	if !strings.Contains(one, "wp_posts") {
		t.Errorf("the table name was collapsed: %s", one)
	}
	if digestOne == digestTwo {
		t.Error("two different tables produced one digest")
	}
}

// A number inside an identifier is part of the NAME. WordPress multisite names
// tables wp_2_options, and collapsing the 2 would merge every site's table.
func TestANumberInsideAnIdentifierIsKept(t *testing.T) {
	normalized, _ := Normalize("SELECT * FROM wp_2_options WHERE option_id=7;")
	if !strings.Contains(normalized, "wp_2_options") {
		t.Errorf("the table name lost its number: %s", normalized)
	}
	if strings.Contains(normalized, "=7") {
		t.Errorf("the value survived: %s", normalized)
	}
}

// Two executions that differ only in their values are ONE shape. This is what
// makes the feature answer its question at all: forty thousand executions become
// one row with a total, not forty thousand rows.
func TestOnlyTheValuesDifferingGivesOneDigest(t *testing.T) {
	_, first := Normalize("SELECT * FROM t WHERE id=1 AND name='alice';")
	_, second := Normalize("SELECT * FROM t WHERE id=99999 AND name='bob';")
	if first != second {
		t.Errorf("the same shape produced two digests: %s vs %s", first, second)
	}

	_, other := Normalize("SELECT * FROM t WHERE id=1 AND email='alice';")
	if first == other {
		t.Error("two different shapes produced one digest")
	}
}

// An IN list of different lengths is the same shape. Without this, WordPress
// fetching three options and the same query fetching four split the very total
// the screen ranks by.
func TestAnInListCollapsesWhateverItsLength(t *testing.T) {
	_, three := Normalize("SELECT * FROM t WHERE id IN (1, 2, 3);")
	_, four := Normalize("SELECT * FROM t WHERE id IN (1, 2, 3, 4);")
	if three != four {
		t.Errorf("IN lists of different lengths gave different digests")
	}

	normalized, _ := Normalize("SELECT * FROM t WHERE id IN (1, 2, 3);")
	if !strings.Contains(normalized, "IN (?)") {
		t.Errorf("the list did not collapse: %s", normalized)
	}
	// A single placeholder is not a list and must stay as it is, or `= (?)`
	// and `IN (?)` would be indistinguishable.
	single, _ := Normalize("SELECT * FROM t WHERE id IN (1);")
	if !strings.Contains(single, "IN (?)") {
		t.Errorf("a one-element list came out wrong: %s", single)
	}
}

// Comments are dropped and runs of whitespace collapse, so line breaks and an
// inline hint do not split one shape into several.
//
// Spacing AROUND an operator is deliberately NOT normalised: `id=?` and `id = ?`
// are two spellings an application does not mix, so they are genuinely different
// shapes, and pt-query-digest keeps them apart for the same reason.
func TestCommentsAndLineBreaksDoNotChangeTheShape(t *testing.T) {
	_, first := Normalize("SELECT a,b FROM t WHERE id = 1;")
	_, second := Normalize("SELECT   a,b\n  FROM t /* hint */ WHERE id = 2; -- note\n")
	if first != second {
		t.Errorf("a comment or a line break changed the digest: %s vs %s", first, second)
	}

	normalized, _ := Normalize("SELECT a /* hint */ FROM t; # trailing\n")
	if strings.Contains(normalized, "hint") || strings.Contains(normalized, "trailing") {
		t.Errorf("a comment survived: %q", normalized)
	}
}

// The stored shape is bounded. A query long enough to exceed the ceiling is
// already unreadable on a screen, and the digest still separates it.
func TestTheStoredShapeIsBounded(t *testing.T) {
	sql := "SELECT " + strings.Repeat("column_name, ", 2000) + "x FROM t;"
	normalized, digest := Normalize(sql)

	if len(normalized) > maxNormalizedLength {
		t.Errorf("normalized is %d bytes, over the %d ceiling", len(normalized), maxNormalizedLength)
	}
	if len(digest) != 32 {
		t.Errorf("digest is %d characters, want 32", len(digest))
	}
}

// The digest is a function of the shape alone, so it is stable across runs and
// across servers. Anything else would make yesterday's rows unmergeable with
// today's.
func TestTheDigestIsStable(t *testing.T) {
	shape, digest := Normalize("SELECT * FROM t WHERE id=1;")
	for i := range 5 {
		if _, again := Normalize("SELECT * FROM t WHERE id=" + strings.Repeat("9", i+1) + ";"); again != digest {
			t.Fatalf("digest changed on run %d", i)
		}
	}
	if shape != "SELECT * FROM t WHERE id=?;" {
		t.Errorf("shape = %q", shape)
	}
}
