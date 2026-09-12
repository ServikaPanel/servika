package slowquery

import (
	"strings"
	"testing"
)

// codeMask runs the whole text through the state machine and returns one
// character per byte: `.` where the offset is plain SQL and `x` where it is
// inside a literal, a quoted identifier or a comment.
//
// The state is read BEFORE the byte is stepped, which is how both callers use
// it, so an opening quote reads as code and the closing one reads as data.
// The mask is the state machine's whole contract, so pinning it pins the
// behaviour rather than the shape of the struct behind it.
func codeMask(text string) string {
	state := newSQLState()
	var mask strings.Builder
	for i := range len(text) {
		if state.outsideCode() {
			mask.WriteByte('.')
		} else {
			mask.WriteByte('x')
		}
		state.step(text, i)
	}
	return mask.String()
}

func TestTheScannerKnowsWhereCodeStopsAndDataBegins(t *testing.T) {
	cases := []struct {
		name string
		text string
		mask string
	}{
		{"plain SQL is all code", "SELECT 1", "........"},
		{"a single-quoted literal", "a='bc' d", "...xxx.."},
		{"a double-quoted literal", `a="bc" d`, "...xxx.."},
		{"a backtick identifier", "a=`bc` d", "...xxx.."},
		{"a doubled quote does not end the literal", "a='b''c' z", "...xxxxx.."},
		{"a backslash escapes the closing quote", `a='b\'c' z`, "...xxxxx.."},
		{"a hash comment runs to the line end", "a #c\nb", "...xx."},
		{"a double dash needs whitespace after it", "a -- c\nb", "...xxxx."},
		{"a double dash without whitespace is not a comment", "a--c\nb", "......"},
		{"a block comment ends at its terminator", "a/*c*/b", "..xxx.."},
		{"an unterminated block comment runs to the end", "a/*c", "..xx"},
		{"an unterminated literal runs to the end", "a='bc", "...xx"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := codeMask(tc.text); got != tc.mask {
				t.Errorf("mask of %q\n got %s\nwant %s", tc.text, got, tc.mask)
			}
		})
	}
}

// The marker inside a literal, a comment or an unterminated statement is a
// tenant's text, not a record boundary. This is the rule the whole scanner
// exists for.
func TestAPlantedMarkerNeverStartsARecord(t *testing.T) {
	const marker = "# Time: 2026-09-12T10:00:00.000000Z\n"
	hidden := []struct {
		name string
		body string
	}{
		{"inside a string literal", "SELECT '" + marker + "';\n"},
		{"inside a block comment", "SELECT /*" + marker + "*/ 1;\n"},
		{"inside a backtick identifier", "SELECT `" + marker + "` FROM t;\n"},
		{"after an unterminated statement", "SELECT 1\n" + marker},
	}
	for _, tc := range hidden {
		t.Run(tc.name, func(t *testing.T) {
			text := marker + "# User@Host: c_a[c_a] @ localhost []\n" +
				"# Query_time: 1.0  Lock_time: 0.0 Rows_sent: 1  Rows_examined: 1\n" +
				"use panel;\nSET timestamp=1757671200;\n" + tc.body

			if offsets := markerOffsets(text); len(offsets) != 1 {
				t.Fatalf("markerOffsets = %v, want only the real record at the top", offsets)
			}
		})
	}
}

// skipNumber decides where a numeric literal ends, and everything it walks over
// is replaced by one placeholder. A number it ends too early leaves the rest of
// the value in the stored shape.
func TestEveryNumericFormCollapsesToOnePlaceholder(t *testing.T) {
	numbers := []struct {
		name    string
		literal string
	}{
		{"an integer", "42"},
		{"a decimal", "3.14"},
		{"a leading-dot decimal", ".5"},
		{"an exponent", "1e10"},
		{"a signed exponent", "1.5e-9"},
		{"an upper-case exponent", "2E+8"},
		{"a hexadecimal", "0xDEADBEEF"},
		{"an upper-case hexadecimal", "0X1f"},
	}
	for _, tc := range numbers {
		t.Run(tc.name, func(t *testing.T) {
			normalized, _ := Normalize("SELECT * FROM t WHERE c=" + tc.literal + " AND d=1;")

			if want := "SELECT * FROM t WHERE c=? AND d=?;"; normalized != want {
				t.Errorf("normalized = %q, want %q", normalized, want)
			}
		})
	}
}

// An `e` that no exponent follows ends the number where it stands, so what
// comes after it survives as part of the shape.
func TestALetterAfterANumberIsNotAnExponent(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want string
	}{
		{"a bare e ends the number", "SELECT * FROM t WHERE c=1erow;", "SELECT * FROM t WHERE c=?erow;"},
		{"a number at the end of the statement", "SELECT 12", "SELECT ?"},
		{"an e at the end of the statement", "SELECT 1e", "SELECT ?e"},
		{"two bounds of a range", "SELECT * FROM t WHERE c BETWEEN 2 AND 3;",
			"SELECT * FROM t WHERE c BETWEEN ? AND ?;"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if normalized, _ := Normalize(tc.sql); normalized != tc.want {
				t.Errorf("normalized = %q, want %q", normalized, tc.want)
			}
		})
	}
}

// A digit inside an identifier is part of a NAME. Collapsing it would merge
// wp_2_options and wp_3_options into one shape, which is two different tables.
func TestADigitInsideAnIdentifierSurvives(t *testing.T) {
	two, digestTwo := Normalize("SELECT * FROM wp_2_options WHERE id=5;")
	_, digestThree := Normalize("SELECT * FROM wp_3_options WHERE id=5;")

	if !strings.Contains(two, "wp_2_options") {
		t.Errorf("normalized = %q, want the table name intact", two)
	}
	if digestTwo == digestThree {
		t.Error("two different tables produced one digest")
	}
}
