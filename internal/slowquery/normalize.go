package slowquery

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// maxNormalizedLength bounds what reaches the database. A shape is a shape; a
// query long enough to exceed this is already unreadable on a screen, and the
// digest still separates it from every other shape.
const maxNormalizedLength = 4000

// Normalize turns a statement into its SHAPE and a digest of that shape.
//
// The shape is what gets stored, never the statement as it ran. A slow log
// records whatever a WHERE clause compared against, so keeping the literals
// would copy customer e-mail addresses, tokens and password hashes into the
// panel's own database and from there into every panel backup. Replacing them
// is also what makes the feature answer its question: forty thousand executions
// of one shape is one row, not forty thousand.
func Normalize(sql string) (normalized, digest string) {
	var b strings.Builder
	b.Grow(len(sql))

	state := newSQLState()
	i := 0
	for i < len(sql) {
		// A literal, a comment or a number begins here: consume the whole run.
		if state.outsideCode() {
			if next, consumed := writeNormalizedRun(&b, sql, i); consumed {
				i = next
				continue
			}
		}
		b.WriteByte(sql[i])
		state.step(sql, i)
		i++
	}

	normalized = collapsePlaceholderLists(strings.TrimSpace(b.String()))
	if len(normalized) > maxNormalizedLength {
		normalized = normalized[:maxNormalizedLength]
	}
	sum := sha256.Sum256([]byte(normalized))
	return normalized, hex.EncodeToString(sum[:])[:32]
}

// writeNormalizedRun writes the shape of whatever run begins at i and returns
// the offset just past it. It reports false when nothing there is a run, and
// then writes nothing.
func writeNormalizedRun(b *strings.Builder, sql string, i int) (int, bool) {
	switch c := sql[i]; {
	case c == '\'' || c == '"':
		writeToken(b, "?")
		return skipQuoted(sql, i), true
	case c == '`':
		// A quoted identifier is a NAME, not a value, so it survives.
		end := skipQuoted(sql, i)
		b.WriteString(sql[i:end])
		return end, true
	case commentStarts(sql, i):
		writeSpace(b)
		return skipComment(sql, i), true
	case numberStarts(sql, i):
		writeToken(b, "?")
		return skipNumber(sql, i), true
	case isSpaceByte(c):
		writeSpace(b)
		return i + 1, true
	}
	return i, false
}

// commentStarts reports whether a comment opens at i.
func commentStarts(sql string, i int) bool {
	c := sql[i]
	return c == '#' ||
		(c == '-' && i+1 < len(sql) && sql[i+1] == '-') ||
		(c == '/' && i+1 < len(sql) && sql[i+1] == '*')
}

// numberStarts reports whether a numeric literal begins at i. A digit that
// follows an identifier byte does not: wp_2_options is a table name, and
// collapsing the 2 would merge it with wp_3_options.
func numberStarts(sql string, i int) bool {
	if i > 0 && isIdentByte(sql[i-1]) {
		return false
	}
	c := sql[i]
	return isDigit(c) || (c == '.' && i+1 < len(sql) && isDigit(sql[i+1]))
}

// isSpaceByte reports whether a byte is whitespace that collapses to one space.
func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// writeToken appends a token, inserting a separating space only when the
// previous byte would otherwise run into it.
func writeToken(b *strings.Builder, token string) {
	b.WriteString(token)
}

// writeSpace collapses any run of whitespace or comment into a single space.
func writeSpace(b *strings.Builder) {
	current := b.String()
	if current == "" || strings.HasSuffix(current, " ") {
		return
	}
	b.WriteByte(' ')
}

// skipQuoted returns the offset just past the literal or quoted identifier that
// starts at i. It mirrors sqlState's rules so the two cannot disagree about
// where a literal ends.
func skipQuoted(sql string, i int) int {
	quote := sql[i]
	i++
	for i < len(sql) {
		switch {
		case sql[i] == '\\' && quote != '`':
			i += 2
			continue
		case sql[i] == quote:
			if i+1 < len(sql) && sql[i+1] == quote {
				i += 2
				continue
			}
			return i + 1
		}
		i++
	}
	return len(sql)
}

// skipComment returns the offset just past the comment that starts at i.
func skipComment(sql string, i int) int {
	if sql[i] == '/' {
		end := strings.Index(sql[i+2:], "*/")
		if end < 0 {
			return len(sql)
		}
		return i + 2 + end + 2
	}
	end := strings.IndexByte(sql[i:], '\n')
	if end < 0 {
		return len(sql)
	}
	return i + end
}

// skipNumber returns the offset just past the numeric literal at i, including a
// decimal point, an exponent and a hexadecimal form.
func skipNumber(sql string, i int) int {
	if hexPrefix(sql, i) {
		return skipHexDigits(sql, i+2)
	}
	for i < len(sql) {
		c := sql[i]
		switch {
		case isDigit(c), c == '.':
			i++
		case c == 'e' || c == 'E':
			if !exponentFollows(sql, i) {
				return i
			}
			i += 2
		default:
			return i
		}
	}
	return i
}

// hexPrefix reports whether a hexadecimal literal begins at i.
func hexPrefix(sql string, i int) bool {
	return sql[i] == '0' && i+1 < len(sql) && (sql[i+1] == 'x' || sql[i+1] == 'X')
}

// skipHexDigits returns the offset just past the hexadecimal digits at i.
func skipHexDigits(sql string, i int) int {
	for i < len(sql) && isHexByte(sql[i]) {
		i++
	}
	return i
}

// exponentFollows reports whether the `e` at i is an exponent marker rather
// than the first letter of what comes after the number.
func exponentFollows(sql string, i int) bool {
	if i+1 >= len(sql) {
		return false
	}
	c := sql[i+1]
	return isDigit(c) || c == '+' || c == '-'
}

// collapsePlaceholderLists rewrites `IN (?, ?, ?)` as `IN (?)`.
//
// Without this a WordPress query fetching three options and the same query
// fetching four are two different shapes, which splits the very total the screen
// is ranking by.
func collapsePlaceholderLists(sql string) string {
	var b strings.Builder
	b.Grow(len(sql))
	i := 0
	for i < len(sql) {
		if sql[i] == '(' {
			if end, ok := placeholderList(sql, i); ok {
				b.WriteString("(?)")
				i = end
				continue
			}
		}
		b.WriteByte(sql[i])
		i++
	}
	return b.String()
}

// placeholderList reports whether a run of `(?, ?, ...)` with two or more
// placeholders starts at i, and where it ends.
func placeholderList(sql string, i int) (int, bool) {
	j := i + 1
	count := 0
	for j < len(sql) {
		switch sql[j] {
		case ' ':
			j++
		case '?':
			count++
			j++
		case ',':
			j++
		case ')':
			return j + 1, count >= 2
		default:
			return 0, false
		}
	}
	return 0, false
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHexByte(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isIdentByte(c byte) bool {
	return isDigit(c) || c == '_' || c == '$' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}
