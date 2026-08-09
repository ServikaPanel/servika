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
		c := sql[i]

		// A literal or a comment begins here: consume the whole run.
		if state.outsideCode() {
			switch {
			case c == '\'' || c == '"':
				i = skipQuoted(sql, i)
				writeToken(&b, "?")
				continue
			case c == '`':
				end := skipQuoted(sql, i)
				// A quoted identifier is a NAME, not a value, so it survives.
				b.WriteString(sql[i:end])
				i = end
				continue
			case c == '#', c == '-' && i+1 < len(sql) && sql[i+1] == '-',
				c == '/' && i+1 < len(sql) && sql[i+1] == '*':
				i = skipComment(sql, i)
				writeSpace(&b)
				continue
			case isDigit(c), c == '.' && i+1 < len(sql) && isDigit(sql[i+1]):
				// Only when the number is not part of an identifier such as
				// wp_2_options, which is a table name and must not collapse.
				if i == 0 || !isIdentByte(sql[i-1]) {
					i = skipNumber(sql, i)
					writeToken(&b, "?")
					continue
				}
			case c == ' ', c == '\t', c == '\n', c == '\r':
				writeSpace(&b)
				i++
				continue
			}
		}

		b.WriteByte(c)
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
	if sql[i] == '0' && i+1 < len(sql) && (sql[i+1] == 'x' || sql[i+1] == 'X') {
		i += 2
		for i < len(sql) && isHexByte(sql[i]) {
			i++
		}
		return i
	}
	for i < len(sql) {
		c := sql[i]
		switch {
		case isDigit(c), c == '.':
			i++
		case c == 'e' || c == 'E':
			if i+1 < len(sql) && (isDigit(sql[i+1]) || sql[i+1] == '+' || sql[i+1] == '-') {
				i += 2
				continue
			}
			return i
		default:
			return i
		}
	}
	return i
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
