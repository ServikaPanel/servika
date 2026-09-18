package credentials

import (
	"strings"
	"testing"
)

// ValidDBIdentifier is the first gate in front of every statement that names a
// schema, a table or an account, and several of those statements reach MariaDB
// over the root socket where the mysql CLI takes no placeholder. This pins the
// allowlist itself: a character that would end the quoted literal, start a new
// statement or a new shell word must never pass.
func TestValidDBIdentifierRefusesInjectionCharacters(t *testing.T) {
	refused := []string{
		"", "a'b", "a\"b", "a\\b", "a;b", "a b", "a`b", "a-b", "a.b", "a*b",
		"a\nb", "a\rb", "a\x00b", "a%b", "a/b", "a--b", strings.Repeat("x", 65),
	}
	for _, name := range refused {
		if ValidDBIdentifier(name) {
			t.Errorf("ValidDBIdentifier(%q) = true, want false", name)
		}
	}

	// The negative half proves nothing on its own: a gate that refuses
	// everything would pass it while breaking every caller.
	accepted := []string{"wp_abc", "c_example_db", "A9", "a_b_c", strings.Repeat("x", 64)}
	for _, name := range accepted {
		if !ValidDBIdentifier(name) {
			t.Errorf("ValidDBIdentifier(%q) = false, want true", name)
		}
	}
}
