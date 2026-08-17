package optimize

import (
	"bufio"
	"fmt"
	"maps"
	"sort"
	"strings"
)

// The editors below are PURE: text in, text out. Every rule about where a value
// may be written is decided here, so it can be tested without a host to break.

// SetNginxDirective replaces a directive's value WHERE IT IS ALREADY DEFINED,
// preserving the surrounding indentation, and REFUSES when it is not defined.
//
// The refusal is the whole point. The upstream this design came from looked the
// directive up in nginx.conf and, when it was not there, wrote it into the
// events block: of 28 directives handled that way, 16 produced
// "directive is not allowed here" and nginx then refused to start. An nginx
// directive is only valid in the contexts its module declares, and nothing in
// the file's text says which those are, so a directive whose definition cannot
// be found is one this package must not place.
func SetNginxDirective(text, directive, value string) (string, error) {
	var out strings.Builder
	replaced := false

	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		rest, found := strings.CutPrefix(trimmed, directive)
		if !found || rest == "" || !isSpace(rest[0]) ||
			trimmed == "" || strings.HasPrefix(trimmed, "#") {
			out.WriteString(line)
			out.WriteString("\n")
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		fmt.Fprintf(&out, "%s%s %s;\n", indent, directive, value)
		replaced = true
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if !replaced {
		return "", fmt.Errorf("%s is not defined in this file, and nginx accepts it only in the contexts its module declares", directive)
	}
	return out.String(), nil
}

// SetPoolValues replaces pm.* settings WHERE THEY ARE ALREADY DEFINED and
// REFUSES for any that are not.
//
// The reason is the same shape as the nginx one and a different mechanism: a
// php-fpm pool file has sections, and a setting appended after the end of
// [www] belongs to whatever section follows. It would also silently miss the
// commented default a few lines above it, so the file would then read as if the
// value were set twice.
func SetPoolValues(text string, values map[string]string) (string, error) {
	remaining := maps.Clone(values)
	if remaining == nil {
		remaining = map[string]string{}
	}

	var out strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "#") {
			out.WriteString(line)
			out.WriteString("\n")
			continue
		}
		name, _, found := strings.Cut(trimmed, "=")
		name = strings.TrimSpace(name)
		value, wanted := remaining[name]
		if !found || !wanted {
			out.WriteString(line)
			out.WriteString("\n")
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		fmt.Fprintf(&out, "%s%s = %s\n", indent, name, value)
		delete(remaining, name)
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if len(remaining) > 0 {
		return "", fmt.Errorf("%s: not defined in this pool", strings.Join(sortedKeys(remaining), ", "))
	}
	return out.String(), nil
}

// MergeDropIn rewrites one of the panel's OWN drop-ins, keeping any setting it
// already carries that this change does not name.
//
// Appending is correct here and refused everywhere else, because this file has
// exactly one section, the panel writes every line in it, and the file is
// created when it is absent. Losing a setting a previous apply wrote would
// silently undo a change the operator still sees on the screen as applied.
//
// header is the section line the file opens with ("[mysqld]"), or empty for a
// sysctl drop-in, which has no sections.
func MergeDropIn(existing, header string, values map[string]string) string {
	merged := map[string]string{}
	var order []string

	scanner := bufio.NewScanner(strings.NewReader(existing))
	for scanner.Scan() {
		trimmed := strings.TrimSpace(scanner.Text())
		if trimmed == "" || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "[") {
			continue
		}
		name, value, found := strings.Cut(trimmed, "=")
		if !found {
			continue
		}
		name = strings.TrimSpace(name)
		if _, seen := merged[name]; !seen {
			order = append(order, name)
		}
		merged[name] = strings.TrimSpace(value)
	}
	for _, name := range sortedKeys(values) {
		if _, seen := merged[name]; !seen {
			order = append(order, name)
		}
		merged[name] = values[name]
	}

	var out strings.Builder
	out.WriteString("# Written by Servika. Every line here was approved one at a time\n")
	out.WriteString("# on the server tuning screen, which can also put each one back.\n")
	if header != "" {
		out.WriteString(header)
		out.WriteString("\n")
	}
	for _, name := range order {
		fmt.Fprintf(&out, "%s = %s\n", name, merged[name])
	}
	return out.String()
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
