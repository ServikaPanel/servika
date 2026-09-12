package siteimport

import (
	"encoding/json"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"

	"servika/internal/files"
	"servika/internal/httpx"
)

// configSearchDepth is how far below the destination the rewriter looks. One
// level catches "I extracted into public_html but the site lives in
// public_html/wp"; deeper starts matching files that belong to something else.
const configSearchDepth = 1

type configRequest struct {
	DBName    string `json:"db_name"`
	Directory string `json:"directory"` // home-relative; empty means public_html
}

// ConfigChange records one file the rewriter touched, or looked at and left
// alone with a reason.
type ConfigChange struct {
	Path    string   `json:"path"` // home-relative
	Kind    string   `json:"kind"` // wordpress | laravel
	Fields  []string `json:"fields"`
	Applied bool     `json:"applied"`
	Note    string   `json:"note,omitempty"`
}

type configResponse struct {
	OK      bool           `json:"ok"`
	DBName  string         `json:"db_name"`
	Changes []ConfigChange `json:"changes"`
}

// RewriteConfig points an imported application at its new database.
//
// This is where a transfer usually stops working. The files arrive and the data
// arrives, and the site still answers "Error establishing a database connection"
// because wp-config.php or .env still names the previous host's database, user
// and password. Nothing else in the panel rewrites those.
//
// Every read and write goes through the openat2 helpers, so a tenant symlink at
// any component of the path cannot turn a root-privileged rewrite into a write
// somewhere else.
func (h *Handlers) RewriteConfig(w http.ResponseWriter, r *http.Request) {
	domainID, home, systemUser, err := h.domain(r)
	if err != nil {
		httpx.WriteError(w, statusFor(err), importMessage(err))
		return
	}
	var request configRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	directory, err := targetDirectory(request.Directory)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	chosen, err := h.databaseTarget(r, domainID, strings.TrimSpace(request.DBName))
	if err != nil {
		httpx.WriteError(w, http.StatusForbidden, err.Error())
		return
	}

	answer := configResponse{OK: true, DBName: chosen.DBName, Changes: []ConfigChange{}}
	for _, candidate := range searchDirectories(home, directory) {
		if change, found := rewriteWordPress(home, systemUser, candidate, chosen); found {
			answer.Changes = append(answer.Changes, change)
		}
		if change, found := rewriteDotEnv(home, systemUser, candidate, chosen); found {
			answer.Changes = append(answer.Changes, change)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, answer)
}

// searchDirectories returns the destination plus its immediate subdirectories.
func searchDirectories(home, root string) []string {
	found := []string{root}
	if configSearchDepth < 1 {
		return found
	}
	names, err := files.ListNamesBeneath(home, root)
	if err != nil {
		return found
	}
	for _, name := range names {
		if strings.HasPrefix(name, ".") {
			continue
		}
		child := path.Join(root, name)
		// IsDirBeneath resolves through openat2, so a symlinked entry is not a
		// directory as far as this walk is concerned and is skipped.
		if isDir, dirErr := files.IsDirBeneath(home, child); dirErr == nil && isDir {
			found = append(found, child)
		}
	}
	return found
}

// ---- WordPress ----

// wpDefinePattern matches define('CONSTANT', '<value>'). RE2 has no
// backreferences, so the two quote styles are separate alternatives rather than
// one captured-and-repeated quote.
func wpDefinePattern(constant string) *regexp.Regexp {
	quoted := regexp.QuoteMeta(constant)
	return regexp.MustCompile(
		`(?i)(define\s*\(\s*['"]` + quoted + `['"]\s*,\s*)` +
			`(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")`)
}

var wordPressConstants = []struct {
	Name  string
	Value func(target) string
}{
	{"DB_NAME", func(t target) string { return t.DBName }},
	{"DB_USER", func(t target) string { return t.User }},
	{"DB_PASSWORD", func(t target) string { return t.Password }},
	{"DB_HOST", func(t target) string { return "localhost" }},
}

func rewriteWordPress(home, systemUser, directory string, chosen target) (ConfigChange, bool) {
	relative := path.Join(directory, "wp-config.php")
	content, err := files.ReadFileBeneath(home, relative, maxConfigBytes)
	if err != nil {
		return ConfigChange{}, false
	}
	change := ConfigChange{Path: relative, Kind: "wordpress", Fields: []string{}}
	text := string(content)
	for _, constant := range wordPressConstants {
		pattern := wpDefinePattern(constant.Name)
		if !pattern.MatchString(text) {
			continue
		}
		text = pattern.ReplaceAllString(text, "${1}'"+phpLiteralForTemplate(constant.Value(chosen))+"'")
		change.Fields = append(change.Fields, constant.Name)
	}
	if len(change.Fields) == 0 {
		change.Note = "no_plain_constants"
		return change, true
	}
	if err := files.WriteFileBeneath(home, relative, []byte(text), 0640, systemUser); err != nil {
		change.Note = "write_failed"
		return change, true
	}
	change.Applied = true
	return change, true
}

// phpLiteral escapes a value for a PHP single-quoted string, where only the
// backslash and the quote itself are special.
func phpLiteral(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `'`, `\'`)
}

// phpLiteralForTemplate adds Go's own replacement escaping on top. Without it a
// password containing "$1" would be read as a capture-group reference and the
// written value would not be the password.
func phpLiteralForTemplate(value string) string {
	return strings.ReplaceAll(phpLiteral(value), "$", "$$")
}

// ---- Laravel / dotenv ----

var dotEnvKeys = []struct {
	Name  string
	Value func(target) string
}{
	{"DB_CONNECTION", func(target) string { return "mysql" }},
	{"DB_HOST", func(target) string { return "localhost" }},
	{"DB_DATABASE", func(t target) string { return t.DBName }},
	{"DB_USERNAME", func(t target) string { return t.User }},
	{"DB_PASSWORD", func(t target) string { return t.Password }},
}

// dotEnvValue quotes a value when it carries anything a dotenv parser would
// treat as syntax. A bare value is left bare, so an untouched-looking file stays
// untouched-looking.
func dotEnvValue(value string) string {
	if value == "" {
		return `""`
	}
	needsQuotes := strings.IndexFunc(value, func(r rune) bool {
		return r <= ' ' || strings.ContainsRune("\"'$\\#", r)
	}) >= 0
	if !needsQuotes {
		return value
	}
	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	escaped = strings.ReplaceAll(escaped, `$`, `\$`)
	return `"` + escaped + `"`
}

// replaceOrAppend sets one dotenv assignment. The first uncommented line that
// assigns the name is replaced in place, so the file keeps its own order; a name
// that is not there yet is appended.
func replaceOrAppend(lines []string, name, replacement string) []string {
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		assigned, _, hasSeparator := strings.Cut(trimmed, "=")
		if !hasSeparator || strings.TrimSpace(assigned) != name {
			continue
		}
		lines[i] = replacement
		return lines
	}
	return append(lines, replacement)
}

func rewriteDotEnv(home, systemUser, directory string, chosen target) (ConfigChange, bool) {
	relative := path.Join(directory, ".env")
	content, err := files.ReadFileBeneath(home, relative, maxConfigBytes)
	if err != nil {
		return ConfigChange{}, false
	}
	// A .env alone proves nothing; plenty of projects ship one. artisan settles
	// it, and failing that the file has to at least name a database.
	_, artisanErr := files.StatBeneath(home, path.Join(directory, "artisan"))
	if artisanErr != nil && !strings.Contains(string(content), "DB_DATABASE") {
		return ConfigChange{}, false
	}

	change := ConfigChange{Path: relative, Kind: "laravel", Fields: []string{}}
	lines := strings.Split(string(content), "\n")
	for _, key := range dotEnvKeys {
		lines = replaceOrAppend(lines, key.Name, key.Name+"="+dotEnvValue(key.Value(chosen)))
		change.Fields = append(change.Fields, key.Name)
	}
	if err := files.WriteFileBeneath(home, relative, []byte(strings.Join(lines, "\n")), 0640, systemUser); err != nil {
		change.Note = "write_failed"
		return change, true
	}
	change.Applied = true
	return change, true
}
