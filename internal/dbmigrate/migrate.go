// Package dbmigrate applies the numbered SQL files under migrations/ exactly
// once each, and resumes a file that failed part way through.
//
// It lives outside cmd/server so the runner can be measured against a real
// MariaDB. Every function here returns an error; the caller decides that a
// migration failure is fatal.
package dbmigrate

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
)

// ErrResumeRefused reports that a file which stopped part way through has since
// changed, so the statements already committed belong to a different file.
var ErrResumeRefused = errors.New("migration changed since it stopped part way through")

// Run applies every unapplied migration file in dir, in name order.
func Run(d *sql.DB, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("migration directory could not be read: %v", err)
		return nil
	}
	if err := ensureTables(d); err != nil {
		return err
	}
	applied, err := appliedChecksums(d)
	if err != nil {
		return err
	}

	for _, name := range migrationNames(entries) {
		if err := applyNamed(d, dir, name, applied); err != nil {
			return err
		}
	}
	return nil
}

// migrationNames returns the migration files of a directory, in the order they
// are applied. A directory is never a migration, whatever it is called.
func migrationNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

// applyNamed applies one migration file unless its checksum says it already ran.
func applyNamed(d *sql.DB, dir, name string, applied map[string]string) error {
	// #nosec G304 -- dir is a fixed system path and name comes from reading it.
	body, err := os.ReadFile(dir + "/" + name)
	if err != nil {
		return fmt.Errorf("could not read %s: %w", name, err)
	}
	sum := sha256.Sum256(body)
	checksum := hex.EncodeToString(sum[:])
	done, err := reconcileApplied(d, name, checksum, applied)
	if err != nil {
		return err
	}
	if done {
		return nil
	}
	log.Printf("migration: %s", name)
	return applyFile(d, name, string(body), checksum)
}

// ensureTables creates the bookkeeping the runner owns. Neither table comes from
// a numbered migration file, because the runner needs them before it can apply
// one.
func ensureTables(d *sql.DB) error {
	if _, err := d.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		filename VARCHAR(255) NOT NULL PRIMARY KEY,
		applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`); err != nil {
		return fmt.Errorf("could not create schema_migrations: %w", err)
	}
	// Backward-compatible checksum column: existing installs recorded only the
	// filename, so add the column when missing and backfill legacy rows below.
	if _, err := d.Exec(`ALTER TABLE schema_migrations
		ADD COLUMN IF NOT EXISTS checksum CHAR(64) NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("could not add checksum column: %w", err)
	}
	// A row here means a file stopped part way through, never that it applied.
	// schema_migrations keeps its own meaning, which assets/ops/servika-verify
	// counts against the number of files on disk.
	if _, err := d.Exec(`CREATE TABLE IF NOT EXISTS schema_migration_progress (
		filename VARCHAR(255) NOT NULL PRIMARY KEY,
		checksum CHAR(64) NOT NULL,
		statements_done INT NOT NULL DEFAULT 0,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`); err != nil {
		return fmt.Errorf("could not create schema_migration_progress: %w", err)
	}
	return nil
}

func appliedChecksums(d *sql.DB) (map[string]string, error) {
	applied := map[string]string{}
	rows, err := d.Query(`SELECT filename, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("could not read schema_migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name, sum string
		if err := rows.Scan(&name, &sum); err != nil {
			return nil, fmt.Errorf("scan applied row: %w", err)
		}
		applied[name] = sum
	}
	// database/sql reports a connection drop, a driver error or a context
	// deadline that arrives MID-ITERATION only here. Without this check the map
	// comes back SHORT, every migration whose row was not read counts as
	// unapplied, and the runner re-applies it. MariaDB gives DDL an implicit
	// commit, so the statements that succeed before the first duplicate-object
	// error stay applied, the schema_migrations INSERT never runs, and the panel
	// then refuses to start on every later boot naming a file that is correct.
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read applied rows: %w", err)
	}
	return applied, nil
}

// reconcileApplied reports whether name is already applied, and repairs a legacy
// row that carries no checksum.
func reconcileApplied(d *sql.DB, name, checksum string, applied map[string]string) (bool, error) {
	prev, ok := applied[name]
	if !ok {
		return false, nil
	}
	// A blank stored checksum is a legacy row: backfill it once. A non-blank
	// mismatch means an applied migration file was edited, which must never
	// happen; stop startup rather than run on a schema that no longer matches
	// its recorded history.
	if prev == "" {
		if _, err := d.Exec(`UPDATE schema_migrations SET checksum=? WHERE filename=?`, checksum, name); err != nil {
			return false, fmt.Errorf("could not backfill checksum for %s: %w", name, err)
		}
		return true, nil
	}
	if prev != checksum {
		return false, fmt.Errorf("%s was already applied but its contents changed", name)
	}
	return true, nil
}

// splitStatements turns a migration file into the statements to execute.
//
// The index of a statement is what a resume is recorded against, so this must
// stay a pure function of the file body. The checksum recorded beside the index
// is what guarantees the body has not changed underneath it.
func splitStatements(body string) []string {
	var cleaned []string
	for line := range strings.SplitSeq(body, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "--") {
			continue
		}
		cleaned = append(cleaned, line)
	}
	return splitOnUnquotedSemicolons(strings.Join(cleaned, "\n"))
}

// splitOnUnquotedSemicolons cuts SQL at the terminators only.
//
// A plain strings.Split on ";" also cuts inside a string literal, and
// migrations/0104_php_defaults.sql carries one ('client_max_body_size 64m;'),
// so that file could never apply on any server: its fourth statement arrived at
// MariaDB truncated and answered a syntax error.
func splitOnUnquotedSemicolons(sql string) []string {
	var statements []string
	var current strings.Builder
	var scan literalScanner

	for _, c := range sql {
		current.WriteRune(c)
		if !scan.terminator(c) {
			continue
		}
		text := current.String()
		statements = appendStatement(statements, text[:len(text)-1])
		current.Reset()
	}
	return appendStatement(statements, current.String())
}

// literalScanner tracks whether the reader is inside a string literal.
type literalScanner struct {
	quote   rune // 0 outside a literal, else the character that opened it
	escaped bool
}

// terminator reports whether c ends a statement, and advances the literal state.
func (s *literalScanner) terminator(c rune) bool {
	switch {
	case s.escaped:
		// A backslash escapes the next character inside a MariaDB string, so a
		// \' does not close the literal.
		s.escaped = false
	case s.quote != 0:
		s.inLiteral(c)
	case c == '\'' || c == '"' || c == '`':
		s.quote = c
	case c == ';':
		return true
	}
	return false
}

// inLiteral advances the state of a reader already inside a literal.
func (s *literalScanner) inLiteral(c rune) {
	if c == '\\' && s.quote != '`' {
		s.escaped = true
	} else if c == s.quote {
		s.quote = 0
	}
}

func appendStatement(statements []string, stmt string) []string {
	if s := strings.TrimSpace(stmt); s != "" {
		return append(statements, s)
	}
	return statements
}

// applyFile runs the statements of one migration and records it as applied.
//
// There is no transaction. MariaDB gives DDL an implicit commit, so a rollback
// was a no-op for exactly the statements migrations are made of: a file that
// failed on its Nth statement had already committed 1..N-1 while nothing
// recorded that, and the next start re-ran it from the first statement and died
// on "table already exists" for good. Each statement is atomic on its own, so
// the statement index is the unit a resume can trust.
func applyFile(d *sql.DB, name, body, checksum string) error {
	statements := splitStatements(body)
	start, err := resumePoint(d, name, statements)
	if err != nil {
		return err
	}
	if start > 0 {
		log.Printf("migration: %s resumes at statement %d of %d", name, start+1, len(statements))
	}
	for i := start; i < len(statements); i++ {
		if _, err := d.Exec(statements[i]); err != nil {
			if perr := recordProgress(d, name, prefixChecksum(statements[:i]), i); perr != nil {
				log.Printf("migration: %s could not record progress: %v", name, perr)
			}
			return fmt.Errorf("%s failed at statement %d of %d (the next start resumes there): %w",
				name, i+1, len(statements), err)
		}
	}
	return finish(d, name, checksum)
}

// prefixChecksum digests the statements that already committed.
//
// The guard is on the APPLIED PREFIX rather than the whole file, because editing
// the file is the operator's only way to repair a migration that failed: a
// whole-file checksum refuses exactly the fix it exists to make possible. A
// repair that leaves the committed statements untouched resumes; one that
// rewrites them is refused, which is the case that would join the head of one
// file to the tail of another.
func prefixChecksum(applied []string) string {
	sum := sha256.Sum256([]byte(strings.Join(applied, ";\n")))
	return hex.EncodeToString(sum[:])
}

// resumePoint reports how many statements of name already committed.
func resumePoint(d *sql.DB, name string, statements []string) (int, error) {
	var stored string
	var done int
	err := d.QueryRow(
		`SELECT checksum, statements_done FROM schema_migration_progress WHERE filename=?`,
		name).Scan(&stored, &done)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, nil
	case err != nil:
		return 0, fmt.Errorf("could not read progress for %s: %w", name, err)
	case done > len(statements) || stored != prefixChecksum(statements[:done]):
		return 0, fmt.Errorf("%w: %s", ErrResumeRefused, name)
	}
	return done, nil
}

func recordProgress(d *sql.DB, name, checksum string, done int) error {
	_, err := d.Exec(`INSERT INTO schema_migration_progress(filename, checksum, statements_done)
		VALUES(?,?,?)
		ON DUPLICATE KEY UPDATE checksum=VALUES(checksum), statements_done=VALUES(statements_done)`,
		name, checksum, done)
	return err
}

// finish records the file as applied and drops its progress row, so the progress
// table is empty on a healthy server.
func finish(d *sql.DB, name, checksum string) error {
	if _, err := d.Exec(
		`INSERT INTO schema_migrations(filename, checksum) VALUES(?,?)`, name, checksum); err != nil {
		return fmt.Errorf("record %s: %w", name, err)
	}
	if _, err := d.Exec(`DELETE FROM schema_migration_progress WHERE filename=?`, name); err != nil {
		return fmt.Errorf("clear progress for %s: %w", name, err)
	}
	return nil
}
