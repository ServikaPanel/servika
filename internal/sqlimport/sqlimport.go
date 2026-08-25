// Package sqlimport streams a SQL dump into one database, and is the only place
// the panel is allowed to do that.
//
// The panel process is root, and root@localhost authenticates to MariaDB through
// the unix_socket plugin with no password. `mysql <db>` run from there selects a
// DEFAULT schema and nothing more: it is not a privilege boundary. Every
// statement in the dump therefore executes with full server rights, so a dump
// carrying
//
//	USE mysql;
//	CREATE USER 'back'@'%' IDENTIFIED BY '...';
//	GRANT ALL PRIVILEGES ON *.* TO 'back'@'%';
//
// hands over the entire database server, including every other tenant's data.
// Both places that fed a dump to root that way (a restored backup archive and an
// imported cPanel account) carry content the panel did not author.
//
// Filtering the dump is not the fix. A line filter that drops `USE ` and
// `CREATE DATABASE ` misses `/*!50000 USE mysql */`, a leading tab, a statement
// split across lines, and anything else the server accepts but the filter was
// not written for. The account is the fix: import runs as a temporary user with
// GRANT ALL on the target schema only, so MariaDB rejects everything else with
// its own privilege check rather than ours.
package sqlimport

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"servika/internal/config"
	"servika/internal/credentials"
)

// commandEnv is the client subprocess environment. It must not inherit the
// panel's, which carries SERVIKA_JWT_SECRET and SERVIKA_SECRET_KEY.
var commandEnv = []string{
	"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	"HOME=/root",
}

// importPasswordLength is the temporary account's password length. The account
// lives for one import and is dropped afterwards, but it is reachable from any
// local process for that window because MariaDB listens on 127.0.0.1.
const importPasswordLength = 28

// longLineLimit bounds how much of one physical line is buffered for DEFINER
// rewriting. Beyond it the line streams through untouched. mysqldump stamps a
// DEFINER only onto short statement lines, and its own default
// --net-buffer-length is 1 MiB, so this is above anything that needs rewriting.
const longLineLimit = 1 << 20

// ErrInvalidTarget means the caller named something that is not an importable
// database.
var ErrInvalidTarget = errors.New("invalid import target database")

// selectsAnotherSchema reports a line that switches or creates a schema. See
// normalize: this is compatibility, and it is deliberately not relied on for
// anything else.
func selectsAnotherSchema(line string) bool {
	trimmed := strings.ToUpper(strings.TrimLeft(line, " \t"))
	return strings.HasPrefix(trimmed, "USE ") ||
		strings.HasPrefix(trimmed, "USE`") ||
		strings.HasPrefix(trimmed, "CREATE DATABASE ")
}

// reDefiner matches the DEFINER clauses mysqldump stamps onto views, triggers,
// routines and events, in both the bare and version-comment forms.
var reDefiner = regexp.MustCompile("(?i)/\\*![0-9]* *DEFINER *= *[^*]*\\*/|DEFINER *= *`[^`]*`@`[^`]*`")

// systemDatabases can never be an import target. The scoped account already
// makes writing to them impossible; refusing the name outright means the panel
// never even creates an account pointed at one.
var systemDatabases = map[string]bool{
	"mysql": true, "information_schema": true, "performance_schema": true,
	"sys": true, "panel": true,
}

// Import streams dump into targetDB.
//
// The dump is never trusted. It reaches MariaDB through a temporary account
// privileged on targetDB alone, which is dropped when the import returns however
// it returns.
func Import(ctx context.Context, targetDB string, dump io.Reader) error {
	return withScopedAccount(ctx, targetDB, func(client *exec.Cmd) error {
		client.Stdin = normalize(dump)
		return nil
	})
}

// Truncate drops every table and view in targetDB, for an import that must
// replace a schema rather than merge into one.
//
// It runs through the same scoped account, so it can only empty the schema the
// caller named. DATABASE() resolves to the connection's own default schema,
// which means the statement text carries no identifier at all and there is
// nothing to quote or escape.
func Truncate(ctx context.Context, targetDB string) error {
	return withScopedAccount(ctx, targetDB, func(client *exec.Cmd) error {
		client.Stdin = strings.NewReader(truncateScript)
		return nil
	})
}

// truncateScript empties the default schema. GROUP_CONCAT is capped at 1 KiB by
// default, which would silently drop tables past the cap and leave a
// half-emptied schema, so the session limit is raised first. Views are dropped
// separately because DROP TABLE does not remove them.
const truncateScript = `
SET FOREIGN_KEY_CHECKS = 0;
SET SESSION group_concat_max_len = 1000000;
SELECT GROUP_CONCAT(CONCAT('` + "`" + `', table_name, '` + "`" + `')) INTO @tables
  FROM information_schema.tables
  WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE';
SET @statement := IFNULL(CONCAT('DROP TABLE IF EXISTS ', @tables), 'DO 0');
PREPARE dropTables FROM @statement;
EXECUTE dropTables;
DEALLOCATE PREPARE dropTables;
SELECT GROUP_CONCAT(CONCAT('` + "`" + `', table_name, '` + "`" + `')) INTO @views
  FROM information_schema.views
  WHERE table_schema = DATABASE();
SET @statement := IFNULL(CONCAT('DROP VIEW IF EXISTS ', @views), 'DO 0');
PREPARE dropViews FROM @statement;
EXECUTE dropViews;
DEALLOCATE PREPARE dropViews;
SET FOREIGN_KEY_CHECKS = 1;
`

// withScopedAccount runs one MariaDB client against targetDB as a temporary
// account granted on that schema alone. prepare supplies the client's input.
func withScopedAccount(ctx context.Context, targetDB string, prepare func(*exec.Cmd) error) error {
	if !credentials.ValidDBIdentifier(targetDB) || systemDatabases[strings.ToLower(targetDB)] {
		return fmt.Errorf("%w: %s", ErrInvalidTarget, targetDB)
	}

	user, password, err := newAccount(targetDB)
	if err != nil {
		return err
	}
	// Dropped on every path. A stranded account would stay usable from any local
	// process, which is the exact exposure this package exists to close.
	defer func() { _ = credentials.MySQLDropUser(user) }()

	optionFile, removeOptionFile, err := writeOptionFile(user, password)
	if err != nil {
		return err
	}
	defer removeOptionFile()

	// --local-infile=0 is explicit rather than trusted to the client default: a
	// dump that reaches LOAD DATA LOCAL INFILE reads files with the PANEL's
	// filesystem rights, which the schema-scoped grant does not restrain.
	// #nosec G204 G702 -- fixed binary with separate args (no shell); targetDB passed ValidDBIdentifier and the option file path is server-internal.
	command := exec.CommandContext(ctx, "mysql",
		"--defaults-extra-file="+optionFile,
		"--local-infile=0",
		"--default-character-set=utf8mb4",
		targetDB)
	command.Env = commandEnv
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := prepare(command); err != nil {
		return err
	}
	if err := command.Run(); err != nil {
		return fmt.Errorf("import into %s failed: %s", targetDB, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// newAccount creates the temporary account for one import.
func newAccount(targetDB string) (string, string, error) {
	raw := make([]byte, 9)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	user := "svk_imp_" + hex.EncodeToString(raw)
	password := credentials.RandomPassword(importPasswordLength)
	if err := credentials.MySQLCreateScopedUser(user, password, targetDB); err != nil {
		return "", "", err
	}
	return user, password, nil
}

// writeOptionFile puts the credentials where the client can read them without
// them appearing in argv, which is world-readable through /proc/<pid>/cmdline
// and which a tenant reaches with arbitrary shell through a cron entry.
func writeOptionFile(user, password string) (string, func(), error) {
	file, err := os.CreateTemp("", "servika-sqlimport-*.cnf")
	if err != nil {
		return "", func() {}, err
	}
	name := file.Name()
	cleanup := func() { _ = os.Remove(name) }
	// Before any content: the file is created 0600 by CreateTemp, and this keeps
	// it that way explicitly rather than by assumption.
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	// An option-file value ends at the newline, so a credential carrying one
	// would silently truncate into a different setting. RandomPassword cannot
	// produce one and the user name is hex, but check rather than rely on that.
	if strings.ContainsAny(user+password, "\r\n\x00") {
		_ = file.Close()
		cleanup()
		return "", func() {}, errors.New("the generated import credentials contain a line break")
	}
	_, err = file.WriteString("[client]\nuser=" + user + "\npassword=\"" + optionFileEscape(password) +
		"\"\nsocket=" + config.MySQLSocket() + "\n")
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	return name, cleanup, nil
}

// optionFileEscape quotes a value for a double-quoted my.cnf entry. The client
// treats \ as an escape inside quotes, so both it and the closing quote have to
// be escaped or the value read back is not the one written.
func optionFileEscape(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
}

// normalize rewrites a dump so a schema-scoped account can apply it.
//
// Everything it does is COMPATIBILITY, never security. The account is the
// boundary; this only removes the two things that would make an otherwise valid
// dump fail against a low-privilege user:
//
//   - DEFINER clauses. mysqldump stamps them onto views, triggers, routines and
//     events. A low-privilege user cannot create an object owned by somebody
//     else, so a dump keeping its original definer (a cPanel account that does
//     not exist here, a tenant account on a restore) is rejected outright.
//     Dropping the clause creates the object as the importing account instead.
//   - USE and CREATE DATABASE lines, which name the SOURCE schema. The account
//     has no rights there, so they now fail with access denied and abort the
//     import. Dropping them is what the cPanel path already did; the difference
//     is that it is no longer mistaken for a defence. It never was one: it does
//     not see `/*!50000 USE mysql */`, a leading tab, or a statement split
//     across lines.
//
// Lines longer than longLineLimit stream through unrewritten rather than being
// buffered whole. Those are bulk INSERT data, not the short statements
// mysqldump stamps a DEFINER onto, and an unbounded buffer here would let a
// crafted dump decide the panel's memory use.
func normalize(dump io.Reader) io.Reader {
	pipeReader, pipeWriter := io.Pipe()
	go func() {
		// ReadSlice, not ReadString or Scanner: it reports ErrBufferFull instead
		// of growing without bound, which is what makes the over-long case a
		// pass-through rather than a memory decision handed to the dump author.
		reader := bufio.NewReaderSize(dump, longLineLimit)
		overLong := false
		for {
			chunk, readErr := reader.ReadSlice('\n')
			text := string(chunk)
			if errors.Is(readErr, bufio.ErrBufferFull) {
				// Mid-line. Emit verbatim and keep doing so until the newline
				// arrives; rewriting a fragment could only corrupt it.
				if _, err := io.WriteString(pipeWriter, text); err != nil {
					_ = pipeWriter.CloseWithError(err)
					return
				}
				overLong = true
				continue
			}
			if !overLong {
				if selectsAnotherSchema(text) {
					text = ""
				} else {
					text = reDefiner.ReplaceAllString(text, "")
				}
			}
			overLong = false
			if text != "" {
				if _, err := io.WriteString(pipeWriter, text); err != nil {
					_ = pipeWriter.CloseWithError(err)
					return
				}
			}
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					_ = pipeWriter.Close()
				} else {
					_ = pipeWriter.CloseWithError(readErr)
				}
				return
			}
		}
	}()
	return pipeReader
}
