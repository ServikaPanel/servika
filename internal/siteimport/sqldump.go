package siteimport

import (
	"bufio"
	"compress/gzip"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"

	"servika/internal/credentials"
	"servika/internal/httpx"
	"servika/internal/sqlimport"
)

// importSlot serializes dump imports across the whole panel. Each one holds an
// uploaded file on disk and streams it into MariaDB, so running several at once
// multiplies both the disk they occupy and the write load, on a host shared with
// every other tenant's live site.
var importSlot = make(chan struct{}, 1)

type sqlResponse struct {
	OK        bool   `json:"ok"`
	DBName    string `json:"db_name"`
	Bytes     int64  `json:"bytes"`
	Truncated bool   `json:"truncated"`
}

// target is a database this domain owns, with the credentials an application's
// configuration file has to name.
type target struct {
	DBName   string
	User     string
	Password string
	Host     string
}

// UploadSQL imports a .sql or .sql.gz dump into one of the domain's databases.
//
// The dump is applied by internal/sqlimport, which runs it as an account granted
// on that one schema. It is never applied on the panel's own root connection,
// where naming a database sets a default schema and imposes no boundary at all,
// so a dump carrying `USE mysql; GRANT ALL PRIVILEGES ON *.* ...` would take the
// whole server.
func (h *Handlers) UploadSQL(w http.ResponseWriter, r *http.Request) {
	// This endpoint moves a body far larger than the server's own read and write
	// timeouts allow for, so it lifts them for this request alone.
	if err := httpx.ExtendDeadline(w, r, httpx.LargeTransferDeadline); err != nil {
		httpx.LogR(r, "sql upload: could not extend the socket deadline: %v", err)
	}

	domainID, _, _, err := h.domain(r)
	if err != nil {
		httpx.WriteError(w, statusFor(err), importMessage(err))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxDumpBytes+(1<<20))
	reader, err := r.MultipartReader()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "a multipart body is required")
		return
	}

	// The upload lands in the panel temp dir (TMPDIR, persistent disk) rather
	// than the tenant home: it is transient, and a dump does not belong in a
	// tenant's quota for the seconds it takes to apply.
	spool, err := os.CreateTemp("", "servika-import-dump-*.sql")
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "a temporary file could not be created")
		return
	}
	spoolName := spool.Name()
	defer func() { _ = os.Remove(spoolName) }()
	defer func() { _ = spool.Close() }()
	if err := spool.Chmod(0600); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "a temporary file could not be secured")
		return
	}

	var (
		dbName    string
		truncate  bool
		written   int64
		dumpFound bool
	)
	for {
		part, partErr := reader.NextPart()
		if errors.Is(partErr, io.EOF) {
			break
		}
		if partErr != nil {
			httpx.WriteError(w, http.StatusBadRequest, "the upload could not be read or exceeded the size limit")
			return
		}
		switch part.FormName() {
		case "db_name":
			dbName = strings.TrimSpace(readField(part))
		case "truncate":
			value := strings.TrimSpace(readField(part))
			truncate = value == "1" || strings.EqualFold(value, "true")
		case "dump":
			written, err = io.Copy(spool, io.LimitReader(part, MaxDumpBytes+1))
			_ = part.Close()
			if err != nil {
				httpx.WriteError(w, http.StatusBadRequest, "the dump could not be read")
				return
			}
			if written > MaxDumpBytes {
				httpx.WriteError(w, http.StatusRequestEntityTooLarge, "the dump exceeds the size limit")
				return
			}
			dumpFound = true
			continue
		}
		_ = part.Close()
	}
	if !dumpFound {
		httpx.WriteError(w, http.StatusBadRequest, "the dump field is required")
		return
	}

	chosen, err := h.databaseTarget(r, domainID, dbName)
	if err != nil {
		httpx.WriteError(w, http.StatusForbidden, err.Error())
		return
	}

	select {
	case importSlot <- struct{}{}:
		defer func() { <-importSlot }()
	case <-r.Context().Done():
		httpx.WriteError(w, http.StatusRequestTimeout, "the request ended while waiting for an import slot")
		return
	}

	source, err := dumpReader(spool)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if closer, ok := source.(io.Closer); ok {
		defer func() { _ = closer.Close() }()
	}

	if truncate {
		if err := sqlimport.Truncate(r.Context(), chosen.DBName); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "the database could not be emptied")
			return
		}
	}
	if err := sqlimport.Import(r.Context(), chosen.DBName, source); err != nil {
		// The client failure text is the useful part of a failed import (a syntax
		// error, a missing table) and it describes the caller's own dump going
		// into the caller's own database, so it is returned rather than hidden.
		httpx.WriteError(w, http.StatusBadRequest, importFailure(err))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sqlResponse{
		OK: true, DBName: chosen.DBName, Bytes: written, Truncated: truncate,
	})
}

// databaseTarget confirms the named database belongs to this domain and returns
// its credentials. db_accounts carries every panel-created database including
// the domain's first one, so the row's existence IS the ownership proof.
func (h *Handlers) databaseTarget(r *http.Request, domainID int64, dbName string) (target, error) {
	if dbName == "" {
		return target{}, errors.New("the db_name field is required")
	}
	if !credentials.ValidDBIdentifier(dbName) {
		return target{}, errors.New("invalid database name")
	}
	var user, stored, host string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT db_user, db_pass_plain, COALESCE(db_host,'localhost')
		   FROM db_accounts WHERE domain_id=? AND db_name=?`, domainID, dbName).
		Scan(&user, &stored, &host)
	if errors.Is(err, sql.ErrNoRows) {
		return target{}, errors.New("that database does not belong to this domain")
	}
	if err != nil {
		return target{}, errors.New("the database record could not be read")
	}
	password, err := credentials.DecryptDBPass(user, stored)
	if err != nil {
		return target{}, errors.New("the stored database password could not be read")
	}
	return target{DBName: dbName, User: user, Password: password, Host: host}, nil
}

// dumpReader rewinds the spooled upload and transparently decompresses gzip.
//
// The magic bytes decide, not the file name: people routinely upload a gzip
// named .sql, and a name-based guess would feed compressed bytes to the client
// and fail with an unreadable syntax error.
func dumpReader(spool *os.File) (io.Reader, error) {
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return nil, errors.New("the uploaded dump could not be read")
	}
	buffered := bufio.NewReaderSize(spool, 64<<10)
	magic, err := buffered.Peek(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, errors.New("the uploaded dump could not be read")
	}
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		decompressed, gzipErr := gzip.NewReader(buffered)
		if gzipErr != nil {
			return nil, errors.New("the dump is not a readable gzip file")
		}
		// No separate cap on the expanded size: the bytes stream straight into
		// MariaDB rather than onto disk, and the resulting schema is already
		// bounded by the tenant's own disk quota.
		return decompressed, nil
	}
	return buffered, nil
}

// importFailure keeps the client's own error readable while bounding it, so a
// dump that fails on its thousandth statement does not return a response the
// size of the dump.
func importFailure(err error) string {
	message := strings.TrimSpace(err.Error())
	const limit = 400
	if len(message) > limit {
		message = message[:limit] + "…"
	}
	if message == "" {
		return "the dump could not be imported"
	}
	return fmt.Sprintf("the dump could not be imported: %s", message)
}

// readField reads a small multipart form field.
func readField(part *multipart.Part) string {
	value, _ := io.ReadAll(io.LimitReader(part, 4<<10))
	return string(value)
}
