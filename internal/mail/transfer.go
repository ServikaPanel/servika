package mail

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"servika/internal/config"
	"servika/internal/httpx"
	"servika/internal/middleware"
)

// Import and export of one mailbox.
//
// Everything that arrives is turned into messages and written through the same
// Maildir writer the migration uses. The alternative, unpacking an archive
// straight into the mailbox, would let the archive decide where its members
// land; here the destination is built from the folder name by maildirSubdir and
// the archive only supplies a body.

const (
	// maxImportBytes bounds one upload. A mailbox larger than this is a migration,
	// not an import, and the IMAP path carries it without buffering a file.
	maxImportBytes = 4 << 30
	// maxImportMessages bounds an archive that declares far more members than a
	// mailbox plausibly holds.
	maxImportMessages = 500000
	// maxImportMessageBytes bounds a single message, so one crafted member cannot
	// be expanded until the host runs out of memory or disk.
	maxImportMessageBytes = 64 << 20
	// importBudget bounds the whole unpack. The upload itself is already limited;
	// this limits the work it can ask for.
	importBudget = 2 * time.Hour
)

// maildirLetters reverses maildirFlags, so an imported message keeps the read,
// answered and flagged state it arrived with instead of the whole mailbox
// coming back unread.
var maildirLetters = map[rune]string{
	'S': "\\Seen", 'R': "\\Answered", 'F': "\\Flagged", 'T': "\\Deleted", 'D': "\\Draft",
}

// Export streams the mailbox as a gzipped tar.
// GET /domains/{id}/mail/{mid}/export
//
// tar runs under the tenant's own uid. The panel is root, so a tenant symlink
// inside the Maildir would otherwise be followed with root's rights; under the
// tenant the kernel's own permission check applies to every file it opens. It is
// never given -h, which would make it follow those links deliberately.
func (h *Handlers) Export(w http.ResponseWriter, r *http.Request) {
	if err := httpx.ExtendDeadline(w, r, httpx.LargeTransferDeadline); err != nil {
		httpx.LogR(r, "mailbox export: could not extend the socket deadline: %v", err)
	}

	id, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	mailboxID, ok := h.scopedMailbox(w, r, id)
	if !ok {
		return
	}
	layout, localPart, err := h.mailboxLayout(r.Context(), mailboxID)
	if err != nil {
		// #nosec G706 -- integer id only.
		httpx.LogR(r, "locate mailbox=%d for export: %v", mailboxID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the mailbox could not be located on disk")
		return
	}

	command := tenantCommand(r.Context(), layout.systemUser,
		"tar", "-czf", "-", "-C", layout.home, layout.root)
	stdout, err := command.StdoutPipe()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the export could not be started")
		return
	}
	if err := command.Start(); err != nil {
		// #nosec G706 -- integer id and the exec error.
		httpx.LogR(r, "start mailbox=%d export: %v", mailboxID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the export could not be started")
		return
	}

	httpx.Attachment(w, "application/gzip", localPart+"-maildir.tar.gz")
	w.WriteHeader(http.StatusOK)

	// The status line is already sent, so a failure from here on cannot become an
	// error response. It is logged, and the client sees a gzip stream that does
	// not finish, which is the honest signal that the file is incomplete.
	if _, err := io.Copy(w, stdout); err != nil {
		// #nosec G706 -- integer id and an I/O error.
		httpx.LogR(r, "stream mailbox=%d export: %v", mailboxID, err)
	}
	if err := command.Wait(); err != nil {
		// #nosec G706 -- integer id and the exec error.
		httpx.LogR(r, "mailbox=%d export finished badly: %v", mailboxID, err)
	}
	h.audit(r, "mail.export", "", true)
}

// ImportFormats reports what this host can accept.
// GET /domains/{id}/mail/{mid}/import
//
// .pst needs readpst from libpst, which EL10 may not package. Its absence is
// reported here as data, so the screen can leave the option out, rather than
// being discovered by a customer whose upload fails after it finished.
func (h *Handlers) ImportFormats(w http.ResponseWriter, r *http.Request) {
	id, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if _, ok := h.scopedMailbox(w, r, id); !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"maildir_tar_supported": true,
		"mbox_supported":        true,
		"pst_supported":         readPSTAvailable(),
		"max_bytes":             maxImportBytes,
	})
}

// Import unpacks an upload into the mailbox.
// POST /domains/{id}/mail/{mid}/import
func (h *Handlers) Import(w http.ResponseWriter, r *http.Request) {
	if err := httpx.ExtendDeadline(w, r, httpx.LargeTransferDeadline); err != nil {
		httpx.LogR(r, "mailbox import: could not extend the socket deadline: %v", err)
	}

	id, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if !middleware.EnforceCustomerNotSuspended(w, r, id) {
		return
	}
	mailboxID, ok := h.scopedMailbox(w, r, id)
	if !ok {
		return
	}
	layout, ok := h.importTarget(w, r, mailboxID)
	if !ok {
		return
	}
	part, ok := importUpload(w, r)
	if !ok {
		return
	}
	defer func() { _ = part.Close() }()

	ctx, cancel := context.WithTimeout(r.Context(), importBudget)
	defer cancel()

	sink := &maildirSink{layout: layout, token: fmt.Sprintf("import-%d", time.Now().UnixNano())}
	name := part.FileName()
	if err := h.unpackImport(ctx, layout, name, part, sink); err != nil {
		writeImportFailure(w, r, mailboxID, sink, err)
		return
	}

	h.audit(r, "mail.import", name, true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "messages": sink.messages, "bytes": sink.bytes,
		"folders": sink.folderCount(),
	})
}

// importTarget refuses a mailbox a migration is writing into and resolves where
// the import writes. It writes the refusal and reports false when the request
// must stop.
func (h *Handlers) importTarget(w http.ResponseWriter, r *http.Request, mailboxID int64) (maildirLayout, bool) {
	// A migration writes into the same Maildir. Two writers would interleave
	// folders and neither count would mean anything afterwards.
	busy, err := migrationInFlight(r.Context(), h.DB, mailboxID)
	if err != nil {
		// #nosec G706 -- integer id only.
		httpx.LogR(r, "check migrations for mailbox=%d: %v", mailboxID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the mailbox state could not be read")
		return maildirLayout{}, false
	}
	if busy {
		httpx.WriteJSON(w, http.StatusConflict, map[string]any{
			"error": "a migration is already writing into this mailbox", "reason": "migration_already_running",
		})
		return maildirLayout{}, false
	}

	layout, _, err := h.mailboxLayout(r.Context(), mailboxID)
	if err != nil {
		// #nosec G706 -- integer id only.
		httpx.LogR(r, "locate mailbox=%d for import: %v", mailboxID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the mailbox could not be located on disk")
		return maildirLayout{}, false
	}
	return layout, true
}

// importUpload bounds the body and returns its file part. It writes the refusal
// and reports false when the request must stop.
func importUpload(w http.ResponseWriter, r *http.Request) (*multipart.Part, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxImportBytes)
	reader, err := r.MultipartReader()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "a multipart body is required")
		return nil, false
	}
	part, err := uploadPart(reader)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "a file is required in the file field")
		return nil, false
	}
	return part, true
}

// unpackImport reads the upload in the format its name names.
func (h *Handlers) unpackImport(ctx context.Context, layout maildirLayout, name string, part io.Reader, sink *maildirSink) error {
	switch {
	case isTarName(name):
		return importMaildirTar(part, sink)
	case strings.HasSuffix(strings.ToLower(name), ".pst"):
		return h.importPST(ctx, layout, part, sink)
	default:
		// mbox has no required suffix and is what every remaining exporter
		// produces, so it is the fallback rather than a named case.
		return importMbox("INBOX", part, sink)
	}
}

// writeImportFailure logs the failure, takes out what the attempt wrote and
// answers with the reason and the outcome of that rollback.
func writeImportFailure(w http.ResponseWriter, r *http.Request, mailboxID int64, sink *maildirSink, err error) {
	// #nosec G706 -- integer id and the unpack error.
	httpx.LogR(r, "import into mailbox=%d: %v", mailboxID, err)
	// Everything this attempt wrote is taken out again. Keeping it would put
	// the customer in a worse place than an empty mailbox: the only way to
	// finish the import is to upload the whole archive again, and that writes
	// a second copy of every message the failed attempt already delivered.
	removed, rollbackErr := sink.rollback()
	if rollbackErr != nil {
		// #nosec G706 -- integer id and a filesystem error.
		httpx.LogR(r, "import into mailbox=%d: rollback left files behind: %v", mailboxID, rollbackErr)
	}
	httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{
		"error": "the upload could not be unpacked", "reason": reasonForImport(err),
		// Reported rather than swallowed: a rollback that could not finish
		// means a retry WILL duplicate, and the operator has to know.
		"removed": removed, "rollback_incomplete": rollbackErr != nil,
	})
}

// maildirSink writes messages and counts what it wrote. Every import format
// funnels through it, so none of them can invent its own destination.
type maildirSink struct {
	layout maildirLayout
	// token separates this import's filenames from every other one, so two
	// uploads cannot overwrite each other's messages.
	token    string
	messages int
	bytes    int64
	folders  map[string]string
}

func (s *maildirSink) folderCount() int { return len(s.folders) }

// rollback removes every message this import wrote.
//
// A failed import used to leave its partial result in the mailbox, on the theory
// that the customer could finish it by hand. There is no way to finish it: the
// archive is re-uploaded whole, and the token is new on every attempt, so the
// names never collide and the retry delivers a SECOND copy of everything the
// first attempt landed. Removing the partial result is what makes a retry
// produce exactly one copy.
//
// Entries are matched on this import's own token, so mail that was already in
// the folder cannot be caught by it. Removal goes through safeio because the
// panel is root and these directories belong to the tenant.
func (s *maildirSink) rollback() (int, error) {
	prefix := messageNamePrefix(s.token)
	var (
		removed  int
		failures error
	)
	for _, curDir := range s.folders {
		names, err := listNamesBeneath(s.layout.home, curDir)
		if err != nil {
			failures = errors.Join(failures, fmt.Errorf("list %s: %w", curDir, err))
			continue
		}
		for _, name := range names {
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			if err := removeAllBeneath(s.layout.home, curDir+"/"+name); err != nil {
				failures = errors.Join(failures, fmt.Errorf("remove %s: %w", name, err))
				continue
			}
			removed++
		}
	}
	return removed, failures
}

// write stores one message in a folder, creating the folder the first time.
func (s *maildirSink) write(folder string, flags []string, body io.Reader) error {
	if s.messages >= maxImportMessages {
		return errTooManyMessages
	}
	if s.folders == nil {
		s.folders = map[string]string{}
	}
	curDir, known := s.folders[folder]
	if !known {
		// The delimiter is '/' because the folder name reaching here is already
		// this package's own, built from a path or from readpst's directory tree.
		var err error
		curDir, err = s.layout.ensureFolder(maildirSubdir(folder, '/'))
		if err != nil {
			return err
		}
		s.folders[folder] = curDir
	}
	size, err := s.layout.writeMessage(curDir,
		fmt.Sprintf("%s-%d", s.token, s.messages), flags, body)
	if err != nil {
		return err
	}
	s.messages++
	s.bytes += size
	return nil
}

var (
	errTooManyMessages = errors.New("the upload declares more messages than a mailbox holds")
	errMessageTooLarge = errors.New("a single message is larger than the import limit")
	errNoPSTSupport    = errors.New("readpst is not installed on this host")
)

func reasonForImport(err error) string {
	switch {
	case errors.Is(err, errTooManyMessages):
		return "too_many_messages"
	case errors.Is(err, errMessageTooLarge):
		return "message_too_large"
	case errors.Is(err, errNoPSTSupport):
		return "pst_not_supported"
	default:
		return "unreadable_upload"
	}
}

// importMaildirTar reads a Maildir out of a tar, gzipped or not.
//
// The member path decides only which FOLDER a message belongs to; the file is
// then written by the sink under a name this package builds. A member called
// ../../etc/passwd therefore names a folder, not a destination.
func importMaildirTar(source io.Reader, sink *maildirSink) error {
	stream, err := maybeGunzip(source)
	if err != nil {
		return err
	}
	archive := tar.NewReader(stream)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if header.Typeflag != tar.TypeReg {
			// Directories carry no messages and links, devices and sockets have no
			// meaning in a mailbox.
			continue
		}
		folder, flags, wanted := maildirMember(header.Name)
		if !wanted {
			continue
		}
		if header.Size > maxImportMessageBytes {
			return errMessageTooLarge
		}
		if err := sink.write(folder, flags, io.LimitReader(archive, maxImportMessageBytes)); err != nil {
			return err
		}
	}
}

// maildirMember maps one archive path onto a folder and the flags in its name.
//
// A Maildir stores messages under cur/ and new/ inside the folder directory, so
// the component before that is the folder. tmp/ holds deliveries that were never
// completed and the index and cache files are Dovecot's own, none of which is a
// message.
func maildirMember(name string) (folder string, flags []string, wanted bool) {
	name = path.Clean(strings.TrimPrefix(filepath.ToSlash(name), "./"))
	parts := strings.Split(name, "/")
	if len(parts) < 2 {
		return "", nil, false
	}
	base := parts[len(parts)-1]
	if strings.HasPrefix(base, "dovecot") || base == maildirsizeName || strings.HasPrefix(base, ".") {
		return "", nil, false
	}
	switch parts[len(parts)-2] {
	case "cur", "new":
	default:
		return "", nil, false
	}

	// Everything above cur/ or new/ is the folder path, with a Maildir++ leading
	// dot dropped so ".Sent" and "Sent" name the same folder.
	folder = strings.Join(parts[:len(parts)-2], "/")
	folder = strings.TrimPrefix(folder, ".")
	folder = strings.ReplaceAll(folder, "/.", "/")
	if folder == "" {
		folder = "INBOX"
	}
	return folder, flagsFromMaildirName(base), true
}

// flagsFromMaildirName reads the letters after ":2," back into IMAP flags.
func flagsFromMaildirName(base string) []string {
	index := strings.LastIndex(base, ":2,")
	if index == -1 {
		return nil
	}
	var flags []string
	seen := map[string]bool{}
	for _, letter := range base[index+3:] {
		flag, known := maildirLetters[letter]
		if !known || seen[flag] {
			continue
		}
		seen[flag] = true
		flags = append(flags, flag)
	}
	return flags
}

// importMbox splits an mbox into messages.
//
// A message starts at a line beginning with "From " and every such line inside a
// body was escaped to ">From " when the file was written, so the escape is undone
// on the way in. Without that a quoted mail would come back one character
// different from what was sent.
func importMbox(folder string, source io.Reader, sink *maildirSink) error {
	return forEachMboxMessage(source, func(body []byte) error {
		// An mbox carries no flags, so an imported message arrives unread, which
		// is what an unread message in the file was.
		return sink.write(folder, nil, bytes.NewReader(body))
	})
}

// forEachMboxMessage splits the stream and calls emit once per message. It is
// separate from the writing so the split itself can be exercised without a
// mailbox on disk.
func forEachMboxMessage(source io.Reader, emit func(body []byte) error) error {
	reader := bufio.NewReaderSize(source, 64<<10)
	split := &mboxSplit{emit: emit}
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			if lineErr := split.add(line); lineErr != nil {
				return lineErr
			}
		}
		if errors.Is(err, io.EOF) {
			return split.flush()
		}
		if err != nil {
			return err
		}
	}
}

// mboxSplit gathers the lines of the message being read.
type mboxSplit struct {
	message bytes.Buffer
	emit    func(body []byte) error
}

// add takes one line: a separator ends the message before it, an escaped
// separator loses its escape, and a message past the size limit is refused.
func (s *mboxSplit) add(line []byte) error {
	switch {
	case bytes.HasPrefix(line, []byte("From ")):
		if flushErr := s.flush(); flushErr != nil {
			return flushErr
		}
		// The separator carries the envelope sender and the delivery date,
		// not the message. Keeping it would put a line that is not a header
		// above the headers of every message after the first.
		line = nil
	case bytes.HasPrefix(line, []byte(">From ")):
		line = line[1:]
	}
	if s.message.Len()+len(line) > maxImportMessageBytes {
		return errMessageTooLarge
	}
	s.message.Write(line)
	return nil
}

// flush emits the gathered message, unless it holds nothing but line breaks.
func (s *mboxSplit) flush() error {
	if s.message.Len() == 0 {
		return nil
	}
	body := bytes.TrimRight(s.message.Bytes(), "\n")
	s.message.Reset()
	if len(body) == 0 {
		return nil
	}
	return s.emit(body)
}

// importPST converts an Outlook export and feeds the result through the mbox
// reader, so a .pst and an mbox land through exactly one writer.
func (h *Handlers) importPST(ctx context.Context, layout maildirLayout, source io.Reader, sink *maildirSink) error {
	if !readPSTAvailable() {
		return errNoPSTSupport
	}
	// An empty dir argument keeps this on TMPDIR, which the server pins to
	// persistent disk: a multi-gigabyte export would otherwise fill the tmpfs.
	work, err := os.MkdirTemp("", "servika-pst-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()

	// readpst parses a file the customer supplied, so it runs as the tenant
	// rather than as root. That needs the working directory to be theirs.
	if err := chownToTenant(work, layout.systemUser); err != nil {
		return err
	}
	archive := filepath.Join(work, "upload.pst")
	if err := spoolTo(archive, source, layout.systemUser); err != nil {
		return err
	}
	output := filepath.Join(work, "out")
	if err := os.Mkdir(output, 0o700); err != nil {
		return err
	}
	if err := chownToTenant(output, layout.systemUser); err != nil {
		return err
	}

	// -r keeps the folder tree, and each folder becomes one mbox file.
	command := tenantCommand(ctx, layout.systemUser,
		config.ReadPSTBin(), "-q", "-r", "-o", output, archive)
	if out, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("readpst: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return walkPSTOutput(output, sink)
}

// walkPSTOutput feeds every mbox readpst produced into the sink, naming each
// folder after its place in the tree.
func walkPSTOutput(root string, sink *maildirSink) error {
	var files []string
	if err := filepath.WalkDir(root, func(p string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			files = append(files, p)
		}
		return nil
	}); err != nil {
		return err
	}
	// A stable order keeps a repeated import producing the same names.
	sort.Strings(files)

	for _, p := range files {
		relative, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		folder := strings.TrimSuffix(filepath.ToSlash(relative), ".mbox")
		if folder == "" {
			folder = "INBOX"
		}
		if err := importPSTFile(p, folder, sink); err != nil {
			return err
		}
	}
	return nil
}

// importPSTFile reads one file the converter produced, refusing to follow a
// symbolic link.
//
// This directory is created by the panel but FILLED by a process running as the
// tenant, so its contents are the tenant's, not this function's. The panel runs
// as root, and `os.Open` follows a link: an entry pointing at /etc/servika/env
// would deliver SERVIKA_JWT_SECRET and SERVIKA_SECRET_KEY into a mailbox the
// tenant reads over IMAP. O_NOFOLLOW refuses the open outright, and the
// regularity check runs on the FD rather than a separate path stat, so nothing
// can be swapped in between the two.
//
// O_NONBLOCK is there for a second reason: opening a fifo BLOCKS until someone
// writes to it, so without it a named pipe left in this directory would hang the
// import for its whole budget and never reach the check below. It has no effect
// on a regular file.
//
// A refused entry is SKIPPED rather than failing the whole import: one odd file
// must not cost the customer the real mail beside it. It is logged, never
// swallowed.
func importPSTFile(path, folder string, sink *maildirSink) error {
	// #nosec G304 -- path comes from walking a directory this function created, and O_NOFOLLOW plus the IsRegular check below refuse anything the tenant may have placed in it.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		// #nosec G706 -- the path is one this process built under its own temp dir.
		log.Printf("import: skipped %s, which could not be opened as a plain file: %v", path, err)
		return nil
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		// #nosec G706 -- the path is one this process built under its own temp dir.
		log.Printf("import: skipped %s, which is not a regular file", path)
		return nil
	}
	return importMbox(folder, file, sink)
}

// maybeGunzip wraps the stream in a gzip reader when it starts with the gzip
// magic, so a .tar and a .tar.gz both read.
func maybeGunzip(source io.Reader) (io.Reader, error) {
	buffered := bufio.NewReaderSize(source, 4<<10)
	magic, err := buffered.Peek(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		return gzip.NewReader(buffered)
	}
	return buffered, nil
}

func isTarName(name string) bool {
	lower := strings.ToLower(name)
	for _, suffix := range []string{".tar", ".tar.gz", ".tgz"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

// readPSTAvailable reports whether the converter is installed. It is checked
// rather than assumed because libpst is not part of a minimal EL10.
func readPSTAvailable() bool {
	info, err := os.Stat(config.ReadPSTBin())
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

// migrationInFlight reports whether this mailbox already has an unfinished job.
//
// It fails closed: a read that errors denies the import, because the alternative
// is two writers in one Maildir and no way to tell afterwards which count is
// real.
func migrationInFlight(ctx context.Context, db *sql.DB, mailboxID int64) (bool, error) {
	var count int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM mail_migration_jobs
		  WHERE mailbox_id=? AND status IN ('queued','running')`, mailboxID).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// mailboxLayout resolves where a mailbox lives and what it is called, so a
// caller needs one round trip rather than two.
func (h *Handlers) mailboxLayout(ctx context.Context, mailboxID int64) (maildirLayout, string, error) {
	layout, err := layoutFor(ctx, h.DB, mailboxID)
	if err != nil {
		return maildirLayout{}, "", err
	}
	var localPart string
	if err := h.DB.QueryRowContext(ctx,
		`SELECT local_part FROM mailboxes WHERE id=?`, mailboxID).Scan(&localPart); err != nil {
		return maildirLayout{}, "", err
	}
	return layout, localPart, nil
}

// uploadPart returns the file part of a multipart body, skipping anything else
// the form carries.
func uploadPart(reader *multipart.Reader) (*multipart.Part, error) {
	for {
		part, err := reader.NextPart()
		if err != nil {
			return nil, err
		}
		if part.FormName() == "file" {
			return part, nil
		}
		_ = part.Close()
	}
}

// chownToTenant hands a working directory to the tenant, which is what lets the
// converter run as them rather than as root.
func chownToTenant(target, systemUser string) error {
	account, err := user.Lookup(systemUser)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	return os.Chown(target, uid, gid)
}

// spoolTo writes the upload to a file the tenant can read back.
func spoolTo(target string, source io.Reader, systemUser string) error {
	// #nosec G304 -- target is built from a directory this process created.
	file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(file, io.LimitReader(source, maxImportBytes)); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return chownToTenant(target, systemUser)
}

// tenantCommand runs a tool under the tenant's own uid with an environment that
// carries nothing of the panel's. Inheriting os.Environ() would hand a
// customer-triggered child SERVIKA_JWT_SECRET and SERVIKA_SECRET_KEY.
func tenantCommand(ctx context.Context, systemUser, name string, arguments ...string) *exec.Cmd {
	full := append([]string{"-u", systemUser, "--", name}, arguments...)
	// #nosec G204 G702 -- fixed binary (runuser) with separate args (no shell); systemUser comes from the mail_domains row, not from the request.
	command := exec.CommandContext(ctx, "runuser", full...)
	command.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/home/" + systemUser,
		"USER=" + systemUser,
		"LOGNAME=" + systemUser,
	}
	return command
}
