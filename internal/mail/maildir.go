package mail

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"servika/internal/files"
)

// Maildir writing for migrated messages.
//
// Messages are written straight into the tenant's Maildir rather than appended
// over IMAP, because the panel keeps only a hash of the mailbox password and so
// cannot log in as its own customer. Writing the files is also what lets the
// copy set ownership correctly.

// The safe-write primitives the Maildir code reaches. They are variables so a
// test can record the writes without a tenant home: the real ones need openat2
// and a Linux user that owns the directory.
var (
	mkdirAllBeneath   = files.MkdirAllBeneath
	chmodBeneath      = files.ChmodBeneath
	restoreconBeneath = files.RestoreconBeneath
	streamIntoBeneath = files.StreamIntoBeneath
	listNamesBeneath  = files.ListNamesBeneath
	removeAllBeneath  = files.RemoveAllBeneath
)

// mailboxMaildir composes a mailbox's message store, with the trailing slash
// Dovecot and Postfix both expect on a Maildir path.
//
// domainName is IN the path. maildirRoot belongs to the SYSTEM USER, while the
// uniqueness constraint on mailboxes is (domain_id, local_part); an addon domain
// carries its parent's system_user, so keying the store on the local part alone
// sent info@parent.com and info@addon.com to one directory. They are two rows
// with two passwords and two quotas, so either password read and deleted the
// other account's mail.
//
// Existing mailboxes keep whatever their maildir column already holds: Dovecot's
// user_query and Postfix's mailbox map read that column instead of rebuilding a
// path, so the two layouts coexist and no message has to be moved.
func mailboxMaildir(maildirRoot, domainName, localPart string) string {
	return filepath.Join(maildirRoot, domainName, localPart) + "/"
}

// createMaildir creates the store and hands it to the tenant.
//
// Through the files.*Beneath primitives, never os.MkdirAll plus os.Chown: this
// runs as root inside a home the tenant owns, so a symlink planted at any
// component of the path would otherwise make root create a directory, and give
// it away, anywhere on the host. MkdirAllBeneath creates 0755, so the leaf is
// chmodded to the 0700 a Maildir wants.
func createMaildir(systemUser, maildir string) error {
	home := filepath.Join("/home", systemUser)
	rel, inside := strings.CutPrefix(filepath.Clean(maildir), home+"/")
	if !inside || rel == "" {
		return fmt.Errorf("maildir is outside the tenant home")
	}
	if err := mkdirAllBeneath(home, rel, systemUser); err != nil {
		return err
	}
	if err := chmodBeneath(home, rel, 0o700); err != nil {
		return err
	}
	restoreconBeneath(home, rel)
	return nil
}

// maildirFlags maps IMAP flags onto the Maildir info suffix.
//
// The letters are defined by the Maildir specification and Dovecot reads them on
// sight, so a copied message arrives already read, flagged or answered instead
// of the whole mailbox coming back unread.
var maildirFlags = map[string]string{
	"\\Seen":     "S",
	"\\Answered": "R",
	"\\Flagged":  "F",
	"\\Deleted":  "T",
	"\\Draft":    "D",
}

// maildirInfo renders the ":2," suffix for a set of IMAP flags. The letters must
// be in ASCII order, which is what the specification requires.
func maildirInfo(flags []string) string {
	var letters []string
	seen := make(map[string]bool, len(flags))
	for _, flag := range flags {
		letter, known := maildirFlags[flag]
		if !known || seen[letter] {
			continue
		}
		seen[letter] = true
		letters = append(letters, letter)
	}
	sort.Strings(letters)
	return ":2," + strings.Join(letters, "")
}

// maildirSubdir returns the directory a remote folder maps onto, relative to the
// Maildir root.
//
// Dovecot's Maildir++ layout puts every folder beside the root as a dot-prefixed
// directory with the hierarchy flattened onto dots, and INBOX IS the root. A
// remote server may use any delimiter, so the one it reported is what gets
// translated.
func maildirSubdir(folder string, delimiter rune) string {
	if strings.EqualFold(folder, "INBOX") {
		return ""
	}
	folder = strings.TrimPrefix(folder, "INBOX"+string(delimiter))
	parts := strings.FieldsFunc(folder, func(r rune) bool { return r == delimiter })

	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		part = sanitizeFolderPart(part)
		if part != "" {
			clean = append(clean, part)
		}
	}
	if len(clean) == 0 {
		return ""
	}
	return "." + strings.Join(clean, ".")
}

// sanitizeFolderPart strips anything that would leave the Maildir or confuse it.
//
// The name comes from the remote server, so it is hostile input: a part
// containing a slash or a dot would create a directory somewhere else entirely,
// and the safeio layer would refuse the write rather than the panel noticing why.
func sanitizeFolderPart(part string) string {
	var out strings.Builder
	for _, r := range part {
		switch {
		case r == '/', r == '.':
			// Characters the server meant, which this layout gives its own
			// meaning to. They become a letter rather than disappearing, so two
			// folders that differ only there stay two folders.
			out.WriteRune('_')
		case r < 0x20 || r == 0x7f:
			// Control characters, NUL and line breaks included, are dropped:
			// they were never part of a name a person chose.
		default:
			out.WriteRune(r)
		}
	}
	// Only an empty result is dropped. A folder the server calls "." or ".."
	// becomes "_" or "__", which is a harmless directory name; refusing it would
	// silently lose every message that folder holds.
	name := strings.TrimSpace(out.String())
	if name == "" {
		return ""
	}
	if len(name) > 100 {
		name = name[:100]
	}
	return name
}

// maildirLayout describes where one mailbox's files live.
type maildirLayout struct {
	// home is the safeio jail root, /home/<system_user>.
	home string
	// root is the Maildir directory relative to home.
	root string
	// systemUser owns everything written, so Dovecot can read it back.
	systemUser string
}

// ensureFolder creates the three Maildir directories for a folder and returns
// the relative path of its cur/ directory.
func (layout maildirLayout) ensureFolder(subdir string) (string, error) {
	base := layout.root
	if subdir != "" {
		base = layout.root + "/" + subdir
	}
	for _, name := range []string{"cur", "new", "tmp"} {
		if err := mkdirAllBeneath(layout.home, base+"/"+name, layout.systemUser); err != nil {
			return "", fmt.Errorf("create %s: %w", name, err)
		}
	}
	return base + "/cur", nil
}

// writeMessage stores one message under cur/ with its flags in the name.
//
// unique identifies the message within whatever produced it. A copy names it
// after the job and the message's own UID, so a run repeated after a failure
// overwrites its earlier attempt instead of delivering everything a second time.
func (layout maildirLayout) writeMessage(curDir, unique string, flags []string, body io.Reader) (int64, error) {
	name := fmt.Sprintf("%d.%s%s", stableStamp, unique, maildirInfo(flags))
	return streamIntoBeneath(layout.home, curDir+"/"+name, body, layout.systemUser)
}

// stableStamp is the leading field of every generated Maildir name. Only the
// unique part after it distinguishes messages here, so a fixed value keeps the
// name reproducible for a re-run; Dovecot reads the date from the message.
const stableStamp = 1000000000

// messageNamePrefix is what every name writeMessage produces for a given token
// begins with.
//
// It exists so the naming rule lives in ONE place: a caller that removes what it
// wrote matches on this rather than rebuilding the format itself, and a message
// that was already in the folder cannot begin with another writer's token.
func messageNamePrefix(token string) string {
	return fmt.Sprintf("%d.%s-", stableStamp, token)
}
