package phpext

// Opening a member of a downloaded archive.
//
// The IonCube loader arrives as a tar.gz from a third party, and ioncube.com
// publishes neither a checksum nor a signature for it (measured: the .sha256
// and .asc paths both answer 302 to the homepage), while the archive itself
// moves, so a checksum compiled into this binary would freeze the loader at
// whatever release shipped with the panel. What is left is to make the artefact
// prove what it is.
//
// The member is opened O_NOFOLLOW and IsRegular() is asserted on the
// DESCRIPTOR, and the copy then reads from that same descriptor rather than
// reopening the path. Measured on AlmaLinux 10 with GNU tar 1.35: a member carrying
// the expected name as a SYMLINK is extracted verbatim, os.Stat follows it and
// succeeds, and the copy that used to follow read 410 bytes of /etc/shadow into
// extension_dir at mode 0644, where every c_* tenant on the server could read
// it. GNU tar refuses a member containing ".." and strips a leading "/", so a
// symlink member is the one thing extraction still creates freely, which is why
// internal/hostapps.VerifyBinary and internal/transfers.tailFile already open
// this way.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// errMemberMissing separates "the archive does not carry this PHP version" from
// "the archive carries something that is not a plain file". The first is an
// ordinary answer to the operator; the second says the download was not what it
// claimed to be.
var errMemberMissing = errors.New("archive member is absent")

// openArchiveMember opens one extracted member for reading and refuses anything
// that is not a plain file.
//
// O_NONBLOCK is there for the same reason as O_NOFOLLOW: a named pipe planted at
// the member's path would block the open itself, before any check could run.
func openArchiveMember(path string) (*os.File, error) {
	// #nosec G304 -- a fixed name under a temporary directory this handler made,
	// built from an identifier already checked against the version whitelist.
	handle, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errMemberMissing
		}
		// ELOOP lands here, which is what a symlink member produces.
		return nil, fmt.Errorf("the archive member could not be opened as a plain file: %w", err)
	}
	info, err := handle.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = handle.Close()
		return nil, errors.New("the archive member is not a plain file")
	}
	return handle, nil
}

// copyFromMember writes an already-opened, already-checked member to its
// destination. It reads the DESCRIPTOR rather than reopening the path, so
// nothing can be swapped in between the check and the copy.
func copyFromMember(source *os.File, destination string) error {
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return err
	}
	// #nosec G304 -- a fixed name under the interpreter's own extension_dir,
	// built from an identifier already checked against the version whitelist.
	out, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	if _, err := io.Copy(out, source); err != nil {
		return err
	}
	return out.Close()
}
