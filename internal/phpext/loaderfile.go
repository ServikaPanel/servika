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
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
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

// loaderMachine is the ELF machine this server can actually load.
//
// The two published archives use IDENTICAL member names and differ only in the
// ELF machine (measured: both carry ioncube/ioncube_loader_lin_8.3.so), so the
// path cannot tell them apart and reading the header is the only thing that can.
func loaderMachine() (elf.Machine, bool) {
	switch runtime.GOARCH {
	case "amd64":
		return elf.EM_X86_64, true
	case "arm64":
		return elf.EM_AARCH64, true
	default:
		return 0, false
	}
}

// verifyLoaderELF requires the member to be a 64-bit ELF shared object built for
// this server's architecture, before it is copied into extension_dir and named
// in a zend_extension line.
//
// This is the second half of making the artefact prove what it is. The publisher
// gives no checksum and no signature, so nothing else establishes that the file
// about to be loaded into every PHP process on the server is even an object.
//
// It also catches the wrong architecture, which until now produced no error at
// all. Measured with a real aarch64 loader on an amd64 PHP 8.3: the interpreter
// prints "Failed loading ..." on stderr and CONTINUES, exit 0. So the install
// reported success, the endpoint answered 201, and every PHP invocation on that
// version wrote a load failure from then on into the tenant's own FPM error log.
//
// The file offset is restored, because the caller copies from this same
// descriptor.
func verifyLoaderELF(handle *os.File) error {
	want, ok := loaderMachine()
	if !ok {
		return fmt.Errorf("IonCube Loader is not supported on %s", runtime.GOARCH)
	}
	defer func() { _, _ = handle.Seek(0, io.SeekStart) }()

	// elf.NewFile reads through ReaderAt, so it does not disturb the offset
	// itself; the seek above covers a caller that read before calling.
	file, err := elf.NewFile(handle)
	if err != nil {
		return errors.New("the downloaded IonCube Loader is not an ELF object")
	}
	defer func() { _ = file.Close() }()

	if file.Class != elf.ELFCLASS64 {
		return errors.New("the downloaded IonCube Loader is not a 64-bit object")
	}
	if file.Type != elf.ET_DYN {
		return errors.New("the downloaded IonCube Loader is not a shared object")
	}
	if file.Machine != want {
		return fmt.Errorf("the downloaded IonCube Loader is built for %s, not for %s",
			file.Machine, want)
	}
	return nil
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
