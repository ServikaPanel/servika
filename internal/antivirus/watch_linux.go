//go:build linux

package antivirus

// fanotify, and the three decisions it forces.
//
//  1. fanotify rather than inotify. inotify needs a watch PER DIRECTORY, and a
//     hosting server has hundreds of thousands of them: the marks alone exhaust
//     max_user_watches and cost megabytes of kernel memory. fanotify places one
//     mark and the kernel reports the whole filesystem.
//
//  2. FAN_CLOSE_WRITE rather than FAN_MODIFY. FAN_MODIFY fires on every write(),
//     so a 10 MB upload produces hundreds of events and the file is inspected
//     half-written every time. CLOSE_WRITE fires ONCE, when the writer is done,
//     which is also the only moment at which inspecting the content means
//     anything.
//
//  3. Notification rather than permission. FAN_OPEN_PERM would let the watcher
//     block a file until it has been inspected, closing a window of a few
//     milliseconds. It also means that a watcher which hangs, or dies holding
//     the queue, freezes every site on the server. An antivirus feature must not
//     be able to take the hosting down, so the window stays open.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// eventMetaSize is the size of the fanotify event header the kernel writes.
var eventMetaSize = uint32(unsafe.Sizeof(unix.FanotifyEventMetadata{}))

// readBuffer holds one read() worth of events. The kernel never splits an
// event across two reads, so a short buffer costs syscalls rather than events;
// 64 KiB is a few thousand of them, which is the size of the burst a server
// writing cache files produces.
const readBuffer = 64 * 1024

// pollTimeoutMS bounds how long a read waits, so the context is checked and the
// settings are refreshed even on a server where nothing is being written.
const pollTimeoutMS = 1000

func (w *watcher) run(ctx context.Context) error {
	roots := w.current().ScanRoots()

	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC,
		unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		return fmt.Errorf("fanotify_init: %w (CAP_SYS_ADMIN is required)", err)
	}
	defer func() { _ = unix.Close(fd) }()

	for _, root := range roots {
		// FAN_MARK_FILESYSTEM, never FAN_MARK_MOUNT, and the reason is the
		// unit rather than the kernel API.
		//
		// A mount mark is attached to the vfsmount the path resolves to. The
		// watcher unit carries ProtectSystem=strict, which gives the service
		// its own mount namespace built from read-only binds, so the mark
		// lands on the service's PRIVATE clone of the mount while every tenant
		// writes through the host's. Measured on 6.x with the shipped unit: the
		// mark is accepted, fanotify_mark returns success, and not one event is
		// ever delivered. Nothing reports it, so the screen shows a running
		// watcher that has been blind since the day the hardening was added.
		//
		// A filesystem mark is attached to the SUPERBLOCK, which both mounts
		// share, so a write through any of them is reported. Same measurement,
		// same unit, filesystem mark: the event arrives. PrivateMounts=yes
		// alone did NOT break the mount mark, so this is specific to the
		// read-only binds strict builds, which is exactly what the unit ships.
		//
		// It needs Linux 4.20. AlmaLinux 9 is on 5.14 and AlmaLinux 10 on 6.12,
		// so a failure here is reported rather than downgraded to a mount mark:
		// the downgrade is the silent blindness above.
		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM,
			unix.FAN_CLOSE_WRITE, unix.AT_FDCWD, root); err != nil {
			return fmt.Errorf("fanotify_mark %s: %w (FAN_MARK_FILESYSTEM needs Linux 4.20 or newer)", root, err)
		}
		// The mark covers the whole filesystem the root sits on, not the
		// subtree under it. Measured on a single-filesystem host: marking /home
		// reported writes under /var/tmp and /opt as well. AlmaLinux's default
		// layout is one / partition, so on most servers this really is a mark
		// on everything and the exclusion list is the only thing narrowing it.
		// Say so, rather than letting an operator read "watching /home" as a
		// statement about cost.
		mount := mountPointOf(root)
		if mount == root {
			log.Printf("antivirus watcher: watching %s", root)
		} else {
			log.Printf("antivirus watcher: watching %s, which marks the whole %s filesystem "+
				"because %s is not a separate one; the exclusion list is what narrows it",
				root, mount, root)
		}
	}

	refresh := time.NewTicker(settingsRefresh)
	defer refresh.Stop()

	buf := make([]byte, readBuffer)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-refresh.C:
			if err := w.refresh(ctx); err != nil {
				return err
			}
		default:
		}

		ready, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, pollTimeoutMS)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("poll: %w", err)
		}
		if ready == 0 {
			continue
		}
		n, err := unix.Read(fd, buf)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			return fmt.Errorf("read: %w", err)
		}
		if err := w.handleEvents(ctx, buf[:n]); err != nil {
			return err
		}
	}
}

// handleEvents parses one read() of the event stream.
//
// unsafe.Pointer is unavoidable: the kernel writes a C struct and decoding it
// with encoding/binary would have to guess the field padding. What is NOT
// optional is checking the version field first, because a struct laid out
// differently from the one this binary was compiled against turns every field
// read here into rubbish, and the file descriptor read out of it into an
// arbitrary number this code would then close.
func (w *watcher) handleEvents(ctx context.Context, b []byte) error {
	for len(b) >= int(eventMetaSize) {
		meta := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&b[0]))
		if meta.Vers != unix.FANOTIFY_METADATA_VERSION {
			// Fatal, not a skipped event. Every later field, the descriptor
			// included, is being read at an offset this build does not know, so
			// continuing means closing arbitrary descriptors of our own.
			return fmt.Errorf("the kernel reports fanotify metadata version %d, "+
				"this build understands %d", meta.Vers, unix.FANOTIFY_METADATA_VERSION)
		}
		if meta.Event_len < eventMetaSize || int(meta.Event_len) > len(b) {
			return nil
		}
		if meta.Fd >= 0 {
			w.handleEvent(ctx, int(meta.Fd))
		}
		b = b[meta.Event_len:]
	}
	return nil
}

// handleEvent inspects one event and ALWAYS closes its descriptor. A leaked
// descriptor here is not a slow leak: the kernel hands one out per event, and a
// server writing files steadily runs the watcher out of its file limit.
func (w *watcher) handleEvent(ctx context.Context, fd int) {
	file := os.NewFile(uintptr(fd), "fanotify-event")
	if file == nil {
		_ = unix.Close(fd)
		return
	}
	defer func() { _ = file.Close() }()

	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil || path == "" {
		return
	}
	// A file unlinked between the write and this read has "(deleted)" appended
	// by procfs. It is not a path, and there is nothing left to contain.
	if strings.HasSuffix(path, " (deleted)") {
		return
	}
	if !filepath.IsAbs(path) || !watchable(path) {
		return
	}
	w.inspect(ctx, path, func(limit int64) ([]byte, error) {
		return readEventFile(file, limit)
	})
}

// readEventFile reads the object the event refers to, through the descriptor
// the kernel supplied.
//
// The regular-file test is on the DESCRIPTOR rather than on a stat of the path,
// which is the same rule every other root-run read in this repository follows:
// a path can be replaced between the check and the open, a descriptor cannot.
func readEventFile(file *os.File, limit int64) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if info.Size() > limit {
		return nil, errors.New("larger than the read limit for its kind")
	}
	return io.ReadAll(io.LimitReader(file, limit))
}

// mountPointOf walks up from a path until the device number changes, which is
// the mount point the path sits on. It answers the path itself when it cannot
// tell, because the message this feeds is a warning and a wrong warning is
// worse than none.
func mountPointOf(path string) string {
	var start unix.Stat_t
	if err := unix.Lstat(path, &start); err != nil {
		return path
	}
	current := filepath.Clean(path)
	for {
		parent := filepath.Dir(current)
		if parent == current {
			return current
		}
		var up unix.Stat_t
		if err := unix.Lstat(parent, &up); err != nil {
			return current
		}
		if up.Dev != start.Dev {
			return current
		}
		current = parent
	}
}
