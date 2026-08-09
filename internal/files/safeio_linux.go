//go:build linux

package files

// safeio — TOCTOU symlink-race-resistant file mutations using openat2(RESOLVE_BENEATH).
//
// PROBLEM: resolving a path STRING (EvalSymlinks and friends) and returning it.
// Mutations (os.Chmod/os.WriteFile/os.Rename/os.RemoveAll/os.Create) later operate
// on that string as root. A tenant can swap an intermediate directory with a symlink
// between the check and the operation, tricking root into mutating a file OUTSIDE the
// jail (LPE / local privilege escalation).
//
// SOLUTION: openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS) provides an atomic fd
// relative to home, following NO symlinks, unable to escape home. All operations
// happen through the fd/*at syscalls. "Resolve + operate" is a single kernel step;
// intermediate symlink swapping becomes impossible.
// AlmaLinux 10 / kernel 6.12 supports openat2.

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type usrInfo struct{ UID, GID int }

func userLookup(name string) (usrInfo, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return usrInfo{}, err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return usrInfo{UID: uid, GID: gid}, nil
}

const dirOpenFlags = unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK

// openHomeFd opens the home directory O_DIRECTORY. home (/home/c_<slug>) is created
// by root; /home is owned by root → the tenant cannot swap the home DIRECTORY ENTRY
// with a symlink, so opening home directly is safe. Sub-components are protected by openat2.
func openHomeFd(home string) (int, error) {
	return unix.Open(home, unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
}

// openAt2Beneath opens rel beneath home atomically, following NO symlinks, unable to
// escape home. Returns an *os.File (caller must Close).
func openAt2Beneath(home, rel string, flags int, mode uint32) (*os.File, error) {
	hf, err := openHomeFd(home)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(hf) }() // dir fd release: Close error not actionable
	p := relClean(rel)
	if p == "" {
		p = "."
	}
	how := &unix.OpenHow{
		Flags:   uint64(flags) | unix.O_CLOEXEC,
		Mode:    uint64(mode),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS,
	}
	fd, err := unix.Openat2(hf, p, how)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), filepath.Join(home, p)), nil
}

// statBeneath returns FileInfo for rel under home via a symlink-safe fd (openat2
// rejects any symlink component), so a tenant cannot race a symlink swap between a
// path check and the stat performed as root.
//
// O_PATH because a caller asks what a path IS, and the answer has to come back
// for every file type. O_RDONLY cannot open a unix socket at all (ENXIO), and a
// tenant can put one in its own home, so opening for reading turned "this is a
// socket" into a failure the caller could not tell apart from a server fault.
// Nothing is read through this descriptor; fstat is a defined operation on one.
//
// The flags stop there. openat2 rejects an invalid combination with EINVAL where
// openat would have ignored the extra bit, and O_PATH admits only O_CLOEXEC,
// O_DIRECTORY and O_NOFOLLOW beside it, so adding O_NONBLOCK or an access mode
// here breaks EVERY call rather than the one case it was meant for.
func statBeneath(home, rel string) (os.FileInfo, error) {
	f, err := openAt2Beneath(home, rel, unix.O_PATH, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only stat probe; Close error not actionable
	return f.Stat()
}

// readDirBeneath lists rel under home through a symlink-safe directory fd, and
// stats every entry through THAT fd.
//
// The metadata cannot be left to os.DirEntry.Info(): it lstats parent + "/" +
// name as a path, so a tenant who swaps a component for a symlink between the
// listing and the call has root read metadata from outside the jail. fstatat on
// the pinned fd has no path to race, and AT_SYMLINK_NOFOLLOW reports the link
// itself rather than its target.
func readDirBeneath(home, rel string) ([]dirEntry, error) {
	f, err := openAt2Beneath(home, rel, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only dir listing; Close error not actionable
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	out := make([]dirEntry, 0, len(names))
	for _, name := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(int(f.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			continue // removed between the listing and the stat
		}
		out = append(out, dirEntry{
			Name:    name,
			Mode:    modeFromStat(&st),
			Size:    st.Size,
			UID:     st.Uid,
			GID:     st.Gid,
			ModTime: time.Unix(st.Mtim.Unix()),
		})
	}
	return out, nil
}

// modeFromStat converts a raw st_mode into the os.FileMode the listing reports.
func modeFromStat(st *unix.Stat_t) os.FileMode {
	mode := os.FileMode(st.Mode & 0o777)
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		mode |= os.ModeDir
	case unix.S_IFLNK:
		mode |= os.ModeSymlink
	case unix.S_IFIFO:
		mode |= os.ModeNamedPipe
	case unix.S_IFSOCK:
		mode |= os.ModeSocket
	case unix.S_IFBLK:
		mode |= os.ModeDevice
	case unix.S_IFCHR:
		mode |= os.ModeDevice | os.ModeCharDevice
	}
	if st.Mode&unix.S_ISUID != 0 {
		mode |= os.ModeSetuid
	}
	if st.Mode&unix.S_ISGID != 0 {
		mode |= os.ModeSetgid
	}
	if st.Mode&unix.S_ISVTX != 0 {
		mode |= os.ModeSticky
	}
	return mode
}

// readFileBeneath reads at most maxBytes of rel under home through a symlink-safe fd.
// It returns the file's FileInfo so callers can enforce size limits without a second,
// race-prone stat. A non-regular file is rejected.
func readFileBeneath(home, rel string, maxBytes int64) ([]byte, os.FileInfo, error) {
	f, err := openAt2Beneath(home, rel, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }() // read fd release: Close error not actionable
	st, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, st, errNotRegular
	}
	if maxBytes > 0 && st.Size() > maxBytes {
		return nil, st, errTooLarge
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, st, err
	}
	return data, st, nil
}

// openReadBeneath opens rel under home read-only through a symlink-safe fd for
// streaming (download). The caller must Close the returned file.
func openReadBeneath(home, rel string) (*os.File, error) {
	return openAt2Beneath(home, rel, unix.O_RDONLY|unix.O_NONBLOCK, 0)
}

// realPathBeneath returns the kernel's own absolute path for rel under home,
// proven free of symlink components because openat2 resolved it with
// RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS.
//
// It exists for the external tools (zip, tar) that must be given a REAL path:
// they write the given name into the archive, so a /proc/self/fd path would put
// the panel's file-descriptor numbers in the entry names. The tool still runs
// under the tenant uid, so the path is not a privilege boundary on its own; this
// only keeps the panel from handing the tool a path outside the jail.
//
// O_PATH is used because the target may be a directory or a file and nothing is
// read through this descriptor.
func realPathBeneath(home, rel string) (string, error) {
	f, err := openAt2Beneath(home, rel, unix.O_PATH, 0)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }() // reference-only fd; Close error not actionable
	resolved, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
	if err != nil {
		return "", err
	}
	if !withinHome(home, resolved) {
		return "", errEscape
	}
	return resolved, nil
}

// isDirBeneath reports whether rel is a DIRECTORY under home (symlink-safe; errors on
// intermediate symlinks).
func isDirBeneath(home, rel string) (bool, error) {
	f, err := openAt2Beneath(home, rel, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }() // read-only stat probe; Close error not actionable
	st, err := f.Stat()
	if err != nil {
		return false, err
	}
	return st.IsDir(), nil
}

// safeParentFd opens the PARENT directory of rel under home symlink-free (raw fd)
// and returns the single-component leaf name. Caller must unix.Close(parentFd).
// Pinning the parent fd means intermediate components can no longer be swapped.
func safeParentFd(home, rel string) (parentFd int, leaf string, err error) {
	p := relClean(rel)
	parent := filepath.Dir(p) // "a/b" → "a", "f" → "."
	leaf = filepath.Base(p)
	f, err := openAt2Beneath(home, parent, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return -1, "", err
	}
	fd, err := unix.Dup(int(f.Fd()))
	_ = f.Close() // dup taken above; releasing original fd, Close error not actionable
	if err != nil {
		return -1, "", err
	}
	return fd, leaf, nil
}

// tenantIDs returns the uid/gid of system user sk (c_<slug>).
func tenantIDs(sk string) (uid, gid int, ok bool) {
	uu, err := userLookup(sk)
	if err != nil {
		return 0, 0, false
	}
	return uu.UID, uu.GID, true
}

// withinHome reports whether p resides beneath the (symlink-resolved) home directory.
// A final safety belt for residual path-based operations like restorecon-by-path.
func withinHome(home, p string) bool {
	hr, err := filepath.EvalSymlinks(home)
	if err != nil {
		hr = home
	}
	pr, err := filepath.EvalSymlinks(p)
	if err != nil {
		pr = p
	}
	return pr == hr || strings.HasPrefix(pr, hr+string(filepath.Separator))
}

// restoreconFd takes the PINNED real path of fd (/proc/self/fd/N — kernel-resolved,
// immune to attacker symlinks) and runs restorecon if it is still under home.
// On Enforcing SELinux servers, files created by root receive the wrong context
// and nginx/PHP-FPM cannot read them without this step. The within-home check
// confines the relabel to the jail.
func restoreconFd(home string, f *os.File) {
	real, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
	if err != nil || !withinHome(home, real) {
		return
	}
	_, _ = exec.Command("restorecon", real).CombinedOutput()
}

// fchownRestoreFd chowns the fd to the tenant (symlink-safe: Fchown on the pinned
// inode) and corrects the SELinux context. The old path-based chown(abs, sk) used
// os.Chown which FOLLOWS symlinks — a risk of handing /etc/shadow to a tenant (LPE);
// Fchown works on the pinned inode instead.
func fchownRestoreFd(home string, f *os.File, sk string) {
	if uid, gid, ok := tenantIDs(sk); ok {
		_ = unix.Fchown(int(f.Fd()), uid, gid)
	}
	restoreconFd(home, f)
}

// ---- High-level symlink-safe mutations ----

// chmodBeneath is a symlink-safe chmod. The leaf is opened via openat2 (symlinks are
// REJECTED); Fchmod is applied. Intermediate swaps are blocked by the kernel.
func chmodBeneath(home, rel string, mode uint32) error {
	f, err := openAt2Beneath(home, rel, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // Fchmod result is the outcome; fd release Close not actionable
	return unix.Fchmod(int(f.Fd()), mode)
}

// resetTreeBeneath resets ownership and permissions across the subtree rooted at
// rel (relative to home): directories get dirMode, regular files get fileMode,
// and every non-symlink inode is chowned to the tenant (uid/gid of sk). It opens
// the root through openAt2Beneath (RESOLVE_BENEATH/NO_SYMLINKS) and then walks
// fd-by-fd with O_NOFOLLOW, so a symlink can never redirect the walk outside
// home; symlinks themselves are skipped (Linux fchmodat follows the link and has
// no AT_SYMLINK_NOFOLLOW for chmod, so a jail-escaping link like
// public_html/x -> /etc/passwd is never touched).
func resetTreeBeneath(home, rel, sk string, dirMode, fileMode uint32) error {
	uid, gid, ok := tenantIDs(sk)
	if !ok {
		return errBadUser
	}
	parentFd, leaf, err := safeParentFd(home, rel)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parentFd) }() // read-only dir fd release; close error is not actionable
	var st unix.Stat_t
	if err := unix.Fstatat(parentFd, leaf, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if (st.Mode & unix.S_IFMT) == unix.S_IFLNK {
		return errEscape // the root itself is a symlink — refuse
	}
	resetEntry(parentFd, leaf, uid, gid, dirMode, fileMode)
	return nil
}

// resetEntry chmods+chowns one entry named `name` under dirfd, recursing into a
// directory by opening it with O_NOFOLLOW (a symlink leaf therefore fails to
// open as a directory and is skipped). It never follows a symlink.
func resetEntry(dirfd int, name string, uid, gid int, dirMode, fileMode uint32) {
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFLNK:
		return // never chmod/chown a symlink
	case unix.S_IFDIR:
		_ = unix.Fchownat(dirfd, name, uid, gid, unix.AT_SYMLINK_NOFOLLOW)
		_ = unix.Fchmodat(dirfd, name, dirMode, 0)
		fd, err := unix.Openat(dirfd, name, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return // could not open as a real directory (raced/replaced) — skip, never escape
		}
		defer func() { _ = unix.Close(fd) }() // read-only dir fd release; close error is not actionable
		names, err := readdirnamesFd(fd)
		if err != nil {
			return
		}
		for _, child := range names {
			if child == "." || child == ".." {
				continue
			}
			resetEntry(fd, child, uid, gid, dirMode, fileMode)
		}
	case unix.S_IFREG:
		_ = unix.Fchownat(dirfd, name, uid, gid, unix.AT_SYMLINK_NOFOLLOW)
		_ = unix.Fchmodat(dirfd, name, fileMode, 0)
	}
}

// writeBeneath is a symlink-safe file write (create/truncate). An existing file's
// permissions are preserved (open won't touch mode outside create); a new file gets
// createMode. The fd is then chowned to the tenant + restorecon'd.
func writeBeneath(home, rel string, data []byte, createMode uint32, sk string) (err error) {
	f, err := openAt2Beneath(home, rel, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC, createMode)
	if err != nil {
		return err
	}
	// Write path: a Close error signals a failed flush (e.g. ENOSPC) — surface it
	// instead of reporting a successful write for data that never reached disk.
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	if _, werr := f.Write(data); werr != nil {
		return werr
	}
	fchownRestoreFd(home, f, sk)
	return nil
}

// createExclBeneath is a symlink-safe new-empty-file (O_EXCL). Returns unix.EEXIST
// if the file already exists.
func createExclBeneath(home, rel, sk string) error {
	f, err := openAt2Beneath(home, rel, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0644)
	if err != nil {
		return err
	}
	fchownRestoreFd(home, f, sk)
	return f.Close()
}

// copyStreamBeneath is a symlink-safe streaming write (upload). Copies from src to fd.
func copyStreamBeneath(home, rel string, src io.Reader, sk string) (n int64, err error) {
	f, err := openAt2Beneath(home, rel, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC, 0644)
	if err != nil {
		return 0, err
	}
	// Write path: a Close error signals a failed flush (e.g. ENOSPC) — surface it
	// instead of reporting a successful upload for data that never reached disk.
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	n, err = io.Copy(f, src)
	if err != nil {
		return n, err
	}
	fchownRestoreFd(home, f, sk)
	return n, nil
}

// streamIntoExclBeneath creates a NEW file and streams src into that same
// descriptor. Returns unix.EEXIST if the file already exists.
//
// Creating the file and then reopening it to write leaves a window between two
// syscalls. RESOLVE_NO_SYMLINKS refuses a symlink planted there, but a HARD link
// is not a symlink: the reopen would follow it and its O_TRUNC would empty
// whatever it points at. Doing both through one descriptor removes the window,
// and O_EXCL still means an existing file is refused rather than overwritten,
// which is what stops an import from replacing mail that is already there.
func streamIntoExclBeneath(home, rel string, src io.Reader, sk string) (n int64, err error) {
	f, err := openAt2Beneath(home, rel, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0644)
	if err != nil {
		return 0, err
	}
	// Write path: a Close error signals a failed flush (e.g. ENOSPC) — surface it
	// instead of reporting a successful write for data that never reached disk.
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	n, err = io.Copy(f, src)
	if err != nil {
		return n, err
	}
	fchownRestoreFd(home, f, sk)
	return n, nil
}

// mkdirAllBeneath is a symlink-safe `mkdir -p`. Each component is created via
// Mkdirat + O_NOFOLLOW openat; any symlink component is REJECTED by O_NOFOLLOW.
// Newly created directories are chowned to the tenant when sk != "".
func mkdirAllBeneath(home, rel, sk string) error {
	p := relClean(rel)
	hf, err := openHomeFd(home)
	if err != nil {
		return err
	}
	if p == "" || p == "." {
		_ = unix.Close(hf) // dir fd release: Close error not actionable
		return nil
	}
	dirfd := hf
	uid, gid, haveIDs := tenantIDs(sk)
	for part := range strings.SplitSeq(p, "/") {
		if part == "" || part == "." {
			continue
		}
		created := false
		if err := unix.Mkdirat(dirfd, part, 0755); err == nil {
			created = true
		} else if err != unix.EEXIST {
			_ = unix.Close(dirfd) // dir fd release: Close error not actionable
			return err
		}
		nfd, err := unix.Openat(dirfd, part, dirOpenFlags, 0)
		_ = unix.Close(dirfd) // walk to child: parent dir fd release, not actionable
		if err != nil {
			return err
		}
		dirfd = nfd
		if created && haveIDs {
			_ = unix.Fchown(dirfd, uid, gid)
		}
	}
	_ = unix.Close(dirfd) // dir fd release: Close error not actionable
	return nil
}

// renameBeneath is a symlink-safe rename/move. Source and destination PARENTs are
// pinned via openat2; Renameat performs the move (rename does NOT follow the final
// component symlink — it moves the entry).
func renameBeneath(home, oldRel, newRel, sk string) error {
	if err := mkdirAllBeneath(home, filepath.Dir(relClean(newRel)), sk); err != nil {
		return err
	}
	of, oleaf, err := safeParentFd(home, oldRel)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(of) }() // pinned parent dir fd release: Close error not actionable
	nf, nleaf, err := safeParentFd(home, newRel)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(nf) }() // pinned parent dir fd release: Close error not actionable
	return unix.Renameat(of, oleaf, nf, nleaf)
}

// removeAllBeneath is a symlink-safe `rm -rf`. The parent is pinned, and the leaf is
// removed (unlink for files/symlinks; fd-recursive unlinkat for directories). Symlinks
// are never followed at any step.
func removeAllBeneath(home, rel string) error {
	pfd, leaf, err := safeParentFd(home, rel)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(pfd) }() // pinned parent dir fd release: Close error not actionable
	return removeAt(pfd, leaf)
}

// removeAt recursively deletes name relative to dirfd (all operations relative to
// pinned fds, O_NOFOLLOW → symlinks never followed, jail escape impossible).
func removeAt(dirfd int, name string) error {
	if err := unix.Unlinkat(dirfd, name, 0); err == nil {
		return nil
	} else if err == unix.ENOENT {
		return nil
	} else if err != unix.EISDIR && err != unix.EPERM && err != unix.ENOTEMPTY {
		return err
	}
	cfd, err := unix.Openat(dirfd, name, dirOpenFlags, 0)
	if err != nil {
		return err
	}
	names, rerr := readdirnamesFd(cfd)
	if rerr != nil {
		_ = unix.Close(cfd) // dir fd release: Close error not actionable
		return rerr
	}
	for _, n := range names {
		if n == "." || n == ".." {
			continue
		}
		if e := removeAt(cfd, n); e != nil {
			_ = unix.Close(cfd) // dir fd release: Close error not actionable
			return e
		}
	}
	_ = unix.Close(cfd) // dir fd release: Close error not actionable
	return unix.Unlinkat(dirfd, name, unix.AT_REMOVEDIR)
}

// readdirnamesFd lists a raw dir fd by duplicating it and reading via os.File.
// The original fd remains owned by the caller.
func readdirnamesFd(dirfd int) ([]string, error) {
	dup, err := unix.Dup(dirfd)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dup), "dir")
	names, err := f.Readdirnames(-1)
	_ = f.Close() // read-only dir listing dup; Close error not actionable
	return names, err
}

// copyTreeBeneath is a symlink-safe recursive copy. Source and destination PARENTs
// are pinned; files are opened O_NOFOLLOW (jail-external symlink CONTENT is never
// read → no information leak), symlinks are recreated as-is (readlink+symlinkat),
// directories are recursed.
func copyTreeBeneath(home, srcRel, dstRel, sk string) error {
	if err := mkdirAllBeneath(home, filepath.Dir(relClean(dstRel)), sk); err != nil {
		return err
	}
	sfd, sleaf, err := safeParentFd(home, srcRel)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(sfd) }() // pinned parent dir fd release: Close error not actionable
	dfd, dleaf, err := safeParentFd(home, dstRel)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dfd) }() // pinned parent dir fd release: Close error not actionable
	uid, gid, haveIDs := tenantIDs(sk)
	return copyEntryAt(sfd, sleaf, dfd, dleaf, uid, gid, haveIDs)
}

func copyEntryAt(sdir int, sname string, ddir int, dname string, uid, gid int, haveIDs bool) error {
	var st unix.Stat_t
	if err := unix.Fstatat(sdir, sname, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		if err := unix.Mkdirat(ddir, dname, st.Mode&0o777); err != nil && err != unix.EEXIST {
			return err
		}
		ncd, err := unix.Openat(ddir, dname, dirOpenFlags, 0)
		if err != nil {
			return err
		}
		defer func() { _ = unix.Close(ncd) }() // dest dir fd release: Close error not actionable
		if haveIDs {
			_ = unix.Fchown(ncd, uid, gid)
		}
		nsd, err := unix.Openat(sdir, sname, dirOpenFlags, 0)
		if err != nil {
			return err
		}
		defer func() { _ = unix.Close(nsd) }() // src dir fd release: Close error not actionable
		names, rerr := readdirnamesFd(nsd)
		if rerr != nil {
			return rerr
		}
		for _, n := range names {
			if n == "." || n == ".." {
				continue
			}
			if e := copyEntryAt(nsd, n, ncd, n, uid, gid, haveIDs); e != nil {
				return e
			}
		}
		return nil
	case unix.S_IFLNK:
		target, err := readlinkAt(sdir, sname)
		if err != nil {
			return err
		}
		_ = unix.Unlinkat(ddir, dname, 0)
		return unix.Symlinkat(target, ddir, dname)
	case unix.S_IFREG:
		return copyRegAt(sdir, sname, ddir, dname, st.Mode&0o777, uid, gid, haveIDs)
	default:
		return nil // skip special files
	}
}

func readlinkAt(dirfd int, name string) (string, error) {
	buf := make([]byte, 4096)
	n, err := unix.Readlinkat(dirfd, name, buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func copyRegAt(sdir int, sname string, ddir int, dname string, perm uint32, uid, gid int, haveIDs bool) (err error) {
	sf, err := unix.Openat(sdir, sname, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	in := os.NewFile(uintptr(sf), sname)
	// Read fd: releasing it cannot lose data, so a Close error is not actionable.
	defer func() { _ = in.Close() }()
	df, err := unix.Openat(ddir, dname, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_NOFOLLOW|unix.O_CLOEXEC, perm)
	if err != nil {
		return err
	}
	out := os.NewFile(uintptr(df), dname)
	// Write path: a Close error signals a failed flush (e.g. ENOSPC) — surface it
	// instead of reporting a successful copy for data that never reached disk.
	defer func() {
		if cerr := out.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	if _, cerr := io.Copy(out, in); cerr != nil {
		return cerr
	}
	if haveIDs {
		_ = unix.Fchown(df, uid, gid)
	}
	return nil
}

// ImportBeneath copies srcAbs, a server-controlled staging path OUTSIDE the tenant
// home (an extracted backup archive, a migration payload), to rel beneath home.
//
// The staging tree carries tenant-authored content, so its own symlinks are recreated
// rather than followed. The destination side is the dangerous one: the tenant owns the
// home and can plant a symlink at any component of rel, so root writing through a
// path string would land outside the jail. Every destination component is therefore
// pinned with openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS), and a leaf that is already
// a symlink is unlinked instead of written through.
func ImportBeneath(home, rel, srcAbs, systemUser string) error {
	cleanRel := relClean(rel)
	if cleanRel == "" || cleanRel == "." {
		return errSafeIOBadTarget
	}
	if err := mkdirAllBeneath(home, filepath.Dir(cleanRel), systemUser); err != nil {
		return err
	}
	srcDir, srcLeaf := filepath.Dir(srcAbs), filepath.Base(srcAbs)
	sfd, err := unix.Open(srcDir, dirOpenFlags, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(sfd) }() // staging dir fd release: Close error not actionable
	dfd, dleaf, err := safeParentFd(home, cleanRel)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dfd) }() // pinned parent dir fd release: Close error not actionable
	var dst unix.Stat_t
	if err := unix.Fstatat(dfd, dleaf, &dst, unix.AT_SYMLINK_NOFOLLOW); err == nil &&
		dst.Mode&unix.S_IFMT == unix.S_IFLNK {
		// The existing entry is a symlink. Remove the LINK (never its target) so the
		// copy below creates a real entry in the tenant's own directory.
		if err := unix.Unlinkat(dfd, dleaf, 0); err != nil {
			return err
		}
	}
	uid, gid, haveIDs := tenantIDs(systemUser)
	return copyEntryAt(sfd, srcLeaf, dfd, dleaf, uid, gid, haveIDs)
}

// RemoveAllBeneath deletes rel under home and everything below it. Every
// component is pinned with openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS) and the
// recursion is fd-relative, so a symlink is unlinked rather than followed and a
// tenant cannot redirect a root-run cleanup outside their home.
func RemoveAllBeneath(home, rel string) error {
	return removeAllBeneath(home, rel)
}

// IsDirBeneath reports whether rel under home resolves to a directory without
// crossing a symlink or leaving the home. Callers that only need to VERIFY a
// tenant-supplied target (rather than write to it) use this instead of os.Stat,
// which resolves by path and would happily confirm a directory outside the jail.
func IsDirBeneath(home, rel string) (bool, error) {
	return isDirBeneath(home, rel)
}

// ClearBeneath empties rel under home, leaving rel itself in place. It exists so
// a root-run "wipe the deploy target before cloning" step cannot be redirected:
// os.ReadDir plus os.RemoveAll resolve by path, so a tenant symlink at ANY
// component of rel makes root list and delete somewhere else entirely.
//
// Both halves stay inside the jail. The listing is read through an openat2 fd,
// and every removal re-pins its own path with RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS,
// so an entry swapped for a symlink between the two steps fails rather than
// escaping. A missing directory is not an error: there is nothing to clear.
func ClearBeneath(home, rel string) error {
	entries, err := readDirBeneath(home, rel)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if err := removeAllBeneath(home, filepath.Join(rel, entry.Name)); err != nil {
			return err
		}
	}
	return nil
}

// MkdirAllBeneath is the exported symlink-safe `mkdir -p` for callers outside this
// package. Every component is created and reopened with O_NOFOLLOW, so a tenant
// cannot swap one for a symlink and have root create directories elsewhere.
func MkdirAllBeneath(home, rel, systemUser string) error {
	return mkdirAllBeneath(home, rel, systemUser)
}

// RestoreconBeneath relabels rel and everything under it. The path handed to
// restorecon is the kernel-resolved /proc/self/fd path of an openat2 fd rather than
// the caller's string, so a tenant symlink cannot redirect a root relabel outside
// the home. Best effort: a host without SELinux simply has nothing to do.
func RestoreconBeneath(home, rel string) {
	f, err := openAt2Beneath(home, rel, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }() // relabel probe fd; Close error not actionable
	real, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
	if err != nil || !withinHome(home, real) {
		return
	}
	// #nosec G204 G702 -- fixed binary (restorecon) with separate args (no shell); real is a kernel-resolved path proven to be under the tenant home.
	_, _ = exec.Command("restorecon", "-R", real).CombinedOutput()
}

// ChmodBeneath sets the mode of rel beneath home. A leaf that is a symlink is
// refused rather than followed, so a tenant cannot aim a root-privileged chmod
// at a file outside their own tree.
func ChmodBeneath(home, rel string, mode uint32) error {
	return chmodBeneath(home, rel, mode)
}

// OpenBeneath opens rel beneath home for reading and hands the caller the
// descriptor, for content that must be STREAMED rather than held in memory.
//
// ReadFileBeneath answers the same question for a bounded file; this exists for
// the one that may be arbitrarily large, where reading it whole would let a
// tenant decide how much of the panel's memory to take. Every path component is
// pinned with openat2, so a tenant symlink at any level cannot redirect a
// root-privileged read at a file outside the home.
//
// The caller closes the descriptor and must assert IsRegular on it, because a
// named pipe or a device node under the home opens successfully.
func OpenBeneath(home, rel string) (*os.File, error) {
	return openReadBeneath(home, rel)
}

// ReadFileBeneath reads rel beneath home, refusing anything that is not a
// regular file and anything larger than maxBytes. Every path component is
// pinned with openat2, so a tenant symlink at any level cannot redirect a
// root-privileged read at a file outside the home.
func ReadFileBeneath(home, rel string, maxBytes int64) ([]byte, error) {
	data, _, err := readFileBeneath(home, rel, maxBytes)
	return data, err
}

// WriteFileBeneath replaces rel beneath home with data, owned by systemUser. A
// leaf that is already a symlink is unlinked rather than written through.
func WriteFileBeneath(home, rel string, data []byte, mode uint32, systemUser string) error {
	return writeBeneath(home, rel, data, mode, systemUser)
}

// StreamIntoBeneath writes src to a NEW file at rel beneath home, owned by
// systemUser, and reports how many bytes landed. It fails when rel already
// exists, so a caller staging an upload cannot be tricked into appending to
// something the tenant put there first.
func StreamIntoBeneath(home, rel string, src io.Reader, systemUser string) (int64, error) {
	return streamIntoExclBeneath(home, rel, src, systemUser)
}

// ListNamesBeneath returns the entry names directly under rel beneath home.
// A missing directory reports no names and no error, because callers use this
// to sweep an area that may not exist yet.
func ListNamesBeneath(home, rel string) ([]string, error) {
	entries, err := readDirBeneath(home, rel)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	return names, nil
}

// StatBeneath reports rel beneath home without following a symlink at any
// component.
func StatBeneath(home, rel string) (os.FileInfo, error) {
	return statBeneath(home, rel)
}
