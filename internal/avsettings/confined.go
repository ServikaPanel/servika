package avsettings

// Whether the kernel is actually limiting the work, rather than where it sits.
//
// "Inside servika-av.slice" and "limited" are DIFFERENT claims, and telling them
// apart is the whole reason av_scans.confined exists: a slice file on disk
// confines nothing until something is launched into it, and the column records
// what the work observed rather than what the panel asked for.
//
// Measured on a server where no antivirus setting has ever been saved, so the
// slice file has never been written:
//
//	slice file         : absent
//	systemd-run --slice=servika-av.slice → the unit still starts
//	cgroup             : .../servika.slice/servika-av.slice/<unit>.service
//	cpu.max            : (absent)
//	memory.max         : max
//	CPUQuota/MemoryMax : infinity infinity infinity
//
// systemd creates the slice IMPLICITLY and it carries no limit at all. The
// cgroup path still contains the slice name, so a check on the path alone
// reports an unlimited scan as a confined one, on exactly the installation
// where the limits reach nothing. Reading the limits is what separates them.

import (
	"os"
	"path/filepath"
	"strings"
)

// cgroupRoot is where the unified hierarchy is mounted. A variable so a test
// can point it at a directory it built.
var cgroupRoot = "/sys/fs/cgroup"

// Confined reports whether a cgroup path is inside the antivirus slice AND that
// slice carries a real limit.
//
// The cgroup argument is what the work read from its OWN /proc/self/cgroup. The
// limits are read from the SLICE, which is that path's parent, because the
// limits are declared on the slice and a leaf unit inherits them without
// carrying its own copy.
func Confined(cgroup string) bool {
	if !strings.Contains(cgroup, "/"+SliceName+"/") {
		return false
	}
	return SliceHasLimit(sliceDirOf(cgroup))
}

// sliceDirOf trims the leaf unit from a cgroup path, leaving the slice.
//
// A leaf is always `<something>.service` or `<something>.scope`, so the parent
// is the slice whatever the path above it looks like inside a container.
func sliceDirOf(cgroup string) string {
	dir := filepath.Dir(strings.TrimRight(cgroup, "/"))
	if dir == "." || dir == "/" {
		return cgroup
	}
	return dir
}

// SliceHasLimit reports whether a cgroup directory carries any real limit.
//
// "Any" rather than "all": an operator may cap CPU and leave memory alone, and
// that is a limited scan. What this exists to catch is the slice with NOTHING
// on it, which is what systemd creates when the panel never wrote the file.
//
// An unreadable cgroup counts as UNLIMITED. The other direction reports a slice
// nobody could measure as limited, which is the reassurance this whole check
// exists to withhold.
func SliceHasLimit(dir string) bool {
	// cpu.max is "max <period>" when unset and "<quota> <period>" when set, so
	// the FIRST field is the answer. memory.max and pids.max are "max" or a
	// number outright.
	if first, ok := readCgroupField(dir, "cpu.max"); ok && first != "max" {
		return true
	}
	for _, name := range []string{"memory.max", "memory.high", "pids.max"} {
		if value, ok := readCgroupField(dir, name); ok && value != "max" {
			return true
		}
	}
	return false
}

// readCgroupField reads the first whitespace-separated field of a cgroup
// attribute, and reports whether it could be read at all.
//
// The directory comes from a /proc/self/cgroup line, which the kernel writes,
// so it is not tenant text. It is still confined to cgroupRoot rather than
// trusted: this function is reached from a worker that read that line in
// another process and handed it back through a file, and a value that travels
// through a file outlives the code that wrote it.
func readCgroupField(dir, name string) (string, bool) {
	root := filepath.Clean(cgroupRoot)
	full := filepath.Clean(filepath.Join(root, strings.TrimPrefix(dir, "/"), name))
	if full != root && !strings.HasPrefix(full, root+string(filepath.Separator)) {
		return "", false
	}
	b, err := os.ReadFile(full) // #nosec G304 -- confined to cgroupRoot on the line above; the path comes from the kernel's own /proc/self/cgroup.
	if err != nil {
		return "", false
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return "", false
	}
	return fields[0], true
}
