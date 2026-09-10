package files

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// resetNameCaches empties both caches and restores the clock seam, so one test
// cannot see what another cached.
func resetNameCaches(t *testing.T) {
	t.Helper()
	previousNow := nameCacheNow
	nameCacheMu.Lock()
	clear(ownerNames)
	clear(groupNames)
	nameCacheMu.Unlock()
	t.Cleanup(func() {
		nameCacheNow = previousNow
		nameCacheMu.Lock()
		clear(ownerNames)
		clear(groupNames)
		nameCacheMu.Unlock()
	})
}

// A listing calls this twice per entry, and the release binary is CGO_ENABLED=0,
// where each call scans /etc/passwd or /etc/group line by line. Without the
// cache, a directory of N entries cost N lookups per id.
func TestOwnerLookupRunsOncePerIDNotOncePerEntry(t *testing.T) {
	resetNameCaches(t)

	var lookups int
	name := cachedName(ownerNames, 1000, func(string) (string, bool) {
		lookups++
		return "c_tenant", true
	})
	if name != "c_tenant" {
		t.Fatalf("cachedName() = %q, want %q", name, "c_tenant")
	}

	for range 500 {
		if got := cachedName(ownerNames, 1000, func(string) (string, bool) {
			lookups++
			return "c_tenant", true
		}); got != "c_tenant" {
			t.Fatalf("cachedName() = %q, want %q", got, "c_tenant")
		}
	}

	if lookups != 1 {
		t.Fatalf("cachedName() performed %d lookups for one id, want 1", lookups)
	}
}

// An id with no account resolves no faster the second time, so the miss is
// cached too and reported as the number.
func TestAnIDWithNoAccountIsCachedAsItsNumber(t *testing.T) {
	resetNameCaches(t)

	var lookups int
	miss := func(string) (string, bool) {
		lookups++
		return "", false
	}

	for range 10 {
		if got := cachedName(groupNames, 4242, miss); got != "4242" {
			t.Fatalf("cachedName() = %q, want the raw id %q", got, "4242")
		}
	}
	if lookups != 1 {
		t.Fatalf("cachedName() performed %d lookups for one missing id, want 1", lookups)
	}
}

// A uid can be reused after a tenant is removed, so a cached name must not
// outlive the TTL.
func TestACachedNameExpiresAfterTheTTL(t *testing.T) {
	resetNameCaches(t)

	now := time.Unix(1_700_000_000, 0)
	nameCacheNow = func() time.Time { return now }

	first := cachedName(ownerNames, 1001, func(string) (string, bool) { return "c_before", true })
	if first != "c_before" {
		t.Fatalf("cachedName() = %q, want %q", first, "c_before")
	}

	now = now.Add(nameCacheTTL - time.Second)
	if got := cachedName(ownerNames, 1001, func(string) (string, bool) { return "c_after", true }); got != "c_before" {
		t.Fatalf("inside the TTL cachedName() = %q, want the cached %q", got, "c_before")
	}

	now = now.Add(2 * time.Second)
	if got := cachedName(ownerNames, 1001, func(string) (string, bool) { return "c_after", true }); got != "c_after" {
		t.Fatalf("past the TTL cachedName() = %q, want the fresh %q", got, "c_after")
	}
}

// The cache is read from every listing request, so concurrent readers must not
// race. Run with -race.
func TestCachedNameIsSafeForConcurrentUse(t *testing.T) {
	resetNameCaches(t)

	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			id := uint32(2000 + i%4)
			for range 50 {
				cachedName(ownerNames, id, func(text string) (string, bool) { return "c_" + text, true })
			}
		})
	}
	wg.Wait()
}

// A tenant home is bounded by an inode quota, not by an entries-per-directory
// rule, so one directory can hold hundreds of thousands of names. Rendering all
// of them put the whole array on the panel's heap, which is the root process
// every customer shares.
func TestAHugeDirectoryIsCappedAndReportsItsRealSize(t *testing.T) {
	dir := make([]dirEntry, 0, maxListEntries+100)
	for i := range maxListEntries + 100 {
		dir = append(dir, dirEntry{Name: fmt.Sprintf("file-%06d", i)})
	}

	kept, total, truncated := orderAndCapEntries(dir)

	if len(kept) != maxListEntries {
		t.Fatalf("orderAndCapEntries() kept %d entries, want the cap %d", len(kept), maxListEntries)
	}
	if total != maxListEntries+100 {
		t.Fatalf("orderAndCapEntries() total = %d, want the directory's real size %d", total, maxListEntries+100)
	}
	if !truncated {
		t.Fatal("orderAndCapEntries() did not report the cut, so the page would read as the whole directory")
	}
}

func TestADirectoryUnderTheCapIsNotReportedAsTruncated(t *testing.T) {
	dir := []dirEntry{{Name: "b.txt"}, {Name: "a.txt"}}

	kept, total, truncated := orderAndCapEntries(dir)

	if len(kept) != 2 || total != 2 {
		t.Fatalf("orderAndCapEntries() kept %d of %d, want 2 of 2", len(kept), total)
	}
	if truncated {
		t.Fatal("orderAndCapEntries() reported a cut for a directory that fits")
	}
}

// The cap keeps a prefix, so the order must be decided before the cut or the
// kept page would be whatever order the filesystem happened to return.
func TestTheCapKeepsTheFirstPageOfTheRenderedOrder(t *testing.T) {
	dir := []dirEntry{
		{Name: "zebra.txt"},
		{Name: "Alpha"},
		{Name: "middle.txt"},
		{Name: "beta", Mode: os.ModeDir},
	}

	kept, _, _ := orderAndCapEntries(dir)

	// "beta" is the only folder, so it leads; the files follow in
	// case-insensitive name order, which puts "Alpha" ahead of "middle.txt".
	want := []string{"beta", "Alpha", "middle.txt", "zebra.txt"}
	if len(kept) != len(want) {
		t.Fatalf("orderAndCapEntries() returned %d entries, want %d", len(kept), len(want))
	}
	for i, name := range want {
		if kept[i].Name != name {
			t.Fatalf("orderAndCapEntries()[%d] = %q, want %q", i, kept[i].Name, name)
		}
	}
}

// Folders sort ahead of files whatever their names are, because that is the
// order the file manager renders and the cap keeps a prefix of it.
func TestFoldersSortAheadOfFilesBeforeTheCap(t *testing.T) {
	dir := []dirEntry{
		{Name: "aaa.txt"},
		{Name: "zzz", Mode: os.ModeDir},
	}

	kept, _, _ := orderAndCapEntries(dir)

	if kept[0].Name != "zzz" {
		t.Fatalf("orderAndCapEntries()[0] = %q, want the folder %q first", kept[0].Name, "zzz")
	}
}
