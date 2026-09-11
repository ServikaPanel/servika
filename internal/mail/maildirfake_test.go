package mail

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
)

// maildirFake stands in for the safe-write primitives, so the Maildir code can
// run its whole sequence in a test without openat2 or a tenant home. Every call is
// recorded, each primitive can be made to fail, and a stream is read to the end
// so its size is what the real writer reports.
type maildirFake struct {
	mu    sync.Mutex
	calls []string
	// written maps each streamed path to its body.
	written map[string]string
	// listed maps a directory to the names a listing answers.
	listed map[string][]string

	failMkdir, failChmod, failList, failRemove error
	// failStream, when set, is asked about each stream and returns its error.
	failStream func(rel string) error
}

func withMaildirFake(t *testing.T) *maildirFake {
	t.Helper()
	fake := &maildirFake{written: map[string]string{}, listed: map[string][]string{}}
	setForTest(t, &mkdirAllBeneath, func(home, rel, owner string) error {
		fake.record("mkdir %s %s %s", home, rel, owner)
		return fake.failMkdir
	})
	setForTest(t, &chmodBeneath, func(home, rel string, mode uint32) error {
		fake.record("chmod %s %s %o", home, rel, mode)
		return fake.failChmod
	})
	setForTest(t, &restoreconBeneath, func(home, rel string) {
		fake.record("restorecon %s %s", home, rel)
	})
	setForTest(t, &streamIntoBeneath, fake.stream)
	setForTest(t, &listNamesBeneath, fake.list)
	setForTest(t, &removeAllBeneath, func(home, rel string) error {
		fake.record("remove %s %s", home, rel)
		return fake.failRemove
	})
	return fake
}

func (f *maildirFake) stream(home, rel string, body io.Reader, owner string) (int64, error) {
	f.record("stream %s %s %s", home, rel, owner)
	if f.failStream != nil {
		if err := f.failStream(rel); err != nil {
			return 0, err
		}
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.written[rel] = string(data)
	return int64(len(data)), nil
}

// list answers from listed when the directory is named there, and otherwise
// with the names streamed directly into it.
func (f *maildirFake) list(home, rel string) ([]string, error) {
	f.record("list %s %s", home, rel)
	f.mu.Lock()
	defer f.mu.Unlock()
	if names, ok := f.listed[rel]; ok {
		return names, f.failList
	}
	var names []string
	for path := range f.written {
		if name, ok := strings.CutPrefix(path, rel+"/"); ok && !strings.Contains(name, "/") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, f.failList
}

func (f *maildirFake) record(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf(format, args...))
}

// recorded returns every call, in order.
func (f *maildirFake) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// streamedUnder returns the bodies written under a directory prefix, keyed by
// the name that follows it.
func (f *maildirFake) streamedUnder(prefix string) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]string{}
	for rel, body := range f.written {
		if name, ok := strings.CutPrefix(rel, prefix); ok {
			out[name] = body
		}
	}
	return out
}
