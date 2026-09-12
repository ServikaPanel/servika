package provisioner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// requestDrivenNginxWriters are the files outside this package that write nginx
// configuration on a REQUEST path. Each has to take the shared lock, or the
// serialization renderAndReload gained holds for renders only while these still
// race them.
//
// A startup heal is deliberately absent: it runs before the server listens, so
// it races nothing.
var requestDrivenNginxWriters = []string{
	"../subdomain/subdomain.go",
	"../subdomain/ssl.go",
	"../passwordprotect/passwordprotect.go",
	"../panelsettings/vhost443.go",
	"../optimize/apply.go",
}

// `nginx -t` validates the WHOLE conf.d tree, so a writer that skips the lock
// both sees another sequence's half-written file and is seen by one. The reader
// then rolls back a change that was valid, or reverts one that was committed.
func TestEveryRequestDrivenNginxWriterTakesTheSharedLock(t *testing.T) {
	for _, path := range requestDrivenNginxWriters {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		body := string(source)
		// The validation argument pair rather than the call around it: a package
		// that runs nginx through a test seam of its own still validates the
		// whole conf.d tree and still has to hold the lock.
		if !strings.Contains(body, `"nginx", "-t"`) &&
			!strings.Contains(body, "ApplyVhostForDomain(") &&
			!strings.Contains(body, "applyVhost(") {
			t.Errorf("%s no longer writes nginx configuration; drop it from this list", filepath.Base(path))
			continue
		}
		if !strings.Contains(body, "provisioner.LockNginx()") {
			t.Errorf("%s writes nginx configuration without taking provisioner.LockNginx", filepath.Base(path))
		}
		// The names rather than the call form: a writer may hand the release to a
		// defer as a function value, which releases it just the same.
		if strings.Count(body, "provisioner.LockNginx") != strings.Count(body, "provisioner.UnlockNginx") {
			t.Errorf("%s takes the lock a different number of times than it releases it", filepath.Base(path))
		}
	}
}

// The lock exists to be shared. A caller that took a mutex of its own would pass
// every test about its own package and leave the guarantee missing.
func TestNoRequestDrivenWriterKeepsAPrivateNginxMutex(t *testing.T) {
	for _, path := range requestDrivenNginxWriters {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(source), "sync.Mutex") {
			t.Errorf("%s declares a mutex of its own beside the shared nginx lock", filepath.Base(path))
		}
	}
}
