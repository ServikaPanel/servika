package provisioner

import (
	"os"
	"strings"
	"testing"
	"time"
)

// `nginx -t` validates the WHOLE conf.d tree and the http-context files a render
// writes are server-global, so two sequences at once break each other in both
// directions: one observes the other's half-written vhost and rolls back its own
// valid change, and one rollback reverts the other's committed country-block and
// rate-limit configuration.
func TestTheNginxLockSerializesTwoWriters(t *testing.T) {
	LockNginx()

	entered := make(chan struct{})
	go func() {
		LockNginx()
		close(entered)
		UnlockNginx()
	}()

	select {
	case <-entered:
		UnlockNginx()
		t.Fatal("a second nginx writer ran while the first held the lock")
	case <-time.After(100 * time.Millisecond):
	}
	UnlockNginx()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the second writer never acquired the lock after it was released")
	}
}

// The lock has to be taken BEFORE the vhost is written and held past the reload,
// because the rollback rests on the content captured at the start still being
// the correct previous content when the rollback runs.
func TestTheRenderTakesTheLockBeforeItWritesAnything(t *testing.T) {
	source, err := os.ReadFile("provisioner.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	start := strings.Index(body, "func renderAndReload(")
	if start < 0 {
		t.Fatal("renderAndReload was renamed; these assertions have to follow it")
	}
	end := strings.Index(body[start:], "\nfunc ")
	if end < 0 {
		end = len(body) - start
	}
	render := body[start : start+end]

	lock := strings.Index(render, "nginxMu.Lock()")
	write := strings.Index(render, "os.WriteFile(cfgPath")
	test := strings.Index(render, `systemCommand("nginx", "-t")`)
	if lock < 0 || write < 0 || test < 0 {
		t.Fatal("the lock, the vhost write or the validation is missing from renderAndReload")
	}
	if !strings.Contains(render, `systemCommand("systemctl", "reload", "nginx")`) {
		t.Fatal("the reload is missing from renderAndReload")
	}
	if lock > write {
		t.Error("the lock is taken after the vhost is written, so another writer can still see it half written")
	}
	if lock > test {
		t.Error("the lock is taken after the validation")
	}
	if !strings.Contains(render, "defer nginxMu.Unlock()") {
		t.Error("the lock is not held to the end of the sequence")
	}
}

// Both validators drop a probe file into the tree `nginx -t` reads, so each both
// sees a render in flight and is seen by one.
func TestBothValidatorsTakeTheLock(t *testing.T) {
	source, err := os.ReadFile("validate.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	for _, fn := range []string{"func ValidateNginxDirectives(", "func ValidateCustomVhost("} {
		start := strings.Index(body, fn)
		if start < 0 {
			t.Errorf("%s is missing from validate.go", fn)
			continue
		}
		end := strings.Index(body[start:], "\nfunc ")
		if end < 0 {
			end = len(body) - start
		}
		if !strings.Contains(body[start:start+end], "nginxMu.Lock()") {
			t.Errorf("%s writes a probe file into conf.d without taking the lock", fn)
		}
	}
}
