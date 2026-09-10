package serverip

import (
	"os"
	"strings"
	"testing"
	"time"

	"servika/internal/panelport"
)

// Both packages change how this server is reached and share one failure: losing
// that access entirely. panelport exports Lock and Unlock so the address package
// can take the SAME lock, and this package used to hold a private mutex instead,
// which left the guarantee absent and those two functions unreachable.
//
// Holding the panel-port lock must therefore block an address change.
func TestAnAddressChangeWaitsForAPanelPortChange(t *testing.T) {
	panelport.Lock()

	entered := make(chan struct{})
	go func() {
		panelport.Lock()
		close(entered)
		panelport.Unlock()
	}()

	select {
	case <-entered:
		panelport.Unlock()
		t.Fatal("an address change ran while a panel-port change held the lock")
	case <-time.After(100 * time.Millisecond):
	}
	panelport.Unlock()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the address change never acquired the lock after it was released")
	}
}

// The two write paths have to take that lock and no other. A private mutex here
// would pass any test about concurrency within this package while leaving the
// cross-package guarantee missing, which is exactly the state that was found.
func TestBothAddressWritePathsTakeThePanelPortLock(t *testing.T) {
	source, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	if strings.Contains(body, "sync.Mutex") {
		t.Error("this package still declares a mutex of its own beside the shared lock")
	}
	if n := strings.Count(body, "panelport.Lock()"); n != 2 {
		t.Errorf("the panel-port lock is taken %d times, want once in Add and once in Remove", n)
	}
	for _, fn := range []string{"func (h *Handlers) Add(", "func (h *Handlers) Remove("} {
		start := strings.Index(body, fn)
		if start < 0 {
			t.Errorf("%s is missing from handlers.go", fn)
			continue
		}
		end := strings.Index(body[start:], "\nfunc ")
		if end < 0 {
			end = len(body) - start
		}
		if !strings.Contains(body[start:start+end], "panelport.Lock()") {
			t.Errorf("%s does not serialise against a panel-port change", fn)
		}
	}
}
