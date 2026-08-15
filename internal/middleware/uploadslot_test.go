package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func resetUploadSlots(t *testing.T) {
	t.Helper()
	uploadSlotsMu.Lock()
	uploadSlots = map[string]int{}
	uploadSlotsMu.Unlock()
	t.Cleanup(func() {
		uploadSlotsMu.Lock()
		uploadSlots = map[string]int{}
		uploadSlotsMu.Unlock()
	})
}

// The ceiling this exists for: an upload endpoint is exempt from the JSON body
// cap and holds resident buffer, so an account that opens them without limit
// occupies the process.
func TestAnAccountCannotExceedTheUploadCeiling(t *testing.T) {
	resetUploadSlots(t)

	var releases []func()
	for i := range maxConcurrentUploads {
		release, ok := acquireUploadSlot("user:1")
		if !ok {
			t.Fatalf("slot %d was refused below the ceiling", i+1)
		}
		releases = append(releases, release)
	}
	if _, ok := acquireUploadSlot("user:1"); ok {
		t.Fatal("an upload past the ceiling was admitted")
	}

	// Finishing one frees exactly one.
	releases[0]()
	release, ok := acquireUploadSlot("user:1")
	if !ok {
		t.Fatal("a slot freed by a finished upload was not reusable")
	}
	release()
	for _, release := range releases[1:] {
		release()
	}

	uploadSlotsMu.Lock()
	held := len(uploadSlots)
	uploadSlotsMu.Unlock()
	if held != 0 {
		t.Errorf("%d accounts still hold slots after every upload finished", held)
	}
}

// The ceiling is per account, so one account filling its allowance must not
// stop another from uploading.
func TestOneAccountDoesNotBlockAnother(t *testing.T) {
	resetUploadSlots(t)
	for i := range maxConcurrentUploads {
		if _, ok := acquireUploadSlot("user:1"); !ok {
			t.Fatalf("slot %d was refused below the ceiling", i+1)
		}
	}
	if _, ok := acquireUploadSlot("user:2"); !ok {
		t.Fatal("a second account was refused because the first had filled its own allowance")
	}
}

// Releasing twice must free exactly one slot.
//
// Two uploads are running and one of them releases twice. Counting that second
// call would drop the account to zero while an upload is still in flight, and
// the ceiling would then admit a full three more.
func TestReleasingTwiceFreesOnlyOneSlot(t *testing.T) {
	resetUploadSlots(t)
	first, ok := acquireUploadSlot("user:1")
	if !ok {
		t.Fatal("the first slot was refused")
	}
	if _, ok := acquireUploadSlot("user:1"); !ok {
		t.Fatal("the second slot was refused")
	}

	first()
	first()

	uploadSlotsMu.Lock()
	held := uploadSlots["user:1"]
	uploadSlotsMu.Unlock()
	if held != 1 {
		t.Fatalf("held = %d after a double release, want 1 for the upload still running", held)
	}

	// Only the remaining allowance is available, not a fresh full one.
	admitted := 0
	for range maxConcurrentUploads + 1 {
		if _, ok := acquireUploadSlot("user:1"); ok {
			admitted++
		}
	}
	if admitted != maxConcurrentUploads-1 {
		t.Errorf("admitted = %d more uploads, want %d", admitted, maxConcurrentUploads-1)
	}
}

func TestConcurrentAcquireStaysWithinTheCeiling(t *testing.T) {
	resetUploadSlots(t)
	var wait sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	var releases []func()

	for range 50 {
		wait.Go(func() {
			if release, ok := acquireUploadSlot("user:1"); ok {
				mu.Lock()
				admitted++
				releases = append(releases, release)
				mu.Unlock()
			}
		})
	}
	wait.Wait()
	if admitted != maxConcurrentUploads {
		t.Errorf("admitted = %d, want %d", admitted, maxConcurrentUploads)
	}
	for _, release := range releases {
		release()
	}
}

// Only the streaming upload endpoints are counted; an ordinary request must not
// spend an account's allowance.
func TestOnlyStreamingUploadsSpendASlot(t *testing.T) {
	resetUploadSlots(t)
	served := 0
	handler := UploadSlot(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served++ }))

	for _, path := range []string{
		"/api/v1/domains/1/files/list",
		"/api/v1/domains/1",
	} {
		for range maxConcurrentUploads + 2 {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
			if recorder.Code == http.StatusTooManyRequests {
				t.Fatalf("%s was counted against the upload ceiling", path)
			}
		}
	}
	if served == 0 {
		t.Fatal("no request reached the handler")
	}
}

// A refused upload answers 429 with the header that tells a client to come back,
// not a generic failure it would read as permanent.
func TestARefusedUploadAnswers429(t *testing.T) {
	resetUploadSlots(t)
	for i := range maxConcurrentUploads {
		if _, ok := acquireUploadSlot("ip:192.0.2.1"); !ok {
			t.Fatalf("slot %d was refused below the ceiling", i+1)
		}
	}

	handler := UploadSlot(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the handler ran for a refused upload")
	}))
	request := httptest.NewRequest(http.MethodPost, "/api/v1/domains/1/files/upload", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusTooManyRequests)
	}
	if recorder.Header().Get("Retry-After") == "" {
		t.Error("the refusal carries no Retry-After header")
	}
}

// Every path the body-limit exemption covers is also counted here, so a new
// upload endpoint cannot gain the exemption without gaining the ceiling.
func TestTheCeilingCoversEveryExemptedUploadPath(t *testing.T) {
	for _, path := range []string{
		"/api/v1/domains/1/files/upload",
		"/api/v1/admin/transfers/analyze",
		"/api/v1/admin/transfers/import",
		"/api/v1/domains/1/import/archive",
		"/api/v1/domains/1/import/sql",
	} {
		if !isStreamingUpload(path) {
			t.Errorf("%s is not recognised as a streaming upload", path)
		}
	}
}
