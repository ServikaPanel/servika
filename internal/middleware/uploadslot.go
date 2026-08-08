package middleware

import (
	"net/http"
	"strconv"
	"sync"

	"servika/internal/httpx"
)

// Bounding how many uploads one account can have in flight.
//
// The streaming upload endpoints are exempt from the JSON body cap because they
// legitimately carry gigabytes, and each one holds up to maxMultipartMemory of
// resident buffer before it spills to disk. Nothing bounded how many of those an
// account could run at once: the nginx `limit_conn` ceiling counts CONNECTIONS
// PER IP, so it neither distinguishes an upload from a page load nor survives a
// client changing address.
//
// The request is refused rather than queued. Holding it would keep the socket,
// the goroutine and the partially read body alive, which is the slow-request
// exhaustion this is meant to prevent, only with the panel doing the waiting.

// maxConcurrentUploads is the ceiling per account. Three covers a person
// dragging a handful of files into the file manager while leaving no room for an
// account to occupy the process on its own.
const maxConcurrentUploads = 3

var (
	uploadSlotsMu sync.Mutex
	uploadSlots   = map[string]int{}
)

// acquireUploadSlot reserves one of an account's slots.
//
// The release function is safe to call once; the entry is deleted at zero so an
// account that stops uploading leaves nothing behind.
func acquireUploadSlot(account string) (release func(), ok bool) {
	uploadSlotsMu.Lock()
	defer uploadSlotsMu.Unlock()
	if uploadSlots[account] >= maxConcurrentUploads {
		return nil, false
	}
	uploadSlots[account]++
	var once sync.Once
	return func() {
		once.Do(func() {
			uploadSlotsMu.Lock()
			defer uploadSlotsMu.Unlock()
			if uploadSlots[account] <= 1 {
				delete(uploadSlots, account)
				return
			}
			uploadSlots[account]--
		})
	}, true
}

// uploadAccount identifies whose quota a request spends.
//
// The authenticated user is the right unit: it is what an upload is charged to,
// and unlike an address it cannot be changed to get a fresh allowance. A request
// that somehow reaches here without claims falls back to the client address,
// which is stricter than letting it through unbounded.
func uploadAccount(r *http.Request) string {
	if claims := ClaimsFrom(r); claims != nil {
		return "user:" + strconv.FormatInt(claims.UserID, 10)
	}
	return "ip:" + httpx.RateLimitKey(httpx.ClientIP(r))
}

// UploadSlot caps concurrent uploads per account.
//
// It is mounted once on the authenticated group and decides for itself which
// requests it applies to, so the set of streaming uploads is declared in exactly
// one place (isStreamingUpload) and cannot drift from the body-limit exemption
// that uses the same list.
func UploadSlot(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !isStreamingUpload(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		release, ok := acquireUploadSlot(uploadAccount(r))
		if !ok {
			w.Header().Set("Retry-After", "5")
			httpx.WriteError(w, http.StatusTooManyRequests, "too many uploads are already running for this account")
			return
		}
		defer release()
		next.ServeHTTP(w, r)
	})
}
