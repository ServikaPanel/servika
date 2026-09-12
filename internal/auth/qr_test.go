package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

func mask(s string) string {
	if len(s) <= 6 {
		return "****"
	}
	return s[:3] + "..." + s[len(s)-3:]
}

// qrDataURIPrefix is the data-URI header the handler emits.
const qrDataURIPrefix = "data:image/png;base64,"

// setupResponse is the /me/2fa/setup answer.
type setupResponse struct {
	Secret     string `json:"secret"`
	Otpauth    string `json:"otpauth"`
	OtpauthURI string `json:"otpauth_uri"`
	QRDataURI  string `json:"qr_data_uri"`
}

// twoFASetup calls the real handler via httptest (no DB needed, only JWT
// claims). The identity is carried in the request context, which is where
// RequireAuth puts it after verifying the session cookie.
func twoFASetup(t *testing.T) setupResponse {
	t.Helper()
	h := &Handlers{Secret: []byte("test-jwt-secret-0123456789-abcdef"), LifetimeSec: 3600}
	req := httptest.NewRequest(http.MethodGet, "/me/2fa/setup", nil)
	req = req.WithContext(WithClaims(req.Context(), &Claims{UserID: 1, Username: "root", Role: "admin"}))
	rec := httptest.NewRecorder()
	h.TwoFASetup(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp setupResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	return resp
}

// decodeQR returns the PNG bytes behind the data-URI.
func decodeQR(t *testing.T, dataURI string) []byte {
	t.Helper()
	if !strings.HasPrefix(dataURI, qrDataURIPrefix) {
		t.Fatalf("qr_data_uri prefix invalid: %.40s", dataURI)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(dataURI, qrDataURIPrefix))
	if err != nil {
		t.Fatalf("qr base64 decode: %v", err)
	}
	return raw
}

// The otpauth URI has to be a valid otpauth://totp URI carrying the same secret
// the response returned, or the manual-entry fallback enrolls a different seed
// than the QR does.
func TestTwoFASetupOtpauthURI(t *testing.T) {
	resp := twoFASetup(t)

	if resp.Secret == "" {
		t.Fatal("secret is empty")
	}
	if resp.OtpauthURI == "" || resp.OtpauthURI != resp.Otpauth {
		t.Fatalf("otpauth_uri/otpauth mismatch: %q vs %q", resp.OtpauthURI, resp.Otpauth)
	}
	u, err := url.Parse(resp.OtpauthURI)
	if err != nil {
		t.Fatalf("otpauth parse: %v", err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("otpauth scheme/host invalid: %q", resp.OtpauthURI)
	}
	if got := u.Query().Get("secret"); got != resp.Secret {
		t.Fatalf("otpauth secret %q != response secret %q", got, resp.Secret)
	}
}

// qr_data_uri: valid data-URI, PNG magic, 256x256 dimensions, and byte-identical
// to a re-encoding of otpauth_uri, which is what proves the QR carries exactly
// that URI.
func TestTwoFASetupQRImage(t *testing.T) {
	resp := twoFASetup(t)
	raw := decodeQR(t, resp.QRDataURI)

	if !bytes.HasPrefix(raw, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}) {
		t.Fatalf("PNG magic missing: % x", raw[:8])
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("png decode: %v", err)
	}
	if b := img.Bounds(); b.Dx() != 256 || b.Dy() != 256 {
		t.Fatalf("qr dimensions %dx%d, expected 256x256", b.Dx(), b.Dy())
	}
	want, err := qrcode.Encode(resp.OtpauthURI, qrcode.Medium, 256)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(raw, want) {
		t.Fatal("QR PNG does not match the otpauth_uri QR encoding")
	}
	t.Logf("PROOF setup response: secret=%s otpauth_uri=%s qr_data_uri=%s<%d byte PNG 256x256>",
		mask(resp.Secret),
		strings.Replace(resp.OtpauthURI, resp.Secret, mask(resp.Secret), 1),
		qrDataURIPrefix, len(raw))
}

// Enrollment chain: a TOTP code derived from the QR secret must pass TOTPVerify
// (end-to-end: generate secret → show QR → user scans → code → enable).
func TestTwoFASetupSecretEnrolls(t *testing.T) {
	resp := twoFASetup(t)

	counter := uint64(time.Now().Unix()) / 30
	code, ok := hotp(resp.Secret, counter)
	if !ok {
		t.Fatal("hotp failed to produce a code")
	}
	if !TOTPVerify(resp.Secret, code) {
		t.Fatal("TOTPVerify rejected a valid code")
	}
}
