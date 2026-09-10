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

// TestTwoFASetupQR calls the real /me/2fa/setup handler via httptest (no DB needed,
// only JWT claims) and proves the QR/otpauth chain end-to-end.
func TestTwoFASetupQR(t *testing.T) {
	h := &Handlers{Secret: []byte("test-jwt-secret-0123456789-abcdef"), LifetimeSec: 3600}

	// The identity is carried in the request context, which is where RequireAuth
	// puts it after verifying the session cookie.
	req := httptest.NewRequest(http.MethodGet, "/me/2fa/setup", nil)
	req = req.WithContext(WithClaims(req.Context(), &Claims{UserID: 1, Username: "root", Role: "admin"}))
	rec := httptest.NewRecorder()
	h.TwoFASetup(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Secret     string `json:"secret"`
		Otpauth    string `json:"otpauth"`
		OtpauthURI string `json:"otpauth_uri"`
		QRDataURI  string `json:"qr_data_uri"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp.Secret == "" {
		t.Fatal("secret is empty")
	}
	if resp.OtpauthURI == "" || resp.OtpauthURI != resp.Otpauth {
		t.Fatalf("otpauth_uri/otpauth mismatch: %q vs %q", resp.OtpauthURI, resp.Otpauth)
	}

	// otpauth_uri must be valid and contain the CORRECT secret.
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

	// qr_data_uri: valid data-URI + PNG magic + 256x256 dimensions.
	const pfx = "data:image/png;base64,"
	if !strings.HasPrefix(resp.QRDataURI, pfx) {
		t.Fatalf("qr_data_uri prefix invalid: %.40s", resp.QRDataURI)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(resp.QRDataURI, pfx))
	if err != nil {
		t.Fatalf("qr base64 decode: %v", err)
	}
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

	// QR PROOF: re-encode otpauth_uri; must be byte-identical → the QR encodes
	// exactly this otpauth_uri.
	want, err := qrcode.Encode(resp.OtpauthURI, qrcode.Medium, 256)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(raw, want) {
		t.Fatal("QR PNG does not match the otpauth_uri QR encoding")
	}

	// Enrollment chain: TOTP code derived from the QR secret must pass
	// TOTPVerify (end-to-end: generate secret → show QR → user scans → code → enable).
	counter := uint64(time.Now().Unix()) / 30
	code, ok := hotp(resp.Secret, counter)
	if !ok {
		t.Fatal("hotp failed to produce a code")
	}
	if !TOTPVerify(resp.Secret, code) {
		t.Fatal("TOTPVerify rejected a valid code")
	}

	t.Logf("PROOF setup response: secret=%s otpauth_uri=%s qr_data_uri=%s<%d byte PNG 256x256> totp=%s → verify OK",
		mask(resp.Secret),
		strings.Replace(resp.OtpauthURI, resp.Secret, mask(resp.Secret), 1),
		pfx, len(raw), code)
}
