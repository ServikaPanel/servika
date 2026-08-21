package avpackage

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
)

func keyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

var produced = time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC)

func built(t *testing.T, key ed25519.PrivateKey, body string) []byte {
	t.Helper()
	pkg, err := Build([]byte(body), key, 7, produced)
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}

// The signature is the whole security property: rules that do not verify never
// reach the scanner. This is the gate, exercised on every way past it.
func TestOnlyAPackageSignedByThisKeyOpens(t *testing.T) {
	public, private := keyPair(t)
	const body = `{"version":7,"rules":[{"name":"PHP.Test","score":60,"pattern":"eval","kind":"php"}]}`
	pkg := built(t, private, body)

	t.Run("the right key opens it", func(t *testing.T) {
		header, got, err := Open(pkg, public)
		if err != nil {
			t.Fatalf("a package this key signed did not open: %v", err)
		}
		if header.Version != 7 {
			t.Errorf("version %d, want 7", header.Version)
		}
		if string(got) != body {
			t.Errorf("body did not survive the round trip")
		}
		stamp, err := header.ProducedAt()
		if err != nil || !stamp.Equal(produced) {
			t.Errorf("produced = %v (%v), want %v", stamp, err, produced)
		}
	})

	t.Run("another key is refused", func(t *testing.T) {
		other, _ := keyPair(t)
		if _, _, err := Open(pkg, other); !errors.Is(err, ErrUnverified) {
			t.Fatalf("a package signed by somebody else answered %v", err)
		}
	})

	t.Run("an edited header is refused", func(t *testing.T) {
		tampered := clone(pkg)
		// The header sits right after the magic and its 4-byte length.
		tampered[len(Magic)+4+2] ^= 0xff
		if _, _, err := Open(tampered, public); !errors.Is(err, ErrUnverified) {
			t.Fatalf("an edited header answered %v", err)
		}
	})

	t.Run("an edited body is refused", func(t *testing.T) {
		tampered := clone(pkg)
		tampered[len(tampered)-4] ^= 0xff
		if _, _, err := Open(tampered, public); !errors.Is(err, ErrUnverified) {
			t.Fatalf("an edited body answered %v", err)
		}
	})

	t.Run("a body swapped whole is refused", func(t *testing.T) {
		// The interesting case: a body the attacker chose, with the signed
		// header left intact. Nothing but the digest catches this.
		honest := built(t, private, body)
		hostile := clone(honest)
		hostile = append(hostile[:len(hostile)-len(body)],
			[]byte(strings.Repeat("x", len(body)))...)
		if _, _, err := Open(hostile, public); !errors.Is(err, ErrUnverified) {
			t.Fatalf("a swapped body answered %v", err)
		}
	})
}

// A download that went wrong and a package somebody else made are different
// facts. Folding them together would report a captive portal's HTML as a
// signature failure, which sends an operator looking for an attacker.
func TestBytesThatAreNotAPackageSaySo(t *testing.T) {
	public, _ := keyPair(t)
	for name, body := range map[string][]byte{
		"empty":              nil,
		"an HTML error page": []byte("<html><body>404 Not Found</body></html>"),
		"the magic alone":    []byte(Magic),
		"a truncated header": append([]byte(Magic), 0xff, 0xff, 0x00, 0x00),
		"another magic":      []byte("GOSPAV01____________________"),
	} {
		if _, _, err := Open(body, public); !errors.Is(err, ErrNotAPackage) {
			t.Errorf("%s answered %v, want ErrNotAPackage", name, err)
		}
	}
}

// A declared length near the top of the uint32 range must not wrap into a
// negative int and slip past the bound. The panel builds for 64-bit only, where
// the conversion is lossless, but the reader is fed by the network and the
// comparison is written to hold regardless.
func TestAnEnormousDeclaredLengthIsRefused(t *testing.T) {
	public, _ := keyPair(t)
	pkg := append([]byte(Magic), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(pkg[len(Magic):], ^uint32(0))
	pkg = append(pkg, []byte("short")...)
	if _, _, err := Open(pkg, public); !errors.Is(err, ErrNotAPackage) {
		t.Fatalf("a 4 GiB header length answered %v", err)
	}
}

// The ceiling is enforced on the way in as well as on the way out, because the
// reader is fed by the network and a caller can forget its own limit.
func TestThePackageCeilingIsEnforced(t *testing.T) {
	public, private := keyPair(t)
	if _, err := Build(make([]byte, MaxBytes+1), private, 1, produced); err == nil {
		t.Error("Build produced a package over the ceiling")
	}
	oversized := make([]byte, MaxBytes+1)
	copy(oversized, Magic)
	if _, _, err := Open(oversized, public); err == nil {
		t.Error("Open accepted a package over the ceiling")
	}
}

// The key itself is checked, so a caller that never configured one gets a
// refusal rather than a panic inside crypto/ed25519.
func TestAKeyOfTheWrongSizeIsRefused(t *testing.T) {
	_, private := keyPair(t)
	if _, _, err := Open(built(t, private, "{}"), ed25519.PublicKey(nil)); err == nil {
		t.Error("an empty verification key was accepted")
	}
	if _, err := Build([]byte("{}"), ed25519.PrivateKey("short"), 1, produced); err == nil {
		t.Error("a short signing key was accepted")
	}
}

// An unparseable production time is an error rather than a zero value. A zero
// time reads as 1970, which makes every package look ancient and would switch
// the whole feature off in silence instead of reporting the malformed field.
func TestAnUnparseableProductionTimeIsAnError(t *testing.T) {
	if _, err := (Header{Produced: "last tuesday"}).ProducedAt(); err == nil {
		t.Fatal("a malformed production time parsed")
	}
	if _, err := (Header{Produced: ""}).ProducedAt(); err == nil {
		t.Fatal("an empty production time parsed")
	}
}

func clone(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
