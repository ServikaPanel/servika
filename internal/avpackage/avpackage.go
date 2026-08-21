// Package avpackage is the signed container the malware rule set travels in.
//
// The panel's detection rules are compiled into the binary, and the binary is
// verified against the release SHA256SUMS on both the install and the update
// path. This package exists so a rule set can also be updated BETWEEN releases,
// which means introducing a remote input to the detection engine. Everything
// here is about making that input answer for itself.
//
// # What the signature buys, and what it does not
//
// The signature proves AUTHORSHIP: a rule set that verifies was produced by
// whoever holds the private half, and nobody else can put rules in front of the
// scanner. That is the whole security property, and it is why the publication
// host does not have to be trusted: serving the package from a compromised
// mirror changes nothing, because the mirror cannot sign.
//
// It does NOT prove FRESHNESS. A signature made a year ago verifies exactly as
// well today, so an attacker who can withhold a new package pins a server to an
// old one forever, with every check passing. That is why the header carries a
// production timestamp and the caller applies a maximum age; see
// internal/antivirus for the policy.
//
// There is deliberately no encryption. The upstream design this is derived from
// wrapped the body in AES-GCM under a key compiled into the agent, and its own
// comment conceded that root can extract the key and that this is not security.
// A layer that buys nothing is a layer that can fail, and the GCM tag would be
// forgeable by exactly the people the signature is defending against, since they
// would hold the key too. The body travels in the clear and the signature covers
// it.
//
// # Format
//
//	"SVKAV001"    8 bytes
//	u32           header length, little-endian
//	header JSON   {version, produced, body_sha256}   <- THE SIGNED BYTES
//	u32           signature length, little-endian
//	signature     Ed25519 over the header's raw bytes
//	body          the rule set, plain JSON
//
// The signature covers the HEADER, and the header carries the body's sha256, so
// one verification covers the whole package: signature -> header -> sha256 ->
// body. Verification runs BEFORE the header is unmarshalled, on the raw bytes
// that were signed, because a re-marshalled header is not the same bytes.
package avpackage

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Magic identifies the container and its version. A change to the layout takes a
// new magic rather than a flag inside the header: the header cannot be trusted
// until the signature over it has been checked, so nothing inside it may decide
// how to parse the bytes around it.
const Magic = "SVKAV001"

// MaxBytes bounds a package. A rule set is text, and the reader is fed by the
// network, so the ceiling is enforced by the caller before these bytes exist and
// again here for a caller that forgot.
const MaxBytes = 1 << 20

// maxField bounds the two length prefixes independently of MaxBytes, so a
// truncated package is refused by its own numbers rather than by arithmetic on
// whatever followed.
const maxField = 64 << 10

// ErrNotAPackage means the bytes are not this container at all: a captive
// portal's HTML, a 404 body, a truncated download.
var ErrNotAPackage = errors.New("not a Servika rule package")

// ErrUnverified means the bytes ARE this container and the signature does not
// hold. It is deliberately separate from ErrNotAPackage: one is a download that
// went wrong, the other is a package somebody else made.
var ErrUnverified = errors.New("the rule package signature did not verify")

// Header is the signed metadata.
type Header struct {
	// Version is monotonic. A package is only adopted when it is newer than what
	// is already in use, so a signed OLD package cannot be replayed as an update.
	Version int `json:"version"`
	// Produced is when the package was signed, RFC3339. The signature says
	// nothing about age, so this is the only thing a freshness rule can read.
	Produced string `json:"produced"`
	// BodySHA256 binds the body to the signature.
	BodySHA256 string `json:"body_sha256"`
}

// ProducedAt parses the production timestamp. A header that verifies can still
// carry an unparseable time, so this is an error rather than a zero value: a
// zero time reads as 1970 and would make every package look ancient, which
// silently disables the feature instead of reporting the malformed field.
func (h Header) ProducedAt() (time.Time, error) {
	stamp, err := time.Parse(time.RFC3339, h.Produced)
	if err != nil {
		return time.Time{}, fmt.Errorf("the package production time is not RFC3339: %w", err)
	}
	return stamp, nil
}

// Build produces a signed package. It is used by the offline signing tool and by
// the tests; nothing in the running panel holds a private key.
func Build(body []byte, key ed25519.PrivateKey, version int, produced time.Time) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("the signing key is not an Ed25519 private key")
	}
	if version <= 0 {
		return nil, errors.New("the package version must be positive")
	}
	sum := sha256.Sum256(body)
	header, err := json.Marshal(Header{
		Version:    version,
		Produced:   produced.UTC().Format(time.RFC3339),
		BodySHA256: hex.EncodeToString(sum[:]),
	})
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(key, header)

	out := make([]byte, 0, len(Magic)+8+len(header)+len(signature)+len(body))
	out = append(out, Magic...)
	out = appendLength(out, len(header))
	out = append(out, header...)
	out = appendLength(out, len(signature))
	out = append(out, signature...)
	out = append(out, body...)
	if len(out) > MaxBytes {
		return nil, fmt.Errorf("the package is %d bytes, over the %d ceiling", len(out), MaxBytes)
	}
	return out, nil
}

// Open verifies a package and returns its header and body.
//
// A caller must treat any error as "there is no package", never as "load it
// anyway": the whole point is that unverified rules never reach the scanner.
func Open(pkg []byte, key ed25519.PublicKey) (Header, []byte, error) {
	var header Header
	if len(key) != ed25519.PublicKeySize {
		return header, nil, errors.New("the verification key is not an Ed25519 public key")
	}
	if len(pkg) > MaxBytes {
		return header, nil, fmt.Errorf("the package is %d bytes, over the %d ceiling", len(pkg), MaxBytes)
	}
	if len(pkg) < len(Magic) || string(pkg[:len(Magic)]) != Magic {
		return header, nil, ErrNotAPackage
	}
	rest := pkg[len(Magic):]

	headerBytes, rest, err := takeField(rest)
	if err != nil {
		return header, nil, err
	}
	signature, body, err := takeField(rest)
	if err != nil {
		return header, nil, err
	}

	// The signature is checked on the raw header bytes, before they are parsed.
	// Unmarshalling first and re-marshalling to verify would compare a
	// re-serialisation, which is not what was signed.
	if !ed25519.Verify(key, headerBytes, signature) {
		return header, nil, ErrUnverified
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return header, nil, fmt.Errorf("the signed header is not valid JSON: %w", err)
	}

	// The body is bound to the signature only through this digest, so a
	// mismatch is a tampered body rather than a corrupt one, and it is compared
	// in constant time for the same reason the signature is.
	sum := sha256.Sum256(body)
	want, err := hex.DecodeString(header.BodySHA256)
	if err != nil || len(want) != len(sum) {
		return header, nil, fmt.Errorf("%w: the header carries no usable body digest", ErrUnverified)
	}
	if subtle.ConstantTimeCompare(sum[:], want) != 1 {
		return header, nil, fmt.Errorf("%w: the body does not match the signed digest", ErrUnverified)
	}
	return header, body, nil
}

func appendLength(out []byte, n int) []byte {
	var field [4]byte
	binary.LittleEndian.PutUint32(field[:], uint32(n)) // #nosec G115 -- bounded by maxField at both ends
	return append(out, field[:]...)
}

// takeField reads one length-prefixed field. The length is compared as uint64
// against the remaining bytes, so a declared length near the top of the uint32
// range cannot wrap into a negative int and slip past the bound.
func takeField(in []byte) (field, rest []byte, err error) {
	if len(in) < 4 {
		return nil, nil, ErrNotAPackage
	}
	length := uint64(binary.LittleEndian.Uint32(in[:4]))
	in = in[4:]
	if length > maxField || length > uint64(len(in)) {
		return nil, nil, ErrNotAPackage
	}
	return in[:length], in[length:], nil
}
