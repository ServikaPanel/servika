//go:build ignore

// Offline signing for the two things Servika publishes that a server must be
// able to trust: the malware rule package and the release SHA256SUMS.
//
// ONE key signs both, and it lives on the maintainer's own machine. That is the
// whole point. A key held in CI or in a repository secret sits on the same host
// that publishes the artefacts, so anybody who can rewrite a release can also
// re-sign it, and the signature adds nothing. Signing locally is what makes the
// publication host untrusted infrastructure.
//
// Generate the key once:
//
//	go run scripts/servika_sign.go -genkey ~/.servika-signing-key
//
// It prints the public half in the two forms the tree needs: hex for
// internal/antivirus.rulePublicKeyHex, and a PEM block for install.sh and
// assets/ops/servika-update. The public half is not a secret and belongs in the
// repository. The PRIVATE half never goes into git, into CI, or onto any server.
//
// Sign a rule package:
//
//	go run scripts/servika_sign.go -key ~/.servika-signing-key \
//	    -rules rules.json -version 3 -out assets/av/rules.svkav
//
// Sign a release checksum list:
//
//	go run scripts/servika_sign.go -key ~/.servika-signing-key -detached SHA256SUMS
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"servika/internal/antivirus"
	"servika/internal/avpackage"
)

func main() {
	genkey := flag.String("genkey", "", "generate a signing key at this path and print its public half")
	keyPath := flag.String("key", "", "the Ed25519 private key to sign with")
	rulesPath := flag.String("rules", "", "a rule set JSON file to package and sign")
	version := flag.Int("version", 0, "the rule package version; a server adopts only a HIGHER one")
	out := flag.String("out", "assets/av/rules.svkav", "where to write the signed rule package")
	detached := flag.String("detached", "", "write a detached signature beside this file, as <file>.sig")
	flag.Parse()

	switch {
	case *genkey != "":
		fail(generateKey(*genkey))
	case *rulesPath != "":
		fail(signRules(*keyPath, *rulesPath, *out, *version))
	case *detached != "":
		fail(signDetached(*keyPath, *detached))
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "servika_sign:", err)
		os.Exit(1)
	}
}

// generateKey writes the private half 0600 and refuses to overwrite an existing
// file. Replacing a signing key is not something to do by mistake: every server
// carrying the old public half stops adopting packages the moment it happens.
func generateKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists; refusing to replace a signing key", path)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(private)+"\n"), 0o600); err != nil {
		return err
	}

	block, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: block})

	fmt.Printf("private key written to %s (mode 0600)\n", path)
	fmt.Println("Keep it off git, off CI and off every server. Nothing else has to be secret.")
	fmt.Println()
	fmt.Println("For internal/antivirus/remoterules.go:")
	fmt.Printf("\tvar rulePublicKeyHex = %q\n", hex.EncodeToString(public))
	fmt.Println()
	fmt.Println("For install.sh and assets/ops/servika-update:")
	fmt.Print(string(encoded))
	return nil
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, fmt.Errorf("-key is required")
	}
	// #nosec G304 -- a path the maintainer typed on their own command line.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("the key file is not hex: %w", err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("the key is %d bytes, want %d", len(decoded), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(decoded), nil
}

// signRules packages a rule set and signs it.
//
// The body is checked against the SCANNER's own acceptance rules first. A
// package whose rules are all dropped verifies perfectly and detects nothing,
// and this is the only moment that can be caught: afterwards it is a valid
// signed package that quietly does nothing on every server that adopts it.
func signRules(keyPath, rulesPath, out string, version int) error {
	if version <= 0 {
		return fmt.Errorf("-version must be positive, and HIGHER than the last published package")
	}
	key, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	// #nosec G304 -- a path the maintainer typed on their own command line.
	body, err := os.ReadFile(rulesPath)
	if err != nil {
		return err
	}
	accepted, err := antivirus.CheckRulePackageBody(body)
	if err != nil {
		return fmt.Errorf("this rule set would not be used: %w", err)
	}

	// The production time is stamped here rather than taken from a flag, because
	// a package's age is what a server's freshness check reads and a hand-typed
	// timestamp is exactly the field somebody copies from the previous release.
	packaged, err := avpackage.Build(body, key, version, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(out, packaged, 0o644); err != nil { // #nosec G306 -- a signed artefact meant to be published
		return err
	}
	fmt.Printf("signed rule package: %s (version %d, %d rules the scanner will use, %d bytes)\n",
		out, version, accepted, len(packaged))
	fmt.Printf("A server stops using it after %s.\n", antivirus.RemoteRuleMaxAge)
	return nil
}

// signDetached writes <file>.sig, a bare 64-byte Ed25519 signature over the
// file's contents, which `openssl pkeyutl -verify -pubin -rawin` reads directly.
func signDetached(keyPath, target string) error {
	key, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	// #nosec G304 -- a path the maintainer typed on their own command line.
	body, err := os.ReadFile(target)
	if err != nil {
		return err
	}
	signature := ed25519.Sign(key, body)
	out := target + ".sig"
	if err := os.WriteFile(out, signature, 0o644); err != nil { // #nosec G306 -- a signature meant to be published
		return err
	}
	fmt.Printf("detached signature: %s (%d bytes over %d bytes of %s)\n",
		out, len(signature), len(body), target)
	return nil
}
