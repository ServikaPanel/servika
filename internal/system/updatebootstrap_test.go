package system

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The bootstrap body becomes a file this panel writes 0755 and runs as root
// through systemd-run in the next statement, so anyone who can answer for the
// URL — including anyone who can only induce a redirect off TLS — gets arbitrary
// root code execution on the host.

// Go's default policy follows an https to plain-http redirect without a word.
func TestTheBootstrapRefusesARedirectThatLeavesTLS(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("#!/bin/sh\necho attacker\n"))
	}))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer secure.Close()

	client := updateToolClient()
	client.Transport = secure.Client().Transport
	if _, err := client.Get(secure.URL); err == nil {
		t.Fatal("the client followed a redirect from https to http")
	} else if !strings.Contains(err.Error(), "refusing a redirect") {
		t.Fatalf("the redirect was refused for the wrong reason: %v", err)
	}
}

// A redirect that stays on TLS is normal and must still work.
func TestARedirectThatStaysOnTLSIsFollowed(t *testing.T) {
	final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("#!/bin/sh\n"))
	}))
	defer final.Close()
	first := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer first.Close()

	client := updateToolClient()
	client.Transport = final.Client().Transport
	response, err := client.Get(first.URL)
	if err != nil {
		t.Fatalf("a redirect within https was refused: %v", err)
	}
	_ = response.Body.Close()
}

// Once a key is configured the signature is REQUIRED, including when the .sig is
// absent: "verify it if a signature is present" is not a check, because the
// attacker chooses whether to publish one.
func TestAConfiguredKeyMakesTheSignatureRequired(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}
	body := []byte("#!/bin/sh\necho real\n")

	withKey(t, hex.EncodeToString(public))

	t.Run("no signature published", func(t *testing.T) {
		server := signatureServer(t, nil, http.StatusNotFound)
		if err := verifyUpdateTool(server.Client(), body); err == nil {
			t.Fatal("a missing signature was accepted")
		}
	})
	t.Run("signature of other bytes", func(t *testing.T) {
		server := signatureServer(t, ed25519.Sign(private, []byte("#!/bin/sh\necho other\n")), http.StatusOK)
		if err := verifyUpdateTool(server.Client(), body); err == nil {
			t.Fatal("a signature over different bytes was accepted")
		}
	})
	t.Run("correct signature", func(t *testing.T) {
		server := signatureServer(t, ed25519.Sign(private, body), http.StatusOK)
		if err := verifyUpdateTool(server.Client(), body); err != nil {
			t.Fatalf("the correct signature was refused: %v", err)
		}
	})
}

// A key from another pair verifies nothing, so a body signed by somebody else is
// refused.
func TestAKeyFromAnotherPairRefusesTheBody(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}
	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate the other key: %v", err)
	}
	body := []byte("#!/bin/sh\n")

	withKey(t, hex.EncodeToString(public))
	server := signatureServer(t, ed25519.Sign(otherPrivate, body), http.StatusOK)
	if err := verifyUpdateTool(server.Client(), body); err == nil {
		t.Fatal("a signature from another key was accepted")
	}
}

// With no key configured the panel keeps working, exactly as install.sh does
// with an empty embedded key. The redirect refusal is then the only guard, and
// this states that rather than leaving it implied.
func TestWithNoKeyTheSignatureStepIsSkipped(t *testing.T) {
	withKey(t, "")
	if err := verifyUpdateTool(http.DefaultClient, []byte("#!/bin/sh\n")); err != nil {
		t.Fatalf("an installation with no key configured was refused: %v", err)
	}
}

// withKey sets the embedded verification key for one test.
func withKey(t *testing.T, keyHex string) {
	t.Helper()
	previous := updateBootstrapKeyHex
	updateBootstrapKeyHex = keyHex
	t.Cleanup(func() { updateBootstrapKeyHex = previous })
}

// signatureServer answers every request with the given signature, and points the
// bootstrap URL at itself.
func signatureServer(t *testing.T, signature []byte, status int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write(signature)
	}))
	t.Cleanup(server.Close)
	t.Setenv("SERVIKA_UPDATE_BOOTSTRAP_URL", server.URL+"/servika-update")
	return server
}
