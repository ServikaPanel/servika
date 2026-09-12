package git

import (
	"os"
	"strings"
	"testing"
)

// git_repos.webhook_secret served two roles at once: the path segment of the
// delivery URL and the HMAC-SHA256 key handed to the remote. Anyone who learned
// the URL therefore held the signing key and could forge a valid signature for
// any body, so the signature check added nothing over the URL it exists to
// backstop. The URL is not a secret in practice: nginx records the full request
// line for every delivery, so the value was written to disk on every push.
func TestTheWebhookSigningKeyIsNotTheURLToken(t *testing.T) {
	body := readGitSource(t, "git.go")
	connect := sourceFunction(t, body, "func (h *Handlers) Connect(")

	if !strings.Contains(connect, "signingKey := randomHex(") {
		t.Error("Connect does not generate a signing key of its own")
	}
	if !strings.Contains(connect, "webhook_signing_key") {
		t.Error("Connect does not store a signing key")
	}

	// The delivery reads the key column; signedByTheRemote is where the key is
	// used, so the verification itself is read there.
	webhook := sourceFunction(t, body, "func (h *Handlers) Webhook(")
	verify := sourceFunction(t, body, "func signedByTheRemote(")
	if strings.Contains(verify, "validGitHubSignature(webhookSecret") {
		t.Error("the webhook still verifies the signature with the URL path token")
	}
	if !strings.Contains(verify, "validGitHubSignature(signingKey") {
		t.Error("the webhook does not verify the signature with the separate signing key")
	}
	if !strings.Contains(webhook, "g.webhook_signing_key") {
		t.Error("the webhook does not read the signing key column")
	}
	if !strings.Contains(webhook, "signedByTheRemote(w, r, signingKey)") {
		t.Error("the webhook does not hand the signing key to the verification")
	}
}

// An empty signing key must refuse, never fall back to the path token. A
// fallback would restore exactly the property the separation removes, and it
// would do so silently on whichever rows happened to be missing the key.
func TestAnEmptySigningKeyRefusesTheDelivery(t *testing.T) {
	verifier := sourceFunction(t, readGitSource(t, "git.go"), "func signedByTheRemote(")
	refusal := strings.Index(verifier, `if signingKey == "" {`)
	verify := strings.Index(verifier, "validGitHubSignature(")
	if refusal < 0 {
		t.Fatal("the webhook does not refuse an empty signing key")
	}
	if verify < 0 || refusal > verify {
		t.Error("the empty-key refusal is judged after the signature check, so it never decides anything")
	}
}

// The GitHub path registers the hook at GitHub, so it is the one place that can
// rotate a pre-separation pair without leaving a delivery signing with a value
// the panel no longer accepts.
func TestTheGitHubHookRegistersTheSigningKeyNotTheURLToken(t *testing.T) {
	body := readGitHubSource(t)
	if strings.Contains(body, "hook.Config.Secret = secret") {
		t.Error("the GitHub hook is still registered with the URL path token as its HMAC key")
	}
	if !strings.Contains(body, "hook.Config.Secret = signingKey") {
		t.Error("the GitHub hook is not registered with the separate signing key")
	}
	// A row carrying the backfilled pair has the two equal; this is where it is
	// rotated apart.
	if !strings.Contains(body, `if signingKey == "" || signingKey == secret {`) {
		t.Error("a repository still carrying the pre-separation pair is never rotated apart")
	}
	if !strings.Contains(body, "hookURL := strings.TrimRight(webhookBase, \"/\") + \"/api/v1/git-webhook/\" + secret") {
		t.Error("the delivery URL no longer carries the path token; this test is out of date")
	}
}

func readGitSource(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name) // #nosec G304 -- a file of this package.
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(body)
}

func readGitHubSource(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile("../github/github.go")
	if err != nil {
		t.Fatalf("read github.go: %v", err)
	}
	return string(body)
}

// sourceFunction returns one function's body, from its signature to the closing
// brace in the first column.
func sourceFunction(t *testing.T, source, signature string) string {
	t.Helper()
	at := strings.Index(source, signature)
	if at < 0 {
		t.Fatalf("%q is not defined", signature)
	}
	body, _, found := strings.Cut(source[at:], "\n}\n")
	if !found {
		t.Fatalf("%q has no closing brace", signature)
	}
	return body
}
