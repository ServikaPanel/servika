package mail

import (
	"context"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// sieveEnvelopeSetting is the Pigeonhole key that decides the envelope-from of a
// Sieve `redirect`, which is what every Servika forward and redirect filter
// compiles to.
const sieveEnvelopeSetting = "sieve_redirect_envelope_from = user_email"

// HealSieveEnvelopeFrom makes a forwarded or redirected message carry the
// forwarding mailbox's OWN address as its envelope-from.
//
// Pigeonhole's default envelope-from for a `redirect` is the ORIGINAL sender, so
// a message forwarded to Gmail is re-sent from a domain this server is not
// authorized for and fails SPF at the destination, which publishes -all: the
// forward lands in spam or is rejected outright, silently. `user_email` makes
// the forwarding mailbox its own envelope-from, which this server's SPF
// authorizes.
//
// The setting reaches a NEW install through the mail template; an existing one
// never reruns the mail setup, so without this repair forwards from hosts
// installed before the change keep failing SPF.
func HealSieveEnvelopeFrom(ctx context.Context) {
	// #nosec G304 -- fixed system configuration path, never built from request input.
	content, err := os.ReadFile(dovecotServikaConf)
	if err != nil {
		return // the Servika mail setup never ran here
	}
	appended, changed := appendSieveEnvelope(string(content))
	if !changed {
		return
	}

	// The mode is 0 because O_CREATE is deliberately absent: the file was read
	// above, so it exists, and its own mode and ownership are preserved.
	// #nosec G304 G703 -- fixed system configuration path (package var), never built from request input.
	if err := os.WriteFile(dovecotServikaConf, []byte(appended), 0); err != nil {
		log.Printf("mail sieve-envelope heal: could not write %s: %v", dovecotServikaConf, err)
		return
	}

	checkCtx, cancelCheck := context.WithTimeout(ctx, 20*time.Second)
	defer cancelCheck()
	// #nosec G204 -- fixed binary with no arguments (no shell).
	if out, err := exec.CommandContext(checkCtx, "doveconf", "-n").CombinedOutput(); err != nil {
		// The appended block did not parse, so put the file back exactly as it was
		// rather than leave Dovecot unable to start.
		// #nosec G304 G703 -- fixed system configuration path (package var), never built from request input.
		if rerr := os.WriteFile(dovecotServikaConf, content, 0); rerr != nil {
			log.Printf("mail sieve-envelope heal: could not restore %s: %v", dovecotServikaConf, rerr)
		}
		// #nosec G706 -- the operand is doveconf output, not client-controlled input.
		log.Printf("mail sieve-envelope heal: doveconf rejected the change, rolled back: %v: %s", err, strings.TrimSpace(string(out)))
		return
	}

	reloadCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	// #nosec G204 -- fixed binary with separate args (no shell).
	if out, err := exec.CommandContext(reloadCtx, "systemctl", "restart", "dovecot").CombinedOutput(); err != nil {
		// #nosec G706 -- the operand is systemctl output, not client-controlled input.
		log.Printf("mail sieve-envelope heal: could not restart dovecot: %v: %s", err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("mail sieve-envelope heal: forwards now pass SPF (envelope-from = user_email)")
}

// appendSieveEnvelope adds the envelope-from setting when it is absent and
// reports whether it changed the content. A second plugin block is merged with
// the first by Dovecot, so the setting is added without editing the existing
// block in place; appending at the end mirrors the Dovecot listen-line repair.
// It is idempotent: content that already carries the setting is returned
// unchanged.
func appendSieveEnvelope(content string) (string, bool) {
	if strings.Contains(content, sieveEnvelopeSetting) {
		return content, false
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += "\n# --- Servika: forward deliverability ---\n" +
		"# Pigeonhole's default keeps the original sender, which fails SPF at the\n" +
		"# destination; user_email makes the forwarding mailbox its own envelope-from.\n" +
		"plugin {\n  " + sieveEnvelopeSetting + "\n}\n"
	return content, true
}
