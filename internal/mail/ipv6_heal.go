package mail

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"servika/internal/logx"
)

// Bringing an existing mail install onto both address families.
//
// The three Postfix settings and the Dovecot listen line reach a NEW install
// through servika-mail-setup and the shipped templates. An existing install
// never reruns that setup, so without a repair here IPv6 mail would work on
// hosts installed after this change and on no host installed before it.
//
// It runs at panel startup rather than from servika-update, for the reason the
// other mail heals document: the updater replaces itself, so a repair added
// there takes effect one update late.

// postfixIPv6Settings are written explicitly rather than left to the packaged
// default, which was ipv4 on older RHEL releases.
//
// The delivery preference is "any", NOT ipv6. The Postfix documentation calls
// an ipv6 preference unsafe: during an IPv6 outage every message waits out its
// timeout before falling back to IPv4, which fills the queue. Balancing across
// both families uses IPv6 where it works without ever making IPv4 wait.
var postfixIPv6Settings = []struct{ key, value string }{
	{"inet_protocols", "all"},
	{"smtp_address_preference", "any"},
	{"smtp_balance_inet_protocols", "yes"},
}

// postfixMainCf is the Postfix configuration the IPv6 repair reads. It is a
// package variable so a test can point the repair at a temporary file, for the
// reason the Dovecot paths are.
var postfixMainCf = "/etc/postfix/main.cf"

// dovecotListenLine is what the Servika drop-in must carry. `listen = [::]`
// alone serves IPv6 ONLY on most systems, so both forms are named.
const dovecotListenLine = "listen = *, ::"

// HealMailIPv6 makes an existing install accept and deliver mail over both
// address families.
//
// GUARD: each half acts only where Servika's own mail setup already ran.
// Without that check the panel would rewrite a Postfix or Dovecot someone
// installed for a different purpose.
func HealMailIPv6(ctx context.Context) {
	healPostfixIPv6(ctx)
	healDovecotListen(ctx)
}

// healPostfixIPv6 writes the three delivery settings when any is missing.
func healPostfixIPv6(ctx context.Context) {
	content, ok := managedPostfixConfig()
	if !ok {
		return
	}
	missing := missingPostfixIPv6Settings(content)
	if len(missing) == 0 {
		return
	}

	applyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if !applyPostfixIPv6(applyCtx, missing) {
		return
	}
	logx.Infof("mail ipv6 heal: postfix now accepts and delivers over IPv4 and IPv6 (%s)", strings.Join(missing, "; "))
}

// managedPostfixConfig reads main.cf when it belongs to a Postfix this panel
// configured and postconf is there to change it.
func managedPostfixConfig() (string, bool) {
	// #nosec G304 -- fixed system configuration path, never built from request input.
	content, err := os.ReadFile(postfixMainCf)
	if err != nil {
		return "", false // no Postfix here
	}
	if !strings.Contains(string(content), "servika-mail") {
		return "", false // a Postfix this panel did not configure; leave it alone
	}
	if _, err := lookPath("postconf"); err != nil {
		return "", false
	}
	return string(content), true
}

// missingPostfixIPv6Settings names each delivery setting main.cf does not carry.
func missingPostfixIPv6Settings(content string) []string {
	var missing []string
	for _, setting := range postfixIPv6Settings {
		if !hasPostfixSetting(content, setting.key, setting.value) {
			missing = append(missing, setting.key+" = "+setting.value)
		}
	}
	return missing
}

// applyPostfixIPv6 writes the missing settings, has Postfix check them and
// restarts it. It logs the step that failed and reports whether every step ran.
func applyPostfixIPv6(ctx context.Context, missing []string) bool {
	for _, setting := range missing {
		// #nosec G204 G702 -- fixed binary with separate args (no shell); every argument comes from the package-level table above, never from a request.
		if out, err := execCommandContext(ctx, "postconf", "-e", setting).CombinedOutput(); err != nil {
			// #nosec G706 -- the operand is postconf output, not client-controlled input.
			logx.Errorf("mail ipv6 heal: could not set %q: %v: %s", setting, err, strings.TrimSpace(string(out)))
			return false
		}
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell).
	if out, err := execCommandContext(ctx, "postfix", "check").CombinedOutput(); err != nil {
		// #nosec G706 -- the operand is postfix output, not client-controlled input.
		logx.Errorf("mail ipv6 heal: postfix refused the settings: %v: %s", err, strings.TrimSpace(string(out)))
		return false
	}
	// inet_protocols is one of the few settings a reload does NOT pick up:
	// Postfix binds its listeners at start, so the master has to come back.
	// #nosec G204 G702 -- fixed binary with separate args (no shell).
	if out, err := execCommandContext(ctx, "systemctl", "restart", "postfix").CombinedOutput(); err != nil {
		// #nosec G706 -- the operand is systemctl output, not client-controlled input.
		logx.Errorf("mail ipv6 heal: could not restart postfix: %v: %s", err, strings.TrimSpace(string(out)))
		return false
	}
	return true
}

// hasPostfixSetting reports whether main.cf already carries key with value.
//
// The LAST active assignment wins in main.cf, so an early stock line that a
// later managed line overrides must not count as present. Scanning to the end
// and keeping the final value is what Postfix itself does.
func hasPostfixSetting(content, key, value string) bool {
	found := ""
	for line := range strings.SplitSeq(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		rest, ok := strings.CutPrefix(trimmed, key)
		if !ok {
			continue
		}
		rest = strings.TrimLeft(rest, " \t")
		if !strings.HasPrefix(rest, "=") {
			continue // a longer key that merely starts with this one
		}
		found = strings.TrimSpace(strings.TrimPrefix(rest, "="))
	}
	return strings.EqualFold(found, value)
}

// healDovecotListen adds the listen line to the Servika drop-in on hosts
// installed before the template carried it.
func healDovecotListen(ctx context.Context) {
	// #nosec G304 -- fixed system configuration path, never built from request input.
	content, err := os.ReadFile(dovecotServikaConf)
	if err != nil {
		return // the Servika mail setup never ran here
	}
	if strings.Contains(string(content), dovecotListenLine) {
		return
	}
	// An operator who set their own listen line keeps it: overwriting it could
	// take the service off an address they deliberately bound it to.
	if hasActiveDovecotListen(string(content)) {
		return
	}

	appended := string(content)
	if !strings.HasSuffix(appended, "\n") {
		appended += "\n"
	}
	appended += "\n# --- Servika: serve both address families ---\n" +
		"# `listen = [::]` alone serves IPv6 ONLY on most systems.\n" +
		dovecotListenLine + "\n"

	// The mode is 0 because O_CREATE is deliberately absent: the file was read
	// above, so it exists, and its own mode and ownership are preserved.
	// #nosec G304 -- fixed system configuration path, never built from request input.
	file, err := os.OpenFile(dovecotServikaConf, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		logx.Errorf("mail ipv6 heal: could not open %s: %v", dovecotServikaConf, err)
		return
	}
	if _, err := file.WriteString(appended); err != nil {
		_ = file.Close()
		logx.Errorf("mail ipv6 heal: could not write %s: %v", dovecotServikaConf, err)
		return
	}
	if err := file.Close(); err != nil {
		logx.Errorf("mail ipv6 heal: could not close %s: %v", dovecotServikaConf, err)
		return
	}

	reloadCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	// #nosec G204 G702 -- fixed binary with separate args (no shell).
	if out, err := exec.CommandContext(reloadCtx, "systemctl", "restart", "dovecot").CombinedOutput(); err != nil {
		// #nosec G706 -- the operand is systemctl output, not client-controlled input.
		logx.Errorf("mail ipv6 heal: could not restart dovecot: %v: %s", err, strings.TrimSpace(string(out)))
		return
	}
	logx.Infof("mail ipv6 heal: dovecot now listens on IPv4 and IPv6")
}

// hasActiveDovecotListen reports whether the file already sets listen.
func hasActiveDovecotListen(content string) bool {
	for line := range strings.SplitSeq(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		rest, ok := strings.CutPrefix(trimmed, "listen")
		if !ok {
			continue
		}
		rest = strings.TrimLeft(rest, " \t")
		if strings.HasPrefix(rest, "=") {
			return true
		}
	}
	return false
}
