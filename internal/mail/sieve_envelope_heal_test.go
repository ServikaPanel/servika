package mail

import (
	"strings"
	"testing"
)

// stockMailDropIn mirrors the plugin block the mail template ships without the
// envelope-from setting, so the repair has something realistic to append to.
const stockMailDropIn = `protocols = imap lmtp

mail_plugins = $mail_plugins quota
protocol lmtp {
  mail_plugins = $mail_plugins sieve quota
}
plugin {
  quota = maildir:User quota
  sieve = file:~/sieve;active=~/.dovecot.sieve
}
`

func TestAppendSieveEnvelopeAddsTheSettingWhenAbsent(t *testing.T) {
	out, changed := appendSieveEnvelope(stockMailDropIn)
	if !changed {
		t.Fatal("the setting was not added to a drop-in that lacks it")
	}
	if !strings.Contains(out, sieveEnvelopeSetting) {
		t.Errorf("the appended content does not carry %q:\n%s", sieveEnvelopeSetting, out)
	}
	// The original content survives ahead of the appended block.
	if !strings.HasPrefix(out, stockMailDropIn) {
		t.Errorf("the original drop-in was not preserved:\n%s", out)
	}
	// The setting must sit INSIDE a plugin block, or Dovecot ignores it. The
	// appended block opens its own `plugin {` before the setting.
	before, _, _ := strings.Cut(out, sieveEnvelopeSetting)
	if !strings.Contains(before, "plugin {") {
		t.Errorf("the setting is not inside a plugin block:\n%s", out)
	}
}

func TestAppendSieveEnvelopeIsIdempotent(t *testing.T) {
	once, changed := appendSieveEnvelope(stockMailDropIn)
	if !changed {
		t.Fatal("first pass did not change the drop-in")
	}
	twice, changed := appendSieveEnvelope(once)
	if changed {
		t.Fatal("second pass changed a drop-in that already carries the setting")
	}
	if twice != once {
		t.Error("second pass altered the content")
	}
	if got := strings.Count(twice, sieveEnvelopeSetting); got != 1 {
		t.Errorf("the setting appears %d times, want 1", got)
	}
}

func TestAppendSieveEnvelopeLeavesAConfiguredDropInAlone(t *testing.T) {
	already := stockMailDropIn + "\nplugin {\n  " + sieveEnvelopeSetting + "\n}\n"
	out, changed := appendSieveEnvelope(already)
	if changed {
		t.Error("a drop-in that already carries the setting was changed")
	}
	if out != already {
		t.Error("the content was altered")
	}
}
