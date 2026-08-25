package mail

import (
	"errors"
	"strings"
	"testing"

	"servika/internal/dnsbl"
)

// The zone list goes into a Postfix parameter. A value carrying a space or a
// newline would not be quoted, it would rewrite the restriction list, so it is
// refused rather than cleaned up.
func TestBlocklistZonesMustBeHostnames(t *testing.T) {
	for _, zone := range []string{
		"zen.spamhaus.org, permit",
		"zen.spamhaus.org\nsmtpd_recipient_restrictions=permit",
		"reject_unauth_destination",
		"-leading.hyphen.test",
		"has space.test",
	} {
		settings := ServerSettings{DNSBLZones: zone}
		if _, err := validateServerSettings(&settings); err == nil {
			t.Errorf("%q was accepted as a blocklist zone", zone)
		}
	}
}

// A real list has to survive, or the validation is just a refusal.
func TestValidBlocklistZonesAreKept(t *testing.T) {
	settings := ServerSettings{DNSBLZones: "  ZEN.spamhaus.org   bl.spamcop.net "}
	zones, err := validateServerSettings(&settings)
	if err != nil {
		t.Fatalf("validateServerSettings: %v", err)
	}
	if len(zones) != 2 || zones[0] != "zen.spamhaus.org" || zones[1] != "bl.spamcop.net" {
		t.Errorf("zones = %v, want the two lower-cased names", zones)
	}
}

// Every bound exists because the value is written into a running mail server. A
// negative size or an absurd limit is a mistake, not a configuration.
func TestServerSettingBoundsAreEnforced(t *testing.T) {
	cases := map[string]ServerSettings{
		"negative message size": {MaxMessageSizeMB: -1},
		"absurd message size":   {MaxMessageSizeMB: maxMessageSizeMB + 1},
		"negative domain limit": {DomainSendLimitHour: -1},
		"absurd client limit":   {ClientSendLimitHour: maxSendLimitHour + 1},
		"too many zones":        {DNSBLZones: strings.Repeat("a.test ", dnsbl.MaxZones+1)},
	}
	for name, settings := range cases {
		if _, err := validateServerSettings(&settings); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// A customer sending through submission must be judged by their credentials,
// not by whether their home connection is on a blocklist.
func TestAuthenticatedSendersAreNotMeasuredAgainstBlocklists(t *testing.T) {
	value := clientRestrictions([]string{"zen.spamhaus.org"})
	permit := strings.Index(value, "permit_sasl_authenticated")
	reject := strings.Index(value, "reject_rbl_client")
	if permit == -1 || reject == -1 {
		t.Fatalf("restrictions = %q, want both a permit and a reject", value)
	}
	if permit > reject {
		t.Errorf("blocklists are consulted before authentication in %q", value)
	}
}

// With no zones configured the restriction must not carry an empty reject, which
// Postfix reads as a syntax error rather than as "no blocklists".
func TestNoZonesProducesNoRejectClause(t *testing.T) {
	if value := clientRestrictions(nil); strings.Contains(value, "reject_rbl_client") {
		t.Errorf("restrictions = %q, want no reject clause", value)
	}
}

// stubPostfix stands in for the whole Postfix installation and returns the
// recorded calls.
//
// It replaces the availability check as well as the command runner, because a
// test that replaces only the runner is really asking whether the machine
// running it happens to ship Postfix.
func stubPostfix(t *testing.T, answer func(name string, args ...string) ([]byte, error)) *[]string {
	t.Helper()
	originalCommand, originalInstalled := postfixCommand, postfixInstalled
	t.Cleanup(func() { postfixCommand, postfixInstalled = originalCommand, originalInstalled })

	var calls []string
	postfixInstalled = func() bool { return true }
	postfixCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return answer(name, args...)
	}
	return &calls
}

// Without Postfix the settings cannot reach a mail server, so saying nothing and
// reporting success would leave the panel claiming a limit it never applied.
func TestMissingPostfixIsRefused(t *testing.T) {
	recorded := stubPostfix(t, func(string, ...string) ([]byte, error) { return nil, nil })
	postfixInstalled = func() bool { return false }

	if err := applyPostfixSettings(ServerSettings{MaxMessageSizeMB: 25}, nil); err == nil {
		t.Fatal("a missing Postfix was reported as a successful apply")
	}
	if len(*recorded) != 0 {
		t.Errorf("commands were run without Postfix: %v", *recorded)
	}
}

// A configuration Postfix will not start with takes mail down for every domain
// on the server, so a rejected change has to leave the previous one running.
func TestRejectedSettingsAreRolledBack(t *testing.T) {
	recorded := stubPostfix(t, func(name string, args ...string) ([]byte, error) {
		if name == "postfix" && len(args) > 0 && args[0] == "check" {
			return []byte("bad parameter"), errors.New("exit status 1")
		}
		if name == "postconf" && len(args) > 1 && args[0] == "-h" {
			return []byte("10240000"), nil
		}
		return nil, nil
	})

	err := applyPostfixSettings(ServerSettings{MaxMessageSizeMB: 25}, nil)
	if err == nil {
		t.Fatal("a failing postfix check was reported as success")
	}

	joined := strings.Join(*recorded, "\n")
	if !strings.Contains(joined, "postconf -h message_size_limit") {
		t.Error("the previous value was never read, so there was nothing to roll back to")
	}
	if !strings.Contains(joined, "postconf -e message_size_limit=10240000") {
		t.Errorf("the previous value was not restored:\n%s", joined)
	}
	if strings.Count(joined, "postfix reload") == 0 {
		t.Error("the rollback never reloaded, so the restored value is not running")
	}
}

// The whole point is that the change reaches the running server, not just
// main.cf.
func TestAcceptedSettingsAreReloaded(t *testing.T) {
	recorded := stubPostfix(t, func(string, ...string) ([]byte, error) { return nil, nil })

	if err := applyPostfixSettings(ServerSettings{MaxMessageSizeMB: 25}, []string{"zen.spamhaus.org"}); err != nil {
		t.Fatalf("applyPostfixSettings: %v", err)
	}
	joined := strings.Join(*recorded, "\n")
	if !strings.Contains(joined, "message_size_limit=26214400") {
		t.Errorf("the size was not written in bytes:\n%s", joined)
	}
	if !strings.Contains(joined, "reject_rbl_client zen.spamhaus.org") {
		t.Errorf("the blocklist zone did not reach the restriction:\n%s", joined)
	}
	if !strings.Contains(joined, "postfix reload") {
		t.Errorf("the change was never reloaded:\n%s", joined)
	}
}

// 0 means the panel does not manage the size, so installing this release must
// not change the limit a running server already has.
func TestZeroMessageSizeLeavesPostfixAlone(t *testing.T) {
	recorded := stubPostfix(t, func(string, ...string) ([]byte, error) { return nil, nil })

	if err := applyPostfixSettings(ServerSettings{}, nil); err != nil {
		t.Fatalf("applyPostfixSettings: %v", err)
	}
	for _, call := range *recorded {
		if strings.Contains(call, "-e message_size_limit") {
			t.Errorf("the size limit was written even though the panel does not manage it: %q", call)
		}
	}
}
