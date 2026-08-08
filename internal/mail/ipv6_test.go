package mail

import (
	"os"
	"strings"
	"testing"
)

// THE proof that an IPv6 pool address produces a configuration Postfix accepts.
//
// Postfix takes smtp_bind_address for IPv4 and smtp_bind_address6 for IPv6.
// Feeding an IPv6 address to the first is a configuration Postfix REFUSES,
// which rolls the whole write back and leaves the operator with no working
// explanation for why adding an address failed.
func TestAnIPv6PoolAddressBindsWithTheIPv6Parameter(t *testing.T) {
	block := renderTransportServices([]string{"2001:db8::5"})

	if !strings.Contains(block, "-o smtp_bind_address6=2001:db8::5") {
		t.Errorf("an IPv6 address did not use smtp_bind_address6:\n%s", block)
	}
	if strings.Contains(block, "-o smtp_bind_address=2001:db8::5") {
		t.Errorf("an IPv6 address was written to the IPv4 parameter, which Postfix refuses:\n%s", block)
	}
}

// The other direction, so the test above cannot be satisfied by a renderer that
// always writes the IPv6 parameter.
func TestAnIPv4PoolAddressStillBindsWithTheIPv4Parameter(t *testing.T) {
	block := renderTransportServices([]string{"203.0.113.5"})

	if !strings.Contains(block, "-o smtp_bind_address=203.0.113.5") {
		t.Errorf("an IPv4 address did not use smtp_bind_address:\n%s", block)
	}
	if strings.Contains(block, "smtp_bind_address6") {
		t.Errorf("an IPv4 address was written to the IPv6 parameter:\n%s", block)
	}
}

// A transport bound to one family must not reach the other.
//
// Without the protocol pin, a service bound to an IPv4 address falls back to
// the DEFAULT source address whenever the recipient answers over IPv6. The
// domain the operator moved onto a dedicated address would then still send from
// the server's main address, invisibly, which defeats the whole feature.
func TestABoundTransportCannotFallThroughToTheOtherFamily(t *testing.T) {
	both := renderTransportServices([]string{"203.0.113.5", "2001:db8::5"})

	for _, want := range []string{"-o inet_protocols=ipv4", "-o inet_protocols=ipv6"} {
		if !strings.Contains(both, want) {
			t.Errorf("missing %q, so a transport could send from the wrong address:\n%s", want, both)
		}
	}
	// Each service pins exactly one family.
	if strings.Count(both, "-o inet_protocols=") != 2 {
		t.Errorf("the protocol pin does not appear once per address:\n%s", both)
	}
}

// The service name has to survive an address full of colons: master.cf splits
// on whitespace and a colon in a service name is not valid there.
func TestAnIPv6TransportNameCarriesNoColon(t *testing.T) {
	name := transportName("2001:db8::5")
	if strings.Contains(name, ":") {
		t.Errorf("transportName(%q) = %q, which master.cf cannot parse", "2001:db8::5", name)
	}
	if name != transportName("2001:db8::5") {
		t.Error("the name is not stable, so every apply would rename the service")
	}
	if name == transportName("2001:db8::6") {
		t.Error("two addresses share a transport name")
	}
}

// An empty pool removes the services rather than leaving dead ones behind.
func TestAnEmptyPoolRendersNothing(t *testing.T) {
	if got := renderTransportServices(nil); got != "" {
		t.Errorf("an empty pool rendered %q", got)
	}
}

// main.cf takes the LAST active assignment, so an early stock line that a later
// managed line overrides must not read as already set. Getting this backwards
// would leave a host on the stock value forever while the heal reported nothing
// to do.
func TestTheLastAssignmentInMainCfWins(t *testing.T) {
	const content = "inet_protocols = ipv4\n" +
		"# ===== servika-mail =====\n" +
		"inet_protocols = all\n"
	if !hasPostfixSetting(content, "inet_protocols", "all") {
		t.Error("the later assignment was not seen")
	}
	if hasPostfixSetting(content, "inet_protocols", "ipv4") {
		t.Error("the overridden stock value was reported as active")
	}
}

// A commented line is not a setting, and a longer key that merely starts with
// the same text is a different setting.
func TestOnlyARealAssignmentCounts(t *testing.T) {
	if hasPostfixSetting("#inet_protocols = all\n", "inet_protocols", "all") {
		t.Error("a commented-out line was read as active")
	}
	if hasPostfixSetting("smtp_address_preference_extra = any\n", "smtp_address_preference", "any") {
		t.Error("a longer key was mistaken for this one")
	}
	if !hasPostfixSetting("smtp_address_preference=any\n", "smtp_address_preference", "any") {
		t.Error("an assignment without spaces was missed")
	}
	if !hasPostfixSetting("inet_protocols = ALL\n", "inet_protocols", "all") {
		t.Error("the value comparison is case-sensitive; postfix values are not")
	}
}

// An operator who bound Dovecot to a specific address keeps that binding: an
// append here could take the service off an address they chose deliberately.
func TestAnOperatorsOwnDovecotListenIsLeftAlone(t *testing.T) {
	if !hasActiveDovecotListen("protocols = imap lmtp\nlisten = 203.0.113.5\n") {
		t.Error("an operator's listen line was not detected, so the heal would overwrite it")
	}
	if hasActiveDovecotListen("protocols = imap lmtp\n# listen = 203.0.113.5\n") {
		t.Error("a commented-out listen line blocked the repair")
	}
	if hasActiveDovecotListen("protocols = imap lmtp\nlisten_extra = x\n") {
		t.Error("a longer key was mistaken for the listen setting")
	}
}

// The shipped Dovecot template and the repair must agree on the line, or a new
// install and a repaired one would differ.
func TestTheRepairWritesTheLineTheTemplateShips(t *testing.T) {
	template, err := os.ReadFile("../../assets/mail/dovecot/10-servika-mail.conf.tmpl")
	if err != nil {
		t.Fatalf("read the shipped Dovecot template: %v", err)
	}
	if !strings.Contains(string(template), dovecotListenLine) {
		t.Errorf("the template does not carry %q, so a repaired host and a fresh one would differ", dovecotListenLine)
	}
}

// The shipped Postfix block and the repair must agree the same way.
func TestTheRepairWritesTheSettingsTheTemplateShips(t *testing.T) {
	template, err := os.ReadFile("../../assets/mail/postfix/main.cf.append")
	if err != nil {
		t.Fatalf("read the shipped Postfix block: %v", err)
	}
	for _, setting := range postfixIPv6Settings {
		if !hasPostfixSetting(string(template), setting.key, setting.value) {
			t.Errorf("the shipped block does not set %s = %s, so a fresh install would differ from a repaired one",
				setting.key, setting.value)
		}
	}
	// The unsafe value must never appear: during an IPv6 outage it makes every
	// message wait out its timeout before falling back to IPv4.
	if hasPostfixSetting(string(template), "smtp_address_preference", "ipv6") {
		t.Error("the shipped block prefers IPv6 for delivery, which Postfix documents as unsafe")
	}
}
