package serverip

import (
	"net"
	"os"
	"testing"
)

func hostAddresses(t *testing.T) []Address {
	t.Helper()
	raw, err := os.ReadFile("testdata/ip-o-addr-show.txt")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	return ParseIPOutput(string(raw))
}

func find(t *testing.T, addresses []Address, ip string) Address {
	t.Helper()
	for _, address := range addresses {
		if address.IP == ip {
			return address
		}
	}
	t.Fatalf("%s is in the captured output but was not parsed", ip)
	return Address{}
}

// The fixture is a real capture from an AlmaLinux 10 kernel, not a hand-written
// sample. A sample written from memory agrees with the parser by construction,
// which is the one thing a parser test must not do, and it would not contain
// the three shapes below that each broke a naive reader.
func TestTheRealKernelOutputIsRead(t *testing.T) {
	addresses := hostAddresses(t)
	if len(addresses) < 8 {
		t.Fatalf("only %d addresses parsed from the capture", len(addresses))
	}

	// A /32 with a label, which is what this package adds.
	panelAddress := find(t, addresses, "198.51.100.7")
	if panelAddress.Label != "panel-0003" || panelAddress.Prefix != 32 ||
		panelAddress.Interface != "servika0" || !panelAddress.PanelAdded {
		t.Errorf("panel address parsed as %+v", panelAddress)
	}

	// An operator's own alias: labelled, but not by this panel.
	operatorAddress := find(t, addresses, "192.0.2.11")
	if operatorAddress.Label != "operator-alias" || operatorAddress.PanelAdded {
		t.Errorf("an operator alias parsed as %+v", operatorAddress)
	}
}

// The primary address of a real interface carries "brd <address>" between the
// CIDR and "scope". A reader that took fields by position is right on a /32 and
// wrong on every primary address, which is the one it must never misread.
func TestTheBroadcastFieldDoesNotShiftTheReading(t *testing.T) {
	addresses := hostAddresses(t)
	primary := find(t, addresses, "192.168.215.4")
	if primary.Prefix != 24 {
		t.Errorf("prefix read as %d, the capture says 24", primary.Prefix)
	}
	if primary.Scope != "global" {
		t.Errorf("scope read as %q, the capture says global", primary.Scope)
	}
	if primary.Label != "eth0" {
		t.Errorf("label read as %q, the capture says eth0", primary.Label)
	}
	if primary.PanelAdded {
		t.Error("a provider-configured primary address was read as panel-added")
	}
}

// The kernel DISCARDS the label on an IPv6 address (measured: "ip addr add
// fd00::1/128 dev lo label panel-0001" is accepted and the address comes back
// with no label at all). That is why this package is IPv4 only: the rule that
// only the panel's own addresses may be removed has nothing to stand on for
// IPv6, so no IPv6 address may ever read as panel-added.
func TestNoIPv6AddressIsEverPanelAdded(t *testing.T) {
	for _, address := range hostAddresses(t) {
		if net.ParseIP(address.IP).To4() != nil {
			continue
		}
		if address.PanelAdded {
			t.Errorf("%s was read as panel-added, but the kernel gives IPv6 no label to prove it", address.IP)
		}
	}
	// And an IPv6 address is refused on the write path with its own code.
	_, err := ValidateNew("2001:db8::1", 128)
	if got := ReasonOf(err); got != ReasonNotIPv4 {
		t.Errorf("adding an IPv6 address was refused as %q, want %q", got, ReasonNotIPv4)
	}
}

// The family check is what makes the rule above hold even when the label is
// there. Today's kernel never produces this line, which is the point: this
// package adds no IPv6 address, so a panel-looking label on one did NOT come
// from here, and reading it as proof of provenance would let the panel remove
// an address it never added. A future kernel that started honouring the label
// would produce exactly this, and the mistake would then be silent.
func TestALabelledIPv6AddressIsStillNotPanelAdded(t *testing.T) {
	crafted := "3: servika0    inet6 2001:db8::99/64 scope global panel-0003\\       valid_lft forever\n"
	parsed := ParseIPOutput(crafted)
	if len(parsed) != 1 {
		t.Fatalf("the crafted line parsed into %d addresses", len(parsed))
	}
	if parsed[0].Label != "panel-0003" {
		t.Fatalf("the label was not read at all: %+v", parsed[0])
	}
	if parsed[0].PanelAdded {
		t.Error("an IPv6 address carrying a panel label was read as panel-added; this package never adds one")
	}
	if err := Removable(parsed[0], nil); err == nil {
		t.Error("a labelled IPv6 address was offered for removal")
	}
}

// The same address can sit on two interfaces at once, which the capture has.
// Losing the interface would make a removal act on whichever one came first.
func TestAnAddressOnTwoInterfacesKeepsBoth(t *testing.T) {
	var found []string
	for _, address := range hostAddresses(t) {
		if address.IP == "192.0.2.10" {
			found = append(found, address.Interface)
		}
	}
	if len(found) != 2 {
		t.Errorf("192.0.2.10 is on two interfaces in the capture, parsed %v", found)
	}
}

// The rule that keeps an operator's access to their own machine. The primary
// address the provider configured carries no panel label, so it is not this
// panel's to take away.
func TestAnAddressThePanelDidNotAddCannotBeRemoved(t *testing.T) {
	addresses := hostAddresses(t)
	for _, ip := range []string{"192.168.215.4", "192.0.2.10", "192.0.2.11", "127.0.0.1"} {
		if err := Removable(find(t, addresses, ip), nil); err == nil {
			t.Errorf("%s is not panel-added but was offered for removal", ip)
		} else if got := ReasonOf(err); got != ReasonNotOurs && got != ReasonReserved {
			t.Errorf("%s refused as %q", ip, got)
		}
	}
	// The panel's own addresses ARE removable, or the guard proves nothing.
	for _, ip := range []string{"198.51.100.7", "198.51.100.8"} {
		if err := Removable(find(t, addresses, ip), nil); err != nil {
			t.Errorf("%s was added by this panel but cannot be removed: %v", ip, err)
		}
	}
}

// The second, weaker guard: an operator who pinned the panel to one address
// must not be able to take that address away.
func TestTheAddressThePanelListensOnCannotBeRemoved(t *testing.T) {
	address := find(t, hostAddresses(t), "198.51.100.7")
	bound := map[string]bool{"198.51.100.7": true}
	err := Removable(address, bound)
	if got := ReasonOf(err); got != ReasonBound {
		t.Errorf("removing the bound address was refused as %q, want %q", got, ReasonBound)
	}
}

// A label is picked against what the HOST carries, not against the panel's own
// table. A restored database can be missing a row for an address the host still
// has, and reusing its label would leave two addresses this cannot tell apart.
func TestALabelAlreadyOnTheHostIsNotReused(t *testing.T) {
	addresses := hostAddresses(t)
	label, err := NextLabel(addresses)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		if address.Label == label {
			t.Errorf("%s is already on the host but was picked again", label)
		}
	}
	if len(label) > maxLabelLength {
		t.Errorf("%q is %d bytes, over the kernel's 15-byte limit", label, len(label))
	}
}

// An address nobody can be reached on is never offered, on either path.
func TestReservedAddressesAreNotOffered(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "0.0.0.0", "169.254.1.1", "224.0.0.1"} {
		if Assignable(net.ParseIP(value)) {
			t.Errorf("%s was treated as assignable", value)
		}
		if _, err := ValidateNew(value, 32); err == nil {
			t.Errorf("%s was accepted for adding", value)
		}
	}
	// A routable address IS accepted, or the check above proves nothing.
	if _, err := ValidateNew("198.51.100.9", 32); err != nil {
		t.Errorf("a routable address was refused: %v", err)
	}
}

// The prefix reaches an "ip addr add" argument, so it is range-checked rather
// than clamped: a value the kernel refuses must come back as a refusal the
// operator can read, not as a number they did not type.
func TestAnImpossiblePrefixIsRefusedRatherThanClamped(t *testing.T) {
	for _, prefix := range []int{-1, 0, 33, 128, 999} {
		_, err := ValidateNew("198.51.100.9", prefix)
		if got := ReasonOf(err); got != ReasonBadPrefix {
			t.Errorf("prefix %d refused as %q, want %q", prefix, got, ReasonBadPrefix)
		}
	}
}

// The interface name reaches an "ip addr" argument.
func TestAnInterfaceNameIsCheckedBeforeItReachesArgv(t *testing.T) {
	for _, name := range []string{"eth0", "servika0", "eno1", "bond0.100", "br-x"} {
		if !ValidInterface(name) {
			t.Errorf("%q is a name the kernel could produce but was refused", name)
		}
	}
	for _, name := range []string{
		"", ".", "..", "eth0 ", "eth0;reboot", "$(id)", "-x",
		"aaaaaaaaaaaaaaaaaaaa", "eth0\nrm",
	} {
		if ValidInterface(name) {
			t.Errorf("%q was accepted as an interface name", name)
		}
	}
}
