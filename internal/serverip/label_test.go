package serverip

import "testing"

// iproute2 prints the address FLAGS as BARE words between the scope value and
// the label. The reader used to accept a bare trailing word only when exactly
// one field remained, so every flagged address lost its label.
//
// The consequence is not cosmetic. PanelAdded is derived from the label, so an
// address this panel added reported as not panel-added, and Removable then
// refused to remove it. NextLabel builds its taken-set from the same label, so
// the next address was handed a name already in use.
func TestTheLabelIsReadPastTheKernelAddressFlags(t *testing.T) {
	// The shape a real iproute2 v7.0.0 prints when the added address carries the
	// same mask and network as one already on the device.
	const flagged = "2: eth0    inet 192.168.215.9/24 scope global secondary panel-0002\\       valid_lft forever preferred_lft forever"

	addresses := ParseIPOutput(flagged)
	if len(addresses) != 1 {
		t.Fatalf("parsed %d addresses, want 1", len(addresses))
	}
	if addresses[0].Label != "panel-0002" {
		t.Errorf("label = %q, want panel-0002", addresses[0].Label)
	}
	if !addresses[0].PanelAdded {
		t.Error("an address this panel added is reported as not panel-added, so it can never be removed")
	}
}

func TestLabelFromTailReadsPastEveryFlagAndKeyedPair(t *testing.T) {
	cases := []struct {
		name string
		tail []string
		want string
	}{
		{"no tail at all", nil, ""},
		{"label alone", []string{"panel-0001"}, "panel-0001"},
		{"one flag then the label", []string{"secondary", "panel-0002"}, "panel-0002"},
		{"two flags then the label", []string{"secondary", "noprefixroute", "panel-0003"}, "panel-0003"},
		{"a keyed pair then the label", []string{"proto", "kernel_ll", "panel-0004"}, "panel-0004"},
		{"a flag with no label", []string{"secondary"}, ""},
		{"a keyed pair with no label", []string{"proto", "kernel_ll"}, ""},
		{"an interface alias label", []string{"secondary", "eth0:2"}, "eth0:2"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := labelFromTail(test.tail); got != test.want {
				t.Errorf("labelFromTail(%v) = %q, want %q", test.tail, got, test.want)
			}
		})
	}
}

// The direction that must stay safe: an address the panel did NOT add must never
// read as panel-added, because that is the answer that permits a removal.
func TestAnUnlabelledAddressStaysNotPanelAdded(t *testing.T) {
	const provider = "2: eth0    inet 203.0.113.5/24 brd 203.0.113.255 scope global eth0\\       valid_lft forever preferred_lft forever"

	addresses := ParseIPOutput(provider)
	if len(addresses) != 1 {
		t.Fatalf("parsed %d addresses, want 1", len(addresses))
	}
	if addresses[0].PanelAdded {
		t.Error("the provider's own address reads as panel-added, which would offer it for removal")
	}
}

// An IPv6 address carries no label, so it must never read as panel-added
// whatever word stands last.
func TestAnIPv6AddressIsNeverPanelAdded(t *testing.T) {
	const v6 = "2: eth0    inet6 2001:db8::1/64 scope global secondary\\       valid_lft forever preferred_lft forever"

	addresses := ParseIPOutput(v6)
	if len(addresses) != 1 {
		t.Fatalf("parsed %d addresses, want 1", len(addresses))
	}
	if addresses[0].PanelAdded {
		t.Error("an IPv6 address reads as panel-added")
	}
}

// NextLabel reads the taken-set from the parsed labels, so a label the parser
// drops is handed out a second time and two addresses become indistinguishable
// to every later removal.
func TestNextLabelSeesALabelOnAFlaggedAddress(t *testing.T) {
	const flagged = "2: eth0    inet 192.168.215.9/24 scope global secondary panel-0001\\       valid_lft forever"

	label, err := NextLabel(ParseIPOutput(flagged))
	if err != nil {
		t.Fatalf("NextLabel() = %v", err)
	}
	if label == "panel-0001" {
		t.Error("NextLabel handed out a label already in use on a flagged address")
	}
}
