package firewall

import (
	"slices"
	"testing"
)

func TestValidIP(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{in: "", want: false},
		{in: "1.2.3.4", want: true},
		{in: "1.2.3.0/24", want: true},
		{in: "2001:db8::1", want: true},
		{in: "::/0", want: true},
		{in: "999.1.1.1", want: false},
		{in: "garbage", want: false},
	}
	for _, test := range tests {
		if got := validIP(test.in); got != test.want {
			t.Fatalf("validIP(%q) = %t, want %t", test.in, got, test.want)
		}
	}
}

func TestSaddr(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "1.2.3.4", want: "ip saddr 1.2.3.4 "},
		{in: "1.2.3.0/24", want: "ip saddr 1.2.3.0/24 "},
		{in: "2001:db8::1", want: "ip6 saddr 2001:db8::1 "},
		{in: "2001:db8::/32", want: "ip6 saddr 2001:db8::/32 "},
	}
	for _, test := range tests {
		if got := saddr(test.in); got != test.want {
			t.Fatalf("saddr(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}

func TestDport(t *testing.T) {
	tests := []struct {
		proto string
		port  int
		want  string
	}{
		{proto: "tcp", port: 3306, want: "tcp dport 3306 "},
		{proto: "udp", port: 53, want: "udp dport 53 "},
		{proto: "tcp", port: 0, want: ""},
		{proto: "tcp", port: -5, want: ""},
	}
	for _, test := range tests {
		if got := dport(test.proto, test.port); got != test.want {
			t.Fatalf("dport(%q, %d) = %q, want %q", test.proto, test.port, got, test.want)
		}
	}
}

func TestFirewallTemplatesAvoidProtectedPorts(t *testing.T) {
	stubSSHPorts(t, []int{22})
	for name, rules := range firewallTemplates {
		for _, rule := range rules {
			if isProtectedPort(rule.Port) {
				t.Fatalf("template %q targets protected port %d", name, rule.Port)
			}
		}
	}
}

// stubSSHPorts stands in for the host probe so the guard can be tested against a
// server whose SSH has been moved.
func stubSSHPorts(t *testing.T, ports []int) {
	t.Helper()
	previous := sshPorts
	sshPorts = func() []int { return ports }
	t.Cleanup(func() { sshPorts = previous })
}

// The guard has to follow sshd. Protecting a fixed 22 locks the administrator out
// of the port they actually use, and refuses to close the one the panel's own
// warning tells them to close.
func TestProtectedPortFollowsTheRunningSSHPort(t *testing.T) {
	stubSSHPorts(t, []int{2222})
	if !isProtectedPort(2222) {
		t.Error("the port sshd serves is not protected, so closing it locks the administrator out")
	}
	if isProtectedPort(22) {
		t.Error("port 22 stays protected after the move, so the advised cleanup is refused")
	}
	for _, port := range []int{80, 443, 8080, 8443, 53} {
		if !isProtectedPort(port) {
			t.Errorf("port %d lost its protection", port)
		}
	}
}

// A half-finished move keeps both ports in service, and both have to stay closed
// to the firewall screen.
func TestProtectedPortCoversEverySSHPort(t *testing.T) {
	stubSSHPorts(t, []int{22, 2222})
	for _, port := range []int{22, 2222} {
		if !isProtectedPort(port) {
			t.Errorf("port %d is not protected while sshd serves it", port)
		}
	}
	if got := protectedPortList(); !slices.Equal(got, []int{22, 53, 80, 443, 2222, 8080, 8443}) {
		t.Errorf("protectedPortList() = %v", got)
	}
}

// stubPanelPorts stands in for the live reader.
func stubPanelPorts(t *testing.T, ports []int) {
	t.Helper()
	previous := panelPorts
	panelPorts = func() []int { return ports }
	t.Cleanup(func() { panelPorts = previous })
}

// The panel's own ports can MOVE. A hardcoded pair goes on guarding the numbers
// the panel used to be on and leaves the ones it is on now closeable from this
// very screen, which locks the operator out weeks after the change with nothing
// to connect the two events.
func TestProtectionFollowsThePanelWhenItsPortsMove(t *testing.T) {
	stubSSHPorts(t, []int{22})
	stubPanelPorts(t, []int{9090, 9443})

	for _, port := range []int{9090, 9443} {
		if !isProtectedPort(port) {
			t.Errorf("the panel is on port %d but closing it is allowed", port)
		}
	}
	// The old numbers are no longer the panel's, so they are no longer guarded:
	// leaving them protected would grey out ports the operator can now use.
	for _, port := range []int{8080, 8443} {
		if isProtectedPort(port) {
			t.Errorf("port %d is protected although the panel has moved off it", port)
		}
	}
	if got := protectedPortList(); !slices.Equal(got, []int{22, 53, 80, 443, 9090, 9443}) {
		t.Errorf("protectedPortList() = %v", got)
	}
}

// A reading that failed must keep the old guard rather than drop it: an empty
// list would leave every panel port closeable.
func TestAFailedPanelPortReadingKeepsTheDefaultGuard(t *testing.T) {
	stubSSHPorts(t, []int{22})
	SetPanelPorts(nil) // a caller that has nothing to give must not clear it
	for _, port := range []int{8080, 8443} {
		if !isProtectedPort(port) {
			t.Errorf("port %d lost its protection when no reader was supplied", port)
		}
	}
}

// The list never repeats a port, however many sources name it.
func TestTheProtectedListHasNoDuplicates(t *testing.T) {
	stubSSHPorts(t, []int{443})
	stubPanelPorts(t, []int{443, 8443})
	got := protectedPortList()
	seen := map[int]bool{}
	for _, port := range got {
		if seen[port] {
			t.Errorf("port %d appears twice in %v", port, got)
		}
		seen[port] = true
	}
}
