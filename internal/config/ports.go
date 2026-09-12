package config

// The tenant application port range, in ONE place.
//
// Four packages need it and they cannot share it through the package that
// allocates from it: internal/apps depends on internal/provisioner, so
// provisioner importing apps is a cycle. Each therefore wrote the literal
// again, and only the firewall copy was ever held to the allocator by a test.
//
// The three uses give the same numbers three different meanings, and a drift
// between any two of them is a fault nobody sees until it bites:
//
//   - internal/apps allocates from the range.
//   - internal/firewall DROPS every port in it, with no way to open one.
//   - internal/panelport REFUSES to move the panel into it, because a panel
//     there answers on loopback and nowhere else: the operator's browser times
//     out, with nothing in any log to say why.
//   - internal/provisioner refuses to render a proxy block pointing outside it,
//     so a hand-edited row cannot make nginx proxy to a service the panel does
//     not manage.
//
// internal/config is the leaf all four already import, so this is the one place
// that costs nobody a new dependency.
const (
	// AppPortMin and AppPortMax sit BELOW the default ephemeral range
	// (net.ipv4.ip_local_port_range = 32768 60999) so an outgoing connection can
	// never take a port an application is meant to hold.
	AppPortMin = 30000
	AppPortMax = 30999

	// EphemeralPortMin is the bottom of the kernel's default ephemeral range.
	// The application range has to stay clear of it; TestTheApplicationRange
	// keeps that true.
	EphemeralPortMin = 32768
)
