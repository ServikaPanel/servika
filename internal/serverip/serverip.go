// Package serverip adds and removes additional IPv4 addresses on this server.
//
// Everything in this file is PURE: text in, decisions out. The host-side half
// lives in host.go. The split is what lets the two rules that can lock an
// operator out of their own server be tested without a server to lock.
package serverip

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// labelPrefix marks an address as one this panel added.
//
// It is the whole mechanism behind "only the panel's own addresses may be
// removed", and it is readable off the HOST rather than only out of the
// panel's table, which matters because a restored database and a reinstalled
// host disagree in opposite directions.
//
// The kernel limits a label to IFNAMSIZ-1 = 15 bytes, and it does NOT require
// the "<device>:" form that ifconfig-era aliases used (measured on AlmaLinux
// 10: "ip addr add ... label panel-0001" is accepted and reported back
// verbatim).
const labelPrefix = "panel-"

// maxLabelLength is IFNAMSIZ-1.
const maxLabelLength = 15

// Refusal reasons, carried beside the English message because the screen
// renders twelve languages.
const (
	ReasonNotIPv4       = "server_ip_not_ipv4"
	ReasonReserved      = "server_ip_reserved"
	ReasonBadPrefix     = "server_ip_bad_prefix"
	ReasonUnknownIface  = "server_ip_unknown_interface"
	ReasonAlreadyOnHost = "server_ip_already_on_host"
	ReasonNotOurs       = "server_ip_not_added_by_panel"
	ReasonBound         = "server_ip_in_use_by_panel"
	ReasonUnreadable    = "server_ip_host_unreadable"
	ReasonNotFound      = "server_ip_not_found"
	ReasonNoLabelLeft   = "server_ip_no_label_available"
)

// Refusal carries a reason code beside the message.
type Refusal struct {
	Reason  string
	Message string
}

func (r *Refusal) Error() string { return r.Message }

func refuse(reason, format string, args ...any) error {
	return &Refusal{Reason: reason, Message: fmt.Sprintf(format, args...)}
}

// Address is one address the host currently carries.
type Address struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
	Prefix    int    `json:"prefix"`
	// Label is what the kernel reports. For a primary address it is the device
	// name; for an address added with an explicit label it is that label; for
	// every IPv6 address it is empty, because the kernel discards it.
	Label string `json:"label"`
	Scope string `json:"scope"`
	// PanelAdded is the one question the remove path asks.
	PanelAdded bool `json:"panel_added"`
}

// ParseIPOutput reads "ip -o addr show".
//
// Fields are read BY NAME, never by position. The shipped output puts an
// optional "brd <address>" between the CIDR and "scope" on any address that has
// a broadcast address, so a positional reader is right on a /32 and wrong on
// the primary address of every real interface.
//
// IPv6 lines are parsed and returned like any other, because the screen has to
// SHOW them; what it must not do is offer to remove them, and PanelAdded is
// what refuses that, since the kernel gives an IPv6 address no label to carry.
func ParseIPOutput(text string) []Address {
	var out []Address
	for line := range strings.SplitSeq(text, "\n") {
		// "ip -o" joins a record's continuation with a literal backslash.
		if index := strings.Index(line, "\\"); index >= 0 {
			line = line[:index]
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// "1: lo    inet 127.0.0.1/8 scope host lo"
		device := strings.TrimSuffix(fields[1], ":")
		family := fields[2]
		if family != "inet" && family != "inet6" {
			continue
		}
		ip, prefix, ok := splitCIDR(fields[3])
		if !ok {
			continue
		}

		address := Address{Interface: device, IP: ip, Prefix: prefix}
		for index := 4; index < len(fields); index++ {
			if fields[index] == "scope" && index+1 < len(fields) {
				address.Scope = fields[index+1]
				// The label, when there is one, is the LAST field of the
				// record and follows the scope value. Everything after it that
				// the kernel adds ("proto kernel_ll") is a keyed pair, so a
				// bare trailing word is the label and a keyed one is not.
				if tail := fields[index+2:]; len(tail) == 1 {
					address.Label = tail[0]
				}
				break
			}
		}
		address.PanelAdded = family == "inet" && strings.HasPrefix(address.Label, labelPrefix)
		out = append(out, address)
	}
	return out
}

func splitCIDR(value string) (string, int, bool) {
	text, prefixText, found := strings.Cut(value, "/")
	if !found {
		return "", 0, false
	}
	if net.ParseIP(text) == nil {
		return "", 0, false
	}
	prefix, err := strconv.Atoi(prefixText)
	if err != nil || prefix < 0 || prefix > 128 {
		return "", 0, false
	}
	return text, prefix, true
}

// Assignable reports whether an address may be OFFERED at all, on either path.
//
// Loopback, link-local, multicast and the unspecified address are excluded
// because none of them is an address a site can be reached on, and offering
// them would put a remove button next to 127.0.0.1.
func Assignable(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	return true
}

// ValidateNew checks an address a request asked to add.
//
// IPv6 is refused with its OWN reason code rather than being quietly ignored.
// The reason is not scope: the kernel silently DISCARDS the label on an IPv6
// address (measured), so an added IPv6 address is indistinguishable from the
// provider's own, and the rule that only the panel's addresses may be removed
// would have nothing to stand on. An operator told "IPv6 is not supported here"
// can go and add it by hand; an operator whose v6 address was added and then
// could never be removed has been handed a worse server.
func ValidateNew(value string, prefix int) (net.IP, error) {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return nil, refuse(ReasonNotIPv4, "%q is not an IP address", value)
	}
	if ip.To4() == nil {
		return nil, refuse(ReasonNotIPv4, "IPv6 addresses cannot be managed here")
	}
	if !Assignable(ip) {
		return nil, refuse(ReasonReserved, "%s is not an address a server can be reached on", ip)
	}
	if prefix < 1 || prefix > 32 {
		return nil, refuse(ReasonBadPrefix, "a prefix length of %d is not valid for IPv4", prefix)
	}
	return ip.To4(), nil
}

// NextLabel picks a label that is not already on the host.
//
// The candidate set is checked against the HOST rather than against the panel's
// table, for the same reason the whole feature checks both: a restored database
// can be missing a row for an address the host still carries, and reusing its
// label would make two addresses indistinguishable to every later removal.
func NextLabel(existing []Address) (string, error) {
	taken := map[string]bool{}
	for _, address := range existing {
		taken[address.Label] = true
	}
	for index := 1; index <= 9999; index++ {
		candidate := fmt.Sprintf("%s%04d", labelPrefix, index)
		if len(candidate) > maxLabelLength {
			break
		}
		if !taken[candidate] {
			return candidate, nil
		}
	}
	return "", refuse(ReasonNoLabelLeft, "every panel address label is in use")
}

// ValidInterface accepts a device name the kernel could have produced.
//
// The name reaches an "ip addr" argument, so it is checked rather than trusted.
// It is not free text either way: the caller picks it from what the host
// reported, and this refuses anything that could not have come from there.
func ValidInterface(name string) bool {
	if name == "" || len(name) > 15 || name == "." || name == ".." {
		return false
	}
	// The name must START with an alphanumeric. A leading dash reads as a FLAG
	// to "ip", which would let a device name pass an arbitrary option to it.
	// This is the same defect internal/laravel closes on a queue name reaching
	// artisan's argument parser.
	first := name[0]
	if (first < 'a' || first > 'z') && (first < 'A' || first > 'Z') && (first < '0' || first > '9') {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '.', r == '_', r == '-', r == ':':
		default:
			return false
		}
	}
	return true
}

// Removable answers the question the delete path exists to ask.
//
// Three things must all hold, and the FIRST is the real boundary. An address
// the panel did not add carries no panel label, so it cannot be removed here at
// all: the primary address the provider configured is what an operator reaches
// this server through, and taking it away locks them out of the machine with no
// way back that does not involve a console.
//
// bound is a second, weaker guard for an operator who pinned the panel to one
// address. It is weaker because a stock install binds the wildcard, where no
// address is explicitly bound and this check never fires; it is kept because
// when it does fire the address really is the one the panel answers on.
func Removable(address Address, bound map[string]bool) error {
	if !address.PanelAdded {
		return refuse(ReasonNotOurs,
			"%s was not added by this panel, so it is not this panel's to remove", address.IP)
	}
	if bound[address.IP] {
		return refuse(ReasonBound,
			"%s is the address this panel is listening on", address.IP)
	}
	if !Assignable(net.ParseIP(address.IP)) {
		return refuse(ReasonReserved, "%s is not an address this manages", address.IP)
	}
	return nil
}

// ReasonOf returns the stable reason code of a refusal, or "" for anything else.
func ReasonOf(err error) string {
	var refusal *Refusal
	if errors.As(err, &refusal) {
		return refusal.Reason
	}
	return ""
}
