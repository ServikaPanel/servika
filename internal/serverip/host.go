package serverip

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const commandTimeout = 20 * time.Second

// run executes a fixed binary with separate arguments, never a shell.
func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	// #nosec G204 -- fixed binary; every argument is either a constant or a
	// value ValidateNew/ValidInterface has already accepted.
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// HostAddresses returns every address the host currently carries.
//
// This asks the HOST, never the panel's table. The table records what the panel
// added; it is not a description of the server, and an address configured
// outside the panel is exactly the one that must not be missed.
func HostAddresses(ctx context.Context) ([]Address, error) {
	out, err := run(ctx, "ip", "-o", "addr", "show")
	if err != nil {
		return nil, refuse(ReasonUnreadable, "the host's addresses could not be read: %s", strings.TrimSpace(out))
	}
	return ParseIPOutput(out), nil
}

// AddToHost puts an address on an interface with a panel label.
//
// It is a RUNTIME change: the kernel forgets it at the next boot, which is what
// the persistence unit in persist.go exists for. Writing the unit without
// making the change live, or the reverse, would leave the screen and the server
// disagreeing until somebody rebooted to find out which was right.
func AddToHost(ctx context.Context, ip net.IP, prefix int, device, label string) error {
	if !ValidInterface(device) {
		return refuse(ReasonUnknownIface, "%q is not an interface name", device)
	}
	if !strings.HasPrefix(label, labelPrefix) || len(label) > maxLabelLength {
		return fmt.Errorf("refusing to write the label %q", label)
	}
	cidr := fmt.Sprintf("%s/%d", ip.String(), prefix)
	out, err := run(ctx, "ip", "addr", "add", cidr, "dev", device, "label", label)
	if err != nil {
		return refuse(ReasonUnreadable, "the address could not be added: %s", strings.TrimSpace(out))
	}
	return nil
}

// RemoveFromHost takes an address off an interface.
func RemoveFromHost(ctx context.Context, address Address) error {
	if !ValidInterface(address.Interface) {
		return refuse(ReasonUnknownIface, "%q is not an interface name", address.Interface)
	}
	cidr := fmt.Sprintf("%s/%d", address.IP, address.Prefix)
	out, err := run(ctx, "ip", "addr", "del", cidr, "dev", address.Interface)
	if err != nil {
		return refuse(ReasonUnreadable, "the address could not be removed: %s", strings.TrimSpace(out))
	}
	return nil
}

// BoundAddresses returns the addresses something on this host is LISTENING on.
//
// It reads /proc/net/tcp and /proc/net/tcp6 rather than running "ss", so there
// is no output format to keep up with and no binary that has to be installed.
//
// A wildcard bind (0.0.0.0 or ::) means the listener answers on every address
// the host has, including ones added after it started, so it pins no particular
// address and contributes nothing here. That is why this guard is the WEAKER of
// the two: a stock install binds the wildcard everywhere, and the rule that
// actually keeps an operator's access is the panel label.
//
// A read failure is an ERROR, never an empty set. An empty set reads as
// "nothing is bound", which is the answer that permits every removal, and the
// one case where being wrong locks somebody out of their own machine.
func BoundAddresses() (map[string]bool, error) {
	bound := map[string]bool{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		file, err := os.Open(path) // #nosec G304 -- both paths are constants.
		if err != nil {
			if os.IsNotExist(err) && path == "/proc/net/tcp6" {
				// A kernel booted without IPv6 has no tcp6 file at all. That is
				// not a failed reading: there is nothing to read.
				continue
			}
			return nil, refuse(ReasonUnreadable, "%s could not be read: %v", path, err)
		}
		err = scanListeners(file, bound)
		_ = file.Close()
		if err != nil {
			return nil, err
		}
	}
	return bound, nil
}

// listenState is TCP_LISTEN as /proc/net/tcp spells it.
const listenState = "0A"

func scanListeners(source io.Reader, bound map[string]bool) error {
	scanner := bufio.NewScanner(source)
	scanner.Scan() // the header row
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[3] != listenState {
			continue
		}
		local, _, found := strings.Cut(fields[1], ":")
		if !found {
			continue
		}
		ip, ok := decodeProcAddress(local)
		if !ok || ip.IsUnspecified() {
			// A wildcard bind pins no address, so it is not evidence about any.
			continue
		}
		bound[ip.String()] = true
	}
	return scanner.Err()
}

// decodeProcAddress reads the hex address form /proc/net/tcp uses.
//
// The bytes are written in the host's own order, so on every platform this runs
// on each 32-bit word is REVERSED. Reading it straight gives a valid-looking
// address that is not the one bound, which here would mean protecting the wrong
// address and permitting the removal of the right one.
func decodeProcAddress(text string) (net.IP, bool) {
	raw, err := hex.DecodeString(text)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return nil, false
	}
	for start := 0; start < len(raw); start += 4 {
		word := raw[start : start+4]
		word[0], word[1], word[2], word[3] = word[3], word[2], word[1], word[0]
	}
	return net.IP(raw), true
}

// ListenPort reports the port the panel was configured to listen on, for the
// message the screen shows beside a refusal.
func ListenPort(listen string) int {
	_, portText, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return 0
	}
	return port
}
