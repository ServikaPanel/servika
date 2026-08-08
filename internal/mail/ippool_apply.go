package mail

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
)

// Teaching Postfix to send a domain's mail from a chosen address.
//
// Two files are involved. master.cf gains one smtp service per pool address,
// each bound to that address, and a sender-dependent transport table names which
// domain uses which service. Both are managed as a marked block that is replaced
// wholesale, so the operator's own entries above and below are never touched and
// removing every pool address returns the files to what they were.

const (
	masterConfigPath    = "/etc/postfix/master.cf"
	senderTransportPath = "/etc/postfix/servika_sender_transport"
	transportParam      = "sender_dependent_default_transport_maps"

	blockBegin = "# BEGIN servika outbound addresses -- managed by the panel, do not edit"
	blockEnd   = "# END servika outbound addresses"
)

var routingApplyMu sync.Mutex

// ApplyOutboundRouting rewrites both files from the database and asks Postfix to
// accept the result.
//
// A rejected configuration is rolled back in full, because master.cf defines
// every Postfix service: one the daemon will not start with does not degrade
// mail for the domain being edited, it stops mail for the machine.
func ApplyOutboundRouting(ctx context.Context, db *sql.DB) error {
	routingApplyMu.Lock()
	defer routingApplyMu.Unlock()
	if _, err := exec.LookPath("postconf"); err != nil {
		return fmt.Errorf("postfix is not installed")
	}

	addresses, assignments, err := poolAddressesForRouting(ctx, db)
	if err != nil {
		return err
	}

	// #nosec G304 -- fixed system path built from a constant, not from any request value.
	master, err := os.ReadFile(masterConfigPath)
	if err != nil {
		return fmt.Errorf("read master.cf: %w", err)
	}
	// #nosec G304 -- fixed system path built from a constant, not from any request value.
	previousTransport, transportErr := os.ReadFile(senderTransportPath)

	updated := replaceManagedBlock(string(master), renderTransportServices(addresses))
	// #nosec G306 G703 -- fixed system path built from a constant; the Postfix daemon must read it and it holds no secret.
	if err := os.WriteFile(masterConfigPath, []byte(updated), 0o644); err != nil {
		return fmt.Errorf("write master.cf: %w", err)
	}
	// #nosec G306 G703 -- fixed system path built from a constant; the Postfix daemon must read it and it holds no secret.
	if err := os.WriteFile(senderTransportPath, renderSenderTransport(assignments), 0o644); err != nil {
		restoreRouting(master, previousTransport, transportErr)
		return fmt.Errorf("write the sender transport table: %w", err)
	}

	if out, err := postfixCommand("postmap", senderTransportPath); err != nil {
		restoreRouting(master, previousTransport, transportErr)
		return fmt.Errorf("postmap: %s", strings.TrimSpace(string(out)))
	}
	if out, err := postfixCommand("postconf", "-e",
		transportParam+"=hash:"+senderTransportPath); err != nil {
		restoreRouting(master, previousTransport, transportErr)
		return fmt.Errorf("postconf: %s", strings.TrimSpace(string(out)))
	}
	if out, err := postfixCommand("postfix", "check"); err != nil {
		restoreRouting(master, previousTransport, transportErr)
		return fmt.Errorf("postfix check: %s", strings.TrimSpace(string(out)))
	}
	if out, err := postfixCommand("postfix", "reload"); err != nil {
		restoreRouting(master, previousTransport, transportErr)
		return fmt.Errorf("postfix reload: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// restoreRouting puts both files back and reloads, so the configuration running
// is the one that was known to work rather than the one just refused.
func restoreRouting(master, transport []byte, transportErr error) {
	// #nosec G306 G703 -- restoring the file this function just replaced, at the same fixed system path.
	_ = os.WriteFile(masterConfigPath, master, 0o644)
	if transportErr == nil {
		// #nosec G306 G703 -- restoring the file this function just replaced, at the same fixed system path.
		_ = os.WriteFile(senderTransportPath, transport, 0o644)
		_, _ = postfixCommand("postmap", senderTransportPath)
	} else {
		_ = os.Remove(senderTransportPath)
		_ = os.Remove(senderTransportPath + ".db")
		_, _ = postfixCommand("postconf", "-X", transportParam)
	}
	_, _ = postfixCommand("postfix", "reload")
}

// replaceManagedBlock swaps the panel's block in master.cf, or appends it when
// there is none yet. Nothing outside the markers is read or rewritten, so an
// operator's own services survive every apply.
func replaceManagedBlock(master, block string) string {
	begin := strings.Index(master, blockBegin)
	if begin == -1 {
		if !strings.HasSuffix(master, "\n") {
			master += "\n"
		}
		if block == "" {
			return master
		}
		return master + block
	}
	end := strings.Index(master[begin:], blockEnd)
	if end == -1 {
		// A truncated block, most likely from an interrupted write. Everything
		// from the marker on is ours, so replacing it is the correct repair.
		return master[:begin] + block
	}
	tail := master[begin+end+len(blockEnd):]
	tail = strings.TrimPrefix(tail, "\n")
	return master[:begin] + block + tail
}

// renderTransportServices produces one bound smtp service per address.
//
// The shape follows the Postfix documentation for sending from a specific
// address: an extra smtp service in master.cf with the bind address set. An
// empty pool produces an empty block, which removes the services entirely rather
// than leaving dead ones behind.
//
// The parameter differs by FAMILY. Postfix takes smtp_bind_address for IPv4 and
// smtp_bind_address6 for IPv6; feeding an IPv6 address to the first is a
// configuration Postfix refuses, which rolls the whole write back and leaves the
// operator with no working explanation for why adding an address failed.
//
// inet_protocols is pinned on the same service. A transport bound to only one
// family falls back to the DEFAULT source address for the other one, so a domain
// the operator moved onto a specific address would still send from the server's
// main address whenever the recipient answered on the other family. That defeats
// the entire point of assigning an outbound address, and it does so invisibly.
func renderTransportServices(addresses []string) string {
	if len(addresses) == 0 {
		return ""
	}
	var out bytes.Buffer
	out.WriteString(blockBegin)
	out.WriteByte('\n')
	for _, value := range addresses {
		bindParam, protocols := bindParameters(value)
		fmt.Fprintf(&out, "%s unix - - n - - smtp\n  -o %s=%s\n  -o inet_protocols=%s\n  -o syslog_name=postfix/%s\n",
			transportName(value), bindParam, value, protocols, transportName(value))
	}
	out.WriteString(blockEnd)
	out.WriteByte('\n')
	return out.String()
}

// bindParameters returns the Postfix bind parameter and protocol restriction
// for one outbound address.
func bindParameters(value string) (bindParam, protocols string) {
	if ip := net.ParseIP(value); ip != nil && ip.To4() == nil {
		return "smtp_bind_address6", "ipv6"
	}
	return "smtp_bind_address", "ipv4"
}

// renderSenderTransport maps each assigned domain to its transport.
//
// The key is "@domain", which is how Postfix looks up a sender-dependent
// transport by domain, and the order is sorted so an unchanged assignment set
// produces an unchanged file.
func renderSenderTransport(assignments map[string]string) []byte {
	domains := make([]string, 0, len(assignments))
	for domain := range assignments {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	var out bytes.Buffer
	out.WriteString("# Generated by Servika; edit from the panel.\n")
	for _, domain := range domains {
		fmt.Fprintf(&out, "@%s\t%s\n", domain, transportName(assignments[domain]))
	}
	return out.Bytes()
}
