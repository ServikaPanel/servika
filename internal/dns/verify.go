// verify.go checks whether a domain's DNS records are ACTUALLY published
// (delegation, A, MX, SPF, DKIM, DMARC).
//
// The queries go to a PUBLIC recursive resolver, never to the panel's own BIND.
// The panel may generate a zone locally while the domain is in fact delegated
// to another provider (Cloudflare, the registrar, ...), in which case the local
// zone is never used by anyone. Asking 127.0.0.1 and reporting "OK" would
// produce exactly the confusion this screen exists to end: the panel says the
// record is there while the world cannot see it.
//
// Every message is a stable reason code rather than prose. The API is English
// and the interface ships 12 languages, so the wording belongs to the frontend.
package dns

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"servika/internal/config"
	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

// verifyTimeout bounds all checks together so a dead resolver cannot leave the
// panel request hanging. It allows for the mail port dials as well, which each
// wait out a filtered port rather than being refused at once.
const verifyTimeout = 20 * time.Second

// Check status values; the frontend colours the rows from these.
const (
	StatusOK      = "ok"
	StatusWarning = "warning"
	StatusError   = "error"
)

// Check is the result of one DNS check. Key names the check, Reason names the
// outcome; the frontend turns both into localized text.
type Check struct {
	Key      string `json:"key"` // ns | a | aaaa | mail_a | mail_aaaa | mx | spf | dkim | dmarc | ptr | mail_ports
	Host     string `json:"host,omitempty"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	Expected string `json:"expected,omitempty"`
	Found    string `json:"found,omitempty"`
}

// VerifyResult carries every check plus a summary.
type VerifyResult struct {
	DomainName string  `json:"domain_name"`
	Checks     []Check `json:"checks"`
	OK         int     `json:"ok_count"`
	Warnings   int     `json:"warning_count"`
	Errors     int     `json:"error_count"`
}

// Verify answers GET /domains/{id}/dns/verify.
func (h *Handlers) Verify(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var domainName, ipv4, ipv6 string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name, COALESCE(ipv4,''), COALESCE(ipv6,'') FROM domains WHERE id=?`, id).Scan(&domainName, &ipv4, &ipv6); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	// Derived from the request context on purpose: these are read-only lookups
	// with no side effects, so a caller that gives up should stop the work.
	ctx, cancel := context.WithTimeout(r.Context(), verifyTimeout)
	defer cancel()
	httpx.WriteJSON(w, http.StatusOK, RunVerification(ctx, h.DB, publicResolver(), id, domainName, ipv4, ipv6))
}

// publicResolver returns a resolver that queries a public recursive server
// rather than whatever /etc/resolv.conf points at. The panel host runs an
// authoritative BIND for the domains it hosts, so the system resolver could
// answer from the local zone and hide the very mismatch being looked for.
func publicResolver() *net.Resolver {
	server := config.DNSVerifyResolver()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 4 * time.Second}
			return dialer.DialContext(ctx, network, server)
		},
	}
}

// RunVerification executes the checks in order and summarizes them.
func RunVerification(ctx context.Context, db *sql.DB, resolver *net.Resolver, domainID int64, domainName, ipv4, ipv6 string) VerifyResult {
	result := VerifyResult{DomainName: domainName, Checks: []Check{}}
	ns1, ns2 := NameserverPair(ctx, db, domainID, domainName)
	result.Checks = append(result.Checks,
		checkDelegation(ctx, resolver, domainName, ns1, ns2),
		checkApexAddress(ctx, resolver, domainName, ipv4),
		checkMailAddress(ctx, resolver, domainName, ipv4),
		checkMX(ctx, resolver, domainName),
		checkSPF(ctx, resolver, domainName, ipv4),
		checkDKIM(ctx, resolver, db, domainID, domainName),
		checkDMARC(ctx, resolver, domainName),
		// Neither of these is a record in the domain's own zone, which is why
		// they were missing: reverse DNS belongs to whoever owns the address, and
		// a listening port is not DNS at all. Both decide whether mail this
		// server sends is accepted, so a screen that says "your mail DNS is fine"
		// without them is answering a narrower question than the one being asked.
		checkPTR(ctx, resolver, ipv4),
		checkMailPorts(ctx, ipv4),
	)
	// The AAAA checks report nothing at all on a domain that uses no IPv6 and
	// publishes none, so they are appended only when they have something to
	// say. An IPv4-only install must not read as misconfigured.
	for _, check := range []*Check{
		checkAddressIPv6(ctx, resolver, "aaaa", domainName, ipv6),
		checkAddressIPv6(ctx, resolver, "mail_aaaa", "mail."+domainName, ipv6),
	} {
		if check != nil {
			result.Checks = append(result.Checks, *check)
		}
	}
	for _, check := range result.Checks {
		switch check.Status {
		case StatusOK:
			result.OK++
		case StatusWarning:
			result.Warnings++
		default:
			result.Errors++
		}
	}
	return result
}

// lookupFailureReason separates "the name does not exist" from "the lookup
// itself failed", so a broken resolver is never reported as a missing record.
func lookupFailureReason(err error, missing string) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return missing
	}
	return "unreadable"
}

// checkDelegation answers whether the domain is really delegated to this
// panel's nameservers. If it is not, every other check below is measuring
// ANOTHER provider's records rather than the zone this panel writes.
func checkDelegation(ctx context.Context, resolver *net.Resolver, domainName, ns1, ns2 string) Check {
	check := Check{Key: "ns", Host: domainName, Expected: ns1 + ", " + ns2}
	servers, err := resolver.LookupNS(ctx, domainName)
	if err != nil || len(servers) == 0 {
		check.Status = StatusError
		check.Reason = lookupFailureReason(err, "missing")
		return check
	}
	var names []string
	ours := 0
	for _, server := range servers {
		name := strings.ToLower(strings.TrimSuffix(server.Host, "."))
		names = append(names, name)
		if name == ns1 || name == ns2 {
			ours++
		}
	}
	check.Found = strings.Join(names, ", ")
	switch {
	case ours >= 2:
		check.Status = StatusOK
	case ours == 1:
		check.Status = StatusWarning
		check.Reason = "partial"
	default:
		// Keeping DNS at another provider can be deliberate, and everything
		// works if the records are right there, so this is a warning rather
		// than an error. It still has to be said: edits made in this panel
		// never reach the public zone.
		check.Status = StatusWarning
		check.Reason = "elsewhere"
	}
	return check
}

func checkApexAddress(ctx context.Context, resolver *net.Resolver, domainName, ipv4 string) Check {
	check := Check{Key: "a", Host: domainName, Expected: ipv4}
	addresses, err := resolver.LookupIPAddr(ctx, domainName)
	if err != nil || len(addresses) == 0 {
		check.Status = StatusError
		check.Reason = lookupFailureReason(err, "missing")
		return check
	}
	check.Found = joinAddresses(addresses)
	if containsIP(addresses, ipv4) {
		check.Status = StatusOK
	} else {
		check.Status = StatusWarning
		check.Reason = "elsewhere"
	}
	return check
}

// checkMailAddress verifies the MX target resolves. mail.<domain> exists as the
// delivery address for mail, not as a web interface.
func checkMailAddress(ctx context.Context, resolver *net.Resolver, domainName, ipv4 string) Check {
	host := "mail." + domainName
	check := Check{Key: "mail_a", Host: host, Expected: ipv4}
	addresses, err := resolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		check.Status = StatusError
		check.Reason = lookupFailureReason(err, "missing")
		return check
	}
	check.Found = joinAddresses(addresses)
	if containsIP(addresses, ipv4) {
		check.Status = StatusOK
	} else {
		check.Status = StatusWarning
		check.Reason = "elsewhere"
	}
	return check
}

func checkMX(ctx context.Context, resolver *net.Resolver, domainName string) Check {
	expected := "mail." + domainName
	check := Check{Key: "mx", Host: domainName, Expected: expected}
	records, err := resolver.LookupMX(ctx, domainName)
	if err != nil || len(records) == 0 {
		check.Status = StatusError
		check.Reason = lookupFailureReason(err, "missing")
		return check
	}
	var names []string
	found := false
	for _, record := range records {
		name := strings.ToLower(strings.TrimSuffix(record.Host, "."))
		names = append(names, strconv.Itoa(int(record.Pref))+" "+name)
		if name == expected {
			found = true
		}
	}
	check.Found = strings.Join(names, ", ")
	if found {
		check.Status = StatusOK
	} else {
		check.Status = StatusWarning
		check.Reason = "elsewhere"
	}
	return check
}

// checkSPF looks for v=spf1 in the apex TXT records and whether it authorizes
// this server.
func checkSPF(ctx context.Context, resolver *net.Resolver, domainName, ipv4 string) Check {
	check := Check{Key: "spf", Host: domainName, Expected: "v=spf1 ... ip4:" + ipv4 + " ..."}
	records, err := resolver.LookupTXT(ctx, domainName)
	if err != nil {
		check.Status = StatusError
		check.Reason = lookupFailureReason(err, "missing")
		return check
	}
	var found []string
	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(record)), "v=spf1") {
			found = append(found, record)
		}
	}
	if len(found) == 0 {
		check.Status = StatusError
		check.Reason = "missing"
		return check
	}
	// More than one SPF record makes SPF INVALID altogether (RFC 7208). It is a
	// silent delivery failure, so it is reported as an error of its own.
	if len(found) > 1 {
		check.Status = StatusError
		check.Reason = "multiple"
		check.Found = strings.Join(found, " | ")
		return check
	}
	check.Found = found[0]
	record := strings.ToLower(found[0])
	if (ipv4 != "" && strings.Contains(record, "ip4:"+ipv4)) ||
		hasSPFMechanism(record, "a") || hasSPFMechanism(record, "mx") {
		check.Status = StatusOK
	} else {
		check.Status = StatusWarning
		check.Reason = "unauthorized"
	}
	return check
}

// hasSPFMechanism reports whether an SPF mechanism is present as a whole term.
// Substring matching would find the "a" inside "ip4:..." and pass an SPF record
// that authorizes nothing.
func hasSPFMechanism(record, mechanism string) bool {
	for _, term := range strings.Fields(record) {
		term = strings.TrimLeft(term, "+-~?")
		if term == mechanism || strings.HasPrefix(term, mechanism+":") || strings.HasPrefix(term, mechanism+"/") {
			return true
		}
	}
	return false
}

// checkDKIM compares the PUBLISHED public key against the one the panel
// generated. Merely having a TXT record is not enough: an old or foreign key
// leaves every signature unverifiable.
func checkDKIM(ctx context.Context, resolver *net.Resolver, db *sql.DB, domainID int64, domainName string) Check {
	selector := "default"
	var stored string
	if err := db.QueryRowContext(ctx,
		`SELECT dkim_selector FROM dns_template_meta WHERE id=1`).Scan(&stored); err == nil && strings.TrimSpace(stored) != "" {
		selector = strings.TrimSpace(stored)
	}
	host := selector + "._domainkey." + domainName
	check := Check{Key: "dkim", Host: host}

	var publicKey string
	if err := db.QueryRowContext(ctx,
		`SELECT public_key FROM dkim_keys WHERE domain_id=? AND selector=?`,
		domainID, selector).Scan(&publicKey); err != nil || publicKey == "" {
		check.Status = StatusWarning
		check.Reason = "no_key"
		return check
	}
	check.Expected = "p=" + shortenKey(publicKey)

	records, err := resolver.LookupTXT(ctx, host)
	if err != nil || len(records) == 0 {
		check.Status = StatusError
		check.Reason = lookupFailureReason(err, "missing")
		return check
	}
	// A resolver may split a long TXT record into chunks; join them back.
	published := publicKeyFromTXT(strings.Join(records, ""))
	check.Found = "p=" + shortenKey(published)
	if published == publicKey {
		check.Status = StatusOK
	} else {
		check.Status = StatusError
		check.Reason = "mismatch"
	}
	return check
}

// publicKeyFromTXT extracts the p= value from a DKIM TXT record. Whitespace is
// stripped because some DNS providers store the long key with spaces in it.
func publicKeyFromTXT(txt string) string {
	for _, part := range strings.Split(txt, ";") {
		part = strings.TrimSpace(part)
		if after, ok := strings.CutPrefix(part, "p="); ok {
			return strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "").Replace(after)
		}
	}
	return ""
}

func shortenKey(key string) string {
	if len(key) <= 24 {
		return key
	}
	return key[:12] + "..." + key[len(key)-8:]
}

func checkDMARC(ctx context.Context, resolver *net.Resolver, domainName string) Check {
	host := "_dmarc." + domainName
	check := Check{Key: "dmarc", Host: host, Expected: "v=DMARC1; p=..."}
	records, err := resolver.LookupTXT(ctx, host)
	if err != nil || len(records) == 0 {
		check.Status = StatusWarning
		check.Reason = lookupFailureReason(err, "missing")
		return check
	}
	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(record)), "v=dmarc1") {
			check.Found = record
			check.Status = StatusOK
			return check
		}
	}
	check.Found = strings.Join(records, " | ")
	check.Status = StatusWarning
	check.Reason = "malformed"
	return check
}

func joinAddresses(addresses []net.IPAddr) string {
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, address.IP.String())
	}
	return strings.Join(values, ", ")
}

func containsIP(addresses []net.IPAddr, value string) bool {
	target := net.ParseIP(value)
	if target == nil {
		return false
	}
	for _, address := range addresses {
		if address.IP.Equal(target) {
			return true
		}
	}
	return false
}
