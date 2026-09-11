package provisioner

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A mail client connecting to mail.<domain> is shown whatever certificate the
// mail stack holds. Postfix and Dovecot serve ONE certificate for every domain,
// so that name never matches and every client warns, or silently refuses.
//
// The fix is a certificate per domain covering the mail hostnames, selected at
// connection time by SNI. The WEB certificate is not touched: it is a separate
// order, so nothing here can regress a working site.

// mailCertFile, mailKeyFile and mailChainFile live beside the domain's web
// certificate under the certificate root. The chain file is what Postfix reads
// through its SNI table, and it starts with the private key, so it is 0600.
const (
	mailCertFile  = "mail.crt"
	mailKeyFile   = "mail.key"
	mailChainFile = "mail-chain.pem"
)

// MailHostNames returns the names a mail certificate should cover. mail. is the
// MX target; the other two are the names clients are told to use by habit, and a
// client configured with one of them checks the certificate against it.
//
// pop. is left out because this server does not run POP3 (assets/mail/dovecot
// sets `protocols = imap lmtp`). Every extra name is another host the ACME
// pre-flight has to reach, and a name that fails takes the whole order with it,
// so covering a service that does not exist only costs issuance reliability.
func MailHostNames(domain string) []string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return []string{
		"mail." + domain,
		"smtp." + domain,
		"imap." + domain,
	}
}

// MailCertificate describes what a mail issuance produced.
type MailCertificate struct {
	CertPath  string            `json:"cert_path"`
	KeyPath   string            `json:"key_path"`
	ChainPath string            `json:"chain_path"`
	Hosts     []string          `json:"hosts"`             // names actually covered
	Skipped   map[string]string `json:"skipped,omitempty"` // name → stable reason code
	ExpiresAt string            `json:"expires_at,omitempty"`
}

// MailCertificatePaths returns where a domain's mail certificate lives, whether
// or not it exists yet.
func MailCertificatePaths(domain string) (certPath, keyPath, chainPath string) {
	dir := certSystemDir(strings.ToLower(strings.TrimSpace(domain)))
	return filepath.Join(dir, mailCertFile), filepath.Join(dir, mailKeyFile), filepath.Join(dir, mailChainFile)
}

// IssueMailCertificate orders a Let's Encrypt certificate for the domain's mail
// hostnames and installs it next to the web certificate.
//
// Every name is put through the same challenge pre-flight the web certificate
// uses, because one unvalidatable name fails the whole order. A name that cannot
// answer is reported with its reason code instead of being dropped silently, and
// when NO name answers nothing is ordered at all: an order that cannot succeed
// still spends the CA's per-hostname failure budget.
func IssueMailCertificate(domain string) (MailCertificate, error) {
	if err := ValidateDomain(domain); err != nil {
		return MailCertificate{}, err
	}
	domain = strings.ToLower(strings.TrimSpace(domain))

	hosts, dropped := validatedSANHosts(MailHostNames(domain))
	skipped := map[string]string{}
	for host, reason := range dropped {
		skipped[host] = string(reason)
	}
	if len(hosts) == 0 {
		return MailCertificate{Skipped: skipped},
			fmt.Errorf("no mail hostname of %s could answer the ACME challenge", domain)
	}

	sslDir, err := prepareCertificateDir(domain)
	if err != nil {
		return MailCertificate{Skipped: skipped}, err
	}
	certPath, keyPath, chainPath := MailCertificatePaths(domain)

	args := []string{"--issue", "--webroot", acmeWebrootDir}
	for _, host := range hosts {
		args = append(args, "-d", host)
	}
	args = append(args, "--keylength", "2048")
	if out, e := RunACMEIssue(args...); e != nil && !IsACMERenewSkip(e) {
		return MailCertificate{Skipped: skipped},
			fmt.Errorf("acme issue for the mail hostnames: %s", strings.TrimSpace(string(out)))
	}

	install := []string{
		"--install-cert",
		"-d", hosts[0],
		"--cert-file", certPath,
		"--key-file", keyPath,
		"--fullchain-file", certPath,
	}
	if out, e := acmeCommand(install...).CombinedOutput(); e != nil {
		return MailCertificate{Skipped: skipped},
			fmt.Errorf("acme install-cert for the mail hostnames: %s", strings.TrimSpace(string(out)))
	}
	// acme.sh exiting zero is not proof that the files exist; a missing file here
	// would be discovered later as a mail stack that will not start.
	if !fileExists(certPath) || !fileExists(keyPath) {
		return MailCertificate{Skipped: skipped},
			fmt.Errorf("acme reported success but %s or %s was not written", certPath, keyPath)
	}
	if err := applyCertificatePermissions(sslDir, certPath, keyPath); err != nil {
		return MailCertificate{Skipped: skipped}, err
	}
	if err := writeMailChain(chainPath, certPath, keyPath); err != nil {
		return MailCertificate{Skipped: skipped}, err
	}

	result := MailCertificate{
		CertPath: certPath, KeyPath: keyPath, ChainPath: chainPath,
		Hosts: hosts, Skipped: skipped,
	}
	if names, notAfter, e := readCertificate(certPath); e == nil {
		result.Hosts = names
		result.ExpiresAt = notAfter.Format("2006-01-02")
	}
	return result, nil
}

// writeMailChain builds the single file Postfix wants behind its SNI table: the
// private key first, then the certificate chain. It is written through a
// temporary file so a reload can never read a half-written chain.
func writeMailChain(chainPath, certPath, keyPath string) error {
	key, err := os.ReadFile(keyPath) // #nosec G304 -- a path this package composed from the certificate root and a validated domain.
	if err != nil {
		return fmt.Errorf("read the mail key: %w", err)
	}
	cert, err := os.ReadFile(certPath) // #nosec G304 -- a path this package composed from the certificate root and a validated domain.
	if err != nil {
		return fmt.Errorf("read the mail certificate: %w", err)
	}
	body := mailChainBytes(key, cert)

	tmp := chainPath + ".tmp"
	// #nosec G703 -- chainPath comes from MailCertificatePaths, which composes it from the certificate root and a domain ValidateDomain has already accepted.
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return fmt.Errorf("write the mail chain: %w", err)
	}
	if err := chown(tmp, 0, 0); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("set the mail chain ownership: %w", err)
	}
	if err := os.Rename(tmp, chainPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("put the mail chain in place: %w", err)
	}
	return nil
}

// RefreshMailChains rewrites every installed mail chain from its certificate and
// key, and reports whether any chain's bytes changed.
//
// acme.sh renews a certificate and re-copies mail.crt and mail.key, but it knows
// nothing about mail-chain.pem: that file is assembled here. Without this pass
// the chain keeps the day-zero certificate for ever, and because postmap -F
// embeds the chain's CONTENT into the indexed SNI table, so does Postfix.
//
// A domain whose files cannot be read is logged and skipped rather than
// abandoning the whole pass, because one unreadable domain must not stop every
// other domain from picking up its renewed certificate.
func RefreshMailChains() (changed bool) {
	for _, domain := range certificateDomains() {
		certPath, keyPath, chainPath := MailCertificatePaths(domain)
		if !fileExists(certPath) || !fileExists(keyPath) {
			continue
		}
		stale, err := mailChainIsStale(chainPath, certPath, keyPath)
		if err != nil {
			log.Printf("mail chain: %s could not be compared with its certificate: %v", domain, err)
			continue
		}
		if !stale {
			continue
		}
		if err := writeMailChain(chainPath, certPath, keyPath); err != nil {
			log.Printf("mail chain: %s could not be rewritten from its renewed certificate: %v", domain, err)
			continue
		}
		changed = true
	}
	return changed
}

// mailChainIsStale reports whether the chain file on disk differs from what the
// certificate and key now assemble to. A missing chain counts as stale.
func mailChainIsStale(chainPath, certPath, keyPath string) (bool, error) {
	key, err := os.ReadFile(keyPath) // #nosec G304 -- a path this package composed from the certificate root and a validated domain.
	if err != nil {
		return false, fmt.Errorf("read the mail key: %w", err)
	}
	cert, err := os.ReadFile(certPath) // #nosec G304 -- a path this package composed from the certificate root and a validated domain.
	if err != nil {
		return false, fmt.Errorf("read the mail certificate: %w", err)
	}
	current, err := os.ReadFile(chainPath) // #nosec G304 -- a path this package composed from the certificate root and a validated domain.
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, fmt.Errorf("read the mail chain: %w", err)
	}
	return !bytes.Equal(current, mailChainBytes(key, cert)), nil
}

// readCertificate returns the DNS names a certificate covers and when it
// expires. The certificate itself is the source of truth for the SNI map, so
// nothing has to be recorded elsewhere and nothing can drift out of sync.
func readCertificate(certPath string) ([]string, time.Time, error) {
	raw, err := os.ReadFile(certPath) // #nosec G304 -- a path this package composed from the certificate root and a validated domain.
	if err != nil {
		return nil, time.Time{}, err
	}
	for len(raw) > 0 {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, time.Time{}, err
		}
		return parsed.DNSNames, parsed.NotAfter, nil // the leaf comes first
	}
	return nil, time.Time{}, fmt.Errorf("no certificate found in %s", certPath)
}

// MailCertificateStatus reports the names a domain's installed mail certificate
// covers, or nothing when there is none or it has expired.
func MailCertificateStatus(domain string) (hosts []string, expiresAt string) {
	certPath, _, _ := MailCertificatePaths(domain)
	names, notAfter, err := readCertificate(certPath)
	if err != nil || time.Now().After(notAfter) {
		return nil, ""
	}
	return names, notAfter.Format("2006-01-02")
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// InstalledMailCertificates walks the certificate root and returns every valid
// mail chain with the names it covers. The mail stack's SNI configuration is
// generated from this, so the certificate files are the single source of truth.
func InstalledMailCertificates() map[string][]string {
	covered := map[string][]string{}
	for _, domain := range certificateDomains() {
		certPath, _, chainPath := MailCertificatePaths(domain)
		if !fileExists(chainPath) {
			continue
		}
		names, notAfter, err := readCertificate(certPath)
		if err != nil {
			log.Printf("mail sni: %s has a chain but its certificate could not be read: %v", domain, err)
			continue
		}
		if time.Now().After(notAfter) {
			log.Printf("mail sni: the certificate for %s expired on %s and is left out", domain, notAfter.Format("2006-01-02"))
			continue
		}
		covered[domain] = names
	}
	return covered
}

// certificateDomains returns the domain directories under the certificate root.
// An unreadable root yields none, so a caller walks nothing rather than acting on
// a partial list it cannot tell apart from an empty one.
func certificateDomains() []string {
	entries, err := os.ReadDir(certSystemBaseDir())
	if err != nil {
		return nil
	}
	domains := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			domains = append(domains, entry.Name())
		}
	}
	return domains
}

// MailSNICovers reports whether the mail stack will present a matching
// certificate for a hostname.
//
// The SNI map Postfix and Dovecot read is generated from the installed mail
// chains and nothing else (internal/mail.ApplySNI), so this is the only honest
// way to ask the question. A name that is absent here is served the server-wide
// default certificate instead, which is a mismatch warning at the client at the
// moment it is about to send a password.
func MailSNICovers(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	for _, names := range InstalledMailCertificates() {
		for _, name := range names {
			if strings.EqualFold(name, host) {
				return true
			}
		}
	}
	return false
}

// mailChainBytes assembles the chain Postfix expects. The ORDER is the contract:
// the private key first, then the certificate chain starting with the leaf.
// Reversed, Postfix rejects the entry and the domain silently falls back to the
// server-wide certificate, which is the problem this exists to solve.
func mailChainBytes(key, cert []byte) []byte {
	chain := make([]byte, 0, len(key)+len(cert)+1)
	chain = append(chain, key...)
	if len(key) > 0 && key[len(key)-1] != '\n' {
		chain = append(chain, '\n')
	}
	return append(chain, cert...)
}
