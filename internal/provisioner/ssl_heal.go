package provisioner

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"servika/internal/config"
)

// ---------------------------------------------------------------------------
// SSL re-issue teardown fix (Let's Encrypt rate-limit resilience)
//
// Root problem: when acme.sh certificate issuance hits 429 (LE rate-limit: "too
// many certificates already issued for this exact set of identifiers in the last
// 168h"), the panel treated it as a total failure, discarded its VALID certificate,
// re-rendered the vhost HTTP-only, and dropped the 443 listener. With Cloudflare in
// Full/strict mode no origin listens on 443 -> 522/525 -> the whole site goes down.
// Meanwhile a valid certificate remained in the acme store (/root/.acme.sh) and/or
// /etc/pki/servika for 90 days.
//
// Solution (three parts, all also repair existing installs via startup heal):
//  1. Reuse-before-issue: when a valid certificate exists, do not re-issue; deploy it
//     (never triggers 429).
//  2. Fail-safe: when issuance fails (including 429), keep 443 alive with the
//     existing/self-signed certificate; never drop the vhost to HTTP-only.
//  3. Startup-heal: on every boot, repair the 443 block and certificate of SSL-enabled
//     domains.
// ---------------------------------------------------------------------------

// acmeStoreCandidates returns the (fullchain, key) candidate pairs acme.sh stores
// for a domain. RSA issuance uses "<domain>", ECC issuance uses "<domain>_ecc"; both
// are returned as candidates.
func acmeStoreCandidates(domain string) [][2]string {
	base := config.ACMEHome()
	var out [][2]string
	for _, d := range []string{
		filepath.Join(base, domain),
		filepath.Join(base, domain+"_ecc"),
	} {
		out = append(out, [2]string{
			filepath.Join(d, "fullchain.cer"),
			filepath.Join(d, domain+".key"),
		})
	}
	return out
}

// certFileExists reports whether a certificate/key file is present.
func certFileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// loadLeaf loads a cert+key PEM pair. The key MUST match the certificate's public key
// (tls.LoadX509KeyPair verifies this, so a wrong key never loads). For a fullchain it
// returns the first (leaf) certificate.
func loadLeaf(certPath, keyPath string) (*x509.Certificate, bool) {
	if !certFileExists(certPath) || !certFileExists(keyPath) {
		return nil, false
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, false // key mismatch or parse error
	}
	leaf := pair.Leaf
	if leaf == nil && len(pair.Certificate) > 0 {
		leaf, _ = x509.ParseCertificate(pair.Certificate[0])
	}
	if leaf == nil {
		return nil, false
	}
	return leaf, true
}

// certCovers reports whether the leaf certificate covers the given host via SAN
// (DNSNames) or CN.
func certCovers(leaf *x509.Certificate, host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, n := range leaf.DNSNames {
		if strings.EqualFold(n, host) {
			return true
		}
	}
	return strings.EqualFold(leaf.Subject.CommonName, host)
}

// certValid reports whether a cert+key pair is valid: keys match, notAfter is beyond
// now+minDays, and it covers ALL given hosts (e.g. domain + www.domain).
func certValid(certPath, keyPath string, minDays int, hosts ...string) bool {
	leaf, ok := loadLeaf(certPath, keyPath)
	if !ok {
		return false
	}
	if time.Now().Add(time.Duration(minDays) * 24 * time.Hour).After(leaf.NotAfter) {
		return false
	}
	for _, h := range hosts {
		if !certCovers(leaf, h) {
			return false
		}
	}
	return true
}

// bestCertificate selects the best valid certificate (matching key, valid for minDays,
// covering the required hostnames) among acme.sh store and /etc/pki candidates. Priority: a real CA
// (Let's Encrypt) beats self-signed; within the same class, the later notAfter wins.
// realCA reports whether the chosen certificate is real-CA-signed (not self-signed).
func bestCertificate(domain string, minDays int) (certPath, keyPath string, realCA bool) {
	type candidate struct{ cert, key string }
	var candidates []candidate
	for _, c := range acmeStoreCandidates(domain) {
		candidates = append(candidates, candidate{c[0], c[1]})
	}
	sysDir := certSystemDir(domain)
	candidates = append(candidates, candidate{
		filepath.Join(sysDir, domain+".crt"),
		filepath.Join(sysDir, domain+".key"),
	})

	// Require only the hostnames a real cert is expected to cover: apex always,
	// www only when DNS supports it. An apex-only cert (issued because www is not
	// in DNS) must be accepted for reuse, not rejected for lacking www. Computed
	// once here rather than per candidate to avoid repeated DNS lookups.
	requiredHosts := certSANHosts(domain)
	var bestCert, bestKey string
	var bestReal bool
	var bestNotAfter time.Time
	for _, c := range candidates {
		if !certValid(c.cert, c.key, minDays, requiredHosts...) {
			continue
		}
		leaf, ok := loadLeaf(c.cert, c.key)
		if !ok {
			continue
		}
		real := leaf.Issuer.String() != leaf.Subject.String() // self-signed has Issuer==Subject
		if bestCert == "" ||
			(real && !bestReal) ||
			(real == bestReal && leaf.NotAfter.After(bestNotAfter)) {
			bestCert, bestKey, bestReal, bestNotAfter = c.cert, c.key, real, leaf.NotAfter
		}
	}
	return bestCert, bestKey, bestReal
}

// reusableLetsEncryptCertificate returns only real CA certificates for pre-issue reuse.
func reusableLetsEncryptCertificate(domain string, minDays int) (certPath, keyPath string) {
	certPath, keyPath, real := bestCertificate(domain, minDays)
	if !real {
		return "", ""
	}
	return certPath, keyPath
}

// installToPKI copies srcCert/srcKey into /etc/pki/servika/<domain>/ (cert 0644,
// key 0600, root-owned, restorecon -> cert_t). When the source is already the target,
// only permissions/context are applied (idempotent). Returns the target cert/key paths.
func installToPKI(domain, srcCert, srcKey string) (certPath, keyPath string, err error) {
	sslDir, err := prepareCertificateDir(domain)
	if err != nil {
		return "", "", err
	}
	certPath = filepath.Join(sslDir, domain+".crt")
	keyPath = filepath.Join(sslDir, domain+".key")
	if srcCert != certPath {
		if err := copyTenantCertificate(srcCert, certPath, 0, 0644); err != nil {
			return "", "", fmt.Errorf("copy certificate: %w", err)
		}
	}
	if srcKey != keyPath {
		if err := copyTenantCertificate(srcKey, keyPath, 0, 0600); err != nil {
			return "", "", fmt.Errorf("copy key: %w", err)
		}
	}
	if err := applyCertificatePermissions(sslDir, certPath, keyPath); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// generateSelfSigned produces a 1-year self-signed certificate in
// /etc/pki/servika/<domain>/ with the same SANs used by nginx and ACME. It does NOT render the vhost;
// the caller wires it up with writeSSLVhost.
func generateSelfSigned(domain string) (certPath, keyPath string, err error) {
	if verr := ValidateDomain(domain); verr != nil {
		return "", "", verr // path safety (no / or ..)
	}
	sslDir, err := prepareCertificateDir(domain)
	if err != nil {
		return "", "", err
	}
	certPath = filepath.Join(sslDir, domain+".crt")
	keyPath = filepath.Join(sslDir, domain+".key")
	subj := fmt.Sprintf("/C=TR/ST=Local/L=Servika/O=%s/CN=%s", domain, domain)
	sanHosts := wwwHostNames(domain)
	sanNames := make([]string, 0, len(sanHosts))
	for _, host := range sanHosts {
		sanNames = append(sanNames, "DNS:"+host)
	}
	args := []string{
		"req", "-x509", "-nodes",
		"-newkey", "rsa:2048",
		"-keyout", keyPath,
		"-out", certPath,
		"-days", "365",
		"-subj", subj,
		"-addext", "subjectAltName=" + strings.Join(sanNames, ","),
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	if out, e := exec.Command("openssl", args...).CombinedOutput(); e != nil {
		return "", "", fmt.Errorf("openssl: %s: %w", strings.TrimSpace(string(out)), e)
	}
	if err := applyCertificatePermissions(sslDir, certPath, keyPath); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// writeSSLVhost renders the domain's vhost with SSL (including the 443 block) using the
// given cert/key. renderAndReload runs nginx -t with rollback fail-safe (broken config
// never stays on disk). Suspension/per-tenant FPM consistency is handled inside
// renderAndReload.
func writeSSLVhost(domainName, systemUser, phpVersion, backend, certPath, keyPath, source string) error {
	_, socket, _ := phpPoolPath(systemUser, phpVersion)
	opts := VhostOpts{
		DomainName: domainName,
		WebRoot:    SafeWebRoot(systemUser, currentWebRoot(systemUser)),
		PHPSocket:  socket,
		PHPVersion: phpVersion,
		CertPath:   certPath,
		KeyPath:    keyPath,
		SSLSource:  source,
		Backend:    backend,
	}
	// Addon domains share the parent's system user; without its own ConfigPath and
	// web root this SSL render would overwrite the parent's dom_<sk>.conf and drop
	// the parent domain from nginx (see addonDomainInfo).
	if wr, isAddon := addonDomainInfo(domainName); isAddon {
		opts.ConfigPath = addonVhostConfigPath(systemUser, domainName)
		opts.WebRoot = safeAddonWebRoot(systemUser, domainName, wr)
	}
	return renderAndReload(opts, systemUser)
}

// sslFailSafe keeps 443 alive when LE issuance fails (including 429) — it never drops
// the vhost to HTTP-only. When a valid certificate (acme store or /etc/pki, not expired,
// matching the required hostnames and key) exists it deploys it; when none exists it generates a
// self-signed one. In both cases the vhost is rendered with SSL (443 listens).
// sslReason names a stable failure code and the transcript line behind it.
//
// The code is what leaves the process: the panel ships twelve languages and
// cannot translate a sentence the CA wrote in English, nor should it print raw
// acme.sh output on a customer screen. The detail stays for the panel log, which
// is where an operator looks when the code is not enough.
type sslReason struct {
	Code   string
	Detail string
	// Skipped names the hosts left out of the SAN, mapped to their own codes.
	Skipped map[string]string
}

// with attaches the dropped-name map to a classified failure.
func (r sslReason) with(skipped map[string]string) sslReason {
	r.Skipped = skipped
	return r
}

// Failure codes the SSL screen renders. Adding one here means adding its
// translation to the SSL page namespace in every language.
const (
	sslReasonDNSUnresolved = "dns_unresolved"
	sslReasonRateLimited   = "rate_limited"
	sslReasonDNSProblem    = "dns_problem"
	sslReasonACMEFailed    = "acme_failed"
	sslReasonInstallFailed = "acme_install_failed"
)

// classifySSLFailure turns an acme.sh transcript into one of the codes above.
//
// Only the distinctions a domain owner can act on are drawn. A rate limit means
// wait; a DNS problem means fix the record; anything else means read the log.
func classifySSLFailure(transcript string) sslReason {
	detail := summarizeSSLReason(transcript)
	lower := strings.ToLower(transcript)
	switch {
	case strings.Contains(lower, "rate limit") || strings.Contains(lower, "too many"):
		return sslReason{Code: sslReasonRateLimited, Detail: detail}
	case strings.Contains(lower, "dns problem"):
		return sslReason{Code: sslReasonDNSProblem, Detail: detail}
	default:
		return sslReason{Code: sslReasonACMEFailed, Detail: detail}
	}
}

func sslFailSafe(domainName, systemUser, phpVersion, backend string, reason sslReason) (certPath, keyPath string, outcome IssueOutcome, err error) {
	if src, srcKey, real := bestCertificate(domainName, 0); src != "" {
		if cp, kp, e := installToPKI(domainName, src, srcKey); e == nil {
			source := "self-signed"
			if real {
				source = "letsencrypt"
			}
			if e := writeSSLVhost(domainName, systemUser, phpVersion, backend, cp, kp, source); e != nil {
				return "", "", IssueOutcome{}, e
			}
			log.Printf("ssl fail-safe: %s LE issuance failed (%s: %s); 443 kept alive with existing %s certificate", domainName, reason.Code, reason.Detail, source)
			return cp, kp, IssueOutcome{Real: real, Reason: reason.Code, Skipped: reason.Skipped}, nil
		}
	}
	// No valid certificate -> self-signed fallback (443 still listens, no teardown).
	cp, kp, e := generateSelfSigned(domainName)
	if e != nil {
		return "", "", IssueOutcome{}, fmt.Errorf("%s + self-signed fallback: %w", reason.Code, e)
	}
	if e := writeSSLVhost(domainName, systemUser, phpVersion, backend, cp, kp, "self-signed"); e != nil {
		return "", "", IssueOutcome{}, e
	}
	log.Printf("ssl fail-safe: %s LE issuance failed (%s: %s); self-signed generated, 443 kept alive", domainName, reason.Code, reason.Detail)
	return cp, kp, IssueOutcome{Reason: reason.Code, Skipped: reason.Skipped}, nil
}

// summarizeSSLReason reduces an acme.sh transcript to the part that tells the
// domain owner what to fix.
//
// The reason has to reach the user. Without it the panel reports a certificate
// was installed while the browser reports the site is not secure, and there is
// nothing on screen connecting the two. acme.sh prints many lines, so the
// validation error is picked out and the result is bounded: this is CA output
// about the caller's own domain, not an internal error trace.
func summarizeSSLReason(reason string) string {
	const limit = 300
	best := ""
	for line := range strings.SplitSeq(reason, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		// The lines that name a cause, in the order acme.sh emits them.
		if strings.Contains(lower, "dns problem") || strings.Contains(lower, "invalid status") ||
			strings.Contains(lower, "detail:") || strings.Contains(lower, "rate limit") ||
			strings.Contains(lower, "too many") {
			best = line
			break
		}
		if best == "" {
			best = line
		}
	}
	best = strings.TrimSpace(best)
	if len(best) > limit {
		best = best[:limit] + "..."
	}
	return best
}

// HealSSLVhost443OnStartup verifies that every SSL-enabled (ssl_enabled=1) domain's
// vhost has its 443 block and the certificate files it references. When missing, it
// places the best certificate (LE > self-signed; fresh self-signed when none exists)
// into /etc/pki, repoints the DB cert_path/key_path, and re-renders the vhost with SSL
// (renderAndReload runs nginx -t with rollback -> fail-closed: on failure the previous
// state is preserved). Idempotent — healthy domains are left untouched. Called from Init
// on every boot so existing broken installs (443 dropped / cert deleted) are repaired
// automatically on the first update + restart.
func HealSSLVhost443OnStartup() {
	if packageDB == nil {
		return
	}
	rows, err := packageDB.Query(`SELECT id, domain_name, system_user, COALESCE(php_version,'8.3'), COALESCE(cert_path,''), COALESCE(key_path,'')
		FROM domains WHERE ssl_enabled=1`)
	if err != nil {
		return
	}
	type dom struct {
		id                                     int64
		domainName, systemUser, php, cert, key string
	}
	var list []dom
	for rows.Next() {
		var x dom
		if e := rows.Scan(&x.id, &x.domainName, &x.systemUser, &x.php, &x.cert, &x.key); e == nil {
			list = append(list, x)
		}
	}
	_ = rows.Close()
	if len(list) == 0 {
		return
	}
	var repaired, failed, healthy int
	for _, x := range list {
		if x.domainName == "" || ValidateDomain(x.domainName) != nil {
			continue // path safety
		}
		// Addon domains keep their 443 block in their own conf; reading the parent's
		// dom_<sk>.conf here would misjudge an SSL-enabled addon's health.
		vpath := "/etc/nginx/conf.d/dom_" + x.systemUser + ".conf"
		if _, isAddon := addonDomainInfo(x.domainName); isAddon {
			vpath = addonVhostConfigPath(x.systemUser, x.domainName)
		}
		// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
		data, rerr := os.ReadFile(vpath)
		has443 := rerr == nil && strings.Contains(string(data), "listen 443")
		certPresent := certFileExists(x.cert) && certFileExists(x.key)
		if has443 && certPresent {
			healthy++
			continue // healthy — leave untouched
		}

		useCert, useKey := x.cert, x.key
		// When the certificate files are missing, find/generate the best one and install it.
		if !certPresent {
			src, srcKey, _ := bestCertificate(x.domainName, 0)
			if src == "" {
				cp, kp, e := generateSelfSigned(x.domainName)
				if e != nil {
					log.Printf("ssl 443 heal: %s cert missing + self-signed generation failed: %v", x.domainName, e)
					failed++
					continue
				}
				src, srcKey = cp, kp
			}
			cp, kp, e := installToPKI(x.domainName, src, srcKey)
			if e != nil {
				log.Printf("ssl 443 heal: %s certificate install into /etc/pki failed: %v", x.domainName, e)
				failed++
				continue
			}
			useCert, useKey = cp, kp
		}
		// Repoint the DB (when changed) — applyVhostForDomain reads the cert from the DB.
		if useCert != x.cert || useKey != x.key {
			if _, e := packageDB.Exec(`UPDATE domains SET cert_path=?, key_path=? WHERE id=?`, useCert, useKey, x.id); e != nil {
				log.Printf("ssl 443 heal: %s DB repoint failed: %v", x.domainName, e)
				failed++
				continue
			}
		}
		socket, _ := PHPSocketFor(x.systemUser, x.php)
		if e := applyVhostForDomain(packageDB, x.id, socket, x.php, nil, nil); e != nil {
			log.Printf("ssl 443 heal: %s vhost 443 re-render failed (previous state preserved): %v", x.domainName, e)
			failed++
			continue
		}
		repaired++
		log.Printf("ssl 443 heal: %s 443 block + certificate repaired", x.domainName)
	}
	if repaired > 0 || failed > 0 {
		log.Printf("ssl 443 heal: %d repaired / %d failed / %d healthy (%d SSL domains total)", repaired, failed, healthy, len(list))
	}
}
