package transfers

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"servika/internal/provisioner"
)

// importSourceSSL copies the source's own working certificate onto the new
// account. A real CA certificate makes HTTPS ready before the DNS cutover, and a
// self-signed one still gives continuity until Let's Encrypt can renew it. It
// returns true when a certificate was imported (so the caller skips Let's
// Encrypt) and false when the source has no usable certificate, which means fall
// back to Let's Encrypt exactly as before (no regression).
func (h *Handlers) importSourceSSL(ctx context.Context, source *RemoteSource, account RemoteAccount, domainID int64, domainName string, logf func(string, ...any), result *MigrationResult) bool {
	certPEM, keyPEM, err := readSourceCertificate(ctx, source, account, domainName)
	if err != nil {
		logf("SSL: the source certificate could not be read (%v); trying Let's Encrypt", err)
		return false
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		logf("SSL: the source has no usable certificate; trying Let's Encrypt")
		return false
	}
	certPath, keyPath, expires, err := provisioner.InstallImportedSSL(domainName, certPEM, keyPEM)
	if err != nil {
		logf("SSL: the source certificate is not usable (%v); trying Let's Encrypt", err)
		return false
	}
	// InstallImportedSSL's contract: update the DB first, then re-render the vhost,
	// so a concurrent re-render cannot overwrite the freshly installed certificate.
	if _, err := h.DB.ExecContext(ctx,
		`UPDATE domains SET ssl_enabled=1, ssl_source='imported', cert_path=?, key_path=?, ssl_expiry=? WHERE id=?`,
		certPath, keyPath, expires, domainID); err != nil {
		logf("SSL: the imported certificate could not be recorded: %v", err)
		return false
	}
	if err := provisioner.RerenderVhost(h.DB, domainID); err != nil {
		logf("SSL: the vhost could not be re-rendered after import: %v", err)
		return false
	}
	if isSelfSignedCertificate(certPEM) {
		logf("SSL: imported the source certificate (self-signed)")
		result.Warnings = append(result.Warnings,
			"the imported SSL certificate is self-signed; renew it via Let's Encrypt once DNS points at this server")
	} else {
		logf("SSL: imported the source certificate")
	}
	return true
}

// readSourceCertificate reads the certificate and private key the source server
// currently serves for the domain, over SSH. The private key is a secret: it is
// fed only to validation and installation and is never logged. An empty return
// with a nil error means the source has no certificate for this domain.
func readSourceCertificate(ctx context.Context, source *RemoteSource, account RemoteAccount, domainName string) (certPEM, keyPEM []byte, err error) {
	if verr := provisioner.ValidateDomain(domainName); verr != nil {
		return nil, nil, verr
	}
	script := sourceCertificateScript(source.Type, domainName, account.SourceAccount)
	if script == "" {
		return nil, nil, nil
	}
	out, err := source.Run(ctx, script)
	if err != nil {
		return nil, nil, err
	}
	cert := strings.TrimSpace(sectionBetween(out, certMarkerStart, certMarkerKey))
	key := strings.TrimSpace(sectionBetween(out, certMarkerKey, certMarkerEnd))
	if cert == "" || key == "" {
		return nil, nil, nil
	}
	return []byte(cert), []byte(key), nil
}

const (
	certMarkerStart = "###SVKCERT###"
	certMarkerKey   = "###SVKKEY###"
	certMarkerEnd   = "###SVKEND###"
)

// sourceCertificateScript builds the remote shell that prints the domain's
// certificate and key between markers, per control panel. The domain and the
// source user enter only through shellQuote, and both are assigned to shell
// variables so they cannot break out of the surrounding paths. An unknown panel
// returns an empty script, which the caller reads as "no certificate".
func sourceCertificateScript(panelType, domainName, sourceUser string) string {
	d := shellQuote(domainName)
	switch panelType {
	case "cpanel":
		// cPanel keeps the installed certificate, chain and key concatenated in one
		// file; passing it as both arguments lets crypto/tls pick the cert out of the
		// first and the key out of the second.
		return "d=" + d + "\n" +
			`c="/var/cpanel/ssl/apache_tls/$d/combined"` + "\n" +
			`if [ -f "$c" ]; then printf '` + certMarkerStart + `\n'; cat "$c"; printf '\n` + certMarkerKey + `\n'; cat "$c"; printf '\n` + certMarkerEnd + `\n'; fi`
	case "plesk":
		// Read whichever certificate the running nginx vhost actually serves, rather
		// than guessing a version-specific path.
		return "d=" + d + "\n" +
			`conf=$(ls /etc/nginx/plesk.conf.d/vhosts/${d}.conf /etc/nginx/plesk.conf.d/vhosts/${d}_*.conf 2>/dev/null | head -1)` + "\n" +
			`[ -z "$conf" ] && conf=$(grep -rlsE "server_name[^;]*${d}" /etc/nginx/plesk.conf.d/vhosts/ 2>/dev/null | head -1)` + "\n" +
			`if [ -n "$conf" ]; then` + "\n" +
			`  cert=$(grep -hE "^[[:space:]]*ssl_certificate[[:space:]]" "$conf" 2>/dev/null | head -1 | sed -E 's/.*ssl_certificate[[:space:]]+([^;]+);.*/\1/' | tr -d " \t")` + "\n" +
			`  key=$(grep -hE "^[[:space:]]*ssl_certificate_key[[:space:]]" "$conf" 2>/dev/null | head -1 | sed -E 's/.*ssl_certificate_key[[:space:]]+([^;]+);.*/\1/' | tr -d " \t")` + "\n" +
			`  if [ -n "$cert" ] && [ -n "$key" ] && [ -f "$cert" ] && [ -f "$key" ]; then` + "\n" +
			`    printf '` + certMarkerStart + `\n'; cat "$cert"; printf '\n` + certMarkerKey + `\n'; cat "$key"; printf '\n` + certMarkerEnd + `\n'` + "\n" +
			`  fi` + "\n" +
			`fi`
	case "directadmin":
		if strings.TrimSpace(sourceUser) == "" {
			return ""
		}
		u := shellQuote(sourceUser)
		return "d=" + d + "\nu=" + u + "\n" +
			`b="/usr/local/directadmin/data/users/$u/domains/$d"` + "\n" +
			`if [ -f "$b.cert" ] && [ -f "$b.key" ]; then` + "\n" +
			`  printf '` + certMarkerStart + `\n'; cat "$b.cert"; [ -f "$b.cacert" ] && cat "$b.cacert"; printf '\n` + certMarkerKey + `\n'; cat "$b.key"; printf '\n` + certMarkerEnd + `\n'` + "\n" +
			`fi`
	}
	return ""
}

// sectionBetween returns the text between the first occurrence of start and the
// next occurrence of end after it, or an empty string when either is missing.
func sectionBetween(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	i += len(start)
	j := strings.Index(s[i:], end)
	if j < 0 {
		return ""
	}
	return s[i : i+j]
}

// isSelfSignedCertificate reports whether the leaf certificate is self-signed
// (its issuer equals its subject), which is the cheap heuristic used to decide
// whether to warn that Let's Encrypt should still renew it. It scans for the
// first CERTIFICATE block, because a combined file may carry the key first.
func isSelfSignedCertificate(certPEM []byte) bool {
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return false
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return false
		}
		return leaf.Issuer.String() == leaf.Subject.String()
	}
}
