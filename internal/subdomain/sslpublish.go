package subdomain

import (
	"fmt"
	"os"
	"path/filepath"

	"servika/internal/files"
)

// certMaxBytes bounds a certificate or key read back from the staging
// directory. A full chain is a few kilobytes; this refuses to hold whatever an
// external tool wrote instead.
const certMaxBytes = 1 << 20

// issueAndPublish generates the certificate in a ROOT-OWNED staging directory
// and then publishes both files beneath the tenant home.
//
// The staging step is the whole point. ~/ssl is created inside the tenant home
// and chowned to the tenant, so the tenant can replace it with a symlink or
// plant <fqdn>.key and <fqdn>.crt inside it as symlinks. openssl and acme.sh
// write BY PATH and dereference every component, and so did the os.MkdirAll and
// os.Chmod around them, so a link redirected a root-privileged write to any
// file on the host: /etc/shadow, a systemd unit, an nginx configuration, or a
// neighbouring tenant's stored certificate. The content is not attacker-chosen,
// so it is a destructive primitive rather than a direct escalation, and the
// private key of the issued certificate lands wherever the tenant points it.
//
// This is the same staging rule the rest of the tree already follows for an
// external tool that writes by path; see generateDeployKey and compileSieve.
// The publish half goes through the safeio primitives, which resolve every
// component with openat2 beneath the home and refuse a symlink.
func issueAndPublish(systemUser, fqdn, certificateType string) error {
	stage, err := os.MkdirTemp("", "servika-subdomain-cert-")
	if err != nil {
		return fmt.Errorf("stage the certificate: %w", err)
	}
	defer func() { _ = os.RemoveAll(stage) }()

	stagedCert := filepath.Join(stage, "cert.pem")
	stagedKey := filepath.Join(stage, "key.pem")
	if certificateType == "letsencrypt" {
		err = issueLetsEncryptCertificate(fqdn, stagedCert, stagedKey)
	} else {
		err = issueSelfSignedCertificate(fqdn, stagedCert, stagedKey)
	}
	if err != nil {
		return err
	}

	// #nosec G304 G703 -- a path this function composed from its own os.MkdirTemp directory.
	certificate, err := os.ReadFile(stagedCert)
	if err != nil {
		return fmt.Errorf("read the staged certificate: %w", err)
	}
	// #nosec G304 G703 -- a path this function composed from its own os.MkdirTemp directory.
	key, err := os.ReadFile(stagedKey)
	if err != nil {
		return fmt.Errorf("read the staged key: %w", err)
	}
	if len(certificate) == 0 || len(key) == 0 || len(certificate) > certMaxBytes || len(key) > certMaxBytes {
		return fmt.Errorf("the issued certificate material is not usable")
	}

	home := tenantHome(systemUser)
	if err := files.MkdirAllBeneath(home, sslRelDir, systemUser); err != nil {
		return fmt.Errorf("prepare the certificate directory: %w", err)
	}
	// The certificate is public; the key is not, and 0640 is what nginx reads it
	// as through the tenant group.
	if err := files.WriteFileBeneath(home, sslRelPath(fqdn, ".crt"), certificate, 0o644, systemUser); err != nil {
		return fmt.Errorf("install the certificate: %w", err)
	}
	if err := files.WriteFileBeneath(home, sslRelPath(fqdn, ".key"), key, 0o640, systemUser); err != nil {
		return fmt.Errorf("install the key: %w", err)
	}
	files.RestoreconBeneath(home, sslRelDir)
	return nil
}

// sslRelDir is the certificate directory relative to the tenant home, which is
// the form every safeio primitive takes.
const sslRelDir = "ssl"

func sslRelPath(fqdn, extension string) string { return sslRelDir + "/" + fqdn + extension }
