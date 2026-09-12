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

	certificate, key, err := stageCertificate(fqdn, certificateType, stage)
	if err != nil {
		return err
	}
	return publishCertificate(systemUser, fqdn, certificate, key)
}

// stageCertificate issues the pair into the staging directory and reads it
// back. Material an issuing tool did not produce, produced empty, or produced
// far more of than a certificate is, is refused here rather than installed.
func stageCertificate(fqdn, certificateType, stage string) (certificate, key []byte, err error) {
	stagedCert := filepath.Join(stage, "cert.pem")
	stagedKey := filepath.Join(stage, "key.pem")
	if certificateType == "letsencrypt" {
		err = issueLetsEncryptCertificate(fqdn, stagedCert, stagedKey)
	} else {
		err = issueSelfSignedCertificate(fqdn, stagedCert, stagedKey)
	}
	if err != nil {
		return nil, nil, err
	}

	// #nosec G304 G703 -- a path this function composed from its own os.MkdirTemp directory.
	certificate, err = os.ReadFile(stagedCert)
	if err != nil {
		return nil, nil, fmt.Errorf("read the staged certificate: %w", err)
	}
	// #nosec G304 G703 -- a path this function composed from its own os.MkdirTemp directory.
	key, err = os.ReadFile(stagedKey)
	if err != nil {
		return nil, nil, fmt.Errorf("read the staged key: %w", err)
	}
	if len(certificate) == 0 || len(key) == 0 || len(certificate) > certMaxBytes || len(key) > certMaxBytes {
		return nil, nil, fmt.Errorf("the issued certificate material is not usable")
	}
	return certificate, key, nil
}

// publishCertificate installs the staged pair beneath the tenant home. Every
// write goes through the safeio primitives, which resolve each component with
// openat2 and refuse a symlink; a plain os.WriteFile to the same path would
// follow exactly the link this staging rule exists to close.
func publishCertificate(systemUser, fqdn string, certificate, key []byte) error {
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
