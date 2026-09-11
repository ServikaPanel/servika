package system

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"servika/internal/httpx"
)

// Overridable for tests; production values point at the real system files.
var (
	hostnameRead    = os.Hostname
	hostnameFile    = "/etc/hostname"
	cloudInitFile   = "/etc/cloud/cloud.cfg.d/99-servika-hostname.cfg"
	networkMgrFile  = "/etc/NetworkManager/conf.d/99-servika-hostname.conf"
	hostnameApplier = func(ctx context.Context, name string) error {
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		return exec.CommandContext(ctx, "hostnamectl", "set-hostname", name).Run()
	}
)

type hostnameState struct {
	Hostname  string `json:"hostname"`
	Protected bool   `json:"protected"`
	Note      string `json:"note"`
}

// validateHostname normalizes and validates a hostname against RFC 1123 label
// rules (lowercased, trailing dot stripped, 1-253 chars, no IP, no localhost).
func validateHostname(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if len(name) == 0 || len(name) > 253 {
		return "", errors.New("hostname must be 1-253 characters")
	}
	if net.ParseIP(name) != nil {
		return "", errors.New("hostname cannot be an IP address")
	}
	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return "", errors.New("localhost cannot be used as a hostname")
	}
	for label := range strings.SplitSeq(name, ".") {
		if err := validateLabel(label); err != nil {
			return "", err
		}
	}
	return name, nil
}

// validateLabel checks one dot-separated part of a hostname: 1-63 characters,
// no leading or trailing hyphen, and nothing outside the RFC 1123 set.
func validateLabel(label string) error {
	if len(label) == 0 || len(label) > 63 ||
		label[0] == '-' || label[len(label)-1] == '-' {
		return errors.New("invalid hostname label")
	}
	for _, r := range label {
		if !validLabelRune(r) {
			return errors.New("hostname may contain only letters, digits, hyphens, and dots")
		}
	}
	return nil
}

func validLabelRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
}

// atomicWrite writes content to a temp file in the destination directory and
// renames it into place so a partial write never leaves a truncated file.
func atomicWrite(path, content string, mode os.FileMode) error {
	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".servika-hostname-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err = f.Chmod(mode); err == nil {
		_, err = f.WriteString(content)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// writeHostnameProtection drops cloud-init and NetworkManager overrides so the
// VPS provider's DHCP/cloud-init cannot rewrite the static hostname on reboot.
func writeHostnameProtection() error {
	if err := atomicWrite(cloudInitFile,
		"# Servika: prevent the provider/cloud-init from rewriting the hostname\npreserve_hostname: true\n", 0644); err != nil {
		return err
	}
	return atomicWrite(networkMgrFile,
		"# Servika: prevent DHCP/NetworkManager from changing the static hostname\n[main]\nhostname-mode=none\n", 0644)
}

// HostnameStatus — GET /system/hostname.
func HostnameStatus(w http.ResponseWriter, _ *http.Request) {
	name, err := hostnameRead()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the hostname")
		return
	}
	_, cloudErr := os.Stat(cloudInitFile)
	_, nmErr := os.Stat(networkMgrFile)
	httpx.WriteJSON(w, http.StatusOK, hostnameState{
		Hostname:  name,
		Protected: cloudErr == nil && nmErr == nil,
		Note:      "cloud-init and DHCP/NetworkManager hostname changes are blocked",
	})
}

// HostnameSave — PUT /system/hostname. Guarded by AdminOnly in the router.
func HostnameSave(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	var req struct {
		Hostname string `json:"hostname"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	name, err := validateHostname(req.Hostname)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := writeHostnameProtection(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not write the hostname persistence guard")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := hostnameApplier(ctx, name); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not apply the hostname")
		return
	}
	// hostnamectl already writes /etc/hostname. Pin the result atomically as well
	// so persistence is guaranteed on minimal/container environments too.
	if err := atomicWrite(hostnameFile, name+"\n", 0644); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "hostname applied but /etc/hostname could not be written")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, hostnameState{
		Hostname:  name,
		Protected: true,
		Note:      "hostname changed permanently; cloud-init and DHCP cannot rewrite it",
	})
}
