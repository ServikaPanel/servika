package dns

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

// DNSSECStatus describes DNSSEC state and registrar DS records for a domain.
type DNSSECStatus struct {
	Active bool     `json:"active"`
	Signed bool     `json:"signed"`
	DS     []string `json:"ds"`
	Status string   `json:"status"`
}

func dnsCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	command := exec.CommandContext(ctx, name, args...)
	command.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"LC_ALL=C",
	}
	return command
}

// GetDNSSEC returns the DNSSEC state and registrar DS records for a domain.
func (h *Handlers) GetDNSSEC(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	domainName, err := h.lookup(r)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	var activeValue int
	if err := h.DB.QueryRowContext(r.Context(), `SELECT COALESCE(dnssec_active,0) FROM domains WHERE id=?`, id).Scan(&activeValue); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	status := DNSSECStatus{Active: activeValue == 1}
	if status.Active {
		status.DS = dsForZone(r.Context(), domainName)
		status.Signed = len(digShort(r.Context(), domainName, "DNSKEY")) > 0
		status.Status = rndcDNSSECStatus(r.Context(), domainName)
	}
	httpx.WriteJSON(w, http.StatusOK, status)
}

// PostDNSSEC enables or disables DNSSEC for a domain and rewrites its BIND configuration.
func (h *Handlers) PostDNSSEC(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	domainName, err := h.lookup(r)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	var request struct {
		Active bool `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var previous int
	if err := h.DB.QueryRowContext(r.Context(), `SELECT COALESCE(dnssec_active,0) FROM domains WHERE id=?`, id).Scan(&previous); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	activeValue := 0
	if request.Active {
		activeValue = 1
	}
	if _, err := h.DB.ExecContext(r.Context(), `UPDATE domains SET dnssec_active=? WHERE id=?`, activeValue, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if err := writeZone(r.Context(), h.DB, id); err != nil {
		if _, rollbackErr := h.DB.ExecContext(r.Context(), `UPDATE domains SET dnssec_active=? WHERE id=?`, previous, id); rollbackErr != nil {
			httpx.LogR(r, "rollback DNSSEC state for domain %d: %v", id, rollbackErr)
		}
		httpx.LogR(r, "write DNS zone after DNSSEC change for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "DNS zone could not be updated")
		return
	}

	status := DNSSECStatus{Active: request.Active}
	if request.Active {
		status.DS = dsForZone(r.Context(), domainName)
		status.Signed = len(digShort(r.Context(), domainName, "DNSKEY")) > 0
		status.Status = rndcDNSSECStatus(r.Context(), domainName)
	}
	httpx.WriteJSON(w, http.StatusOK, status)
}

func dsForZone(ctx context.Context, zone string) []string {
	if cds := digShort(ctx, zone, "CDS"); len(cds) > 0 {
		return cds
	}
	return dsFromDNSKEY(ctx, zone)
}

func dsFromDNSKEY(ctx context.Context, zone string) []string {
	queryContext, cancelQuery := context.WithTimeout(ctx, 5*time.Second)
	defer cancelQuery()
	dnsKeys, err := dnsCommand(queryContext, "dig", "+noall", "+answer", "@127.0.0.1", zone, "DNSKEY").Output()
	if err != nil || len(strings.TrimSpace(string(dnsKeys))) == 0 {
		return nil
	}
	keyFile, err := os.CreateTemp("", "servika-dnskey-*.txt")
	if err != nil {
		return nil
	}
	defer func() { _ = os.Remove(keyFile.Name()) }()
	if _, err := keyFile.Write(dnsKeys); err != nil {
		_ = keyFile.Close()
		return nil
	}
	if err := keyFile.Close(); err != nil {
		return nil
	}

	convertContext, cancelConvert := context.WithTimeout(ctx, 5*time.Second)
	defer cancelConvert()
	output, err := dnsCommand(convertContext, "dnssec-dsfromkey", "-f", keyFile.Name(), zone).Output()
	if err != nil {
		return nil
	}
	var records []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(output)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if index := strings.Index(line, " DS "); index >= 0 {
			line = strings.TrimSpace(line[index+4:])
		}
		records = append(records, line)
	}
	return records
}

func digShort(ctx context.Context, zone, recordType string) []string {
	queryContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := dnsCommand(queryContext, "dig", "+short", "@127.0.0.1", zone, recordType).Output()
	if err != nil {
		return nil
	}
	var records []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(output)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			records = append(records, line)
		}
	}
	return records
}

func rndcDNSSECStatus(ctx context.Context, zone string) string {
	statusContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, _ := dnsCommand(statusContext, "rndc", "dnssec", "-status", zone).CombinedOutput()
	return strings.TrimSpace(string(output))
}
