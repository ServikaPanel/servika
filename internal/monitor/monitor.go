// Package monitor provides process monitoring and domain HTTP health probes.
package monitor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"servika/internal/httpx"
	"servika/internal/netguard"

	"github.com/go-chi/chi/v5"
)

type Process struct {
	PID     int     `json:"pid"`
	User    string  `json:"user"`
	CPU     float64 `json:"cpu_percent"`
	Mem     float64 `json:"mem_percent"`
	Command string  `json:"command"`
}

type Handlers struct {
	DB *sql.DB
}

// psCommand runs the process listing. It is a variable so a test can stand in
// for the host's own ps, which prints a different table on every platform.
var psCommand = exec.CommandContext

// psBudget bounds the process listing.
//
// ps reads /proc for every process, and one task stuck in uninterruptible sleep
// on a hung mount holds it there. The handler timeout cancels r.Context() and
// nothing else, so an uncontexted command kept the handler, its goroutine and
// the child process alive until the socket write deadline dropped the client
// with no response at all.
var psBudget = 10 * time.Second

// rowLimit reads how many processes the caller asked for. An unreadable or
// out-of-range value takes the default rather than an unbounded listing.
func rowLimit(r *http.Request) int {
	s := r.URL.Query().Get("n")
	if s == "" {
		return 15
	}
	v, err := strconv.Atoi(s)
	if err != nil || v <= 0 || v > 100 {
		return 15
	}
	return v
}

// sortFlagOf maps the requested order onto the ps flag. The sort runs in ps,
// because it holds the whole process table and the panel holds a page of it.
func sortFlagOf(r *http.Request) string {
	if r.URL.Query().Get("sort") == "mem" {
		return "-pmem"
	}
	return "-pcpu"
}

// parseProcess reads one ps row. It reports false for a row that does not carry
// all five columns, so a short line is skipped instead of listed as a process
// with no name.
func parseProcess(line string) (Process, bool) {
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) < 5 {
		return Process{}, false
	}
	pid, _ := strconv.Atoi(f[0])
	cpu, _ := strconv.ParseFloat(f[2], 64)
	mem, _ := strconv.ParseFloat(f[3], 64)
	command := strings.Join(f[4:], " ")
	if len(command) > 120 {
		command = command[:120] + "…"
	}
	return Process{PID: pid, User: f[1], CPU: cpu, Mem: mem, Command: command}, true
}

// GET /system/processes?n=15&sort=cpu|mem
func Processes(w http.ResponseWriter, r *http.Request) {
	n := rowLimit(r)

	ctx, cancel := context.WithTimeout(r.Context(), psBudget)
	defer cancel()
	cmd := psCommand(ctx, "ps", "-eo", "pid,user:32,pcpu,pmem,args", "--no-headers", "--sort="+sortFlagOf(r))
	out, err := cmd.Output()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to read process list")
		return
	}
	procs := make([]Process, 0, n)
	for line := range strings.SplitSeq(string(out), "\n") {
		p, ok := parseProcess(line)
		if !ok {
			continue
		}
		procs = append(procs, p)
		if len(procs) >= n {
			break
		}
	}
	httpx.WriteJSON(w, http.StatusOK, procs)
}

type SSLInfo struct {
	Valid         bool   `json:"valid"`
	EndDate       string `json:"end_date"`
	RemainingDays int    `json:"remaining_days"`
	Issuer        string `json:"issuer,omitempty"`
	SubjectName   string `json:"subject,omitempty"`
	CertError     string `json:"cert_error,omitempty"`
}

type DomainHealth struct {
	URL            string   `json:"url"`
	StatusCode     int      `json:"status_code"`
	ResponseTimeMS float64  `json:"response_time_ms"`
	Reachable      bool     `json:"reachable"`
	Error          string   `json:"error,omitempty"`
	Scheme         string   `json:"scheme"` // "http" | "https"
	SSL            *SSLInfo `json:"ssl,omitempty"`
	Size           int64    `json:"size_byte"`
	Server         string   `json:"server,omitempty"`
}

// GET /domains/{id}/health
// Health tries HTTPS first, falls back to HTTP, and reads SSL details from the certificate.
func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var domainName, ipv4 string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name, ipv4 FROM domains WHERE id=?`, id).Scan(&domainName, &ipv4)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to read domain")
		return
	}

	res := probe("https://" + domainName)
	res.Scheme = "https"
	if !res.Reachable {
		// Fall back to HTTP when HTTPS fails.
		alt := probe("http://" + domainName)
		if alt.Reachable {
			alt.Scheme = "http"
			httpx.WriteJSON(w, http.StatusOK, alt)
			return
		}
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func probe(targetURL string) DomainHealth {
	res := DomainHealth{URL: targetURL}

	// Host to verify the certificate against: the domain the operator asked about,
	// not a redirected host. Parsed from the original probe URL.
	var host string
	if u, err := url.Parse(targetURL); err == nil {
		host = u.Hostname()
	}

	// #nosec G402 -- operator-initiated health probe reports cert state; it must reach hosts with invalid/expired certs. SSRF and DNS rebinding are blocked by netguard.DialControl below.
	tlsCfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	// DialControl rejects connections to internal addresses at dial time, so the
	// initial request and every followed redirect are checked (and DNS rebinding
	// is defeated because the check runs on the concrete resolved IP).
	dialer := &net.Dialer{Timeout: 6 * time.Second, Control: netguard.DialControl}
	tr := &http.Transport{
		TLSClientConfig:       tlsCfg,
		DialContext:           dialer.DialContext,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 6 * time.Second,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   8 * time.Second,
		// Follow up to five redirects.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	start := time.Now()
	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("User-Agent", "Servika-Monitor/1.0")
	req.Header.Set("Accept", "text/html,*/*")
	resp, err := client.Do(req)
	res.ResponseTimeMS = float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		res.Error = "request failed"
		return res
	}
	defer func() { _ = resp.Body.Close() }()
	res.Reachable = true
	res.StatusCode = resp.StatusCode
	res.Server = resp.Header.Get("Server")
	res.Size = resp.ContentLength

	// Read SSL certificate information when a TLS connection exists. Verify the
	// presented chain and hostname against the system roots so a self-signed,
	// wrong-host, or MITM certificate is reported as invalid rather than trusted
	// from its dates alone. Verification runs out-of-band (the transport keeps
	// InsecureSkipVerify) so a broken certificate still reports HTTP reachability.
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		c := resp.TLS.PeerCertificates[0]
		now := time.Now()
		remainingDays := int(c.NotAfter.Sub(now).Hours() / 24)
		valid, certErr := verifyLeaf(c, resp.TLS.PeerCertificates[1:], host, nil)
		res.SSL = &SSLInfo{
			Valid:         valid,
			EndDate:       c.NotAfter.Format("2006-01-02"),
			RemainingDays: remainingDays,
			Issuer:        c.Issuer.CommonName,
			SubjectName:   c.Subject.CommonName,
			CertError:     certErr,
		}
	}
	return res
}

// verifyLeaf verifies the leaf certificate against the given intermediates and
// hostname. roots is the trusted root pool; a nil pool uses the host's system
// roots. It returns whether the certificate is trusted and, on failure, a short
// error reason suitable for an operator-facing health response.
func verifyLeaf(leaf *x509.Certificate, intermediates []*x509.Certificate, host string, roots *x509.CertPool) (bool, string) {
	var pool *x509.CertPool
	if len(intermediates) > 0 {
		pool = x509.NewCertPool()
		for _, ic := range intermediates {
			pool.AddCert(ic)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: pool,
	}); err != nil {
		return false, "certificate chain or hostname verification failed"
	}
	return true, ""
}
