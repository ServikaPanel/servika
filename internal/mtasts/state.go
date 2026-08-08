package mtasts

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"servika/internal/provisioner"
)

// State is what the panel knows about one domain's MTA-STS publication.
type State struct {
	Mode Mode `json:"mode"`
	// PolicyID is the value in the _mta-sts TXT record.
	PolicyID string `json:"policy_id,omitempty"`
	// ChangedAt is when the mode last moved, which is what the enforce soak is
	// measured from.
	ChangedAt string `json:"changed_at,omitempty"`
	// MXHosts is what the policy names.
	MXHosts []string `json:"mx_hosts"`
	// DNSReady and CertReady say which step the sequence is waiting on, so a
	// screen can name the blocker instead of showing a spinner.
	DNSReady  bool `json:"dns_ready"`
	CertReady bool `json:"cert_ready"`
	// EnforceBlocked and EnforceReason say why the enforce control is locked.
	// The reason is a stable CODE, never a sentence: the screen renders it in
	// the reader's own language.
	EnforceBlocked bool   `json:"enforce_blocked"`
	EnforceReason  string `json:"enforce_reason,omitempty"`
}

// Enforce lock reasons. These are contract values, not prose.
const (
	ReasonNotTesting  = "not_testing"
	ReasonSoak        = "soak_incomplete"
	ReasonMXCertUnset = "mx_certificate_missing"
)

// newPolicyID returns a fresh id for the _mta-sts TXT record.
func newPolicyID() (string, error) {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

// domainRow is what the state machine needs about a domain.
type domainRow struct {
	domainName string
	mode       Mode
	policyID   string
	changedAt  sql.NullString
}

func loadDomain(ctx context.Context, db *sql.DB, domainID int64) (domainRow, error) {
	var row domainRow
	var mode string
	err := db.QueryRowContext(ctx,
		`SELECT d.domain_name, md.mtasts_mode, md.mtasts_id,
		        DATE_FORMAT(md.mtasts_changed_at, '%Y-%m-%d %H:%i')
		   FROM mail_domains md
		   JOIN domains d ON d.id = md.domain_id
		  WHERE md.domain_id = ? AND md.status = 'active'`, domainID).
		Scan(&row.domainName, &mode, &row.policyID, &row.changedAt)
	row.mode = Mode(mode)
	return row, err
}

// MXHosts returns the hostnames the policy will name.
//
// They come from the domain's own MX records rather than a constant, because a
// policy that names a server the domain does not actually publish MX for would
// reject every message in enforce mode.
func MXHosts(ctx context.Context, db *sql.DB, domainID int64) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT value FROM dns_records
		  WHERE domain_id = ? AND type = 'MX' AND enabled = 1
		  ORDER BY priority, value`, domainID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var hosts []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		host := strings.TrimSuffix(strings.TrimSpace(value), ".")
		if host != "" && !strings.ContainsAny(host, " \t\r\n") {
			hosts = append(hosts, host)
		}
	}
	return hosts, rows.Err()
}

// Read returns the current state, including which step the sequence waits on.
func Read(ctx context.Context, db *sql.DB, domainID int64) (State, error) {
	row, err := loadDomain(ctx, db, domainID)
	if err != nil {
		return State{}, err
	}
	hosts, err := MXHosts(ctx, db, domainID)
	if err != nil {
		return State{}, err
	}
	state := State{
		Mode:      row.mode,
		PolicyID:  row.policyID,
		ChangedAt: row.changedAt.String,
		MXHosts:   hosts,
		DNSReady:  dnsResolves(row.domainName),
	}
	state.CertReady = certCovers(row.domainName)
	state.EnforceBlocked, state.EnforceReason = enforceLock(ctx, db, domainID, row, hosts)
	return state, nil
}

// dnsResolves reports whether mta-sts.<domain> points at this server yet.
var dnsResolves = provisioner.MTASTSResolvesToApex

// certCovers reports whether the certificate the vhost serves names
// mta-sts.<domain>.
var certCovers = provisioner.MTASTSCertificateReady

// mxCertCovers reports whether the certificate a SENDER is presented for a
// policy's MX hostname names it.
//
// That is the mail certificate, not the web one: a sender connecting to the MX
// gets whatever Postfix's SNI map holds, so asking the web vhost's certificate
// would answer a different question and unlock enforce on a mismatch.
var mxCertCovers = provisioner.MailSNICovers

// enforceLock decides whether enforce may be selected, and says why not.
//
// This is the guard that keeps MTA-STS from losing mail. Enforce is refused
// unless the policy has soaked in testing AND the certificate a sender will be
// shown for every MX host in the policy actually names that host: a sender
// honouring an enforce policy against a mismatched certificate does not deliver
// and does not bounce.
func enforceLock(ctx context.Context, db *sql.DB, domainID int64, row domainRow, hosts []string) (bool, string) {
	if row.mode != ModeTesting && row.mode != ModeEnforce {
		return true, ReasonNotTesting
	}
	if len(hosts) == 0 {
		return true, ReasonMXCertUnset
	}
	for _, host := range hosts {
		if !mxCertCovers(host) {
			return true, ReasonMXCertUnset
		}
	}
	if row.mode == ModeEnforce {
		return false, "" // already there
	}
	var soaked int
	if err := db.QueryRowContext(ctx,
		`SELECT mtasts_changed_at IS NOT NULL
		        AND mtasts_changed_at <= DATE_SUB(NOW(), INTERVAL ? DAY)
		   FROM mail_domains WHERE domain_id = ?`, TestingSoakDays, domainID).Scan(&soaked); err != nil {
		// FAIL-CLOSED: an unreadable timestamp must not unlock the one control
		// in the panel that can stop mail being delivered.
		log.Printf("mtasts: read the testing soak for domain %d: %v", domainID, err)
		return true, ReasonSoak
	}
	if soaked != 1 {
		return true, ReasonSoak
	}
	return false, ""
}

// setMode writes a mode and, when the policy content changes with it, a fresh
// id so senders refetch instead of keeping what they cached.
func setMode(ctx context.Context, db *sql.DB, domainID int64, mode Mode, newID bool) (string, error) {
	id := ""
	if newID {
		fresh, err := newPolicyID()
		if err != nil {
			return "", err
		}
		id = fresh
		if _, err := db.ExecContext(ctx,
			`UPDATE mail_domains SET mtasts_mode=?, mtasts_id=?, mtasts_changed_at=NOW()
			  WHERE domain_id=?`, string(mode), id, domainID); err != nil {
			return "", err
		}
		return id, nil
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE mail_domains SET mtasts_mode=?, mtasts_changed_at=NOW() WHERE domain_id=?`,
		string(mode), domainID); err != nil {
		return "", err
	}
	return "", nil
}

// describe renders a mode for a log line without letting a database value reach
// the log unchecked.
func describe(mode Mode) string {
	if Published(mode) || mode == ModeOff || mode == ModePendingDNS || mode == ModePendingCert {
		return string(mode)
	}
	return fmt.Sprintf("unknown(%d)", len(mode))
}
