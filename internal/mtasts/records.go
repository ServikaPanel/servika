package mtasts

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"servika/internal/dns"
)

// The three records MTA-STS and TLS-RPT need, by their in-zone label.
//
// They are written to the domain's OWN zone rather than the shared template.
// The template shapes every zone created after it changes, so a name there would
// reach domains that never asked for MTA-STS, and each of those would then
// resolve mta-sts.<domain> and pull the name into their certificate order (K2).
const (
	labelPolicyHost = "mta-sts"    // A, points the policy host at this server
	labelPolicyTXT  = "_mta-sts"   // TXT, carries the id senders cache against
	labelReportTXT  = "_smtp._tls" // TXT, asks for TLS-RPT reports
)

// upsertRecord writes one record, replacing an existing row with the same label
// and type rather than adding a second one.
//
// A duplicate would not be a cosmetic problem: two _mta-sts TXT records make the
// policy id ambiguous and RFC 8461 section 3.1 says a sender MUST treat that as
// no record at all, which silently un-publishes the policy.
func upsertRecord(ctx context.Context, tx *sql.Tx, domainID int64, name, recordType, value string) error {
	res, err := tx.ExecContext(ctx,
		`UPDATE dns_records SET value=?, ttl=3600, priority=0, enabled=1
		  WHERE domain_id=? AND name=? AND type=?`,
		value, domainID, name, recordType)
	if err != nil {
		return err
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if changed > 0 {
		return nil
	}
	// RowsAffected is 0 both when no row matched and when the row already held
	// this exact value, so the insert has to be conditional on absence rather
	// than on the update having missed.
	var present int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM dns_records WHERE domain_id=? AND name=? AND type=?`,
		domainID, name, recordType).Scan(&present); err != nil {
		return err
	}
	if present > 0 {
		return nil
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO dns_records(domain_id, name, type, value, ttl, priority, enabled)
		 VALUES(?,?,?,?,3600,0,1)`,
		domainID, name, recordType, value)
	return err
}

func deleteRecord(ctx context.Context, tx *sql.Tx, domainID int64, name, recordType string) error {
	_, err := tx.ExecContext(ctx,
		`DELETE FROM dns_records WHERE domain_id=? AND name=? AND type=?`,
		domainID, name, recordType)
	return err
}

// reportAddress is where DMARC and TLS-RPT reports are asked for.
//
// It matches the rua the DNS template already publishes for _dmarc, so the two
// report streams land in the same mailbox and the panel reads both with one
// collector.
func reportAddress(domainName string) string { return "postmaster@" + domainName }

// WriteEnableRecords publishes the policy host and the TLS-RPT address.
//
// The policy TXT is deliberately NOT written here. Publishing an id before the
// policy file is fetchable tells senders a policy exists at a host that does not
// answer yet, and RFC 8461 section 5 says a sender that fails to fetch a policy
// it was told about keeps trying rather than treating the domain as unprotected.
func WriteEnableRecords(ctx context.Context, db *sql.DB, domainID int64, domainName, ipv4 string) error {
	if strings.TrimSpace(ipv4) == "" {
		return fmt.Errorf("the server address is unknown, so the policy host cannot be pointed at it")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if err := upsertRecord(ctx, tx, domainID, labelPolicyHost, "A", ipv4); err != nil {
		return err
	}
	if err := upsertRecord(ctx, tx, domainID, labelReportTXT, "TXT",
		ReportTXT(reportAddress(domainName))); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return dns.WriteZone(ctx, db, domainID)
}

// WritePolicyTXT publishes the id senders cache the policy against.
func WritePolicyTXT(ctx context.Context, db *sql.DB, domainID int64, id string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if err := upsertRecord(ctx, tx, domainID, labelPolicyTXT, "TXT", PolicyTXT(id)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return dns.WriteZone(ctx, db, domainID)
}

// RemoveRecords withdraws the publication.
//
// This runs at the END of a withdrawal, never at the start. Deleting the records
// while senders still hold a cached enforce policy does not cancel it: they keep
// applying what they fetched, against a host that has stopped proving it, and
// refuse to deliver (K3). The TLS-RPT address is left in place because reporting
// costs nothing and is what shows whether the withdrawal was needed.
func RemoveRecords(ctx context.Context, db *sql.DB, domainID int64) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if err := deleteRecord(ctx, tx, domainID, labelPolicyTXT, "TXT"); err != nil {
		return err
	}
	if err := deleteRecord(ctx, tx, domainID, labelPolicyHost, "A"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return dns.WriteZone(ctx, db, domainID)
}
