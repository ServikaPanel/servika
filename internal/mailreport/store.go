package mailreport

import (
	"context"
	"database/sql"
	"strings"
)

// StoreAggregate writes one DMARC report and its rows.
//
// The header and the rows go in ONE transaction: a header without its rows is a
// report that says zero messages were seen, which is a different and wrong
// claim rather than a partial one.
//
// A report already stored is not an error. The UNIQUE key is the deduplication
// boundary precisely so a second sweep over the same mailbox costs an ignored
// insert instead of a second copy.
func StoreAggregate(ctx context.Context, db *sql.DB, domainID int64, report Report) error {
	transaction, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = transaction.Rollback() }()

	result, err := transaction.ExecContext(ctx,
		`INSERT IGNORE INTO dmarc_reports
		   (domain_id, org_name, report_id, date_begin, date_end, policy_p, policy_adkim, policy_aspf)
		 VALUES(?,?,?,?,?,?,?,?)`,
		domainID, report.OrgName, report.ReportID, report.DateBegin, report.DateEnd,
		report.PolicyP, report.PolicyADKIM, report.PolicyASPF)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return nil // already stored
	}
	reportRowID, err := result.LastInsertId()
	if err != nil {
		return err
	}

	for _, row := range report.Rows {
		if _, err := transaction.ExecContext(ctx,
			`INSERT INTO dmarc_report_rows
			   (report_row_id, source_ip, message_count, disposition, dkim_result, spf_result, header_from)
			 VALUES(?,?,?,?,?,?,?)`,
			reportRowID, row.SourceIP, row.MessageCount, row.Disposition,
			row.DKIMResult, row.SPFResult, row.HeaderFrom); err != nil {
			return err
		}
	}
	return transaction.Commit()
}

// StoreTLSRPT writes one TLS-RPT report and its failure buckets.
func StoreTLSRPT(ctx context.Context, db *sql.DB, domainID int64, report TLSReport) error {
	transaction, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = transaction.Rollback() }()

	result, err := transaction.ExecContext(ctx,
		`INSERT IGNORE INTO tlsrpt_reports
		   (domain_id, org_name, report_id, date_begin, date_end, policy_type, success_count, failure_count)
		 VALUES(?,?,?,?,?,?,?,?)`,
		domainID, report.OrgName, report.ReportID, report.DateBegin, report.DateEnd,
		report.PolicyType, report.SuccessCount, report.FailureCount)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return nil
	}
	reportRowID, err := result.LastInsertId()
	if err != nil {
		return err
	}

	for _, failure := range report.Failures {
		if _, err := transaction.ExecContext(ctx,
			`INSERT INTO tlsrpt_failures
			   (report_row_id, result_type, sending_mta_ip, receiving_mx_hostname, failed_session_count)
			 VALUES(?,?,?,?,?)`,
			reportRowID, failure.ResultType, failure.SendingMTAIP,
			failure.ReceivingMX, failure.SessionCount); err != nil {
			return err
		}
	}
	return transaction.Commit()
}

// Source is one sending address as the dashboard shows it.
type Source struct {
	SourceIP     string `json:"source_ip"`
	Messages     uint64 `json:"messages"`
	DKIMPass     uint64 `json:"dkim_pass"`
	SPFPass      uint64 `json:"spf_pass"`
	Quarantined  uint64 `json:"quarantined"`
	Rejected     uint64 `json:"rejected"`
	HeaderFroms  string `json:"header_froms"`
	ReporterName string `json:"reporter"`
}

// Sources summarises the sending addresses seen for a domain over a window.
//
// The grouping happens in SQL rather than in Go because a busy domain's window
// is thousands of rows and only the grouped result is ever shown.
func Sources(ctx context.Context, db *sql.DB, domainID int64, days int) ([]Source, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT r.source_ip,
		        SUM(r.message_count),
		        SUM(CASE WHEN r.dkim_result = 'pass' THEN r.message_count ELSE 0 END),
		        SUM(CASE WHEN r.spf_result  = 'pass' THEN r.message_count ELSE 0 END),
		        SUM(CASE WHEN r.disposition = 'quarantine' THEN r.message_count ELSE 0 END),
		        SUM(CASE WHEN r.disposition = 'reject'     THEN r.message_count ELSE 0 END),
		        GROUP_CONCAT(DISTINCT r.header_from ORDER BY r.header_from SEPARATOR ', '),
		        GROUP_CONCAT(DISTINCT h.org_name ORDER BY h.org_name SEPARATOR ', ')
		   FROM dmarc_report_rows r
		   JOIN dmarc_reports h ON h.id = r.report_row_id
		  WHERE h.domain_id = ? AND h.date_begin >= DATE_SUB(NOW(), INTERVAL ? DAY)
		  GROUP BY r.source_ip
		  ORDER BY SUM(r.message_count) DESC
		  LIMIT 500`, domainID, days)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]Source, 0, 32)
	for rows.Next() {
		var source Source
		var froms, reporters sql.NullString
		if err := rows.Scan(&source.SourceIP, &source.Messages, &source.DKIMPass,
			&source.SPFPass, &source.Quarantined, &source.Rejected, &froms, &reporters); err != nil {
			return nil, err
		}
		source.HeaderFroms = strings.TrimSpace(froms.String)
		source.ReporterName = strings.TrimSpace(reporters.String)
		out = append(out, source)
	}
	return out, rows.Err()
}

// TLSSummary is the TLS-RPT view for a domain over a window.
type TLSSummary struct {
	SuccessCount uint64       `json:"success_count"`
	FailureCount uint64       `json:"failure_count"`
	Failures     []TLSBucket  `json:"failures"`
	Reports      []TLSReportH `json:"reports"`
}

// TLSBucket is one failure reason with its total.
type TLSBucket struct {
	ResultType   string `json:"result_type"`
	ReceivingMX  string `json:"receiving_mx"`
	SessionCount uint64 `json:"session_count"`
}

// TLSReportH is one report header, so a screen can say who reported and when.
type TLSReportH struct {
	OrgName   string `json:"org_name"`
	DateBegin string `json:"date_begin"`
	Success   uint64 `json:"success_count"`
	Failure   uint64 `json:"failure_count"`
}

// TLSOverview summarises TLS-RPT reports for a domain over a window.
func TLSOverview(ctx context.Context, db *sql.DB, domainID int64, days int) (TLSSummary, error) {
	summary := TLSSummary{Failures: []TLSBucket{}, Reports: []TLSReportH{}}

	headers, err := db.QueryContext(ctx,
		`SELECT org_name, DATE_FORMAT(date_begin,'%Y-%m-%d'), success_count, failure_count
		   FROM tlsrpt_reports
		  WHERE domain_id = ? AND date_begin >= DATE_SUB(NOW(), INTERVAL ? DAY)
		  ORDER BY date_begin DESC LIMIT 100`, domainID, days)
	if err != nil {
		return summary, err
	}
	for headers.Next() {
		var header TLSReportH
		if err := headers.Scan(&header.OrgName, &header.DateBegin, &header.Success, &header.Failure); err != nil {
			_ = headers.Close()
			return summary, err
		}
		summary.SuccessCount += header.Success
		summary.FailureCount += header.Failure
		summary.Reports = append(summary.Reports, header)
	}
	if err := headers.Err(); err != nil {
		_ = headers.Close()
		return summary, err
	}
	if err := headers.Close(); err != nil {
		return summary, err
	}

	buckets, err := db.QueryContext(ctx,
		`SELECT f.result_type, f.receiving_mx_hostname, SUM(f.failed_session_count)
		   FROM tlsrpt_failures f
		   JOIN tlsrpt_reports h ON h.id = f.report_row_id
		  WHERE h.domain_id = ? AND h.date_begin >= DATE_SUB(NOW(), INTERVAL ? DAY)
		  GROUP BY f.result_type, f.receiving_mx_hostname
		  ORDER BY SUM(f.failed_session_count) DESC LIMIT 100`, domainID, days)
	if err != nil {
		return summary, err
	}
	defer func() { _ = buckets.Close() }()
	for buckets.Next() {
		var bucket TLSBucket
		if err := buckets.Scan(&bucket.ResultType, &bucket.ReceivingMX, &bucket.SessionCount); err != nil {
			return summary, err
		}
		summary.Failures = append(summary.Failures, bucket)
	}
	return summary, buckets.Err()
}
