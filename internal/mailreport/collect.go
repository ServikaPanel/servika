package mailreport

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Reading reports out of the mailbox the DNS record already names.
//
// The panel does not own that mailbox. `postmaster@` is a real address people
// write to, so the collector is STRICTLY READ-ONLY: no message is deleted,
// moved, or has its flags changed. That rules out the usual "process and
// remove" design and with it any cursor that depends on a filename, because
// Dovecot renames a Maildir file whenever its flags change.
//
// Two layers replace it. The leading epoch second of a Maildir unique name
// survives those renames, so it is a cheap filter for "newer than the last
// pass". Correctness rests on the UNIQUE keys in the schema: a report seen
// twice is one insert and one ignored duplicate.

const (
	// collectInterval is how often the mailboxes are swept. Reports arrive
	// daily, so this only decides how soon after delivery one appears.
	collectInterval = 15 * time.Minute
	// collectStartDelay keeps the first sweep out of the boot sequence.
	collectStartDelay = 90 * time.Second
	// maxMessagesPerPass bounds one domain's sweep so a mailbox with a large
	// backlog cannot hold the pass open indefinitely. The cursor does not
	// advance past what was read, so the rest is picked up next time.
	maxMessagesPerPass = 500
)

// StartCollector sweeps every mail domain's report mailbox on a timer.
func StartCollector(db *sql.DB) {
	go func() {
		time.Sleep(collectStartDelay)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			if err := CollectAll(ctx, db); err != nil {
				log.Printf("mail report collector: %v", err)
			}
			cancel()
			time.Sleep(collectInterval)
		}
	}()
}

// domainTarget is one domain's report mailbox.
type domainTarget struct {
	domainID     int64
	mailboxLocal string
	maildir      string
	cursorEpoch  int64
}

// CollectAll reads new reports for every active mail domain.
func CollectAll(ctx context.Context, db *sql.DB) error {
	targets, err := loadTargets(ctx, db)
	if err != nil {
		return err
	}
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		collectDomain(ctx, db, target)
	}
	return nil
}

// loadTargets pairs each active mail domain with its report mailbox.
//
// The join is LEFT because a domain whose mailbox does not exist is the case
// this feature has to REPORT, not skip: the DNS record already asks the world
// to send reports there, so an absent mailbox is the single most likely reason
// a customer sees an empty dashboard.
func loadTargets(ctx context.Context, db *sql.DB) ([]domainTarget, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT md.domain_id,
		        COALESCE(c.mailbox_local, 'postmaster'),
		        COALESCE(mb.maildir, ''),
		        COALESCE(c.last_message_epoch, 0)
		   FROM mail_domains md
		   LEFT JOIN mail_report_cursor c ON c.domain_id = md.domain_id
		   LEFT JOIN mailboxes mb
		          ON mb.domain_id = md.domain_id
		         AND mb.local_part = COALESCE(c.mailbox_local, 'postmaster')
		         AND mb.status = 'active'
		  WHERE md.status = 'active'
		  ORDER BY md.domain_id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var targets []domainTarget
	for rows.Next() {
		var target domainTarget
		if err := rows.Scan(&target.domainID, &target.mailboxLocal,
			&target.maildir, &target.cursorEpoch); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

// collectDomain sweeps one domain's mailbox and records what happened.
//
// Every outcome, including "there is no such mailbox", is written to the cursor
// row so the status endpoint can answer with a reason rather than leaving an
// empty dashboard to speak for itself.
func collectDomain(ctx context.Context, db *sql.DB, target domainTarget) {
	if target.maildir == "" {
		saveCursor(ctx, db, target, target.cursorEpoch, "mailbox not found")
		return
	}
	names, newest, err := newMessages(target.maildir, target.cursorEpoch)
	if err != nil {
		saveCursor(ctx, db, target, target.cursorEpoch, "mailbox could not be read")
		log.Printf("mail report: read %s for domain %d: %v", target.maildir, target.domainID, err)
		return
	}

	var failures int
	for _, name := range names {
		raw, err := readMessage(name)
		if err != nil {
			failures++
			log.Printf("mail report: read a message for domain %d: %v", target.domainID, err)
			continue
		}
		for _, document := range Attachments(raw) {
			storeDocument(ctx, db, target.domainID, document)
		}
	}
	reason := ""
	if failures > 0 {
		reason = strconv.Itoa(failures) + " messages could not be read"
	}
	saveCursor(ctx, db, target, newest, reason)
}

// storeDocument tries a document as each report kind and stores the one it is.
//
// A document that is neither is not an error: a postmaster mailbox is mostly
// ordinary mail, and every part of every message reaches here.
func storeDocument(ctx context.Context, db *sql.DB, domainID int64, document []byte) {
	if report, err := ParseAggregate(document); err == nil {
		if err := StoreAggregate(ctx, db, domainID, report); err != nil {
			log.Printf("mail report: store a DMARC report for domain %d: %v", domainID, err)
		}
		return
	} else if !errors.Is(err, ErrNotAReport) {
		// A document that IS a report and was refused is worth saying out loud:
		// silently skipping it would look identical to no report arriving.
		log.Printf("mail report: refused a DMARC report for domain %d: %v", domainID, err)
		return
	}
	if report, err := ParseTLSRPT(document); err == nil {
		if err := StoreTLSRPT(ctx, db, domainID, report); err != nil {
			log.Printf("mail report: store a TLS-RPT report for domain %d: %v", domainID, err)
		}
	} else if !errors.Is(err, ErrNotAReport) {
		log.Printf("mail report: refused a TLS-RPT report for domain %d: %v", domainID, err)
	}
}

// newMessages lists the message files newer than the cursor, and the newest
// epoch seen. Both `cur` and `new` are read: a message the customer has already
// opened has moved to `cur`, and the report inside it is no less valid.
func newMessages(maildir string, since int64) ([]string, int64, error) {
	newest := since
	var names []string
	for _, sub := range []string{"new", "cur"} {
		entries, err := os.ReadDir(filepath.Join(maildir, sub))
		if err != nil {
			if os.IsNotExist(err) {
				continue // a Maildir without `new` yet is empty, not broken
			}
			return nil, since, err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			epoch, dated := maildirEpoch(entry.Name())
			if dated {
				if epoch <= since {
					continue
				}
				if epoch > newest {
					newest = epoch
				}
			}
			names = append(names, filepath.Join(maildir, sub, entry.Name()))
			if len(names) >= maxMessagesPerPass {
				// The cursor advances only as far as what was actually read, so
				// the remainder is picked up on the next pass rather than lost.
				return names, newest, nil
			}
		}
	}
	return names, newest, nil
}

// maildirEpoch reads the delivery second from a Maildir unique name
// (`<epoch>.<unique>.<host>[:2,<flags>]`).
//
// The second return says whether the name carried one. A name that did not is
// ALWAYS eligible and never advances the cursor: reading it again on the next
// pass costs one ignored duplicate insert, while skipping it would lose a
// report for good, and a delivery agent is free to name a file however it likes.
func maildirEpoch(name string) (int64, bool) {
	digits := name
	if index := strings.IndexByte(name, '.'); index > 0 {
		digits = name[:index]
	}
	epoch, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || epoch < 0 {
		return 0, false
	}
	return epoch, true
}

// saveCursor records where the sweep got to and why it stopped there.
func saveCursor(ctx context.Context, db *sql.DB, target domainTarget, epoch int64, reason string) {
	if _, err := db.ExecContext(ctx,
		`INSERT INTO mail_report_cursor(domain_id, mailbox_local, last_scan_at, last_message_epoch, last_error)
		 VALUES(?,?,NOW(),?,?)
		 ON DUPLICATE KEY UPDATE last_scan_at=NOW(), last_message_epoch=VALUES(last_message_epoch),
		   last_error=VALUES(last_error)`,
		target.domainID, target.mailboxLocal, epoch, reason); err != nil {
		log.Printf("mail report: save the cursor for domain %d: %v", target.domainID, err)
	}
}
