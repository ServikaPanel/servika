package stats

import (
	"bufio"
	"database/sql"
	"errors"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"servika/internal/bgjob"
)

const trafficJobName = "stats: traffic aggregator"

var trafficDomainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// trafficLogRoot is a seam so a test can point the aggregator at a temporary
// access log instead of the host's. nginx writes the real ones here.
var trafficLogRoot = "/var/log/nginx/"

// StartTrafficAggregator periodically aggregates nginx traffic for every domain.
func StartTrafficAggregator(db *sql.DB, every time.Duration) {
	go func() {
		time.Sleep(30 * time.Second)
		// Each pass is guarded on its own: an unrecovered panic here would take
		// the whole panel process down, and recovering only at the loop's exit
		// would leave the aggregator silent until the next restart.
		bgjob.Guard(trafficJobName, func() { AggregateAll(db) })
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for range ticker.C {
			bgjob.Guard(trafficJobName, func() { AggregateAll(db) })
		}
	}()
}

// AggregateAll aggregates traffic and returns the number of processed domains.
func AggregateAll(db *sql.DB) int {
	rows, err := db.Query(`SELECT id, domain_name FROM domains`)
	if err != nil {
		log.Printf("traffic domain list: %v", err)
		return 0
	}
	type domain struct {
		id   int64
		name string
	}
	domains := make([]domain, 0)
	for rows.Next() {
		var item domain
		if err := rows.Scan(&item.id, &item.name); err == nil {
			domains = append(domains, item)
		}
	}
	if err := rows.Err(); err != nil {
		// A domain missing from this pass has its traffic counted on the next one
		// only if the log has not rotated first, so the figure is lost, not late.
		log.Printf("traffic aggregator: could not read the domain list: %v", err)
	}
	_ = rows.Close()

	processed := 0
	for _, item := range domains {
		if aggregateDomain(db, item.id, item.name) {
			processed++
		}
	}
	return processed
}

func aggregateDomain(db *sql.DB, domainID int64, domainName string) bool {
	if !trafficDomainPattern.MatchString(domainName) {
		log.Printf("traffic rejected unsafe domain name for domain=%d", domainID)
		return false
	}
	logPath := trafficLogRoot + domainName + ".access.log"
	info, err := os.Stat(logPath)
	if err != nil {
		refreshTrafficKB(db, domainID)
		return false
	}
	size := info.Size()

	start, ok := readCursor(db, domainID, size)
	if !ok {
		return false
	}
	if start == size {
		refreshTrafficKB(db, domainID)
		return true
	}

	monthly, consumed, ok := readLog(logPath, domainID, start)
	if !ok {
		return false
	}

	if !storeTraffic(db, domainID, monthly, consumed, size) {
		return false
	}
	refreshTrafficKB(db, domainID)
	return true
}

// readCursor returns the offset this pass starts at, and whether the pass may
// go on at all.
//
// The error is NOT discarded, and that is the whole point. sql.ErrNoRows is
// the legitimate first pass and means "start at zero"; anything else means
// the cursor could not be read, and starting at zero there re-parses the
// entire access log and ADDS it on top of what is already stored, because
// the merge is `bytes=bytes+VALUES(bytes)`. That figure is not cosmetic:
// it becomes domains.traffic_kb, which a reseller's contracted traffic ceiling
// is measured against, so one transient read failure could push a reseller over
// a quota they never used, for the rest of the month, with nothing in the
// journal saying so.
//
// `offset` is backticked because OFFSET is a reserved word from MariaDB 10.6
// onward. Unquoted it is a parse error.
func readCursor(db *sql.DB, domainID, size int64) (start int64, ok bool) {
	var offset, previousSize int64
	switch err := db.QueryRow("SELECT `offset`, `size` FROM domain_traffic_cursor WHERE domain_id=?",
		domainID).Scan(&offset, &previousSize); {
	case errors.Is(err, sql.ErrNoRows):
		// No cursor yet: this domain has never been counted, so zero is right.
	case err != nil:
		// #nosec G706 -- an integer domain id and a MariaDB driver error for a parameterized statement; no tenant string reaches the log.
		log.Printf("traffic cursor read domain=%d: %v; this domain is not accounted this pass", domainID, err)
		return 0, false
	}
	if size < offset || size < previousSize {
		// The log is smaller than it was, so it rotated and the stored offset
		// points into a different file.
		return 0, true
	}
	return offset, true
}

// readLog counts the bytes each month gained since start, and reports where the
// reading stopped.
func readLog(logPath string, domainID, start int64) (monthly map[string]int64, consumed int64, ok bool) {
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	file, err := os.Open(logPath)
	if err != nil {
		// #nosec G706 -- an integer domain id and an os error naming a path built from a validated domain name; no raw tenant string reaches the log.
		log.Printf("traffic log open domain=%d: %v; this domain is not accounted this pass", domainID, err)
		return nil, 0, false
	}
	defer func() { _ = file.Close() }()
	if start > 0 {
		if _, err := file.Seek(start, 0); err != nil {
			// Rewinding re-counts the whole log on top of what is stored, for
			// the same reason the cursor read above must not fail silently. Stop
			// instead: a pass skipped is recoverable, a doubled figure is not.
			// #nosec G706 -- an integer domain id, an integer offset and an os error; no tenant string reaches the log.
			log.Printf("traffic log seek domain=%d offset=%d: %v; this domain is not accounted this pass",
				domainID, start, err)
			return nil, 0, false
		}
	}

	reader := bufio.NewReaderSize(file, 256*1024)
	monthly = map[string]int64{}
	consumed = start
	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > 0 && strings.HasSuffix(line, "\n") {
			consumed += int64(len(line))
			if month, bytes, parsed := parseTrafficLine(line); parsed {
				monthly[month] += bytes
			}
		}
		if readErr != nil {
			break
		}
	}
	return monthly, consumed, true
}

// storeTraffic merges the counted months and the new cursor in ONE transaction,
// so a failure leaves the cursor where it was and the same bytes are counted
// again rather than lost or doubled.
func storeTraffic(db *sql.DB, domainID int64, monthly map[string]int64, consumed, size int64) bool {
	tx, err := db.Begin()
	if err != nil {
		log.Printf("begin traffic update domain=%d: %v", domainID, err)
		return false
	}
	defer func() { _ = tx.Rollback() }()
	if !mergeMonths(tx, domainID, monthly) {
		return false
	}
	if _, err := tx.Exec(
		"INSERT INTO domain_traffic_cursor(domain_id, `offset`, `size`) VALUES(?,?,?)\n"+
			" ON DUPLICATE KEY UPDATE `offset`=VALUES(`offset`), `size`=VALUES(`size`)",
		domainID, consumed, size); err != nil {
		log.Printf("traffic cursor update domain=%d: %v", domainID, err)
		return false
	}
	if err := tx.Commit(); err != nil {
		log.Printf("commit traffic update domain=%d: %v", domainID, err)
		return false
	}
	return true
}

// mergeMonths adds each counted month to the stored total.
//
// `year_month` is backticked for the same reason as `offset` above: it is an
// interval unit, so MariaDB reserves it and reads it unquoted as syntax rather
// than a column name.
func mergeMonths(tx *sql.Tx, domainID int64, monthly map[string]int64) bool {
	for month, bytes := range monthly {
		if bytes <= 0 {
			continue
		}
		if _, err := tx.Exec(
			"INSERT INTO domain_traffic(domain_id, `year_month`, bytes) VALUES(?,?,?)\n"+
				" ON DUPLICATE KEY UPDATE bytes=bytes+VALUES(bytes)",
			domainID, month, bytes); err != nil {
			log.Printf("traffic upsert domain=%d month=%s: %v", domainID, month, err)
			return false
		}
	}
	return true
}

func refreshTrafficKB(db *sql.DB, domainID int64) {
	month := time.Now().UTC().Format("2006-01")
	var bytes int64
	_ = db.QueryRow("SELECT bytes FROM domain_traffic WHERE domain_id=? AND `year_month`=?", domainID, month).Scan(&bytes)
	_, _ = db.Exec(`UPDATE domains SET traffic_kb=? WHERE id=?`, bytes/1024, domainID)
}

func parseTrafficLine(line string) (string, int64, bool) {
	matches := reLog.FindStringSubmatch(line)
	if matches == nil {
		return "", 0, false
	}
	parsed, err := time.Parse("02/Jan/2006", strings.TrimSpace(matches[2]))
	if err != nil {
		return "", 0, false
	}
	bytes := int64(0)
	if matches[6] != "-" {
		bytes, err = strconv.ParseInt(matches[6], 10, 64)
		if err != nil || bytes < 0 {
			return "", 0, false
		}
	}
	return parsed.Format("2006-01"), bytes, true
}
