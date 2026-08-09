package stats

import (
	"bufio"
	"database/sql"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var trafficDomainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// StartTrafficAggregator periodically aggregates nginx traffic for every domain.
func StartTrafficAggregator(db *sql.DB, every time.Duration) {
	go func() {
		time.Sleep(30 * time.Second)
		AggregateAll(db)
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for range ticker.C {
			AggregateAll(db)
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
	logPath := "/var/log/nginx/" + domainName + ".access.log"
	info, err := os.Stat(logPath)
	if err != nil {
		refreshTrafficKB(db, domainID)
		return false
	}
	size := info.Size()

	// `offset` is backticked because OFFSET is a reserved word from MariaDB 10.6
	// onward. Unquoted it is a parse error, and the error is discarded here, so
	// the cursor would silently read as zero and every pass would count the whole
	// access log again on top of what it had already stored.
	var offset, previousSize int64
	_ = db.QueryRow("SELECT `offset`, `size` FROM domain_traffic_cursor WHERE domain_id=?", domainID).Scan(&offset, &previousSize)
	start := offset
	if size < offset || size < previousSize {
		start = 0
	}
	if start == size {
		refreshTrafficKB(db, domainID)
		return true
	}

	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	file, err := os.Open(logPath)
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()
	if start > 0 {
		if _, err := file.Seek(start, 0); err != nil {
			start = 0
			_, _ = file.Seek(0, 0)
		}
	}

	reader := bufio.NewReaderSize(file, 256*1024)
	monthly := map[string]int64{}
	consumed := start
	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > 0 && strings.HasSuffix(line, "\n") {
			consumed += int64(len(line))
			if month, bytes, ok := parseTrafficLine(line); ok {
				monthly[month] += bytes
			}
		}
		if readErr != nil {
			break
		}
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("begin traffic update domain=%d: %v", domainID, err)
		return false
	}
	defer func() { _ = tx.Rollback() }()
	for month, bytes := range monthly {
		if bytes <= 0 {
			continue
		}
		// `year_month` is backticked for the same reason as `offset` above: it is
		// an interval unit, so MariaDB reserves it and reads it unquoted as
		// syntax rather than a column name.
		if _, err := tx.Exec(
			"INSERT INTO domain_traffic(domain_id, `year_month`, bytes) VALUES(?,?,?)\n"+
				" ON DUPLICATE KEY UPDATE bytes=bytes+VALUES(bytes)",
			domainID, month, bytes); err != nil {
			log.Printf("traffic upsert domain=%d month=%s: %v", domainID, month, err)
			return false
		}
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
	refreshTrafficKB(db, domainID)
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
