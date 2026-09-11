// porta.go: BIND zone-file import/export for a domain.
//
//	Export: returns the domain's DNS records plus SOA as a standard, portable
//	  BIND zone file (downloadable), so a zone can move to another panel.
//	Import: parses an uploaded BIND zone file and either merges its records
//	  into the domain or replaces the existing set, then re-renders and
//	  validates the zone (WriteZone runs named-checkzone + reload).
package dns

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

// typeOrder groups records for readable export output.
var typeOrder = map[string]int{
	"NS": 0, "A": 1, "AAAA": 2, "CNAME": 3, "MX": 4, "TXT": 5,
	"SRV": 6, "CAA": 7, "PTR": 8, "DS": 9, "TLSA": 10, "SSHFP": 11, "NAPTR": 12,
}

// Export writes the domain's DNS records and SOA as a downloadable BIND zone file.
func (h *Handlers) Export(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	domainName, err := h.lookup(r)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	soa := LoadSOA(r.Context(), h.DB, id, domainName)
	rows, err := h.DB.QueryContext(r.Context(), selectAll+" WHERE domain_id=? AND enabled=1", id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	defer func() { _ = rows.Close() }()
	var records []Record
	for rows.Next() {
		if rec, e := scan(rows); e == nil {
			records = append(records, rec)
		}
	}
	if err := rows.Err(); err != nil {
		// This file is what an operator loads into another nameserver. A zone
		// short of its records would be exported, imported and served, with the
		// missing names looking like they were never there.
		httpx.WriteError(w, http.StatusInternalServerError, "dns record read failed")
		return
	}
	zone := renderBindZone(domainName, soa, records)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+domainName+`.zone"`)
	_, _ = w.Write([]byte(zone))
}

// renderBindZone produces a standard, portable BIND zone text from records + SOA.
func renderBindZone(domainName string, soa SOA, records []Record) string {
	origin := strings.TrimSuffix(domainName, ".") + "."
	var b strings.Builder
	fmt.Fprintf(&b, "$ORIGIN %s\n$TTL %d\n", origin, soa.TTL)
	fmt.Fprintf(&b, "@\tIN\tSOA\t%s %s (\n", soaHost(soa.PrimaryNS), soaMail(soa.Hostmaster))
	fmt.Fprintf(&b, "\t\t\t%s ; serial\n", time.Now().UTC().Format("20060102")+"01")
	fmt.Fprintf(&b, "\t\t\t%d ; refresh\n", soa.Refresh)
	fmt.Fprintf(&b, "\t\t\t%d ; retry\n", soa.Retry)
	fmt.Fprintf(&b, "\t\t\t%d ; expire\n", soa.Expire)
	fmt.Fprintf(&b, "\t\t\t%d ; minimum\n\t\t\t)\n", soa.Minimum)

	sort.SliceStable(records, func(i, j int) bool {
		ti, tj := typeOrder[records[i].Type], typeOrder[records[j].Type]
		if ti != tj {
			return ti < tj
		}
		return records[i].Name < records[j].Name
	})
	lastType := ""
	for _, rec := range records {
		if rec.Type != lastType {
			fmt.Fprintf(&b, "\n; %s\n", rec.Type)
			lastType = rec.Type
		}
		name := rec.Name
		if name == "" {
			name = "@"
		}
		prio := ""
		if rec.Type == "MX" || rec.Type == "SRV" {
			prio = strconv.Itoa(rec.Priority) + " "
		}
		fmt.Fprintf(&b, "%s\t%d\tIN\t%s\t%s%s\n", name, rec.TTL, rec.Type, prio, rdata(rec.Type, rec.Value))
	}
	return b.String()
}

// Import parses an uploaded BIND zone file and merges or replaces the records.
func (h *Handlers) Import(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	domainName, err := h.lookup(r)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}

	content, read := readZoneUpload(w, r)
	if !read {
		return
	}
	if len(strings.TrimSpace(string(content))) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "empty zone content")
		return
	}

	records, soaParsed := parseBindZone(string(content), domainName)
	if len(records) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "no valid DNS record found (check the file format)")
		return
	}

	replace := r.URL.Query().Get("mode") == "replace"

	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	defer func() { _ = tx.Rollback() }()

	added, skipped, stored := importRecords(w, r, tx, id, records, replace)
	if !stored {
		return
	}
	writeImportedSOA(r, tx, id, soaParsed)
	if e := tx.Commit(); e != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	h.writeImportResult(w, r, id, added, skipped, replace)
}

// readZoneUpload returns the zone text of the request, whether it came as a
// multipart upload or as a plain body. It answers the client itself when the
// upload cannot be read.
func readZoneUpload(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20) // a zone file is small
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		content, _ := io.ReadAll(r.Body)
		return content, true
	}
	// #nosec G120 -- body is bounded by MaxBytesReader above, so parsing cannot exhaust memory.
	if e := r.ParseMultipartForm(2 << 20); e != nil {
		httpx.WriteError(w, http.StatusBadRequest, "could not read the upload")
		return nil, false
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()
	f, _, e := r.FormFile("file")
	if e != nil {
		httpx.WriteError(w, http.StatusBadRequest, "file field not found")
		return nil, false
	}
	defer func() { _ = f.Close() }()
	content, _ := io.ReadAll(f)
	return content, true
}

// importRecords writes the parsed records inside tx and reports how many it
// added and skipped. It answers the client itself when a statement fails.
func importRecords(w http.ResponseWriter, r *http.Request, tx *sql.Tx, id int64, records []Record, replace bool) (added, skipped int, stored bool) {
	if replace {
		if _, e := tx.ExecContext(r.Context(), `DELETE FROM dns_records WHERE domain_id=?`, id); e != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not remove the existing records")
			return 0, 0, false
		}
	}
	for _, rec := range records {
		if !replace {
			var n int
			_ = tx.QueryRowContext(r.Context(),
				`SELECT COUNT(*) FROM dns_records WHERE domain_id=? AND name=? AND type=? AND value=?`,
				id, rec.Name, rec.Type, rec.Value).Scan(&n)
			if n > 0 {
				skipped++
				continue
			}
		}
		if _, e := tx.ExecContext(r.Context(),
			`INSERT INTO dns_records(domain_id, name, type, value, ttl, priority, enabled)
			 VALUES(?,?,?,?,?,?, 1)`,
			id, rec.Name, rec.Type, rec.Value, rec.TTL, normalizePriority(rec.Type, rec.Priority)); e != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not add a record")
			return added, skipped, false
		}
		added++
	}
	return added, skipped, true
}

// writeImportedSOA stores the SOA the uploaded zone carried, if it had one.
func writeImportedSOA(r *http.Request, tx *sql.Tx, id int64, soaParsed *SOA) {
	if soaParsed == nil {
		return
	}
	_, _ = tx.ExecContext(r.Context(),
		`INSERT INTO dns_soa(domain_id, primary_ns, hostmaster, refresh, retry, expire, minimum, ttl)
		 VALUES(?,?,?,?,?,?,?,?)
		 ON DUPLICATE KEY UPDATE primary_ns=VALUES(primary_ns), hostmaster=VALUES(hostmaster),
		   refresh=VALUES(refresh), retry=VALUES(retry), expire=VALUES(expire),
		   minimum=VALUES(minimum), ttl=VALUES(ttl)`,
		id, soaParsed.PrimaryNS, soaParsed.Hostmaster, soaParsed.Refresh, soaParsed.Retry,
		soaParsed.Expire, soaParsed.Minimum, soaParsed.TTL)
}

// writeImportResult rewrites the zone and answers with the counts. A zone the
// validator refuses is reported as a warning, because the records are stored.
func (h *Handlers) writeImportResult(w http.ResponseWriter, r *http.Request, id int64, added, skipped int, replace bool) {
	zoneWarning := ""
	if zerr := writeZone(r.Context(), h.DB, id); zerr != nil {
		zoneWarning = "records saved but zone validation warned: " + zerr.Error()
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"added":   added,
		"skipped": skipped,
		"mode":    map[bool]string{true: "replace", false: "merge"}[replace],
		"warning": zoneWarning,
	})
}

// parseBindZone parses BIND zone text into records + (optional) SOA. It supports
// $ORIGIN/$TTL, the @ apex, relative/absolute names, ( ) multi-line groups, ;
// comments, TXT quote joining, and MX/SRV priority. Unsupported or invalid lines
// are skipped.
func parseBindZone(text, domainName string) ([]Record, *SOA) {
	parser := &zoneParse{
		origin:     strings.TrimSuffix(domainName, ".") + ".",
		defaultTTL: 3600,
		lastName:   "@",
	}
	for _, rawLine := range logicalLines(text) {
		parser.line(stripParens(rawLine)) // comments were already removed in logicalLines
	}
	return parser.out, parser.soa
}

// zoneParse carries the state one zone file builds up as it is read: the
// current origin and TTL, the name a continuation line repeats, and what has
// been parsed so far.
type zoneParse struct {
	origin     string
	defaultTTL int
	lastName   string
	soa        *SOA
	out        []Record
}

// line reads one logical line of the zone file.
func (p *zoneParse) line(line string) {
	if strings.TrimSpace(line) == "" {
		return
	}
	if p.directive(line) {
		return
	}
	name, rest := p.splitName(line)
	p.lastName = name

	toks := strings.Fields(rest)
	if len(toks) == 0 {
		return
	}
	ttl, at := p.ttlAndClass(toks)
	if at >= len(toks) {
		return
	}
	p.record(relativeName(name, p.origin), strings.ToUpper(toks[at]), toks[at+1:], ttl)
}

// directive applies a $ORIGIN or $TTL line and reports whether the line was one.
func (p *zoneParse) directive(line string) bool {
	if !strings.HasPrefix(strings.TrimSpace(line), "$") {
		return false
	}
	f := strings.Fields(line)
	switch strings.ToUpper(f[0]) {
	case "$ORIGIN":
		if len(f) >= 2 {
			p.origin = f[1]
			if !strings.HasSuffix(p.origin, ".") {
				p.origin += "."
			}
		}
	case "$TTL":
		if len(f) >= 2 {
			if n, e := strconv.Atoi(f[1]); e == nil {
				p.defaultTTL = n
			}
		}
	}
	return true
}

// splitName returns the record name and the rest of the line. When the line
// starts with whitespace the previous name repeats; otherwise it is the first
// token.
func (p *zoneParse) splitName(line string) (name, rest string) {
	if line[0] == ' ' || line[0] == '\t' {
		return p.lastName, strings.TrimLeft(line, " \t")
	}
	ff := strings.Fields(line)
	name = ff[0]
	return name, strings.TrimSpace(line[len(name):])
}

// ttlAndClass reads the optional TTL and class tokens, in any order, and
// returns the TTL to use with the index of the record type.
func (p *zoneParse) ttlAndClass(toks []string) (ttl, at int) {
	ttl = p.defaultTTL
	for at < len(toks) {
		if n, e := strconv.Atoi(toks[at]); e == nil {
			ttl = n
			at++
			continue
		}
		up := strings.ToUpper(toks[at])
		if up == "IN" || up == "CH" || up == "HS" {
			at++
			continue
		}
		break
	}
	return ttl, at
}

// record keeps one parsed record, or the SOA. A line the panel cannot store is
// skipped rather than failing the whole file.
func (p *zoneParse) record(name, recType string, rdataToks []string, ttl int) {
	if recType == "SOA" {
		if s := parseSOARdata(rdataToks, ttl); s != nil {
			p.soa = s
		}
		return
	}
	if !validType(recType) || len(rdataToks) == 0 {
		return
	}
	rec := Record{Name: name, Type: recType, TTL: ttl}
	rec.Priority, rec.Value = rdataFields(recType, rdataToks)
	if rec.Value == "" || strings.ContainsAny(rec.Value, "\r\n") || strings.ContainsAny(rec.Name, " \t\r\n") {
		return
	}
	p.out = append(p.out, rec)
}

// rdataFields reads a record's priority and value out of its rdata tokens.
func rdataFields(recType string, rdataToks []string) (priority int, value string) {
	switch recType {
	case "MX":
		if len(rdataToks) >= 2 {
			priority, _ = strconv.Atoi(rdataToks[0])
			return priority, trimDot(rdataToks[1])
		}
		return 0, trimDot(rdataToks[0])
	case "SRV":
		if len(rdataToks) >= 4 {
			priority, _ = strconv.Atoi(rdataToks[0])
			return priority, rdataToks[1] + " " + rdataToks[2] + " " + trimDot(rdataToks[3])
		}
		return 0, strings.Join(rdataToks, " ")
	case "TXT":
		return 0, unquoteTXT(rdataToks)
	case "CNAME", "NS", "PTR":
		return 0, trimDot(rdataToks[0])
	}
	return 0, strings.Join(rdataToks, " ")
}

// parseSOARdata parses SOA rdata (mname rname serial refresh retry expire minimum).
func parseSOARdata(t []string, ttl int) *SOA {
	if len(t) < 7 {
		return nil
	}
	atoi := func(s string) int { n, _ := strconv.Atoi(s); return n }
	return &SOA{
		PrimaryNS:  trimDot(t[0]),
		Hostmaster: soaMailToEmail(t[1]),
		Refresh:    atoi(t[3]),
		Retry:      atoi(t[4]),
		Expire:     atoi(t[5]),
		Minimum:    atoi(t[6]),
		TTL:        ttl,
	}
}

// logicalLines strips the comment (;) from each physical line, then joins ( )
// continuation blocks into a single logical line (quote-aware).
func logicalLines(text string) []string {
	var clean []string
	for ln := range strings.SplitSeq(text, "\n") {
		clean = append(clean, stripComment(strings.TrimRight(ln, "\r")))
	}
	var res []string
	var cur strings.Builder
	paren := 0
	for _, ln := range clean {
		open, closed := countParens(ln)
		if paren > 0 {
			cur.WriteByte(' ')
			cur.WriteString(ln)
			paren += open - closed
			if paren <= 0 {
				res = append(res, cur.String())
				cur.Reset()
				paren = 0
			}
			continue
		}
		if open > closed {
			cur.WriteString(ln)
			paren = open - closed
			continue
		}
		res = append(res, ln)
	}
	if cur.Len() > 0 {
		res = append(res, cur.String())
	}
	return res
}

// stripComment removes an unquoted ';' comment to end of line (parens are kept).
func stripComment(ln string) string {
	inQuote := false
	for i := 0; i < len(ln); i++ {
		if ln[i] == '"' {
			inQuote = !inQuote
		} else if !inQuote && ln[i] == ';' {
			return ln[:i]
		}
	}
	return ln
}

// countParens counts unquoted ( and ) (comments were already removed).
func countParens(ln string) (open, closed int) {
	inQuote := false
	for i := 0; i < len(ln); i++ {
		switch ln[i] {
		case '"':
			inQuote = !inQuote
		case '(':
			if !inQuote {
				open++
			}
		case ')':
			if !inQuote {
				closed++
			}
		}
	}
	return
}

// stripParens replaces unquoted ( and ) with spaces.
func stripParens(ln string) string {
	inQuote := false
	var b strings.Builder
	for i := 0; i < len(ln); i++ {
		c := ln[i]
		if c == '"' {
			inQuote = !inQuote
			b.WriteByte(c)
			continue
		}
		if !inQuote && (c == '(' || c == ')') {
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// relativeName converts an absolute/@/relative name to the panel's stored
// relative label.
func relativeName(name, origin string) string {
	name = strings.TrimSpace(name)
	o := strings.TrimSuffix(origin, ".")
	if name == "@" || name == origin || name == o {
		return "@"
	}
	if n, ok := strings.CutSuffix(name, "."); ok {
		if n == o {
			return "@"
		}
		if base, ok := strings.CutSuffix(n, "."+o); ok {
			return base
		}
		return n
	}
	return name
}

// trimDot removes a trailing dot from a target name (render re-adds the fqdn dot).
func trimDot(s string) string { return strings.TrimSuffix(strings.TrimSpace(s), ".") }

// unquoteTXT joins TXT char-string tokens and removes the surrounding quotes.
func unquoteTXT(toks []string) string {
	joined := strings.Join(toks, " ")
	var b strings.Builder
	inQuote := false
	sawQuote := false
	for i := 0; i < len(joined); i++ {
		c := joined[i]
		if c == '"' {
			inQuote = !inQuote
			sawQuote = true
			continue
		}
		if inQuote {
			b.WriteByte(c)
		}
	}
	if !sawQuote {
		return strings.TrimSpace(joined) // unquoted TXT
	}
	return b.String()
}

// soaMailToEmail turns a zone RNAME (admin.example.com.) into an e-mail (admin@example.com).
func soaMailToEmail(rname string) string {
	r := trimDot(rname)
	if local, domain, ok := strings.Cut(r, "."); ok {
		return local + "@" + domain
	}
	return r
}
