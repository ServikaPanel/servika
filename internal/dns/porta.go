// porta.go: BIND zone-file import/export for a domain.
//
//	Export: returns the domain's DNS records plus SOA as a standard, portable
//	  BIND zone file (downloadable), so a zone can move to another panel.
//	Import: parses an uploaded BIND zone file and either merges its records
//	  into the domain or replaces the existing set, then re-renders and
//	  validates the zone (WriteZone runs named-checkzone + reload).
package dns

import (
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

	var content []byte
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20) // a zone file is small
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		// #nosec G120 -- body is bounded by MaxBytesReader above, so parsing cannot exhaust memory.
		if e := r.ParseMultipartForm(2 << 20); e != nil {
			httpx.WriteError(w, http.StatusBadRequest, "could not read the upload")
			return
		}
		defer func() {
			if r.MultipartForm != nil {
				_ = r.MultipartForm.RemoveAll()
			}
		}()
		f, _, e := r.FormFile("file")
		if e != nil {
			httpx.WriteError(w, http.StatusBadRequest, "file field not found")
			return
		}
		defer func() { _ = f.Close() }()
		content, _ = io.ReadAll(f)
	} else {
		content, _ = io.ReadAll(r.Body)
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

	if replace {
		if _, e := tx.ExecContext(r.Context(), `DELETE FROM dns_records WHERE domain_id=?`, id); e != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not remove the existing records")
			return
		}
	}
	added, skipped := 0, 0
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
			return
		}
		added++
	}
	if soaParsed != nil {
		_, _ = tx.ExecContext(r.Context(),
			`INSERT INTO dns_soa(domain_id, primary_ns, hostmaster, refresh, retry, expire, minimum, ttl)
			 VALUES(?,?,?,?,?,?,?,?)
			 ON DUPLICATE KEY UPDATE primary_ns=VALUES(primary_ns), hostmaster=VALUES(hostmaster),
			   refresh=VALUES(refresh), retry=VALUES(retry), expire=VALUES(expire),
			   minimum=VALUES(minimum), ttl=VALUES(ttl)`,
			id, soaParsed.PrimaryNS, soaParsed.Hostmaster, soaParsed.Refresh, soaParsed.Retry,
			soaParsed.Expire, soaParsed.Minimum, soaParsed.TTL)
	}
	if e := tx.Commit(); e != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}

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
	origin := strings.TrimSuffix(domainName, ".") + "."
	defaultTTL := 3600
	var out []Record
	var soa *SOA
	lastName := "@"

	for _, rawLine := range logicalLines(text) {
		line := stripParens(rawLine) // comments were already removed in logicalLines
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "$") {
			f := strings.Fields(line)
			switch strings.ToUpper(f[0]) {
			case "$ORIGIN":
				if len(f) >= 2 {
					origin = f[1]
					if !strings.HasSuffix(origin, ".") {
						origin += "."
					}
				}
			case "$TTL":
				if len(f) >= 2 {
					if n, e := strconv.Atoi(f[1]); e == nil {
						defaultTTL = n
					}
				}
			}
			continue
		}

		// name: when the line starts with whitespace the previous name repeats;
		// otherwise it is the first token.
		var name, rest string
		if line[0] == ' ' || line[0] == '\t' {
			name = lastName
			rest = strings.TrimLeft(line, " \t")
		} else {
			ff := strings.Fields(line)
			name = ff[0]
			rest = strings.TrimSpace(line[len(name):])
		}
		lastName = name
		relativeName := relativeName(name, origin)

		toks := strings.Fields(rest)
		if len(toks) == 0 {
			continue
		}
		// optional TTL + class (any order)
		ttl := defaultTTL
		i := 0
		for i < len(toks) {
			if n, e := strconv.Atoi(toks[i]); e == nil {
				ttl = n
				i++
				continue
			}
			up := strings.ToUpper(toks[i])
			if up == "IN" || up == "CH" || up == "HS" {
				i++
				continue
			}
			break
		}
		if i >= len(toks) {
			continue
		}
		recType := strings.ToUpper(toks[i])
		rdataToks := toks[i+1:]

		if recType == "SOA" {
			if s := parseSOARdata(rdataToks, ttl); s != nil {
				soa = s
			}
			continue
		}
		if !validType(recType) || len(rdataToks) == 0 {
			continue
		}

		rec := Record{Name: relativeName, Type: recType, TTL: ttl}
		switch recType {
		case "MX":
			if len(rdataToks) >= 2 {
				rec.Priority, _ = strconv.Atoi(rdataToks[0])
				rec.Value = trimDot(rdataToks[1])
			} else {
				rec.Value = trimDot(rdataToks[0])
			}
		case "SRV":
			if len(rdataToks) >= 4 {
				rec.Priority, _ = strconv.Atoi(rdataToks[0])
				rec.Value = rdataToks[1] + " " + rdataToks[2] + " " + trimDot(rdataToks[3])
			} else {
				rec.Value = strings.Join(rdataToks, " ")
			}
		case "TXT":
			rec.Value = unquoteTXT(rdataToks)
		case "CNAME", "NS", "PTR":
			rec.Value = trimDot(rdataToks[0])
		default:
			rec.Value = strings.Join(rdataToks, " ")
		}
		if rec.Value == "" || strings.ContainsAny(rec.Value, "\r\n") || strings.ContainsAny(rec.Name, " \t\r\n") {
			continue
		}
		out = append(out, rec)
	}
	return out, soa
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
