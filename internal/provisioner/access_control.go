package provisioner

import (
	"database/sql"
	"log"
	"net"
	"regexp"
	"strings"
)

var hotlinkAllowedDomainPattern = regexp.MustCompile(`^\*?\.?[a-zA-Z0-9.-]+$`)

func buildIPRules(domainName string) string {
	if packageDB == nil {
		return ""
	}
	var domainID int64
	var mode string
	err := packageDB.QueryRow(
		`SELECT id, COALESCE(ip_access_mode,'off') FROM domains WHERE domain_name=? LIMIT 1`, domainName).
		Scan(&domainID, &mode)
	if err != nil || mode == "off" {
		return ""
	}
	rows, err := packageDB.Query(`SELECT ip_cidr FROM domain_ip_rules WHERE domain_id=? ORDER BY id`, domainID)
	if err != nil {
		return ""
	}
	defer func() { _ = rows.Close() }()
	directive := "deny"
	if mode == "allow" {
		directive = "allow"
	}
	lines, count := ipRuleLines(rows, domainID, directive)
	if count == 0 {
		return ""
	}
	out := "    # ---- IP access rules, managed by Servika ----\n" + lines
	if mode == "allow" {
		out += "    deny all;\n"
	}
	return out
}

// ipRuleLines renders every usable stored rule as one directive line and counts
// the lines rendered.
func ipRuleLines(rows *sql.Rows, domainID int64, directive string) (string, int) {
	var builder strings.Builder
	count := 0
	for rows.Next() {
		var ipCIDR string
		if err := rows.Scan(&ipCIDR); err != nil {
			// A dropped rule renders as the opposite of what the operator saved: a
			// missing deny lets that address in, a missing allow shuts it out.
			log.Printf("access control: skipping an unreadable IP rule for domain %d: %v", domainID, err)
			continue
		}
		// A stored value that is not a valid nginx address is refused rather than
		// dropped in silence, because it would otherwise fail the whole reload.
		if !validNginxIPRule(ipCIDR) {
			log.Printf("access control: refusing an invalid stored IP rule for domain %d", domainID)
			continue
		}
		builder.WriteString("    ")
		builder.WriteString(directive)
		builder.WriteByte(' ')
		builder.WriteString(ipCIDR)
		builder.WriteString(";\n")
		count++
	}
	if err := rows.Err(); err != nil {
		// A short list renders an access rule that is not the one the operator
		// saved: a missing entry is let in on a deny list and refused on an allow
		// list, and the rendered file gives no sign of it.
		log.Printf("access control: could not read the IP rules for domain %d: %v", domainID, err)
	}
	return builder.String(), count
}

func buildHotlink(domainName string) string {
	if packageDB == nil {
		return ""
	}
	var active int
	var allowed sql.NullString
	err := packageDB.QueryRow(
		`SELECT COALESCE(hotlink_enabled,0), hotlink_allowed FROM domains WHERE domain_name=? LIMIT 1`, domainName).
		Scan(&active, &allowed)
	if err != nil || active == 0 {
		return ""
	}
	domainName = strings.ToLower(strings.TrimSpace(domainName))
	if ValidateDomain(domainName) != nil {
		return ""
	}
	extra := strings.Builder{}
	if allowed.Valid {
		for domain := range strings.SplitSeq(allowed.String, ",") {
			domain = strings.ToLower(strings.TrimSpace(domain))
			if domain != "" && hotlinkAllowedDomainPattern.MatchString(domain) {
				extra.WriteByte(' ')
				extra.WriteString(domain)
			}
		}
	}
	return "    location ~* \\.(jpg|jpeg|png|gif|webp|svg|ico|bmp)$ {\n" +
		"        valid_referers none blocked " + domainName + " *." + domainName + extra.String() + ";\n" +
		"        if ($invalid_referer) { return 403; }\n" +
		"        try_files $uri =404;\n" +
		"    }\n"
}

func validNginxIPRule(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return true
	}
	log.Printf("access control: skipped invalid IP rule %q", value)
	return false
}
