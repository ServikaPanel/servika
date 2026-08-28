package transfers

import (
	"context"
	"fmt"
	"strings"
)

// RemoteAccount is one migratable site found on the source server.
type RemoteAccount struct {
	SourceAccount string   `json:"source_account"` // remote panel user
	DomainName    string   `json:"domain_name"`
	WebRoot       string   `json:"web_root"`
	PHPVersion    string   `json:"php_version"`
	Databases     []string `json:"databases"`
	SizeMB        int64    `json:"size_mb"`
	Note          string   `json:"note"`
}

// DetectPanel reports which control panel is installed on the source server.
func (s *RemoteSource) DetectPanel(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	out, err := s.Run(ctx,
		"if [ -d /usr/local/cpanel ]; then echo cpanel; "+
			"elif [ -d /usr/local/psa ] || command -v plesk >/dev/null 2>&1; then echo plesk; "+
			"elif [ -d /usr/local/directadmin ]; then echo directadmin; "+
			"else echo unknown; fi")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// Discover lists every account and site on the source panel.
func (s *RemoteSource) Discover(ctx context.Context) ([]RemoteAccount, error) {
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout*3)
	defer cancel()
	switch s.Type {
	case "cpanel":
		return s.parseDiscovery(s.Run(ctx, discoverCpanel))
	case "plesk":
		return s.parseDiscovery(s.Run(ctx, discoverPlesk))
	case "directadmin":
		return s.parseDiscovery(s.Run(ctx, discoverDirectAdmin))
	}
	return nil, fmt.Errorf("unsupported panel type")
}

func (s *RemoteSource) parseDiscovery(out string, err error) ([]RemoteAccount, error) {
	if err != nil {
		return nil, err
	}
	return parseDiscoveryBlocks(out), nil
}

// ---------------------------------------------------------------------------
// Remote discovery commands
// ---------------------------------------------------------------------------
//
// A SEPARATE docroot and PHP version is produced for EVERY domain. When all
// domains point at the account's main docroot, addon domains receive the main
// site's files and the same databases migrate several times.
//
// Output format (line based):
//
//	###USER:<panel user>
//	###DB:<db1,db2,...>          (account wide — assigned to the MAIN domain only)
//	###DOM:<domain>|<docroot>|<php version>|<size MB>|<main|addon>

const discoverCpanel = `for f in /var/cpanel/users/*; do
  [ -f "$f" ] || continue
  u=$(basename "$f")
  case "$u" in system|root|*.cache|*.lock) continue ;; esac
  echo "###USER:$u"
  echo "###DB:$(mysql -N -B -e "SHOW DATABASES" 2>/dev/null | grep -E "^${u}_" | tr '\n' ',')"
  first=1
  for d in $(grep -E '^DNS[0-9]*=' "$f" 2>/dev/null | sed 's/^DNS[0-9]*=//'); do
    [ -n "$d" ] || continue
    ud="/var/cpanel/userdata/$u/$d"
    dr=$(grep -E '^documentroot:' "$ud" 2>/dev/null | head -1 | sed 's/^documentroot: *//')
    pv=$(grep -E '^phpversion:' "$ud" 2>/dev/null | head -1 | sed 's/^phpversion: *//')
    [ -n "$dr" ] || dr="/home/$u/public_html"
    [ -n "$pv" ] || pv=$(grep -E '^phpversion=' "$f" 2>/dev/null | head -1 | sed 's/^phpversion=//')
    sz=$(du -sm "$dr" 2>/dev/null | cut -f1)
    if [ "$first" = "1" ]; then kind=main; first=0; else kind=addon; fi
    echo "###DOM:$d|$dr|$pv|$sz|$kind"
  done
done`

const discoverPlesk = `for d in $(plesk bin subscription --list 2>/dev/null); do
  su=$(plesk db -Ne "SELECT s.login FROM domains dom JOIN hosting h ON h.dom_id=dom.id JOIN sys_users s ON s.id=h.sys_user_id WHERE dom.name='$d' LIMIT 1" 2>/dev/null)
  [ -n "$su" ] || su="$d"
  echo "###USER:$su"
  echo "###DB:$(plesk db -Ne "SELECT db.name FROM data_bases db JOIN domains dom ON db.dom_id=dom.id WHERE dom.name='$d'" 2>/dev/null | tr '\n' ',')"
  first=1
  for sub in $d $(plesk db -Ne "SELECT dom.name FROM domains dom WHERE dom.webspace_id=(SELECT id FROM domains WHERE name='$d') AND dom.name<>'$d'" 2>/dev/null); do
    dr=$(plesk db -Ne "SELECT CONCAT(h.www_root) FROM domains dom JOIN hosting h ON h.dom_id=dom.id WHERE dom.name='$sub' LIMIT 1" 2>/dev/null)
    # Fall back to the subscription httpdocs ONLY for the main domain. A hosting-less
    # subdomain (redirect only) with no www_root must stay empty, or it would inherit
    # the MAIN domain's document root and pull its entire tree during migration.
    if [ -z "$dr" ]; then if [ "$sub" = "$d" ]; then dr="/var/www/vhosts/$d/httpdocs"; else dr=""; fi; fi
    pv=$(plesk db -Ne "SELECT h.php_handler_id FROM domains dom JOIN hosting h ON h.dom_id=dom.id WHERE dom.name='$sub' LIMIT 1" 2>/dev/null | grep -oE 'php[0-9]+' | head -1 | sed 's/php//')
    sz=$(du -sm "$dr" 2>/dev/null | cut -f1)
    if [ "$first" = "1" ]; then kind=main; first=0; else kind=addon; fi
    echo "###DOM:$sub|$dr|$pv|$sz|$kind"
  done
done`

// DirectAdmin: php1_select is an INDEX (1/2/3), not a version — it maps to
// phpN_release in the custombuild options.conf file.
const discoverDirectAdmin = `oc=/usr/local/directadmin/custombuild/options.conf
# DirectAdmin keeps the MySQL admin account password-protected, so a credential-
# less mysql is refused with 1045 and the database list comes back EMPTY. Read
# the admin credentials from DA's own config (same source as mysqlAdminAuth); the
# password stays on the remote side and never reaches this panel's argv or ps.
mc=/usr/local/directadmin/conf/mysql.conf
dbu=$(sed -n 's/^user=//p' "$mc" 2>/dev/null)
dbp=$(sed -n 's/^passwd=//p' "$mc" 2>/dev/null)
for ud in /usr/local/directadmin/data/users/*; do
  [ -d "$ud" ] || continue
  u=$(basename "$ud")
  case "$u" in admin) continue ;; esac
  echo "###USER:$u"
  echo "###DB:$(MYSQL_PWD="$dbp" mysql -u"$dbu" -N -B -e "SHOW DATABASES" 2>/dev/null | grep -E "^${u}_" | tr '\n' ',')"
  first=1
  while read -r d; do
    [ -n "$d" ] || continue
    dr="/home/$u/domains/$d/public_html"
    idx=$(grep -h -E '^php1_select=' "$ud/domains/$d.conf" 2>/dev/null | head -1 | sed 's/^php1_select=//')
    [ -n "$idx" ] || idx=1
    pv=$(grep -E "^php${idx}_release=" "$oc" 2>/dev/null | head -1 | sed "s/^php${idx}_release=//")
    sz=$(du -sm "$dr" 2>/dev/null | cut -f1)
    if [ "$first" = "1" ]; then kind=main; first=0; else kind=addon; fi
    echo "###DOM:$d|$dr|$pv|$sz|$kind"
  done < "$ud/domains.list"
done`

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------
//
// REMOTE DATA IS HOSTILE: the account, domain, database name and path pass an
// allowlist. Anything that fails is DROPPED SILENTLY.

func parseDiscoveryBlocks(out string) []RemoteAccount {
	var result []RemoteAccount
	var currentAccount, databases string

	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "###USER:"):
			user := strings.TrimPrefix(line, "###USER:")
			currentAccount, databases = "", ""
			if reRemoteAccount.MatchString(user) {
				currentAccount = user
			}
		case strings.HasPrefix(line, "###DB:"):
			databases = strings.TrimPrefix(line, "###DB:")
		case strings.HasPrefix(line, "###DOM:"):
			if currentAccount == "" {
				continue
			}
			parts := strings.Split(strings.TrimPrefix(line, "###DOM:"), "|")
			if len(parts) < 5 {
				continue
			}
			domain := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(parts[0], ".")))
			if domain == "" || !reRemoteDomain.MatchString(domain) || !strings.Contains(domain, ".") {
				continue
			}
			root := strings.TrimSpace(parts[1])
			if !validRemotePath(root) {
				continue
			}
			var sizeMB int64
			_, _ = fmt.Sscanf(strings.TrimSpace(parts[3]), "%d", &sizeMB)
			isMain := strings.TrimSpace(parts[4]) == "main"

			account := RemoteAccount{
				SourceAccount: currentAccount,
				DomainName:    domain,
				WebRoot:       root,
				PHPVersion:    normalizeRemotePHP(parts[2]),
				SizeMB:        sizeMB,
			}
			// Databases go to the MAIN domain ONLY. Giving the account-wide list
			// to addon domains too would migrate the same database repeatedly.
			if isMain {
				for name := range strings.SplitSeq(databases, ",") {
					name = strings.TrimSpace(name)
					if name != "" && reRemoteDBName.MatchString(name) && !remoteSystemDB(name) {
						account.Databases = append(account.Databases, name)
					}
				}
			} else {
				account.Note = "addon domain — the database migrates with the main domain"
			}
			result = append(result, account)
		}
	}
	return result
}

// validRemotePath checks a remote docroot: absolute, no traversal, no shell
// metacharacter.
func validRemotePath(p string) bool {
	if p == "" || !strings.HasPrefix(p, "/") || len(p) > 512 {
		return false
	}
	if strings.Contains(p, "..") {
		return false
	}
	return !strings.ContainsAny(p, "\x00\r\n'\"`$;|&<>*?")
}

var remoteSystemDBs = map[string]bool{
	"information_schema": true, "performance_schema": true, "mysql": true,
	"sys": true, "test": true, "psa": true, "horde": true, "roundcube": true,
	"phpmyadmin": true, "leechprotect": true, "eximstats": true, "modsec": true,
	"cphulkd": true, "whmxfer": true, "panel": true,
}

func remoteSystemDB(s string) bool { return remoteSystemDBs[strings.ToLower(s)] }

// normalizeRemotePHP turns values such as "ea-php81", "php81", "8.1.30" or "8"
// into a "<major>.<minor>" string. A single digit ("8") is KEPT as the major
// version so installedPHPOrClosest can match inside the same major release;
// leaving it untouched made a version comparison fall BELOW 8.0 (to 7.4).
func normalizeRemotePHP(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	s = strings.TrimPrefix(s, "ea-")
	s = strings.TrimPrefix(s, "alt-")
	s = strings.TrimPrefix(s, "php")
	s = strings.TrimSpace(strings.Trim(s, "-_"))
	if s == "" {
		return ""
	}
	// "81" -> "8.1"
	if !strings.Contains(s, ".") {
		if len(s) >= 2 {
			return s[:1] + "." + s[1:]
		}
		return s // single digit: major version only (for example "8")
	}
	parts := strings.Split(s, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return s
}
