package domains

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"servika/internal/addondomains"
	"servika/internal/apps"
	"servika/internal/credentials"
	"servika/internal/dns"
	"servika/internal/httpx"
	"servika/internal/mail"
	"servika/internal/middleware"
	"servika/internal/provisioner"
	"servika/internal/quota"
	"servika/internal/redis"
	"servika/internal/resourcelimit"
	"servika/internal/tenantaccount"

	"github.com/go-chi/chi/v5"
)

type Domain struct {
	ID         int64  `json:"id"`
	DomainName string `json:"domain_name"`
	PHPVersion string `json:"php_version"`
	SSL        bool   `json:"ssl"`
	SSLExpiry  string `json:"ssl_expiry,omitempty"`
	Status     string `json:"status"`
	SystemUser string `json:"system_user"`
	SizeKB     int64  `json:"size_kb"`
	TrafficKB  int64  `json:"traffic_kb"`
	CreatedAt  string `json:"created_at"`
	IPv4       string `json:"ipv4"`
	// IPv6 is the address this domain answers on over IPv6, empty when it has
	// none. Empty is the ordinary state, not a fault: a server without IPv6
	// publishes no AAAA record at all, which is the only safe answer.
	IPv6      string `json:"ipv6"`
	FTPHost   string `json:"ftp_host"`
	FTPUser   string `json:"ftp_user"`
	DBHost    string `json:"db_host"`
	DBUser    string `json:"db_user"`
	DBName    string `json:"db_name"`
	WebRoot   string `json:"web_root"`
	IsDemo    bool   `json:"is_demo"`
	Notes     string `json:"notes,omitempty"`
	PlanID    *int64 `json:"plan_id,omitempty"`
	PlanName  string `json:"plan_name,omitempty"`
	SshAccess bool   `json:"ssh_access"`
	Suspended bool   `json:"suspended"`
	// ResellerName is the username of the reseller who owns the domain's customer.
	// Empty means the customer is directly under admin (no reseller).
	ResellerName string `json:"reseller_name,omitempty"`
	// SiteType records what the domain is for. It decides whether creation opens
	// a MySQL database, and lets the client point a fresh WordPress domain at the
	// screen that finishes the install.
	SiteType string `json:"site_type"`
	// SSLSource is which kind of certificate is installed, so a list can tell a
	// browser-trusted one from the self-signed fail-safe instead of showing both
	// as simply "SSL". Empty means unknown, which is not the same as bad.
	SSLSource string `json:"ssl_source,omitempty"`
}

// The values domains.ssl_source can hold. Every writer is in this package
// (ssl_progress.go) or in internal/transfers; the column is VARCHAR, not an
// ENUM, so these are the contract.
//
// An empty value is deliberately NOT an error case: it is what a domain with no
// certificate carries, and what rows written before the column existed still
// hold. Treating unknown as untrusted would raise a false alarm on both.
const (
	SSLSourceLetsEncrypt = "letsencrypt"
	SSLSourceSelfSigned  = "self-signed"
	SSLSourceImported    = "imported"
)

// SSLSourceIsTrusted reports whether a browser will accept the certificate
// without warning the visitor.
//
// Only the self-signed fail-safe is untrusted. An imported certificate arrives
// from a cPanel migration and is as real as one Servika ordered, and an unknown
// value is left trusted so a source added later cannot start raising alarms on
// its own.
func SSLSourceIsTrusted(source string) bool {
	return source != SSLSourceSelfSigned
}

type Handlers struct {
	DB   *sql.DB
	IPv4 string
}

const selectAll = `SELECT d.id, d.domain_name, d.system_user, d.php_version, d.ssl_enabled,
  COALESCE(DATE_FORMAT(d.ssl_expiry,'%Y-%m-%d'),''), d.status, d.ipv4, d.ftp_host, d.ftp_user,
  d.db_host, d.db_user, d.db_name, d.web_root, d.size_kb, d.traffic_kb, d.is_demo,
  COALESCE(d.notes,''), DATE_FORMAT(d.created_at,'%Y-%m-%d'),
  d.plan_id, COALESCE(p.name,''), d.ssh_access, COALESCE(d.suspended,0),
  COALESCE(ru.username,''), d.site_type, COALESCE(d.ssl_source,''), COALESCE(d.ipv6,'')
  FROM domains d
  LEFT JOIN service_plans p ON p.id=d.plan_id
  LEFT JOIN customers cu ON cu.id=d.customer_id
  LEFT JOIN users ru ON ru.id=cu.owner_user_id`

func scan(rs interface{ Scan(...any) error }) (Domain, error) {
	var d Domain
	var ssl, demo, sshE, suspended int
	var planID sql.NullInt64
	err := rs.Scan(&d.ID, &d.DomainName, &d.SystemUser, &d.PHPVersion, &ssl,
		&d.SSLExpiry, &d.Status, &d.IPv4, &d.FTPHost, &d.FTPUser,
		&d.DBHost, &d.DBUser, &d.DBName, &d.WebRoot, &d.SizeKB, &d.TrafficKB, &demo,
		&d.Notes, &d.CreatedAt,
		&planID, &d.PlanName, &sshE, &suspended,
		&d.ResellerName, &d.SiteType, &d.SSLSource, &d.IPv6)
	d.SSL = ssl == 1
	d.IsDemo = demo == 1
	d.SshAccess = sshE == 1
	d.Suspended = suspended == 1
	if planID.Valid {
		v := planID.Int64
		d.PlanID = &v
	}
	return d, err
}

func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	// Scope narrowing happens INSIDE the query: an admin sees every domain, a
	// reseller only its own customers', a customer only its own. A row-by-row
	// ownership check does not work here — an unfiltered list would already leak
	// every tenant name.
	cond, arg := middleware.ScopeSQL(r, "d")
	// #nosec G701 G202 -- cond is a constant scope fragment from ScopeSQL with a literal alias; all user values are bound via arg placeholders.
	rows, err := h.DB.QueryContext(r.Context(), selectAll+cond+" ORDER BY d.id DESC", arg...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database operation failed")
		return
	}
	defer func() { _ = rows.Close() }()
	out := make([]Domain, 0)
	for rows.Next() {
		d, err := scan(rows)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
			return
		}
		out = append(out, d)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handlers) Get(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	row := h.DB.QueryRowContext(r.Context(), selectAll+" WHERE d.id=?", id)
	d, err := scan(row)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

type createReq struct {
	DomainName string `json:"domain_name"`
	PHPVersion string `json:"php_version"`
	CustomerID *int64 `json:"customer_id,omitempty"`
	PlanID     *int64 `json:"plan_id,omitempty"`
	SiteType   string `json:"site_type,omitempty"`
	// OwnerUserID names the reseller a NEW customer record is opened under, for
	// the case where no existing customer is named. It is the only way an
	// administrator can hand a domain to a reseller at creation time; until it
	// existed the auto-created record was always unowned and the reseller could
	// not see the domain at all.
	//
	// It is mutually exclusive with CustomerID: an existing customer already has
	// an owner, and changing it is a transfer with its own endpoint.
	OwnerUserID *int64 `json:"owner_user_id,omitempty"`
}

// Reason codes a create request can be refused with. They are CODES rather than
// sentences because the interface ships twelve languages and wording produced
// here could not be translated.
const (
	reasonCustomerNotFound  = "customer_not_found"
	reasonPlanNotFound      = "plan_not_found"
	reasonOwnerNotReseller  = "owner_not_reseller"
	reasonOwnerWithCustomer = "owner_with_customer"
	reasonOwnerNotAllowed   = "owner_not_allowed"
)

// warningOwnerNotApplied rides on a SUCCESSFUL create: the domain exists, but
// the reseller the caller asked for was not applied because the tenant already
// had a customer record and an existing record keeps the owner it had.
//
// Reachable because provisioner.SlugFromDomain truncates the system user at 26
// characters, so two long domain names can resolve to the same tenant.
const warningOwnerNotApplied = "owner_not_applied"

// referencedAccountsExist checks that the rows a create request points at are
// real, and returns a reason code when one is not.
//
// It has to exist because `domains.customer_id` carries no foreign key, so an id
// matching nothing is written verbatim. The domain then hangs off a customer
// `middleware.ScopeSQL` can never find: an administrator still sees it, because
// that branch adds no condition, while the reseller and the customer it was
// meant for never do, and it is missing from the Customer Accounts screen. The
// reseller path was already safe, `ResellerOwnsCustomer` reads the row, but an
// administrator's id went straight through.
//
// The owner is held to a stricter rule than the other two: it must not merely
// exist but be an ACTIVE RESELLER, because it is written to
// `customers.owner_user_id`, which is one half of the ownership chain. Pointing
// it at an administrator or a customer would build a chain no role resolves.
//
// A database failure is reported as an error, not as "not found", so the caller
// refuses instead of provisioning against an unchecked id.
func (h *Handlers) referencedAccountsExist(ctx context.Context, customerID, planID, ownerUserID *int64) (string, error) {
	if ownerUserID != nil && *ownerUserID > 0 {
		if customerID != nil && *customerID > 0 {
			// Two different intents in one request. Applying one and dropping the
			// other would report a placement that did not happen.
			return reasonOwnerWithCustomer, nil
		}
		// The role and the status are both part of the check: a suspended account
		// is one an operator deliberately took out of service, and handing it a
		// fresh domain would quietly put it back to work.
		var found int64
		switch err := h.DB.QueryRowContext(ctx,
			`SELECT id FROM users WHERE id=? AND role='reseller' AND status='active'`,
			*ownerUserID).Scan(&found); {
		case errors.Is(err, sql.ErrNoRows):
			return reasonOwnerNotReseller, nil
		case err != nil:
			return "", err
		}
	}
	if customerID != nil && *customerID > 0 {
		var found int64
		switch err := h.DB.QueryRowContext(ctx,
			`SELECT id FROM customers WHERE id=?`, *customerID).Scan(&found); {
		case errors.Is(err, sql.ErrNoRows):
			return reasonCustomerNotFound, nil
		case err != nil:
			return "", err
		}
	}
	if planID != nil && *planID > 0 {
		var found int64
		switch err := h.DB.QueryRowContext(ctx,
			`SELECT id FROM service_plans WHERE id=?`, *planID).Scan(&found); {
		case errors.Is(err, sql.ErrNoRows):
			return reasonPlanNotFound, nil
		case err != nil:
			return "", err
		}
	}
	return "", nil
}

// nameAlreadyServed reports whether a name already has an nginx server block, as
// a domain or as somebody's subdomain.
//
// Both halves are needed because both produce a server block for the same
// server_name, and nginx answers such a pair with whichever it loaded first. The
// subdomain side has always checked both directions; this side checked only its
// own table, so `blog.example.com` could be added as a domain while it was
// already serving as a subdomain of `example.com`.
//
// A failed lookup is an ERROR, not "the name is free". Treating it as free is
// how a database hiccup becomes a duplicate server block that nobody chose.
func (h *Handlers) nameAlreadyServed(ctx context.Context, name string) (bool, error) {
	for _, query := range []string{
		`SELECT id FROM domains WHERE domain_name=?`,
		`SELECT id FROM subdomains WHERE fqdn=?`,
	} {
		var found int64
		switch err := h.DB.QueryRowContext(ctx, query, name).Scan(&found); {
		case err == nil:
			return true, nil
		case !errors.Is(err, sql.ErrNoRows):
			return false, err
		}
	}
	return false, nil
}

// The site types a domain may be created as. Only siteTypeStatic changes what
// gets provisioned; siteTypePHP and siteTypeWordPress are provisioned alike and
// differ only in where the client sends the customer afterwards.
const (
	siteTypePHP       = "php"
	siteTypeWordPress = "wordpress"
	siteTypeStatic    = "static"
)

// normalizeSiteType coerces a requested site type to one the column accepts.
//
// An unrecognised value falls back to PHP rather than being refused, so a client
// that predates the field, or an API caller that omits it, keeps working. The
// fallback deliberately runs TOWARDS the type that provisions everything: the
// opposite default would silently withhold a database the caller expected.
func normalizeSiteType(requested string) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case siteTypeWordPress:
		return siteTypeWordPress
	case siteTypeStatic:
		return siteTypeStatic
	default:
		return siteTypePHP
	}
}

// databaseNamesFor returns the default database and user a site type is entitled
// to, or an empty pair when it is entitled to neither.
//
// The names are what the connection-details screen reads off the domains row, so
// an empty pair is also the signal that no database was opened. Deriving the
// skip from these names rather than from the type again keeps the two decisions
// from drifting apart.
func databaseNamesFor(siteType, systemUser string) (dbName, dbUser string) {
	if siteType == siteTypeStatic {
		return "", ""
	}
	return systemUser + "_main", systemUser + "_db"
}

// mysqlCreateDB is a seam so provisionDatabase can be tested without a MariaDB
// socket. Production always uses the real implementation.
var mysqlCreateDB = credentials.MySQLCreateDB

// provisionDatabase opens the default database for a freshly created domain and
// returns the password it generated. An empty dbName means the site type is
// entitled to no database, and the empty password that comes back keeps a
// credential for a database nobody opened out of the create response.
func (h *Handlers) provisionDatabase(domainID int64, dbName, dbUser string) string {
	if dbName == "" {
		return ""
	}
	dbPass := credentials.RandomPassword(24)
	if err := mysqlCreateDB(h.DB, domainID, dbName, dbUser, dbPass); err != nil {
		log.Printf("MySQL create %q error: %v", dbName, err)
	}
	return dbPass
}

type createResp struct {
	Domain
	CreatedPasswords struct {
		FTP string `json:"ftp"`
		DB  string `json:"db"`
	} `json:"created_passwords"`
	// Nameservers is the pair the customer enters at their registrar. It rides
	// on the create response rather than a separate endpoint because it is
	// needed at exactly the same "shown once, write it down" moment as the
	// passwords, and because the pair depends on the RESELLER that created the
	// domain, so a client cannot work it out on its own. It is omitted when no
	// real pair is configured.
	Nameservers *nameserverPair `json:"nameservers,omitempty"`
	// Warning names something the create could not do, as a stable CODE the
	// interface translates. The domain itself was created; this is not an error.
	Warning string `json:"warning,omitempty"`
}

type nameserverPair struct {
	NS1 string `json:"ns1"`
	NS2 string `json:"ns2"`
}

func (h *Handlers) Create(w http.ResponseWriter, r *http.Request) {
	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.DomainName = strings.ToLower(strings.TrimSpace(req.DomainName))
	if req.PlanID == nil {
		var defaultPlanID int64
		err := h.DB.QueryRowContext(r.Context(),
			`SELECT id FROM service_plans WHERE is_default=1 ORDER BY id LIMIT 1`).Scan(&defaultPlanID)
		if err == nil {
			req.PlanID = &defaultPlanID
		} else if !errors.Is(err, sql.ErrNoRows) {
			log.Printf("read default plan: %v", err)
		}
	}
	if req.PHPVersion == "" {
		req.PHPVersion = "8.3"
		// If a plan is selected, inherit the PHP version from the plan.
		if req.PlanID != nil {
			var pv string
			if e := h.DB.QueryRowContext(r.Context(), `SELECT php_version FROM service_plans WHERE id=?`, *req.PlanID).Scan(&pv); e == nil && strings.TrimSpace(pv) != "" {
				req.PHPVersion = pv
			}
		}
	}
	if err := provisioner.ValidateDomain(req.DomainName); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid domain name")
		return
	}

	switch taken, err := h.nameAlreadyServed(r.Context(), req.DomainName); {
	case err != nil:
		// #nosec G706 -- the logged name passed provisioner.ValidateDomain just above, so it carries no CR/LF.
		log.Printf("check whether %q is already served: %v", req.DomainName, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not verify the domain name")
		return
	case taken:
		httpx.WriteError(w, http.StatusConflict, "this domain name is already registered")
		return
	}

	// 1) Linux user + nginx + PHP pool
	if err := quota.CheckDomainAllowed(r.Context(), h.DB, nil); err != nil {
		var le *quota.LimitError
		if errors.As(err, &le) {
			httpx.WriteError(w, http.StatusForbidden, le.Message)
			return
		}
		log.Printf("domain quota check failed: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not verify plan limit")
		return
	}

	// Choosing which reseller a new customer belongs to is an administrator's
	// decision. A reseller cannot reach the auto-creation path at all, it is
	// refused just below unless it names one of its own customers, so accepting
	// the field from one would let it ask for something that silently does
	// nothing.
	if req.OwnerUserID != nil {
		if c := middleware.ClaimsFrom(r); c == nil || c.Role != middleware.RoleAdmin {
			httpx.WriteError(w, http.StatusForbidden, reasonOwnerNotAllowed)
			return
		}
	}

	// Reseller guard: a reseller may only attach a domain to its own customer,
	// and the reseller's total domain quota applies (a ceiling separate from the
	// customer plan's max_domain).
	if c := middleware.ClaimsFrom(r); c != nil && c.Role == middleware.RoleReseller {
		if req.CustomerID == nil {
			httpx.WriteError(w, http.StatusBadRequest, "a domain must be attached to a customer")
			return
		}
		if !middleware.ResellerOwnsCustomer(r, c.UserID, *req.CustomerID) {
			httpx.WriteError(w, http.StatusForbidden, "no access to this customer")
			return
		}
		if err := quota.CheckResellerDomainAllowed(r.Context(), h.DB, c.UserID); err != nil {
			var le *quota.LimitError
			if errors.As(err, &le) {
				httpx.WriteError(w, http.StatusForbidden, le.Message)
				return
			}
			httpx.WriteError(w, http.StatusInternalServerError, "could not verify reseller limit")
			return
		}
		// Disk/traffic quota: when full, no new domain may be opened. Existing
		// sites are unaffected — these are "new resource" gates, not cuts.
		if err := quota.CheckResellerDiskAllowed(r.Context(), h.DB, c.UserID); err != nil {
			var le *quota.LimitError
			if errors.As(err, &le) {
				httpx.WriteError(w, http.StatusForbidden, le.Message)
				return
			}
			httpx.WriteError(w, http.StatusInternalServerError, "could not verify reseller disk quota")
			return
		}
		if err := quota.CheckResellerTrafficAllowed(r.Context(), h.DB, c.UserID); err != nil {
			var le *quota.LimitError
			if errors.As(err, &le) {
				httpx.WriteError(w, http.StatusForbidden, le.Message)
				return
			}
			httpx.WriteError(w, http.StatusInternalServerError, "could not verify reseller traffic quota")
			return
		}
	}

	// Check the ids the request points at BEFORE provisioning. Provision creates
	// the Linux user, the nginx vhost and the FPM pool, so refusing after it ran
	// would leave a half-provisioned domain behind for a request that was never
	// going to be accepted.
	if reason, err := h.referencedAccountsExist(r.Context(), req.CustomerID, req.PlanID, req.OwnerUserID); err != nil {
		log.Printf("verify referenced accounts for %q: %v", req.DomainName, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not verify the selected account")
		return
	} else if reason != "" {
		httpx.WriteError(w, http.StatusBadRequest, reason)
		return
	}

	pr, err := provisioner.Provision(req.DomainName, req.PHPVersion)
	if err != nil {
		log.Printf("provision %q failed: %v", req.DomainName, err)
		httpx.WriteError(w, http.StatusInternalServerError, "domain provisioning failed")
		return
	}

	// A static site never connects to MySQL, so it gets no database and no user.
	// The names stay EMPTY rather than being generated and left unbacked: the
	// connection-details screen reads db_name/db_user straight off this row, so a
	// generated name would advertise a database that does not exist.
	siteType := normalizeSiteType(req.SiteType)
	dbName, dbUser := databaseNamesFor(siteType, pr.SystemUser)

	// 2) domains row
	res, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO domains(domain_name, system_user, php_version, ssl_enabled, status, ipv4,
		   ftp_host, ftp_user, db_host, db_user, db_name, web_root, is_demo, site_type)
		 VALUES(?,?,?,0,'active',?,?,?, 'localhost',?,?,?, 0,?)`,
		req.DomainName, pr.SystemUser, req.PHPVersion, h.IPv4,
		h.IPv4, pr.SystemUser, dbUser, dbName, pr.WebRoot, siteType)
	if err != nil {
		_ = provisioner.Deprovision(req.DomainName, pr.SystemUser)
		httpx.WriteError(w, http.StatusInternalServerError, "domain record creation failed")
		return
	}
	id, _ := res.LastInsertId()

	if req.CustomerID != nil || req.PlanID != nil {
		// Not silently discarded: the domain is provisioned and serving, so a lost
		// write here leaves it attached to nobody while the caller was told which
		// customer it went to. Both ids were checked above, so a failure now is
		// the database itself.
		if _, err := h.DB.ExecContext(r.Context(),
			`UPDATE domains SET customer_id=?, plan_id=? WHERE id=?`,
			req.CustomerID, req.PlanID, id); err != nil {
			log.Printf("attach domain %d to customer/plan: %v", id, err)
			httpx.WriteError(w, http.StatusInternalServerError, "the domain was created but could not be attached to the selected account")
			return
		}
	}
	// Set when the caller asked for a reseller owner that could not be applied.
	// Carried to the response so a placement that did not happen is never
	// reported as one that did.
	var createWarning string
	if req.CustomerID == nil {
		// Nobody was named, so build the ownership chain now rather than leaving
		// it to the next restart. Until this existed, the account for a freshly
		// added domain appeared only after the startup backfill ran, so the
		// Customer Accounts screen stayed empty in the meantime.
		//
		// Reachable on an administrator's authority alone: a reseller is refused
		// above unless it names one of its own customers, so the owner written
		// here is one an administrator chose, or none at all.
		//
		// Not fatal. The domain is already provisioned and serving; a failure here
		// is logged and the startup backfill picks the tenant up.
		account, err := tenantaccount.Ensure(r.Context(), h.DB, pr.SystemUser, req.DomainName, req.OwnerUserID)
		switch {
		case err != nil:
			// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
			log.Printf("customer account for %q: %v", pr.SystemUser, err)
		case account.CustomerID > 0:
			if _, err := h.DB.ExecContext(r.Context(),
				`UPDATE domains SET customer_id=? WHERE id=?`, account.CustomerID, id); err != nil {
				log.Printf("link domain %d to customer %d: %v", id, account.CustomerID, err)
			}
			if req.OwnerUserID != nil && account.Reused {
				createWarning = warningOwnerNotApplied
			}
		}
	}
	// If a plan is selected, seed the nginx web-server defaults to the domain + refresh vhost
	if req.PlanID != nil {
		h.applyPlanNginxDefaults(r.Context(), id, *req.PlanID, pr.SystemUser, req.PHPVersion)
	}

	// 3) FTP account with a random password.
	ftpPass := credentials.RandomPassword(20)
	uidN, gidN := uidGidOf(pr.SystemUser)
	if err := credentials.FTPCreate(h.DB, id, pr.SystemUser, ftpPass, uidN, gidN); err != nil {
		log.Printf("FTP create %q error: %v", pr.SystemUser, err)
	}

	// 4) Default MySQL database + user, unless the site type is entitled to none.
	dbPass := h.provisionDatabase(id, dbName, dbUser)

	// 5) Auto-seed the DNS template + write BIND zone + reload
	if _, err := dns.SeedDefaults(r.Context(), h.DB, id, req.DomainName, h.IPv4); err != nil {
		log.Printf("DNS SeedDefaults %q error: %v", req.DomainName, err)
	}
	if err := dns.WriteZone(r.Context(), h.DB, id); err != nil {
		log.Printf("DNS WriteZone %q error: %v", req.DomainName, err)
	}

	// #nosec G118 -- intentional detached context: the request ends before this background cgroup write finishes; the request context would cancel it mid-write.
	go func(domainID int64) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := resourcelimit.ApplyAll(ctx, h.DB, domainID); err != nil {
			log.Printf("resource limit apply after domain creation, domain=%d: %v", domainID, err)
		}
	}(id)

	row := h.DB.QueryRowContext(r.Context(), selectAll+" WHERE d.id=?", id)
	d, _ := scan(row)

	resp := createResp{Domain: d, Warning: createWarning}
	resp.CreatedPasswords.FTP = ftpPass
	resp.CreatedPasswords.DB = dbPass
	// Only shown when a REAL pair is configured. The vanity values returned
	// otherwise (ns1.<domain>) cannot be handed to a customer, because they
	// would need a separate glue record at that domain's own registrar.
	if dns.NameserversConfigured(r.Context(), h.DB) {
		ns1, ns2 := dns.NameserverPair(r.Context(), h.DB, d.ID, d.DomainName)
		resp.Nameservers = &nameserverPair{NS1: ns1, NS2: ns2}
	}
	httpx.WriteJSON(w, http.StatusCreated, resp)
}

// Delete removes a domain and its panel-managed resources.
func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var domainName, sk string
	var isDemo int
	var parentDomainID sql.NullInt64
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name, system_user, is_demo, parent_domain_id FROM domains WHERE id=?`, id).
		Scan(&domainName, &sk, &isDemo, &parentDomainID)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}

	if parentDomainID.Valid {
		deleted, err := addondomains.Cleanup(r.Context(), h.DB, id)
		if err != nil {
			log.Printf("addon domain delete warn (%d): %v", id, err)
			httpx.WriteError(w, http.StatusInternalServerError, "addon domain deletion failed")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"deleted": map[string]string{"domain_name": deleted, "system_user": sk},
		})
		return
	}

	if childRows, err := h.DB.QueryContext(r.Context(), `SELECT id FROM domains WHERE parent_domain_id=?`, id); err == nil {
		childIDs := make([]int64, 0)
		for childRows.Next() {
			var childID int64
			if childRows.Scan(&childID) == nil {
				childIDs = append(childIDs, childID)
			}
		}
		_ = childRows.Close()
		for _, childID := range childIDs {
			if _, err := addondomains.Cleanup(r.Context(), h.DB, childID); err != nil {
				log.Printf("addon domain cleanup warn (parent=%d, child=%d): %v", id, childID, err)
			}
		}
	}

	// Applications go before the row does: the foreign key removes their records
	// but not their units, environment files or logs, and a unit left behind
	// holds its port out of the allocator's reach for good.
	apps.TeardownForDomain(r.Context(), h.DB, id)
	// The generated maintenance page is a host artefact: the foreign key
	// cascade removes the database rows and nothing on disk, so a deleted
	// domain would leave its page behind for good.
	if err := provisioner.RemoveMaintenancePage(id); err != nil {
		log.Printf("remove maintenance page for domain %d: %v", id, err)
	}

	if isDemo == 0 {
		// Remove the real DBs in MariaDB (CASCADE FK only deletes the panel DB metadata)
		if err := credentials.MySQLDropAllForDomain(h.DB, id); err != nil {
			log.Printf("mysql drop-all warn (%s): %v", domainName, err)
		}
		// nginx vhost + PHP pool + Linux user
		if err := provisioner.Deprovision(domainName, sk); err != nil {
			log.Printf("deprovision warn (%s): %v", domainName, err)
		}
		if err := resourcelimit.DeleteSystemdSlice(sk); err != nil {
			log.Printf("resource slice cleanup warn (%s): %v", sk, err)
		}
		// Redis tenant cache: Valkey ACL user + WP drop-in + domain_redis row.
		// Since domain_redis has no CASCADE FK, the row was orphaned when the domain was deleted.
		if err := redis.CloseDomain(h.DB, id, sk); err != nil {
			log.Printf("redis close-domain warn (%s): %v", sk, err)
		}
		// Mail metadata uses cascading foreign keys. The hook keeps domain deletion extensible.
		mail.CleanupDomain(h.DB, id, sk)
		// NOTE: Preserve /var/backups/servika/<sk>/ intentionally.
		// The customer may have deleted the domain by accident, so backups are kept for recovery.
		// (backups.RemoveDomainBackups is available for manual cleanup.)
	}

	// Existing installations may not have foreign keys on the traffic tables.
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM domain_traffic WHERE domain_id=?`, id); err != nil {
		log.Printf("domain traffic cleanup warn (%d): %v", id, err)
	}
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM domain_traffic_cursor WHERE domain_id=?`, id); err != nil {
		log.Printf("domain traffic cursor cleanup warn (%d): %v", id, err)
	}
	// These domain-owned tables have a domain_id index but no ON DELETE CASCADE, so
	// their rows would be orphaned after the domain is deleted. Remove them explicitly.
	for _, table := range []string{"protected_directories", "av_findings", "av_scans", "subdomains"} {
		// #nosec G202 -- table names come from this fixed literal whitelist, never user input; domain_id is bound.
		if _, err := h.DB.ExecContext(r.Context(),
			"DELETE FROM "+table+" WHERE domain_id=?", id); err != nil {
			log.Printf("%s cleanup warn (%d): %v", table, id, err)
		}
	}

	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM domains WHERE id=?`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "domain deletion failed")
		return
	}

	// BIND zone cleanup AFTER the DELETE: updateZoneIncludes regenerates zones.conf from the domains
	// table; if the domain were still in the table (old order) the last deleted
	// domain zone include would be rewritten (dangling, named reload error).
	if isDemo == 0 {
		if err := dns.DeleteZone(r.Context(), h.DB, domainName); err != nil {
			log.Printf("DNS DeleteZone warn (%s): %v", domainName, err)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"deleted": map[string]string{"domain_name": domainName, "system_user": sk},
	})
}

func uidGidOf(u string) (int, int) {
	uu, err := user.Lookup(u)
	if err != nil {
		return 0, 0
	}
	uid, _ := strconv.Atoi(uu.Uid)
	gid, _ := strconv.Atoi(uu.Gid)
	return uid, gid
}

type setPHPReq struct {
	PHPVersion string `json:"php_version"`
}

func (h *Handlers) SetPHP(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var req setPHPReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.PHPVersion == "" {
		httpx.WriteError(w, http.StatusBadRequest, "php_version is required")
		return
	}
	var domainName, sk, backend, certPath, keyPath, sslSource, webRoot string
	var isDemo int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name, system_user, is_demo, COALESCE(web_backend,'php-fpm'), COALESCE(cert_path,''), COALESCE(key_path,''), COALESCE(ssl_source,''), COALESCE(web_root,'') FROM domains WHERE id=?`, id).
		Scan(&domainName, &sk, &isDemo, &backend, &certPath, &keyPath, &sslSource, &webRoot)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	if isDemo == 1 {
		httpx.WriteError(w, http.StatusForbidden, "pHP versions cannot be changed for demo subscriptions")
		return
	}
	socket, err := provisioner.SetPHPVersion(domainName, sk, req.PHPVersion, certPath, keyPath, sslSource, backend, webRoot)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pHP version change failed")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE domains SET php_version=? WHERE id=?`, req.PHPVersion, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database update failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "id": id, "php_version": req.PHPVersion, "socket": socket,
	})
}

type setWebRootReq struct {
	Subdirectory string `json:"subdirectory"`
}

type webRootResp struct {
	WebRoot      string   `json:"web_root"`
	Subdirectory string   `json:"subdirectory"`
	Candidates   []string `json:"candidates"`
}

func webRootCandidates(systemUser string) []string {
	base := provisioner.PublicHTML(systemUser)
	candidates := []string{""}
	entries, err := os.ReadDir(base)
	if err != nil {
		return candidates
	}
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		if sub, err := provisioner.SafeWebRootSubdirectory(entry.Name()); err == nil && sub != "" {
			candidates = append(candidates, sub)
		}
	}
	return candidates
}

func (h *Handlers) GetWebRoot(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var systemUser, webRoot string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user, COALESCE(web_root,'') FROM domains WHERE id=?`, id).
		Scan(&systemUser, &webRoot)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	subdirectory := provisioner.WebRootSubdirectory(systemUser, webRoot)
	httpx.WriteJSON(w, http.StatusOK, webRootResp{
		WebRoot:      provisioner.SafeWebRoot(systemUser, webRoot),
		Subdirectory: subdirectory,
		Candidates:   webRootCandidates(systemUser),
	})
}

func (h *Handlers) SetWebRoot(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var req setWebRootReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var systemUser string
	var isDemo int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user, is_demo FROM domains WHERE id=?`, id).
		Scan(&systemUser, &isDemo)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	if isDemo == 1 {
		httpx.WriteError(w, http.StatusForbidden, "web root cannot be changed for demo subscriptions")
		return
	}
	abs, err := provisioner.AbsoluteWebRoot(systemUser, req.Subdirectory)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid web root")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(), `UPDATE domains SET web_root=? WHERE id=?`, abs, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database update failed")
		return
	}
	if err := provisioner.RerenderVhost(h.DB, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "virtual host update failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, webRootResp{
		WebRoot:      abs,
		Subdirectory: provisioner.WebRootSubdirectory(systemUser, abs),
		Candidates:   webRootCandidates(systemUser),
	})
}

// Web backend selector: "php-fpm" | "apache" | "static"
type setBackendReq struct {
	Backend string `json:"backend"`
}

var validBackends = map[string]bool{"php-fpm": true, "apache": true, "static": true}

func (h *Handlers) GetWebBackend(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var backend string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT COALESCE(web_backend,'php-fpm') FROM domains WHERE id=?`, id).Scan(&backend)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"backend":   backend,
		"available": []string{"php-fpm", "apache", "static"},
	})
}

func (h *Handlers) SetWebBackend(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var req setBackendReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !validBackends[req.Backend] {
		httpx.WriteError(w, http.StatusBadRequest, "invalid backend (php-fpm|apache|static)")
		return
	}
	var domainName, sk, phpVersion string
	var isDemo int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name, system_user, php_version, is_demo FROM domains WHERE id=?`, id).
		Scan(&domainName, &sk, &phpVersion, &isDemo)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	if isDemo == 1 {
		httpx.WriteError(w, http.StatusForbidden, "the backend cannot be changed for demo subscriptions")
		return
	}
	_ = domainName
	// 1) update DB
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE domains SET web_backend=? WHERE id=?`, req.Backend, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database update failed")
		return
	}
	// 2) Reapply the vhost (nginx + apache manager read web_backend from the DB)
	socket, _ := provisioner.PHPSocketFor(sk, phpVersion)
	if err := provisioner.ApplyVhostForDomain(h.DB, id, socket, phpVersion); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "virtual host update failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "id": id, "backend": req.Backend,
	})
}

// setFTPPwReq contains a replacement FTP password.
type setFTPPwReq struct {
	Password string `json:"password"`
}

func (h *Handlers) SetFTPPassword(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var req setFTPPwReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Password == "" {
		req.Password = credentials.RandomPassword(20)
	}
	if !credentials.ValidPassword(req.Password) {
		httpx.WriteError(w, http.StatusBadRequest, "password contains invalid characters")
		return
	}
	var sk string
	var isDemo int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user, is_demo FROM domains WHERE id=?`, id).
		Scan(&sk, &isDemo)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	// A swallowed Scan error would update the FTP password of the empty system
	// user, which matches no account and still answers 200 with the new
	// password, and would leave isDemo reading 0 so the guard below is bypassed.
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	if sk == "" {
		httpx.WriteError(w, http.StatusInternalServerError, "domain record is incomplete")
		return
	}
	if isDemo == 1 {
		httpx.WriteError(w, http.StatusForbidden, "fTP passwords cannot be changed for demo subscriptions")
		return
	}
	if err := credentials.FTPUpdatePassword(h.DB, sk, req.Password); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "fTP password update failed")
		return
	}
	// If SSH is enabled, sync the system (SSH) password with FTP too
	var sshOn int
	_ = h.DB.QueryRowContext(r.Context(), `SELECT ssh_access FROM domains WHERE id=?`, id).Scan(&sshOn)
	if sshOn == 1 {
		if err := credentials.SyncSSHPassword(h.DB, sk); err != nil {
			// SSH password stayed at its old value; the returned password only works
			// for FTP. Report a degraded result rather than implying SSH is in sync.
			log.Printf("ssh password sync warn (%s): %v", sk, err)
			httpx.WriteJSON(w, http.StatusOK, map[string]any{
				"ok": true, "id": id, "username": sk, "password": req.Password,
				"ssh_sync_failed": true,
			})
			return
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "id": id, "username": sk, "password": req.Password,
	})
}

// ShowFTPPassword returns the plaintext FTP password for a domain.
func (h *Handlers) ShowFTPPassword(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var sk string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user FROM domains WHERE id=?`, id).Scan(&sk)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	pass, err := credentials.FTPPlainPassword(h.DB, sk)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"ftp_pass_plain": ""})
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read FTP password")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"ftp_pass_plain": pass})
}

// DBAccount describes a database account belonging to a domain.
type DBAccount struct {
	ID        int64  `json:"id"`
	DomainID  int64  `json:"domain_id"`
	DBName    string `json:"db_name"`
	DBUser    string `json:"db_user"`
	DBHost    string `json:"db_host"`
	DBPass    string `json:"db_pass"`
	CreatedAt string `json:"created_at"`
}

func (h *Handlers) ListDatabases(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, domain_id, db_name, db_user, db_host, db_pass_plain, DATE_FORMAT(created_at,'%Y-%m-%d %H:%i')
		 FROM db_accounts WHERE domain_id=? ORDER BY id`, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer func() { _ = rows.Close() }()
	out := make([]DBAccount, 0)
	for rows.Next() {
		var d DBAccount
		if err := rows.Scan(&d.ID, &d.DomainID, &d.DBName, &d.DBUser, &d.DBHost, &d.DBPass, &d.CreatedAt); err != nil {
			continue
		}
		// db_pass_plain is encrypted at rest (bound to db_user); decrypt for the
		// reveal response. Legacy plaintext rows pass through unchanged.
		if pw, err := credentials.DecryptDBPass(d.DBUser, d.DBPass); err == nil {
			d.DBPass = pw
		} else {
			d.DBPass = ""
		}
		out = append(out, d)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// createDBReq models a "New Database" request.
//
// When Auto is true (or no fields are supplied), the database name, user, and password are
// generated automatically (legacy behavior, backward compatible). Otherwise the customer
// customizes:
//   - DBSuffix: database name suffix; the panel forcibly prepends the `<system_user>_` prefix.
//   - UserMode "new": UserSuffix is supplied (prefix prepended); "existing": ExistingUser selected.
//   - Password: customer supplies a strong password, or leaves it blank for a generated one.
type createDBReq struct {
	Auto         bool   `json:"auto"`
	DBSuffix     string `json:"db_suffix"`
	UserMode     string `json:"user_mode"` // "new" | "existing"
	UserSuffix   string `json:"user_suffix"`
	ExistingUser string `json:"existing_user"`
	Password     string `json:"password"`
}

func (h *Handlers) CreateDatabase(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var req createDBReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var sk string
	var isDemo int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user, is_demo FROM domains WHERE id=?`, id).
		Scan(&sk, &isDemo)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "domain query failed")
		return
	}
	if isDemo == 1 {
		httpx.WriteError(w, http.StatusForbidden, "databases cannot be added to demo subscriptions")
		return
	}
	// Hold a per-customer lock across the quota check AND the database creation below
	// so concurrent requests cannot each pass the count check before either insert
	// lands and exceed the plan limit.
	unlock := quota.LockCustomerForDomain(r.Context(), h.DB, id)
	defer unlock()
	if err := quota.CheckDatabaseAllowed(r.Context(), h.DB, id); err != nil {
		var le *quota.LimitError
		if errors.As(err, &le) {
			httpx.WriteError(w, http.StatusForbidden, le.Message)
			return
		}
		log.Printf("database quota check for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not verify plan limit")
		return
	}

	// Backward compatible: empty body or Auto=true generates everything (legacy behavior).
	auto := req.Auto ||
		(req.DBSuffix == "" && req.UserSuffix == "" && req.ExistingUser == "" && req.Password == "")

	var dbName, dbUser, password string
	existingUserMode := false

	if auto {
		dbName = sk + "_db" + strconv.FormatInt(id, 10)
		dbUser = dbName
		password = credentials.RandomPassword(24)
	} else {
		if req.DBSuffix == "" {
			httpx.WriteError(w, http.StatusBadRequest, "database name suffix is required")
			return
		}
		if !credentials.ValidDBSuffix(req.DBSuffix) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid database suffix (lowercase letters, digits, underscore only; 1-32 characters)")
			return
		}
		dbName = sk + "_" + req.DBSuffix
		if !credentials.ValidCustomerDBIdentifier(sk, dbName) {
			httpx.WriteError(w, http.StatusBadRequest, "database name too long (prefix + suffix must be at most 64 characters)")
			return
		}

		switch req.UserMode {
		case "existing":
			if req.ExistingUser == "" || !credentials.ValidCustomerDBIdentifier(sk, req.ExistingUser) {
				httpx.WriteError(w, http.StatusBadRequest, "invalid existing user")
				return
			}
			// Ownership: the selected user must actually belong to this domain (prefix guarantee).
			var n int
			_ = h.DB.QueryRowContext(r.Context(),
				`SELECT COUNT(*) FROM db_accounts WHERE domain_id=? AND db_user=?`, id, req.ExistingUser).Scan(&n)
			if n == 0 {
				httpx.WriteError(w, http.StatusBadRequest, "selected user does not belong to this domain")
				return
			}
			dbUser = req.ExistingUser
			existingUserMode = true
		default: // "new"
			if req.UserSuffix == "" {
				httpx.WriteError(w, http.StatusBadRequest, "user name suffix is required")
				return
			}
			if !credentials.ValidDBSuffix(req.UserSuffix) {
				httpx.WriteError(w, http.StatusBadRequest, "invalid user suffix (lowercase letters, digits, underscore only; 1-32 characters)")
				return
			}
			dbUser = sk + "_" + req.UserSuffix
			if !credentials.ValidCustomerDBIdentifier(sk, dbUser) {
				httpx.WriteError(w, http.StatusBadRequest, "user name too long (prefix + suffix must be at most 64 characters)")
				return
			}
			if req.Password == "" {
				password = credentials.RandomPassword(24)
			} else {
				if ok, reason := credentials.StrongPassword(req.Password); !ok {
					httpx.WriteError(w, http.StatusBadRequest, reason)
					return
				}
				password = req.Password
			}
		}
	}

	// Name collision: return a clear 409 instead of a duplicate-key 500.
	var collision int
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM db_accounts WHERE db_name=?`, dbName).Scan(&collision)
	if collision > 0 {
		httpx.WriteError(w, http.StatusConflict, "A database with this name already exists: "+dbName)
		return
	}

	if existingUserMode {
		if err := credentials.MySQLCreateDBForUser(h.DB, id, dbName, dbUser); err != nil {
			if errors.Is(err, credentials.ErrInvalidMySQLCredentials) {
				httpx.WriteError(w, http.StatusBadRequest, "invalid database name or user")
				return
			}
			httpx.WriteError(w, http.StatusInternalServerError, "database creation failed")
			return
		}
		// Surface the existing user's password in the response (the customer already owns it).
		var stored string
		if err := h.DB.QueryRowContext(r.Context(),
			`SELECT db_pass_plain FROM db_accounts WHERE db_user=? LIMIT 1`, dbUser).Scan(&stored); err == nil {
			if pw, derr := credentials.DecryptDBPass(dbUser, stored); derr == nil {
				password = pw
			}
		}
	} else {
		if err := credentials.MySQLCreateDB(h.DB, id, dbName, dbUser, password); err != nil {
			if errors.Is(err, credentials.ErrInvalidMySQLCredentials) {
				httpx.WriteError(w, http.StatusBadRequest, "invalid database name or user")
				return
			}
			httpx.WriteError(w, http.StatusInternalServerError, "database creation failed")
			return
		}
	}

	// Governor/limits: apply plan limits to the new database user in the background, best-effort.
	// #nosec G118 -- intentional detached context: the request ends before this background cgroup write finishes; the request context would cancel it mid-write.
	go func(domainID int64) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := resourcelimit.ApplyAll(ctx, h.DB, domainID); err != nil {
			log.Printf("resourcelimit apply (db-create) domain=%d: %v", domainID, err)
		}
	}(id)

	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"ok": true, "domain_id": id, "db_name": dbName, "db_user": dbUser, "db_pass": password,
	})
}

func (h *Handlers) DeleteDatabase(w http.ResponseWriter, r *http.Request) {
	dbid, _ := strconv.ParseInt(chi.URLParam(r, "dbid"), 10, 64)
	var dbName, dbUser string
	var isDemo int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT db.db_name, db.db_user, d.is_demo
		 FROM db_accounts db JOIN domains d ON d.id=db.domain_id
		 WHERE db.id=?`, dbid).Scan(&dbName, &dbUser, &isDemo)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "database record not found")
		return
	}
	// A swallowed Scan error would leave isDemo reading 0, bypassing the demo
	// guard below, and would send empty identifiers into the drop path.
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	if dbName == "" || dbUser == "" {
		httpx.WriteError(w, http.StatusInternalServerError, "database record is incomplete")
		return
	}
	if isDemo == 1 {
		httpx.WriteError(w, http.StatusForbidden, "databases cannot be deleted from demo subscriptions")
		return
	}
	// When the user is shared across other databases (existing-user mode), drop only the database
	// and keep the user, so the sharing databases keep their access.
	//
	// The count decides whether the MySQL user survives, so a failed query must
	// not read as "not shared": that branch drops a user other databases still
	// authenticate with, and no later step would notice.
	var shared int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM db_accounts WHERE db_user=? AND db_name<>?`, dbUser, dbName).
		Scan(&shared); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	if shared > 0 {
		if err := credentials.MySQLDropDBKeepUser(h.DB, dbName); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "database deletion failed")
			return
		}
	} else if err := credentials.MySQLDropDB(h.DB, dbName, dbUser); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database deletion failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": dbName})
}

// BulkOwner updates customer_id for multiple domains.
type bulkOwnerReq struct {
	IDs        []int64 `json:"ids"`
	CustomerID *int64  `json:"customer_id"`
}

func (h *Handlers) BulkOwner(w http.ResponseWriter, r *http.Request) {
	var req bulkOwnerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.IDs) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "at least one domain ID is required")
		return
	}
	clearing := req.CustomerID == nil || *req.CustomerID <= 0

	// A reseller may move a domain between its OWN customers and nothing else.
	if c := middleware.ClaimsFrom(r); c != nil && c.Role == middleware.RoleReseller {
		if clearing {
			// Detaching hands the domain to admin, which takes it out of the
			// reseller's own scope permanently. That is a one-way loss the reseller
			// could not undo, so it stays an administrator's decision.
			httpx.WriteError(w, http.StatusForbidden, "a reseller cannot detach a domain from its customer")
			return
		}
		if !middleware.ResellerOwnsCustomer(r, c.UserID, *req.CustomerID) {
			httpx.WriteError(w, http.StatusForbidden, "no access to this customer")
			return
		}
	}

	// customer_id may be NULL or a positive value.
	if !clearing {
		var exists int
		_ = h.DB.QueryRowContext(r.Context(),
			`SELECT COUNT(*) FROM customers WHERE id=?`, *req.CustomerID).Scan(&exists)
		if exists == 0 {
			httpx.WriteError(w, http.StatusBadRequest, "customer not found")
			return
		}
	}
	// Build placeholders for the IN clause.
	placeholders := make([]string, len(req.IDs))
	args := []any{}
	if !clearing {
		args = append(args, *req.CustomerID)
	} else {
		args = append(args, nil)
	}
	for i, id := range req.IDs {
		placeholders[i] = "?"
		args = append(args, id)
	}
	// The SOURCE domains are narrowed by the query itself, not checked row by
	// row: an id the caller does not own simply matches nothing, so a hand-built
	// request body cannot move somebody else's domain. ScopeSQL returns a whole
	// " WHERE ..." clause and this statement already has one, so its keyword is
	// swapped for AND. Empty for an admin, which leaves the statement unchanged.
	scope, scopeArgs := middleware.ScopeSQL(r, "d")
	scope = strings.Replace(scope, " WHERE ", " AND ", 1)
	args = append(args, scopeArgs...)
	// #nosec G202 -- only literal "?" placeholders and the constant ScopeSQL fragment are joined; all values are bound via args.
	sql := `UPDATE domains d SET d.customer_id=? WHERE d.id IN (` + strings.Join(placeholders, ",") + `)` + scope
	// #nosec G701 G202 -- scope is a constant fragment from ScopeSQL with a literal alias and placeholders holds only literal "?"; every user value is bound via args.
	res, err := h.DB.ExecContext(r.Context(), sql, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "bulk update failed")
		return
	}
	n, _ := res.RowsAffected()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "updated": n})
}

// BulkStatus toggles multiple domains between active and passive states.
type bulkStatusReq struct {
	IDs    []int64 `json:"ids"`
	Status string  `json:"status"` // "active" | "passive"
}

func (h *Handlers) BulkStatus(w http.ResponseWriter, r *http.Request) {
	var req bulkStatusReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.IDs) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "at least one domain ID is required")
		return
	}
	if req.Status != "active" && req.Status != "passive" {
		httpx.WriteError(w, http.StatusBadRequest, "status must be active or passive")
		return
	}
	placeholders := make([]string, len(req.IDs))
	args := []any{req.Status}
	for i, id := range req.IDs {
		placeholders[i] = "?"
		args = append(args, id)
	}
	// #nosec G202 -- only literal "?" placeholders are joined into the IN clause; all IDs are bound via args.
	sql := `UPDATE domains SET status=? WHERE id IN (` + strings.Join(placeholders, ",") + `)`
	res, err := h.DB.ExecContext(r.Context(), sql, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "bulk update failed")
		return
	}
	n, _ := res.RowsAffected()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "updated": n})
}

// applyPlanNginxDefaults writes the plan nginx
// defaults (FastCGI cache + client_max_body + extra directives) to the domain
// nginx_settings row when a new domain is attached to a plan, and re-renders the vhost with these settings.
// Best-effort: on error the domain still remains created (only logged).
func (h *Handlers) applyPlanNginxDefaults(ctx context.Context, domainID, planID int64, sk, php string) {
	var fastCGICache, clientMaxBodyMB int
	var planDirectives string
	if err := h.DB.QueryRowContext(ctx,
		`SELECT fastcgi_cache, client_max_body_mb, COALESCE(nginx_extra_directives,'')
		   FROM service_plans WHERE id=?`, planID).Scan(&fastCGICache, &clientMaxBodyMB, &planDirectives); err != nil {
		log.Printf("read plan nginx defaults (plan=%d): %v", planID, err)
		return
	}
	extraDirectives := ""
	if clientMaxBodyMB > 0 {
		extraDirectives = "client_max_body_size " + strconv.Itoa(clientMaxBodyMB) + "m;\n"
	}
	if strings.TrimSpace(planDirectives) != "" {
		extraDirectives += planDirectives
	}
	if _, err := h.DB.ExecContext(ctx,
		`INSERT INTO nginx_settings(domain_id, subdomain_id, fastcgi_cache, extra_directives)
		 VALUES(?,0,?,?)
		 ON DUPLICATE KEY UPDATE fastcgi_cache=VALUES(fastcgi_cache), extra_directives=VALUES(extra_directives)`,
		domainID, fastCGICache, extraDirectives); err != nil {
		log.Printf("seed nginx_settings (domain=%d): %v", domainID, err)
		return
	}
	socket, err := provisioner.PHPSocketFor(sk, php)
	if err != nil {
		log.Printf("php socket (domain=%d): %v", domainID, err)
		return
	}
	if err := provisioner.ApplyVhostForDomain(h.DB, domainID, socket, php); err != nil {
		log.Printf("rerender plan virtual host (domain=%d): %v", domainID, err)
	}
}
