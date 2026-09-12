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

	"servika/internal/credentials"
	"servika/internal/httpx"
	"servika/internal/middleware"
	"servika/internal/provisioner"
	"servika/internal/quota"

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
	// MaintenanceEnabled lets a list say a site is deliberately closed rather
	// than broken. Without it the overview shows a healthy domain while every
	// visitor is getting a 503.
	MaintenanceEnabled bool `json:"maintenance_enabled"`
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
  d.db_host, d.db_user, d.db_name, d.web_root, d.size_kb, d.traffic_kb,
  COALESCE(d.notes,''), DATE_FORMAT(d.created_at,'%Y-%m-%d'),
  d.plan_id, COALESCE(p.name,''), d.ssh_access, COALESCE(d.suspended,0),
  COALESCE(ru.username,''), d.site_type, COALESCE(d.ssl_source,''), COALESCE(d.ipv6,''),
  COALESCE(d.maintenance_enabled,0) FROM domains d
  LEFT JOIN service_plans p ON p.id=d.plan_id
  LEFT JOIN customers cu ON cu.id=d.customer_id
  LEFT JOIN users ru ON ru.id=cu.owner_user_id`

func scan(rs interface{ Scan(...any) error }) (Domain, error) {
	var d Domain
	var ssl, sshE, suspended, maintenance int
	var planID sql.NullInt64
	err := rs.Scan(&d.ID, &d.DomainName, &d.SystemUser, &d.PHPVersion, &ssl,
		&d.SSLExpiry, &d.Status, &d.IPv4, &d.FTPHost, &d.FTPUser,
		&d.DBHost, &d.DBUser, &d.DBName, &d.WebRoot, &d.SizeKB, &d.TrafficKB,
		&d.Notes, &d.CreatedAt,
		&planID, &d.PlanName, &sshE, &suspended,
		&d.ResellerName, &d.SiteType, &d.SSLSource, &d.IPv6, &maintenance)
	d.SSL = ssl == 1
	d.SshAccess = sshE == 1
	d.Suspended = suspended == 1
	d.MaintenanceEnabled = maintenance == 1
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
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
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
// A NEW domain no longer reaches this: allocateSystemUser gives every domain a
// system user of its own, so a create cannot land on another tenant's account.
// It stays because a panel upgraded from before that can still carry two domains
// sharing one, and a reseller named for the second of them is still not applied.
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
	if positiveID(ownerUserID) && positiveID(customerID) {
		// Two different intents in one request. Applying one and dropping the
		// other would report a placement that did not happen.
		return reasonOwnerWithCustomer, nil
	}
	for _, ref := range []struct {
		id      *int64
		query   string
		missing string
	}{
		// The role and the status are both part of the check: a suspended account
		// is one an operator deliberately took out of service, and handing it a
		// fresh domain would quietly put it back to work.
		{ownerUserID, `SELECT id FROM users WHERE id=? AND role='reseller' AND status='active'`, reasonOwnerNotReseller},
		{customerID, `SELECT id FROM customers WHERE id=?`, reasonCustomerNotFound},
		{planID, `SELECT id FROM service_plans WHERE id=?`, reasonPlanNotFound},
	} {
		if !positiveID(ref.id) {
			continue
		}
		if reason, err := h.referencedRowMissing(ctx, ref.query, *ref.id, ref.missing); reason != "" || err != nil {
			return reason, err
		}
	}
	return "", nil
}

// referencedRowMissing looks up one referenced row and returns missing when it
// is not there. A lookup that failed is an error, never a verdict.
func (h *Handlers) referencedRowMissing(ctx context.Context, query string, id int64, missing string) (string, error) {
	var found int64
	switch err := h.DB.QueryRowContext(ctx, query, id).Scan(&found); {
	case errors.Is(err, sql.ErrNoRows):
		return missing, nil
	case err != nil:
		return "", err
	}
	return "", nil
}

// positiveID reports whether an optional id names a row.
func positiveID(id *int64) bool { return id != nil && *id > 0 }

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
	h.fillCreateDefaults(r, &req)
	if h.createRefused(w, r, &req) {
		return
	}
	domain, ok := h.provisionDomain(w, r, &req)
	if !ok {
		return
	}
	createWarning, ok := h.attachDomain(w, r, &req, domain)
	if !ok {
		return
	}
	h.finishCreate(w, r, &req, domain, createWarning)
}

// fillCreateDefaults fills in what a create request left out: the default plan,
// and the PHP version of the selected plan or 8.3.
func (h *Handlers) fillCreateDefaults(r *http.Request, req *createReq) {
	if req.PlanID == nil {
		var defaultPlanID int64
		err := h.DB.QueryRowContext(r.Context(),
			`SELECT id FROM service_plans WHERE is_default=1 ORDER BY id LIMIT 1`).Scan(&defaultPlanID)
		if err == nil {
			req.PlanID = &defaultPlanID
		} else if !errors.Is(err, sql.ErrNoRows) {
			httpx.LogR(r, "read default plan: %v", err)
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
}

// createRefused answers a create request that must not provision anything, and
// reports whether it did.
func (h *Handlers) createRefused(w http.ResponseWriter, r *http.Request, req *createReq) bool {
	if err := provisioner.ValidateDomain(req.DomainName); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid domain name")
		return true
	}
	// The archive import path reaches domain creation through this handler, so
	// the ban covers it here rather than in internal/transfers.
	if refuseIfBlocked(w, r, h.DB, req.DomainName) {
		return true
	}
	if h.nameRefused(w, r, req.DomainName) {
		return true
	}
	if ownerRefused(w, r, req) {
		return true
	}
	if h.resellerRefused(w, r, req) {
		return true
	}
	return h.accountsRefused(w, r, req)
}

// nameRefused answers a name that is already served, or that could not be
// checked.
func (h *Handlers) nameRefused(w http.ResponseWriter, r *http.Request, name string) bool {
	switch taken, err := h.nameAlreadyServed(r.Context(), name); {
	case err != nil:
		// #nosec G706 -- the logged name passed provisioner.ValidateDomain just above, so it carries no CR/LF.
		httpx.LogR(r, "check whether %q is already served: %v", name, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not verify the domain name")
		return true
	case taken:
		httpx.WriteError(w, http.StatusConflict, "this domain name is already registered")
		return true
	}
	return false
}

// ownerRefused answers an owner named by anyone but an administrator.
//
// Choosing which reseller a new customer belongs to is an administrator's
// decision. A reseller cannot reach the auto-creation path at all, it is
// refused just below unless it names one of its own customers, so accepting
// the field from one would let it ask for something that silently does
// nothing.
func ownerRefused(w http.ResponseWriter, r *http.Request, req *createReq) bool {
	if req.OwnerUserID == nil {
		return false
	}
	if c := middleware.ClaimsFrom(r); c == nil || c.Role != middleware.RoleAdmin {
		httpx.WriteError(w, http.StatusForbidden, reasonOwnerNotAllowed)
		return true
	}
	return false
}

// resellerRefused applies the reseller guard: a reseller may only attach a
// domain to its own customer, and the reseller's total domain quota applies (a
// ceiling separate from the customer plan's max_domain).
func (h *Handlers) resellerRefused(w http.ResponseWriter, r *http.Request, req *createReq) bool {
	c := middleware.ClaimsFrom(r)
	if c == nil || c.Role != middleware.RoleReseller {
		return false
	}
	if req.CustomerID == nil {
		httpx.WriteError(w, http.StatusBadRequest, "a domain must be attached to a customer")
		return true
	}
	if !resellerOwnsCustomer(r, c.UserID, *req.CustomerID) {
		httpx.WriteError(w, http.StatusForbidden, "no access to this customer")
		return true
	}
	return resellerQuotaRefused(w, r, h.DB, c.UserID)
}

// resellerQuotaRefused checks the reseller's domain ceiling and its disk and
// traffic quotas, in that order, and answers the first one that does not pass.
func resellerQuotaRefused(w http.ResponseWriter, r *http.Request, db *sql.DB, resellerID int64) bool {
	for _, gate := range []struct {
		check   func(context.Context, *sql.DB, int64) error
		failure string
	}{
		{checkResellerDomainAllowed, "could not verify reseller limit"},
		// Disk/traffic quota: when full, no new domain may be opened. Existing
		// sites are unaffected — these are "new resource" gates, not cuts.
		{checkResellerDiskAllowed, "could not verify reseller disk quota"},
		{checkResellerTrafficAllowed, "could not verify reseller traffic quota"},
	} {
		if err := gate.check(r.Context(), db, resellerID); err != nil {
			writeQuotaRefusal(w, err, gate.failure)
			return true
		}
	}
	return false
}

// writeQuotaRefusal answers a quota check that did not pass: a reached limit
// with its own message, and anything else as the failure it is.
func writeQuotaRefusal(w http.ResponseWriter, err error, failure string) {
	if le, ok := errors.AsType[*quota.LimitError](err); ok {
		httpx.WriteError(w, http.StatusForbidden, le.Message)
		return
	}
	httpx.WriteError(w, http.StatusInternalServerError, failure)
}

// quotaLimitReached reports whether a quota check refused on a reached limit
// rather than failing to read it.
func quotaLimitReached(err error) bool {
	_, limited := errors.AsType[*quota.LimitError](err)
	return limited
}

// accountsRefused checks the accounts the request points at and the customer
// plan's domain ceiling.
func (h *Handlers) accountsRefused(w http.ResponseWriter, r *http.Request, req *createReq) bool {
	// Check the ids the request points at BEFORE provisioning. Provision creates
	// the Linux user, the nginx vhost and the FPM pool, so refusing after it ran
	// would leave a half-provisioned domain behind for a request that was never
	// going to be accepted.
	if reason, err := h.referencedAccountsExist(r.Context(), req.CustomerID, req.PlanID, req.OwnerUserID); err != nil {
		httpx.LogR(r, "verify referenced accounts for %q: %v", req.DomainName, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not verify the selected account")
		return true
	} else if reason != "" {
		httpx.WriteError(w, http.StatusBadRequest, reason)
		return true
	}

	// The customer plan's max_domain ceiling, with the customer the request names.
	// It used to be called with a literal nil, which returns on the function's
	// first branch ("administrators have no quota limit") and so never read the
	// plan at all: a reseller could attach any number of top-level domains to a
	// customer whose plan allowed one, bounded only by the reseller's own
	// aggregate ceiling. The addon-domain path has always passed the real id.
	//
	// It runs AFTER referencedAccountsExist so an id that names no customer is
	// answered as a bad request rather than as a failed quota read, and BEFORE
	// Provision so a refusal leaves no Linux user, vhost or FPM pool behind.
	if err := checkDomainAllowed(r.Context(), h.DB, req.CustomerID); err != nil {
		if !quotaLimitReached(err) {
			httpx.LogR(r, "domain quota check failed: %v", err)
		}
		writeQuotaRefusal(w, err, "could not verify plan limit")
		return true
	}
	return false
}

// createdDomain is the tenant Create provisioned and the row it recorded.
type createdDomain struct {
	id             int64
	systemUser     string
	dbName, dbUser string
}

// provisionDomain builds the tenant on the host and records its domains row. A
// row that cannot be written takes the tenant down again.
func (h *Handlers) provisionDomain(w http.ResponseWriter, r *http.Request, req *createReq) (createdDomain, bool) {
	// 1) Linux user + nginx + PHP pool
	pr, err := provisionTenant(req.DomainName, req.PHPVersion)
	if err != nil {
		httpx.LogR(r, "provision %q failed: %v", req.DomainName, err)
		httpx.WriteError(w, http.StatusInternalServerError, "domain provisioning failed")
		return createdDomain{}, false
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
		   ftp_host, ftp_user, db_host, db_user, db_name, web_root, site_type)
		 VALUES(?,?,?,0,'active',?,?,?, 'localhost',?,?,?,?)`,
		req.DomainName, pr.SystemUser, req.PHPVersion, h.IPv4,
		h.IPv4, pr.SystemUser, dbUser, dbName, pr.WebRoot, siteType)
	if err != nil {
		_ = deprovisionTenant(req.DomainName, pr.SystemUser)
		// The domain name was already checked above, so the only key left to break
		// here is uq_domains_system_user_top: two creates running together read the
		// same free system user name, and the database refused the second. The
		// teardown just above correctly leaves the host alone, because the winner's
		// row now answers to that name. Retrying allocates the next one.
		if strings.Contains(err.Error(), "uq_domains_system_user_top") {
			httpx.LogR(r, "create %q lost the race for system user %q", req.DomainName, pr.SystemUser)
			httpx.WriteError(w, http.StatusConflict, "another domain took this system user name; try again")
			return createdDomain{}, false
		}
		httpx.WriteError(w, http.StatusInternalServerError, "domain record creation failed")
		return createdDomain{}, false
	}
	id, _ := res.LastInsertId()
	return createdDomain{id: id, systemUser: pr.SystemUser, dbName: dbName, dbUser: dbUser}, true
}

// attachDomain writes the customer and plan the request named, or builds the
// ownership chain when it named no customer. It returns the warning the response
// carries, and false when the answer was already written.
func (h *Handlers) attachDomain(w http.ResponseWriter, r *http.Request, req *createReq, domain createdDomain) (string, bool) {
	if req.CustomerID != nil || req.PlanID != nil {
		// Not silently discarded: the domain is provisioned and serving, so a lost
		// write here leaves it attached to nobody while the caller was told which
		// customer it went to. Both ids were checked above, so a failure now is
		// the database itself.
		if _, err := h.DB.ExecContext(r.Context(),
			`UPDATE domains SET customer_id=?, plan_id=? WHERE id=?`,
			req.CustomerID, req.PlanID, domain.id); err != nil {
			httpx.LogR(r, "attach domain %d to customer/plan: %v", domain.id, err)
			httpx.WriteError(w, http.StatusInternalServerError, "the domain was created but could not be attached to the selected account")
			return "", false
		}
	}
	if req.CustomerID != nil {
		return "", true
	}
	return h.linkTenantAccount(r, req, domain), true
}

// linkTenantAccount builds the ownership chain for a domain created with no
// customer named, and returns the warning to carry to the response: set when the
// caller asked for a reseller owner that could not be applied, so a placement
// that did not happen is never reported as one that did.
//
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
func (h *Handlers) linkTenantAccount(r *http.Request, req *createReq, domain createdDomain) string {
	account, err := ensureTenantAccount(r.Context(), h.DB, domain.systemUser, req.DomainName, req.OwnerUserID)
	switch {
	case err != nil:
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		httpx.LogR(r, "customer account for %q: %v", domain.systemUser, err)
	case account.CustomerID > 0:
		if _, err := h.DB.ExecContext(r.Context(),
			`UPDATE domains SET customer_id=? WHERE id=?`, account.CustomerID, domain.id); err != nil {
			httpx.LogR(r, "link domain %d to customer %d: %v", domain.id, account.CustomerID, err)
		}
		if req.OwnerUserID != nil && account.Reused {
			return warningOwnerNotApplied
		}
	}
	return ""
}

// finishCreate runs the best-effort steps that follow the domain row, and
// answers with the domain and the passwords created for it.
func (h *Handlers) finishCreate(w http.ResponseWriter, r *http.Request, req *createReq, domain createdDomain, createWarning string) {
	id := domain.id
	// If a plan is selected, seed the nginx web-server defaults to the domain + refresh vhost
	if req.PlanID != nil {
		h.applyPlanNginxDefaults(r.Context(), id, *req.PlanID, domain.systemUser, req.PHPVersion)
	}

	// 3) FTP account with a random password.
	ftpPass := credentials.RandomPassword(20)
	uidN, gidN := uidGidOf(domain.systemUser)
	if err := createFTPAccount(h.DB, id, domain.systemUser, ftpPass, uidN, gidN); err != nil {
		httpx.LogR(r, "FTP create %q error: %v", domain.systemUser, err)
	}

	// 4) Default MySQL database + user, unless the site type is entitled to none.
	dbPass := h.provisionDatabase(id, domain.dbName, domain.dbUser)

	// 5) Auto-seed the DNS template + write BIND zone + reload
	if _, err := seedDNSDefaults(r.Context(), h.DB, id, req.DomainName, h.IPv4); err != nil {
		httpx.LogR(r, "DNS SeedDefaults %q error: %v", req.DomainName, err)
	}
	if err := writeDNSZone(r.Context(), h.DB, id); err != nil {
		httpx.LogR(r, "DNS WriteZone %q error: %v", req.DomainName, err)
	}

	// #nosec G118 -- intentional detached context: the request ends before this background cgroup write finishes; the request context would cancel it mid-write.
	go func(domainID int64) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := applyResourceLimits(ctx, h.DB, domainID); err != nil {
			httpx.LogR(r, "resource limit apply after domain creation, domain=%d: %v", domainID, err)
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
	if nameserversConfigured(r.Context(), h.DB) {
		ns1, ns2 := readNameserverPair(r.Context(), h.DB, d.ID, d.DomainName)
		resp.Nameservers = &nameserverPair{NS1: ns1, NS2: ns2}
	}
	httpx.WriteJSON(w, http.StatusCreated, resp)
}

// Delete removes a domain and its panel-managed resources.
func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var domainName, sk string
	var parentDomainID sql.NullInt64
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name, system_user, parent_domain_id FROM domains WHERE id=?`, id).
		Scan(&domainName, &sk, &parentDomainID)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}

	if parentDomainID.Valid {
		h.deleteAddonDomain(w, r, id, sk)
		return
	}

	h.cleanupAddonChildren(r, id)
	siblings := h.tearDownTenant(r, id, domainName, sk)
	if !h.deleteDomainRows(w, r, id) {
		return
	}
	h.afterDomainRowDeleted(r, domainName, siblings)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"deleted": map[string]string{"domain_name": domainName, "system_user": sk},
	})
}

// deleteAddonDomain removes an addon domain through its own cleanup.
func (h *Handlers) deleteAddonDomain(w http.ResponseWriter, r *http.Request, id int64, sk string) {
	deleted, err := cleanupAddonDomain(r.Context(), h.DB, id)
	if err != nil {
		httpx.LogR(r, "addon domain delete warn (%d): %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "addon domain deletion failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"deleted": map[string]string{"domain_name": deleted, "system_user": sk},
	})
}

// cleanupAddonChildren removes every addon domain that answers to this one. A
// child list that cannot be read is skipped, and every other failure is logged.
func (h *Handlers) cleanupAddonChildren(r *http.Request, id int64) {
	childRows, err := h.DB.QueryContext(r.Context(), `SELECT id FROM domains WHERE parent_domain_id=?`, id)
	if err != nil {
		return
	}
	childIDs := make([]int64, 0)
	for childRows.Next() {
		var childID int64
		if err := childRows.Scan(&childID); err != nil {
			httpx.LogR(r, "addon domain cleanup warn (parent=%d): skipping an unreadable child row: %v", id, err)
			continue
		}
		childIDs = append(childIDs, childID)
	}
	if err := childRows.Err(); err != nil {
		// A child missed here keeps its vhost, its certificate paths and its DNS
		// zone after the parent is gone, with no row left to find it from.
		httpx.LogR(r, "addon domain cleanup warn (parent=%d): could not read the child list: %v", id, err)
	}
	_ = childRows.Close()
	for _, childID := range childIDs {
		if _, err := cleanupAddonDomain(r.Context(), h.DB, childID); err != nil {
			httpx.LogR(r, "addon domain cleanup warn (parent=%d, child=%d): %v", id, childID, err)
		}
	}
}

// tearDownTenant removes what the domain holds on the host and in the other
// panel packages, and returns the top-level domains that still share its system
// user.
func (h *Handlers) tearDownTenant(r *http.Request, id int64, domainName, sk string) []int64 {
	// Applications go before the row does: the foreign key removes their records
	// but not their units, environment files or logs, and a unit left behind
	// holds its port out of the allocator's reach for good.
	teardownApps(r.Context(), h.DB, id)
	// Laravel queue workers and the schedule cron are the same shape of
	// artefact and were left behind until now: the unit kept running as a login
	// userdel had just removed, and the cron entry kept trying to run a
	// scheduler in a directory that was gone.
	teardownLaravel(r.Context(), h.DB, id)
	// The generated maintenance page is a host artefact: the foreign key
	// cascade removes the database rows and nothing on disk, so a deleted
	// domain would leave its page behind for good.
	if err := removeMaintenancePage(id); err != nil {
		httpx.LogR(r, "remove maintenance page for domain %d: %v", id, err)
	}

	// Read BEFORE anything is torn down and before the row goes: an upgraded panel
	// can still carry two domains that share one system user, and every teardown
	// below that is named after the user rather than the domain would take the
	// survivor's cgroup limits, cache account and files with it. A failed lookup
	// counts as shared, because the cost of guessing wrong is a live tenant's
	// resources.
	siblings, siblingErr := otherTopLevelDomainsUsing(sk, domainName)
	if siblingErr != nil {
		httpx.LogR(r, "delete %q: cannot tell whether the system user is shared, keeping tenant resources: %v", domainName, siblingErr)
	}
	systemUserShared := siblingErr != nil || len(siblings) > 0

	// Remove the real DBs in MariaDB (CASCADE FK only deletes the panel DB metadata)
	if err := mysqlDropAllForDomain(h.DB, id); err != nil {
		httpx.LogR(r, "mysql drop-all warn (%s): %v", domainName, err)
	}
	// nginx vhost + PHP pool + Linux user. Deprovision asks the same question
	// again for itself, so a caller that never learned about sharing cannot
	// reintroduce the data loss.
	if err := deprovisionTenant(domainName, sk); err != nil {
		httpx.LogR(r, "deprovision warn (%s): %v", domainName, err)
	}
	h.releaseTenantUser(r, id, sk, systemUserShared)
	// Mail metadata uses cascading foreign keys. The hook keeps domain deletion extensible.
	cleanupMailDomain(h.DB, id, sk)
	// NOTE: Preserve /var/backups/servika/<sk>/ intentionally.
	// The customer may have deleted the domain by accident, so backups are kept
	// for recovery. Removing that directory is an operator's decision, taken on
	// the host; the panel has no helper for it.
	return siblings
}

// releaseTenantUser removes what is named after the system user unless another
// domain still answers to it. This domain's Redis row goes either way.
func (h *Handlers) releaseTenantUser(r *http.Request, id int64, sk string, systemUserShared bool) {
	if !systemUserShared {
		if err := deleteSystemdSlice(sk); err != nil {
			httpx.LogR(r, "resource slice cleanup warn (%s): %v", sk, err)
		}
		// The quarantine store lives OUTSIDE the home, so userdel -r never
		// reaches it: the rows go with the foreign key and the files would stay
		// for good, holding a tenant's malware after the tenant is gone.
		if err := removeQuarantineStore(sk); err != nil {
			httpx.LogR(r, "quarantine store cleanup warn (%s): %v", sk, err)
		}
	}
	// Redis tenant cache: Valkey ACL user + WP drop-in + domain_redis row.
	// Since domain_redis has no CASCADE FK, the row was orphaned when the domain was deleted.
	// While the system user is shared, the ACL account belongs to the survivor,
	// so only this domain's row goes.
	if systemUserShared {
		if err := forgetRedisDomain(h.DB, id); err != nil {
			httpx.LogR(r, "redis row cleanup warn (%d): %v", id, err)
		}
	} else if err := closeRedisDomain(h.DB, id, sk); err != nil {
		httpx.LogR(r, "redis close-domain warn (%s): %v", sk, err)
	}
}

// deleteDomainRows removes the rows no foreign key cascades to, and the domain
// row last. It answers the request and reports false when the domain row stays.
func (h *Handlers) deleteDomainRows(w http.ResponseWriter, r *http.Request, id int64) bool {
	// Existing installations may not have foreign keys on the traffic tables.
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM domain_traffic WHERE domain_id=?`, id); err != nil {
		httpx.LogR(r, "domain traffic cleanup warn (%d): %v", id, err)
	}
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM domain_traffic_cursor WHERE domain_id=?`, id); err != nil {
		httpx.LogR(r, "domain traffic cursor cleanup warn (%d): %v", id, err)
	}
	// These domain-owned tables have a domain_id index but no ON DELETE CASCADE, so
	// their rows would be orphaned after the domain is deleted. Remove them explicitly.
	for _, table := range []string{"protected_directories", "av_findings", "av_scans", "subdomains"} {
		// #nosec G202 -- table names come from this fixed literal whitelist, never user input; domain_id is bound.
		if _, err := h.DB.ExecContext(r.Context(),
			"DELETE FROM "+table+" WHERE domain_id=?", id); err != nil {
			httpx.LogR(r, "%s cleanup warn (%d): %v", table, id, err)
		}
	}

	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM domains WHERE id=?`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "domain deletion failed")
		return false
	}
	return true
}

// afterDomainRowDeleted renders the surviving domains' vhosts again and removes
// the DNS zone, both of which have to wait until the row is gone.
func (h *Handlers) afterDomainRowDeleted(r *http.Request, domainName string, siblings []int64) {
	// A shared vhost file is named after the SYSTEM USER, so it still carries the
	// deleted domain in server_name. Render it again from the survivor's own row,
	// AFTER the delete so the table no longer contains the domain that just went.
	for _, otherID := range siblings {
		if err := rerenderVhost(h.DB, otherID); err != nil {
			httpx.LogR(r, "re-render the vhost of domain %d after %q was deleted: %v", otherID, domainName, err)
		}
	}

	// BIND zone cleanup AFTER the DELETE: updateZoneIncludes regenerates zones.conf from the domains
	// table; if the domain were still in the table (old order) the last deleted
	// domain zone include would be rewritten (dangling, named reload error).
	if err := deleteDNSZone(r.Context(), h.DB, domainName); err != nil {
		httpx.LogR(r, "DNS DeleteZone warn (%s): %v", domainName, err)
	}
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
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name, system_user, COALESCE(web_backend,'php-fpm'), COALESCE(cert_path,''), COALESCE(key_path,''), COALESCE(ssl_source,''), COALESCE(web_root,'') FROM domains WHERE id=?`, id).
		Scan(&domainName, &sk, &backend, &certPath, &keyPath, &sslSource, &webRoot)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	socket, err := provisioner.SetPHPVersion(domainName, sk, req.PHPVersion, certPath, keyPath, sslSource, backend, webRoot)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "PHP version change failed")
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
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user FROM domains WHERE id=?`, id).
		Scan(&systemUser)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
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
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name, system_user, php_version FROM domains WHERE id=?`, id).
		Scan(&domainName, &sk, &phpVersion)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
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
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user FROM domains WHERE id=?`, id).
		Scan(&sk)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	// A swallowed Scan error would update the FTP password of the empty system
	// user, which matches no account and still answers 200 with the new
	// password.
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	if sk == "" {
		httpx.WriteError(w, http.StatusInternalServerError, "domain record is incomplete")
		return
	}
	if err := credentials.FTPUpdatePassword(h.DB, sk, req.Password); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "FTP password update failed")
		return
	}
	// If SSH is enabled, sync the system (SSH) password with FTP too
	var sshOn int
	_ = h.DB.QueryRowContext(r.Context(), `SELECT ssh_access FROM domains WHERE id=?`, id).Scan(&sshOn)
	if sshOn == 1 {
		if err := credentials.SyncSSHPassword(h.DB, sk); err != nil {
			// SSH password stayed at its old value; the returned password only works
			// for FTP. Report a degraded result rather than implying SSH is in sync.
			httpx.LogR(r, "ssh password sync warn (%s): %v", sk, err)
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
	Size      int64  `json:"size"` // data+index length in bytes, 0 when unknown
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
			// A dropped row is a database the customer owns and cannot see, so it
			// can be neither opened, nor reset, nor deleted from this screen.
			httpx.LogR(r, "databases: skipping an unreadable account row for domain %d: %v", d.DomainID, err)
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
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	// Fill each database's on-disk size (data+index). This needs root over the
	// unix socket, so it is best-effort: a failure leaves the sizes at 0 rather
	// than failing the list the customer asked for.
	if len(out) > 0 {
		names := make([]string, len(out))
		for i := range out {
			names[i] = out[i].DBName
		}
		if sizes, err := credentials.SchemaSizes(r.Context(), names); err != nil {
			httpx.LogR(r, "database sizes could not be read: %v", err)
		} else {
			for i := range out {
				out[i].Size = sizes[out[i].DBName]
			}
		}
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
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user FROM domains WHERE id=?`, id).
		Scan(&sk)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "domain query failed")
		return
	}
	// Hold a per-customer lock across the quota check AND the database creation below
	// so concurrent requests cannot each pass the count check before either insert
	// lands and exceed the plan limit.
	unlock := lockCustomerForDomain(r.Context(), h.DB, id)
	defer unlock()
	if err := checkDatabaseAllowed(r.Context(), h.DB, id); err != nil {
		if !quotaLimitReached(err) {
			httpx.LogR(r, "database quota check for domain %d: %v", id, err)
		}
		writeQuotaRefusal(w, err, "could not verify plan limit")
		return
	}

	plan, ok := h.planDatabase(w, r, id, sk, req)
	if !ok {
		return
	}

	// Name collision: return a clear 409 instead of a duplicate-key 500.
	var collision int
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM db_accounts WHERE db_name=?`, plan.name).Scan(&collision)
	if collision > 0 {
		httpx.WriteError(w, http.StatusConflict, "A database with this name already exists: "+plan.name)
		return
	}

	if !h.createPlannedDatabase(w, r, id, &plan) {
		return
	}

	// Governor/limits: apply plan limits to the new database user in the background, best-effort.
	// #nosec G118 -- intentional detached context: the request ends before this background cgroup write finishes; the request context would cancel it mid-write.
	go func(domainID int64) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := applyResourceLimits(ctx, h.DB, domainID); err != nil {
			httpx.LogR(r, "resourcelimit apply (db-create) domain=%d: %v", domainID, err)
		}
	}(id)

	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"ok": true, "domain_id": id, "db_name": plan.name, "db_user": plan.user, "db_pass": plan.password,
	})
}

// databasePlan is the database, the user and the password a create request
// resolves to.
type databasePlan struct {
	name, user, password string
	// existingUser is set when the database is opened for a user the domain
	// already holds, whose password is kept.
	existingUser bool
}

// wantsGeneratedDatabase reports whether a request asks for everything to be
// generated. Backward compatible: empty body or Auto=true generates everything
// (legacy behavior).
func wantsGeneratedDatabase(req createDBReq) bool {
	return req.Auto ||
		(req.DBSuffix == "" && req.UserSuffix == "" && req.ExistingUser == "" && req.Password == "")
}

// planDatabase resolves the names and the password a request asks for, and
// answers the request itself when they are not acceptable.
func (h *Handlers) planDatabase(w http.ResponseWriter, r *http.Request, id int64, sk string, req createDBReq) (databasePlan, bool) {
	if wantsGeneratedDatabase(req) {
		name := sk + "_db" + strconv.FormatInt(id, 10)
		return databasePlan{name: name, user: name, password: credentials.RandomPassword(24)}, true
	}
	if req.DBSuffix == "" {
		httpx.WriteError(w, http.StatusBadRequest, "database name suffix is required")
		return databasePlan{}, false
	}
	if !credentials.ValidDBSuffix(req.DBSuffix) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid database suffix (lowercase letters, digits, underscore only; 1-32 characters)")
		return databasePlan{}, false
	}
	plan := databasePlan{name: sk + "_" + req.DBSuffix}
	if !credentials.ValidCustomerDBIdentifier(sk, plan.name) {
		httpx.WriteError(w, http.StatusBadRequest, "database name too long (prefix + suffix must be at most 64 characters)")
		return databasePlan{}, false
	}
	var ok bool
	if req.UserMode == "existing" {
		ok = h.planExistingUser(w, r, id, sk, req, &plan)
	} else { // "new"
		ok = h.planNewUser(w, r, sk, req, &plan)
	}
	return plan, ok
}

// planExistingUser takes a user the domain already holds.
func (h *Handlers) planExistingUser(w http.ResponseWriter, r *http.Request, id int64, sk string, req createDBReq, plan *databasePlan) bool {
	if req.ExistingUser == "" || !credentials.ValidCustomerDBIdentifier(sk, req.ExistingUser) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid existing user")
		return false
	}
	// Ownership: the selected user must actually belong to this domain (prefix guarantee).
	var n int
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM db_accounts WHERE domain_id=? AND db_user=?`, id, req.ExistingUser).Scan(&n)
	if n == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "selected user does not belong to this domain")
		return false
	}
	plan.user = req.ExistingUser
	plan.existingUser = true
	return true
}

// planNewUser names a new user and its password.
func (h *Handlers) planNewUser(w http.ResponseWriter, r *http.Request, sk string, req createDBReq, plan *databasePlan) bool {
	if req.UserSuffix == "" {
		httpx.WriteError(w, http.StatusBadRequest, "user name suffix is required")
		return false
	}
	if !credentials.ValidDBSuffix(req.UserSuffix) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user suffix (lowercase letters, digits, underscore only; 1-32 characters)")
		return false
	}
	plan.user = sk + "_" + req.UserSuffix
	if !credentials.ValidCustomerDBIdentifier(sk, plan.user) {
		httpx.WriteError(w, http.StatusBadRequest, "user name too long (prefix + suffix must be at most 64 characters)")
		return false
	}
	// A new account may not take a name that already exists. The prefix
	// test does not make this impossible: a suffix may contain "_" and
	// provisioner.allocateSystemUser mints c_X_2 on a slug collision, so
	// c_X can spell an account of c_X_2. Creating it would reset that
	// account's password instead of making a new one. A name held by this
	// same domain is refused too, because other databases share it and
	// "existing" mode is what preserves their password.
	var taken int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM db_accounts WHERE db_user=?`, plan.user).Scan(&taken); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database creation failed")
		return false
	}
	if taken > 0 {
		httpx.WriteError(w, http.StatusConflict, "A database user with this name already exists: "+plan.user)
		return false
	}
	return planNewUserPassword(w, req, plan)
}

// planNewUserPassword takes the password the customer chose when it is strong
// enough, or generates one.
func planNewUserPassword(w http.ResponseWriter, req createDBReq, plan *databasePlan) bool {
	if req.Password == "" {
		plan.password = credentials.RandomPassword(24)
		return true
	}
	if ok, reason := credentials.StrongPassword(req.Password); !ok {
		httpx.WriteError(w, http.StatusBadRequest, reason)
		return false
	}
	plan.password = req.Password
	return true
}

// createPlannedDatabase creates the database in MariaDB, for the user the
// domain already holds or with a new one, and answers the request itself when
// that fails.
func (h *Handlers) createPlannedDatabase(w http.ResponseWriter, r *http.Request, id int64, plan *databasePlan) bool {
	if plan.existingUser {
		return h.createForExistingUser(w, r, id, plan)
	}
	if err := mysqlCreateDB(h.DB, id, plan.name, plan.user, plan.password); err != nil {
		if errors.Is(err, credentials.ErrDBUserOwnedByAnotherDomain) {
			httpx.WriteError(w, http.StatusConflict, "A database user with this name already exists: "+plan.user)
			return false
		}
		if errors.Is(err, credentials.ErrInvalidMySQLCredentials) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid database name or user")
			return false
		}
		httpx.WriteError(w, http.StatusInternalServerError, "database creation failed")
		return false
	}
	return true
}

// createForExistingUser opens the database for a user the domain holds, and
// returns that user's stored password with it.
func (h *Handlers) createForExistingUser(w http.ResponseWriter, r *http.Request, id int64, plan *databasePlan) bool {
	if err := mysqlCreateDBForUser(h.DB, id, plan.name, plan.user); err != nil {
		if errors.Is(err, credentials.ErrInvalidMySQLCredentials) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid database name or user")
			return false
		}
		httpx.WriteError(w, http.StatusInternalServerError, "database creation failed")
		return false
	}
	// Surface the existing user's password in the response (the customer already owns it).
	var stored string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT db_pass_plain FROM db_accounts WHERE db_user=? LIMIT 1`, plan.user).Scan(&stored); err == nil {
		if pw, derr := decryptDBPass(plan.user, stored); derr == nil {
			plan.password = pw
		}
	}
	return true
}

func (h *Handlers) DeleteDatabase(w http.ResponseWriter, r *http.Request) {
	dbid, _ := strconv.ParseInt(chi.URLParam(r, "dbid"), 10, 64)
	var dbName, dbUser string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT db.db_name, db.db_user FROM db_accounts db JOIN domains d ON d.id=db.domain_id
		 WHERE db.id=?`, dbid).Scan(&dbName, &dbUser)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "database record not found")
		return
	}
	// A swallowed Scan error would send empty identifiers into the drop path.
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	if dbName == "" || dbUser == "" {
		httpx.WriteError(w, http.StatusInternalServerError, "database record is incomplete")
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

// OptimizeDatabase runs OPTIMIZE TABLE across one schema and reports the on-disk
// size before and after, so the operator sees how much space was reclaimed.
//
// The size is measured on both sides with SchemaSizes rather than trusted from
// OPTIMIZE's own output, which is a per-table status table, not a byte count.
// reclaimed is clamped at zero: OPTIMIZE rebuilds an InnoDB table and can leave
// it marginally larger, which is not a loss to report as a negative saving.
func (h *Handlers) OptimizeDatabase(w http.ResponseWriter, r *http.Request) {
	dbid, _ := strconv.ParseInt(chi.URLParam(r, "dbid"), 10, 64)
	var dbName string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT db.db_name FROM db_accounts db WHERE db.id=?`, dbid).Scan(&dbName)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "database record not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	if dbName == "" {
		httpx.WriteError(w, http.StatusInternalServerError, "database record is incomplete")
		return
	}
	before, err := credentials.SchemaSizes(r.Context(), []string{dbName})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "size read failed")
		return
	}
	if err := credentials.OptimizeDatabase(r.Context(), dbName); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "optimize failed")
		return
	}
	after, err := credentials.SchemaSizes(r.Context(), []string{dbName})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "size read failed")
		return
	}
	beforeBytes, afterBytes := before[dbName], after[dbName]
	reclaimed := max(beforeBytes-afterBytes, 0)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"before_bytes":    beforeBytes,
		"after_bytes":     afterBytes,
		"reclaimed_bytes": reclaimed,
	})
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
	if bulkOwnerRefusedForReseller(w, r, req, clearing) {
		return
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
	sql, args := bulkOwnerStatement(r, req, clearing)
	// #nosec G701 G202 -- scope is a constant fragment from ScopeSQL with a literal alias and placeholders holds only literal "?"; every user value is bound via args.
	res, err := h.DB.ExecContext(r.Context(), sql, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "bulk update failed")
		return
	}
	n, _ := res.RowsAffected()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "updated": n})
}

// bulkOwnerRefusedForReseller answers a reseller that asks for a move it may not
// make.
func bulkOwnerRefusedForReseller(w http.ResponseWriter, r *http.Request, req bulkOwnerReq, clearing bool) bool {
	c := middleware.ClaimsFrom(r)
	if c == nil || c.Role != middleware.RoleReseller {
		return false
	}
	if clearing {
		// Detaching hands the domain to admin, which takes it out of the
		// reseller's own scope permanently. That is a one-way loss the reseller
		// could not undo, so it stays an administrator's decision.
		httpx.WriteError(w, http.StatusForbidden, "a reseller cannot detach a domain from its customer")
		return true
	}
	if !middleware.ResellerOwnsCustomer(r, c.UserID, *req.CustomerID) {
		httpx.WriteError(w, http.StatusForbidden, "no access to this customer")
		return true
	}
	return false
}

// bulkOwnerStatement builds the UPDATE that moves the named domains and their
// addon rows to the new customer, narrowed to the caller's scope.
func bulkOwnerStatement(r *http.Request, req bulkOwnerReq, clearing bool) (string, []any) {
	// Build placeholders for the IN clause.
	placeholders := make([]string, len(req.IDs))
	args := []any{}
	if !clearing {
		args = append(args, *req.CustomerID)
	} else {
		args = append(args, nil)
	}
	idArgs := make([]any, len(req.IDs))
	for i, id := range req.IDs {
		placeholders[i] = "?"
		idArgs[i] = id
	}
	// Bound TWICE: once for d.id, once for d.parent_domain_id. An addon row
	// copied the parent's customer_id AND its system_user and nothing re-derives
	// either, so moving the parent alone leaves a row owned by the PREVIOUS
	// customer whose system_user is the account the new owner now holds, and
	// every CustomerScope handler resolves the tenant from the row the URL names.
	args = append(args, idArgs...)
	args = append(args, idArgs...)
	// The SOURCE domains are narrowed by the query itself, not checked row by
	// row: an id the caller does not own simply matches nothing, so a hand-built
	// request body cannot move somebody else's domain. ScopeSQL returns a whole
	// " WHERE ..." clause and this statement already has one, so its keyword is
	// swapped for AND. Empty for an admin, which leaves the statement unchanged.
	scope, scopeArgs := middleware.ScopeSQL(r, "d")
	scope = strings.Replace(scope, " WHERE ", " AND ", 1)
	args = append(args, scopeArgs...)
	// The two id conditions are bracketed together, or the scope fragment would
	// bind to the second alternative alone and a reseller could move an addon
	// row of a domain they do not own.
	//
	// The id alternative is restricted to a TOP-LEVEL row. A child row carries
	// the parent's system_user, so moving it on its own hands the new owner the
	// parent tenant's home directory, database namespace and backups through
	// that row's id. A child follows its parent through the second alternative
	// and never moves alone.
	idList := strings.Join(placeholders, ",")
	// #nosec G202 -- only literal "?" placeholders and the constant ScopeSQL fragment are joined; all values are bound via args.
	sql := `UPDATE domains d SET d.customer_id=? WHERE ((d.parent_domain_id IS NULL AND d.id IN (` + idList + `)) OR d.parent_domain_id IN (` + idList + `))` + scope
	return sql, args
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
	// The ceiling goes into its OWN column, not into extra_directives. That column
	// is the one the customer's nginx-settings save replaces wholesale, so a plan
	// value written there as text held only until the customer sent one request.
	clientMaxBody := ""
	if clientMaxBodyMB > 0 {
		clientMaxBody = strconv.Itoa(clientMaxBodyMB) + "m"
	}
	extraDirectives := ""
	if strings.TrimSpace(planDirectives) != "" {
		extraDirectives = planDirectives
	}
	if _, err := h.DB.ExecContext(ctx,
		`INSERT INTO nginx_settings(domain_id, subdomain_id, fastcgi_cache, extra_directives, client_max_body)
		 VALUES(?,0,?,?,?)
		 ON DUPLICATE KEY UPDATE fastcgi_cache=VALUES(fastcgi_cache),
		    extra_directives=VALUES(extra_directives), client_max_body=VALUES(client_max_body)`,
		domainID, fastCGICache, extraDirectives, clientMaxBody); err != nil {
		log.Printf("seed nginx_settings (domain=%d): %v", domainID, err)
		return
	}
	socket, err := phpSocketFor(sk, php)
	if err != nil {
		log.Printf("php socket (domain=%d): %v", domainID, err)
		return
	}
	if err := applyVhostForDomain(h.DB, domainID, socket, php); err != nil {
		log.Printf("rerender plan virtual host (domain=%d): %v", domainID, err)
	}
}
