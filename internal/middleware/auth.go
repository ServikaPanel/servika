package middleware

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"servika/internal/auth"
	"servika/internal/httpx"
	"servika/internal/sessionidle"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
)

var scopeDB *sql.DB

var suspendedDomainLookup = func(ctx context.Context, domainID int64) (bool, error) {
	if scopeDB == nil {
		return false, nil
	}
	// Read through readState so a momentary database failure retries and then
	// falls back to the flag last read for this domain; see dbresilience.go. A
	// suspended domain stays refused on that path too.
	suspended, err := readState(ctx, "suspended:"+strconv.FormatInt(domainID, 10),
		func(ctx context.Context) (int64, error) {
			var flag int64
			err := scopeDB.QueryRowContext(ctx,
				`SELECT COALESCE(suspended,0) FROM domains WHERE id=?`, domainID).
				Scan(&flag)
			return flag, err
		})
	return suspended == 1, err
}

// Init configures the database used to enforce suspended customer scopes.
func Init(db *sql.DB) {
	scopeDB = db
}

// tokenVersionMatches reports whether the token's embedded version still equals
// the identity's current version in the given table. A mismatch means the
// session was revoked (the version was bumped). It fails closed: a real query
// error returns (false, err) so the caller denies access. When scopeDB is unset
// (tests) it accepts, so token-only tests keep working. The table argument is a
// fixed internal literal, never user input.
//
// The read goes through readState, which retries a transient failure and then
// falls back to the version last read for this identity; see dbresilience.go.
// A bumped version is refused from that fallback exactly as it is from the
// database, because the fallback replays an answer rather than granting one.
func tokenVersionMatches(ctx context.Context, table string, id, claimVersion int64) (bool, error) {
	if scopeDB == nil {
		return true, nil
	}
	current, err := readState(ctx, "token_version:"+table+":"+strconv.FormatInt(id, 10),
		func(ctx context.Context) (int64, error) {
			var version int64
			err := scopeDB.QueryRowContext(ctx,
				"SELECT token_version FROM "+table+" WHERE id=?", id).Scan(&version)
			return version, err
		})
	if err != nil {
		return false, err
	}
	return current == claimVersion, nil
}

// RequireAuth validates the session token and stores the claims in the request
// context.
//
// There is a single token type (auth.Claims); the role distinction lives in the
// Role claim. A customer-only second token type (auth.CustomerClaims) was
// removed: it embedded the scope in the token, whereas authorization is now
// resolved from the ownership chain on every request.
func RequireAuth(secret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The session JWT is carried only by the HttpOnly servika_session
			// cookie; it is never read from the Authorization header so a stolen
			// bearer value (e.g. from JS/localStorage) cannot be replayed.
			ck, err := r.Cookie(httpx.SessionCookie)
			if err != nil || ck.Value == "" {
				httpx.WriteError(w, http.StatusUnauthorized, "authorization required")
				return
			}
			tokenRaw := ck.Value
			if len(tokenRaw) > 8192 {
				httpx.WriteError(w, http.StatusUnauthorized, "invalid session")
				return
			}

			c, err := auth.Parse(secret, tokenRaw)
			if err != nil {
				httpx.WriteError(w, http.StatusUnauthorized, "invalid session")
				return
			}
			ok, verr := tokenVersionMatches(r.Context(), "users", c.UserID, c.TokenVersion)
			if verr != nil {
				// 503, not 500: the session may well be valid, the panel just
				// cannot say so at this moment. The client is being told to come
				// back, not that its request was wrong.
				httpx.WriteError(w, http.StatusServiceUnavailable, "could not verify session")
				return
			}
			if !ok {
				httpx.WriteError(w, http.StatusUnauthorized, "session has been revoked")
				return
			}
			// The idle timeout runs AFTER the revocation check, because the two
			// answer different questions and only the first is a security
			// boundary. It also FAILS OPEN, which is the opposite of every
			// other check here and is deliberate: an idle limit is a policy, so
			// a database outage that signed every operator out at once would
			// remove the people who fix it while protecting nothing that
			// token_version, which fails closed, does not already protect. The
			// failure is logged rather than swallowed.
			switch expired, err := sessionidle.Enforce(r.Context(), scopeDB, c.UserID); {
			case err != nil:
				sessionidle.Complain(err)
			case expired:
				httpx.WriteError(w, http.StatusUnauthorized, "session expired after inactivity")
				return
			}
			ctx := auth.WithClaims(r.Context(), c)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole restricts access to administrators with an allowed role.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := map[string]bool{}
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := ClaimsFrom(r)
			if c == nil || !allowed[c.Role] {
				httpx.WriteError(w, http.StatusForbidden, "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Role constants — one-to-one with users.role ENUM('admin','reseller','user').
const (
	RoleAdmin    = "admin"
	RoleReseller = "reseller"
	RoleUser     = "user"
)

// AdminOnly accepts only role=admin and returns 403 otherwise.
//
// SECURITY: this used to check only whether an admin-type token existed
// (ClaimsFrom(r) == nil) and never read the role. That was harmless while a
// single token type was issued (root → role=admin), but the moment reseller
// accounts are given an auth.Claims token, all 87 admin endpoints — firewall,
// service restart, package installation included — would open to that reseller.
// The role check is a PRECONDITION for multi-user support, not a later refinement.
func AdminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := ClaimsFrom(r)
		if c == nil || c.Role != RoleAdmin {
			httpx.WriteError(w, http.StatusForbidden, "administrator access required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ResellerOrAbove accepts role=admin or role=reseller.
//
// Used on two kinds of endpoint:
//   - Account operations (domain, customer, DNS, SSL...) where the reseller acts
//     within ITS OWN scope; the scope narrowing is applied separately via
//     DomainOwnedBy/ScopeSQL — this middleware answers only "is the role enough".
//   - Read-only server information (service status, load, version) visible so a
//     reseller can offer support, while every mutating endpoint stays AdminOnly.
func ResellerOrAbove(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := ClaimsFrom(r)
		if c == nil || (c.Role != RoleAdmin && c.Role != RoleReseller) {
			httpx.WriteError(w, http.StatusForbidden, "insufficient permissions")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CustomerScope requires the URL domain ID to match the customer token domain ID.
// Administrators are unrestricted. Use CustomerScopeParam for a parameter other than "id".
func CustomerScope(next http.Handler) http.Handler {
	return CustomerScopeParam("id")(next)
}

func CustomerScopeParam(param string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// SECURITY: this used to be a bare "ClaimsFrom(r) != nil", so EVERY
			// token carrying auth.Claims was treated as admin and skipped the
			// scope check. Reseller tokens are auth.Claims too, so that meant
			// unscoped access to all 141 customer-scoped endpoints — the
			// wider-surface twin of the same bug in AdminOnly.
			if c := ClaimsFrom(r); c != nil {
				switch c.Role {
				case RoleAdmin:
					next.ServeHTTP(w, r) // Administrator: all domains.
					return
				case RoleReseller:
					urlID, _ := strconv.ParseInt(chi.URLParam(r, param), 10, 64)
					if !ResellerOwnsDomain(r, c.UserID, urlID) {
						httpx.WriteError(w, http.StatusForbidden, "access to this domain is forbidden")
						return
					}
					next.ServeHTTP(w, r)
					return
				case RoleUser:
					// A customer may own several domains, so the scope is
					// resolved from the ownership chain, not the token.
					urlID, _ := strconv.ParseInt(chi.URLParam(r, param), 10, 64)
					if !CustomerUserOwnsDomain(r, c.UserID, urlID) {
						httpx.WriteError(w, http.StatusForbidden, "access to this domain is forbidden")
						return
					}
					suspended, err := suspendedDomainLookup(r.Context(), urlID)
					if err != nil {
						httpx.WriteError(w, http.StatusServiceUnavailable, "could not verify account status")
						return
					}
					if suspended {
						httpx.WriteError(w, http.StatusForbidden, "account is suspended")
						return
					}
					next.ServeHTTP(w, r)
					return
				default:
					httpx.WriteError(w, http.StatusForbidden, "access to this domain is forbidden")
					return
				}
			}
			httpx.WriteError(w, http.StatusUnauthorized, "authorization required")
		})
	}
}

// RequestIDHeader echoes the chi RequestID from the request context into the
// X-Request-Id response header, so every response (including error responses that
// use httpx.WriteError) carries a correlation ID without touching each call site.
// Mount it after chimw.RequestID, which populates the context value.
func RequestIDHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := chimw.GetReqID(r.Context()); id != "" {
			w.Header().Set("X-Request-Id", id)
		}
		next.ServeHTTP(w, r)
	})
}

// DomainOwnedBy reports whether the authenticated identity may access a domain.
//   - Admin token    => always true (accesses every domain).
//   - Reseller token => true when the domain belongs to a customer the reseller manages.
//   - Customer token => true when the domain belongs to a customer record bound to the account.
//   - No identity     => false.
//
// This is the in-handler counterpart of CustomerScope: on endpoints whose URL
// carries no {id} domain param (e.g. a derived resource like {dbId}), ownership
// is verified with this function after the resource's domain_id is resolved from
// the database.
func DomainOwnedBy(r *http.Request, domainID int64) bool {
	c := ClaimsFrom(r)
	if c == nil {
		return false
	}
	switch c.Role {
	case RoleAdmin:
		return true // Administrator: accesses every domain.
	case RoleReseller:
		return ResellerOwnsDomain(r, c.UserID, domainID)
	case RoleUser:
		return CustomerUserOwnsDomain(r, c.UserID, domainID)
	}
	return false
}

// ResellerOwnsDomain reports whether a domain belongs to a customer managed by
// the given reseller.
//
// The ownership chain is resolved in one place: domains.customer_id ->
// customers.owner_user_id. The authorization decision is always read from the
// database, never from a list embedded in the token — when a reseller loses or
// transfers a customer, its old token must become invalid immediately.
//
// FAIL-CLOSED: returns false (access denied) when the database cannot be read.
func ResellerOwnsDomain(r *http.Request, resellerUserID, domainID int64) bool {
	if scopeDB == nil || resellerUserID <= 0 {
		return false
	}
	var n int
	err := scopeDB.QueryRowContext(r.Context(), `
		SELECT COUNT(*)
		FROM domains d
		JOIN customers c ON c.id = d.customer_id
		WHERE d.id = ? AND c.owner_user_id = ?`, domainID, resellerUserID).Scan(&n)
	return err == nil && n > 0
}

// CustomerUserOwnsDomain reports whether a domain belongs to the given CUSTOMER
// account.
//
// Chain: users.id -> customers.user_id -> domains.customer_id. A customer may
// own SEVERAL domains and ownership can change, so the scope is not embedded in
// the token; it is resolved from the chain on every request.
//
// FAIL-CLOSED: returns false when the database cannot be read.
func CustomerUserOwnsDomain(r *http.Request, userID, domainID int64) bool {
	if scopeDB == nil || userID <= 0 {
		return false
	}
	var n int
	err := scopeDB.QueryRowContext(r.Context(), `
		SELECT COUNT(*)
		FROM domains d
		JOIN customers c ON c.id = d.customer_id
		WHERE d.id = ? AND c.user_id = ?`, domainID, userID).Scan(&n)
	return err == nil && n > 0
}

// ResellerOwnsCustomer reports whether a customer record belongs to the given
// reseller (for endpoints operating on customers directly, without going through
// the domain chain).
func ResellerOwnsCustomer(r *http.Request, resellerUserID, customerID int64) bool {
	if scopeDB == nil || resellerUserID <= 0 {
		return false
	}
	var n int
	err := scopeDB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM customers WHERE id = ? AND owner_user_id = ?`,
		customerID, resellerUserID).Scan(&n)
	return err == nil && n > 0
}

// ScopeSQL produces the WHERE fragment and argument for list endpoints.
//
// On list endpoints verifying ownership row by row does not work — the query
// itself must be narrowed, otherwise a reseller receives a list showing ALL
// records. Usage:
//
//	cond, arg := middleware.ScopeSQL(r, "d")
//	query := "SELECT ... FROM domains d " + cond
//
// Returns an empty string for admins (no narrowing). Resellers and customers
// both narrow through the customers table over the SAME ownership chain; only
// the matched column differs (owner_user_id / user_id). An anonymous request
// returns a condition that matches no row (fail-closed).
//
// The RoleUser branch is not optional: a customer signed in with a panel
// account carries auth.Claims like everyone else, so without it the switch
// would fall through to WHERE 1 = 0 and every scoped list endpoint would return
// empty for that customer.
func ScopeSQL(r *http.Request, domainAlias string) (string, []any) {
	cond, args, unrestricted := ScopeCondition(r, domainAlias)
	if unrestricted {
		return "", nil
	}
	return " WHERE " + cond, args
}

// ScopeCondition is the same narrowing as a bare CONDITION, so a caller that
// already has a WHERE clause can AND it in.
//
// Some tables are not narrowed by ownership alone. A notification with a NULL
// domain_id is panel-wide and belongs to admins only, which no ownership
// condition can express, so that query needs its own clause beside this one and
// cannot use ScopeSQL. Writing the ownership SQL a second time is how the two
// copies drift, so ScopeSQL is built on this and the chain exists once.
//
// The third return value says the caller is unrestricted (admin). It is a bool
// rather than a sentinel string, because comparing the returned SQL to decide
// that would break the moment the text is reworded.
func ScopeCondition(r *http.Request, domainAlias string) (string, []any, bool) {
	c := ClaimsFrom(r)
	if c == nil {
		return "1 = 0", nil, false
	}
	switch c.Role {
	case RoleAdmin:
		return "1 = 1", nil, true
	case RoleReseller:
		return "EXISTS (SELECT 1 FROM customers sc WHERE sc.id = " +
			domainAlias + ".customer_id AND sc.owner_user_id = ?)", []any{c.UserID}, false
	case RoleUser:
		return "EXISTS (SELECT 1 FROM customers sc WHERE sc.id = " +
			domainAlias + ".customer_id AND sc.user_id = ?)", []any{c.UserID}, false
	}
	return "1 = 0", nil, false
}

// EnforceCustomerNotSuspended applies the same suspended-domain gate as CustomerScope
// for handlers that cannot use the CustomerScope middleware because their route is not
// keyed by the "id" parameter (for example the pma-token route keyed by dbId).
//
// Only end customers (role=user) are subject to suspension, mirroring the RoleUser
// branch of CustomerScope; admins and resellers bypass it. The role must be read
// explicitly: every authenticated identity now carries auth.Claims, so a bare
// "ClaimsFrom(r) != nil" would bypass the check for customers too and let a
// suspended customer mint a phpMyAdmin signon token. It writes the HTTP error and
// returns false when access must be denied; callers must stop on false.
func EnforceCustomerNotSuspended(w http.ResponseWriter, r *http.Request, domainID int64) bool {
	c := ClaimsFrom(r)
	if c == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "authorization required")
		return false
	}
	if c.Role != RoleUser {
		return true // Admin/reseller are not subject to end-customer suspension.
	}
	suspended, err := suspendedDomainLookup(r.Context(), domainID)
	if err != nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "could not verify account status")
		return false
	}
	if suspended {
		httpx.WriteError(w, http.StatusForbidden, "account is suspended")
		return false
	}
	return true
}

func ClaimsFrom(r *http.Request) *auth.Claims {
	return auth.ClaimsFromContext(r.Context())
}
