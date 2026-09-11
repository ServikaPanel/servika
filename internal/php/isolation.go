package php

import (
	"context"
	"database/sql"
	"net/http"

	"servika/internal/middleware"
)

// isolationFields are the settings whose ini key the panel already refuses in
// the free-text extra_directives box, and which also exist as dedicated fields
// of the same request body.
//
// The two input paths contradicted each other. A directive line overriding
// open_basedir was refused with "extra directive line 1 cannot override
// open_basedir", while the same value sent as the open_basedir FIELD of the
// same request was accepted and rendered into the pool as a php_admin_value.
// Only disable_functions carried the role guard, described in its own comment
// as "an ISOLATION control, so only an admin may change it"; the reason applies
// word for word to the other four.
//
// Each entry names the settings field and the ini key it renders as, so the
// test that compares this set against prohibitedExtraDirectives can do so by
// key rather than by eye.
var isolationFields = []struct {
	// column is the php_settings column the stored value is read back from.
	column string
	// iniKey is the directive this field becomes in the pool.
	iniKey string
	// get and set reach the field on a Settings value.
	get func(*Settings) string
	set func(*Settings, string)
}{
	{
		column: "disable_functions", iniKey: "disable_functions",
		get: func(s *Settings) string { return s.DisableFunctions },
		set: func(s *Settings, v string) { s.DisableFunctions = v },
	},
	{
		column: "open_basedir", iniKey: "open_basedir",
		get: func(s *Settings) string { return s.OpenBasedir },
		set: func(s *Settings, v string) { s.OpenBasedir = v },
	},
	{
		column: "include_path", iniKey: "include_path",
		get: func(s *Settings) string { return s.IncludePath },
		set: func(s *Settings, v string) { s.IncludePath = v },
	},
	{
		column: "session_save_path", iniKey: "session.save_path",
		get: func(s *Settings) string { return s.SessionSavePath },
		set: func(s *Settings, v string) { s.SessionSavePath = v },
	},
	{
		column: "mail_force_extra_parameters", iniKey: "mail.force_extra_parameters",
		get: func(s *Settings) string { return s.MailForceExtraParameters },
		set: func(s *Settings, v string) { s.MailForceExtraParameters = v },
	},
}

// keepIsolationFields discards a non-admin's value for every isolation field and
// puts back the stored one, or the hardened default when no row exists yet.
//
// It runs BEFORE validation, so a non-admin's value is never even checked, and
// it fails closed: a missing claim is treated as non-admin. An admin's request
// passes through untouched.
//
// The effect of the gap it closes was bounded but real. A domain on the SHARED
// php-fpm master takes open_basedir from this row, so a customer could set it to
// "/" and remove the only thing keeping their PHP inside their home. A domain
// with its own tenant master was never affected, because that renderer hardcodes
// these values and never reads them from here.
func keepIsolationFields(ctx context.Context, db *sql.DB, r *http.Request, domainID, subdomainID int64, s *Settings) {
	if claims := middleware.ClaimsFrom(r); claims != nil && claims.Role == middleware.RoleAdmin {
		return
	}
	defaults := Defaults()
	for _, field := range isolationFields {
		var current sql.NullString
		// #nosec G202 -- the column name comes from the fixed table above, never from a request.
		_ = db.QueryRowContext(ctx,
			`SELECT `+field.column+` FROM php_settings WHERE domain_id=? AND subdomain_id=?`,
			domainID, subdomainID).Scan(&current)
		if current.Valid {
			field.set(s, current.String)
			continue
		}
		field.set(s, field.get(&defaults))
	}
}
