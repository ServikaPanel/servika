// Package geoip keeps a country database on disk and answers which address
// ranges belong to a country.
//
// The data is MaxMind's GeoLite2 Country CSV, which the operator's own account
// downloads. There is no bundled fallback: without credentials the package
// reports that it has nothing, and every caller treats that as "the feature is
// off" rather than as an empty answer, because an empty answer would let a
// customer save a country policy that blocks nobody while the screen says they
// are protected.
package geoip

import (
	"errors"
	"path/filepath"
	"strings"

	"servika/internal/config"
)

const (
	// MaxDownloadBytes bounds the archive as it arrives. The Country CSV
	// edition is a few megabytes; this leaves generous room without letting a
	// wrong URL or a captive portal fill the disk.
	MaxDownloadBytes = 64 << 20
	// MaxUnpackedBytes bounds what the archive is allowed to expand into.
	MaxUnpackedBytes = 512 << 20
	// MaxArchiveEntries bounds how many members the archive may hold. The
	// edition ships a directory plus four files; anything near this is not the
	// archive this package was written for.
	MaxArchiveEntries = 32
	// MaxNetworks bounds how many rows one CSV may contribute. IPv4 and IPv6
	// together are around 700 thousand today.
	MaxNetworks = 4_000_000
)

// ErrNoDatabase is returned when no country database has been downloaded.
var ErrNoDatabase = errors.New("no country database is available")

// ErrNoCredentials is returned when the panel holds no MaxMind account.
var ErrNoCredentials = errors.New("no MaxMind credentials are configured")

// Reason codes. These are contract values a screen renders in its own
// language, never prose.
const (
	ReasonUnavailable      = "geoip_unavailable"
	ReasonCountryUnknown   = "country_unknown"
	ReasonTooManyCountries = "too_many_countries"
	ReasonRateNotAllowed   = "rate_not_allowed"
)

// Data file names under config.GeoIPDir.
//
// The two normalized files are what everything downstream reads. They are
// written whole and renamed into place, so a reader never sees a half-written
// database, and the CSV parsing cost is paid once per download rather than once
// per nginx render.
const (
	ipv4File = "networks-v4.csv"
	ipv6File = "networks-v6.csv"
	metaFile = "build-date"
)

func dataPath(name string) string { return filepath.Join(config.GeoIPDir(), name) }

// NormalizeCountry returns the canonical form of an ISO 3166-1 alpha-2 code, or
// "" when the value is not one.
//
// The check is on SHAPE only. Whether a code exists in the downloaded database
// is a separate question with a separate answer, because a code can be
// perfectly valid and simply absent from the edition on disk.
func NormalizeCountry(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) != 2 {
		return ""
	}
	for index := range 2 {
		if value[index] < 'A' || value[index] > 'Z' {
			return ""
		}
	}
	return value
}
