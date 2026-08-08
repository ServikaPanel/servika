package geoip

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"os"
	"slices"
	"sort"
	"strings"
)

// Ranges holds the address ranges of the countries a caller asked for, split by
// family because the two consumers need them apart: nftables takes one set per
// family, and nginx takes both in one geo block.
type Ranges struct {
	V4 []Network
	V6 []Network
}

// Network is one CIDR and the country it belongs to.
type Network struct {
	CIDR    string
	Country string
}

// Available reports whether a country database has been downloaded.
//
// It is checked before a policy is SAVED, not only before one is rendered: a
// country policy stored with no ranges behind it blocks nobody while the screen
// says the site is protected, which is worse than refusing the save.
func Available() bool {
	info, err := os.Stat(dataPath(ipv4File))
	return err == nil && info.Size() > 0
}

// BuildDate returns the edition date of the database on disk.
func BuildDate() string {
	body, err := os.ReadFile(dataPath(metaFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

// Countries returns every ISO code present in the database, sorted.
func Countries() ([]string, error) {
	seen := make(map[string]bool, 512)
	for _, name := range []string{ipv4File, ipv6File} {
		if err := scanNetworks(name, func(_, country string) bool {
			seen[country] = true
			return true
		}); err != nil {
			// The IPv6 file may legitimately be missing on a partial download;
			// the IPv4 one is what decides whether there is a database at all.
			if name == ipv4File {
				return nil, err
			}
		}
	}
	if len(seen) == 0 {
		return nil, ErrNoDatabase
	}
	codes := make([]string, 0, len(seen))
	for code := range seen {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	return codes, nil
}

// Lookup returns the ranges belonging to the given countries.
//
// The whole file is scanned once for the whole set rather than once per
// country: the caller always wants a union, and the files are read on a render
// or a firewall rebuild, both of which are already the slow path.
func Lookup(codes []string) (Ranges, error) {
	wanted := make(map[string]bool, len(codes))
	for _, code := range codes {
		if normalized := NormalizeCountry(code); normalized != "" {
			wanted[normalized] = true
		}
	}
	var ranges Ranges
	if len(wanted) == 0 {
		return ranges, nil
	}
	if !Available() {
		return ranges, ErrNoDatabase
	}
	if err := scanNetworks(ipv4File, func(cidr, country string) bool {
		if wanted[country] {
			ranges.V4 = append(ranges.V4, Network{CIDR: cidr, Country: country})
		}
		return true
	}); err != nil {
		return Ranges{}, err
	}
	// A missing IPv6 file leaves V6 empty rather than failing the whole lookup:
	// blocking a country's IPv4 space is still what the operator asked for, and
	// the screen reports which families the database carries.
	_ = scanNetworks(ipv6File, func(cidr, country string) bool {
		if wanted[country] {
			ranges.V6 = append(ranges.V6, Network{CIDR: cidr, Country: country})
		}
		return true
	})
	return ranges, nil
}

// scanNetworks walks a normalized file, calling visit for each row.
func scanNetworks(name string, visit func(cidr, country string) bool) error {
	// #nosec G304 -- fixed system data path built from config.GeoIPDir and a package constant, never from request input.
	file, err := os.Open(dataPath(name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNoDatabase
		}
		return err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		comma := strings.IndexByte(line, ',')
		if comma <= 0 || comma+1 >= len(line) {
			continue
		}
		if !visit(line[:comma], line[comma+1:]) {
			return nil
		}
	}
	return scanner.Err()
}

// Status is what a screen needs to explain the feature's state.
type Status struct {
	// Configured reports whether MaxMind credentials are stored. The key
	// itself is never returned.
	Configured bool   `json:"configured"`
	AccountID  string `json:"account_id,omitempty"`
	// Available reports whether a database has actually been downloaded.
	Available bool   `json:"available"`
	BuildDate string `json:"build_date,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
	LastError string `json:"last_error,omitempty"`
	// Countries is every ISO code the database carries, so a screen can offer
	// exactly what can be blocked rather than a hardcoded list.
	Countries []string `json:"countries"`
	// IPv6 reports whether the database carries IPv6 ranges, because a country
	// blocked without them is only half blocked.
	IPv6 bool `json:"ipv6"`
}

// ReadStatus reports the state of the country database.
func ReadStatus(ctx context.Context, db *sql.DB) (Status, error) {
	var status Status
	var accountID, buildDate, lastError string
	var updatedAt sql.NullString
	var sealed sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(maxmind_account_id,''), maxmind_license_key,
		        COALESCE(geoip_build_date,''), COALESCE(geoip_last_error,''),
		        DATE_FORMAT(geoip_updated_at, '%Y-%m-%d %H:%i')
		   FROM panel_settings WHERE id=1`).
		Scan(&accountID, &sealed, &buildDate, &lastError, &updatedAt)
	if err != nil {
		return status, err
	}
	status.AccountID = strings.TrimSpace(accountID)
	status.Configured = status.AccountID != "" && sealed.Valid && strings.TrimSpace(sealed.String) != ""
	status.BuildDate = buildDate
	status.LastError = lastError
	status.UpdatedAt = updatedAt.String
	status.Available = Available()
	status.Countries = []string{}
	if status.Available {
		if codes, err := Countries(); err == nil {
			status.Countries = codes
		}
		if info, err := os.Stat(dataPath(ipv6File)); err == nil && info.Size() > 0 {
			status.IPv6 = true
		}
	}
	// The date on disk is what the ranges actually came from. A row saying
	// otherwise means an update failed after the files were replaced, and the
	// file wins because that is what is being enforced.
	if onDisk := BuildDate(); onDisk != "" {
		status.BuildDate = onDisk
	}
	return status, nil
}

// KnownCountry reports whether a code is present in the database on disk.
func KnownCountry(code string) bool {
	normalized := NormalizeCountry(code)
	if normalized == "" {
		return false
	}
	codes, err := Countries()
	if err != nil {
		return false
	}
	return slices.Contains(codes, normalized)
}
