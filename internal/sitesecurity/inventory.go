package sitesecurity

import (
	"context"
	"strings"
)

// Inventory is one installation the sweep looked at.
//
// It is recorded whether or not anything was found, and a Findings of 0 is the
// valuable case. security_findings records a vulnerability and nothing at all
// about a clean installation, so without this the screen drew one empty list
// for "every site is clean" and for "the sweep never ran", and a silent failure
// read as reassurance.
type Inventory struct {
	AppType     string
	InstallPath string
	Version     string
	Packages    int
	Findings    int
}

// installKey identifies an installation within one domain. The separator is a
// NUL byte, which cannot appear in either half, so no two different pairs can
// produce one key by running together; findingKey uses the same separator for
// the same reason.
func installKey(appType, installPath string) string {
	return appType + "\x00" + installPath
}

// recordInventory writes what one domain's sweep looked at.
//
// complete says the domain's whole sweep reported no error. Rows are written
// either way, because a record of what was inspected is worth having from a
// partial pass too, but stale rows are only PRUNED when the pass was complete:
// a WordPress installation missed because wp-cli failed once must not be
// reported as removed, which would put the domain back into the "never scanned"
// list and say the opposite of what happened.
//
// The prune is by identity, never by timestamp. A cutoff would have to be
// compared against last_scanned, which is written by NOW() on the server clock
// while a Go time.Time reaches the driver as UTC, so the two are wrong by the
// session offset. Naming the installations that survive needs no clock at all.
func (c *Collector) recordInventory(ctx context.Context, domainID int64, apps []Inventory, complete bool) error {
	// Truncate once, so the value written and the value the prune protects are
	// the same string. Truncating separately would let the prune delete the row
	// the insert above it had just written.
	kept := make([]Inventory, 0, len(apps))
	for _, app := range apps {
		app.InstallPath = truncate(app.InstallPath, 512)
		app.Version = truncate(app.Version, 64)
		kept = append(kept, app)
	}

	for _, app := range kept {
		if _, err := c.DB.ExecContext(ctx,
			`INSERT INTO security_apps
			   (domain_id, app_type, install_path, app_version, package_count, finding_count)
			 VALUES (?,?,?,?,?,?)
			 ON DUPLICATE KEY UPDATE
			   app_version=VALUES(app_version), package_count=VALUES(package_count),
			   finding_count=VALUES(finding_count), last_scanned=NOW()`,
			domainID, app.AppType, app.InstallPath, app.Version,
			app.Packages, app.Findings); err != nil {
			return err
		}
	}
	if !complete {
		return nil
	}

	query := `DELETE FROM security_apps WHERE domain_id = ?`
	args := []any{domainID}
	if len(kept) > 0 {
		pairs := make([]string, 0, len(kept))
		for _, app := range kept {
			pairs = append(pairs, "(?,?)")
			args = append(args, app.AppType, app.InstallPath)
		}
		// #nosec G201 G202 -- only the literal string "(?,?)" is joined; every value is bound through args.
		query += ` AND (app_type, install_path) NOT IN (` + strings.Join(pairs, ",") + `)`
	}
	// #nosec G201 G202 -- see above: the statement is built from literal placeholders only.
	_, err := c.DB.ExecContext(ctx, query, args...)
	return err
}
