package platform

// Which Windows services this panel may see and touch, and how the host's
// resource snapshot is read.
//
// THE ALLOWLIST IS THE WHOLE POINT. An operator here manages a web, database,
// DNS and FTP stack, and nothing else. Stopping an arbitrary Windows service
// breaks the machine: RpcSs, LSASS and Winlogon carry half the system between
// them. Both the listing AND the action are limited to a fixed set, so the
// boundary lives in code rather than in an intention.
//
// This file carries no build tag so the allowlist and the decoding are measured
// on every build. The PowerShell calls live in winservice_windows.go.

import (
	"fmt"
	"strings"
)

// serviceAllowlist is the only set of services the panel can see or drive.
//
//	W3SVC, WAS        the IIS core: publishing and process activation
//	MSSQLSERVER       the SQL Server default instance
//	SQLBrowser        the SQL Server browser
//	ftpsvc            the IIS FTP service
//	DNS               the DNS Server role
//	MySQL80, MySQL    the MySQL service name changes between versions
//	postgresql-x64-16 PostgreSQL 16
//
// A service that is not installed simply does not appear. A name outside this
// list is never acted on.
var serviceAllowlist = []string{
	"W3SVC", "WAS", "MSSQLSERVER", "SQLBrowser", "ftpsvc",
	"DNS", "MySQL80", "MySQL", "postgresql-x64-16",
}

// serviceActions are the only things that may be done to one, mapped to the
// state each must reach for the action to have worked.
var serviceActions = map[string]string{
	"start":   "Running",
	"stop":    "Stopped",
	"restart": "Running",
}

// ServiceView is one row of the service listing.
type ServiceView struct {
	Name        string
	DisplayName string
	State       string
	StartType   string
}

// MemoryView is the host's memory use.
type MemoryView struct {
	Percent float64 `json:"percent"`
	TotalMB float64 `json:"total_mb"`
	UsedMB  float64 `json:"used_mb"`
}

// DiskView is one local fixed disk.
type DiskView struct {
	Drive   string
	Percent float64
	TotalGB float64
	FreeGB  float64
}

// ResourceView is the host's resource snapshot.
type ResourceView struct {
	CPUPercent float64    `json:"cpu_percent"`
	Memory     MemoryView `json:"memory"`
	Disks      []DiskView `json:"disks"`
}

// canonicalService returns the allowlist's own spelling of a name, or "" when
// the name is not on it. Windows service names are case-insensitive, so the
// comparison is too.
//
// The CANONICAL name is what reaches a command, never the caller's echo of it.
func canonicalService(name string) string {
	name = strings.TrimSpace(name)
	for _, allowed := range serviceAllowlist {
		if strings.EqualFold(allowed, name) {
			return allowed
		}
	}
	return ""
}

// targetState returns the state an action has to reach, and refuses an action
// that is not one of the three.
func targetState(action string) (string, error) {
	state, ok := serviceActions[action]
	if !ok {
		return "", fmt.Errorf("action %q is not start, stop or restart: %w", action, ErrInvalidRequest)
	}
	return state, nil
}

// quotedAllowlist renders the allowlist as PowerShell arguments. The names are
// generated from the list itself rather than written twice, so the query and the
// gate can never drift apart. Every name is letters, digits and hyphens, so it
// sits safely inside single quotes.
func quotedAllowlist() string {
	quoted := make([]string, len(serviceAllowlist))
	for i, name := range serviceAllowlist {
		quoted[i] = "'" + name + "'"
	}
	return strings.Join(quoted, ",")
}

// parseServices reads the service query's answer.
func parseServices(out []byte) ([]ServiceView, error) {
	list, err := decodeRecords[ServiceView](out)
	if err != nil {
		return nil, err
	}
	if list == nil {
		return []ServiceView{}, nil
	}
	return list, nil
}
