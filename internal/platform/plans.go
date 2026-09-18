package platform

// Hosting plans for the Windows agent: a disk quota plus IIS limits, saved as a
// preset and assigned to a site. This is the Windows counterpart of the panel's
// hosting package.
//
// TWO DIFFERENT ENGINES SIT BEHIND ONE PLAN:
//
//   - The IIS limits (connections, bandwidth, CPU, memory) are applied with
//     appcmd to the site and its application pool. IIS is present on every host
//     that runs this provider at all, so they ALWAYS apply.
//   - The disk quota is applied with FSRM, the File Server Resource Manager.
//     FSRM is an optional server feature and most installations do not have it.
//     When it is missing the quota is NOT applied and that is reported plainly.
//     Reporting "quota active" when nothing enforces it is a false assurance,
//     and an operator would size a disk against it.
//
// This file holds the store and the limit arithmetic, with no build tag, so
// both are measured on every build. Applying them to a host lives in
// plans_windows.go.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// iisUnlimited is the largest value IIS accepts for a limit, and what it means
// by "no limit": the maximum of an unsigned 32-bit integer.
const iisUnlimited int64 = 4294967295

// planNamePattern is what a plan may be called: 1 to 40 letters, digits, spaces,
// underscores or hyphens. The name becomes a JSON assignment key, so control
// characters and escapes are kept out.
var planNamePattern = regexp.MustCompile(`^[\p{L}0-9 _-]{1,40}$`)

// Plan is one hosting plan. EVERY LIMIT TREATS 0 AS UNLIMITED.
type Plan struct {
	Name         string `json:"name"`
	DiskQuotaMB  int64  `json:"diskQuotaMB"`
	MaxConns     int64  `json:"maxConnections"`
	MaxBandwidth int64  `json:"maxBandwidthKBs"`
	CPUPercent   int    `json:"cpuPercent"`
	MemoryMB     int64  `json:"memoryMB"`
}

// planFile is the file's shape: the plans, and which site carries which.
type planFile struct {
	Plans       []Plan            `json:"plans"`
	Assignments map[string]string `json:"assignments"` // site domain -> plan name
}

// PlanStatus is what the agent answers for the plans screen.
type PlanStatus struct {
	Plans       []Plan            `json:"plans"`
	Assignments map[string]string `json:"assignments"`
	QuotaEngine bool              `json:"quotaEngine"` // is FSRM installed
}

// AssignResult reports what actually happened.
//
// The limits and the quota are reported SEPARATELY, because one can land while
// the other does not: IIS always accepts limits, FSRM may not be installed at
// all. One combined "ok" would hide exactly the case that matters.
type AssignResult struct {
	Site      string   `json:"site"`
	Plan      string   `json:"plan"`
	LimitsSet bool     `json:"limitsSet"`
	QuotaSet  bool     `json:"quotaSet"`
	QuotaNote string   `json:"quotaNote"`
	Warnings  []string `json:"warnings"`
}

// PlanStore is the JSON file holding the plans and their assignments.
type PlanStore struct{ Path string }

// connectionLimit turns a plan's connection limit into what IIS wants. 0 means
// unlimited, and a value over the IIS maximum is clamped rather than refused:
// appcmd answers a hard error on an out-of-range number.
func connectionLimit(max int64) int64 {
	if max <= 0 || max > iisUnlimited {
		return iisUnlimited
	}
	return max
}

// bandwidthBytes turns a plan's bandwidth into what IIS wants. The plan holds
// KB per second and IIS wants BYTES per second.
func bandwidthBytes(kbs int64) int64 {
	if kbs <= 0 {
		return iisUnlimited
	}
	if kbs > iisUnlimited/1024 {
		return iisUnlimited
	}
	return kbs * 1024
}

// cpuThrottle turns a plan's CPU percentage into the pair appcmd wants. The
// unit is a THOUSANDTH of a percent, so 20% is 20000, and 0 has to switch the
// action off rather than throttle to nothing.
func cpuThrottle(percent int) (limit int, action string) {
	if percent <= 0 {
		return 0, "NoAction"
	}
	return percent * 1000, "Throttle"
}

// memoryKB turns a plan's memory limit into the kilobytes appcmd wants, where 0
// turns the periodic private-memory recycle off.
func memoryKB(mb int64) int64 {
	if mb <= 0 {
		return 0
	}
	return mb * 1024
}

// validatePlan refuses a plan this store will not carry.
func validatePlan(p Plan) error {
	if !planNamePattern.MatchString(strings.TrimSpace(p.Name)) {
		return fmt.Errorf("a plan name is 1 to 40 letters, digits, spaces, underscores or hyphens: %w", ErrInvalidRequest)
	}
	if p.DiskQuotaMB < 0 || p.MaxConns < 0 || p.MaxBandwidth < 0 || p.MemoryMB < 0 {
		return fmt.Errorf("a limit cannot be negative: %w", ErrInvalidRequest)
	}
	if p.CPUPercent < 0 || p.CPUPercent > 100 {
		return fmt.Errorf("the CPU limit is a percentage between 0 and 100: %w", ErrInvalidRequest)
	}
	return nil
}

// read loads the file. A missing or empty file is an empty store.
func (s PlanStore) read() (planFile, error) {
	file := planFile{Plans: []Plan{}, Assignments: map[string]string{}}
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return file, nil
		}
		return file, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return file, nil
	}
	if err := json.Unmarshal(b, &file); err != nil {
		return file, fmt.Errorf("the plan file is corrupt: %w", err)
	}
	if file.Plans == nil {
		file.Plans = []Plan{}
	}
	if file.Assignments == nil {
		file.Assignments = map[string]string{}
	}
	return file, nil
}

// write replaces the file atomically, for the same reason the account store does.
func (s PlanStore) write(file planFile) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	temp := s.Path + ".new"
	if err := os.WriteFile(temp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(temp, s.Path)
}

// planIndex finds a plan by name, comparing case-insensitively.
func planIndex(file planFile, name string) int {
	return slices.IndexFunc(file.Plans, func(p Plan) bool {
		return strings.EqualFold(p.Name, name)
	})
}

// Status returns the plans, the assignments, and whether a quota engine is
// there to enforce a disk quota at all.
func (s PlanStore) Status(quotaEngine bool) (PlanStatus, error) {
	file, err := s.read()
	if err != nil {
		return PlanStatus{}, err
	}
	return PlanStatus{Plans: file.Plans, Assignments: file.Assignments, QuotaEngine: quotaEngine}, nil
}

// Save adds a plan, or replaces the one with the same name.
func (s PlanStore) Save(p Plan) error {
	p.Name = strings.TrimSpace(p.Name)
	if err := validatePlan(p); err != nil {
		return err
	}
	file, err := s.read()
	if err != nil {
		return err
	}
	if i := planIndex(file, p.Name); i >= 0 {
		file.Plans[i] = p
	} else {
		file.Plans = append(file.Plans, p)
	}
	return s.write(file)
}

// Find returns one plan by name.
func (s PlanStore) Find(name string) (Plan, error) {
	file, err := s.read()
	if err != nil {
		return Plan{}, err
	}
	i := planIndex(file, strings.TrimSpace(name))
	if i < 0 {
		return Plan{}, fmt.Errorf("plan %q: %w", name, ErrNotFound)
	}
	return file.Plans[i], nil
}

// Delete removes a plan. A plan a site still carries is REFUSED, because
// deleting it would leave that site pointing at a plan that does not exist.
func (s PlanStore) Delete(name string) error {
	name = strings.TrimSpace(name)
	file, err := s.read()
	if err != nil {
		return err
	}
	if site := siteCarrying(file, name); site != "" {
		return fmt.Errorf("the plan %q is assigned to %s; remove the assignment first: %w", name, site, ErrInvalidRequest)
	}
	i := planIndex(file, name)
	if i < 0 {
		return fmt.Errorf("plan %q: %w", name, ErrNotFound)
	}
	file.Plans = slices.Delete(file.Plans, i, i+1)
	return s.write(file)
}

// siteCarrying names one site assigned the given plan, or "" for none.
func siteCarrying(file planFile, plan string) string {
	for site, name := range file.Assignments {
		if strings.EqualFold(name, plan) {
			return site
		}
	}
	return ""
}

// Assign records that a site carries a plan. Applying the limits to the host is
// the caller's job; this is only the bookkeeping.
func (s PlanStore) Assign(site, plan string) error {
	file, err := s.read()
	if err != nil {
		return err
	}
	file.Assignments[strings.ToLower(strings.TrimSpace(site))] = plan
	return s.write(file)
}

// Unassign drops a site's assignment and reports when there was none, so a
// caller can tell the operator rather than answering success for no work.
func (s PlanStore) Unassign(site string) error {
	site = strings.ToLower(strings.TrimSpace(site))
	file, err := s.read()
	if err != nil {
		return err
	}
	if _, ok := file.Assignments[site]; !ok {
		return fmt.Errorf("%s carries no plan: %w", site, ErrNotFound)
	}
	delete(file.Assignments, site)
	return s.write(file)
}

// Forget drops a deleted site's assignment without complaining when there is
// none.
//
// This runs when a SITE is deleted. Without it the assignment is orphaned, and
// Delete then refuses to remove the plan because it is "assigned" to a site that
// no longer exists: the plan can never be deleted again.
func (s PlanStore) Forget(site string) error {
	site = strings.ToLower(strings.TrimSpace(site))
	file, err := s.read()
	if err != nil {
		return err
	}
	if _, ok := file.Assignments[site]; !ok {
		return nil
	}
	delete(file.Assignments, site)
	return s.write(file)
}
