package wordpress

// The one place a WordPress installation is located on disk, and the one place
// its components are listed. Both were written inline in the HTTP handlers
// three times over; a second copy in another package would drift from the
// layout the panel actually provisions.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Install names one WordPress installation on disk.
type Install struct {
	SystemUser string
	// Dir is the absolute directory holding wp-config.php.
	Dir string
	// Rel is Dir relative to public_html, "/" for the document root itself. It
	// is what a screen shows and what a finding is keyed on, because the
	// absolute path carries the system user and means nothing to a customer.
	Rel string
}

// Discover returns the WordPress installations of one tenant.
//
// It looks in public_html and ONE directory below it, which is the layout the
// panel provisions and the same depth the domain and cross-domain listings have
// always used. Walking the whole home would sweep node_modules and every backup
// a tenant left lying around.
func Discover(systemUser string) []Install {
	if !strings.HasPrefix(systemUser, "c_") {
		return nil
	}
	root := "/home/" + systemUser + "/public_html"
	directories := []string{root}
	// #nosec G703 -- path is composed from a validated tenant identifier (^c_[A-Za-z0-9_]+$) and a fixed system prefix.
	if entries, err := os.ReadDir(root); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				directories = append(directories, filepath.Join(root, entry.Name()))
			}
		}
	}
	var out []Install
	for _, dir := range directories {
		// #nosec G703 -- see above; dir is root or one of its own entries.
		if _, err := os.Stat(filepath.Join(dir, "wp-config.php")); err != nil {
			continue
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(dir, root), "/")
		if rel == "" {
			rel = "/"
		}
		out = append(out, Install{SystemUser: systemUser, Dir: dir, Rel: rel})
	}
	return out
}

// Component is one plugin or theme as wp-cli reports it.
type Component struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Version string `json:"version"`
}

// componentTimeout is one listing's budget. wp-cli loads the whole site to
// answer, so a broken plugin can hang it.
const componentTimeout = 40 * time.Second

// Components lists the plugins ("plugin") or themes ("theme") of one
// installation.
//
// The kind reaches an argv slot, so it is checked against the two words rather
// than passed through: everything else about this call is fixed, and a caller
// that could name the subcommand could name any of them.
func Components(ctx context.Context, systemUser, dir, kind string) ([]Component, error) {
	if kind != "plugin" && kind != "theme" {
		return nil, os.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, componentTimeout)
	defer cancel()
	body, err := wpStdout(ctx, systemUser, kind, "list", "--path="+dir, "--format=json",
		"--fields=name,status,version")
	if err != nil {
		return nil, err
	}
	var out []Component
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CoreVersion returns the WordPress version one installation is running.
func CoreVersion(systemUser, dir string) (string, error) {
	body, err := runWP(systemUser, "core", "version", "--path="+dir)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}
