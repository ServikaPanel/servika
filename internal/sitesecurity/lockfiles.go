package sitesecurity

import (
	"encoding/json"
	"strings"
)

// A lockfile belongs to the tenant, so it is untrusted input with a ceiling on
// every axis: how much is read off disk, how many entries are taken from it,
// and how long a name may be. A malformed lockfile drops that INSTALLATION and
// never the sweep.
const (
	// maxLockfileBytes is what is read from one lockfile. A package-lock.json
	// for a large application runs to a few megabytes; past this it is not a
	// dependency list any more.
	maxLockfileBytes = 8 << 20

	// maxPackagesPerLockfile bounds one dependency list. A tree deeper than
	// this cannot be shown on a screen and would take more feed requests than
	// the sweep's budget allows.
	maxPackagesPerLockfile = 2000

	// maxPackageNameBytes matches the schema's package_name column.
	maxPackageNameBytes = 255
)

// npmLockfile covers both layouts npm has shipped.
//
// Lockfile v2 and v3 list every installed package under "packages", keyed by
// its path ("node_modules/foo", "node_modules/a/node_modules/b"). v1 nests them
// under "dependencies". Both are read, because npm 6 lockfiles are still in the
// wild and a v1 file read as v2 yields nothing at all rather than an error.
type npmLockfile struct {
	Packages     map[string]npmEntry `json:"packages"`
	Dependencies map[string]npmDep   `json:"dependencies"`
}

type npmEntry struct {
	Version string `json:"version"`
	Name    string `json:"name"`
}

type npmDep struct {
	Version      string            `json:"version"`
	Dependencies map[string]npmDep `json:"dependencies"`
}

// ParseNPMLock reads the dependencies out of a package-lock.json.
//
// The result is deduplicated by name and version, because one package at one
// version appears many times in a deep tree and each copy would otherwise be a
// separate feed query and a separate row saying the same thing.
func ParseNPMLock(body []byte) ([]Package, error) {
	var decoded npmLockfile
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}

	seen := map[Package]bool{}
	var out []Package
	add := func(name, version string) {
		if len(out) >= maxPackagesPerLockfile {
			return
		}
		name = strings.TrimSpace(name)
		version = strings.TrimSpace(version)
		if name == "" || version == "" || len(name) > maxPackageNameBytes {
			return
		}
		pkg := Package{Name: name, Version: version}
		if seen[pkg] {
			return
		}
		seen[pkg] = true
		out = append(out, pkg)
	}

	for path, entry := range decoded.Packages {
		// The root project is keyed by the empty string and is not a
		// dependency; it has no published advisories and its "version" is the
		// application's own.
		if path == "" {
			continue
		}
		name := entry.Name
		if name == "" {
			// The key is a path, and the package name is everything after the
			// LAST node_modules segment, so a scoped nested package
			// ("node_modules/a/node_modules/@scope/b") keeps its scope.
			_, after, found := strings.Cut(path, "node_modules/")
			if !found {
				continue
			}
			for {
				_, deeper, nested := strings.Cut(after, "node_modules/")
				if !nested {
					break
				}
				after = deeper
			}
			name = after
		}
		add(name, entry.Version)
	}

	var walk func(map[string]npmDep)
	walk = func(deps map[string]npmDep) {
		for name, dep := range deps {
			add(name, dep.Version)
			walk(dep.Dependencies)
		}
	}
	walk(decoded.Dependencies)

	return out, nil
}

// composerLockfile is the part of a composer.lock this reads.
//
// packages-dev is deliberately NOT read. It describes what a developer machine
// installs; a production `composer install --no-dev` leaves those directories
// absent, so reporting one would name a package that is not on the server.
type composerLockfile struct {
	Packages []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"packages"`
}

// ParseComposerLock reads the dependencies out of a composer.lock.
func ParseComposerLock(body []byte) ([]Package, error) {
	var decoded composerLockfile
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}
	seen := map[Package]bool{}
	out := make([]Package, 0, len(decoded.Packages))
	for _, entry := range decoded.Packages {
		if len(out) >= maxPackagesPerLockfile {
			break
		}
		name := strings.TrimSpace(entry.Name)
		// Composer writes a release as "v1.2.3" and a branch as "dev-main".
		// The leading v is handled by the comparison; a dev branch has no
		// orderable version, so it is dropped here rather than counted as a
		// package the sweep failed to judge.
		version := strings.TrimSpace(entry.Version)
		if name == "" || version == "" || len(name) > maxPackageNameBytes {
			continue
		}
		if strings.HasPrefix(version, "dev-") || strings.HasSuffix(version, "-dev") {
			continue
		}
		pkg := Package{Name: name, Version: version}
		if seen[pkg] {
			continue
		}
		seen[pkg] = true
		out = append(out, pkg)
	}
	return out, nil
}
