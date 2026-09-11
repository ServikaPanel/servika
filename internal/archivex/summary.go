package archivex

import (
	"context"
	"errors"
	"os/exec"
	"path"
	"slices"
	"sort"
	"strings"
)

// ErrStripUnsupported means the server cannot skip a container directory for
// this archive format. unzip has no equivalent of tar's --strip-components, so
// zip and rar need bsdtar; when it is absent the caller must extract whole and
// let the user move the tree.
var ErrStripUnsupported = errors.New("this archive format cannot skip its container directory on this server")

// Summary is what an archive contains, established WITHOUT extracting it.
//
// The point is to let the panel show what is about to happen, and to answer the
// one question every real-world site backup raises: does everything sit inside a
// single wrapper directory? Extracting `backup/public_html/...` into public_html
// without noticing produces public_html/backup/public_html and a site that does
// not load.
type Summary struct {
	// Members is how many entries the archive declares.
	Members int `json:"members"`
	// TotalBytes is the declared uncompressed size. Formats listed through
	// bsdtar report no size, so this can be 0 for a rar.
	TotalBytes int64 `json:"total_bytes"`
	// Roots are the distinct first path components, sorted.
	Roots []string `json:"roots"`
	// ContainerRoot is the single wrapper directory every member sits under, or
	// "" when there is not exactly one.
	ContainerRoot string `json:"container_root"`
	// Markers maps a requested marker filename to the directories holding it,
	// relative to the archive root ("" is the archive root itself).
	Markers map[string][]string `json:"markers"`
}

// Summarize inventories an archive without writing anything.
//
// It runs the same validation Scan does, so an archive with an absolute path, a
// ".." component, a symlink or a special file is rejected here too rather than
// being described and only refused later at extraction.
func Summarize(ctx context.Context, archivePath string, archiveType Type, limits Limits, markers []string) (Summary, error) {
	builder := summaryBuilder{
		summary: Summary{Roots: []string{}, Markers: map[string][]string{}},
		roots:   map[string]bool{},
		wanted:  make(map[string]bool, len(markers)),
	}
	for _, marker := range markers {
		builder.wanted[marker] = true
	}

	if err := scan(ctx, archivePath, archiveType, limits, builder.add); err != nil {
		return Summary{}, err
	}

	for root := range builder.roots {
		builder.summary.Roots = append(builder.summary.Roots, root)
	}
	sort.Strings(builder.summary.Roots)
	// One root is only a CONTAINER when something lives inside it. An archive of
	// a single loose file has one root too, and stripping that would discard the
	// file rather than unwrap a directory.
	if len(builder.summary.Roots) == 1 && builder.nested {
		builder.summary.ContainerRoot = builder.summary.Roots[0]
	}
	return builder.summary, nil
}

// summaryBuilder accumulates the inventory while the scan walks the archive.
type summaryBuilder struct {
	summary Summary
	roots   map[string]bool
	wanted  map[string]bool
	nested  bool
}

// add records one member that already passed validation.
func (b *summaryBuilder) add(name string, size int64) {
	clean := strings.Trim(strings.ReplaceAll(name, `\`, "/"), "/")
	clean = strings.TrimPrefix(clean, "./")
	if clean == "" || clean == "." {
		return
	}
	b.summary.Members++
	b.summary.TotalBytes += size
	first, rest, hasSlash := strings.Cut(clean, "/")
	b.roots[first] = true
	if hasSlash && strings.TrimSpace(rest) != "" {
		b.nested = true
	}
	if base := path.Base(clean); b.wanted[base] {
		dir := path.Dir(clean)
		if dir == "." {
			dir = ""
		}
		b.summary.Markers[base] = appendUnique(b.summary.Markers[base], dir)
	}
}

// AppRoot picks the application inside an archive from its markers, returning
// the app name and the directory holding its configuration.
//
// The shallowest match wins: a WordPress backup routinely carries a second
// wp-config.php inside a plugin's test fixtures, and the real one is the one
// closest to the root.
func AppRoot(summary Summary) (app, dir string) {
	for _, candidate := range []struct{ marker, app string }{
		{"wp-config.php", "wordpress"},
		{"artisan", "laravel"},
		{"configuration.php", "joomla"},
		{"settings.php", "drupal"},
		{".env", "laravel"},
	} {
		paths := summary.Markers[candidate.marker]
		if len(paths) == 0 {
			continue
		}
		shallowest := paths[0]
		for _, candidatePath := range paths[1:] {
			if depth(candidatePath) < depth(shallowest) {
				shallowest = candidatePath
			}
		}
		return candidate.app, shallowest
	}
	return "", ""
}

// StripSupported reports whether this server can skip a container directory for
// archiveType. The tar family carries it in tar itself; zip and rar need bsdtar.
func StripSupported(archiveType Type) bool {
	switch archiveType {
	case TypeZIP, TypeRAR:
		_, err := exec.LookPath("bsdtar")
		return err == nil
	case TypeTAR, TypeTARGzip, TypeTARBzip2, TypeTARXz:
		return true
	default:
		return false
	}
}

func depth(p string) int {
	if p == "" {
		return 0
	}
	return strings.Count(p, "/") + 1
}

func appendUnique(list []string, value string) []string {
	if slices.Contains(list, value) {
		return list
	}
	return append(list, value)
}
