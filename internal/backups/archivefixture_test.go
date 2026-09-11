package backups

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tarEntry is one member of a fixture archive. A zero typeflag is a regular
// file.
type tarEntry struct {
	name     string
	body     string
	typeflag byte
	linkname string
}

// writeTarGz writes a gzip-compressed tar holding entries at path.
func writeTarGz(t *testing.T, path string, entries ...tarEntry) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create the archive directory: %v", err)
	}
	file, err := os.Create(path) // #nosec G304 -- a path under the test's temporary directory.
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	zipped := gzip.NewWriter(file)
	archive := tar.NewWriter(zipped)
	for _, entry := range entries {
		writeTarEntry(t, archive, entry)
	}
	for _, closer := range []io.Closer{archive, zipped, file} {
		if err := closer.Close(); err != nil {
			t.Fatalf("close %s: %v", path, err)
		}
	}
}

func writeTarEntry(t *testing.T, archive *tar.Writer, entry tarEntry) {
	t.Helper()
	header := &tar.Header{Name: entry.name, Mode: 0o644, Typeflag: entry.typeflag, Linkname: entry.linkname}
	switch header.Typeflag {
	case 0:
		header.Typeflag = tar.TypeReg
	case tar.TypeDir:
		header.Mode = 0o755
	}
	if header.Typeflag == tar.TypeReg {
		header.Size = int64(len(entry.body))
	}
	if err := archive.WriteHeader(header); err != nil {
		t.Fatalf("write the header of %s: %v", entry.name, err)
	}
	if header.Typeflag != tar.TypeReg {
		return
	}
	if _, err := io.WriteString(archive, entry.body); err != nil {
		t.Fatalf("write the body of %s: %v", entry.name, err)
	}
}

// extractMembers does what `tar -xz -f archive -C dest members...` does for the
// regular files and directories of a fixture: every entry that is a member or
// lies under one is written below dest. It returns an error instead of failing a
// test, because the command fake that calls it can run on a goroutine the test
// does not own.
func extractMembers(archivePath, dest string, members []string) error {
	file, err := os.Open(archivePath) // #nosec G304 -- a fixture under the test's temporary directory.
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	zipped, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	reader := tar.NewReader(zipped)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if !underAMember(strings.TrimPrefix(header.Name, "./"), members) {
			continue
		}
		if err := writeExtracted(dest, header, reader); err != nil {
			return err
		}
	}
}

func underAMember(name string, members []string) bool {
	for _, member := range members {
		if name == member || strings.HasPrefix(name, strings.TrimSuffix(member, "/")+"/") {
			return true
		}
	}
	return false
}

func writeExtracted(dest string, header *tar.Header, body io.Reader) error {
	target := filepath.Join(dest, header.Name) // #nosec G305 -- fixture archives are written by the test itself.
	if header.Typeflag == tar.TypeDir {
		return os.MkdirAll(target, 0o755)
	}
	if header.Typeflag != tar.TypeReg {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	content, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	return os.WriteFile(target, content, 0o600)
}

// extractingCommands installs a recorder under which `tar -xz` really extracts
// the requested members of a fixture, and every other command succeeds unless its
// argv starts with one of fail.
func extractingCommands(t *testing.T, fail ...[]string) *commandRecorder {
	t.Helper()
	return withCommandScript(t, func(argv []string) (string, int) {
		for _, prefix := range fail {
			if hasArgvPrefix(argv, prefix) {
				return "scripted failure", 1
			}
		}
		// tar -xz -f <archive> -C <dest> <members...>
		if hasArgvPrefix(argv, []string{"tar", "-xz", "-f"}) && len(argv) > 6 {
			if err := extractMembers(argv[3], argv[5], argv[6:]); err != nil {
				return err.Error(), 2
			}
		}
		return "", 0
	})
}
