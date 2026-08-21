package phpext

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// elfHeader builds a 64-byte ELF64 header with no program or section headers.
// debug/elf parses it, which is all the check reads, and building it here keeps
// the fixtures deterministic and independent of the machine running the test:
// the wrong-architecture case has to be expressible on every platform, and a
// checked-in binary could only ever be one architecture.
func elfHeader(class elf.Class, kind elf.Type, machine elf.Machine) []byte {
	header := make([]byte, 64)
	copy(header, "\x7fELF")
	header[4] = byte(class)
	header[5] = byte(elf.ELFDATA2LSB)
	header[6] = byte(elf.EV_CURRENT)

	if class == elf.ELFCLASS32 {
		// A 32-bit header is 52 bytes and its fields sit at different offsets;
		// only the identification and the first three fields matter here, and
		// they are what the class check reads.
		header = header[:52]
		binary.LittleEndian.PutUint16(header[16:], uint16(kind))
		binary.LittleEndian.PutUint16(header[18:], uint16(machine))
		binary.LittleEndian.PutUint32(header[20:], uint32(elf.EV_CURRENT))
		binary.LittleEndian.PutUint16(header[40:], 52) // e_ehsize
		return header
	}

	binary.LittleEndian.PutUint16(header[16:], uint16(kind))
	binary.LittleEndian.PutUint16(header[18:], uint16(machine))
	binary.LittleEndian.PutUint32(header[20:], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint16(header[52:], 64) // e_ehsize
	return header
}

func writeMember(t *testing.T, body []byte) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ioncube_loader_lin_8.3.so")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	handle, err := openArchiveMember(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	return handle
}

// The publisher gives no checksum and no signature (measured: the .sha256 and
// .asc paths both answer 302 to the homepage), so nothing else established that
// the file about to be copied into extension_dir and named in a zend_extension
// line was even an object.
func TestOnlyAnELFSharedObjectForThisMachineIsAccepted(t *testing.T) {
	mine, ok := loaderMachine()
	if !ok {
		t.Skipf("no loader machine for %s", "this platform")
	}
	other := elf.EM_AARCH64
	if mine == elf.EM_AARCH64 {
		other = elf.EM_X86_64
	}

	cases := []struct {
		name    string
		body    []byte
		refused bool
	}{
		{"a shared object for this machine", elfHeader(elf.ELFCLASS64, elf.ET_DYN, mine), false},
		{"a shared object for another machine", elfHeader(elf.ELFCLASS64, elf.ET_DYN, other), true},
		{"a 32-bit object", elfHeader(elf.ELFCLASS32, elf.ET_DYN, mine), true},
		{"an executable rather than a shared object", elfHeader(elf.ELFCLASS64, elf.ET_EXEC, mine), true},
		{"a shell script", []byte("#!/bin/sh\nid\n"), true},
		{"an HTML error page", []byte("<html><body>404</body></html>"), true},
		{"an empty file", nil, true},
	}
	for _, item := range cases {
		err := verifyLoaderELF(writeMember(t, item.body))
		if item.refused && err == nil {
			t.Errorf("%s was accepted", item.name)
		}
		if !item.refused && err != nil {
			t.Errorf("%s was refused: %v", item.name, err)
		}
	}
}

// The wrong architecture used to produce no error anywhere. Measured with a real
// aarch64 loader on an amd64 PHP 8.3: the interpreter prints "Failed loading ..."
// on stderr and CONTINUES, exit 0, so the install answered 201 while every PHP
// invocation on that version wrote a load failure from then on. The refusal has
// to say which architecture it found, or an operator has nothing to act on.
func TestTheWrongArchitectureIsNamed(t *testing.T) {
	mine, ok := loaderMachine()
	if !ok {
		t.Skip("no loader machine for this platform")
	}
	other := elf.EM_AARCH64
	if mine == elf.EM_AARCH64 {
		other = elf.EM_X86_64
	}
	err := verifyLoaderELF(writeMember(t, elfHeader(elf.ELFCLASS64, elf.ET_DYN, other)))
	if err == nil {
		t.Fatal("an object for another architecture was accepted")
	}
	if !strings.Contains(err.Error(), other.String()) || !strings.Contains(err.Error(), mine.String()) {
		t.Errorf("the refusal names neither architecture: %v", err)
	}
}

// The check reads through ReaderAt and the caller copies from the same
// descriptor afterwards, so the offset must come back to the start. Without it
// the installed loader would be a truncated file that loads on no interpreter.
func TestTheOffsetSurvivesTheCheck(t *testing.T) {
	mine, ok := loaderMachine()
	if !ok {
		t.Skip("no loader machine for this platform")
	}
	body := append(elfHeader(elf.ELFCLASS64, elf.ET_DYN, mine), []byte("loader payload")...)
	handle := writeMember(t, body)
	if err := verifyLoaderELF(handle); err != nil {
		t.Fatalf("a well-formed object was refused: %v", err)
	}

	destination := filepath.Join(t.TempDir(), "installed.so")
	if err := copyFromMember(handle, destination); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(body) {
		t.Errorf("copied %d bytes after the check, want %d", len(got), len(body))
	}
}
