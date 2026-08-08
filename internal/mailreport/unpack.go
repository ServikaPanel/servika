package mailreport

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
)

// Unpack returns the document inside a report attachment.
//
// The format is decided by MAGIC BYTES, never by the attachment's filename: the
// filename is chosen by whoever sent the message, so trusting it would let a zip
// be handed to the gzip reader (or a 30 MB "report.xml.gz" that is really a
// plain file) purely by naming.
//
// The result is fully buffered rather than streamed. A zip needs random access
// to its central directory, and both formats have to be measured against
// MaxUnpackedBytes before anything downstream sees them, which a stream cannot
// promise.
func Unpack(body io.Reader) ([]byte, error) {
	// One byte over the ceiling is enough to know the ceiling was passed, and
	// stops a large attachment being read into memory in full.
	raw, err := io.ReadAll(io.LimitReader(body, MaxCompressedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read the attachment: %w", err)
	}
	if len(raw) > MaxCompressedBytes {
		return nil, fmt.Errorf("the attachment is larger than %d bytes", MaxCompressedBytes)
	}
	switch {
	case bytes.HasPrefix(raw, []byte("PK\x03\x04")):
		return unpackZip(raw)
	case bytes.HasPrefix(raw, []byte{0x1f, 0x8b}):
		return unpackGzip(raw)
	default:
		return raw, nil
	}
}

// readCapped copies at most MaxUnpackedBytes and reports anything beyond it as
// an error rather than a truncated document.
//
// Truncation would be worse than refusal here: a cut-off XML document is
// invalid and the parser would report a syntax error, which reads as "the
// reporter sent something broken" when what actually happened is that the panel
// refused to keep expanding it.
func readCapped(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, MaxUnpackedBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxUnpackedBytes {
		return nil, fmt.Errorf("the report expands past %d bytes", MaxUnpackedBytes)
	}
	return body, nil
}

func unpackGzip(raw []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("open the gzip attachment: %w", err)
	}
	defer func() { _ = reader.Close() }()
	body, err := readCapped(reader)
	if err != nil {
		return nil, fmt.Errorf("read the gzip attachment: %w", err)
	}
	return body, nil
}

// unpackZip returns the single member of a report archive.
//
// A report archive holds exactly one document. The entry count is checked
// BEFORE any member is opened, so an archive with thousands of entries costs
// nothing, and each member is still read through readCapped because the entry
// count alone says nothing about how far one member expands.
func unpackZip(raw []byte) ([]byte, error) {
	archive, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("open the zip attachment: %w", err)
	}
	if len(archive.File) == 0 {
		return nil, errors.New("the zip attachment is empty")
	}
	if len(archive.File) > MaxArchiveEntries {
		return nil, fmt.Errorf("the zip attachment holds more than %d entries", MaxArchiveEntries)
	}
	for _, entry := range archive.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		file, err := entry.Open()
		if err != nil {
			return nil, fmt.Errorf("open a zip member: %w", err)
		}
		body, err := readCapped(file)
		closeErr := file.Close()
		if err != nil {
			return nil, fmt.Errorf("read a zip member: %w", err)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close a zip member: %w", closeErr)
		}
		return body, nil
	}
	return nil, errors.New("the zip attachment holds no file")
}
