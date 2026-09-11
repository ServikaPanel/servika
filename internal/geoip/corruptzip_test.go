package geoip

import (
	"archive/zip"
	"bytes"
	"testing"
	"time"
)

// A real corrupt archive member, not a hand-written reader: this builds a valid
// zip, flips a byte in the stored data so the CRC no longer matches, and drives
// the real parser over it. archive/zip reports the mismatch only at the END of
// the member and then latches the error, which is exactly the shape that made
// the old loop spin for ever.
func TestACorruptArchiveMemberDoesNotSpin(t *testing.T) {
	archive := corruptCountryArchive(t)
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatalf("open the built archive: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := readLocations(reader)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Error("a corrupt member was accepted as a complete country list")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the parser did not return; this is the spin the fix exists to stop")
	}
}

// corruptCountryArchive builds a zip holding one country-list member whose
// stored bytes no longer match the CRC recorded for them.
func corruptCountryArchive(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	// Store, not Deflate, so the corruption below lands in the member's own
	// bytes rather than in a compressed stream the reader rejects earlier.
	entry, err := writer.CreateHeader(&zip.FileHeader{
		Name:   "GeoLite2-Country-Locations-en.csv",
		Method: zip.Store,
	})
	if err != nil {
		t.Fatalf("create the member: %v", err)
	}
	if _, err := entry.Write([]byte("geoname_id,country_iso_code\n1,TR\n2,DE\n3,FR\n")); err != nil {
		t.Fatalf("write the member: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close the archive: %v", err)
	}

	raw := buffer.Bytes()
	at := bytes.Index(raw, []byte("2,DE"))
	if at < 0 {
		t.Fatal("the member body is not stored verbatim; this test cannot corrupt it")
	}
	raw[at] = 'X' // The CRC recorded in the header no longer matches.
	return raw
}
