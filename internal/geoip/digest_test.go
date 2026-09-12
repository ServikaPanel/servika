package geoip

import (
	"context"
	"crypto/sha256"
	"net/http"
	"os"
	"strings"
	"testing"
)

// The archive download redirects cross-host to object storage and the
// credential is deliberately not carried across that hop, so the bytes are
// authenticated by the TLS certificate of a host that is not maxmind.com. The
// files this builds drive the nginx geo check and the nftables country set, so
// a wrong ranges file is a country list that admits what it was written to
// refuse.
func TestAnArchiveThatDoesNotMatchThePublishedChecksumIsRefused(t *testing.T) {
	useDataDir(t)
	archive := countryArchive(t, "GeoLite2-Country-CSV_20260804", sampleLocations, sampleIPv4, sampleIPv6)
	var record recorder
	server := serveArchive(t, archive, &record)
	withDownloadURL(t, server.URL)
	// MaxMind publishes the digest of a DIFFERENT archive, which is what a
	// swapped object in storage looks like from here.
	publishDigest(t, sha256.Sum256([]byte("another edition")))

	_, err := fetchAndBuild(context.Background(), Account{ID: "1", Key: "k"})

	if err == nil {
		t.Fatal("an archive that does not match its published checksum was accepted")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("the reason is not stated: %v", err)
	}
	if _, statErr := os.Stat(dataPath(ipv4File)); statErr == nil {
		t.Error("a refused archive still wrote a network file")
	}
}

// A digest that cannot be read refuses the update. The network files on disk
// are a working country list, and keeping them costs one edition, while
// accepting an unverified archive is the failure this guards.
func TestAnUnreadablePublishedChecksumRefusesTheUpdate(t *testing.T) {
	useDataDir(t)
	archive := countryArchive(t, "GeoLite2-Country-CSV_20260804", sampleLocations, sampleIPv4, sampleIPv6)
	var record recorder
	server := serveArchive(t, archive, &record)
	withDownloadURL(t, server.URL)
	refuseDigest(t)

	_, err := fetchAndBuild(context.Background(), Account{ID: "1", Key: "k"})

	if err == nil {
		t.Fatal("an unverifiable archive was accepted")
	}
	if _, statErr := os.Stat(dataPath(ipv4File)); statErr == nil {
		t.Error("an unverifiable archive still wrote a network file")
	}
}

// refuseDigest points digestURL at an endpoint that answers 401.
func refuseDigest(t *testing.T) {
	t.Helper()
	withDigestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
}
