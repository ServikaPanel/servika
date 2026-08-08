package geoip

import (
	"archive/zip"
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"servika/internal/config"
	"servika/internal/secret"
)

// downloadURL is MaxMind's current authenticated endpoint.
//
// The older /app/geoip_download form took the license key as a QUERY
// PARAMETER and is deprecated. That shape is unusable here for a second reason
// as well: this endpoint redirects to object storage on another host, and Go's
// client drops the Authorization header across hosts but carries the query
// string, so a key in the URL would be handed to a third party on every
// download.
var downloadURL = "https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip"

// downloadDialContext replaces the transport's dialer.
//
// Only the DIALER is replaceable, never the client. Go decides whether to
// forward the Authorization header by comparing hostnames with the port
// removed, so two test servers on 127.0.0.1 are one host to it; routing two
// distinct names to them lets a test drive a genuine cross-host redirect
// against the client this function actually builds. Replacing the whole client
// instead would leave its redirect policy untested, which is the one thing that
// decides whether the license key travels.
var downloadDialContext func(ctx context.Context, network, address string) (net.Conn, error)

func newDownloadClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if downloadDialContext != nil {
		transport.DialContext = downloadDialContext
	}
	return &http.Client{Timeout: 10 * time.Minute, Transport: transport}
}

// Account is the MaxMind credential pair. Both halves are required: the
// endpoint authenticates the account id as the user and the license key as the
// password.
type Account struct {
	ID  string
	Key string
}

// Credentials reads the stored MaxMind account.
//
// A key that cannot be DECRYPTED is reported as absent rather than passed
// through. The column holds ciphertext, so handing the stored value to the
// download would send a base64 blob as a password, and reporting it as
// configured would tell the operator a broken key is fine.
func Credentials(ctx context.Context, db *sql.DB) (Account, error) {
	var account Account
	var sealed sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(maxmind_account_id,''), maxmind_license_key FROM panel_settings WHERE id=1`).
		Scan(&account.ID, &sealed)
	if err != nil {
		return Account{}, err
	}
	account.ID = strings.TrimSpace(account.ID)
	if account.ID == "" || !sealed.Valid || strings.TrimSpace(sealed.String) == "" {
		return Account{}, ErrNoCredentials
	}
	key, err := secret.Decrypt(sealed.String)
	if err != nil {
		return Account{}, ErrNoCredentials
	}
	account.Key = strings.TrimSpace(key)
	if account.Key == "" {
		return Account{}, ErrNoCredentials
	}
	return account, nil
}

// Download fetches the country database and rewrites the normalized files.
//
// The result is recorded on panel_settings either way, so a screen can tell a
// database that has never been downloaded apart from one whose last download
// failed.
func Download(ctx context.Context, db *sql.DB) error {
	account, err := Credentials(ctx, db)
	if err != nil {
		recordResult(ctx, db, "", "no MaxMind account is configured")
		return err
	}
	buildDate, err := fetchAndBuild(ctx, account)
	if err != nil {
		recordResult(ctx, db, "", err.Error())
		return err
	}
	recordResult(ctx, db, buildDate, "")
	return nil
}

// recordResult stores the outcome. The message is truncated to the column, and
// its first line only: an error carrying a newline would otherwise be stored
// and later rendered as several.
func recordResult(ctx context.Context, db *sql.DB, buildDate, failure string) {
	failure = strings.TrimSpace(failure)
	if index := strings.IndexAny(failure, "\r\n"); index >= 0 {
		failure = failure[:index]
	}
	if len(failure) > 255 {
		failure = failure[:255]
	}
	if failure != "" {
		_, _ = db.ExecContext(ctx,
			`UPDATE panel_settings SET geoip_last_error=? WHERE id=1`, failure)
		return
	}
	_, _ = db.ExecContext(ctx,
		`UPDATE panel_settings SET geoip_build_date=?, geoip_updated_at=NOW(), geoip_last_error='' WHERE id=1`,
		buildDate)
}

// fetchAndBuild downloads the archive and writes the normalized files,
// returning the edition's build date.
func fetchAndBuild(ctx context.Context, account Account) (string, error) {
	archive, err := fetchArchive(ctx, account)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = archive.Close()
		_ = os.Remove(archive.Name())
	}()

	info, err := archive.Stat()
	if err != nil {
		return "", fmt.Errorf("measure the archive: %w", err)
	}
	reader, err := zip.NewReader(archive, info.Size())
	if err != nil {
		return "", fmt.Errorf("open the archive: %w", err)
	}
	// The entry count is checked BEFORE any member is opened, so an archive
	// built to exhaust the reader never gets a member decompressed at all.
	if len(reader.File) > MaxArchiveEntries {
		return "", fmt.Errorf("the archive holds %d entries", len(reader.File))
	}
	var declared uint64
	for _, file := range reader.File {
		declared += file.UncompressedSize64
		if declared > MaxUnpackedBytes {
			return "", errors.New("the archive declares more content than the ceiling allows")
		}
	}

	countries, err := readLocations(reader)
	if err != nil {
		return "", err
	}
	if len(countries) == 0 {
		return "", errors.New("the archive names no country")
	}
	// 0750 is enough: the only reader is the nginx MASTER process, which parses
	// the include while still running as root, so the worker user never opens
	// it and no tenant needs to traverse the directory.
	if err := os.MkdirAll(config.GeoIPDir(), 0o750); err != nil {
		return "", fmt.Errorf("create the data directory: %w", err)
	}
	for _, pair := range []struct{ member, target string }{
		{"GeoLite2-Country-Blocks-IPv4.csv", ipv4File},
		{"GeoLite2-Country-Blocks-IPv6.csv", ipv6File},
	} {
		if err := writeNetworks(reader, pair.member, pair.target, countries); err != nil {
			return "", err
		}
	}

	buildDate := archiveBuildDate(reader)
	if err := writeAtomic(dataPath(metaFile), []byte(buildDate+"\n")); err != nil {
		return "", err
	}
	return buildDate, nil
}

// fetchArchive streams the archive to a temporary FILE rather than into memory.
//
// A zip needs random access to its central directory, and the edition is large
// enough that buffering it would be charged to the panel's own memory. The file
// is created with an empty directory argument so it lands under TMPDIR, which
// main pins to persistent disk.
func fetchArchive(ctx context.Context, account Account) (*os.File, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("prepare the request: %w", err)
	}
	// Basic auth, never the URL. The redirect below crosses hosts, and Go's
	// client strips this header when it does; a query parameter would survive.
	request.SetBasicAuth(account.ID, account.Key)
	request.Header.Set("User-Agent", "Servika")

	response, err := newDownloadClient().Do(request)
	if err != nil {
		return nil, errors.New("the country database endpoint could not be reached")
	}
	defer func() { _ = response.Body.Close() }()
	switch {
	case response.StatusCode == http.StatusUnauthorized, response.StatusCode == http.StatusForbidden:
		return nil, errors.New("MaxMind refused the account id and license key")
	case response.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("the country database endpoint answered %d", response.StatusCode)
	}

	file, err := os.CreateTemp("", "servika-geoip-*.zip")
	if err != nil {
		return nil, fmt.Errorf("create a temporary file: %w", err)
	}
	written, err := io.Copy(file, io.LimitReader(response.Body, MaxDownloadBytes+1))
	if err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, fmt.Errorf("read the archive: %w", err)
	}
	if written > MaxDownloadBytes {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, errors.New("the archive is larger than the ceiling allows")
	}
	return file, nil
}

// archiveBuildDate reads the edition date out of the archive's directory name,
// which MaxMind shapes as GeoLite2-Country-CSV_20260804.
func archiveBuildDate(reader *zip.Reader) string {
	for _, file := range reader.File {
		root := file.Name
		if index := strings.IndexByte(root, '/'); index >= 0 {
			root = root[:index]
		}
		if index := strings.LastIndexByte(root, '_'); index >= 0 {
			candidate := root[index+1:]
			if len(candidate) == 8 && isDigits(candidate) {
				return candidate
			}
		}
	}
	return time.Now().UTC().Format("20060102")
}

func isDigits(value string) bool {
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return len(value) > 0
}

// member finds an archive entry by its BASE name.
//
// MaxMind nests everything under a dated directory, so matching the full path
// would break on every release. Only the base name is compared, and a member
// whose path escapes the archive root is skipped rather than resolved: nothing
// here is extracted to disk, but a name like ../../etc is still a signal that
// this is not the archive it claims to be.
func member(reader *zip.Reader, name string) (*zip.File, bool) {
	for _, file := range reader.File {
		if strings.Contains(file.Name, "..") {
			continue
		}
		if path.Base(file.Name) == name {
			return file, true
		}
	}
	return nil, false
}

// readLocations maps MaxMind's numeric geoname id onto an ISO country code.
func readLocations(reader *zip.Reader) (map[string]string, error) {
	file, ok := member(reader, "GeoLite2-Country-Locations-en.csv")
	if !ok {
		return nil, errors.New("the archive holds no country list")
	}
	handle, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("open the country list: %w", err)
	}
	defer func() { _ = handle.Close() }()

	records := csv.NewReader(io.LimitReader(handle, MaxUnpackedBytes))
	records.FieldsPerRecord = -1
	header, err := records.Read()
	if err != nil {
		return nil, fmt.Errorf("read the country list header: %w", err)
	}
	idColumn := columnIndex(header, "geoname_id")
	codeColumn := columnIndex(header, "country_iso_code")
	if idColumn < 0 || codeColumn < 0 {
		return nil, errors.New("the country list is missing a required column")
	}

	countries := make(map[string]string, 512)
	for {
		row, err := records.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// One malformed row must not discard a database that is otherwise
			// usable: this is a third-party file and the alternative is no
			// country blocking at all until MaxMind's next release.
			continue
		}
		if idColumn >= len(row) || codeColumn >= len(row) {
			continue
		}
		code := NormalizeCountry(row[codeColumn])
		id := strings.TrimSpace(row[idColumn])
		if code == "" || id == "" {
			continue
		}
		countries[id] = code
	}
	return countries, nil
}

// writeNetworks turns one blocks CSV into `network,CC` lines sorted by country.
func writeNetworks(reader *zip.Reader, memberName, target string, countries map[string]string) error {
	file, ok := member(reader, memberName)
	if !ok {
		return fmt.Errorf("the archive holds no %s", memberName)
	}
	handle, err := file.Open()
	if err != nil {
		return fmt.Errorf("open %s: %w", memberName, err)
	}
	defer func() { _ = handle.Close() }()

	records := csv.NewReader(io.LimitReader(handle, MaxUnpackedBytes))
	records.FieldsPerRecord = -1
	header, err := records.Read()
	if err != nil {
		return fmt.Errorf("read the %s header: %w", memberName, err)
	}
	networkColumn := columnIndex(header, "network")
	geonameColumn := columnIndex(header, "geoname_id")
	registeredColumn := columnIndex(header, "registered_country_geoname_id")
	if networkColumn < 0 || geonameColumn < 0 {
		return fmt.Errorf("%s is missing a required column", memberName)
	}

	var body strings.Builder
	written := 0
	for {
		row, err := records.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			continue
		}
		if networkColumn >= len(row) {
			continue
		}
		network := strings.TrimSpace(row[networkColumn])
		if _, _, err := net.ParseCIDR(network); err != nil {
			continue
		}
		code := ""
		if geonameColumn < len(row) {
			code = countries[strings.TrimSpace(row[geonameColumn])]
		}
		// MaxMind leaves geoname_id empty for a network it cannot place but
		// still knows the registering country for. Falling back keeps ranges
		// that would otherwise silently drop out of a block list.
		if code == "" && registeredColumn >= 0 && registeredColumn < len(row) {
			code = countries[strings.TrimSpace(row[registeredColumn])]
		}
		if code == "" {
			continue
		}
		body.WriteString(network)
		body.WriteByte(',')
		body.WriteString(code)
		body.WriteByte('\n')
		written++
		if written > MaxNetworks {
			return fmt.Errorf("%s holds more networks than the ceiling allows", memberName)
		}
	}
	if written == 0 {
		return fmt.Errorf("%s produced no usable network", memberName)
	}
	return writeAtomic(dataPath(target), []byte(body.String()))
}

func columnIndex(header []string, name string) int {
	for index, column := range header {
		if strings.EqualFold(strings.TrimSpace(column), name) {
			return index
		}
	}
	return -1
}

// writeAtomic replaces a file whole.
//
// A reader of the country data holds no lock, so a partially written file would
// be read as a partially populated country and would quietly stop blocking part
// of it. Writing beside the target and renaming makes the swap one step.
func writeAtomic(target string, body []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(target), ".servika-*")
	if err != nil {
		return fmt.Errorf("create the temporary file: %w", err)
	}
	name := temporary.Name()
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		_ = os.Remove(name)
		return fmt.Errorf("write the temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("close the temporary file: %w", err)
	}
	// 0600 is enough for both readers: the panel runs as root, and nginx parses
	// the include in its master process before dropping to the worker user.
	if err := os.Chmod(name, 0o600); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("set the file mode: %w", err)
	}
	if err := os.Rename(name, target); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("replace the file: %w", err)
	}
	return nil
}
