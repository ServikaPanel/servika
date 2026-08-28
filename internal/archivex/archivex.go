// Package archivex securely extracts tenant-owned archives.
package archivex

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
)

var (
	// ErrUnsupported indicates that an archive format is not supported.
	ErrUnsupported = errors.New("unsupported archive format")
	// ErrUnsafePath indicates that an archive member would escape the destination.
	ErrUnsafePath = errors.New("archive member escapes the destination")
	// ErrUnsafeMember indicates that an archive contains a link or special file.
	ErrUnsafeMember = errors.New("archive contains a link or special file")
	// ErrInvalidTenant indicates that the extraction user is not managed by Servika.
	ErrInvalidTenant = errors.New("invalid tenant user")
	// ErrRARUnavailable indicates that no safely supported RAR extractor is installed.
	ErrRARUnavailable = errors.New("RAR extraction is unavailable")
	// ErrInvalidArchive indicates that an archive listing could not be validated.
	ErrInvalidArchive = errors.New("archive could not be validated")
	// ErrArchiveTooLarge indicates that the declared uncompressed size exceeds the limit.
	ErrArchiveTooLarge = errors.New("archive expands beyond the allowed size")
	// ErrTooManyMembers indicates that the archive contains more members than allowed.
	ErrTooManyMembers = errors.New("archive contains too many members")
)

// Limits bounds an archive's declared expansion to defend against decompression
// bombs. A zero field imposes no limit for that dimension.
type Limits struct {
	// MaxTotalBytes caps the sum of declared uncompressed member sizes.
	MaxTotalBytes int64
	// MaxMembers caps the number of members.
	MaxMembers int
}

// exceedsBytes reports whether total is over a positive MaxTotalBytes.
func (l Limits) exceedsBytes(total int64) bool {
	return l.MaxTotalBytes > 0 && total > l.MaxTotalBytes
}

// exceedsMembers reports whether count is over a positive MaxMembers.
func (l Limits) exceedsMembers(count int) bool {
	return l.MaxMembers > 0 && count > l.MaxMembers
}

// Type identifies a supported archive format.
type Type uint8

const (
	// TypeUnknown identifies an unsupported archive format.
	TypeUnknown Type = iota
	// TypeZIP identifies a ZIP archive.
	TypeZIP
	// TypeTAR identifies an uncompressed TAR archive.
	TypeTAR
	// TypeTARGzip identifies a gzip-compressed TAR archive.
	TypeTARGzip
	// TypeTARBzip2 identifies a bzip2-compressed TAR archive.
	TypeTARBzip2
	// TypeTARXz identifies an xz-compressed TAR archive.
	TypeTARXz
	// TypeRAR identifies a RAR archive.
	TypeRAR
)

const safePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// DetectType determines an archive type from its case-insensitive filename suffix.
func DetectType(name string) Type {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		return TypeZIP
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return TypeTARGzip
	case strings.HasSuffix(lower, ".tar.bz2"), strings.HasSuffix(lower, ".tbz2"):
		return TypeTARBzip2
	case strings.HasSuffix(lower, ".tar.xz"), strings.HasSuffix(lower, ".txz"):
		return TypeTARXz
	case strings.HasSuffix(lower, ".tar"):
		return TypeTAR
	case strings.HasSuffix(lower, ".rar"):
		return TypeRAR
	default:
		return TypeUnknown
	}
}

func unsafeMemberName(name string) bool {
	name = strings.ReplaceAll(name, `\`, "/")
	if strings.HasPrefix(name, "/") {
		return true
	}
	return slices.Contains(strings.Split(name, "/"), "..")
}

// Scan validates every archive member without writing files. limits bounds the
// declared expansion (zero fields = unbounded) to reject decompression bombs.
func Scan(ctx context.Context, archivePath string, archiveType Type, limits Limits) error {
	return scan(ctx, archivePath, archiveType, limits, nil)
}

// scan is Scan with an optional collector, called once per member AFTER that
// member passed validation. Summarize rides on this rather than listing the
// archive a second time, so an inventory inherits the same rejection of
// absolute paths, ".." components, links and special files.
func scan(ctx context.Context, archivePath string, archiveType Type, limits Limits, collect func(name string, size int64)) error {
	switch archiveType {
	case TypeZIP:
		return scanZIP(ctx, archivePath, limits, collect)
	case TypeTAR, TypeTARGzip, TypeTARBzip2, TypeTARXz:
		return scanTAR(ctx, archivePath, archiveType, limits, collect)
	case TypeRAR:
		return scanRAR(ctx, archivePath, limits, collect)
	default:
		return ErrUnsupported
	}
}

type lsarListing struct {
	Contents []struct {
		Name            string `json:"XADFileName"`
		Type            string `json:"XADFileType"`
		LinkDestination string `json:"XADLinkDestination"`
		Size            int64  `json:"XADFileSize"`
	} `json:"lsarContents"`
}

// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
func safeCommand(ctx context.Context, name string, arguments ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = []string{"PATH=" + safePath, "LANG=C", "LC_ALL=C"}
	return command
}

func rarTool() (string, bool) {
	if _, err := exec.LookPath("bsdtar"); err == nil {
		return "bsdtar", true
	}
	if _, err := exec.LookPath("unar"); err == nil {
		if _, listErr := exec.LookPath("lsar"); listErr == nil {
			return "unar", true
		}
	}
	return "", false
}

func scanRAR(ctx context.Context, archivePath string, limits Limits, collect func(string, int64)) error {
	tool, ok := rarTool()
	if !ok {
		return ErrRARUnavailable
	}
	if tool == "bsdtar" {
		return scanRARWithBSDTar(ctx, archivePath, limits, collect)
	}
	return scanRARWithLSAR(ctx, archivePath, limits, collect)
}

func scanRARWithBSDTar(ctx context.Context, archivePath string, limits Limits, collect func(string, int64)) error {
	namesOutput, err := safeCommand(ctx, "bsdtar", "-tf", archivePath).Output()
	if err != nil {
		return ErrInvalidArchive
	}
	verboseOutput, err := safeCommand(ctx, "bsdtar", "-tvf", archivePath).Output()
	if err != nil {
		return ErrInvalidArchive
	}
	return validateBSDTarListings(namesOutput, verboseOutput, limits, collect)
}

func validateBSDTarListings(namesOutput, verboseOutput []byte, limits Limits, collect func(string, int64)) error {
	members := 0
	for line := range strings.SplitSeq(string(namesOutput), "\n") {
		name := strings.TrimSuffix(line, "\r")
		if name == "" {
			continue
		}
		if unsafeMemberName(name) {
			return ErrUnsafePath
		}
		members++
		if limits.exceedsMembers(members) {
			return ErrTooManyMembers
		}
		if collect != nil {
			// bsdtar -tf gives no size; the inventory only needs names here.
			collect(name, 0)
		}
	}
	for line := range strings.SplitSeq(string(verboseOutput), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line[0] != '-' && line[0] != 'd' {
			return ErrUnsafeMember
		}
	}
	return nil
}

func scanRARWithLSAR(ctx context.Context, archivePath string, limits Limits, collect func(string, int64)) error {
	output, err := safeCommand(ctx, "lsar", "-json", archivePath).Output()
	if err != nil {
		return ErrInvalidArchive
	}
	return validateLSARListing(output, limits, collect)
}

func validateLSARListing(output []byte, limits Limits, collect func(string, int64)) error {
	var listing lsarListing
	if err := json.Unmarshal(output, &listing); err != nil || len(listing.Contents) == 0 {
		return ErrInvalidArchive
	}
	if limits.exceedsMembers(len(listing.Contents)) {
		return ErrTooManyMembers
	}
	var total int64
	for _, member := range listing.Contents {
		if unsafeMemberName(member.Name) {
			return ErrUnsafePath
		}
		if member.LinkDestination != "" || (member.Type != "Regular" && member.Type != "Directory") {
			return ErrUnsafeMember
		}
		total += member.Size
		if limits.exceedsBytes(total) {
			return ErrArchiveTooLarge
		}
		if collect != nil {
			collect(member.Name, member.Size)
		}
	}
	return nil
}

func scanZIP(ctx context.Context, archivePath string, limits Limits, collect func(string, int64)) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open ZIP archive: %w", err)
	}
	defer func() { _ = reader.Close() }()

	if limits.exceedsMembers(len(reader.File)) {
		return ErrTooManyMembers
	}
	var total int64
	for _, member := range reader.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		mode := member.Mode()
		if mode&os.ModeSymlink != 0 || mode&(os.ModeDevice|os.ModeNamedPipe|os.ModeSocket) != 0 {
			return ErrUnsafeMember
		}
		if unsafeMemberName(member.Name) {
			return ErrUnsafePath
		}
		// The declared uncompressed size is attacker-controlled. Reject values that
		// would overflow int64 (individually or when summed) so a crafted header
		// cannot wrap total negative and bypass the size limit.
		if member.UncompressedSize64 > math.MaxInt64 || total > math.MaxInt64-int64(member.UncompressedSize64) {
			return ErrArchiveTooLarge
		}
		total += int64(member.UncompressedSize64)
		if limits.exceedsBytes(total) {
			return ErrArchiveTooLarge
		}
		if collect != nil {
			collect(member.Name, int64(member.UncompressedSize64))
		}
	}
	return nil
}

func scanTAR(ctx context.Context, archivePath string, archiveType Type, limits Limits, collect func(string, int64)) error {
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	file, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer func() { _ = file.Close() }()

	var reader io.Reader = file
	var gzipReader *gzip.Reader
	var xzCommand *exec.Cmd
	var xzStderr bytes.Buffer

	switch archiveType {
	case TypeTARGzip:
		gzipReader, err = gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("open gzip stream: %w", err)
		}
		defer func() { _ = gzipReader.Close() }()
		reader = gzipReader
	case TypeTARBzip2:
		reader = bzip2.NewReader(file)
	case TypeTARXz:
		xzCommand = exec.CommandContext(ctx, "xz", "-dc")
		xzCommand.Env = []string{"PATH=" + safePath}
		xzCommand.Stdin = file
		xzCommand.Stderr = &xzStderr
		pipe, pipeErr := xzCommand.StdoutPipe()
		if pipeErr != nil {
			return fmt.Errorf("open xz output: %w", pipeErr)
		}
		if err := xzCommand.Start(); err != nil {
			return fmt.Errorf("start xz: %w", err)
		}
		defer func() {
			if xzCommand != nil && xzCommand.Process != nil {
				_ = xzCommand.Process.Kill()
				_ = xzCommand.Wait()
			}
		}()
		reader = pipe
	}

	tarReader := tar.NewReader(reader)
	var total int64
	members := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, nextErr := tarReader.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return fmt.Errorf("read TAR archive: %w", nextErr)
		}
		switch header.Typeflag {
		case tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			return ErrUnsafeMember
		}
		if unsafeMemberName(header.Name) {
			return ErrUnsafePath
		}
		members++
		if limits.exceedsMembers(members) {
			return ErrTooManyMembers
		}
		total += header.Size
		if limits.exceedsBytes(total) {
			return ErrArchiveTooLarge
		}
		if collect != nil {
			collect(header.Name, header.Size)
		}
	}

	if xzCommand != nil {
		waitErr := xzCommand.Wait()
		xzCommand = nil
		if waitErr != nil {
			return fmt.Errorf("decompress xz archive: %s: %w", strings.TrimSpace(xzStderr.String()), waitErr)
		}
	}
	return nil
}

// stripFlag renders the leading-component count both tar and bsdtar accept.
func stripFlag(strip int) string {
	return "--strip-components=" + strconv.Itoa(strip)
}

func tenantCommand(ctx context.Context, systemUser string, arguments ...string) *exec.Cmd {
	fullArguments := append([]string{"-u", systemUser, "--"}, arguments...)
	// #nosec G204 G702 -- fixed binary (runuser) with separate args (no shell); systemUser is validated by the caller.
	command := exec.CommandContext(ctx, "runuser", fullArguments...)
	command.Env = []string{
		"PATH=" + safePath,
		"HOME=/home/" + systemUser,
		"USER=" + systemUser,
		"LOGNAME=" + systemUser,
	}
	return command
}

// Extract validates an archive and extracts it as the owning tenant user.
// limits bounds the declared expansion (zero fields = unbounded) to reject bombs.
func Extract(ctx context.Context, archivePath, destination, systemUser string, limits Limits) (string, error) {
	return ExtractStrip(ctx, archivePath, destination, systemUser, 0, limits)
}

// Count returns the number of members in the archive, for a progress total. It
// walks the whole archive through the same validation scan as Extract (tar
// headers are interleaved with the compressed body, so counting is a full
// streaming pass), so it inherits the rejection of unsafe members and can take a
// few seconds on a large archive; callers run it off the request path.
func Count(ctx context.Context, archivePath string, archiveType Type, limits Limits) (int, error) {
	total := 0
	if err := scan(ctx, archivePath, archiveType, limits, func(string, int64) { total++ }); err != nil {
		return 0, err
	}
	return total, nil
}

// progressCounter counts newline-delimited members from a verbose extractor and
// reports each batch through onLine, keeping the tail of the output for the
// error message. Extractors print one line per member in verbose mode, so the
// line count tracks progress in real time. The output lands on stdout for some
// tools (unzip, unar) and on stderr for others (tar, bsdtar), so both are wired
// to one counter.
type progressCounter struct {
	mu     sync.Mutex
	tail   []byte
	onLine func(delta int)
}

const progressTailMax = 8192

func (p *progressCounter) Write(b []byte) (int, error) {
	lines := bytes.Count(b, []byte{'\n'})
	p.mu.Lock()
	p.tail = append(p.tail, b...)
	if len(p.tail) > progressTailMax {
		p.tail = p.tail[len(p.tail)-progressTailMax:]
	}
	p.mu.Unlock()
	if p.onLine != nil && lines > 0 {
		p.onLine(lines)
	}
	return len(b), nil
}

func (p *progressCounter) tailString() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return string(p.tail)
}

// ExtractStrip is Extract with strip leading path components removed from every
// member, which is how a site backup wrapped in one container directory lands
// as the site rather than as public_html/backup/public_html.
//
// unzip has no equivalent, so zip and rar with strip > 0 go through bsdtar and
// report ErrStripUnsupported when it is absent. Extraction still runs as the
// tenant through runuser, so the kernel's own permission check is the last line
// even if a member slips past the pre-scan.
func ExtractStrip(ctx context.Context, archivePath, destination, systemUser string, strip int, limits Limits) (string, error) {
	return extractStrip(ctx, archivePath, destination, systemUser, strip, limits, nil, nil)
}

// ExtractProgress extracts like Extract and reports progress. onTotal is called
// once with the member count before extraction begins, and onLine with the
// number of members extracted since the previous call. Both may be nil, and with
// both nil it behaves exactly like Extract. The extractor is run verbose so each
// member emits one line, which is what onLine counts.
func ExtractProgress(ctx context.Context, archivePath, destination, systemUser string, limits Limits, onTotal func(int), onLine func(delta int)) (string, error) {
	var prog *progressCounter
	if onLine != nil {
		prog = &progressCounter{onLine: onLine}
	}
	return extractStrip(ctx, archivePath, destination, systemUser, 0, limits, prog, onTotal)
}

func extractStrip(ctx context.Context, archivePath, destination, systemUser string, strip int, limits Limits, prog *progressCounter, onTotal func(int)) (string, error) {
	if strip < 0 {
		return "", ErrUnsupported
	}
	archiveType := DetectType(archivePath)
	if archiveType == TypeUnknown {
		return "", ErrUnsupported
	}
	if !strings.HasPrefix(systemUser, "c_") || len(systemUser) == 2 {
		return "", ErrInvalidTenant
	}
	for _, character := range systemUser[2:] {
		if character != '_' && (character < '0' || character > '9') && (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') {
			return "", ErrInvalidTenant
		}
	}
	total := 0
	if err := scan(ctx, archivePath, archiveType, limits, func(string, int64) { total++ }); err != nil {
		return "", err
	}
	if onTotal != nil {
		onTotal(total)
	}

	// In verbose mode each extractor prints one line per member, which the
	// progress counter turns into a running total.
	verbose := prog != nil
	var command *exec.Cmd
	switch archiveType {
	case TypeZIP:
		if strip > 0 {
			if _, err := exec.LookPath("bsdtar"); err != nil {
				return "", ErrStripUnsupported
			}
			bsdX := "-x"
			if verbose {
				bsdX = "-xv"
			}
			command = tenantCommand(ctx, systemUser, "bsdtar", bsdX, stripFlag(strip),
				"-f", archivePath, "-C", destination)
			break
		}
		// verbose drops -q so unzip prints one " extracting: ..." line per member.
		if verbose {
			command = tenantCommand(ctx, systemUser, "unzip", "-o", archivePath, "-d", destination)
			break
		}
		command = tenantCommand(ctx, systemUser, "unzip", "-o", "-q", archivePath, "-d", destination)
	case TypeRAR:
		tool, ok := rarTool()
		if !ok {
			return "", ErrRARUnavailable
		}
		if tool == "bsdtar" {
			bsdX := "-x"
			if verbose {
				bsdX = "-xv"
			}
			arguments := []string{"bsdtar", bsdX}
			if strip > 0 {
				arguments = append(arguments, stripFlag(strip))
			}
			command = tenantCommand(ctx, systemUser, append(arguments, "-f", archivePath, "-C", destination)...)
			break
		}
		// unar unpacks whole; it cannot drop a leading component.
		if strip > 0 {
			return "", ErrStripUnsupported
		}
		command = tenantCommand(ctx, systemUser, "unar", "-f", "-D", "-o", destination, archivePath)
	default:
		// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
		file, err := os.Open(archivePath)
		if err != nil {
			return "", fmt.Errorf("open archive: %w", err)
		}
		defer func() { _ = file.Close() }()

		flag := "-x"
		switch archiveType {
		case TypeTARGzip:
			flag = "-xz"
		case TypeTARBzip2:
			flag = "-xj"
		case TypeTARXz:
			flag = "-xJ"
		}
		if verbose {
			flag += "v" // GNU tar prints one line per member to stderr.
		}
		arguments := []string{"tar", flag}
		if strip > 0 {
			arguments = append(arguments, stripFlag(strip))
		}
		command = tenantCommand(ctx, systemUser, append(arguments, "-f", "-", "-C", destination)...)
		command.Stdin = file
	}

	if prog != nil {
		command.Stdout = prog
		command.Stderr = prog
		if err := command.Run(); err != nil {
			return prog.tailString(), fmt.Errorf("extract archive as tenant: %w", err)
		}
		return prog.tailString(), nil
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("extract archive as tenant: %w", err)
	}
	return string(output), nil
}
