package mailreport

import (
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"os"
	"strings"
	"syscall"
)

// maxMessageBytes bounds one message read out of a mailbox.
//
// A report attachment is base64 encoded on the wire, which costs about a third
// again on top of MaxCompressedBytes, and the message carries headers and a
// human-readable part beside it.
const maxMessageBytes = 8 << 20

// maxMIMEDepth bounds how deep the part walk goes. A report is one attachment
// inside a multipart/mixed, sometimes inside one more level; a message nested
// far past that is not a report and would otherwise be walked forever.
const maxMIMEDepth = 4

// maxParts bounds how many parts one message may contribute. Without it a
// message declaring thousands of tiny parts costs a parse attempt for each.
const maxParts = 64

// readMessage returns the raw bytes of one message file.
//
// The file lives in a Maildir the TENANT owns and their own processes write to,
// so the open is O_NOFOLLOW (root would otherwise follow a planted link out of
// the directory) and O_NONBLOCK (a named pipe would otherwise block the open
// before any check could run), and IsRegular is asserted on the DESCRIPTOR
// rather than on a separate stat of the path, which describes a different file
// the moment the path is reused. internal/transfers.tailFile is the pattern.
func readMessage(path string) ([]byte, error) {
	// #nosec G304 -- the path is built from a Maildir directory listing this package owns; the open below is O_NOFOLLOW with a regular-file check on the descriptor.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	body, err := io.ReadAll(io.LimitReader(file, maxMessageBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxMessageBytes {
		return nil, fmt.Errorf("the message is larger than %d bytes", maxMessageBytes)
	}
	return body, nil
}

// Attachments returns the candidate report documents inside one message, each
// already unpacked.
//
// Every part is offered rather than only the ones whose name or media type
// looks right: reporters disagree about whether a gzipped XML report is
// application/gzip, application/x-gzip, application/octet-stream or text/xml
// with an encoding, and Unpack decides the real format from the bytes anyway.
// A part that fails to unpack is skipped, because most parts in a postmaster
// mailbox are ordinary mail.
func Attachments(raw []byte) [][]byte {
	message, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return nil
	}
	var out [][]byte
	collectParts(textproto.MIMEHeader(message.Header), message.Body, 0, &out)
	return out
}

func collectParts(header textproto.MIMEHeader, body io.Reader, depth int, out *[][]byte) {
	if depth > maxMIMEDepth || len(*out) >= maxParts {
		return
	}
	mediaType, params, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil {
		mediaType = "text/plain"
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return
		}
		reader := multipart.NewReader(body, boundary)
		for len(*out) < maxParts {
			part, err := reader.NextPart()
			if err != nil {
				return
			}
			// The part is passed UNDECODED. decodeTransfer is applied once, at
			// the leaf: applying it here as well would run a base64 attachment
			// through the decoder twice, and the second pass turns the report
			// into a decode error that looks exactly like "no report here".
			// A multipart part is never itself base64 (RFC 2045 forbids it), so
			// nothing is lost by leaving the walk on the raw bytes.
			collectParts(part.Header, part, depth+1, out)
			_ = part.Close()
		}
		return
	}
	document, err := Unpack(decodeTransfer(header, body))
	if err != nil || len(document) == 0 {
		return
	}
	*out = append(*out, document)
}

// decodeTransfer undoes the Content-Transfer-Encoding. multipart.Reader does
// not: it hands back the encoded bytes, so without this a base64 attachment
// reaches Unpack as ASCII and never matches an archive's magic bytes.
func decodeTransfer(header textproto.MIMEHeader, body io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(header.Get("Content-Transfer-Encoding"))) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, newlineStripper{body})
	case "quoted-printable":
		return quotedprintable.NewReader(body)
	default:
		return body
	}
}

// newlineStripper drops the line breaks a base64 body is wrapped at. The
// standard decoder refuses them, so a correctly formatted attachment would
// otherwise fail to decode.
type newlineStripper struct{ inner io.Reader }

func (s newlineStripper) Read(p []byte) (int, error) {
	read, err := s.inner.Read(p)
	if read > 0 {
		kept := p[:0]
		for _, b := range p[:read] {
			if b != '\r' && b != '\n' {
				kept = append(kept, b)
			}
		}
		return len(kept), err
	}
	return read, err
}
