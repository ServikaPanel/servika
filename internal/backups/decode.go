package backups

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// decodeOptionalBody decodes a request body that is allowed to be ABSENT but
// not allowed to be malformed.
//
// Two endpoints assigned the decode error to the blank identifier so an empty
// body would fall through to defaults. That also swallowed a syntax or type
// error, and on both endpoints the defaults are the WIDEST operation available:
// an unparsed restore ran as a full restore over the live site and every
// schema instead of the files-only or single-database restore that was asked
// for, and an unparsed bulk backup ran over every domain on the server instead
// of the two that were named. A truncated body from any non-browser client, a
// proxy that cuts a request, or a partial write was enough.
//
// io.EOF is the only tolerated outcome: it is what Decode returns for a body
// with nothing in it. Everything else is a client error.
func decodeOptionalBody(r *http.Request, target any) error {
	if r.Body == nil {
		return nil
	}
	if err := json.NewDecoder(r.Body).Decode(target); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
