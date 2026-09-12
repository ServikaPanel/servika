package logsink

import (
	"encoding/json"
	"strings"
	"unicode"
)

// MaxBodyBytes bounds what is kept from a request body.
//
// A body past this is stored as nothing rather than truncated, because a
// truncated JSON document is not JSON and the column refuses it, and because a
// half-document is a half-answer to whoever reads the row later.
const MaxBodyBytes = 16 << 10

// redactedValue replaces a secret rather than removing its key, so a reader can
// see that the field was sent without learning what it held.
const redactedValue = "[REDACTED]"

// secretWords names the field-name WORDS whose value never reaches a log table.
//
// A field name is split into words first, so one entry covers every spelling:
// `api_key`, `apiKey` and `API-KEY` all yield the word `key`. Matching whole
// words rather than substrings is what keeps `keyboard_layout` and `monkey`
// out: a substring rule redacts those too, and a row whose ordinary fields are
// blanked is a row nobody can use.
var secretWords = map[string]bool{
	"password": true, "passwd": true, "pass": true,
	"secret": true, "token": true, "key": true, "keys": true,
	"jwt": true, "authorization": true, "auth": true,
	"cookie": true, "session": true,
	"otp": true, "totp": true, "credential": true, "credentials": true,
	"dsn": true, "signature": true, "hash": true,
}

// splitWords breaks a field name into lowercase words, at a separator and at a
// camelCase boundary alike.
func splitWords(key string) []string {
	var words []string
	var current strings.Builder
	runes := []rune(key)
	for i, r := range runes {
		switch {
		case r == '_' || r == '-' || r == '.' || r == ' ':
			words = append(words, current.String())
			current.Reset()
		case unicode.IsUpper(r) && i > 0 && !unicode.IsUpper(runes[i-1]):
			words = append(words, current.String())
			current.Reset()
			current.WriteRune(unicode.ToLower(r))
		default:
			current.WriteRune(unicode.ToLower(r))
		}
	}
	return append(words, current.String())
}

// IsSecretKey reports whether a field's value must be replaced before storing.
func IsSecretKey(key string) bool {
	for _, word := range splitWords(key) {
		if secretWords[word] {
			return true
		}
	}
	return false
}

// redactValue walks a decoded JSON value and replaces every secret it holds.
func redactValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, inner := range typed {
			if IsSecretKey(key) {
				typed[key] = redactedValue
				continue
			}
			typed[key] = redactValue(inner)
		}
		return typed
	case []any:
		for i, inner := range typed {
			typed[i] = redactValue(inner)
		}
		return typed
	default:
		return value
	}
}

// RedactJSON returns body with every secret field replaced, or ok=false when it
// must not be stored at all.
//
// A body that does not parse is REFUSED rather than stored raw. The redaction
// works on field names, so a document whose shape is unknown is a document whose
// secrets cannot be found: storing it would be the one thing this function
// exists to prevent.
func RedactJSON(body []byte) (string, bool) {
	if len(body) == 0 || len(body) > MaxBodyBytes {
		return "", false
	}
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", false
	}
	encoded, err := json.Marshal(redactValue(decoded))
	if err != nil {
		return "", false
	}
	return string(encoded), true
}

// RedactPairs returns the JSON form of a query string or a structured log
// context, with every secret value replaced.
//
// It takes the map form rather than the raw string because a query string is
// already parsed by the time it is logged, and because a value here is a plain
// string: there is no nesting to walk.
func RedactPairs(pairs map[string][]string) (string, bool) {
	if len(pairs) == 0 {
		return "", false
	}
	flat := make(map[string]string, len(pairs))
	for key, values := range pairs {
		if IsSecretKey(key) {
			flat[key] = redactedValue
			continue
		}
		flat[key] = strings.Join(values, ",")
	}
	encoded, err := json.Marshal(flat)
	if err != nil {
		return "", false
	}
	return string(encoded), true
}
