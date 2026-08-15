package mail

import (
	"strings"
	"time"
)

// Parsing the Postfix log.
//
// Postfix spreads one delivery across at least two lines, joined by the queue
// ID: qmgr records the sender, smtp/lmtp records each recipient and the outcome.
// The sender therefore has to be remembered until the outcome arrives.
//
//	... postfix/qmgr[1200]: A1B2C3: from=<a@example.com>, size=1234, nrcpt=1 (queue active)
//	... postfix/smtp[1234]: A1B2C3: to=<b@example.net>, relay=..., dsn=2.0.0, status=sent (250 2.0.0 OK)
//
// Everything below treats the file as untrusted input. A remote sender chooses
// its own envelope addresses and a remote server chooses the text Postfix quotes
// back, so both reach this parser under someone else's control.

// deliveryRecord is one delivery attempt, ready to be stored.
type deliveryRecord struct {
	QueueID   string
	At        time.Time
	Sender    string
	Recipient string
	Status    string
	Reason    string
}

// maxFieldLen bounds every stored string. The columns are sized for a full
// address; the reason column is narrower and truncating is better than letting
// one pathological line drive a row rejection.
const (
	maxAddressLen = 320
	maxReasonLen  = 255
	maxQueueIDLen = 32
)

// knownStatuses is the closed set the column accepts. Postfix also emits
// status=... values this panel has no column for, and those lines are skipped
// rather than stored under a guessed name.
var knownStatuses = map[string]bool{
	"sent": true, "deferred": true, "bounced": true, "expired": true,
}

// parseTimestamp reads either syslog format the log may be in.
//
// rsyslog's traditional format has no year, so one has to be supplied. Using
// "now" alone is wrong across a New Year boundary, where a December line read in
// January would be filed eleven months in the future; a timestamp that lands
// ahead of the reference is therefore moved back a year.
func parseTimestamp(field string, reference time.Time) (time.Time, bool) {
	field = strings.TrimSpace(field)
	if field == "" {
		return time.Time{}, false
	}
	// RFC3339 with fractional seconds, which newer rsyslog defaults to.
	if parsed, err := time.Parse(time.RFC3339Nano, field); err == nil {
		return parsed, true
	}
	parsed, err := time.Parse(time.Stamp, field)
	if err != nil {
		return time.Time{}, false
	}
	dated := time.Date(reference.Year(), parsed.Month(), parsed.Day(),
		parsed.Hour(), parsed.Minute(), parsed.Second(), 0, reference.Location())
	if dated.Sub(reference) > 24*time.Hour {
		dated = dated.AddDate(-1, 0, 0)
	}
	return dated, true
}

// splitTimestamp separates the leading timestamp from the rest of a syslog line.
func splitTimestamp(line string) (stamp, rest string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", "", false
	}
	// RFC3339 is one field; the traditional format is three ("Aug", "6",
	// "07:12:33"), and the day may be space-padded, which Fields already handles.
	if strings.Count(fields[0], "-") == 2 && strings.Contains(fields[0], "T") {
		return fields[0], strings.Join(fields[1:], " "), true
	}
	if len(fields) < 4 {
		return "", "", false
	}
	// time.Stamp wants the day right-aligned in two columns.
	day := fields[1]
	if len(day) == 1 {
		day = " " + day
	}
	return fields[0] + " " + day + " " + fields[2], strings.Join(fields[3:], " "), true
}

// parseSender returns the queue ID and envelope sender of a qmgr line.
func parseSender(line string) (queueID, sender string, ok bool) {
	_, rest, ok := splitTimestamp(line)
	if !ok || !strings.Contains(rest, "postfix/qmgr") {
		return "", "", false
	}
	queueID, payload, ok := splitQueueID(rest)
	if !ok {
		return "", "", false
	}
	sender, ok = bracketedValue(payload, "from=")
	if !ok {
		return "", "", false
	}
	return queueID, sanitize(sender, maxAddressLen), true
}

// parseDelivery returns one recipient's outcome from an smtp, lmtp or local line.
func parseDelivery(line string, reference time.Time) (deliveryRecord, bool) {
	stamp, rest, ok := splitTimestamp(line)
	if !ok {
		return deliveryRecord{}, false
	}
	if !strings.Contains(rest, "postfix/smtp") && !strings.Contains(rest, "postfix/lmtp") &&
		!strings.Contains(rest, "postfix/local") && !strings.Contains(rest, "postfix/error") {
		return deliveryRecord{}, false
	}
	queueID, payload, ok := splitQueueID(rest)
	if !ok {
		return deliveryRecord{}, false
	}
	recipient, ok := bracketedValue(payload, "to=")
	if !ok {
		return deliveryRecord{}, false
	}
	status, reason, ok := splitStatus(payload)
	if !ok {
		return deliveryRecord{}, false
	}
	at, ok := parseTimestamp(stamp, reference)
	if !ok {
		return deliveryRecord{}, false
	}
	return deliveryRecord{
		QueueID:   queueID,
		At:        at,
		Recipient: sanitize(recipient, maxAddressLen),
		Status:    status,
		Reason:    sanitize(reason, maxReasonLen),
	}, true
}

// splitQueueID pulls the hex queue ID out of "postfix/smtp[123]: A1B2C3: rest".
func splitQueueID(rest string) (queueID, payload string, ok bool) {
	colon := strings.Index(rest, ": ")
	if colon == -1 {
		return "", "", false
	}
	rest = rest[colon+2:]
	colon = strings.Index(rest, ": ")
	if colon == -1 {
		return "", "", false
	}
	queueID = strings.TrimSpace(rest[:colon])
	if queueID == "" || len(queueID) > maxQueueIDLen || !isHexish(queueID) {
		return "", "", false
	}
	return queueID, rest[colon+2:], true
}

// bracketedValue reads the <...> value of a key, e.g. from=<a@example.com>.
func bracketedValue(payload, key string) (string, bool) {
	idx := strings.Index(payload, key+"<")
	if idx == -1 {
		return "", false
	}
	rest := payload[idx+len(key)+1:]
	before, _, ok := strings.Cut(rest, ">")
	if !ok {
		return "", false
	}
	return before, true
}

// splitStatus reads "status=sent (250 2.0.0 OK)" into its two halves.
func splitStatus(payload string) (status, reason string, ok bool) {
	_, rest, found := strings.Cut(payload, "status=")
	if !found {
		return "", "", false
	}
	// Cut hands back the whole remainder as the first half when there is no
	// space, which is the "status with no reason" case the caller expects.
	value, trailer, _ := strings.Cut(rest, " ")
	status = strings.TrimSpace(value)
	reason = strings.TrimSpace(trailer)
	if !knownStatuses[status] {
		return "", "", false
	}
	reason = strings.TrimPrefix(reason, "(")
	reason = strings.TrimSuffix(reason, ")")
	return status, reason, true
}

// sanitize makes a log-derived string safe to store and to display.
//
// A remote peer controls both the envelope addresses and the text Postfix quotes
// back from it. Storing that verbatim would let it write its own lines into any
// view that renders the value, so every control character, CR and LF is dropped
// rather than escaped, and the result is bounded.
func sanitize(value string, limit int) string {
	var out strings.Builder
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			continue
		}
		out.WriteRune(r)
		if out.Len() >= limit {
			break
		}
	}
	return strings.TrimSpace(out.String())
}

func isHexish(value string) bool {
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'F', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// addressDomain returns the lower-cased domain part of an envelope address.
func addressDomain(address string) string {
	if idx := strings.LastIndex(address, "@"); idx != -1 {
		return strings.ToLower(address[idx+1:])
	}
	return ""
}
