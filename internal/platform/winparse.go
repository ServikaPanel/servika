package platform

// This file holds the parts of the Windows provider that are pure data work:
// deriving a name, reading what a Windows tool printed, shaping it into what
// the panel answers. It carries NO build tag on purpose.
//
// Everything here is a trap that only shows up against a real Windows host, and
// a test that can only run on Windows is a test nobody runs. Keeping the
// parsing here means the traps are measured on every build, on every machine,
// while the exec and filesystem half stays in windows.go where it belongs.

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"hash/fnv"
	"io"
	"regexp"
	"strings"
	"time"
)

// domainPattern is what the Windows side accepts as a domain name. It is
// stricter than the panel's own validation on purpose: the value becomes an
// appcmd argument and a directory name.
var domainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// eventLogs is the set of logs the agent will read. The value is passed
// straight to wevtutil, so free text would be both an argument injection and a
// way to read any log on the host.
var eventLogs = map[string]bool{"System": true, "Application": true, "Security": true}

const (
	// messageRunes caps one event message. The cut is by RUNE, not by byte: a
	// byte cut splits a multi-byte character in half and puts a broken string
	// into the JSON answer.
	messageRunes = 2000

	// maxEvents bounds one event read, taskLimit one task listing. A server can
	// carry thousands of scheduled tasks and a list screen does not need them.
	maxEvents = 200
	taskLimit = 300

	// userPrefix starts every derived account name.
	userPrefix = "sv_"

	// bodyRunes is how much of the domain survives into the account name.
	bodyRunes = 8
)

// systemUserFor derives a Windows local account name from a domain.
//
// A SAM account name is at most 20 characters, so this cannot be the long name
// the Linux side uses. The shape is "sv_" (3) + body (<=8) + the FULL 32 bits of
// FNV-1a as hex (8) = at most 19.
//
// The body is truncated, so two domains sharing a prefix are told apart by the
// hash alone. 32 bits, not 16: at 16 bits two domains with the same prefix
// collide at about a 50% chance within ~256 domains, which is reachable on
// purpose. The hash is NOT the only defense either - creating a site refuses to
// take over a directory whose owner marker names a different domain, so even a
// collision cannot serve one tenant's files as another's.
// The domain is lowercased BEFORE it is hashed. Hashing the raw value would
// give "Shop.example.com" and "shop.example.com" two different accounts for one
// site, and deletion recomputes this name as its last resort - it would then
// name an account that never existed and leave the real one orphaned.
func systemUserFor(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	h := fnv.New32a()
	_, _ = h.Write([]byte(domain))
	body := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, domain)
	if len(body) > bodyRunes {
		body = body[:bodyRunes]
	}
	return fmt.Sprintf("%s%s%08x", userPrefix, body, h.Sum32())
}

// ownerConflict reports whether a tenant directory's owner marker names a
// DIFFERENT domain from the one asking for it.
//
// Deleting a site deliberately keeps the web root, because it holds customer
// files. A deleted domain's directory therefore stays on disk, and if a hash
// collision maps a different domain onto the same account name, silently taking
// that directory over would serve one tenant's files as another's. This is the
// check that turns the collision into a refusal.
//
// An unreadable or empty marker is NOT a conflict: the directory is either new
// or was made before the marker existed. The same domain re-creating its own
// site matches its marker, so the operation stays idempotent.
func ownerConflict(marker []byte, domain string) bool {
	owner := strings.TrimSpace(string(marker))
	return owner != "" && owner != strings.ToLower(strings.TrimSpace(domain))
}

// decodeRecords reads a ConvertTo-Json answer into a list.
//
// ConvertTo-Json writes a bare OBJECT for a single result and an ARRAY for
// several. Both shapes are accepted by looking at the first byte. Assuming the
// array shape loses every host that happens to have exactly one of whatever was
// asked for, which is the common case for a service query.
//
// An empty answer is an empty list, not a failure: it means nothing matched.
func decodeRecords[T any](out []byte) ([]T, error) {
	raw := bytes.TrimSpace(out)
	if len(raw) == 0 {
		return nil, nil
	}
	if raw[0] == '{' {
		var one T
		if err := json.Unmarshal(raw, &one); err != nil {
			return nil, fmt.Errorf("could not decode the answer: %w", err)
		}
		return []T{one}, nil
	}
	var list []T
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("could not decode the answer: %w", err)
	}
	return list, nil
}

// serviceNames reads the Name fields out of a service query.
//
// A decode failure answers no names rather than an error: this feeds capability
// discovery, where an unreadable answer means "nothing proven", and failing the
// whole probe over it would take the readable capabilities down with it.
func serviceNames(out []byte) []string {
	type record struct{ Name string }
	list, err := decodeRecords[record](out)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(list))
	for _, r := range list {
		if r.Name != "" {
			names = append(names, r.Name)
		}
	}
	return names
}

// capabilitiesFromServices maps installed service names onto capability bits.
func capabilitiesFromServices(names []string) Capability {
	var c Capability
	for _, name := range names {
		key := strings.ToLower(name)
		switch {
		case strings.HasPrefix(key, "mssql"): // MSSQLSERVER and MSSQL$INSTANCE
			c |= CapMSSQL
		case key == "ftpsvc":
			c |= CapFTP
		case key == "dns":
			c |= CapDNS
		case strings.HasPrefix(key, "mysql"):
			c |= CapMySQL
		case strings.HasPrefix(key, "postgresql"):
			c |= CapPostgreSQL
		}
	}
	return c
}

// EventRecord is one line of the agent's event answer.
type EventRecord struct {
	Time   string // "2006-01-02 15:04:05", local time
	Log    string
	Source string
	ID     int
	Level  string // "error" | "warning" | "info"
	Text   string
}

// wevtEvent is one <Event> node of wevtutil's RenderedXml output.
//
// The level comes from System/Level, which is a NUMBER. RenderingInfo/Level is
// deliberately unused: that text is localised, so it reads "Error" on one host
// and "Hata" on another.
type wevtEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     int `xml:"EventID"`
		Level       int `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Channel string `xml:"Channel"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	RenderingInfo struct {
		Message string `xml:"Message"`
	} `xml:"RenderingInfo"`
}

// parseEvents reads wevtutil's output into records.
//
// wevtutil does NOT produce a single root element: the output is a run of
// <Event>...</Event> nodes one after another. xml.Unmarshal expects one
// document and fails on the second node with "unexpected token", so the stream
// is walked token by token and every Event is decoded on its own.
//
// The input is run through ToValidUTF8 first, because bytes leaking from the
// host's code page otherwise stop the decoder on an unrelated event.
func parseEvents(fallbackLog string, out []byte) ([]EventRecord, error) {
	events := []EventRecord{}
	d := xml.NewDecoder(strings.NewReader(strings.ToValidUTF8(string(out), "�")))
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("could not read the event XML stream: %w", err)
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "Event" {
			continue
		}
		var ev wevtEvent
		if err := d.DecodeElement(&ev, &start); err != nil {
			return nil, fmt.Errorf("could not decode an event: %w", err)
		}
		events = append(events, eventRecordOf(fallbackLog, ev))
	}
	return events, nil
}

// eventLevel maps the Windows numeric level onto the three the panel shows.
// Windows uses 1 Critical, 2 Error, 3 Warning, 4 Information, 5 Verbose and
// 0 LogAlways, which is also what a Security audit record carries.
func eventLevel(level int) string {
	switch level {
	case 1, 2:
		return "error"
	case 3:
		return "warning"
	}
	return "info"
}

// eventText picks the message, falling back to the raw data fields.
func eventText(ev wevtEvent) string {
	text := strings.TrimSpace(ev.RenderingInfo.Message)
	if text == "" {
		// The message DLL is missing or did not resolve. Assembling the data
		// fields keeps the line from being empty.
		var parts []string
		for _, d := range ev.EventData.Data {
			if v := strings.TrimSpace(d.Value); v != "" {
				parts = append(parts, v)
			}
		}
		text = strings.Join(parts, " | ")
	}
	if r := []rune(text); len(r) > messageRunes {
		text = string(r[:messageRunes])
	}
	return text
}

// eventRecordOf reduces one raw node to the panel's record.
func eventRecordOf(fallbackLog string, ev wevtEvent) EventRecord {
	// SystemTime arrives as UTC ISO-8601. An unparsable value is kept as it
	// came, because dropping the record would drop information.
	when := ev.System.TimeCreated.SystemTime
	if t, err := time.Parse(time.RFC3339Nano, when); err == nil {
		when = t.Local().Format("2006-01-02 15:04:05")
	}
	log := ev.System.Channel
	if log == "" {
		log = fallbackLog
	}
	return EventRecord{
		Time:   when,
		Log:    log,
		Source: ev.System.Provider.Name,
		ID:     ev.System.EventID,
		Level:  eventLevel(ev.System.Level),
		Text:   eventText(ev),
	}
}

// TaskRecord is one line of the agent's scheduled task answer.
type TaskRecord struct {
	Name       string // "\Folder\TaskName"
	State      string // Ready | Running | Disabled ...
	LastRun    string // "yyyy-MM-dd HH:mm:ss"; empty when it never ran
	NextRun    string // empty when nothing is scheduled
	LastResult uint32 // 0 is success, anything else is a Windows error code
}

// parseTasks reads the task listing and drops the operating system's own tasks
// unless all is set.
func parseTasks(out []byte, all bool) ([]TaskRecord, error) {
	records, err := decodeRecords[TaskRecord](out)
	if err != nil {
		return nil, err
	}
	tasks := make([]TaskRecord, 0, len(records))
	for _, t := range records {
		if !all && strings.HasPrefix(t.Name, `\Microsoft\`) {
			continue
		}
		tasks = append(tasks, t)
		if len(tasks) >= taskLimit {
			break
		}
	}
	return tasks, nil
}

// boundedCount clamps a requested event count into what the agent will read.
func boundedCount(count int) int {
	if count < 1 {
		return 1
	}
	if count > maxEvents {
		return maxEvents
	}
	return count
}
