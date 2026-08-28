// Package cron manages crontab entries for domain users.
package cron

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"servika/internal/config"
	"servika/internal/httpx"
	"servika/internal/notifications"
	"servika/internal/phpversion"

	"github.com/go-chi/chi/v5"
)

// runTimeout bounds a manual cron run so a wedged command cannot hold the request.
const runTimeout = 120 * time.Second

// runOutputLimit is how much combined output a manual run returns; the tail is
// kept because a failing command's error is usually at the end.
const runOutputLimit = 8192

const (
	maxTasks         = 100
	maxCommandLength = 1024
	bannerLine       = "# servika cron: this file is managed by the panel; do not edit manually"
	// metaPrefix marks the panel's own metadata comment. A task's type, PHP
	// version and enabled flag do not fit a crontab line, so they ride in a
	// comment the panel writes and reads back; crond ignores it.
	metaPrefix = "servika-meta:"
)

// Task types. An empty type reads as TypeCommand.
const (
	TypeCommand = "command"
	TypeURL     = "url"
	TypePHP     = "php"
)

// Notification preferences for a scheduled run. An empty value reads as
// NotifyNone. When a task wants a notification, its crontab command is wrapped
// in the on-host reporter so a run that crond starts still reaches the panel.
const (
	NotifyNone   = "none"   // no notification
	NotifyErrors = "errors" // notify only when the run exits non-zero
	NotifyAlways = "always" // notify on every run
)

type Task struct {
	Idx     int    `json:"idx"`
	Minute  string `json:"minute"`
	Hour    string `json:"hour"`
	Day     string `json:"day"`
	Month   string `json:"month"`
	Week    string `json:"week"`
	Command string `json:"command"`
	Comment string `json:"comment,omitempty"`
	// A disabled task's cron line is commented out with a leading '#', so crond
	// never runs it while the panel still reads and lists it.
	Enabled bool `json:"enabled"`
	// Type is how the command was authored: a raw command, a URL fetched with
	// curl, or a PHP file run with a chosen interpreter. Command always holds the
	// generated shell command that actually runs.
	Type       string `json:"type,omitempty"`
	PHPVersion string `json:"php_version,omitempty"` // Type == TypePHP: which PHP version runs it.
	// Notify is whether a scheduled run reports its outcome to the panel, and
	// when. NotifyNone (or empty) wraps nothing; the other values wrap the
	// command in the reporter.
	Notify string `json:"notify,omitempty"`
}

type Handlers struct {
	DB *sql.DB
	// SecretKey signs the domain-bound token the on-host reporter carries, so a
	// scheduled run can report its outcome without a panel session.
	SecretKey []byte
}

var (
	errDemo = errors.New("cron cannot be managed for a demo subscription")
	errBad  = errors.New("security: user without c_ prefix rejected")
)

// lookup returns the domain's system user and its id. The id is needed on the
// write paths to sign the reporter's domain-bound token.
func (h *Handlers) lookup(r *http.Request) (string, int64, error) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var systemUser string
	var isDemo int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user, is_demo FROM domains WHERE id=?`, id).
		Scan(&systemUser, &isDemo)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, os.ErrNotExist
	}
	if err != nil {
		return "", 0, err
	}
	if isDemo == 1 {
		return "", 0, errDemo
	}
	if !strings.HasPrefix(systemUser, "c_") {
		return "", 0, errBad
	}
	return systemUser, id, nil
}

// cronPath returns the domain user's crontab path.
func cronPath(systemUser string) string {
	return "/var/spool/cron/" + systemUser
}

func read(systemUser string) ([]Task, error) {
	p := cronPath(systemUser)
	// #nosec G703 G304 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return []Task{}, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return parseCrontab(f)
}

// parseCrontab turns a crontab into tasks. It is separated from read so the
// round-trip can be tested without the spool path and its chown.
func parseCrontab(r io.Reader) ([]Task, error) {
	out := make([]Task, 0)
	sc := bufio.NewScanner(r)
	var lastComment string
	var meta map[string]string
	idx := 0
	// add turns one cron line into a Task. disabled is true when the line was
	// commented out with a leading '#', which is how the panel stores a disabled
	// task; the accumulated metadata comment (if any) fills the rich fields.
	add := func(line string, disabled bool) {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			return
		}
		task := Task{
			Idx:    idx,
			Minute: fields[0], Hour: fields[1], Day: fields[2],
			Month: fields[3], Week: fields[4],
			Command: strings.Join(fields[5:], " "),
			Comment: lastComment,
			Enabled: !disabled,
			Type:    TypeCommand,
		}
		if meta != nil {
			if v := meta["type"]; v != "" {
				task.Type = v
			}
			task.PHPVersion = meta["php_version"]
			task.Notify = meta["notify"]
			if meta["enabled"] == "0" {
				task.Enabled = false
			}
			// A notifying task's cron line runs the reporter, not the command; the
			// original was stored base64'd so the panel shows and edits the real one.
			if b64 := meta["cmd"]; b64 != "" {
				if raw, err := base64.StdEncoding.DecodeString(b64); err == nil {
					task.Command = string(raw)
				}
			}
		}
		out = append(out, task)
		idx++
		lastComment = ""
		meta = nil
	}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			lastComment = ""
			meta = nil
			continue
		}
		if c, found := strings.CutPrefix(line, "#"); found {
			c = strings.TrimSpace(c)
			// The panel's own metadata comment for the NEXT task.
			if rest, ok := strings.CutPrefix(c, metaPrefix); ok {
				meta = parseMeta(strings.TrimSpace(rest))
				continue
			}
			// A disabled task is a commented-out cron line: tell it apart from a
			// human comment by whether what follows the '#' looks like a cron
			// schedule (five schedule fields then a command).
			if looksCron(c) {
				add(c, true)
				continue
			}
			// Skip the banner generated by this package; keep any other comment.
			if !strings.HasPrefix(c, "servika") {
				lastComment = c
			}
			continue
		}
		add(line, false)
	}
	return out, sc.Err()
}

// parseMeta turns a "k=v k=v" metadata comment into a map. The values carry no
// spaces (a type name, a version, a flag), so splitting on whitespace is enough.
func parseMeta(s string) map[string]string {
	m := map[string]string{}
	for kv := range strings.FieldsSeq(s) {
		if i := strings.IndexByte(kv, '='); i > 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

// looksCron reports whether a line is a cron schedule (five schedule fields then
// a command), so a commented-out task can be told apart from a human comment.
// The first field must contain only cron schedule characters.
func looksCron(s string) bool {
	fields := strings.Fields(s)
	if len(fields) < 6 {
		return false
	}
	for _, c := range fields[0] {
		if (c < '0' || c > '9') && c != '*' && c != ',' && c != '-' && c != '/' {
			return false
		}
	}
	return true
}

// notifies reports whether a task wants a notification, which is what makes its
// cron line run the reporter instead of the command directly.
func notifies(task Task) bool {
	return task.Notify == NotifyErrors || task.Notify == NotifyAlways
}

// reporterPath is the on-host helper that runs a scheduled task and reports its
// outcome to the panel.
func reporterPath() string {
	return config.OpsTool("servika-cron-report")
}

// reportToken signs a domain-bound token the reporter carries. A tenant can read
// their own crontab and so this token, but it authenticates ONLY their own
// domain, so forging it buys nothing they could not already do.
func reportToken(secret []byte, domainID int64) string {
	mac := hmac.New(sha256.New, secret)
	// hash.Hash.Write is documented never to return an error.
	_, _ = fmt.Fprintf(mac, "cron:%d", domainID)
	return hex.EncodeToString(mac.Sum(nil))
}

// serializeCrontab renders the tasks into a crontab. It is separated from write
// so the round-trip can be tested without the spool path and its chown.
func serializeCrontab(systemUser string, domainID int64, secret []byte, list []Task) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s\n", bannerLine)
	fmt.Fprintf(&buf, "# last update: %s\n\n", systemUser)
	for _, task := range list {
		// Metadata comment: only the fields that differ from the defaults, so a
		// plain enabled command task writes no metadata line at all.
		var meta []string
		if task.Type != "" && task.Type != TypeCommand {
			meta = append(meta, "type="+task.Type)
		}
		if task.PHPVersion != "" {
			meta = append(meta, "php_version="+task.PHPVersion)
		}
		if notifies(task) {
			meta = append(meta, "notify="+task.Notify)
		}
		if !task.Enabled {
			meta = append(meta, "enabled=0")
		}
		// A notifying task's cron line runs the reporter; the original command is
		// stored base64'd so read() can show and edit the real one.
		runCommand := task.Command
		if notifies(task) {
			b64 := base64.StdEncoding.EncodeToString([]byte(task.Command))
			meta = append(meta, "cmd="+b64)
			runCommand = fmt.Sprintf("%s %d %s %s %s",
				reporterPath(), domainID, task.Notify, reportToken(secret, domainID), b64)
		}
		if len(meta) > 0 {
			fmt.Fprintf(&buf, "# %s %s\n", metaPrefix, strings.Join(meta, " "))
		}
		if task.Comment != "" {
			fmt.Fprintf(&buf, "# %s\n", strings.ReplaceAll(task.Comment, "\n", " "))
		}
		// A disabled task's cron line is commented out so crond never runs it,
		// while read() still parses it back through looksCron.
		prefix := ""
		if !task.Enabled {
			prefix = "#"
		}
		fmt.Fprintf(&buf, "%s%s %s %s %s %s %s\n",
			prefix, task.Minute, task.Hour, task.Day, task.Month, task.Week, runCommand)
	}
	return buf.Bytes()
}

func write(systemUser string, domainID int64, secret []byte, list []Task) error {
	content := serializeCrontab(systemUser, domainID, secret, list)
	p := cronPath(systemUser)
	tmp := p + ".tmp"
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	if err := os.WriteFile(tmp, content, 0600); err != nil {
		return err
	}
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	_ = os.Chmod(p, 0600)
	// Set ownership to the domain user.
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	if out, err := exec.Command("chown", systemUser+":"+systemUser, p).CombinedOutput(); err != nil {
		return fmt.Errorf("chown: %s: %w", strings.TrimSpace(string(out)), err)
	}
	// SELinux context — system_cron_spool_t
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_, _ = exec.Command("restorecon", p).CombinedOutput()
	return nil
}

func validate(task Task) error {
	if task.Minute == "" || task.Hour == "" || task.Day == "" || task.Month == "" || task.Week == "" {
		return fmt.Errorf("all schedule fields are required")
	}
	if task.Command == "" {
		return fmt.Errorf("command cannot be empty")
	}
	if len(task.Command) > maxCommandLength {
		return fmt.Errorf("command is too long (max %d)", maxCommandLength)
	}
	for _, field := range []string{task.Minute, task.Hour, task.Day, task.Month, task.Week} {
		if strings.ContainsAny(field, ";|&`\n") {
			return fmt.Errorf("invalid character in schedule fields")
		}
	}
	if strings.ContainsAny(task.Command, "\n\r") {
		return fmt.Errorf("command cannot contain line breaks")
	}
	return nil
}

// taskInput is the Create/Update body: a Task plus the type-specific RAW fields
// the backend turns into Command. The raw fields never reach the crontab; only
// the generated Command does.
type taskInput struct {
	Task
	URL    string `json:"url,omitempty"`    // Type == TypeURL
	Script string `json:"script,omitempty"` // Type == TypePHP: the PHP file path
	Args   string `json:"args,omitempty"`   // Type == TypePHP: arguments
}

// dangerousMeta lists the shell metacharacters a type-generated command must not
// carry in its RAW inputs, because those inputs are placed inside a
// single-quoted argument and one of these would break out of the quoting.
const dangerousMeta = "'\n\r`;|&<>$\""

// phpBinFor returns the interpreter path for an INSTALLED PHP version, refusing
// a version that is not installed. Upstream fell back to /usr/bin/php, which
// runs the wrong interpreter silently; here the path comes from the same
// discovery the rest of the panel uses (`phpversion.AllVersions`).
func phpBinFor(version string) (string, error) {
	for _, v := range phpversion.AllVersions() {
		if v.Version == version && v.Loaded && v.PHPBin != "" {
			return v.PHPBin, nil
		}
	}
	return "", fmt.Errorf("PHP %s is not installed", version)
}

// buildCommand turns a typed input into the shell command that runs. The raw
// url/script/args are validated against shell metacharacters, because they are
// interpolated into a single-quoted argument.
func buildCommand(in taskInput) (string, error) {
	switch in.Type {
	case TypeURL:
		u := strings.TrimSpace(in.URL)
		if u == "" {
			return "", fmt.Errorf("URL cannot be empty")
		}
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return "", fmt.Errorf("URL must start with http:// or https://")
		}
		if strings.ContainsAny(u, dangerousMeta) {
			return "", fmt.Errorf("URL contains an invalid character")
		}
		return fmt.Sprintf("curl -fsS -o /dev/null --max-time 300 '%s'", u), nil
	case TypePHP:
		s := strings.TrimSpace(in.Script)
		if s == "" {
			return "", fmt.Errorf("PHP file path cannot be empty")
		}
		if strings.ContainsAny(s, dangerousMeta) {
			return "", fmt.Errorf("PHP file path contains an invalid character")
		}
		bin, err := phpBinFor(in.PHPVersion)
		if err != nil {
			return "", err
		}
		command := fmt.Sprintf("%s -q '%s'", bin, s)
		if args := strings.TrimSpace(in.Args); args != "" {
			if strings.ContainsAny(args, dangerousMeta) {
				return "", fmt.Errorf("arguments contain an invalid character")
			}
			command += " " + args
		}
		return command, nil
	default: // TypeCommand or empty
		return in.Command, nil
	}
}

// prepare derives the Task to persist from a typed input: it fills the defaults,
// generates Command, and validates the result.
func prepare(in taskInput) (Task, error) {
	task := in.Task
	if task.Type == "" {
		task.Type = TypeCommand
	}
	command, err := buildCommand(in)
	if err != nil {
		return Task{}, err
	}
	task.Command = command
	if err := validate(task); err != nil {
		return Task{}, err
	}
	return task, nil
}

// installedPHPVersions lists the installed PHP versions, so the frontend's
// PHP-task version selector offers only versions that exist on this server.
func installedPHPVersions() []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range phpversion.AllVersions() {
		if v.Loaded && !seen[v.Version] {
			seen[v.Version] = true
			out = append(out, v.Version)
		}
	}
	return out
}

func statusFromErr(err error) int {
	switch err {
	case os.ErrNotExist:
		return http.StatusNotFound
	case errDemo:
		return http.StatusForbidden
	case errBad:
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	systemUser, _, err := h.lookup(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), "operation failed")
		return
	}
	list, err := read(systemUser)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"system_user":  systemUser,
		"total":        len(list),
		"tasks":        list,
		"php_versions": installedPHPVersions(),
	})
}

func (h *Handlers) Create(w http.ResponseWriter, r *http.Request) {
	systemUser, domainID, err := h.lookup(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), "operation failed")
		return
	}
	var in taskInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	task, err := prepare(in)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	list, err := read(systemUser)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	if len(list) >= maxTasks {
		httpx.WriteError(w, http.StatusBadRequest, fmt.Sprintf("at most %d tasks are allowed", maxTasks))
		return
	}
	list = append(list, task)
	if err := write(systemUser, domainID, h.SecretKey, list); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"ok": true, "idx": len(list) - 1})
}

// Update replaces one existing task in place (PUT /domains/{id}/cron/{idx}).
func (h *Handlers) Update(w http.ResponseWriter, r *http.Request) {
	systemUser, domainID, err := h.lookup(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), "operation failed")
		return
	}
	idx, _ := strconv.Atoi(chi.URLParam(r, "idx"))
	var in taskInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	task, err := prepare(in)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	list, err := read(systemUser)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	if idx < 0 || idx >= len(list) {
		httpx.WriteError(w, http.StatusNotFound, "index out of range")
		return
	}
	list[idx] = task
	if err := write(systemUser, domainID, h.SecretKey, list); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "idx": idx})
}

func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	systemUser, domainID, err := h.lookup(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), "operation failed")
		return
	}
	idx, _ := strconv.Atoi(chi.URLParam(r, "idx"))
	list, err := read(systemUser)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	if idx < 0 || idx >= len(list) {
		httpx.WriteError(w, http.StatusNotFound, "index out of range")
		return
	}
	deleted := list[idx]
	list = append(list[:idx], list[idx+1:]...)
	if err := write(systemUser, domainID, h.SecretKey, list); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": deleted})
}

// Run triggers one cron task by hand (a test/verification run). The task's command
// runs as the tenant user, with a clean environment carrying no panel secrets, a
// 120-second timeout, and the tail of the combined output returned.
//
// Security: the command is read from the tenant's OWN crontab (they wrote it) and
// was already going to run under their own identity, so this only brings the time
// forward. runuser drops to the tenant; no privilege is added. lookup enforces the
// demo and scope checks.
func (h *Handlers) Run(w http.ResponseWriter, r *http.Request) {
	systemUser, _, err := h.lookup(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), "operation failed")
		return
	}
	idx, _ := strconv.Atoi(chi.URLParam(r, "idx"))
	list, err := read(systemUser)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	if idx < 0 || idx >= len(list) {
		httpx.WriteError(w, http.StatusNotFound, "index out of range")
		return
	}
	command := list[idx].Command

	ctx, cancel := context.WithTimeout(r.Context(), runTimeout)
	defer cancel()
	// #nosec G204 G702 -- runuser drops to the validated tenant account (systemUser ^c_[A-Za-z0-9_]+$); the command is the tenant's own crontab entry, already destined to run under this identity by cron, so no new capability is granted and this only brings the run forward.
	cmd := exec.CommandContext(ctx, "runuser", "-u", systemUser, "--", "/bin/sh", "-c", command)
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/home/" + systemUser,
	}
	out, runErr := cmd.CombinedOutput()
	output := string(out)
	if len(output) > runOutputLimit {
		output = "...(truncated)\n" + output[len(output)-runOutputLimit:]
	}
	resp := map[string]any{"ok": runErr == nil, "output": output, "command": command}
	if runErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			resp["error"] = "timed out (120s); the task may still be running in the background"
		} else {
			resp["error"] = runErr.Error()
		}
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// commandSnippet trims a command for the notification's English fallback text so
// a long command line does not fill the alert.
func commandSnippet(command string) string {
	command = strings.TrimSpace(command)
	if len(command) > 80 {
		return command[:80] + "..."
	}
	return command
}

// Report turns a scheduled task's outcome, sent by the on-host reporter over the
// loopback, into a panel notification. It carries no session; the reporter
// authenticates with a domain-bound HMAC token, so a tenant can only ever report
// for their own domain, which is harmless. This is what makes the per-task
// notification setting a real preference rather than a stored value nothing reads.
func (h *Handlers) Report(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	domainID, _ := strconv.ParseInt(r.FormValue("domain_id"), 10, 64)
	token := r.FormValue("token")
	if domainID <= 0 || !hmac.Equal([]byte(token), []byte(reportToken(h.SecretKey, domainID))) {
		httpx.WriteError(w, http.StatusForbidden, "invalid token")
		return
	}
	var domainName string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name FROM domains WHERE id=?`, domainID).Scan(&domainName)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	exit, _ := strconv.Atoi(r.FormValue("exit"))
	snippet := commandSnippet(r.FormValue("cmd"))
	d := domainID
	event := notifications.Event{
		Category: "cron",
		Key:      "cron.ran",
		Level:    notifications.LevelInfo,
		Title:    "Scheduled task ran",
		Message:  fmt.Sprintf("Scheduled task ran on %s: %s", domainName, snippet),
		Params:   map[string]any{"domain": domainName, "code": exit, "command": snippet},
		DomainID: &d,
		RefType:  "domain",
		RefID:    domainID,
	}
	if exit != 0 {
		event.Key = "cron.failed"
		event.Level = notifications.LevelWarning
		event.Title = "Scheduled task failed"
		event.Message = fmt.Sprintf("Scheduled task failed on %s (exit %d): %s", domainName, exit, snippet)
	}
	// A failed notification write must not fail the report; the run already ran.
	if err := notifications.Write(r.Context(), h.DB, event); err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": false})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
