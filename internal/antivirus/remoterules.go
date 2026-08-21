package antivirus

// Malware rules that arrive in a signed package, beside the ones compiled into
// this binary.
//
// # What a remote rule may and may not do
//
// Every weight in rules.go was chosen against a measured clean corpus:
// WordPress core plus the five most-installed plugins, 8536 real PHP files, on
// which the whole shipped set reports NOTHING. That measurement is what makes
// the evidence tiers usable, and a rule that arrived over the network has not
// had it. So a remote rule is admitted on tighter terms than a shipped one:
//
//   - its weight is CAPPED at weightStrong, below scoreCritical, so no single
//     remote rule can convict a file;
//   - and a critical verdict requires at least one BUILT-IN match (see verdict),
//     so two remote rules cannot add up to one either.
//
// Both are needed, and the second is the one the upstream design this is derived
// from lacks entirely: there, a signed rule carrying weight 100 and the pattern
// "." convicts every file on every server, and automatic containment then MOVES
// them out of live sites. Reporting is reversible and containment is not, so
// remote evidence can raise a file to suspicious and no further on its own.
//
// # What travels, and what does not
//
// Only PATTERN rules travel. Ten of the panel's detections are Go code rather
// than regular expressions (the two taint rules, the entropy line, the concealed
// function name, the five location rules and the WordPress extra-file verdict),
// and they stay in the binary. A package is not a complete rule set and must
// never be treated as one.
//
// # The trust chain
//
// The package is verified by internal/avpackage against a public key compiled
// into this binary, whose private half never reaches the publication host. That
// is what makes serving the package from an ordinary GitHub path safe: a
// compromised mirror cannot sign. A package that does not verify is REFUSED and
// the built-in set keeps running; there is no state in which the scanner has no
// rules at all.
//
// The disk copy is verified too, on every read. It is written only after a
// package verified, but the file outlives the process that wrote it and a
// signature check costs nothing next to a scan.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync/atomic"
	"time"

	"servika/internal/avpackage"
	"servika/internal/config"
)

// rulePublicKeyHex is the Ed25519 public half of the rule-signing key, hex
// encoded. Its private half is generated and held OFFLINE by the maintainer
// (scripts/servika_sign.go -genkey) and never reaches CI or the publication
// host, which is the entire reason the host does not have to be trusted.
//
// An EMPTY value means no signing key has been configured for this build, and
// the whole remote path is then skipped: no fetch, no disk read, no log line
// per attempt. That is the default, and it is what every installation that
// predates this feature keeps doing.
//
// A public key is not a secret and belongs in the repository once the key
// exists; it is a var rather than a const so a build can also inject one with
// -ldflags "-X servika/internal/antivirus.rulePublicKeyHex=<hex>", and so the
// tests can exercise a real key pair.
var rulePublicKeyHex = ""

const (
	// RemoteRuleMaxAge is how old a package may be before it stops being used.
	//
	// A signature proves authorship, not freshness: one made a year ago verifies
	// exactly as well today. Without an age limit, an attacker who can merely
	// WITHHOLD the new package (a mirror that answers with an old file, a
	// resolver that points somewhere stale) pins a server to yesterday's rules
	// forever, with every check passing and nothing to see. Version
	// monotonicity does not help, because the old package is not a downgrade
	// from the server's point of view: it is what it already has.
	//
	// Expiry costs nothing that was not already true: the built-in set takes
	// over, which is exactly what a panel with no package at all runs. The price
	// is that the channel has to be re-signed to stay effective, which is the
	// right way round.
	RemoteRuleMaxAge = 60 * 24 * time.Hour

	// maxRemoteRules and maxRemotePatternBytes bound what a package can ask the
	// scanner to do. Go's RE2 carries no backtracking, so the classic
	// catastrophic blow-up is closed by the engine itself; what is left is
	// memory and time, and this text becomes a regular expression run against
	// every file on the server.
	maxRemoteRules        = 512
	maxRemotePatternBytes = 4096

	// ruleFetchInterval is how often the panel looks for a newer package. Rules
	// change on the order of days, and the fetch is one small GET.
	ruleFetchInterval = 6 * time.Hour
	ruleFetchTimeout  = 30 * time.Second
	maxRuleRedirects  = 5
)

// ruleKindExtensions maps a package's declared file kind onto the extension
// lists the scanner already owns.
//
// A package names a KIND rather than listing extensions, so it cannot invent a
// file type the walk does not open or scope a PHP pattern onto JavaScript. The
// lists themselves stay in rules.go, where they are written once.
func ruleKindExtensions(kind string) ([]string, bool) {
	switch kind {
	case "php":
		return phpExts, true
	case "js":
		return jsExts, true
	case "htaccess":
		return []string{extHTAccess}, true
	case "any":
		return nil, true
	default:
		return nil, false
	}
}

// ruleNamePattern is what a rule may be called. The name is a stable API string:
// it is written into av_findings, grouped by the screen, and read back by
// CoreFileProtected, so it stays to the shape the shipped names already use.
var ruleNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(\.[A-Za-z0-9]+){1,3}$`)

// packagedRule is one rule as it travels.
type packagedRule struct {
	Name    string `json:"name"`
	Score   int    `json:"score"`
	Pattern string `json:"pattern"`
	Kind    string `json:"kind"`
}

// packagedSet is the package body.
type packagedSet struct {
	Rules []packagedRule `json:"rules"`
}

// remoteSet is what is actually in use.
type remoteSet struct {
	version  int
	produced time.Time
	rules    []rule
}

var activeRemote atomic.Pointer[remoteSet]

// RemoteRules returns the rules currently in use from a signed package. It is
// empty until one has been adopted, which is the state every installation starts
// in and the state a failed verification leaves untouched.
func RemoteRules() []rule {
	set := activeRemote.Load()
	if set == nil {
		return nil
	}
	return set.rules
}

// RemoteRuleVersion reports the adopted package version, or 0 when the scanner
// is running on the built-in set alone. It is what a status screen should show:
// "no package" and "a package that failed to verify" both read as 0 here, and
// the reason is in the log.
func RemoteRuleVersion() int {
	set := activeRemote.Load()
	if set == nil {
		return 0
	}
	return set.version
}

// RuleSetState is which rule set the scanner is running on right now.
//
// It answers a question nothing else did. A stale package is REFUSED and the
// built-in set takes over, which is the safe behaviour, but from outside the
// process that is indistinguishable from a panel that adopted a package
// yesterday: both scan, both report, and the fallback shows up only in the log.
// An operator who is told nothing reads a scan as covering rules it never had.
type RuleSetState struct {
	// Configured says whether this build carries a signing key at all. When it
	// is false every other field describes the built-in set and nothing is
	// wrong: that is the default and what most installations run.
	Configured bool `json:"configured"`
	// Source is "builtin" or "package".
	Source string `json:"source"`
	// Version is the adopted package version, 0 for the built-in set.
	Version int `json:"version"`
	// Produced is the package's own SIGNED production stamp, RFC3339, empty for
	// the built-in set.
	//
	// The age is taken from here rather than from the cache file's timestamp,
	// and the difference is not cosmetic. The file is written only when a NEWER
	// package is adopted, so its timestamp means "when a new version last
	// arrived", not "when the mirror was last reached". A rule set that has
	// simply not changed for two months would make a file-age check warn on a
	// perfectly healthy server.
	Produced string `json:"produced"`
	// Rules is how many packaged rules are in use, beside the built-in set.
	Rules int `json:"rules"`
	// AgeDays is how old the adopted package is, from Produced.
	AgeDays int `json:"age_days"`
	// MaxAgeDays is the panel's own freshness limit, so a reader compares
	// against the number the code enforces instead of inventing a second one.
	MaxAgeDays int `json:"max_age_days"`
}

// RuleSetInUse reports the current state.
func RuleSetInUse() RuleSetState {
	state := RuleSetState{
		Configured: RemoteRulesConfigured(),
		Source:     "builtin",
		MaxAgeDays: int(RemoteRuleMaxAge / (24 * time.Hour)),
	}
	set := activeRemote.Load()
	if set == nil {
		return state
	}
	state.Source = "package"
	state.Version = set.version
	state.Rules = len(set.rules)
	state.Produced = set.produced.UTC().Format(time.RFC3339)
	state.AgeDays = int(time.Since(set.produced) / (24 * time.Hour))
	return state
}

// rulePublicKey decodes the compiled-in key. An empty or malformed key means the
// remote path is off rather than broken: this is a build-time constant, so a bad
// one is a mistake made once and must not stop a panel from starting.
func rulePublicKey() (ed25519.PublicKey, bool) {
	if rulePublicKeyHex == "" {
		return nil, false
	}
	raw, err := hex.DecodeString(rulePublicKeyHex)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(raw), true
}

// RemoteRulesConfigured reports whether this build carries a rule-signing key at
// all. Callers use it to skip the whole path in silence rather than log a
// failure per attempt on an installation that never opted in.
func RemoteRulesConfigured() bool {
	_, ok := rulePublicKey()
	return ok
}

// ErrRuleKeyAbsent means this build carries no signing key, so there is nothing
// to verify a package against.
var ErrRuleKeyAbsent = errors.New("no malware rule signing key is configured for this build")

// ErrRuleSetStale means the package verified and is older than RemoteRuleMaxAge.
var ErrRuleSetStale = errors.New("the malware rule package is older than the freshness limit")

// ErrRuleSetNotNewer means the package verified and does not supersede what is
// already in use.
var ErrRuleSetNotNewer = errors.New("the malware rule package is not newer than the one in use")

// adoptPackage verifies a package and, if it is fresh and newer, installs its
// rules. It returns the adopted version.
//
// Every refusal leaves the current set exactly as it was. There is no path here
// that ends with the scanner holding fewer rules than it started with.
func adoptPackage(raw []byte, now time.Time) (int, error) {
	key, ok := rulePublicKey()
	if !ok {
		return 0, ErrRuleKeyAbsent
	}
	header, body, err := avpackage.Open(raw, key)
	if err != nil {
		return 0, err
	}
	produced, err := header.ProducedAt()
	if err != nil {
		return 0, err
	}
	if now.Sub(produced) > RemoteRuleMaxAge {
		return 0, fmt.Errorf("%w: signed %s", ErrRuleSetStale, header.Produced)
	}
	// A package stamped in the future is refused for the same reason a stale one
	// is: the timestamp is the only freshness signal there is, and one that
	// cannot be true says the package was not produced the way it claims.
	if produced.Sub(now) > 24*time.Hour {
		return 0, fmt.Errorf("%w: signed %s, which is in the future", ErrRuleSetStale, header.Produced)
	}
	if current := activeRemote.Load(); current != nil && header.Version <= current.version {
		return 0, fmt.Errorf("%w: %d is not above %d", ErrRuleSetNotNewer, header.Version, current.version)
	}

	rules, err := compilePackagedSet(body)
	if err != nil {
		return 0, err
	}
	activeRemote.Store(&remoteSet{version: header.Version, produced: produced, rules: rules})
	return header.Version, nil
}

// CheckRulePackageBody reports how many rules of a candidate package body this
// scanner would actually use, and refuses a body it could use nothing from.
//
// It exists for the offline signing tool. A package whose rules are all dropped
// verifies perfectly and detects nothing, and the only moment that can be caught
// is before it is signed: afterwards it is a valid package that quietly does
// nothing, on every server that adopts it.
func CheckRulePackageBody(body []byte) (int, error) {
	rules, err := compilePackagedSet(body)
	if err != nil {
		return 0, err
	}
	return len(rules), nil
}

// compilePackagedSet turns a verified body into rules.
//
// A rule that does not compile is DROPPED and the rest of the set is kept: one
// bad pattern in a package of two hundred must not cost the other hundred and
// ninety-nine. A malformed body is a different matter and refuses the whole
// package, because at that point nothing about it can be read.
func compilePackagedSet(body []byte) ([]rule, error) {
	var packaged packagedSet
	if err := json.Unmarshal(body, &packaged); err != nil {
		return nil, fmt.Errorf("the rule package body is not valid JSON: %w", err)
	}
	if len(packaged.Rules) == 0 {
		return nil, errors.New("the rule package carries no rules")
	}
	if len(packaged.Rules) > maxRemoteRules {
		return nil, fmt.Errorf("the rule package carries %d rules, over the %d ceiling",
			len(packaged.Rules), maxRemoteRules)
	}

	out := make([]rule, 0, len(packaged.Rules))
	seen := make(map[string]bool, len(packaged.Rules))
	for _, candidate := range packaged.Rules {
		compiled, err := compilePackagedRule(candidate)
		if err != nil {
			log.Printf("antivirus: dropping packaged rule %q: %v", candidate.Name, err)
			continue
		}
		if seen[compiled.name] {
			log.Printf("antivirus: dropping packaged rule %q: the name appears twice", candidate.Name)
			continue
		}
		seen[compiled.name] = true
		out = append(out, compiled)
	}
	if len(out) == 0 {
		return nil, errors.New("no rule in the package could be compiled")
	}
	return out, nil
}

func compilePackagedRule(candidate packagedRule) (rule, error) {
	var empty rule
	if !ruleNamePattern.MatchString(candidate.Name) {
		return empty, errors.New("the name is not a dotted signature name")
	}
	// A packaged rule may not take a shipped rule's name. The name is what the
	// screen groups by and what CoreFileProtected reads, so two rules answering
	// to one name make a finding impossible to interpret.
	for _, shipped := range heuristics {
		if shipped.name == candidate.Name {
			return empty, errors.New("the name belongs to a built-in rule")
		}
	}
	if candidate.Score <= 0 {
		return empty, errors.New("the score is not positive")
	}
	if len(candidate.Pattern) == 0 || len(candidate.Pattern) > maxRemotePatternBytes {
		return empty, fmt.Errorf("the pattern is %d bytes, outside 1..%d",
			len(candidate.Pattern), maxRemotePatternBytes)
	}
	exts, ok := ruleKindExtensions(candidate.Kind)
	if !ok {
		return empty, fmt.Errorf("%q is not a file kind this scanner opens", candidate.Kind)
	}
	expression, err := regexp.Compile(candidate.Pattern)
	if err != nil {
		return empty, fmt.Errorf("the pattern does not compile: %w", err)
	}

	// The cap, not a refusal. A package asking for more weight than a remote
	// rule may carry is not hostile in itself, and dropping the rule would lose
	// a detection over a number; what must not happen is the rule convicting a
	// file on its own, and clamping is exactly what prevents that.
	score := candidate.Score
	if score > weightStrong {
		score = weightStrong
	}
	return rule{name: candidate.Name, score: score, re: expression, exts: exts}, nil
}

// printRulesFlag is the argument servika-verify passes.
const printRulesFlag = "print-av-rules"

// PrintRuleSetIfAsked answers "-print-av-rules" and reports whether it did.
//
// servika-verify is a shell script and the package is a binary container, so
// parsing the signed header in shell would mean a second reader of a format
// that already has one. This hands the panel's own answer to the shell, exactly
// as -print-ports hands it the panel's ports rather than growing a second
// parser.
//
// Like that flag it runs before config.Load, which requires the JWT and secret
// keys: reporting which rules are loaded is not a reason to need them, and the
// tool has to work on an installation broken enough to be worth verifying.
//
// It loads the cached package first, because this process is not the panel and
// holds nothing in memory. That read verifies the signature, so a tampered
// cache reports the built-in set, which is what the panel would run.
func PrintRuleSetIfAsked() bool {
	if len(os.Args) < 2 || (os.Args[1] != "-"+printRulesFlag && os.Args[1] != "--"+printRulesFlag) {
		return false
	}
	// The load narrates through log, which writes to stderr and would sit in the
	// middle of a caller's output. This mode reports rather than narrates.
	log.SetOutput(io.Discard)
	cache := cacheStateFrom(LoadRulesFromDisk())
	state := RuleSetInUse()

	// Plain KEY=VALUE lines so a shell reads them field by field. Never a form
	// that invites eval: this output is parsed by a tool running as root.
	fmt.Printf("configured=%s\n", yesNo(state.Configured))
	fmt.Printf("source=%s\n", state.Source)
	fmt.Printf("cache=%s\n", cache)
	fmt.Printf("version=%d\n", state.Version)
	fmt.Printf("produced=%s\n", state.Produced)
	fmt.Printf("rules=%d\n", state.Rules)
	fmt.Printf("age_days=%d\n", state.AgeDays)
	fmt.Printf("max_age_days=%d\n", state.MaxAgeDays)
	return true
}

// cacheStateFrom names WHY the built-in set is in use, which "source=builtin"
// alone cannot.
//
// A panel that has never fetched a package and one whose cached package fails
// its signature both run the built-in set, and they need different actions: the
// first is an ordinary new installation, the second is a file that was replaced
// on disk. This is the same separation the container itself makes between a
// download that went wrong and a package somebody else made.
func cacheStateFrom(err error) string {
	switch {
	case err == nil:
		return "verified"
	case errors.Is(err, ErrRuleKeyAbsent), errors.Is(err, os.ErrNotExist):
		return "absent"
	case errors.Is(err, ErrRuleSetStale):
		return "stale"
	default:
		return "refused"
	}
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

// LoadRulesFromDisk adopts the package the panel last verified, if there is one.
//
// This is what the scan worker and the real-time watcher call: both are separate
// processes with no business fetching anything, and the panel is the only thing
// that writes this file. The signature is checked here too, because the file
// outlives the process that wrote it.
//
// An absent file, an unconfigured key and a package that does not verify all
// leave the built-in set running, which is why this returns an error for a
// caller to log rather than one to act on.
func LoadRulesFromDisk() error {
	if !RemoteRulesConfigured() {
		return ErrRuleKeyAbsent
	}
	path := config.AVRulesFile()
	// #nosec G304 -- a fixed root-owned state path from the panel's own configuration.
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	version, err := adoptPackage(raw, time.Now())
	if err != nil {
		return err
	}
	log.Printf("antivirus: malware rule package version %d adopted from %s (%d rules)",
		version, path, len(RemoteRules()))
	return nil
}

// ruleClient fetches the package.
//
// The signature is what protects this, not the transport: a hostile mirror
// cannot sign, and a package that does not verify is refused. The redirect
// policy is here because the client needs one anyway (it must count its own
// hops) and refusing to leave TLS costs nothing.
func ruleClient() *http.Client {
	return &http.Client{
		Timeout: ruleFetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRuleRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRuleRedirects)
			}
			if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return fmt.Errorf("refusing a redirect from https to %s", req.URL.Scheme)
			}
			return nil
		},
	}
}

// FetchRules looks for a newer package and adopts it, writing it to disk only
// after it has verified.
//
// The disk write comes after adoption on purpose: a package that was refused is
// not worth keeping, and writing first would let a stale or malformed file
// replace a good one that is still in use.
func FetchRules(ctx context.Context) error {
	if !RemoteRulesConfigured() {
		return ErrRuleKeyAbsent
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, config.AVRulesURL(), nil)
	if err != nil {
		return err
	}
	response, err := ruleClient().Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("the rule package endpoint answered HTTP %d", response.StatusCode)
	}
	// The ceiling is enforced while streaming rather than read off
	// Content-Length, which the server supplies.
	raw, err := io.ReadAll(io.LimitReader(response.Body, avpackage.MaxBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > avpackage.MaxBytes {
		return fmt.Errorf("the rule package is over the %d byte ceiling", avpackage.MaxBytes)
	}

	version, err := adoptPackage(raw, time.Now())
	if err != nil {
		return err
	}
	if err := writeRulesToDisk(raw); err != nil {
		// The rules are already in use; a disk that could not be written costs
		// the next restart, not this scan, so it is reported and not fatal.
		log.Printf("antivirus: rule package version %d adopted but not cached: %v", version, err)
		return nil
	}
	log.Printf("antivirus: malware rule package version %d adopted from the network (%d rules)",
		version, len(RemoteRules()))
	return nil
}

func writeRulesToDisk(raw []byte) error {
	path := config.AVRulesFile()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	temporary := path + ".new"
	// The package is signed and published, so it is not a secret, but the only
	// processes that read it are the panel, the scan worker and the watcher, all
	// of them root. Nothing is gained by making a copy of it readable to every
	// tenant on the server, and a rule set they can read is a rule set they can
	// write detections around.
	if err := os.WriteFile(temporary, raw, 0o600); err != nil {
		return err
	}
	// The rename is what makes a reader see either the old file or the new one,
	// never half of the new one.
	return os.Rename(temporary, path)
}

// StartRuleUpdater keeps the panel's copy current.
//
// Only the panel fetches. The scan worker runs inside servika-av.slice with
// nested deadlines and its budget is for reading files, and the watcher's unit
// is sandboxed for reading tenant trees; both read the disk copy the panel
// wrote. An installation with no signing key configured starts nothing.
func StartRuleUpdater(ctx context.Context) {
	if !RemoteRulesConfigured() {
		return
	}
	if err := LoadRulesFromDisk(); err != nil && !os.IsNotExist(err) {
		log.Printf("antivirus: no cached malware rule package in use: %v", err)
	}
	go func() {
		ticker := time.NewTicker(ruleFetchInterval)
		defer ticker.Stop()
		for {
			if err := FetchRules(ctx); err != nil &&
				!errors.Is(err, ErrRuleSetNotNewer) && !errors.Is(err, context.Canceled) {
				log.Printf("antivirus: malware rule package not updated: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
