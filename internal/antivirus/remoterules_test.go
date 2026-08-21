package antivirus

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"servika/internal/avpackage"
)

// withSigningKey gives this build a real key pair for the duration of a test and
// clears whatever package was adopted, so tests cannot leak a rule set into each
// other.
func withSigningKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	previousKey, previousSet := rulePublicKeyHex, activeRemote.Load()
	rulePublicKeyHex = hex.EncodeToString(public)
	activeRemote.Store(nil)
	t.Cleanup(func() {
		rulePublicKeyHex = previousKey
		activeRemote.Store(previousSet)
	})
	return private
}

func signedSet(t *testing.T, key ed25519.PrivateKey, version int, produced time.Time, rules ...packagedRule) []byte {
	t.Helper()
	body, err := json.Marshal(packagedSet{Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := avpackage.Build(body, key, version, produced)
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}

func aRule(name, pattern string, score int) packagedRule {
	return packagedRule{Name: name, Score: score, Pattern: pattern, Kind: "php"}
}

// The rule that matters most, and the one the upstream design this is derived
// from lacks entirely. Every shipped weight was measured against a real clean
// corpus; a rule that arrived over the network has not been, and a critical
// finding is what automatic containment MOVES out of a customer's live site.
//
// Two things have to hold together. A remote rule is capped below the critical
// threshold so none can convict alone, AND a critical verdict needs a built-in
// match so two of them cannot add up to one either.
func TestARemoteRuleCannotDriveContainment(t *testing.T) {
	key := withSigningKey(t)
	now := time.Now()

	// A package asking for weightProof twice over. Nothing here is malformed;
	// this is exactly what a compromised signing key, or a mistake, produces.
	pkg := signedSet(t, key, 1, now,
		aRule("Remote.One", `AAAA`, weightProof),
		aRule("Remote.Two", `BBBB`, weightProof),
	)
	if _, err := adoptPackage(pkg, now); err != nil {
		t.Fatalf("a well-formed package was refused: %v", err)
	}

	content := []byte("<?php $x = 'AAAA'; $y = 'BBBB';")
	matches := evaluate(".php", content)
	if len(matches) != 2 {
		t.Fatalf("the two packaged rules produced %d matches: %+v", len(matches), matches)
	}
	for _, found := range matches {
		if !found.remote {
			t.Errorf("%s was not marked as remote", found.name)
		}
		if found.score > weightStrong {
			t.Errorf("%s carries %d, over the remote cap of %d", found.name, found.score, weightStrong)
		}
	}

	score, _, _, level := verdict(matches, 0)
	if score < scoreCritical {
		t.Fatalf("the two capped rules total %d, which is below the critical threshold, so this test would pass for the wrong reason", score)
	}
	if level != LevelSuspicious {
		t.Fatalf("two remote rules totalling %d produced %q, want %q", score, level, LevelSuspicious)
	}
}

// The guard is not vacuous: the same total from a BUILT-IN rule is still
// critical, and one remote rule beside a built-in one is too. Remote evidence
// adds to a verdict, it just cannot be the whole of one.
func TestABuiltInMatchStillReachesCritical(t *testing.T) {
	cases := []struct {
		name    string
		matches []match
		want    string
	}{
		{
			name:    "a built-in rule alone",
			matches: []match{{name: "PHP.Webshell.EvalSuperglobal", score: weightProof}},
			want:    LevelCritical,
		},
		{
			name: "a built-in rule beside a remote one",
			matches: []match{
				{name: "PHP.Evasion.ErrorSuppressedExec", score: weightModerate},
				{name: "Remote.One", score: weightStrong, remote: true},
			},
			want: LevelCritical,
		},
		{
			name: "remote rules alone, however many",
			matches: []match{
				{name: "Remote.One", score: weightStrong, remote: true},
				{name: "Remote.Two", score: weightStrong, remote: true},
				{name: "Remote.Three", score: weightStrong, remote: true},
			},
			want: LevelSuspicious,
		},
	}
	for _, item := range cases {
		if _, _, _, level := verdict(item.matches, 0); level != item.want {
			t.Errorf("%s produced %q, want %q", item.name, level, item.want)
		}
	}
}

// A signature proves authorship, not freshness. An attacker who can merely
// WITHHOLD the new package pins a server to yesterday's rules forever, with
// every check passing, and version monotonicity does not notice because the old
// package is not a downgrade from that server's point of view.
func TestAStalePackageIsRefusedAndAFreshOneIsNot(t *testing.T) {
	key := withSigningKey(t)
	now := time.Now()

	stale := signedSet(t, key, 9, now.Add(-RemoteRuleMaxAge-time.Hour), aRule("Remote.Old", `AAAA`, weightStrong))
	if _, err := adoptPackage(stale, now); !errors.Is(err, ErrRuleSetStale) {
		t.Fatalf("a package past the freshness limit answered %v", err)
	}
	if RemoteRules() != nil {
		t.Fatal("a refused package left rules in use")
	}

	fresh := signedSet(t, key, 9, now.Add(-RemoteRuleMaxAge+time.Hour), aRule("Remote.New", `AAAA`, weightStrong))
	if _, err := adoptPackage(fresh, now); err != nil {
		t.Fatalf("a package inside the freshness limit was refused: %v", err)
	}
	if len(RemoteRules()) != 1 {
		t.Fatalf("the fresh package left %d rules in use", len(RemoteRules()))
	}

	// A package stamped in the future is refused too: the timestamp is the only
	// freshness signal there is, and one that cannot be true says the package
	// was not produced the way it claims.
	future := signedSet(t, key, 10, now.Add(72*time.Hour), aRule("Remote.Ahead", `AAAA`, weightStrong))
	if _, err := adoptPackage(future, now); !errors.Is(err, ErrRuleSetStale) {
		t.Fatalf("a package stamped in the future answered %v", err)
	}
}

// A signed OLD package must not replace a newer one that is already in use, or
// an attacker who kept a copy could roll a server back to rules that miss what
// the new ones catch.
func TestAnOlderPackageDoesNotReplaceANewerOne(t *testing.T) {
	key := withSigningKey(t)
	now := time.Now()

	if _, err := adoptPackage(signedSet(t, key, 5, now, aRule("Remote.Five", `AAAA`, weightStrong)), now); err != nil {
		t.Fatal(err)
	}
	older := signedSet(t, key, 4, now, aRule("Remote.Four", `BBBB`, weightStrong))
	if _, err := adoptPackage(older, now); !errors.Is(err, ErrRuleSetNotNewer) {
		t.Fatalf("an older package answered %v", err)
	}
	if got := RemoteRuleVersion(); got != 5 {
		t.Fatalf("version %d is in use, want 5", got)
	}
	if _, err := adoptPackage(signedSet(t, key, 6, now, aRule("Remote.Six", `CCCC`, weightStrong)), now); err != nil {
		t.Fatalf("a newer package was refused: %v", err)
	}
	if got := RemoteRuleVersion(); got != 6 {
		t.Fatalf("version %d is in use after an update, want 6", got)
	}
}

// One bad pattern in a package of many must not cost the rest, and a package
// nothing can be read from must not be adopted at all.
func TestAnUncompilablePatternDropsOnlyItsOwnRule(t *testing.T) {
	key := withSigningKey(t)
	now := time.Now()

	pkg := signedSet(t, key, 1, now,
		aRule("Remote.Good", `AAAA`, weightStrong),
		aRule("Remote.Broken", `(unclosed`, weightStrong),
		aRule("Remote.AlsoGood", `BBBB`, weightModerate),
	)
	if _, err := adoptPackage(pkg, now); err != nil {
		t.Fatalf("a package with one bad pattern was refused whole: %v", err)
	}
	if got := len(RemoteRules()); got != 2 {
		t.Fatalf("%d rules survived, want 2", got)
	}

	onlyBroken := signedSet(t, key, 2, now, aRule("Remote.Broken", `(unclosed`, weightStrong))
	if _, err := adoptPackage(onlyBroken, now); err == nil {
		t.Fatal("a package in which nothing compiles was adopted")
	}
	if got := RemoteRuleVersion(); got != 1 {
		t.Fatalf("the refused package changed the version in use to %d", got)
	}
}

// A package cannot invent a file kind the walk does not open, cannot take a
// shipped rule's name, and cannot carry a name the screen could not group by.
func TestARuleTheScannerCannotHonourIsDropped(t *testing.T) {
	cases := map[string]packagedRule{
		"an unknown file kind":            {Name: "Remote.Kind", Score: 40, Pattern: "AAAA", Kind: "python"},
		"a built-in rule's name":          {Name: "PHP.Webshell.EvalSuperglobal", Score: 40, Pattern: "AAAA", Kind: "php"},
		"a name with no dot":              {Name: "Remote", Score: 40, Pattern: "AAAA", Kind: "php"},
		"a name with a path in it":        {Name: "../../etc/passwd", Score: 40, Pattern: "AAAA", Kind: "php"},
		"a score of zero":                 {Name: "Remote.Zero", Score: 0, Pattern: "AAAA", Kind: "php"},
		"a negative score":                {Name: "Remote.Negative", Score: -50, Pattern: "AAAA", Kind: "php"},
		"an empty pattern":                {Name: "Remote.Empty", Score: 40, Pattern: "", Kind: "php"},
		"a pattern over the limit":        {Name: "Remote.Huge", Score: 40, Pattern: strings.Repeat("a", maxRemotePatternBytes+1), Kind: "php"},
		"a pattern that will not compile": {Name: "Remote.Bad", Score: 40, Pattern: "(", Kind: "php"},
	}
	for name, candidate := range cases {
		if _, err := compilePackagedRule(candidate); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	// Not vacuous: a rule that breaks none of those is accepted, on every kind
	// the scanner opens.
	for _, kind := range []string{"php", "js", "htaccess", "any"} {
		if _, err := compilePackagedRule(packagedRule{
			Name: "Remote.Fine", Score: 40, Pattern: `eval\s*\(`, Kind: kind,
		}); err != nil {
			t.Errorf("a well-formed %s rule was refused: %v", kind, err)
		}
	}
}

// A build with no signing key does the whole thing in silence: no fetch, no disk
// read, no rules. That is the default and it is what every installation that
// predates this feature keeps doing.
func TestABuildWithNoKeyDoesNothing(t *testing.T) {
	previous := rulePublicKeyHex
	rulePublicKeyHex = ""
	t.Cleanup(func() { rulePublicKeyHex = previous })

	if RemoteRulesConfigured() {
		t.Fatal("an empty key reads as configured")
	}
	if err := LoadRulesFromDisk(); !errors.Is(err, ErrRuleKeyAbsent) {
		t.Errorf("LoadRulesFromDisk answered %v", err)
	}
	if _, err := adoptPackage([]byte("anything"), time.Now()); !errors.Is(err, ErrRuleKeyAbsent) {
		t.Errorf("adoptPackage answered %v", err)
	}

	// A malformed key is the same answer as none: this is a build-time constant,
	// so a bad one is a mistake made once and must not stop a panel from
	// starting.
	rulePublicKeyHex = "not hex"
	if RemoteRulesConfigured() {
		t.Error("a malformed key reads as configured")
	}
	rulePublicKeyHex = hex.EncodeToString([]byte("too short"))
	if RemoteRulesConfigured() {
		t.Error("a short key reads as configured")
	}
}

// A package somebody else signed reaches nothing, which is the whole point of
// the channel: the publication host does not have to be trusted because it
// cannot sign.
func TestAPackageFromAnotherKeyChangesNothing(t *testing.T) {
	key := withSigningKey(t)
	now := time.Now()
	if _, err := adoptPackage(signedSet(t, key, 3, now, aRule("Remote.Mine", `AAAA`, weightStrong)), now); err != nil {
		t.Fatal(err)
	}

	_, hostile, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged := signedSet(t, hostile, 99, now, aRule("Remote.Theirs", `BBBB`, weightProof))
	if _, err := adoptPackage(forged, now); !errors.Is(err, avpackage.ErrUnverified) {
		t.Fatalf("a package signed by another key answered %v", err)
	}
	if got := RemoteRuleVersion(); got != 3 {
		t.Fatalf("the forged package moved the version in use to %d", got)
	}
	if len(RemoteRules()) != 1 || RemoteRules()[0].name != "Remote.Mine" {
		t.Fatalf("the forged package changed the rules in use: %+v", RemoteRules())
	}
}

// The built-in rules are a FLOOR: a package ADDS to them and can never take one
// away. Nothing in the production code asserts this today, because it falls out
// of how evaluate() is written: the shipped set is evaluated first and remote
// matches are appended. A later refactor that merged the two sets into one slice
// "for efficiency" would reintroduce exactly the defect this pins.
//
// The case is upstream's own proof of concept. There the remote set was ASSIGNED
// over the base rather than merged, so a signed package carrying one inert rule
// at a very high version removed every base rule, and the rule that catches an
// eval(base64_decode(...)) backdoor disappeared in silence. A leaked signing key
// would then have switched detection off by DELETING rules rather than by
// adding any.
func TestAThinPackageCannotTakeABuiltInRuleAway(t *testing.T) {
	key := withSigningKey(t)
	now := time.Now()
	backdoor := []byte(`<?php eval(base64_decode($_POST['x'])); ?>`)

	before := evaluate(".php", backdoor)
	_, signatureBefore, _, levelBefore := verdict(before, 0)
	if levelBefore != LevelCritical || signatureBefore != "PHP.Webshell.EvalBase64" {
		t.Fatalf("the built-in set does not convict the sample, so this test proves nothing: %q %q",
			signatureBefore, levelBefore)
	}

	thin := signedSet(t, key, 9999, now, aRule("Remote.Inert", `zzz-this-matches-nothing-zzz`, weightStrong))
	if _, err := adoptPackage(thin, now); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if RemoteRuleVersion() != 9999 || len(RemoteRules()) != 1 {
		t.Fatalf("the package was not adopted, so the floor is untested: version %d, %d rules",
			RemoteRuleVersion(), len(RemoteRules()))
	}

	after := evaluate(".php", backdoor)
	_, signatureAfter, _, levelAfter := verdict(after, 0)
	if len(after) != len(before) || signatureAfter != signatureBefore || levelAfter != levelBefore {
		t.Fatalf("a thin package changed the built-in verdict: %d matches %q %q became %d matches %q %q",
			len(before), signatureBefore, levelBefore, len(after), signatureAfter, levelAfter)
	}

	// Not vacuous in the other direction: the same adopted package really is in
	// use, so it adds a finding to a file its own pattern matches.
	own := evaluate(".php", []byte(`<?php /* zzz-this-matches-nothing-zzz */`))
	if len(own) != 1 || !own[0].remote {
		t.Fatalf("the adopted package produced %+v on a file its own rule matches", own)
	}
}

// A package may not take a built-in rule's NAME either, which is a tighter rule
// than the floor and closes what a floor alone leaves open.
//
// Upstream's merge keeps every base ID but writes `m[k.ID] = k`, so a remote
// rule carrying a base rule's ID REPLACES its pattern. The rule count and the ID
// survive while the behaviour is neutered, which is the same class of defect one
// level down. Refusing the name outright is what makes the floor mean the
// detection rather than the label.
func TestAPackageCannotTakeABuiltInRuleName(t *testing.T) {
	_, err := compilePackagedRule(packagedRule{
		Name:    "PHP.Webshell.EvalBase64",
		Score:   weightStrong,
		Pattern: `zzz-this-matches-nothing-zzz`,
		Kind:    "php",
	})
	if err == nil {
		t.Fatal("a package replaced a built-in rule's pattern under its own name")
	}
	if !strings.Contains(err.Error(), "built-in") {
		t.Errorf("refused for the wrong reason: %v", err)
	}

	// Not vacuous: the same rule under a name of its own is accepted.
	if _, err := compilePackagedRule(packagedRule{
		Name:    "Remote.EvalBase64",
		Score:   weightStrong,
		Pattern: `zzz-this-matches-nothing-zzz`,
		Kind:    "php",
	}); err != nil {
		t.Errorf("a rule under its own name was refused: %v", err)
	}
}

// A stale package is refused and the built-in set takes over, which is the safe
// behaviour but is invisible from outside the process: a panel that adopted a
// package yesterday and one that fell back a month ago both scan and both
// report. An operator told nothing reads a scan as covering rules it never had.
func TestTheStateSaysWhichRuleSetIsRunning(t *testing.T) {
	key := withSigningKey(t)
	now := time.Now()

	before := RuleSetInUse()
	if before.Source != "builtin" || before.Version != 0 || before.Produced != "" {
		t.Fatalf("with no package adopted the state reads %+v", before)
	}
	if !before.Configured {
		t.Fatal("a build with a key reports itself unconfigured")
	}
	if before.MaxAgeDays != int(RemoteRuleMaxAge/(24*time.Hour)) {
		t.Errorf("the reported limit is %d days, not the one the code enforces", before.MaxAgeDays)
	}

	// The age comes from the package's own SIGNED stamp, never from the cache
	// file's timestamp: that file is written only when a NEWER package arrives,
	// so its age means "when a new version last came", not "how old these rules
	// are". A rule set that simply has not changed would make a file-age check
	// warn on a healthy server.
	produced := now.AddDate(0, 0, -20)
	if _, err := adoptPackage(signedSet(t, key, 12, produced, aRule("Remote.Seen", `AAAA`, weightStrong)), now); err != nil {
		t.Fatal(err)
	}
	after := RuleSetInUse()
	if after.Source != "package" || after.Version != 12 || after.Rules != 1 {
		t.Fatalf("after adopting, the state reads %+v", after)
	}
	if after.AgeDays != 20 {
		t.Errorf("age is %d days, want 20 from the signed stamp", after.AgeDays)
	}
	if after.Produced == "" {
		t.Error("the state carries no production stamp")
	}
}

// "The built-in set is running" is one answer to several different questions,
// and they need different actions: a new installation has never fetched, while a
// cache that fails its signature is a file somebody replaced on disk.
func TestTheCacheStateSeparatesWhyTheBuiltInSetIsRunning(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"a verified package":     {nil, "verified"},
		"no key in this build":   {ErrRuleKeyAbsent, "absent"},
		"no package on disk":     {os.ErrNotExist, "absent"},
		"past the freshness cap": {ErrRuleSetStale, "stale"},
		"a bad signature":        {avpackage.ErrUnverified, "refused"},
		"not a package at all":   {avpackage.ErrNotAPackage, "refused"},
	}
	for name, item := range cases {
		if got := cacheStateFrom(item.err); got != item.want {
			t.Errorf("%s reported %q, want %q", name, got, item.want)
		}
	}
}
