package antivirus

// A semantic layer that beats the obfuscations a regular expression cannot
// express by its nature.
//
// A regex matches a fixed shape in the text. It cannot follow a value from one
// statement to the next, so splitting a dangerous name across concatenation and
// rebuilding it through assignments defeats every pattern in the set at once:
//
//	$a = 'sy'; $b = 'stem'; $c = $a.$b; $c('id');
//
// No dangerous name appears anywhere in that file, yet it runs `system('id')`.
// `concealed.go` folds INLINE literal concatenation (`'sy'.'stem'`) and catches
// the direct form, but it cannot cross the variable boundary above. This layer
// tokenises the PHP, folds CONSTANT string concatenation, and tracks
// `$v = literal` / `$v .= literal` assignments so the rebuilt name is seen.
//
// Two independent classes are caught:
//
//  1. CONCATENATION SPLITTING: a sink name assembled from string pieces, whether
//     inline (`('sy'.'stem')(...)`), through one assignment (`$f='ev'.'al'`), or
//     transitively across several (`$c=$a.$b`), plus the compound form
//     (`$c='sy'; $c.='stem'`).
//  2. STRUCTURAL escapes a regex cannot express: a variable function whose value
//     is a constant sink name (`$f(...)`), a directly-callable superglobal
//     (`$_GET['x'](...)`), and eval/assert/create_function fed reconstructed
//     code.
//
// FALSE-POSITIVE discipline (the lesson regex taint taught: it fired on six
// clean WordPress files). A `$v(` call that is a MEMBER access (`->`/`?->`/`::`)
// is skipped, because dynamic METHOD dispatch (`$this->$action()`) is a
// legitimate framework pattern, not arbitrary code. The concat rescan reads ONLY
// eval'd reconstructed code, so documentation and UI strings never reach it. A
// directly-called superglobal has no legitimate counterpart.
//
// DoS: every folded string and symtab value is bounded by semMaxFoldBytes, so a
// billion-laughs doubling (`$b=$a.$a; $c=$b.$b`) cannot blow memory. The
// superglobal index skip is token-bounded against an O(n^2) nested
// `$_GET[$_GET[...]]`. The tokenizer is O(input) and finite.
//
// KNOWN / DEFERRED escapes (roadmap honesty, a later phase): names built with
// chr()/implode()/pack()/sprintf (a constant-string folder cannot fold them by
// nature), variable-variables `$$x` and `${'_GET'}`, a sanitiser-shaped wrapper
// that clears taint (`$c=strtolower($_POST[x])`), the queue past the token cap
// (the raw regex and decode layers still scan the whole file), and
// `call_user_func($_GET[x])` callback dispatch (an array_map data argument is a
// false-positive risk that needs its own careful detector).

import "strings"

const (
	// semRescanCap bounds the concat-rescan contribution. It is deliberately
	// BELOW scoreCritical, so a rescan match can never on its own convict a
	// file: the containment gate that other unmeasured layers (remote, decoded)
	// need a mark for is provided here by the cap alone.
	semRescanCap = 60
	// semMaxToken caps the tokenizer output (DoS).
	semMaxToken = 200000
	// semMaxFragments caps how many eval'd fragments are queued for rescan.
	semMaxFragments = 4096
	// semMaxFoldBytes bounds every folded string and symtab value (OOM guard).
	semMaxFoldBytes = 64 << 10
	// semMaxIndexTok bounds the superglobal `[ ... ]` skip (O(n^2) guard).
	semMaxIndexTok = 256
)

// semanticRescanPrefix names a rule that fired against reconstructed eval'd code
// rather than the file's literal bytes.
const semanticRescanPrefix = "Semantic.Concat:"

// semHardSink are the real PHP functions that are almost always malicious when
// their NAME is concealed and then called. call_user_func / array_map are
// OMITTED (framework false positives). assert is included (a PHP<8 function).
var semHardSink = map[string]bool{
	"system": true, "exec": true, "shell_exec": true, "passthru": true,
	"popen": true, "proc_open": true, "pcntl_exec": true, "assert": true,
	"create_function": true,
}

// semSuperglobal are the request-data arrays. A callable one is a webshell.
var semSuperglobal = map[string]bool{
	"$_GET": true, "$_POST": true, "$_REQUEST": true, "$_COOKIE": true,
	"$_SERVER": true, "$_FILES": true, "$_ENV": true,
}

// semEvalIdent execute their argument. When that argument is CONCATENATED code,
// it is concealed execution.
var semEvalIdent = map[string]bool{
	"eval": true, "assert": true, "create_function": true,
}

type semTokKind int

const (
	stStr    semTokKind = iota // string literal
	stDot                      // .
	stDotEq                    // .=
	stVar                      // $name
	stIdent                    // bareword
	stAssign                   // =
	stLParen                   // (
	stRParen                   // )
	stSemi                     // ;
	stOther                    // operator / number / [ ] / -> / :: / ?-> ...
)

type semToken struct {
	kind     semTokKind
	val      string
	constant bool // stStr: free of interpolation
}

// semState carries the fold tables while walking one file's token stream.
type semState struct {
	toks      []semToken
	symtab    map[string]string // $v -> constant string value (each <= semMaxFoldBytes)
	taint     map[string]bool   // $v is superglobal-derived
	concatVar map[string]bool   // $v came from a >=2-part concat (concealed-name candidate)
	fragments []string          // ONLY eval'd folded code, queued for rescan
	out       []match
	seen      map[string]bool
}

// semanticMatches folds constant concatenation and tracks assignments to find
// obfuscated sinks a regular expression cannot express. clearNames is the set of
// shipped rule names that already fired against the file's literal bytes; the
// concat rescan skips them so it only ever adds a NEW signal.
func semanticMatches(ext string, content []byte, clearNames map[string]bool) []match {
	if !phpish(ext) {
		return nil
	}
	toks := phpTokenize(content)
	if len(toks) == 0 {
		return nil
	}
	s := &semState{
		toks:      toks,
		symtab:    map[string]string{},
		taint:     map[string]bool{},
		concatVar: map[string]bool{},
		seen:      map[string]bool{},
	}
	for i := 0; i < len(toks); {
		i = s.step(i)
	}
	s.rescan(ext, clearNames)
	return s.out
}

// add records one detector's match, deduplicated by name so a shape firing
// twice in a file produces one match (mirrors the upstream per-id dedup).
func (s *semState) add(score int, name string) {
	if s.seen[name] {
		return
	}
	s.seen[name] = true
	s.out = append(s.out, match{name: name, score: score})
}

func semSinkName(v string) bool {
	return semHardSink[strings.ToLower(strings.TrimSpace(v))]
}

// step runs the detectors at position i and returns the next index. Assignment
// forms advance past `$v` and the operator only, so the right-hand side is
// re-walked by the main loop and any structural call inside it is still seen.
func (s *semState) step(i int) int {
	if n, ok := s.detectAssign(i); ok {
		return n
	}
	if n, ok := s.detectCompoundAssign(i); ok {
		return n
	}
	s.detectVarCall(i)
	s.detectSuperglobalCall(i)
	s.detectEvalConcat(i)
	if n, ok := s.detectDirectConcat(i); ok {
		return n
	}
	return i + 1
}

// detectAssign handles `$v = <concat>`: it folds the right-hand side, records
// the result, and reports a concealed sink name assembled by concatenation.
func (s *semState) detectAssign(i int) (int, bool) {
	if s.toks[i].kind != stVar || i+1 >= len(s.toks) || s.toks[i+1].kind != stAssign {
		return 0, false
	}
	val, parts, constant, tainted, _ := s.foldExpr(i + 2)
	s.applyAssign(s.toks[i].val, val, parts, constant, tainted)
	if constant && parts >= 2 && semSinkName(val) {
		s.add(weightProof, "PHP.Semantic.ConcatenatedSink")
	}
	return i + 2, true
}

// detectCompoundAssign handles `$v .= <concat>`, joining onto the prior value.
func (s *semState) detectCompoundAssign(i int) (int, bool) {
	if s.toks[i].kind != stVar || i+1 >= len(s.toks) || s.toks[i+1].kind != stDotEq {
		return 0, false
	}
	name := s.toks[i].val
	rhs, _, constant, tainted, _ := s.foldExpr(i + 2)
	switch {
	case constant:
		s.appendConst(name, rhs)
	case tainted:
		s.taint[name] = true
	}
	return i + 2, true
}

// appendConst joins rhs onto $name's constant value, bounded by semMaxFoldBytes.
func (s *semState) appendConst(name, rhs string) {
	joined := s.symtab[name] + rhs
	if len(joined) > semMaxFoldBytes {
		delete(s.symtab, name)
		delete(s.concatVar, name)
		return
	}
	s.symtab[name] = joined
	s.concatVar[name] = true // the prior value plus the appended piece is >=2 parts
	delete(s.taint, name)
	if semSinkName(joined) {
		s.add(weightProof, "PHP.Semantic.ConcatenatedSink")
	}
}

// detectVarCall reports a variable function whose value is a constant sink name
// (`$f(...)`) or whose value is request data (`$cb(...)`). A member access
// (`$obj->$m()`) is a dynamic method dispatch, not a global call, and is skipped.
func (s *semState) detectVarCall(i int) {
	t := s.toks[i]
	if t.kind != stVar || i+1 >= len(s.toks) || s.toks[i+1].kind != stLParen {
		return
	}
	if s.memberAccess(i) {
		return
	}
	if name, ok := s.symtab[t.val]; ok && semSinkName(name) {
		s.add(weightStrong, "PHP.Semantic.VariableSinkCall")
	}
	if s.taint[t.val] {
		s.add(weightProof, "PHP.Semantic.TaintedNameCall")
	}
}

// detectSuperglobalCall reports a directly-callable superglobal
// (`$_GET['x'](...)`). A member access is skipped for the same reason as above.
func (s *semState) detectSuperglobalCall(i int) {
	t := s.toks[i]
	if t.kind != stVar || !semSuperglobal[t.val] || s.memberAccess(i) {
		return
	}
	j := s.skipIndex(i + 1)
	if j < len(s.toks) && s.toks[j].kind == stLParen {
		s.add(weightProof, "PHP.Semantic.SuperglobalCall")
	}
}

// skipIndex steps over a `[ ... ]` subscript beginning at j, token-bounded so a
// nested `$_GET[$_GET[...]]` cannot cost O(n^2). It returns j unchanged when
// there is no subscript.
func (s *semState) skipIndex(j int) int {
	if j >= len(s.toks) || s.toks[j].kind != stOther || s.toks[j].val != "[" {
		return j
	}
	depth, steps := 0, 0
	for j < len(s.toks) && steps < semMaxIndexTok {
		switch {
		case s.toks[j].kind == stOther && s.toks[j].val == "[":
			depth++
		case s.toks[j].kind == stOther && s.toks[j].val == "]":
			depth--
			if depth == 0 {
				return j + 1
			}
		}
		j++
		steps++
	}
	return j
}

// detectEvalConcat reports eval/assert/create_function given concatenated code,
// and queues the reconstructed code for the rescan.
func (s *semState) detectEvalConcat(i int) {
	t := s.toks[i]
	if t.kind != stIdent || !semEvalIdent[strings.ToLower(t.val)] ||
		i+2 >= len(s.toks) || s.toks[i+1].kind != stLParen {
		return
	}
	arg := s.toks[i+2]
	switch {
	case arg.kind == stVar && s.concatVar[arg.val]:
		s.add(weightProof, "PHP.Semantic.EvalConcat")
		s.queueFragment(s.symtab[arg.val])
	case arg.kind == stStr && i+3 < len(s.toks) && s.toks[i+3].kind == stDot:
		val, parts, constant, _, _ := s.foldExpr(i + 2)
		if constant && parts >= 2 {
			s.add(weightProof, "PHP.Semantic.EvalConcat")
			s.queueFragment(val)
		}
	}
}

// detectDirectConcat reports a concat-built sink called inline: `'sy'.'stem'(`
// or `('sy'.'stem')(`. It advances past the folded expression when it consumed
// one, so the pieces are not re-walked as separate strings.
func (s *semState) detectDirectConcat(i int) (int, bool) {
	t := s.toks[i]
	if t.kind == stStr && i+1 < len(s.toks) && s.toks[i+1].kind == stDot {
		val, parts, constant, _, next := s.foldExpr(i)
		if constant && parts >= 2 && semSinkName(val) && next < len(s.toks) && s.toks[next].kind == stLParen {
			s.add(weightProof, "PHP.Semantic.ConcatenatedSink")
		}
		if next > i {
			return next, true
		}
	}
	if t.kind == stLParen && i+2 < len(s.toks) && s.toks[i+1].kind == stStr && s.toks[i+2].kind == stDot {
		s.detectParenConcat(i)
	}
	return 0, false
}

// detectParenConcat reports `('sy'.'stem')(` without consuming tokens, so a
// non-matching parenthesised expression is still walked normally.
func (s *semState) detectParenConcat(i int) {
	val, parts, constant, _, next := s.foldExpr(i + 1)
	if !constant || parts < 2 {
		return
	}
	end := next
	if end < len(s.toks) && s.toks[end].kind == stRParen {
		end++
	}
	if semSinkName(val) && end < len(s.toks) && s.toks[end].kind == stLParen {
		s.add(weightProof, "PHP.Semantic.ConcatenatedSink")
	}
}

func (s *semState) queueFragment(code string) {
	if code != "" && len(s.fragments) < semMaxFragments {
		s.fragments = append(s.fragments, code)
	}
}

// memberAccess reports whether the token before i is a member-access operator,
// which separates a dynamic method dispatch (`$obj->$m()`) from a plain call.
func (s *semState) memberAccess(i int) bool {
	if i == 0 {
		return false
	}
	p := s.toks[i-1]
	return p.kind == stOther && (p.val == "->" || p.val == "?->" || p.val == "::")
}

// applyAssign writes `$v = value` into the fold tables, bounded by
// semMaxFoldBytes.
func (s *semState) applyAssign(v, value string, parts int, constant, tainted bool) {
	if constant && len(value) <= semMaxFoldBytes {
		s.symtab[v] = value
		delete(s.taint, v)
		if parts >= 2 && value != "" {
			s.concatVar[v] = true
		} else {
			delete(s.concatVar, v)
		}
		return
	}
	delete(s.symtab, v)
	delete(s.concatVar, v)
	if !constant && tainted {
		s.taint[v] = true
	} else {
		delete(s.taint, v)
	}
}

// foldExpr folds the `A . B . C` concatenation starting at i, bounded by
// semMaxFoldBytes. It returns the value, the part count, whether the whole
// expression is constant, whether it is superglobal-tainted, and the index it
// advanced to.
func (s *semState) foldExpr(i int) (string, int, bool, bool, int) {
	var sb strings.Builder
	parts := 0
	constant := true
	tainted := false
	wantTerm := true
	j := i
	for j < len(s.toks) {
		t := s.toks[j]
		if !wantTerm {
			if t.kind == stDot {
				wantTerm = true
				j++
				continue
			}
			break
		}
		ct, ok := s.foldTerm(&sb, t, j, &parts, &tainted)
		if !ok {
			return sb.String(), parts, false, tainted, j
		}
		constant = constant && ct
		if sb.Len() > semMaxFoldBytes {
			return "", parts, false, tainted, j + 1
		}
		wantTerm = false
		j++
	}
	return sb.String(), parts, constant, tainted, j
}

// foldTerm folds one term of a concatenation. It returns whether the term is
// constant and whether the caller should keep folding; a term that is neither a
// constant string nor a resolvable variable stops the fold.
func (s *semState) foldTerm(sb *strings.Builder, t semToken, j int, parts *int, tainted *bool) (bool, bool) {
	switch {
	case t.kind == stStr && t.constant:
		sb.WriteString(t.val)
		*parts++
		return true, true
	case t.kind == stVar:
		return s.foldVarTerm(sb, t, j, parts, tainted), true
	default:
		return false, false
	}
}

// foldVarTerm folds a variable term. A variable immediately followed by `(` is a
// CALL, not a value, so it is not folded (it would bind a return value wrongly).
func (s *semState) foldVarTerm(sb *strings.Builder, t semToken, j int, parts *int, tainted *bool) bool {
	next := stOther
	if j+1 < len(s.toks) {
		next = s.toks[j+1].kind
	}
	if v, ok := s.symtab[t.val]; ok && next != stLParen {
		sb.WriteString(v)
		*parts++
		return true
	}
	if s.taint[t.val] || semSuperglobal[t.val] {
		*tainted = true
	}
	return false
}

// rescan runs the shipped heuristics against the reconstructed eval'd code only.
// Its combined contribution is trimmed to semRescanCap, which keeps it below the
// critical threshold so it can never convict on its own; it appears only beside
// the weightProof EvalConcat match that queued the code.
func (s *semState) rescan(ext string, clearNames map[string]bool) {
	if len(s.fragments) == 0 {
		return
	}
	blob := []byte(strings.Join(s.fragments, "\n"))
	budget := semRescanCap
	for _, h := range heuristics {
		if budget <= 0 {
			return
		}
		name := semanticRescanPrefix + h.name
		if clearNames[h.name] || s.seen[name] {
			continue
		}
		if !appliesTo(h, ext) || !h.re.Match(blob) {
			continue
		}
		add := min(h.score, budget)
		budget -= add
		s.seen[name] = true
		s.out = append(s.out, match{name: name, score: add})
	}
}

// phpTokenize is a bounded PHP tokeniser. It processes only `<?php ... ?>`
// regions; text outside them is not PHP and is skipped.
func phpTokenize(src []byte) []semToken {
	var out []semToken
	n := len(src)
	i := 0
	inPhp := false
	for i < n && len(out) < semMaxToken {
		if !inPhp {
			i, inPhp = openTag(src, i)
			continue
		}
		i, inPhp = tokenizeOne(src, i, &out)
	}
	return out
}

// openTag advances past non-PHP text to the next PHP open tag. `<?xml` is not a
// PHP short tag (PHP itself treats it this way).
func openTag(src []byte, i int) (int, bool) {
	n := len(src)
	c := src[i]
	if c != '<' || i+1 >= n || src[i+1] != '?' {
		return i + 1, false
	}
	if i+5 <= n && strings.EqualFold(string(src[i:i+5]), "<?php") {
		return i + 5, true
	}
	if i+3 <= n && string(src[i:i+3]) == "<?=" {
		return i + 3, true
	}
	if i+5 <= n && strings.EqualFold(string(src[i+2:i+5]), "xml") {
		return i + 2, false
	}
	return i + 2, true
}

// tokenizeOne reads one token (or skips whitespace/comments/close tag) starting
// at i, appends it to out, and returns the next index and whether still in PHP.
func tokenizeOne(src []byte, i int, out *[]semToken) (int, bool) {
	n := len(src)
	c := src[i]
	switch {
	case c == '?' && i+1 < n && src[i+1] == '>':
		return i + 2, false
	case c == ' ' || c == '\t' || c == '\n' || c == '\r':
		return i + 1, true
	case c == '/' && i+1 < n && src[i+1] == '/', c == '#':
		return skipLine(src, i), true
	case c == '/' && i+1 < n && src[i+1] == '*':
		return skipBlockComment(src, i), true
	}
	return tokenizeToken(src, i, out), true
}

func skipLine(src []byte, i int) int {
	for i < len(src) && src[i] != '\n' {
		i++
	}
	return i
}

func skipBlockComment(src []byte, i int) int {
	n := len(src)
	i += 2
	for i+1 < n && (src[i] != '*' || src[i+1] != '/') {
		i++
	}
	return i + 2
}

// tokenizeToken reads one non-trivia token and appends it.
func tokenizeToken(src []byte, i int, out *[]semToken) int {
	n := len(src)
	c := src[i]
	switch {
	case c == '\'':
		val, ni := singleQuote(src, i)
		*out = append(*out, semToken{kind: stStr, val: val, constant: true})
		return ni
	case c == '"':
		val, constant, ni := doubleQuote(src, i)
		*out = append(*out, semToken{kind: stStr, val: val, constant: constant})
		return ni
	case c == '<' && i+2 < n && src[i+1] == '<' && src[i+2] == '<':
		val, constant, ni := heredoc(src, i)
		*out = append(*out, semToken{kind: stStr, val: val, constant: constant})
		return ni
	case c == '$':
		j := scanWord(src, i+1)
		*out = append(*out, semToken{kind: stVar, val: string(src[i:j])})
		return j
	case isLetterByte(c) || c == '_':
		j := scanWord(src, i)
		*out = append(*out, semToken{kind: stIdent, val: string(src[i:j])})
		return j
	}
	return tokenizeOperator(src, i, out)
}

// scanWord returns the index past an identifier body beginning at i.
func scanWord(src []byte, i int) int {
	for i < len(src) && (isLetterByte(src[i]) || isDigitByte(src[i]) || src[i] == '_') {
		i++
	}
	return i
}

// tokenizeOperator reads the punctuation tokens the fold detectors care about.
func tokenizeOperator(src []byte, i int, out *[]semToken) int {
	n := len(src)
	c := src[i]
	switch {
	case c == '.' && i+1 < n && src[i+1] == '=':
		*out = append(*out, semToken{kind: stDotEq, val: ".="})
		return i + 2
	case c == '.':
		*out = append(*out, semToken{kind: stDot})
		return i + 1
	case c == '=' && i+1 < n && (src[i+1] == '=' || src[i+1] == '>'):
		*out = append(*out, semToken{kind: stOther, val: string(src[i : i+2])})
		return i + 2
	case c == '=':
		*out = append(*out, semToken{kind: stAssign})
		return i + 1
	case c == '-' && i+1 < n && src[i+1] == '>':
		*out = append(*out, semToken{kind: stOther, val: "->"})
		return i + 2
	case c == '?' && i+2 < n && src[i+1] == '-' && src[i+2] == '>':
		*out = append(*out, semToken{kind: stOther, val: "?->"})
		return i + 3
	case c == ':' && i+1 < n && src[i+1] == ':':
		*out = append(*out, semToken{kind: stOther, val: "::"})
		return i + 2
	}
	return tokenizePunct(src, i, out)
}

// tokenizePunct reads the single-byte structural tokens.
func tokenizePunct(src []byte, i int, out *[]semToken) int {
	switch c := src[i]; c {
	case '(':
		*out = append(*out, semToken{kind: stLParen})
	case ')':
		*out = append(*out, semToken{kind: stRParen})
	case ';':
		*out = append(*out, semToken{kind: stSemi})
	case '[', ']':
		*out = append(*out, semToken{kind: stOther, val: string(c)})
	default:
		*out = append(*out, semToken{kind: stOther, val: string(c)})
	}
	return i + 1
}

// singleQuote reads '...'; the only escapes are \\ and \'.
func singleQuote(src []byte, i int) (string, int) {
	n := len(src)
	var sb strings.Builder
	i++
	for i < n {
		c := src[i]
		if c == '\\' && i+1 < n && (src[i+1] == '\\' || src[i+1] == '\'') {
			sb.WriteByte(src[i+1])
			i += 2
			continue
		}
		if c == '\'' {
			return sb.String(), i + 1
		}
		sb.WriteByte(c)
		i++
		if sb.Len() > semMaxFoldBytes {
			return sb.String(), skipToQuote(src, i, '\'')
		}
	}
	return sb.String(), i
}

// doubleQuote reads "..."; a $ or { makes it NON-constant (interpolation), and
// \xNN / \NNN are resolved so a hex-hidden sink name folds ("\x73\x79...m").
func doubleQuote(src []byte, i int) (string, bool, int) {
	n := len(src)
	var sb strings.Builder
	constant := true
	i++
	for i < n {
		c := src[i]
		if c == '\\' && i+1 < n {
			i = doubleQuoteEscape(src, i, &sb, &constant)
			continue
		}
		if c == '$' || c == '{' {
			constant = false
		}
		if c == '"' {
			return sb.String(), constant, i + 1
		}
		sb.WriteByte(c)
		i++
		if sb.Len() > semMaxFoldBytes {
			return sb.String(), false, skipToQuote(src, i, '"')
		}
	}
	return sb.String(), constant, i
}

// doubleQuoteEscape resolves one backslash escape inside a double-quoted string
// and returns the next index. A resolved escape that pushes the value past the
// fold ceiling marks the string non-constant.
func doubleQuoteEscape(src []byte, i int, sb *strings.Builder, constant *bool) int {
	n := len(src)
	nx := src[i+1]
	var next int
	switch {
	case nx == '\\' || nx == '"' || nx == '$':
		sb.WriteByte(nx)
		next = i + 2
	case nx == 'n':
		sb.WriteByte('\n')
		next = i + 2
	case nx == 't':
		sb.WriteByte('\t')
		next = i + 2
	case nx == 'x' && i+2 < n && isHexByte(src[i+2]):
		next = writeHexEscape(src, i, sb)
	case nx >= '0' && nx <= '7':
		next = writeOctalEscape(src, i, sb)
	default:
		sb.WriteByte(nx)
		next = i + 2
	}
	if sb.Len() > semMaxFoldBytes {
		*constant = false
	}
	return next
}

// writeHexEscape resolves \xNN (one or two hex digits) and returns the next
// index.
func writeHexEscape(src []byte, i int, sb *strings.Builder) int {
	n := len(src)
	h := i + 2
	val, count := 0, 0
	for h < n && count < 2 && isHexByte(src[h]) {
		val = val*16 + hexVal(src[h])
		h++
		count++
	}
	sb.WriteByte(byte(val))
	return h
}

// writeOctalEscape resolves \NNN (one to three octal digits) and returns the
// next index.
func writeOctalEscape(src []byte, i int, sb *strings.Builder) int {
	n := len(src)
	h := i + 1
	val, count := 0, 0
	for h < n && count < 3 && src[h] >= '0' && src[h] <= '7' {
		val = val*8 + int(src[h]-'0')
		h++
		count++
	}
	sb.WriteByte(byte(val))
	return h
}

// heredoc reads <<<EOT / <<<'EOT' (nowdoc). A nowdoc is constant; a heredoc is
// constant when it carries no interpolation.
func heredoc(src []byte, i int) (string, bool, int) {
	n := len(src)
	j := i + 3
	for j < n && (src[j] == ' ' || src[j] == '\t') {
		j++
	}
	nowdoc := false
	if j < n && (src[j] == '\'' || src[j] == '"') {
		nowdoc = src[j] == '\''
		j++
	}
	labelStart := j
	j = scanWord(src, j)
	label := string(src[labelStart:j])
	if label == "" {
		return "", false, i + 3
	}
	for j < n && src[j] != '\n' {
		j++
	}
	if j < n {
		j++
	}
	return heredocBody(src, j, label, nowdoc)
}

// heredocBody reads from bodyStart to the closing label line.
func heredocBody(src []byte, bodyStart int, label string, nowdoc bool) (string, bool, int) {
	n := len(src)
	j := bodyStart
	for j < n {
		lineStart := j
		for j < n && src[j] != '\n' {
			j++
		}
		line := strings.TrimRight(string(src[lineStart:j]), "\r")
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == label || strings.HasPrefix(trimmed, label+";") {
			body := string(src[bodyStart:lineStart])
			constant := nowdoc || !strings.ContainsAny(body, "${")
			if len(body) > semMaxFoldBytes {
				constant = false
			}
			if j < n {
				j++
			}
			return body, constant, j
		}
		if j < n {
			j++
		}
	}
	return "", false, j
}

// skipToQuote advances past the remainder of an over-long literal to its closing
// quote (the value already exceeded the fold ceiling).
func skipToQuote(src []byte, i int, q byte) int {
	for i < len(src) && src[i] != q {
		i++
	}
	if i < len(src) {
		i++
	}
	return i
}

func isLetterByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isDigitByte(c byte) bool { return c >= '0' && c <= '9' }

func isHexByte(c byte) bool {
	return isDigitByte(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return int(c-'A') + 10
	}
}
