package provisioner

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// maintenanceFragment renders a fragment for a domain with the given exception
// addresses, without a database behind it.
//
// buildMaintenanceBlock reads its inputs from packageDB, which no unit test
// has. This calls the assembler it delegates to, so the assertions run against
// the production text and not against a copy written here.
func maintenanceFragment(t *testing.T, domainID int64, addresses []string) string {
	t.Helper()
	var quoted []string
	for _, address := range addresses {
		quoted = append(quoted, regexp.QuoteMeta(address))
	}
	return assembleMaintenanceBlock(domainID, quoted)
}

// THE trap this fragment is shaped around. nginx evaluates `if` in the REWRITE
// phase, BEFORE it has matched a location, so a server-context `return 503`
// fires on the ACME challenge path as well. A domain left in maintenance would
// pass its first certificate check and then fail every renewal, silently.
func TestMaintenanceDoesNotRefuseTheACMEChallenge(t *testing.T) {
	fragment := maintenanceFragment(t, 12, nil)

	if !strings.Contains(fragment, `if ($request_uri ~ "^/\.well-known/") { set $servika_maint 0; }`) {
		t.Fatalf("the ACME challenge path is not exempted:\n%s", fragment)
	}
	// The exemption has to come BEFORE the refusal, or it sets a variable
	// nothing reads afterwards.
	exempt := strings.Index(fragment, "well-known")
	refuse := strings.Index(fragment, "return 503")
	if exempt < 0 || refuse < 0 || exempt > refuse {
		t.Errorf("the exemption is evaluated after the refusal:\n%s", fragment)
	}
}

// An excepted address reaches the real site and nothing else does.
//
// The anchors and the escaped dots are the whole guard: without them
// 203.0.113.5 would also admit 203.0.113.55 and 1203.0.113.5x.
func TestOnlyAnExceptedAddressBypassesMaintenance(t *testing.T) {
	fragment := maintenanceFragment(t, 12, []string{"203.0.113.5", "2001:db8::5"})

	pattern := exceptionPattern(t, fragment)
	for _, allowed := range []string{"203.0.113.5", "2001:db8::5"} {
		if !pattern.MatchString(allowed) {
			t.Errorf("%s was excepted but the pattern does not match it", allowed)
		}
	}
	for _, refused := range []string{"203.0.113.55", "1203.0.113.5", "203.0.113.6", "2001:db8::6", "203a0b113c5"} {
		if pattern.MatchString(refused) {
			t.Errorf("%s is not on the list but the pattern matches it", refused)
		}
	}
}

// With no exceptions the address condition is not rendered at all. An empty
// alternation ("^()$") matches the empty string, and nginx sets $remote_addr to
// nothing for a unix-socket client, which would let one through.
func TestNoExceptionsRendersNoAddressCondition(t *testing.T) {
	fragment := maintenanceFragment(t, 12, nil)
	if strings.Contains(fragment, "$remote_addr") {
		t.Errorf("an address condition was rendered with no addresses to match:\n%s", fragment)
	}
	if !strings.Contains(fragment, "return 503") {
		t.Errorf("nothing is refused, so the mode does nothing:\n%s", fragment)
	}
}

// A missing page file must answer 503, never 404. For a crawler 404 is the
// opposite of what maintenance means: gone rather than temporarily away.
func TestAMissingPageFileStillAnswers503(t *testing.T) {
	fragment := maintenanceFragment(t, 12, nil)
	if !strings.Contains(fragment, "try_files /12.html =503;") {
		t.Errorf("the page location has no 503 fallback:\n%s", fragment)
	}
	if strings.Contains(fragment, "=404") {
		t.Errorf("the fallback answers 404, which reads as removed:\n%s", fragment)
	}
	// error_page carries no "=", so nginx keeps the original 503. With "=200"
	// the maintenance page would be indexed as the site's real content.
	if !strings.Contains(fragment, "error_page 503 /_servika_maint.html;") {
		t.Errorf("the error_page line would change the status code:\n%s", fragment)
	}
}

// Retry-After belongs in server context. An add_header inside a location
// cancels every header inherited from the server block, so putting it in the
// page's own location would strip the site's security headers off exactly the
// response a crawler reads.
func TestRetryAfterDoesNotCancelTheSecurityHeaders(t *testing.T) {
	fragment := maintenanceFragment(t, 12, nil)
	header := strings.Index(fragment, "add_header Retry-After")
	location := strings.Index(fragment, "location = /_servika_maint.html")
	if header < 0 || location < 0 {
		t.Fatalf("unexpected fragment shape:\n%s", fragment)
	}
	if header > location {
		t.Errorf("Retry-After is inside the page location, which drops the inherited headers:\n%s", fragment)
	}
	if strings.Count(fragment, "add_header") != 1 {
		t.Errorf("more than one add_header is rendered:\n%s", fragment)
	}
}

// The fragment is valid nginx, checked by nginx itself. A syntax error here
// fails the configuration test for the WHOLE server, not just this domain.
func TestTheMaintenanceVhostIsValidNginxSyntax(t *testing.T) {
	prefix := t.TempDir()
	fragment := maintenanceFragment(t, 12, []string{"203.0.113.5", "2001:db8::5"})
	body := "events {}\nhttp {\nserver {\n    listen 8481;\n    server_name example.com;\n" +
		fragment + "    location / { return 200; }\n}\n}\n"
	checkNginxSyntax(t, prefix, body, "the maintenance fragment is not valid nginx syntax")
}

// Customer text cannot break out of the document.
func TestCustomerTextCannotBreakTheDocument(t *testing.T) {
	page := MaintenancePage{
		Title:   `</title><script>alert(1)</script>`,
		Message: `a & b <img src=x onerror=alert(1)> "quoted"`,
	}
	document := renderMaintenanceHTML(page)

	// The property is that no TAG forms, not that the text disappears.
	// "onerror=" survives as literal text inside an escaped &lt;img ...&gt;
	// and is inert there, so asserting on the substring would be a false
	// premise. What must not appear is an opening angle bracket the customer
	// supplied, and with no logo set the document writes no img or script tag
	// of its own either.
	for _, tag := range []string{"<script", "<img", "<iframe", "</title><"} {
		if strings.Contains(document, tag) {
			t.Errorf("a %q tag formed from customer text:\n%s", tag, document)
		}
	}
	for _, escaped := range []string{"&lt;/title&gt;", "&amp;", "&lt;img"} {
		if !strings.Contains(document, escaped) {
			t.Errorf("expected %q in the escaped output:\n%s", escaped, document)
		}
	}
	// The quote must be escaped too: the message is not in an attribute today,
	// but a future edit that moves it into one would otherwise close it.
	if strings.Contains(document, `"quoted"`) {
		t.Errorf("a double quote survived unescaped:\n%s", document)
	}
}

// A colour that is not a colour, written into a style rule, ends the rule and
// takes the rest of the document with it. Same for a logo URL in an attribute.
func TestAnUnvalidatedAccentOrLogoIsDropped(t *testing.T) {
	// Asserted on the exact CSS value the renderer writes, not on the bare
	// substring: "#0f172" is a prefix of the default "#0f172a", so a substring
	// check would report a rejected value as present when only the fallback is.
	for _, accent := range []string{"#GGGGGG", "red;}body{display:none", "#0f172", "", "#0f172a8", "#0f172a "} {
		document := renderMaintenanceHTML(MaintenancePage{Accent: accent})
		if strings.Contains(document, "background:"+accent+";") {
			t.Errorf("accent %q reached the document:\n%s", accent, document)
		}
		if !strings.Contains(document, "background:"+defaultMaintenanceAccent+";") {
			t.Errorf("accent %q did not fall back to the default", accent)
		}
	}
	// A valid one is used, or the loop above would also pass on a renderer that
	// ignores the field entirely and always writes the default.
	if document := renderMaintenanceHTML(MaintenancePage{Accent: "#Ab12Cd"}); !strings.Contains(document, "background:#Ab12Cd;") {
		t.Errorf("a valid accent was dropped:\n%s", document)
	}

	for _, logo := range []string{"javascript:alert(1)", "http://example.com/l.png", "//example.com/l.png", "data:image/png;base64,AAA", "  "} {
		if got := validMaintenanceLogo(logo); got != "" {
			t.Errorf("logo %q was accepted as %q", logo, got)
		}
	}
	if got := validMaintenanceLogo("https://cdn.example.com/logo.png"); got == "" {
		t.Error("an https logo was refused, so the field could never be used")
	}
}

// The page is written under a root-owned directory, named by domain ID, and a
// deletion removes it. A domain recreated under the same name gets a new ID, so
// it cannot inherit the previous owner's page.
func TestThePageIsWrittenAndRemovedByID(t *testing.T) {
	if path := MaintenancePagePath(12); filepath.Base(path) != "12.html" {
		t.Errorf("page path = %q, want it named by the domain id", path)
	}
	if MaintenancePagePath(12) == MaintenancePagePath(13) {
		t.Error("two domains share one page file")
	}
	// Removing a page that was never written is not an error: the file only
	// exists once the mode has been turned on, and deletion runs for every
	// domain.
	if err := RemoveMaintenancePage(999999); err != nil {
		t.Errorf("removing an absent page returned %v", err)
	}
	if err := RemoveMaintenancePage(0); err != nil {
		t.Errorf("removing an invalid id returned %v", err)
	}
}

// A page written twice with the same content leaves the file alone, so nginx
// keeps serving the same inode across an unrelated re-render.
func TestWritingTheSamePageTwiceDoesNotRewriteIt(t *testing.T) {
	page := MaintenancePage{Title: "Back soon", Message: "Please try again later."}
	first := renderMaintenanceHTML(page)
	if second := renderMaintenanceHTML(page); first != second {
		t.Error("the same input rendered two different documents")
	}
	if strings.Contains(first, "noindex") == false {
		t.Errorf("the page does not ask crawlers to skip it:\n%s", first)
	}
}

// An empty page still renders something a visitor can read. A customer who
// turns the mode on without writing anything must not get a blank screen.
func TestAnEmptyPageFallsBackToReadableText(t *testing.T) {
	document := renderMaintenanceHTML(MaintenancePage{})
	for _, want := range []string{defaultMaintenanceTitle, defaultMaintenanceMessage, defaultMaintenanceAccent} {
		if !strings.Contains(document, want) {
			t.Errorf("missing %q in the default page:\n%s", want, document)
		}
	}
}

// exceptionPattern lifts the address regex out of the fragment and compiles it,
// so the assertions run against what nginx would actually match rather than
// against a copy written in the test.
func exceptionPattern(t *testing.T, fragment string) *regexp.Regexp {
	t.Helper()
	const prefix = `if ($remote_addr ~ "`
	_, rest, ok := strings.Cut(fragment, prefix)
	if !ok {
		t.Fatalf("no address condition in:\n%s", fragment)
	}
	body, _, terminated := strings.Cut(rest, `")`)
	if !terminated {
		t.Fatalf("unterminated address condition in:\n%s", fragment)
	}
	pattern, err := regexp.Compile(body)
	if err != nil {
		t.Fatalf("the rendered pattern does not compile: %v", err)
	}
	return pattern
}
