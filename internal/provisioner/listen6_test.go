package provisioner

import (
	"strings"
	"testing"
)

// withoutHostIPv6 drives the host-has-no-IPv6 branch.
//
// A developer machine and CI both have IPv6, so the branch that keeps nginx
// alive on a kernel booted with ipv6.disable=1 would otherwise never run in any
// test anywhere.
func withoutHostIPv6(t *testing.T) {
	t.Helper()
	previous := hostHasIPv6
	hostHasIPv6 = func() bool { return false }
	t.Cleanup(func() { hostHasIPv6 = previous })
}

func withHostIPv6(t *testing.T) {
	t.Helper()
	previous := hostHasIPv6
	hostHasIPv6 = func() bool { return true }
	t.Cleanup(func() { hostHasIPv6 = previous })
}

// A host whose kernel refuses AF_INET6 must get no IPv6 listen line at all.
// nginx treats a failed bind as fatal, so one such line takes down every site
// on the server, the panel included, which leaves the operator with no screen
// to read the reason on.
func TestNoIPv6ListenLineWhenTheKernelHasNoIPv6(t *testing.T) {
	withoutHostIPv6(t)
	for _, tail := range []string{"80", "443 ssl", "8443 ssl default_server"} {
		if got := ListenIPv6(tail); got != "" {
			t.Errorf("ListenIPv6(%q) = %q on a host without IPv6", tail, got)
		}
	}
}

// The other direction. A test that only proved the line CAN be absent would
// also pass against a helper that never emits anything.
func TestTheIPv6ListenLineIsRenderedWhenTheKernelHasIPv6(t *testing.T) {
	withHostIPv6(t)
	if got := ListenIPv6("80"); got != "    listen [::]:80;\n" {
		t.Errorf("ListenIPv6(\"80\") = %q", got)
	}
	if got := ListenIPv6("443 ssl"); got != "    listen [::]:443 ssl;\n" {
		t.Errorf("ListenIPv6(\"443 ssl\") = %q", got)
	}
}

// The rendered vhost loses its IPv6 lines and stays valid nginx, and IPv4 is
// untouched in both directions: this feature adds a family, it never trades one
// for the other.
func TestAVhostWithoutIPv6IsStillValidAndStillServesIPv4(t *testing.T) {
	render := func(t *testing.T) string {
		t.Helper()
		var out strings.Builder
		if err := vhostTmpl.Execute(&out, VhostOpts{
			DomainName: "example.com",
			WebRoot:    "/home/example/public_html",
			PHPSocket:  "/run/php-fpm/example.sock",
			PHPVersion: "8.3",
		}); err != nil {
			t.Fatalf("render the vhost: %v", err)
		}
		return out.String()
	}

	withoutHostIPv6(t)
	plain := render(t)
	if strings.Contains(plain, "[::]") {
		t.Errorf("an IPv6 listen line survived on a host without IPv6:\n%s", plain)
	}
	if !strings.Contains(plain, "listen 80;") {
		t.Errorf("the IPv4 listen line was lost along with the IPv6 one:\n%s", plain)
	}

	withHostIPv6(t)
	dual := render(t)
	if !strings.Contains(dual, "listen [::]:80;") {
		t.Errorf("no IPv6 listen line on a host with IPv6:\n%s", dual)
	}
	if !strings.Contains(dual, "listen 80;") {
		t.Errorf("the IPv4 listen line is missing:\n%s", dual)
	}

	// The two renders must differ by EXACTLY the IPv6 listen lines. A weaker
	// check would not notice the line being replaced by a blank one, which
	// leaves a hole in the file, nor any other directive going missing with it.
	if got := withoutIPv6Listen(dual); got != plain {
		t.Errorf("turning IPv6 off changed more than the listen lines:\n--- want ---\n%s\n--- got ---\n%s", got, plain)
	}

	// Same sandboxing the other vhost gates use: the log paths and the
	// privileged ports are moved somewhere an unprivileged nginx -t can reach,
	// and nothing else about the body is touched.
	prefix := t.TempDir()
	body := strings.ReplaceAll(unprivilegedListen(plain), "/var/log/nginx/", prefix+"/")
	checkNginxSyntax(t, prefix,
		"events {}\nhttp {\n"+body+"}\n",
		"the IPv4-only vhost is not valid nginx")
}

// The shipped files are copied rather than rendered, so they need the same
// treatment applied to their text.
func TestTheShippedFilesLoseTheirIPv6ListenLines(t *testing.T) {
	withoutHostIPv6(t)
	for name, body := range map[string]string{
		"_default80.conf":  default80Conf,
		"_default443.conf": default443Conf,
	} {
		adjusted := adjustIPv6Listen(body)
		if strings.Contains(adjusted, "[::]") {
			t.Errorf("%s kept an IPv6 listen line:\n%s", name, adjusted)
		}
		if !strings.Contains(adjusted, "listen ") {
			t.Errorf("%s lost every listen line:\n%s", name, adjusted)
		}
	}
}

// Putting the lines BACK matters as much as removing them: a panel that stays
// IPv4-only after the operator enables IPv6 is unreachable from an IPv6 client
// with no visible reason.
func TestTheIPv6ListenLineComesBackWhenIPv6Returns(t *testing.T) {
	const stripped = "server {\n    listen 8443 ssl default_server;\n    http2 on;\n    server_name _;\n}\n"

	withHostIPv6(t)
	restored := adjustIPv6Listen(stripped)
	if !strings.Contains(restored, "    listen [::]:8443 ssl default_server;") {
		t.Fatalf("the IPv6 line was not restored:\n%s", restored)
	}
	if !strings.Contains(restored, "    listen 8443 ssl default_server;") {
		t.Errorf("the IPv4 line was lost while restoring IPv6:\n%s", restored)
	}
	// Applying it twice must not add a second copy: nginx refuses a duplicate
	// listen on the same address and port and fails the whole server.
	if twice := adjustIPv6Listen(restored); twice != restored {
		t.Errorf("the transform is not idempotent:\n%s", twice)
	}
}

// The sibling is looked for anywhere in the file. The shipped panel vhost puts
// six directives between its two listen lines, and a neighbour-only check would
// add a duplicate there.
func TestASiblingIsFoundEvenWhenItIsNotOnTheNextLine(t *testing.T) {
	withHostIPv6(t)
	const separated = "server {\n" +
		"    listen 8443 ssl default_server;\n" +
		"    ssl_certificate /etc/ssl/servika/panel.crt;\n" +
		"    http2 on;\n" +
		"    listen [::]:8443 ssl default_server;\n" +
		"}\n"
	if got := adjustIPv6Listen(separated); got != separated {
		t.Errorf("a duplicate listen line was added:\n%s", got)
	}
	if strings.Count(adjustIPv6Listen(separated), "[::]:8443") != 1 {
		t.Error("the IPv6 listen line was duplicated")
	}
}

// Only a real listen DIRECTIVE is touched. A comment or a word in prose that
// happens to start with the same text must be left alone, or a heal would eat
// documentation out of an operator's file.
func TestOnlyARealListenDirectiveIsRecognised(t *testing.T) {
	withoutHostIPv6(t)
	const body = "# listen [::]:80; is what this used to say\n" +
		"    listen 80;\n" +
		"    listen [::]:80;\n" +
		"    # nginx would listen [::]:443 ssl here\n"
	got := adjustIPv6Listen(body)
	if !strings.Contains(got, "# listen [::]:80; is what this used to say") {
		t.Errorf("a comment was removed:\n%s", got)
	}
	if strings.Contains(got, "\n    listen [::]:80;") {
		t.Errorf("the real IPv6 directive survived:\n%s", got)
	}
}

// The heal must recognise a file it stripped itself as shipped rather than
// operator-edited, or a host without IPv6 would warn on every boot and never
// receive a template update again.
func TestAStrippedShippedFileIsNotMistakenForAnOperatorEdit(t *testing.T) {
	withoutHostIPv6(t)
	stripped := adjustIPv6Listen(default80Conf)
	known := append([]string{}, knownDefault80...)
	known = append(known, contentHash(withIPv6Listen(default80Conf)))

	if action := decideVhostAction(stripped, true, stripped, known); action != vhostUpToDate {
		t.Errorf("a file this heal wrote was classified as %v, not up to date", action)
	}
	// And the dual-stack canonical text is still recognised when IPv6 returns.
	if action := decideVhostAction(default80Conf, true, withIPv6Listen(default80Conf), known); action != vhostUpToDate {
		t.Errorf("the shipped dual-stack text was classified as %v", action)
	}
}
