package provisioner

import (
	"strings"
	"testing"
)

// A password-protected document root puts auth_basic at server level, which the
// browser-cache location inherits, and the location used to answer
// Cache-Control: public. That is the one thing that lets a shared cache store a
// response to a request carrying credentials and hand it to a client that has
// none, for browser_cache_days.
//
// The visibility now follows the request: nginx sets $remote_user to the
// authenticated name and leaves it empty when no auth_basic applied. Verified
// against nginx 1.29 on the two vhosts this renders: the protected one answered
// "Cache-Control: private" and an unprotected one answered "public".
func TestTheBrowserCacheDoesNotAdvertiseProtectedContentAsPublic(t *testing.T) {
	f := withRenderSequence(t)
	opts := exampleVhost()
	opts.BrowserCache = true
	opts.BrowserCacheDays = 30
	opts.ExtraDirectives = "    auth_basic \"Authentication Required\";\n" +
		"    auth_basic_user_file /home/c_example_com/.htpasswd;\n"

	body, err := f.render(t, opts)

	if err != nil {
		t.Fatalf("renderAndReload() error = %v", err)
	}
	if strings.Contains(body, `add_header Cache-Control "public"`) {
		t.Error("the browser-cache location still advertises every static file as publicly cacheable")
	}
	assertVhostCarries(t, body, []string{
		`set $servika_cache_visibility "public";`,
		`if ($remote_user) { set $servika_cache_visibility "private"; }`,
		"add_header Cache-Control $servika_cache_visibility always;",
	}, nil)
}
