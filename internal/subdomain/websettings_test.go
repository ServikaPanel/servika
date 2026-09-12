package subdomain

import (
	"strings"
	"testing"

	"servika/internal/nginxset"
)

func TestStaticBackendRemovesTheFastCGIPass(t *testing.T) {
	web := renderWebSettings(nginxset.Defaults(), "app.example.com", false)
	web.Static = true
	config := vhost("app.example.com", "/home/c_example_com/subdomains/app.example.com",
		"/run/php-fpm-c_example_com/sub-3.sock", "", web)
	if strings.Contains(config, "fastcgi_pass") {
		t.Error("a static subdomain vhost still passes requests to PHP-FPM")
	}
	if !strings.Contains(config, "location / { try_files $uri $uri/ =404; }") {
		t.Error("a static subdomain vhost does not serve files directly")
	}
}

func TestSubdomainVhostRendersTheStoredCacheSettings(t *testing.T) {
	settings := nginxset.Defaults()
	settings.FastCgiCache = true
	settings.FastCgiCacheMinutes = 15
	settings.BrowserCacheDays = 7
	web := renderWebSettings(settings, "app.example.com", false)
	config := vhost("app.example.com", "/home/c_example_com/subdomains/app.example.com",
		"/run/php-fpm-c_example_com/sub-3.sock", "", web)
	for _, want := range []string{
		"fastcgi_cache servikacache;",
		"fastcgi_cache_valid 200 301 302 15m;",
		"set $skip_cache 0;",
		"expires 7d;",
	} {
		if !strings.Contains(config, want) {
			t.Errorf("subdomain vhost is missing %q", want)
		}
	}
}

// A subdomain carries its own auth_basic blocks, and its browser-cache location
// used to label every static file publicly cacheable whatever they guarded. The
// visibility now follows the request through $remote_user, which nginx leaves
// empty when no auth_basic applied.
func TestTheSubdomainBrowserCacheDoesNotAdvertiseProtectedContentAsPublic(t *testing.T) {
	settings := nginxset.Defaults()
	settings.BrowserCacheDays = 7
	web := renderWebSettings(settings, "app.example.com", false)
	protected := "    auth_basic \"Authentication Required\";\n    auth_basic_user_file /home/c_example_com/.htpasswd;\n"

	config := vhost("app.example.com", "/home/c_example_com/subdomains/app.example.com",
		"/run/php-fpm-c_example_com/sub-3.sock", protected, web)

	if strings.Contains(config, `add_header Cache-Control "public"`) {
		t.Error("the browser-cache location still advertises every static file as publicly cacheable")
	}
	for _, want := range []string{
		`set $servika_cache_visibility "public";`,
		`if ($remote_user) { set $servika_cache_visibility "private"; }`,
		"add_header Cache-Control $servika_cache_visibility always;",
	} {
		if !strings.Contains(config, want) {
			t.Errorf("subdomain vhost is missing %q", want)
		}
	}
}

func TestSubdomainHSTSOnlyOnTheHTTPSVhost(t *testing.T) {
	settings := nginxset.Defaults()
	settings.HdrHSTS = true
	if plain := renderWebSettings(settings, "app.example.com", false); strings.Contains(plain.Headers, "Strict-Transport-Security") {
		t.Error("the plain HTTP subdomain vhost emits HSTS")
	}
	secure := renderWebSettings(settings, "app.example.com", true)
	if !strings.Contains(secure.Headers, "Strict-Transport-Security") {
		t.Error("the HTTPS subdomain vhost does not emit HSTS")
	}
}

func TestDisabledSecurityHeadersAreNotRendered(t *testing.T) {
	settings := nginxset.Defaults()
	settings.HdrXContentType = false
	settings.HdrReferrer = false
	web := renderWebSettings(settings, "app.example.com", false)
	if strings.Contains(web.Headers, "X-Content-Type-Options") {
		t.Error("a disabled header is still rendered")
	}
	if strings.Contains(web.Headers, "Referrer-Policy") {
		t.Error("a disabled header is still rendered")
	}
	if !strings.Contains(web.Headers, "X-XSS-Protection") {
		t.Error("an enabled header was dropped")
	}
}

func TestSubdomainInheritsParentExtraDirectivesUntilConfigured(t *testing.T) {
	// A subdomain with no row of its own renders the parent's directive block, or
	// it would answer differently from the domain it belongs to.
	parent := nginxset.Defaults()
	parent.ExtraDirectives = "add_header X-Parent yes;"
	web := renderWebSettings(parent, "app.example.com", false)
	config := vhost("app.example.com", "/home/c_example_com/subdomains/app.example.com",
		"/run/php-fpm-c_example_com/sub-3.sock", "", web)
	if !strings.Contains(config, "add_header X-Parent yes;") {
		t.Error("the subdomain vhost dropped the inherited directives")
	}
}

// The plan's ceiling reaches a subdomain through its own column, not through the
// customer-writable directive block. A subdomain that dropped it would reject
// uploads the parent accepts.
func TestSubdomainRendersTheInheritedUploadCeiling(t *testing.T) {
	parent := nginxset.Defaults()
	parent.ClientMaxBody = "8192m"
	web := renderWebSettings(parent, "app.example.com", false)

	plain := vhost("app.example.com", "/home/c_example_com/subdomains/app.example.com",
		"/run/php-fpm-c_example_com/sub-3.sock", "", web)
	if got := strings.Count(plain, "client_max_body_size 8192m;"); got != 1 {
		t.Errorf("the plain subdomain vhost states the ceiling %d times, want exactly 1", got)
	}

	secure := vhostSSL("app.example.com", "/home/c_example_com/subdomains/app.example.com",
		"/run/php-fpm-c_example_com/sub-3.sock", "/etc/ssl/x.pem", "/etc/ssl/x.key", "", web)
	if got := strings.Count(secure, "client_max_body_size 8192m;"); got != 1 {
		t.Errorf("the HTTPS subdomain vhost states the ceiling %d times, want exactly 1", got)
	}
}

// A plan that states no ceiling must leave the directive out entirely rather than
// render an empty one, which nginx refuses to load.
func TestSubdomainWithNoCeilingStatesNoDirective(t *testing.T) {
	web := renderWebSettings(nginxset.Defaults(), "app.example.com", false)
	config := vhost("app.example.com", "/home/c_example_com/subdomains/app.example.com",
		"/run/php-fpm-c_example_com/sub-3.sock", "", web)
	if strings.Contains(config, "client_max_body_size") {
		t.Error("a subdomain with no plan ceiling still states client_max_body_size")
	}
}
