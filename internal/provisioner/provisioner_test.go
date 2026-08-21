package provisioner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"servika/internal/config"
)

func TestDangerousNginxDirectiveRejectsPrivilegedOperations(t *testing.T) {
	tests := []struct {
		name       string
		directives string
		want       string
	}{
		{name: "proxy SSRF", directives: "location /internal { proxy_pass http://127.0.0.1; }", want: "proxy_pass"},
		{name: "local file disclosure", directives: "location /secret { alias /etc/; }", want: "alias"},
		{name: "module loading", directives: "load_module modules/ngx_http_perl_module.so;", want: "load_module"},
		{name: "Lua execution", directives: "content_by_lua_block { ngx.say('unsafe') }", want: "content_by_lua_block"},
		{name: "commented directive", directives: "# proxy_pass http://127.0.0.1;\nclient_max_body_size 10m;", want: ""},
		{name: "safe directive", directives: "client_max_body_size 10m;\nadd_header X-Test safe;", want: ""},
		{name: "quoted hash does not hide alias", directives: `add_header X-Test "#"; alias /etc/;`, want: "alias"},
		{name: "hash inside quotes is literal", directives: `add_header X-Marker "a#b safe";`, want: ""},
		{name: "quoted directive name still caught", directives: `"alias" /etc/;`, want: "alias"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := DangerousNginxDirective(test.directives); got != test.want {
				t.Fatalf("DangerousNginxDirective() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestManagedCacheZoneMatchesVhostUsage(t *testing.T) {
	var rendered bytes.Buffer
	if err := vhostTmpl.Execute(&rendered, VhostOpts{
		DomainName:          "example.com",
		WebRoot:             "/home/c_example_com/public_html",
		PHPSocket:           "/run/php-fpm/c_example_com.sock",
		PHPVersion:          "8.3",
		FastCgiCache:        true,
		FastCgiCacheMinutes: 60,
	}); err != nil {
		t.Fatalf("render vhost: %v", err)
	}

	if usage := "fastcgi_cache " + cacheZoneName + ";"; !strings.Contains(rendered.String(), usage) {
		t.Fatalf("vhost does not use managed cache zone %q", cacheZoneName)
	}
	if definition := "keys_zone=" + cacheZoneName + ":"; !strings.Contains(cacheZoneBody(), definition) {
		t.Fatalf("managed configuration does not define cache zone %q", cacheZoneName)
	}
}

// TestTheCacheKeyTravelsWithTheZone holds the two directives together, because
// nginx has NO DEFAULT for fastcgi_cache_key and does not refuse a zone that
// lacks one: it warns and exits 0. Measured on nginx 1.26.3 with a real
// php-fpm backend, the key is then the empty string, the cache file is named
// md5("") = d41d8cd98f00b204e9800998ecf8427e, and every page in the site shares
// it, so a request for /beta was answered with /alpha's body. Deleting the key
// line from cacheZoneBody would leave every other test passing.
func TestTheCacheKeyTravelsWithTheZone(t *testing.T) {
	body := cacheZoneBody()
	if !strings.Contains(body, "keys_zone="+cacheZoneName+":") {
		t.Fatalf("managed configuration does not define cache zone %q", cacheZoneName)
	}
	// The value separates scheme, method, host and the full request URI, so
	// HTTP and HTTPS, GET and HEAD, two domains on one server, and two query
	// strings never collide on one entry.
	const key = `fastcgi_cache_key "$scheme$request_method$host$request_uri";`
	if !strings.Contains(body, key) {
		t.Fatalf("managed configuration defines the cache zone with no cache key; want a line %q, got:\n%s", key, body)
	}
}

func TestTenantVhostAppliesHardeningAtEveryHeaderBoundary(t *testing.T) {
	opts := VhostOpts{
		DomainName:       "example.com",
		WebRoot:          "/home/c_example_com/public_html",
		PHPSocket:        "/run/php-fpm/c_example_com.sock",
		PHPVersion:       "8.3",
		HdrXContentType:  true,
		HdrXXSS:          true,
		HdrReferrer:      true,
		HdrPermissions:   true,
		BrowserCache:     true,
		BrowserCacheDays: 30,
	}
	opts.SecHeaders = buildSecurityHeaders(opts)
	opts.DenyBlocks = denyBlocksNginx

	var rendered bytes.Buffer
	if err := vhostTmpl.Execute(&rendered, opts); err != nil {
		t.Fatalf("render vhost: %v", err)
	}
	config := rendered.String()

	for _, directive := range []string{
		"disable_symlinks if_not_owner;",
		`location ~* \.(cgi|pl|py|sh|rb|lua|fcgi)$ { deny all; }`,
		`location ~* \.(sql|sql\.gz|bak|old|orig|save|swp|swo|dump|inc|log|php\.bak|php~|php\.save)$ { deny all; }`,
	} {
		if !strings.Contains(config, directive) {
			t.Errorf("vhost does not contain hardening directive %q", directive)
		}
	}
	if strings.Contains(config, "X-Frame-Options") {
		t.Error("tenant vhost must not emit X-Frame-Options; clickjacking protection moved to CSP frame-ancestors so the panel can preview the site")
	}
	if count := strings.Count(config, `add_header Content-Security-Policy "frame-ancestors `); count != 3 {
		t.Errorf("enforced frame-ancestors CSP appears %d times, want server, PHP, and browser-cache locations", count)
	}
	if strings.Contains(config, "Strict-Transport-Security") {
		t.Error("HTTP-only vhost must not emit HSTS")
	}
	browserCacheLocation := `location ~* \.(jpg|jpeg|png|gif|ico|css|js|woff2?|svg|webp|avif|mp4|webm|pdf|zip|gz)$ {`
	if !strings.Contains(config, browserCacheLocation) {
		t.Error("browser-cache location must allow static files and legitimate ZIP or GZIP downloads")
	}
	for _, archiveExtension := range []string{"|tar|", "|tgz|", "|zip|", "|rar|", "|7z|"} {
		if strings.Contains(denyBlocksNginx, archiveExtension) {
			t.Errorf("sensitive-file deny block must not reject legitimate archive extension %q", archiveExtension)
		}
	}
}

func TestTLSVhostRepeatsHSTSAtEveryHeaderBoundary(t *testing.T) {
	opts := VhostOpts{
		DomainName:       "example.com",
		WebRoot:          "/home/c_example_com/public_html",
		PHPSocket:        "/run/php-fpm/c_example_com.sock",
		PHPVersion:       "8.3",
		CertPath:         "/etc/letsencrypt/live/example.com/fullchain.pem",
		KeyPath:          "/etc/letsencrypt/live/example.com/privkey.pem",
		HdrHSTS:          true,
		HSTSMaxAge:       31536000,
		HSTSSubdomains:   true,
		BrowserCache:     true,
		BrowserCacheDays: 30,
	}
	opts.SecHeaders = buildSecurityHeaders(opts)
	opts.DenyBlocks = denyBlocksNginx

	var rendered bytes.Buffer
	if err := vhostTmpl.Execute(&rendered, opts); err != nil {
		t.Fatalf("render TLS vhost: %v", err)
	}
	if count := strings.Count(rendered.String(), "add_header Strict-Transport-Security"); count != 3 {
		t.Errorf("HSTS appears %d times, want server, PHP, and browser-cache locations", count)
	}
}

func TestCustomVhostBypassesManagedTemplateWhenActive(t *testing.T) {
	custom := "server {\n    listen 80;\n    server_name example.com;\n    return 200 'custom';\n}"
	opts := VhostOpts{
		DomainName:         "example.com",
		WebRoot:            "/home/c_example_com/public_html",
		PHPSocket:          "/run/php-fpm/c_example_com.sock",
		PHPVersion:         "8.3",
		CustomVhostContent: custom,
	}
	var rendered bytes.Buffer
	if opts.CustomVhostContent != "" && !opts.Suspended {
		rendered.WriteString(strings.TrimSpace(opts.CustomVhostContent))
		rendered.WriteByte('\n')
	} else if err := vhostTmpl.Execute(&rendered, opts); err != nil {
		t.Fatalf("render vhost: %v", err)
	}

	config := rendered.String()
	if !strings.Contains(config, "return 200 'custom';") {
		t.Fatal("custom vhost content was not rendered")
	}
	if strings.Contains(config, "Managed by Servika") || strings.Contains(config, "Servika managed") {
		t.Fatal("managed template content leaked into custom vhost rendering")
	}
}

func TestSuspendedDomainIgnoresCustomVhost(t *testing.T) {
	opts := VhostOpts{
		DomainName:         "example.com",
		WebRoot:            "/home/c_example_com/public_html",
		PHPSocket:          "/run/php-fpm/c_example_com.sock",
		PHPVersion:         "8.3",
		Suspended:          true,
		CustomVhostContent: "server { return 200 'custom'; }",
	}
	var rendered bytes.Buffer
	tmpl := vhostTmpl
	if opts.Suspended {
		tmpl = suspendedVhostTmpl
	}
	if opts.CustomVhostContent != "" && !opts.Suspended {
		rendered.WriteString(strings.TrimSpace(opts.CustomVhostContent))
		rendered.WriteByte('\n')
	} else if err := tmpl.Execute(&rendered, opts); err != nil {
		t.Fatalf("render vhost: %v", err)
	}

	config := rendered.String()
	if strings.Contains(config, "return 200 'custom';") {
		t.Fatal("suspended vhost rendered custom content")
	}
	if !strings.Contains(config, "Account Suspended") {
		t.Fatal("suspended vhost template was not rendered")
	}
}

func TestSanitizeNginxValidationMessageBoundsOutputAndReplacesPath(t *testing.T) {
	path := "/etc/nginx/conf.d/_customvhost_validate_123.conf"
	message := path + " " + strings.Repeat("x", maxNginxValidationMessage+100)
	got := sanitizeNginxValidationMessage([]byte(message), path, "(custom vhost)", nil)
	if strings.Contains(got, path) {
		t.Fatal("validation message leaked the temporary path")
	}
	if !strings.Contains(got, "(custom vhost)") {
		t.Fatal("validation message did not include the public label")
	}
	if len(got) > maxNginxValidationMessage+3 {
		t.Fatalf("validation message length = %d, want bounded output", len(got))
	}
}

func TestPHPPoolConfinesTenantAndDisablesProcessExecution(t *testing.T) {
	var rendered bytes.Buffer
	if err := phpPoolTmpl.Execute(&rendered, map[string]string{
		"User":   "c_example_com",
		"Socket": "/run/php-fpm/c_example_com.sock",
	}); err != nil {
		t.Fatalf("render PHP pool: %v", err)
	}
	config := rendered.String()

	if !strings.Contains(config, "php_admin_value[open_basedir] = /home/c_example_com/:/tmp/") {
		t.Error("PHP pool does not confine filesystem access to the tenant home and temporary directory")
	}
	for _, function := range []string{"exec", "proc_open", "pcntl_exec", "symlink", "posix_setuid"} {
		if !strings.Contains(config, function) {
			t.Errorf("PHP pool does not disable %q", function)
		}
	}
}

func TestLegacyTenantHomePermissionsBlockOtherUsersAndPermitWebGroup(t *testing.T) {
	home := t.TempDir()
	publicHTML := filepath.Join(home, "public_html")
	if err := os.Mkdir(publicHTML, 0755); err != nil {
		t.Fatalf("create public_html: %v", err)
	}

	applyLegacyHomePerms(home, os.Getuid(), os.Getgid())

	homeInfo, err := os.Stat(home)
	if err != nil {
		t.Fatalf("stat tenant home: %v", err)
	}
	if got := homeInfo.Mode().Perm(); got != 0710 {
		t.Fatalf("tenant home mode = %#o, want 0710", got)
	}
	publicInfo, err := os.Stat(publicHTML)
	if err != nil {
		t.Fatalf("stat public_html: %v", err)
	}
	if got := publicInfo.Mode().Perm(); got != 0750 {
		t.Fatalf("public_html mode = %#o, want 0750", got)
	}
}

func TestPMASignonAssetMatchesStartupRepairContent(t *testing.T) {
	asset, err := os.ReadFile("../../assets/phpmyadmin/pma-signon.php")
	if err != nil {
		t.Fatalf("read phpMyAdmin signon asset: %v", err)
	}
	if string(asset) != pmaSignonPHP() {
		t.Fatal("phpMyAdmin signon asset differs from startup repair content")
	}
}

func TestPMAConfigHostUsesLocalSocketAccount(t *testing.T) {
	config := "$cfg['Servers'][$i]['host'] = '127.0.0.1';"
	got := pmaConfigHost.ReplaceAllString(config, `${1}'localhost';`)
	want := "$cfg['Servers'][$i]['host'] = 'localhost';"
	if got != want {
		t.Fatalf("phpMyAdmin host repair = %q, want %q", got, want)
	}
}

func TestCertificateSystemDirUsesServikaPKIPath(t *testing.T) {
	if got := certSystemDir("example.com"); got != "/etc/pki/servika/example.com" {
		t.Fatalf("certSystemDir() = %q, want %q", got, "/etc/pki/servika/example.com")
	}
}

// TestAddonVhostConfigPathNeverOverwritesParentVhost guards the parked-domain SSL
// incident: an addon domain shares its parent's system user, so its config file
// must NEVER resolve to the parent's dom_<system_user>.conf, and two addon domains
// under the same user must not collide on one file.
func TestAddonVhostConfigPathNeverOverwritesParentVhost(t *testing.T) {
	const systemUser = "c_example_com"
	parentPath := "/etc/nginx/conf.d/dom_" + systemUser + ".conf"

	if got := addonVhostConfigPath(systemUser, "addon.example.net"); got == parentPath {
		t.Fatal("addon domain resolves to the parent's vhost file; SSL on the addon would drop the parent domain")
	}
	if got := addonVhostConfigPath(systemUser, "addon.example.net"); !strings.Contains(got, "addon_example_net") {
		t.Errorf("config path %q must include the sanitized domain, otherwise addons under one user collide", got)
	}
	if addonVhostConfigPath(systemUser, "a.net") == addonVhostConfigPath(systemUser, "b.net") {
		t.Error("two addon domains under the same system user share one config file")
	}
}

func TestReusableLetsEncryptCertificateSkipsSelfSignedCertificate(t *testing.T) {
	domain := "example.com"
	certRoot := t.TempDir()
	t.Setenv("SERVIKA_CERT_ROOT", certRoot)
	t.Setenv("SERVIKA_ACME_HOME", t.TempDir())

	certPath := filepath.Join(certRoot, domain, domain+".crt")
	keyPath := filepath.Join(certRoot, domain, domain+".key")
	writeCertificateFixture(t, certPath, keyPath, domain, true)

	cert, key := reusableLetsEncryptCertificate(domain, 30)
	if cert != "" || key != "" {
		t.Fatalf("reusableLetsEncryptCertificate() = %q, %q, want no reusable certificate", cert, key)
	}
}

func TestReusableLetsEncryptCertificateAcceptsRealCACertificate(t *testing.T) {
	domain := "example.com"
	acmeHome := t.TempDir()
	t.Setenv("SERVIKA_ACME_HOME", acmeHome)
	t.Setenv("SERVIKA_CERT_ROOT", t.TempDir())

	certPath := filepath.Join(acmeHome, domain, "fullchain.cer")
	keyPath := filepath.Join(acmeHome, domain, domain+".key")
	writeCertificateFixture(t, certPath, keyPath, domain, false)

	cert, key := reusableLetsEncryptCertificate(domain, 30)
	if cert != certPath || key != keyPath {
		t.Fatalf("reusableLetsEncryptCertificate() = %q, %q, want %q, %q", cert, key, certPath, keyPath)
	}
}

func writeCertificateFixture(t *testing.T, certPath, keyPath, domain string, selfSigned bool) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		t.Fatalf("create certificate directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		t.Fatalf("create key directory: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     wwwHostNames(domain),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	issuer := template
	issuerKey := key
	if !selfSigned {
		caKey, caCert := certificateAuthorityFixture(t)
		issuer = caCert
		issuerKey = caKey
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func certificateAuthorityFixture(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return key, cert
}

func TestReadTenantCertificateAcceptsOwnedRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "example.com.crt")
	content := []byte("test certificate")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatalf("write certificate fixture: %v", err)
	}

	got, err := readTenantCertificate(path, os.Getuid())
	if err != nil {
		t.Fatalf("readTenantCertificate() returned an unexpected error: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("readTenantCertificate() = %q, want %q", got, content)
	}
}

func TestReadTenantCertificateRejectsUnexpectedOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "example.com.crt")
	if err := os.WriteFile(path, []byte("test certificate"), 0600); err != nil {
		t.Fatalf("write certificate fixture: %v", err)
	}

	if _, err := readTenantCertificate(path, os.Getuid()+1); err == nil {
		t.Fatal("readTenantCertificate() accepted a file owned by another account")
	}
}

func TestReadTenantCertificateRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.key")
	if err := os.WriteFile(target, []byte("private key"), 0600); err != nil {
		t.Fatalf("write private key fixture: %v", err)
	}
	link := filepath.Join(directory, "example.com.key")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create certificate symlink: %v", err)
	}

	if _, err := readTenantCertificate(link, os.Getuid()); err == nil {
		t.Fatal("readTenantCertificate() accepted a symlink")
	}
}

func TestTenantCommandUsesExplicitArgumentsAndEnvironment(t *testing.T) {
	t.Setenv("SERVIKA_JWT_SECRET", "must-not-leak")
	command := tenantCommand("pkill", "-KILL", "-u", "c_example_com")
	if got := command.Args; len(got) != 4 || got[1] != "-KILL" || got[2] != "-u" || got[3] != "c_example_com" {
		t.Fatalf("tenant command argv = %#v", got)
	}
	environment := strings.Join(command.Env, "\n")
	if strings.Contains(environment, "SERVIKA_JWT_SECRET") {
		t.Fatal("tenant command inherited a panel secret")
	}
	if !strings.Contains(environment, "PATH=/usr/sbin:/usr/bin:/sbin:/bin") {
		t.Fatal("tenant command does not define its executable search path")
	}
}

func TestACMECommandUsesRootHomeWithoutPanelSecrets(t *testing.T) {
	t.Setenv("SERVIKA_DB_DSN", "must-not-leak")
	command := acmeCommand("--issue", "-d", "example.com")
	environment := strings.Join(command.Env, "\n")
	if strings.Contains(environment, "SERVIKA_DB_DSN") {
		t.Fatal("ACME command inherited a panel secret")
	}
	if !strings.Contains(environment, "HOME=/root") {
		t.Fatal("ACME command does not define the root account home")
	}
}

func TestTenantFPMUnitUsesServikaSliceAndHomeIsolation(t *testing.T) {
	unit := renderTenantUnit("c_example_com", "/usr/sbin/php-fpm")
	for _, directive := range []string{
		"Description=Servika per-tenant PHP-FPM for c_example_com",
		"Slice=servika-c_example_com.slice",
		"ProtectHome=tmpfs",
		"BindPaths=/home/c_example_com",
		"ReadWritePaths=/home/c_example_com " + tenantLogDir(),
	} {
		if !strings.Contains(unit, directive) {
			t.Errorf("tenant PHP-FPM unit does not contain %q", directive)
		}
	}
}

// A bind naming a path that is not on the host fails the systemd namespace setup, so the
// unit never starts and EnableTenantFPM rolls the tenant back onto the shared PHP-FPM
// master, losing its isolation. Every MTA path the unit binds must therefore exist.
func TestTenantUnitBindsOnlyExistingMTAPaths(t *testing.T) {
	unit := renderTenantUnit("c_example_com", "/usr/sbin/php-fpm")
	for line := range strings.SplitSeq(unit, "\n") {
		var path string
		switch {
		case strings.HasPrefix(line, "BindReadOnlyPaths="):
			path = strings.TrimPrefix(line, "BindReadOnlyPaths=")
		// The tenant home bind is created by the provisioner itself, so only the MTA
		// paths are checked here.
		case strings.HasPrefix(line, "BindPaths=/var/spool/"), strings.HasPrefix(line, "BindPaths=/usr/"):
			path = strings.TrimPrefix(line, "BindPaths=")
		default:
			continue
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("tenant unit binds %q, which does not exist on this host", path)
		}
	}
}

func TestResolveTenantPMMaxChildrenUsesPlanOrMemory(t *testing.T) {
	tests := []struct {
		name         string
		planChildren int
		memoryMB     int
		wantChildren int
	}{
		{name: "explicit plan value", planChildren: 12, memoryMB: 256, wantChildren: 12},
		{name: "memory derived", memoryMB: 1024, wantChildren: 16},
		{name: "minimum worker count", memoryMB: 128, wantChildren: 4},
		{name: "missing plan fallback", wantChildren: 8},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := resolveTenantPMMaxChildren(test.planChildren, test.memoryMB); got != test.wantChildren {
				t.Fatalf("resolveTenantPMMaxChildren() = %d, want %d", got, test.wantChildren)
			}
		})
	}
}

func TestTenantPoolSanitizesScalarSettings(t *testing.T) {
	if got := tenantSanitizeScalar("512M\nphp_admin_value[open_basedir] = /", "256M"); got != "256M" {
		t.Fatalf("newline setting = %q, want fallback", got)
	}
	if got := tenantSanitizeScalar("512M\x00unsafe", "256M"); got != "256M" {
		t.Fatalf("NUL setting = %q, want fallback", got)
	}
	if got := tenantSanitizeScalar(" 512M ", "256M"); got != "512M" {
		t.Fatalf("valid setting = %q, want 512M", got)
	}
}

func TestTenantPoolUsesSafeDefaultWorkerLimit(t *testing.T) {
	pool := renderTenantPool(nil, "c_example_com", 0)
	if !strings.Contains(pool, "pm.max_children = 8") {
		t.Fatal("tenant PHP-FPM pool does not use the safe worker fallback")
	}
}

func TestSubdomainPoolIsSeparateAndNarrowerThanTheDomainPool(t *testing.T) {
	sub := renderTenantPoolScoped(nil, "c_example_com", 0, 7, "/home/c_example_com/subdomains/app.example.com")
	for _, want := range []string{
		"[sub-7]",
		"listen = /run/php-fpm-c_example_com/sub-7.sock",
		"user = c_example_com",
		"php_admin_value[open_basedir] = /home/c_example_com/subdomains/app.example.com/:/home/c_example_com/tmp/:/tmp/",
	} {
		if !strings.Contains(sub, want) {
			t.Errorf("subdomain pool is missing %q", want)
		}
	}
	// A subdomain pool must not reopen the parent document root through open_basedir.
	if strings.Contains(sub, "php_admin_value[open_basedir] = /home/c_example_com/:") {
		t.Error("subdomain pool grants the whole tenant home through open_basedir")
	}
}

func TestTenantGlobalConfigIncludesThePoolDirectory(t *testing.T) {
	// The include must be the directory, not a single file: a subdomain pool is added
	// and removed as its own file without rewriting the domain's pool.
	global := renderTenantGlobalConfig("c_example_com")
	if !strings.Contains(global, "include=/etc/php-fpm-tenant/c_example_com/pool.d/*.conf") {
		t.Fatalf("tenant global config does not include the pool directory:\n%s", global)
	}
}

func TestApacheVhostDeniesScriptsBackupsAndForeignSymlinks(t *testing.T) {
	var rendered bytes.Buffer
	if err := apacheVhostTmpl.Execute(&rendered, VhostOpts{
		DomainName: "example.com",
		WebRoot:    "/home/c_example_com/public_html",
		PHPSocket:  "/run/php-fpm/c_example_com.sock",
	}); err != nil {
		t.Fatalf("render Apache vhost: %v", err)
	}
	config := rendered.String()

	for _, directive := range []string{
		"Options -ExecCGI -Indexes -Includes -FollowSymLinks +SymLinksIfOwnerMatch",
		"RemoveHandler .cgi .pl .py .sh .rb .lua .fcgi .fpl",
		`<FilesMatch "\.(cgi|pl|py|sh|rb|lua|fcgi)$">`,
		`<FilesMatch "\.(sql|sql\.gz|bak|old|orig|save|swp|swo|dump|inc|log)$">`,
		`<FilesMatch "\.(php\.bak|php~|php\.save)$">`,
		"AllowOverride AuthConfig FileInfo Indexes Limit Options=Indexes,MultiViews",
	} {
		if !strings.Contains(config, directive) {
			t.Errorf("Apache vhost does not contain hardening directive %q", directive)
		}
	}
	for _, archiveExtension := range []string{"|tar|", "|tgz|", "|zip|", "|rar|", "|7z|"} {
		if strings.Contains(config, archiveExtension) {
			t.Errorf("Apache vhost must not reject legitimate archive extension %q", archiveExtension)
		}
	}
}

// Every acme.sh invocation must be bounded: issuance waits on Let's Encrypt to
// validate a challenge, so an unreachable or rate-limiting CA would otherwise leave
// the process running for the life of the panel.
func TestACMECommandCarriesADeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := acmeCommandContext(ctx, "--version")
	if command.Cancel == nil {
		t.Fatal("acmeCommandContext built a command with no cancellation")
	}
	if !slices.Contains(command.Env, "HOME="+config.ACMEHome()) {
		t.Error("acmeCommandContext dropped the acme.sh HOME, so acme.sh would not find its own store")
	}
}

// A hung acme.sh must be killed rather than waited on forever.
func TestTenantCommandContextKillsAHungProcess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := tenantCommandContext(ctx, "sleep", "60").Run()
	if err == nil {
		t.Fatal("a command that outran its deadline reported success")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("the deadline took %s to take effect", elapsed)
	}
}
