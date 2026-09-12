package provisioner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installedStaticCache is the shape every panel installed before this repair
// carries: `expires` and an add_header in the same location, and `immutable`
// on file names that carry no content hash.
const installedStaticCache = `server {
    location /assets/ {
        try_files $uri =404;
        expires 7d;
        add_header Cache-Control "public, immutable";
        add_header X-Content-Type-Options "nosniff" always;
    }

    location ^~ /pma/ {
        alias /opt/phpmyadmin/;

        location ~ ^/pma/(.+\.php)$ {
            fastcgi_pass unix:/run/php-fpm/phpmyadmin.sock;
        }

        location ~ ^/pma/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt|svg|woff2?|map))$ {
            alias /opt/phpmyadmin/$1;
            expires 7d;
            add_header Cache-Control "public, immutable";
            add_header X-Content-Type-Options "nosniff" always;
        }
    }

    location ~ ^/webmail/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt|svg|woff2?|map))$ {
        alias /opt/roundcube/public_html/$1;
        expires 7d;
        add_header Cache-Control "public, immutable";
    }
}
`

// blockOf returns the body of the location whose opening line is openLine.
func blockOf(t *testing.T, content, openLine string) string {
	t.Helper()
	lines := strings.Split(content, "\n")
	start, end, ok := blockBounds(lines, openLine)
	if !ok {
		t.Fatalf("the vhost declares no %q", openLine)
	}
	return strings.Join(lines[start+1:end], "\n")
}

// phpMyAdmin and Roundcube ship fixed file names, so `immutable` tells the
// browser not to revalidate a URL whose bytes an update replaced. Measured
// against nginx 1.27: with `immutable` the browser is entitled to serve the old
// file for the whole lifetime and sends no conditional request at all.
func TestOnlyContentHashedNamesAreServedAsImmutable(t *testing.T) {
	repaired := applyPanelStaticCache(installedStaticCache)

	for _, location := range panelStaticCacheLocations {
		body := blockOf(t, repaired, location.open)
		if !strings.Contains(body, location.cacheControl) {
			t.Errorf("%q does not carry %q:\n%s", location.open, location.cacheControl, body)
		}
	}
	for _, open := range []string{
		`location ~ ^/pma/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt|svg|woff2?|map))$ {`,
		`location ~ ^/webmail/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt|svg|woff2?|map))$ {`,
	} {
		if body := blockOf(t, repaired, open); strings.Contains(body, "immutable") {
			t.Errorf("%q still serves a fixed file name as immutable:\n%s", open, body)
		}
	}
}

// nginx writes its own Cache-Control from `expires`, so a location carrying
// both sends the header twice. Measured against nginx 1.27: the response held
// `Cache-Control: max-age=604800` and `Cache-Control: public, immutable`.
func TestAStaticLocationSendsOneFreshnessDirective(t *testing.T) {
	repaired := applyPanelStaticCache(installedStaticCache)

	for _, location := range panelStaticCacheLocations {
		body := blockOf(t, repaired, location.open)
		if strings.Contains(body, "expires ") {
			t.Errorf("%q still sets expires next to an add_header:\n%s", location.open, body)
		}
		if n := strings.Count(body, "add_header Cache-Control"); n != 1 {
			t.Errorf("%q sends %d Cache-Control headers, want 1:\n%s", location.open, n, body)
		}
	}
}

// The repair must not touch anything else in the location, because these blocks
// also carry the security headers a location loses when it declares one.
func TestTheRepairKeepsTheRestOfTheLocation(t *testing.T) {
	repaired := applyPanelStaticCache(installedStaticCache)

	for _, want := range []string{
		"try_files $uri =404;",
		"alias /opt/phpmyadmin/$1;",
		"alias /opt/roundcube/public_html/$1;",
		"fastcgi_pass unix:/run/php-fpm/phpmyadmin.sock;",
		`add_header X-Content-Type-Options "nosniff" always;`,
	} {
		if !strings.Contains(repaired, want) {
			t.Errorf("the repair dropped %q", want)
		}
	}
}

// The rewritten line takes the indent of the lines around it. A nested location
// sits deeper than the top-level ones, and a hardcoded indent put the directive
// four columns to the left of its neighbours.
func TestTheRewrittenLineKeepsTheLocationsIndent(t *testing.T) {
	const nested = `server {
    location ^~ /pma/ {
        location ~ ^/pma/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt|svg|woff2?|map))$ {
            alias /opt/phpmyadmin/$1;
            expires 7d;
            add_header Cache-Control "public, immutable";
        }
    }
}
`
	repaired := applyPanelStaticCache(nested)
	want := "            " + panelPlainAssetCache
	if !strings.Contains(repaired, want) {
		t.Errorf("the directive does not line up with its neighbours:\n%s", repaired)
	}
}

// The panel compresses CSS, JavaScript, JSON and SVG, and nginx defaults
// gzip_vary off. Measured against nginx 1.27 without it: the gzip response
// carried `Content-Encoding: gzip` and no `Vary` at all.
func TestCompressionDeclaresItsVariant(t *testing.T) {
	const compressed = "http {\n    gzip on;\n    gzip_types text/css;\n}\n"

	repaired := applyPanelStaticCache(compressed)

	if !strings.Contains(repaired, "    gzip_vary on;") {
		t.Errorf("a compressing vhost does not declare Vary: Accept-Encoding:\n%s", repaired)
	}
	if n := strings.Count(repaired, "gzip_vary on;"); n != 1 {
		t.Errorf("the repair wrote gzip_vary %d times, want 1", n)
	}
	if twice := applyPanelStaticCache(repaired); twice != repaired {
		t.Errorf("the second pass added another gzip_vary:\n%s", twice)
	}
}

// A vhost that does not compress gains nothing, because gzip_vary alone would
// be a directive with no subject.
func TestAVhostThatDoesNotCompressGainsNoVary(t *testing.T) {
	const plain = "http {\n    server {\n        listen 80;\n    }\n}\n"
	if applyPanelStaticCache(plain) != plain {
		t.Error("the repair added gzip_vary to a vhost that does not compress")
	}
}

// Running twice must change nothing, because the heal runs at every startup.
func TestTheRepairIsIdempotent(t *testing.T) {
	once := applyPanelStaticCache(installedStaticCache)
	if twice := applyPanelStaticCache(once); twice != once {
		t.Errorf("the second pass changed the vhost:\n%s", twice)
	}
}

// A vhost the repair cannot find its locations in is left exactly as it is,
// rather than gaining a directive in the wrong place.
func TestAVhostWithoutTheseLocationsIsUntouched(t *testing.T) {
	const other = "server {\n    location /api/ {\n        proxy_pass http://127.0.0.1:8080;\n    }\n}\n"
	if applyPanelStaticCache(other) != other {
		t.Error("the repair edited a vhost that declares none of the static locations")
	}
}

// The shipped template is what a new host gets, and it must already satisfy the
// repair, or every first startup would rewrite and reload nginx.
func TestTheShippedTemplateNeedsNoRepair(t *testing.T) {
	template, err := os.ReadFile(filepath.Join("..", "..", "assets", "nginx", "_panel.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if repaired := applyPanelStaticCache(string(template)); repaired != string(template) {
		t.Error("assets/nginx/_panel.conf and the heal disagree about the static cache headers")
	}
}
