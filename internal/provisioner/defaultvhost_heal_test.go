package provisioner

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The embedded copy is what a running panel installs; assets/nginx is what
// servika-install.sh copies onto a fresh host. They must not drift, or a new
// install and a healed one would end up serving different catch-all vhosts.
func TestEmbeddedDefaultVhostsMatchTheShippedAssets(t *testing.T) {
	for _, tc := range []struct {
		asset    string
		embedded string
	}{
		{"_default80.conf", default80Conf},
		{"_default443.conf", default443Conf},
	} {
		onDisk, err := os.ReadFile(filepath.Join("..", "..", "assets", "nginx", tc.asset))
		if err != nil {
			t.Fatalf("read assets/nginx/%s: %v", tc.asset, err)
		}
		if string(onDisk) != tc.embedded {
			t.Errorf("assets/nginx/%s and the embedded copy have diverged; copy the asset into internal/provisioner/nginx/ and append the old hash to the known list", tc.asset)
		}
	}
}

// The heal writes the current text. If that text's own hash were missing from
// the known list, the next boot would read back its own output, fail to
// recognise it, and warn about an operator edit that never happened.
func TestCurrentDefaultVhostsAreListedAsKnown(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		known   []string
	}{
		{"_default80.conf", default80Conf, knownDefault80},
		{"_default443.conf", default443Conf, knownDefault443},
	} {
		if !slices.Contains(tc.known, contentHash(tc.content)) {
			t.Errorf("%s: current content hash %s is not in the known list", tc.name, contentHash(tc.content))
		}
	}
}

// Both catch-alls fall back to /index.html under defaultWebroot, and BOTH parts
// of that have to keep holding or the park page lands where nginx will not look
// for it. Measured against nginx 1.29.8: with the fallback declared and the file
// missing, every request with an unmatched Host answers 500 and logs `rewrite or
// internal redirection cycle`, which nginx -t does not catch.
//
// This is what makes the page mandatory rather than decorative. If a template
// ever stops declaring the fallback, this test is the thing that asks whether
// the page is still needed instead of leaving a file nothing reads.
func TestBothCatchAllsFallBackToThePageThisHealWrites(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
	}{
		{"_default80.conf", default80Conf},
		{"_default443.conf", default443Conf},
	} {
		if !strings.Contains(tc.content, "try_files $uri /index.html;") {
			t.Errorf("%s no longer falls back to /index.html; the park page may be unnecessary or may need a different name", tc.name)
		}
		if !strings.Contains(tc.content, "root "+defaultWebroot+";") {
			t.Errorf("%s declares a root other than %s, so the park page is written where nginx does not look for it", tc.name, defaultWebroot)
		}
	}
	if want := defaultWebroot + "/index.html"; defaultParkPage != want {
		t.Errorf("defaultParkPage = %q, want %q", defaultParkPage, want)
	}
}

// A page that renders empty resolves the redirection cycle and then shows a
// blank screen, which is the failure this cannot detect from the status code
// alone.
func TestTheParkPageIsARenderedDocument(t *testing.T) {
	page := defaultParkHTML()
	if !strings.HasPrefix(page, "<!DOCTYPE html>") {
		t.Fatalf("the park page is not an HTML document: %.60q", page)
	}
	for _, want := range []string{"<title>", brandStyle, brandDrawing, brandFooter} {
		if !strings.Contains(page, want) {
			t.Errorf("the park page is missing a required part: %.60q", want)
		}
	}
}

// Neither catch-all declares `location ^~ /_srv/`, so anything the page requests
// from there is two guaranteed 404s for an asset that can never load. The inline
// drawing is the fallback that already covers this case.
func TestTheParkPageRequestsNothingTheCatchAllCannotServe(t *testing.T) {
	page := defaultParkHTML()
	if strings.Contains(page, "/_srv/") {
		t.Errorf("the park page references /_srv/, which no catch-all vhost serves")
	}
	for _, vhost := range []string{default80Conf, default443Conf} {
		if strings.Contains(vhost, "/_srv/") {
			t.Errorf("a catch-all now serves /_srv/; the park page may use the animation after all")
		}
	}
}

func TestDecideVhostAction(t *testing.T) {
	const wanted = "server { listen 80; }\n"
	shipped := "server { listen 80; } # an older release\n"
	known := []string{contentHash(wanted), contentHash(shipped)}

	for _, tc := range []struct {
		name     string
		existing string
		exists   bool
		want     vhostAction
	}{
		{"absent file is installed", "", false, vhostInstall},
		{"current text is left alone", wanted, true, vhostUpToDate},
		{"previously shipped text is brought forward", shipped, true, vhostReplace},
		{"operator edit is preserved", wanted + "# our own location\n", true, vhostKeepEdited},
		// An empty but PRESENT file is not a shipped version, so it counts as an
		// edit. Treating it as absent would let the heal overwrite whatever an
		// operator deliberately blanked.
		{"blanked file counts as an edit", "", true, vhostKeepEdited},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideVhostAction(tc.existing, tc.exists, wanted, known); got != tc.want {
				t.Errorf("decideVhostAction = %v, want %v", got, tc.want)
			}
		})
	}
}
