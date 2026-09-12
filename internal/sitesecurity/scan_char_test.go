package sitesecurity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"servika/internal/wordpress"
)

// The two scan passes reach wp-cli, a tenant home and openat2, none of which
// exist in a test and the last of which only exists on Linux. Every one of them
// is behind a package seam (see seams.go), so these tests replace the seam and
// leave the scan code itself untouched.

// setForTest swaps one seam for the duration of a test.
func setForTest[T any](t *testing.T, target *T, value T) {
	t.Helper()
	original := *target
	*target = value
	t.Cleanup(func() { *target = original })
}

// shopTarget is the domain every case below scans.
var shopTarget = target{id: 7, name: "shop.example", systemUser: "c_shop"}

// oneInstall makes discoverInstalls report a single installation in the
// document root.
func oneInstall(t *testing.T) {
	t.Helper()
	setForTest(t, &discoverInstalls, func(systemUser string) []wordpress.Install {
		return []wordpress.Install{{
			SystemUser: systemUser,
			Dir:        "/test-home/" + systemUser + "/public_html",
			Rel:        "/",
		}}
	})
}

// noComponents answers both component listings with nothing.
func noComponents(t *testing.T) {
	t.Helper()
	setForTest(t, &wpComponents, func(context.Context, string, string, string) ([]wordpress.Component, error) {
		return nil, nil
	})
}

// wpFeed answers the WordPress feed: the live contact-form-7 record for that
// one slug, and an empty record for everything else. An unknown slug really
// does answer 200 with a null vulnerability list; see feeds_test.go.
func wpFeed(t *testing.T) *Collector {
	t.Helper()
	return collectorAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "contact-form-7") {
			_, _ = io.WriteString(w, wpLiveRecord)
			return
		}
		_, _ = io.WriteString(w, `{"error":0,"data":{"vulnerability":null}}`)
	}))
}

func TestAWordPressInstallationIsRecordedWithItsCoreAndItsComponents(t *testing.T) {
	oneInstall(t)
	setForTest(t, &coreVersion, func(string, string) (string, error) { return "6.4.1", nil })
	setForTest(t, &wpComponents, func(_ context.Context, _, _, kind string) ([]wordpress.Component, error) {
		if kind == "plugin" {
			return []wordpress.Component{{Name: "contact-form-7", Version: "5.3.1"}}, nil
		}
		return []wordpress.Component{{Name: "twentytwenty", Version: "1.0"}}, nil
	})

	result, err := wpFeed(t).scanWordPress(context.Background(), shopTarget)
	if err != nil {
		t.Fatalf("scanWordPress: %v", err)
	}

	// Core, one plugin and one theme are three packages, and they are counted
	// both on the sweep total and on the installation's own row.
	if result.counts.packages != 3 {
		t.Errorf("packages = %d, want 3", result.counts.packages)
	}
	assertOneInventoryRow(t, result, Inventory{
		AppType: AppWordPress, InstallPath: "/", Version: "6.4.1", Packages: 3,
	})
	assertOneFinding(t, result, Finding{
		AppType: AppWordPress, InstallPath: "/",
		Package: "plugin:contact-form-7", Installed: "5.3.1",
	})
}

// assertOneInventoryRow checks that the scan produced exactly the row given.
func assertOneInventoryRow(t *testing.T, result scanResult, want Inventory) {
	t.Helper()
	if len(result.apps) != 1 {
		t.Fatalf("got %d inventory rows, want 1", len(result.apps))
	}
	if got := result.apps[0]; got != want {
		t.Errorf("inventory row is %+v, want %+v", got, want)
	}
}

// assertOneFinding checks the four fields of the single finding a scan filed.
// The advisory itself is the feed's business and is pinned in feeds_test.go.
func assertOneFinding(t *testing.T, result scanResult, want Finding) {
	t.Helper()
	if len(result.findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(result.findings))
	}
	got := result.findings[0]
	got.Advisory = Advisory{}
	if got != want {
		t.Errorf("finding is %+v, want %+v", got, want)
	}
}

// wp-config.php is there, so the installation is a WordPress site the sweep
// looked at. An unreadable version must not remove it from the inventory,
// because that is the row saying somebody inspected this site.
func TestAnInstallationIsRecordedEvenWhenItsVersionCannotBeRead(t *testing.T) {
	oneInstall(t)
	setForTest(t, &coreVersion, func(string, string) (string, error) { return "", errors.New("wp-cli failed") })
	noComponents(t)

	result, err := wpFeed(t).scanWordPress(context.Background(), shopTarget)
	if err != nil {
		t.Fatalf("scanWordPress: %v", err)
	}
	if len(result.apps) != 1 {
		t.Fatalf("got %d inventory rows, want 1", len(result.apps))
	}
	if result.apps[0].Version != "" || result.apps[0].Packages != 0 {
		t.Errorf("inventory row is %+v, want no version and no package", result.apps[0])
	}
	// The core read failure is NOT an error of the scan: it is the normal answer
	// for a directory that carries wp-config.php and nothing else.
	if result.counts.packages != 0 {
		t.Errorf("packages = %d, want 0", result.counts.packages)
	}
}

// An empty version string is what wp-cli returns for a broken installation, and
// it is treated exactly like the error above rather than queried as a slug.
func TestAnEmptyCoreVersionIsNotQueried(t *testing.T) {
	oneInstall(t)
	setForTest(t, &coreVersion, func(string, string) (string, error) { return "", nil })
	noComponents(t)

	collector := collectorAgainst(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the feed was contacted for an empty core version")
	}))
	result, err := collector.scanWordPress(context.Background(), shopTarget)
	if err != nil {
		t.Fatalf("scanWordPress: %v", err)
	}
	if len(result.apps) != 1 || result.apps[0].Version != "" {
		t.Errorf("inventory is %+v, want one row with no version", result.apps)
	}
}

// A vulnerable core is filed under the package name "wordpress", which is what
// separates it from a plugin of the same slug.
func TestAVulnerableCoreIsFiledAgainstWordPressItself(t *testing.T) {
	oneInstall(t)
	setForTest(t, &coreVersion, func(string, string) (string, error) { return "5.3.1", nil })
	noComponents(t)

	collector := collectorAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, wpLiveRecord)
	}))
	result, err := collector.scanWordPress(context.Background(), shopTarget)
	if err != nil {
		t.Fatalf("scanWordPress: %v", err)
	}
	if len(result.findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(result.findings))
	}
	if result.findings[0].Package != "wordpress" || result.findings[0].Installed != "5.3.1" {
		t.Errorf("finding is %+v, want wordpress at 5.3.1", result.findings[0])
	}
}

// A version the comparison cannot order is COUNTED, not dropped. A sweep that
// could judge nothing must not read as a clean one.
func TestAVersionThatCannotBeJudgedIsCounted(t *testing.T) {
	oneInstall(t)
	setForTest(t, &coreVersion, func(string, string) (string, error) { return "5.3.1-rc.2", nil })
	setForTest(t, &wpComponents, func(_ context.Context, _, _, kind string) ([]wordpress.Component, error) {
		if kind == "plugin" {
			return []wordpress.Component{{Name: "contact-form-7", Version: "5.3.1-rc.2"}}, nil
		}
		return nil, nil
	})

	collector := collectorAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, wpLiveRecord)
	}))
	result, err := collector.scanWordPress(context.Background(), shopTarget)
	if err != nil {
		t.Fatalf("scanWordPress: %v", err)
	}
	if result.counts.unparsed != 2 {
		t.Errorf("unparsed = %d, want the core and the plugin", result.counts.unparsed)
	}
	if len(result.findings) != 0 {
		t.Errorf("got %d findings from an unjudged record, want 0", len(result.findings))
	}
}

// A feed that fails is reported once and stops nothing: the component is still
// counted as a package, and the theme listing still runs.
func TestAFailingFeedIsReportedOnceAndStopsNothing(t *testing.T) {
	oneInstall(t)
	setForTest(t, &coreVersion, func(string, string) (string, error) { return "6.4.1", nil })
	setForTest(t, &wpComponents, func(_ context.Context, _, _, kind string) ([]wordpress.Component, error) {
		if kind == "plugin" {
			return []wordpress.Component{{Name: "contact-form-7", Version: "5.3.1"}}, nil
		}
		return nil, nil
	})

	collector := collectorAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	result, err := collector.scanWordPress(context.Background(), shopTarget)
	if err == nil || !strings.Contains(err.Error(), "feed answered") {
		t.Fatalf("error is %v, want the feed failure", err)
	}
	// Core and the plugin are both counted: the package is there whether or not
	// the feed could say anything about it.
	if result.counts.packages != 2 {
		t.Errorf("packages = %d, want 2", result.counts.packages)
	}
	// A failed query is not an unjudged record. Counting it as one would report
	// a broken feed as a tenant with unreadable versions.
	if result.counts.unparsed != 1 {
		t.Errorf("unparsed = %d, want only the core record", result.counts.unparsed)
	}
	if len(result.apps) != 1 || result.apps[0].Packages != 2 {
		t.Errorf("inventory is %+v, want one row holding two packages", result.apps)
	}
}

// The first failure is the one reported, and a component's failed lookup is a
// first failure when the core above it could not be read at all.
func TestAComponentLookupFailureIsReportedWhenItIsTheFirstOne(t *testing.T) {
	oneInstall(t)
	setForTest(t, &coreVersion, func(string, string) (string, error) { return "", os.ErrNotExist })
	setForTest(t, &wpComponents, func(_ context.Context, _, _, kind string) ([]wordpress.Component, error) {
		if kind == "plugin" {
			return []wordpress.Component{{Name: "contact-form-7", Version: "5.3.1"}}, nil
		}
		return nil, nil
	})

	collector := collectorAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	result, err := collector.scanWordPress(context.Background(), shopTarget)
	if err == nil || !strings.Contains(err.Error(), "feed answered") {
		t.Fatalf("error is %v, want the feed failure", err)
	}
	if result.counts.unparsed != 0 {
		t.Errorf("unparsed = %d, want 0: a failed query is not an unjudged record", result.counts.unparsed)
	}
}

// One failed listing must not hide the other one: the error is kept, the loop
// continues, and the theme is still counted.
func TestAFailedPluginListingStillLetsTheThemesBeCounted(t *testing.T) {
	oneInstall(t)
	setForTest(t, &coreVersion, func(string, string) (string, error) { return "", os.ErrNotExist })
	setForTest(t, &wpComponents, func(_ context.Context, _, _, kind string) ([]wordpress.Component, error) {
		if kind == "plugin" {
			return nil, errors.New("wp-cli exited 1")
		}
		return []wordpress.Component{{Name: "twentytwenty", Version: "1.0"}}, nil
	})

	result, err := wpFeed(t).scanWordPress(context.Background(), shopTarget)
	if err == nil {
		t.Fatal("the failed listing was not reported")
	}
	if want := "plugin list for shop.example: wp-cli exited 1"; err.Error() != want {
		t.Errorf("error is %q, want %q", err, want)
	}
	if result.counts.packages != 1 {
		t.Errorf("packages = %d, want the one theme", result.counts.packages)
	}
	if len(result.apps) != 1 || result.apps[0].Packages != 1 {
		t.Errorf("inventory is %+v, want one row holding one package", result.apps)
	}
}

// A cancellation inside the component loop still appends the installation, so a
// sweep that ran out of its budget reports what it had already inspected.
func TestACancellationInsideTheComponentLoopStillRecordsTheInstallation(t *testing.T) {
	oneInstall(t)
	setForTest(t, &coreVersion, func(string, string) (string, error) { return "", os.ErrNotExist })

	ctx, cancel := context.WithCancel(context.Background())
	setForTest(t, &wpComponents, func(context.Context, string, string, string) ([]wordpress.Component, error) {
		cancel()
		return []wordpress.Component{{Name: "twentytwenty", Version: "1.0"}}, nil
	})

	result, err := wpFeed(t).scanWordPress(ctx, shopTarget)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error is %v, want context.Canceled", err)
	}
	if len(result.apps) != 1 {
		t.Fatalf("got %d inventory rows, want the installation that was in progress", len(result.apps))
	}
	if result.counts.packages != 0 {
		t.Errorf("packages = %d, want 0: the component was never inspected", result.counts.packages)
	}
}

// A cancellation before the first installation reports nothing at all.
func TestACancelledScanRecordsNoInstallation(t *testing.T) {
	oneInstall(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := wpFeed(t).scanWordPress(ctx, shopTarget)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error is %v, want context.Canceled", err)
	}
	if len(result.apps) != 0 {
		t.Errorf("inventory is %+v, want nothing", result.apps)
	}
}

// ---------------------------------------------------------------------------
// scanLockfiles
// ---------------------------------------------------------------------------

const npmLockWithOnePackage = `{"lockfileVersion":3,"packages":{
  "": {"name":"site","version":"1.0.0"},
  "node_modules/lodash": {"version":"4.17.15"}
}}`

// tenantFiles routes the two openat2 seams at an in-memory home. Every key is
// the path relative to the home, exactly as the scan composes it.
func tenantFiles(t *testing.T, names []string, namesErr error, files map[string]string) {
	t.Helper()
	setForTest(t, &tenantHomeRoot, "/test-home")
	setForTest(t, &listNamesBeneath, func(home, dir string) ([]string, error) {
		if home != "/test-home/c_shop" || dir != "public_html" {
			t.Errorf("listNamesBeneath(%q, %q), want the tenant document root", home, dir)
		}
		return names, namesErr
	})
	setForTest(t, &readFileBeneath, func(home, rel string, _ int64) ([]byte, error) {
		if home != "/test-home/c_shop" {
			t.Errorf("readFileBeneath read from %q, want the tenant home", home)
		}
		body, ok := files[rel]
		if !ok {
			return nil, os.ErrNotExist
		}
		return []byte(body), nil
	})
}

// osvFeed answers both OSV endpoints. Every package named in vulnerable comes
// back from the batch pass and gets one advisory from the query pass.
func osvFeed(t *testing.T, vulnerable map[string]bool) *Collector {
	t.Helper()
	return collectorAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/querybatch") {
			var body struct {
				Queries []osvQuery `json:"queries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode the batch request: %v", err)
			}
			var results []string
			for _, query := range body.Queries {
				if vulnerable[query.Package.Name] {
					results = append(results, `{"vulns":[{"id":"GHSA-x"}]}`)
					continue
				}
				results = append(results, `{}`)
			}
			_, _ = fmt.Fprintf(w, `{"results":[%s]}`, strings.Join(results, ","))
			return
		}
		_, _ = io.WriteString(w, `{"vulns":[{"id":"GHSA-x","summary":"a hole",
		  "database_specific":{"severity":"HIGH"}}]}`)
	}))
}

func TestALockfileInTheDocumentRootIsRecordedAtTheRootPath(t *testing.T) {
	tenantFiles(t, nil, nil, map[string]string{
		"public_html/package-lock.json": npmLockWithOnePackage,
	})

	result, err := osvFeed(t, map[string]bool{"lodash": true}).
		scanLockfiles(context.Background(), shopTarget)
	if err != nil {
		t.Fatalf("scanLockfiles: %v", err)
	}
	if result.counts.packages != 1 {
		t.Errorf("packages = %d, want 1", result.counts.packages)
	}
	// The document root itself is "/", not the empty string a plain prefix trim
	// would leave.
	assertOneInventoryRow(t, result, Inventory{
		AppType: AppNodeJS, InstallPath: "/", Packages: 1,
	})
	assertOneFinding(t, result, Finding{
		AppType: AppNodeJS, InstallPath: "/", Package: "lodash", Installed: "4.17.15",
	})
}

// One directory below the document root is scanned too, and its rows carry the
// path relative to it.
func TestALockfileOneDirectoryDownKeepsItsRelativePath(t *testing.T) {
	tenantFiles(t, []string{"shop"}, nil, map[string]string{
		"public_html/shop/composer.lock": `{"packages":[{"name":"monolog/monolog","version":"1.0.0"}]}`,
	})

	result, err := osvFeed(t, nil).scanLockfiles(context.Background(), shopTarget)
	if err != nil {
		t.Fatalf("scanLockfiles: %v", err)
	}
	if len(result.apps) != 1 {
		t.Fatalf("got %d inventory rows, want 1", len(result.apps))
	}
	if result.apps[0].InstallPath != "/shop" || result.apps[0].AppType != AppComposer {
		t.Errorf("inventory row is %+v, want a php-composer row at /shop", result.apps[0])
	}
	if result.apps[0].Packages != 1 {
		t.Errorf("package count is %d, want 1", result.apps[0].Packages)
	}
}

// An absent lockfile is the normal case for most sites, so it produces neither
// an error nor an inventory row.
func TestAnAbsentLockfileIsNotAnError(t *testing.T) {
	tenantFiles(t, nil, nil, nil)

	result, err := osvFeed(t, nil).scanLockfiles(context.Background(), shopTarget)
	if err != nil {
		t.Fatalf("scanLockfiles: %v", err)
	}
	if len(result.apps) != 0 || len(result.findings) != 0 {
		t.Errorf("result is %+v, want nothing at all", result)
	}
}

// A malformed lockfile is the tenant's own file. It drops that installation and
// writes NO inventory row, because claiming the installation was inspected
// would be false reassurance.
func TestAMalformedLockfileDropsTheInstallationAndNotTheSweep(t *testing.T) {
	tenantFiles(t, nil, nil, map[string]string{
		"public_html/package-lock.json": `{"packages":`,
		"public_html/composer.lock":     `{"packages":[{"name":"monolog/monolog","version":"1.0.0"}]}`,
	})

	result, err := osvFeed(t, nil).scanLockfiles(context.Background(), shopTarget)
	if err == nil {
		t.Fatal("the malformed lockfile was not reported")
	}
	if !strings.HasPrefix(err.Error(), "package-lock.json under shop.example: ") {
		t.Errorf("error is %q, want it to name the file and the domain", err)
	}
	// The composer.lock beside it is still read, and it is the only row.
	if len(result.apps) != 1 || result.apps[0].AppType != AppComposer {
		t.Errorf("inventory is %+v, want only the composer row", result.apps)
	}
}

// A home whose document root cannot be listed still gets the document root
// itself scanned, and the listing failure is reported.
func TestAnUnlistableDocumentRootIsReportedAndStillScanned(t *testing.T) {
	tenantFiles(t, nil, errors.New("openat2 refused"), map[string]string{
		"public_html/package-lock.json": npmLockWithOnePackage,
	})

	result, err := osvFeed(t, nil).scanLockfiles(context.Background(), shopTarget)
	if err == nil || err.Error() != "openat2 refused" {
		t.Fatalf("error is %v, want the listing failure", err)
	}
	if len(result.apps) != 1 || result.apps[0].InstallPath != "/" {
		t.Errorf("inventory is %+v, want the document root row", result.apps)
	}
}

// A feed that fails on the batch pass leaves the inventory row in place: the
// dependency list WAS read, and that is what the row records.
func TestAFailingBatchPassStillLeavesTheInventoryRow(t *testing.T) {
	tenantFiles(t, nil, nil, map[string]string{
		"public_html/package-lock.json": npmLockWithOnePackage,
	})
	collector := collectorAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))

	result, err := collector.scanLockfiles(context.Background(), shopTarget)
	if err == nil || !strings.Contains(err.Error(), "feed answered") {
		t.Fatalf("error is %v, want the feed failure", err)
	}
	if len(result.apps) != 1 || result.apps[0].Packages != 1 {
		t.Errorf("inventory is %+v, want the row for the list that was read", result.apps)
	}
	if len(result.findings) != 0 {
		t.Errorf("got %d findings from a feed that failed, want 0", len(result.findings))
	}
}

// The second pass asks for one package's advisories. Its failure is reported
// and the walk continues.
func TestAFailingAdvisoryLookupIsReported(t *testing.T) {
	tenantFiles(t, nil, nil, map[string]string{
		"public_html/package-lock.json": npmLockWithOnePackage,
	})
	collector := collectorAgainst(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/querybatch") {
			_, _ = io.WriteString(w, `{"results":[{"vulns":[{"id":"GHSA-x"}]}]}`)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))

	result, err := collector.scanLockfiles(context.Background(), shopTarget)
	if err == nil || !strings.Contains(err.Error(), "feed answered") {
		t.Fatalf("error is %v, want the feed failure", err)
	}
	if len(result.findings) != 0 {
		t.Errorf("got %d findings, want 0", len(result.findings))
	}
}

// A cancellation stops the walk where it stands.
func TestACancelledLockfileScanStopsImmediately(t *testing.T) {
	tenantFiles(t, []string{"shop"}, nil, map[string]string{
		"public_html/package-lock.json": npmLockWithOnePackage,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := osvFeed(t, nil).scanLockfiles(ctx, shopTarget)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error is %v, want context.Canceled", err)
	}
	if len(result.apps) != 0 {
		t.Errorf("inventory is %+v, want nothing", result.apps)
	}
}
