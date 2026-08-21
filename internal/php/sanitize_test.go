package php

import (
	"errors"
	"strings"
	"testing"
)

// The size boxes on the PHP page are free text, because the dropdown they
// replaced could not be escaped. Nothing downstream checks what is typed:
// measured with php-fpm 8.3.32, `php-fpm -t` reports `test is successful` and
// exits 0 for a pool carrying `php_admin_value[memory_limit] = notasize`, while
// the running interpreter answers `Invalid quantity "notasize": no valid
// leading digits, interpreting as "0"`. A typo therefore breaks the site on
// every request with no configuration error anywhere to explain it, which is
// why the format is checked here, on the write path.
func TestASizeValuePHPWouldRefuseIsRefusedHere(t *testing.T) {
	accepted := []string{
		"2048M",   // the default
		"8000M",   // post_max_size
		"1g",      // lower case multiplier, measured accepted
		"1G",      //
		"1024K",   //
		"1048576", // plain bytes, no multiplier
		"-1",      // PHP's unlimited
		"0",       // post_max_size reads 0 as unlimited
	}
	for _, value := range accepted {
		settings := Defaults()
		settings.MemoryLimit = value
		if _, err := sanitizeSettings(settings); err != nil {
			t.Errorf("memory_limit %q was refused: %v", value, err)
		}
	}

	refused := []string{
		"notasize", // no leading digits
		"2048MB",   // measured: unknown multiplier "B"
		"2.5G",     // measured: fractional quantity
		"",         // empty renders a directive with no value
		"2048 M",   // a space inside the quantity
		"1T",       // not a multiplier PHP knows
		"M2048",    //
		"-2048M",   // only -1 is meaningful
	}
	for _, value := range refused {
		settings := Defaults()
		settings.MemoryLimit = value
		_, err := sanitizeSettings(settings)
		if err == nil {
			t.Errorf("memory_limit %q was accepted", value)
			continue
		}
		var refusal settingError
		if !errors.As(err, &refusal) || refusal.Reason != reasonInvalidSize {
			t.Errorf("memory_limit %q was refused without the %s code: %v", value, reasonInvalidSize, err)
		}
	}
}

// All three size fields are checked, not only the first one written.
func TestEverySizeFieldIsChecked(t *testing.T) {
	for _, field := range []string{"memory_limit", "post_max_size", "upload_max_filesize"} {
		settings := Defaults()
		switch field {
		case "memory_limit":
			settings.MemoryLimit = "notasize"
		case "post_max_size":
			settings.PostMaxSize = "notasize"
		case "upload_max_filesize":
			settings.UploadMaxFilesize = "notasize"
		}
		_, err := sanitizeSettings(settings)
		if err == nil {
			t.Fatalf("%s accepted a value PHP reads as zero", field)
		}
		if !strings.Contains(err.Error(), field) {
			t.Errorf("the refusal for %s does not name the field: %v", field, err)
		}
	}
}

// Surrounding whitespace is trimmed rather than refused, because PHP ignores it
// and storing it would put the space into the pool file.
func TestSurroundingWhitespaceIsTrimmedNotRefused(t *testing.T) {
	settings := Defaults()
	settings.MemoryLimit = "  2048M  "
	settings.PostMaxSize = "\t8000M"
	sanitized, err := sanitizeSettings(settings)
	if err != nil {
		t.Fatalf("a padded size value was refused: %v", err)
	}
	if sanitized.MemoryLimit != "2048M" {
		t.Errorf("memory_limit was stored as %q", sanitized.MemoryLimit)
	}
	if sanitized.PostMaxSize != "8000M" {
		t.Errorf("post_max_size was stored as %q", sanitized.PostMaxSize)
	}
}

// The control-character check that was already here still fires, and now says
// which refusal it is. A line break is the one input that could add a second
// directive to the pool file.
func TestALineBreakIsStillRefusedWithItsOwnCode(t *testing.T) {
	settings := Defaults()
	settings.DisableFunctions = "exec\nphp_admin_value[open_basedir] = /"
	_, err := sanitizeSettings(settings)
	if err == nil {
		t.Fatal("a value carrying a line break was accepted")
	}
	var refusal settingError
	if !errors.As(err, &refusal) || refusal.Reason != reasonControlCharacter {
		t.Fatalf("want the %s code, got: %v", reasonControlCharacter, err)
	}
}

// Defaults() must itself pass the check, or every save of an untouched form is
// refused.
func TestTheDefaultsPassTheirOwnCheck(t *testing.T) {
	if _, err := sanitizeSettings(Defaults()); err != nil {
		t.Fatalf("the shipped defaults are refused by sanitizeSettings: %v", err)
	}
}
