package db

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// pinned parses the DSN this package would open.
func pinned(t *testing.T, dsn string) *mysql.Config {
	t.Helper()
	parsed, err := mysql.ParseDSN(pinTimeContract(dsn))
	if err != nil {
		t.Fatalf("the pinned DSN does not parse: %v", err)
	}
	return parsed
}

// The installer writes parseTime, but nothing required it. A DSN edited by hand
// in /etc/servika/env, or the short one in the README, left internal/chains
// logging "skipping an unreadable event" for every row and writing no chain at
// all, with nothing on screen to say why.
func TestEveryDSNIsOpenedWithParseTime(t *testing.T) {
	for _, dsn := range []string{
		"root@unix(/var/lib/mysql/mysql.sock)/panel",
		"root:secret@tcp(127.0.0.1:3306)/panel",
		"root:secret@tcp(127.0.0.1:3306)/panel?charset=utf8mb4",
		"root:secret@tcp(127.0.0.1:3306)/panel?parseTime=false",
		"root:secret@tcp(127.0.0.1:3306)/panel?parseTime=true",
	} {
		if !pinned(t, dsn).ParseTime {
			t.Errorf("%q is opened without parseTime", dsn)
		}
	}
}

// internal/slowquery compares its stored buckets against UTC_TIMESTAMP()
// because the driver's default location is UTC. An operator who set loc=Local
// would store every bucket as a local wall clock and shift it off the clock
// those queries compare it to.
func TestEveryDSNIsOpenedInUTC(t *testing.T) {
	for _, dsn := range []string{
		"root@unix(/var/lib/mysql/mysql.sock)/panel",
		"root:secret@tcp(127.0.0.1:3306)/panel?loc=Local",
		"root:secret@tcp(127.0.0.1:3306)/panel?loc=Europe%2FIstanbul",
	} {
		if got := pinned(t, dsn).Loc; got != time.UTC {
			t.Errorf("%q is opened in %v, want UTC", dsn, got)
		}
	}
}

// Everything else the operator configured has to survive: the pin rewrites the
// DSN, so a parameter it dropped would be a setting silently lost.
func TestPinningKeepsTheRestOfTheDSN(t *testing.T) {
	const dsn = "panel:s3cret@tcp(db.internal:3307)/servika" +
		"?charset=utf8mb4&collation=utf8mb4_unicode_ci&timeout=10s&readTimeout=30s&tls=skip-verify"

	parsed := pinned(t, dsn)

	for _, check := range []struct {
		name      string
		got, want any
	}{
		{"user", parsed.User, "panel"},
		{"password", parsed.Passwd, "s3cret"},
		{"network", parsed.Net, "tcp"},
		{"address", parsed.Addr, "db.internal:3307"},
		{"database", parsed.DBName, "servika"},
		{"collation", collationOf(parsed), "utf8mb4_unicode_ci"},
		{"connect timeout", parsed.Timeout, 10 * time.Second},
		{"read timeout", parsed.ReadTimeout, 30 * time.Second},
		{"TLS setting", parsed.TLSConfig, "skip-verify"},
	} {
		if check.got != check.want {
			t.Errorf("the %s changed to %v, want %v", check.name, check.got, check.want)
		}
	}
}

// collationOf reads the collation from wherever the driver's config kept it.
func collationOf(parsed *mysql.Config) string {
	if parsed.Collation != "" {
		return parsed.Collation
	}
	return parsed.Params["collation"]
}

// A DSN the driver cannot parse is handed on unchanged, so sql.Open reports the
// real problem rather than this function inventing one.
func TestAnUnparsableDSNIsHandedOnUnchanged(t *testing.T) {
	const broken = "this is not a dsn"
	if got := pinTimeContract(broken); got != broken {
		t.Errorf("the broken DSN was rewritten to %q", got)
	}
}

// The rewritten DSN must not carry the password into a log line by accident:
// FormatDSN reproduces it, so anything that prints the return value prints the
// credential. This pins that the only caller is sql.Open.
func TestThePinnedDSNStillCarriesTheCredentialItWasGiven(t *testing.T) {
	const dsn = "panel:s3cret@tcp(127.0.0.1:3306)/servika"
	if !strings.Contains(pinTimeContract(dsn), "s3cret") {
		t.Error("the pinned DSN lost its password, so the connection would fail to authenticate")
	}
}

// The proof that matters is against a real server: db.Open with a DSN that
// carries no parseTime must still scan a TIMESTAMP into a time.Time. Before
// this, that scan failed with "unsupported Scan, storing driver.Value type
// []uint8 into type *time.Time", which internal/chains swallowed one row at a
// time.
//
// Skipped without SERVIKA_TEST_DSN, like every other live test here.
func TestOpenScansATimestampFromABareDSN(t *testing.T) {
	dsn := os.Getenv("SERVIKA_TEST_DSN")
	if dsn == "" {
		t.Skip("SERVIKA_TEST_DSN is unset, so there is no server to ask")
	}
	// Strip everything the caller configured, which is exactly the shape a
	// hand-edited /etc/servika/env or the README's development DSN has.
	parsed, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("the test DSN does not parse: %v", err)
	}
	bare := &mysql.Config{
		User: parsed.User, Passwd: parsed.Passwd,
		Net: parsed.Net, Addr: parsed.Addr, DBName: parsed.DBName,
		AllowNativePasswords: true,
	}
	if bare.ParseTime {
		t.Fatal("the stripped DSN still asks for parseTime, so this proves nothing")
	}

	handle, err := Open(bare.FormatDSN())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = handle.Close() }()

	var when time.Time
	if err := handle.QueryRow(`SELECT CAST('2026-03-04 05:06:07' AS DATETIME)`).Scan(&when); err != nil {
		t.Fatalf("a TIMESTAMP did not scan into a time.Time: %v", err)
	}
	if when.Year() != 2026 || when.Month() != time.March || when.Day() != 4 {
		t.Errorf("the value came back as %v", when)
	}
	if when.Location() != time.UTC {
		t.Errorf("the value came back in %v, want UTC", when.Location())
	}
}
