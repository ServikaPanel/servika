package config

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Config contains the server's environment-derived runtime configuration.
type Config struct {
	ListenAddr  string
	DBDsn       string
	JWTSecret   []byte
	SecretKey   []byte
	JWTLifetime int // Lifetime in seconds.
	Env         string
}

// Load reads and validates runtime configuration from environment variables.
func Load() (*Config, error) {
	// No built-in DSN default: a fallback credential is the same string in every
	// installation, so a server started without its environment file would come up
	// silently on a publicly known account instead of refusing to start.
	dsn := strings.TrimSpace(os.Getenv("SERVIKA_DB_DSN"))
	if dsn == "" {
		return nil, fmt.Errorf("SERVIKA_DB_DSN is required")
	}
	c := &Config{
		ListenAddr:  envOr("SERVIKA_LISTEN", ":8080"),
		DBDsn:       dsn,
		Env:         envOr("SERVIKA_ENV", "production"),
		JWTLifetime: envInt("SERVIKA_JWT_LIFETIME_SEC", 8*3600),
	}
	secret := strings.TrimSpace(os.Getenv("SERVIKA_JWT_SECRET"))
	if len(secret) < 32 {
		return nil, fmt.Errorf("SERVIKA_JWT_SECRET must be at least 32 characters (current: %d)", len(secret))
	}
	secretKey := strings.TrimSpace(os.Getenv("SERVIKA_SECRET_KEY"))
	if len(secretKey) < 32 {
		return nil, fmt.Errorf("SERVIKA_SECRET_KEY must be at least 32 characters (current: %d)", len(secretKey))
	}
	if err := ValidateRuntimePaths(); err != nil {
		return nil, err
	}
	c.JWTSecret = []byte(secret)
	c.SecretKey = []byte(secretKey)
	return c, nil
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// Pool bounds for the panel's own MariaDB connections.
const (
	DBMinOpenConns = 16 // The historical fixed value; no host loses capacity.
	// The panel is ONE client of a MariaDB that also serves every tenant site.
	// AlmaLinux 10 ships max_connections at 151 and servika-optimize raises it
	// to 200, so a panel that could take 128 of them would starve the sites it
	// exists to host.
	DBMaxOpenConnsCap = 64
	dbConnsPerCPU     = 4
)

// DBMaxOpenConns returns the ceiling for the panel's MariaDB pool, and whether
// an operator override was out of range.
//
// A fixed 16 is too small on a busy host: httpx.ExtendDeadline lets one request
// hold a connection for minutes on the import, export, transfer and download
// endpoints, so a few concurrent transfers take the whole pool and every other
// request waits behind them.
//
// An out-of-range SERVIKA_DB_MAX_CONNS is reported rather than obeyed: a pool
// of one deadlocks the panel, and a pool larger than the server's own
// max_connections fails at the point of use, in the middle of a request.
func DBMaxOpenConns() (n int, override string) {
	if v := strings.TrimSpace(os.Getenv("SERVIKA_DB_MAX_CONNS")); v != "" {
		parsed, err := strconv.Atoi(v)
		switch {
		case err != nil:
			return defaultDBMaxOpenConns(), fmt.Sprintf("SERVIKA_DB_MAX_CONNS=%q is not a number", v)
		case parsed < DBMinOpenConns || parsed > DBMaxOpenConnsCap:
			return defaultDBMaxOpenConns(), fmt.Sprintf(
				"SERVIKA_DB_MAX_CONNS=%d is outside %d-%d", parsed, DBMinOpenConns, DBMaxOpenConnsCap)
		default:
			return parsed, ""
		}
	}
	return defaultDBMaxOpenConns(), ""
}

func defaultDBMaxOpenConns() int {
	return min(max(runtime.NumCPU()*dbConnsPerCPU, DBMinOpenConns), DBMaxOpenConnsCap)
}
