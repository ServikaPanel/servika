// Package apphealth waits for an application to start answering after the
// panel has started its unit.
//
// systemctl returning 0 says the unit was ACCEPTED, not that the program came
// up. A Node process that dies on a missing environment variable, a Grafana
// that cannot open its database, a binary built for the other architecture: all
// three leave systemd reporting activating or even active for a moment, and the
// panel reported the start as a success. The operator then read a screen saying
// the application was running while nothing was listening on its port, and the
// only way to find out was to open the log.
//
// The probe is deliberately LOCAL ONLY. The host is not taken from a request,
// from the catalog, or from any other input: it is 127.0.0.1, and the only
// thing a caller chooses is the port it assigned itself. An application probe
// that could be pointed at a host is an SSRF with the panel's own network
// position.
package apphealth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

// The probe budget. Eight attempts one second apart covers the start of every
// application in the catalog measured on a cold cache (Grafana is the slowest
// at about four seconds), and eight seconds is short enough that a request
// waiting on it does not look hung.
const (
	Attempts    = 8
	Interval    = time.Second
	DialTimeout = 3 * time.Second
)

// loopback is the only host this package ever connects to.
const loopback = "127.0.0.1"

// ErrNoPort reports a probe that named no port. It is a programming error
// rather than an unhealthy application, and the two must not read the same.
var ErrNoPort = errors.New("apphealth: the probe names no port")

// Probe is one application to wait for.
//
// Path decides the check. Empty means a TCP connect, which is all that can be
// asked of an application whose protocol the panel does not speak (a TeamSpeak
// server, an SFTP daemon). A path makes it an HTTP GET, and any answer at all
// counts: a 401 or a 404 proves the program is up and serving, which is the
// question. Only a transport failure is a failed attempt.
type Probe struct {
	Port int
	Path string
	// InitialDelay is how long to wait before the FIRST attempt. A program that
	// needs a moment to bind refuses the connection rather than timing out, so
	// without it the first two or three attempts are spent on a port that was
	// never going to answer yet.
	InitialDelay time.Duration
}

// Wait blocks until the application answers, the attempts run out, or ctx ends.
//
// It reports an error rather than a boolean so the caller can put the reason on
// screen. A caller that only wants the fact can compare against nil.
func Wait(ctx context.Context, probe Probe) error {
	if probe.Port <= 0 {
		return ErrNoPort
	}
	if err := sleep(ctx, probe.InitialDelay); err != nil {
		return err
	}
	var last error
	for attempt := 1; attempt <= Attempts; attempt++ {
		if last = attemptOnce(ctx, probe); last == nil {
			return nil
		}
		if attempt == Attempts {
			break
		}
		if err := sleep(ctx, Interval); err != nil {
			return err
		}
	}
	return fmt.Errorf("the application did not answer on port %d after %d attempts: %w",
		probe.Port, Attempts, last)
}

// Healthy is Wait reduced to the fact, for a caller that records a state rather
// than a message.
func Healthy(ctx context.Context, probe Probe) bool {
	return Wait(ctx, probe) == nil
}

// attemptOnce runs one check.
func attemptOnce(ctx context.Context, probe Probe) error {
	if probe.Path == "" {
		return dialOnce(ctx, probe.Port)
	}
	return getOnce(ctx, probe)
}

// dialOnce proves something is accepting connections on the port.
func dialOnce(ctx context.Context, port int) error {
	dialer := net.Dialer{Timeout: DialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(loopback, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	return conn.Close()
}

// getOnce proves the application is serving HTTP.
//
// Any status is a pass. The panel does not know what the application's own
// paths mean, so treating a 404 as unhealthy would report a working Gitea as
// down for the whole of its first eight seconds and then stop checking.
//
// Redirects are NOT followed: a redirect is already an answer, and following
// one would let an application's own configuration send this request somewhere
// off the loopback interface.
func getOnce(ctx context.Context, probe Probe) error {
	url := "http://" + net.JoinHostPort(loopback, strconv.Itoa(probe.Port)) + probe.Path
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: DialTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	return response.Body.Close()
}

// sleep waits unless the context ends first.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
