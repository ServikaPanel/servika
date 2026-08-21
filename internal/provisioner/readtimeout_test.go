package provisioner

import (
	"bytes"
	"strings"
	"testing"
)

// nginx stops waiting for the FastCGI response on its own clock, so a PHP
// max_execution_time above that clock is invisible to a visitor. Measured with
// nginx 1.26.3 against a real php-fpm pool carrying max_execution_time 3000 and
// the shipped `fastcgi_read_timeout 60s`: a sleep(65) request answered HTTP 504
// after 60.06 seconds while sleep(2) answered 200. The panel reported 3000
// seconds while every script died at 60.
func TestTheReadTimeoutFollowsTheExecutionLimit(t *testing.T) {
	tests := []struct {
		name             string
		maxExecutionTime int
		want             int
	}{
		{"unset keeps what the vhost always carried", 0, 60},
		{"PHP's unlimited does not hold a worker forever", -1, 60},
		{"a small limit still clears the floor through its margin", 5, 65},
		{"the old default clears the floor with its margin", 30, 90},
		{"the new default", 3000, 3060},
		{"a limit past the ceiling is bounded", 100000, 3600},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := FastCgiReadTimeout(test.maxExecutionTime); got != test.want {
				t.Fatalf("FastCgiReadTimeout(%d) = %d, want %d", test.maxExecutionTime, got, test.want)
			}
		})
	}
}

// Two invariants that must hold for EVERY input, not only the cases listed
// above: nginx gives up after PHP does, so the visitor gets PHP's own error
// rather than a bare 504, and no domain ever comes out of a render with a
// shorter timeout than the 60s every tenant vhost carried before.
func TestTheReadTimeoutInvariantsHoldForEveryInput(t *testing.T) {
	for _, maxExecutionTime := range []int{-1, 0, 1, 5, 30, 60, 300, 3000, 3600, 100000} {
		got := FastCgiReadTimeout(maxExecutionTime)
		if got < 60 {
			t.Errorf("FastCgiReadTimeout(%d) = %d, shorter than the 60s the vhost carried before",
				maxExecutionTime, got)
		}
		if maxExecutionTime > 0 && maxExecutionTime <= 3540 && got <= maxExecutionTime {
			t.Errorf("FastCgiReadTimeout(%d) = %d, which is not longer than the script is allowed to run",
				maxExecutionTime, got)
		}
	}
}

// A VhostOpts filled in by hand, which is what every heal and every other test
// does, must keep the timeout the vhost has always had rather than rendering a
// zero. `fastcgi_read_timeout 0s` means NO timeout in nginx, so a raw field in
// the template would silently let one request hold a worker forever.
func TestAVhostBuiltWithoutTheLimitKeepsTheOldTimeout(t *testing.T) {
	render := func(opts VhostOpts) string {
		t.Helper()
		var out bytes.Buffer
		if err := vhostTmpl.Execute(&out, opts); err != nil {
			t.Fatalf("render vhost: %v", err)
		}
		return out.String()
	}
	base := VhostOpts{
		DomainName: "example.com",
		WebRoot:    "/home/c_example_com/public_html",
		PHPSocket:  "/run/php-fpm/c_example_com.sock",
		PHPVersion: "8.3",
	}

	if body := render(base); !strings.Contains(body, "fastcgi_read_timeout 60s;") {
		t.Fatalf("a vhost with no max_execution_time did not keep the 60s timeout:\n%s", body)
	}

	withLimit := base
	withLimit.MaxExecutionTime = 3000
	body := render(withLimit)
	if !strings.Contains(body, "fastcgi_read_timeout 3060s;") {
		t.Fatalf("a vhost with max_execution_time 3000 did not derive its timeout:\n%s", body)
	}
	if strings.Contains(body, "fastcgi_read_timeout 60s;") {
		t.Fatal("the derived vhost still carries the old fixed timeout")
	}
}
