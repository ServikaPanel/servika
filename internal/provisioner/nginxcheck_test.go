package provisioner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The floor is what the product's target platform ships. AlmaLinux 10 carries
// nginx 1.26, and `http2 on;` in assets/nginx/_panel.conf needs 1.25.1, so an
// older nginx cannot judge the configuration Servika actually installs: it
// rejects it as an unknown directive and the gate reports a defect that does not
// exist. Ubuntu 24.04 packages 1.24, which is why CI installs nginx from
// nginx.org rather than from the distribution.
const (
	minNginxMajor = 1
	minNginxMinor = 26
)

var nginxVersionPattern = regexp.MustCompile(`nginx/(\d+)\.(\d+)\.`)

// requireNginx returns the nginx binary the syntax gates run against.
//
// Absent nginx SKIPS, because a developer machine is not required to have one
// and CI installs it. Present but too old FAILS, because that is a broken gate
// rather than a missing one, and it has to say so instead of failing later on a
// directive the running nginx has simply never heard of.
func requireNginx(t *testing.T) string {
	t.Helper()
	nginx, err := exec.LookPath("nginx")
	if err != nil {
		t.Skip("nginx is unavailable")
	}
	// nginx writes its version banner to stderr.
	out, err := exec.Command(nginx, "-v").CombinedOutput()
	if err != nil {
		t.Fatalf("could not read the nginx version: %v\n%s", err, out)
	}
	match := nginxVersionPattern.FindSubmatch(out)
	if match == nil {
		t.Fatalf("could not parse the nginx version from %q", out)
	}
	major, _ := strconv.Atoi(string(match[1]))
	minor, _ := strconv.Atoi(string(match[2]))
	if major < minNginxMajor || (major == minNginxMajor && minor < minNginxMinor) {
		t.Fatalf("nginx %d.%d is older than the %d.%d Servika targets, so it cannot judge the shipped configuration",
			major, minor, minNginxMajor, minNginxMinor)
	}
	return nginx
}

// scratchPaths are the writable locations nginx -t insists on, whose compiled-in
// defaults live under /var/cache/nginx.
var scratchPaths = []string{
	"client_body_temp_path", "proxy_temp_path", "fastcgi_temp_path",
	"uwsgi_temp_path", "scgi_temp_path",
}

// sandbox returns the http-context directives that keep nginx -t off the paths
// only root may write.
//
// Those defaults are compiled in as absolute paths (/var/cache/nginx/...,
// /var/log/nginx/access.log), so -p does not move them, and a check running
// unprivileged fails on a permission error long before it says anything about
// the configuration. That is what these gates did on CI, where the job is not
// root: they reported a defect in the shipped files that was really the sandbox.
//
// They are http-context, which -g does not accept, so they are injected into the
// body's own http block. Nothing else about the body is touched, and a shipped
// directive of the same name still wins because it sits in a deeper block.
func sandbox(prefix string) string {
	var directives strings.Builder
	for _, path := range scratchPaths {
		fmt.Fprintf(&directives, "    %s %s;\n", path, filepath.Join(prefix, path))
	}
	directives.WriteString("    access_log off;\n")
	return directives.String()
}

// checkNginxSyntax writes body into prefix and runs `nginx -t` over it.
func checkNginxSyntax(t *testing.T, prefix, body, whatFailed string) {
	t.Helper()
	nginx := requireNginx(t)

	sandboxed := strings.Replace(body, "http {\n", "http {\n"+sandbox(prefix), 1)
	if sandboxed == body {
		t.Fatalf("the configuration has no http block to sandbox:\n%s", body)
	}

	// A PHP vhost carries `include fastcgi_params;`, which nginx resolves under
	// the prefix and which only the distribution package installs. Without a
	// stub here the gate fails on a missing file and says nothing about the
	// configuration it was asked to judge. Its CONTENT does not matter: the
	// directives it would carry are fastcgi_param lines nginx never validates
	// against a backend at -t time.
	if err := os.WriteFile(filepath.Join(prefix, "fastcgi_params"), nil, 0o600); err != nil {
		t.Fatalf("write the fastcgi_params stub: %v", err)
	}

	config := filepath.Join(prefix, "nginx.conf")
	if err := os.WriteFile(config, []byte(sandboxed), 0o600); err != nil {
		t.Fatalf("write the configuration: %v", err)
	}
	out, err := exec.Command(nginx, "-t",
		"-p", prefix,
		"-c", config,
		"-e", "stderr",
		"-g", "pid "+filepath.Join(prefix, "nginx.pid")+";",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s\n%s", whatFailed, err, out, sandboxed)
	}
}
