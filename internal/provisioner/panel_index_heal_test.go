package provisioner

import (
	"os"
	"strings"
	"testing"
)

// A fresh installation must need no repair at all. The shipped template and the
// rendered block have to be byte-identical, or the panel rewrites its own vhost
// and reloads nginx on the first boot of every new host for no reason.
func TestTheShippedTemplateAlreadyServesTheBlockTheHealWouldWrite(t *testing.T) {
	body, err := os.ReadFile("../../assets/nginx/_panel.conf")
	if err != nil {
		t.Fatalf("read the panel vhost: %v", err)
	}
	updated, replaced := replaceIndentedBlock(string(body), "location / {", panelIndexNoCacheBlock())
	if replaced != 1 {
		t.Fatalf("the template declares %d SPA locations, want exactly 1", replaced)
	}
	if updated != string(body) {
		t.Error("the heal would rewrite the shipped template, so every fresh install reloads nginx once for nothing")
	}
}

// The heal exists for an installation made before the template carried the
// block. Replacing it must leave exactly one copy.
func TestAnOldInstallationGetsTheBlockExactlyOnce(t *testing.T) {
	const old = `server {
    listen 8443 ssl;

    location / {
        try_files $uri $uri/ /index.html;
    }

    access_log /var/log/nginx/panel.access.log;
}
`
	updated, replaced := replaceIndentedBlock(old, "location / {", panelIndexNoCacheBlock())
	if replaced != 1 {
		t.Fatalf("replaced %d blocks, want 1", replaced)
	}
	if got := strings.Count(updated, "location / {"); got != 1 {
		t.Errorf("the vhost now declares %d SPA locations", got)
	}
	if got := strings.Count(updated, "add_header Content-Security-Policy"); got != 1 {
		t.Errorf("the vhost now carries %d policies in one location", got)
	}
	// Re-running must be a no-op, or the panel writes and reloads on every boot.
	again, _ := replaceIndentedBlock(updated, "location / {", panelIndexNoCacheBlock())
	if again != updated {
		t.Error("a second run changed the vhost again")
	}
}

// nginx -t accepts a vhost that has swallowed a neighbouring directive, so a
// wrong block boundary silently drops a security header instead of failing the
// reload. Everything after the block must survive intact.
func TestReplacingTheBlockDoesNotSwallowWhatFollowsIt(t *testing.T) {
	const vhost = `server {
    location / {
        try_files $uri $uri/ /index.html;
    }

    add_header X-Operator-Header "kept" always;
    access_log /var/log/nginx/panel.access.log;
}
`
	updated, replaced := replaceIndentedBlock(vhost, "location / {", panelIndexNoCacheBlock())
	if replaced != 1 {
		t.Fatalf("replaced %d blocks, want 1", replaced)
	}
	for _, survivor := range []string{
		`add_header X-Operator-Header "kept" always;`,
		"access_log /var/log/nginx/panel.access.log;",
	} {
		if !strings.Contains(updated, survivor) {
			t.Errorf("the replacement swallowed %q", survivor)
		}
	}
}

// A nested block closes at a deeper indent, so its brace must not be mistaken
// for the end of the outer one.
func TestANestedBlockDoesNotEndTheOuterOne(t *testing.T) {
	const vhost = `server {
    location / {
        if ($request_method = POST) {
            return 405;
        }
        try_files $uri $uri/ /index.html;
    }

    access_log /var/log/nginx/panel.access.log;
}
`
	updated, replaced := replaceIndentedBlock(vhost, "location / {", "    location / {\n        REPLACED\n    }")
	if replaced != 1 {
		t.Fatalf("replaced %d blocks, want 1", replaced)
	}
	// Ending at the nested brace leaves everything between it and the real
	// closing brace orphaned, plus a stray `    }` that nginx then reads as
	// closing the server block early.
	if strings.Contains(updated, "try_files") {
		t.Errorf("the outer block ended at the nested brace, orphaning its tail:\n%s", updated)
	}
	if opened, closed := strings.Count(updated, "{"), strings.Count(updated, "}"); opened != closed {
		t.Errorf("the result has %d opening and %d closing braces:\n%s", opened, closed, updated)
	}
	if !strings.Contains(updated, "access_log /var/log/nginx/panel.access.log;") {
		t.Error("the replacement ran past the outer block")
	}
}

// An unterminated block means the file is not what this code thinks it is.
// Consuming the rest of it would destroy the vhost, so nothing is touched.
func TestAnUnterminatedBlockIsLeftAlone(t *testing.T) {
	const broken = `server {
    location / {
        try_files $uri $uri/ /index.html;
`
	updated, replaced := replaceIndentedBlock(broken, "location / {", panelIndexNoCacheBlock())
	if replaced != 0 {
		t.Errorf("replaced %d blocks in a file whose block never closes", replaced)
	}
	if updated != broken {
		t.Error("an unterminated block was rewritten anyway")
	}
}
