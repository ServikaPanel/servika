package git

import (
	"fmt"

	"servika/internal/files"
)

// GitHub's published SSH host keys, verbatim from https://api.github.com/meta
// (the `ssh_keys` field), rendered as known_hosts lines.
//
// These are PINNED rather than accepted on first use. The tenant config used to
// carry `StrictHostKeyChecking no` with `UserKnownHostsFile=/dev/null`, so every
// clone and fetch the panel ran as the tenant accepted whatever key was
// presented and recorded nothing: an attacker with a network position between
// the panel and github.com could present their own key, be accepted silently,
// and serve an arbitrary repository. The clone target is the tenant's document
// root, which the clone empties first, so the result is attacker-chosen PHP
// executing on the customer's live site.
//
// All three key types are pinned, which is what keeps a single rotation from
// stopping every deployment. GitHub rotated its RSA key in March 2023 after an
// exposure and left the others alone. Measured against the real github.com with
// OpenSSH 10.3p1: with one of the three lines corrupted the connection still
// verifies, because ssh negotiates one of the remaining pinned types; with all
// three corrupted it answers "Host key verification failed" and refuses. So the
// pin is genuinely enforced, and a single upstream rotation is survivable until
// the new line is shipped here.
//
// Fingerprints published beside the keys, for anyone checking this list:
//
//	SHA256_ED25519 +DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU
//	SHA256_ECDSA   p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM
//	SHA256_RSA     uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s
const githubHostKeys = `github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=
github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=
`

const (
	relKnownHosts = ".ssh/servika_known_hosts"
	relSSHConfig  = ".ssh/config"
)

// sshConfigBody is the tenant ssh configuration the panel's git commands run
// under. GlobalKnownHostsFile is closed too, or a key trusted for some
// unrelated purpose on this host would satisfy the check.
const sshConfigBody = `Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/servika_deploy
    StrictHostKeyChecking yes
    UserKnownHostsFile ~/.ssh/servika_known_hosts
    GlobalKnownHostsFile /dev/null
`

// writeSSHTrust installs the pinned host keys and the config that uses them.
//
// It runs on EVERY call rather than only when a deploy key is generated,
// because generateDeployKey returns early for a tenant that already has one.
// Without that, a host installed before this change would keep the old config
// that disables verification for the life of the installation, which is exactly
// the shape the repository's heal rule exists to prevent.
func writeSSHTrust(home, systemUser string) error {
	if err := files.WriteFileBeneath(home, relKnownHosts, []byte(githubHostKeys), 0o644, systemUser); err != nil {
		return fmt.Errorf("install the github host keys: %w", err)
	}
	if err := files.WriteFileBeneath(home, relSSHConfig, []byte(sshConfigBody), 0o600, systemUser); err != nil {
		return fmt.Errorf("write the ssh configuration: %w", err)
	}
	return nil
}
