# Servika Windows Agent — modularity and stability

The goal of this document is one sentence: **fixing one feature must not break
another.** It maps each stability principle onto the real code, records the
tracked technical debt, and keeps the architecture decisions that explain why
the code looks the way it does.

Scope: `internal/platform/` (the platform abstraction plus its Windows half) and
`cmd/servika-agent` (the agent, its API, the local panel and the interface). The
Linux panel is a SEPARATE binary on a separate channel; nothing here changes it
(see ADR-1).

**Verification level in this document.** A claim marked "verified" was run on
this machine: `gofmt`, `go vet` (darwin/arm64 and linux/arm64), `golangci-lint`,
`gocyclo -over 10`, `modernize` for both target platforms, the cross-compile
`GOOS=windows GOARCH=amd64 go build`, and `go test -count=1`. Anything that
needs a real Windows host is marked "not run here" and says so plainly. There
is no VM behind this document.

---

## 1. Principles → code state

| # | Principle | State | Where / note |
|---|-----------|-------|--------------|
| 1 | Modular architecture | done | `platform.Provider` plus the `Capability` bit field is the module boundary; the operating systems are split by build tag; the agent is a SEPARATE binary. The web layer never reaches appcmd directly (`GET /api/local/sites` goes through `platform.SiteList`). |
| 2 | Regression tests | done | 225 tests across `internal/platform` and `cmd/servika-agent`. Every load-bearing guard was mutated, the test confirmed red, and the mutation reverted. |
| 3 | Test pyramid | partial | Unit tests cover the pure logic. The end-to-end layer needs a Windows host and does NOT exist yet. |
| 4 | State machine | done | An installation job is `running` / `done` / `failed` / `cut` / `partial`, single flight, with a disk marker that survives a restart; a half installation is `partial`, not a silent success. The agent update rolls back by itself. |
| 5 | Idempotency | done | `CreateDatabase` uses `IF NOT EXISTS` and reapplies the login password; the MSSQL install repairs a half-finished sqlcmd instead of refetching 750 MB; a service action reads the real state back. |
| 6 | Asynchronous jobs | done | An install answers `202` with a job id; the progress is streamed over SSE and polled as a fallback. |
| 7 | Timeout / retry | partial | Every command and download carries a 30 minute timeout with context cancellation; a download retries with exponential backoff and resumes over HTTP Range. A circuit breaker on the installer commands is NOT implemented. |
| 8 | Observability | partial | Every mutation goes through the audit wrapper with a request id (in the response header, in the log line and in the error envelope). The installation reports structured progress. Metrics and tracing are NOT implemented. |
| 9 | Standard error model | done | `failure.go`: one `{code, message, error, request_id, retryable}` envelope plus machine codes. Every local-panel endpoint writes through `writeError` / `methodFailure` / `bodyFailure`. |
| 10 | Security development lifecycle | done | Injection is closed (validation plus exec without a shell), TLS with certificate pinning on the panel side, bcrypt for the panel password, SHA-256 pins on nine downloads, a pool-name pattern, a CSRF Origin↔Host check, and the PostgreSQL password passed through an option file rather than argv. |
| 11 | Backup and restore | not started | Windows has NO backup or restore yet. When it is added the Linux lesson is mandatory: a checksum, a test restore, and honest reporting. |
| 12 | Release engineering | done | A separate `windows/dev` channel and a separate version constant; `scripts/build-agent-windows.sh` builds the agent alone. The `update` command runs a pre-check, swaps atomically, gates on health, and rolls back automatically when the gate fails. |
| 13 | Feature flags | partial | The catalog `Tier` (`proven` / `experimental` / `undecided`) is the staged rollout the operator sees. A percentage rollout does NOT exist. |
| 14 | Chaos testing | not started | Killing a service, filling a disk and cutting the database are not exercised. |
| 15 | API contract and versioning | partial | The wire contract is fixed (`X-Servika-Token`, the JSON shapes). Contract tests and versioning are NOT implemented. |
| 16 | Technical debt | done | Section 3 is the tracked record. |
| 17 | Architecture decisions | done | Section 4. |
| 18 | Definition of done | done | Section 5. |

---

## 2. What the design defends against

Each of these is a failure that happened somewhere else first, and the code
carries the defence plus a comment saying why.

- **A silent success.** `ServiceAction` does not trust an exit code: `sc start`
  is asynchronous and `Restart-Service` does not set `$LASTEXITCODE`, so a failed
  action used to answer `{"ok":true}`. The state is read back until it matches,
  and an unreachable state is an honest error.
- **A cross-tenant leak.** A tenant's system account name carries 32 bits of
  randomness and the web root holds an owner marker. A colliding reuse is
  REFUSED outright rather than inheriting a deleted tenant's directory, and a
  delete reads the account name back from IIS so an algorithm change cannot
  orphan anything.
- **An installation that takes the agent down.** The installer goroutine is
  wrapped in `recover`: one component's panic does not kill the process.
- **An installation cut short.** A marker on disk survives a restart. On the
  next boot a pending marker refuses new installations with `INSTALL_PENDING`
  and shows the job as `cut`; an operator clears it deliberately, because only
  a human can know no installer is still running.
- **A password in the process table.** `/proc`-equivalent command lines are
  world readable on Windows too, so the PostgreSQL superuser password goes
  through a 0600 option file that is deleted after use, and a one-off generated
  password never enters the job log.
- **A tampered download.** Nine of the eleven installers are pinned to a
  SHA-256; a mismatch deletes the file and retries. Two are deliberately NOT
  pinned (the MSSQL and .NET hosting bundle addresses are redirects whose target
  changes when the vendor publishes an update), and that is logged rather than
  hidden.
- **A made-up estimate.** While an installer runs, the remaining time genuinely
  cannot be predicted, so the progress bar goes indeterminate and shows the
  elapsed time next to the catalog estimate. It never invents an ETA.

---

## 3. Tracked technical debt

Open items, in the order they are worth doing.

| Item | Priority | Finding |
|------|----------|---------|
| W-1 | high | There is NO end-to-end verification on a real Windows host. Every claim in this repository rests on cross-compilation plus unit tests. The site, database, service and installation paths have side effects that only a host can prove. |
| W-2 | high | Backup and restore do not exist on Windows (principle 11). |
| W-3 | medium | No duplicate-request guard on the endpoints. A repeated POST with the same body runs the work twice; the operations themselves are idempotent, so the damage is bounded, but a request id guard belongs here. |
| W-4 | medium | The central agent API on 8460 does not use the error envelope yet. It is an internal channel between the panel and the agent, so the priority is below the operator-facing panel. |
| W-5 | low | No circuit breaker on the installer commands (principle 7). |
| W-6 | low | No metrics and no tracing (principle 8). |
| W-7 | low | No chaos testing (principle 14). |
| W-8 | low | No contract tests and no API versioning (principle 15). |

---

## 4. Architecture decisions

- **ADR-1 — A separate binary on a separate channel.** The Windows agent is NOT
  embedded in the panel binary: it is `cmd/servika-agent`, its channel is
  `windows/dev`, and its version constant is independent of the panel's.
  *Reason:* "breaking something on Linux must not break Windows." A shared
  artefact or a shared version number would break that on the first day. The two
  constants are deliberately NOT linked.
- **ADR-2 — The capability gate and the selftest seal.** `CapSite` is never
  granted from code. It opens only once a real create-and-delete cycle through
  IIS has proved it on that host, and the seal records the version that proved
  it. *Reason:* a capability is announced only after it is demonstrated, per
  machine, mechanically. A new agent version proves itself again.
- **ADR-3 — Honesty.** A fake success is forbidden. MySQL and PostgreSQL
  administration answers a clear error because the agent does not hold their
  administrator password, rather than reporting a success that did not happen.
- **ADR-4 — Single-flight installation.** At most one installation at a time; a
  second request is refused with `409`, not queued. *Reason:* concurrent MSI or
  CBS work leaves a broken system, and a queue would only delay that.
- **ADR-5 — Two doors, one process, an isolated panel.** The central API on 8460
  and the local panel on 8443 run in separate goroutines from one process and
  share one certificate, so the operator approves one exception. If the panel
  fails, the central API stays up.
- **ADR-6 — The interface is compiled in.** The agent is one file an operator
  copies to a host. A separate assets directory would leave the panel blank the
  moment somebody copied the exe alone, so the four interface files are embedded
  with `go:embed`. There is no CDN and no outside request, because an offline
  Windows host has neither.
- **ADR-7 — Pure logic lives without a build tag.** Parsing, validation and
  state live in files with no `//go:build windows`, so their tests run in CI on
  Linux. Only the code that actually executes something on the host carries the
  tag. A test that only runs on Windows is a test nobody runs.

---

## 5. Definition of done — a Windows feature

- [ ] The code, plus unit tests for the pure logic in an untagged file
- [ ] `GOOS=windows GOARCH=amd64 go build` and `go vet` clean
- [ ] `gofmt -l .`, `golangci-lint run`, `gocyclo -over 10` and `modernize`
      clean for both target platforms
- [ ] The error path: no silent success; a failure is confirmed against the real
      state
- [ ] Idempotent: the same request twice is safe, and a half state is
      recoverable
- [ ] Deletion is symmetric: everything creation made (the account, the pool,
      the login, the ACL) is cleaned up or deliberately kept
- [ ] Authorisation (a session or a token) plus injection defence (validation
      and exec without a shell)
- [ ] At least an operator-visible record of the mutation
- [ ] A heal function when the feature carries asynchronous state or host
      configuration, because a restart otherwise strands it
- [ ] This document updated (the state table plus the debt)

---

## 6. Verification commands

```bash
gofmt -l .
go vet ./...
GOOS=linux GOARCH=arm64 go vet ./...
GOOS=windows GOARCH=amd64 go build ./cmd/servika-agent/
GOOS=windows GOARCH=amd64 go vet ./cmd/servika-agent/ ./internal/platform/
golangci-lint run ./cmd/servika-agent/ ./internal/platform/
gocyclo -over 10 cmd/servika-agent internal/platform
go test -count=1 ./cmd/servika-agent/ ./internal/platform/
./scripts/build-agent-windows.sh
```

On a Windows host, once one exists:

```powershell
servika-agent-windows-amd64.exe install      # self-install as a service
servika-agent-windows-amd64.exe selftest     # prove CapSite on this host
servika-agent-windows-amd64.exe fingerprint  # the certificate the panel pins
```

The end-to-end cycle that is still owed (W-1): create a site, delete it, create
the same domain again and confirm the owner marker matches; force a different
domain onto the same account name and confirm it is REFUSED; create a database,
drop it, create it again with the same user and confirm the password converges;
stop a service that is already stopped and confirm the real state is read back
rather than a fake success.
