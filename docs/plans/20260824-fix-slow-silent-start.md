# Fix slow, silent `corvex start` and its proxy self-deadlock

> Revised 2026-08-24 after an adversarial review (codex gpt-5.6-sol, verdict
> `needs-attention`, 7 findings). The review is folded in below; the net effect
> is a **smaller** plan — the cross-platform resolver subsystem and the xray
> stderr classifier are both gone. See "Review outcomes" for what changed.

## Status (2026-08-24)

**Partly delivered.** Tasks 1–4 — the environment-proxy bypass, `redact_url`,
`corvex.log` at 0600 with an `info` default, and the `phase_line` start
narration — shipped on branch `docs/start-and-dns-plans` and are described in
`docs/plans/completed/20260824-start-deadlock-logging-and-dns-diagnostic.md`,
which is the plan that was actually executed. The checkboxes below were never
ticked; read Tasks 1–4 as done and their acceptance criteria as met.

**What remains here** is problem 2, the slow half: Task 5 (bound DNS resolution
and the threads that outlive it), Task 6 (parallel candidate health checks),
Task 7 (disjoint per-worker port ranges) and Task 8 (say why a start stalled).
Task 9's acceptance criteria and Task 10's documentation cover the whole plan
and are therefore only partly satisfied.

## Overview

Three defects on the `corvex start` path, found by diagnosis on 2026-08-24. They
compound: a broken resolver on the host makes every name lookup cost 60s, corvex
has no timeout around name lookups, corvex routes its own subscription download
through the proxy it has not started yet, and none of it is written to a log the
user can read.

**Problem 1 — start deadlocks on its own proxy.** `proxy.port` is `1080` and the
user's shell exports `HTTP_PROXY=http://localhost:1080`. ureq 3 defaults
`Config.proxy` to the environment (`Config::default` sets
`proxy: Proxy::try_from_env()`, ureq-3.3.0 `config.rs:872`; the vars read are
`ALL_PROXY`/`HTTPS_PROXY`/`HTTP_PROXY` plus lowercase, `proxy.rs:222-230`), and
`download_subscription` builds its agent with only `timeout_global`, never
`.proxy(None)`. So `corvex start` fetches the subscription through corvex's own
xray — which start has not launched yet. Surfaces as `timeout: global` and
`no supported proxy servers found in subscriptions`. Only the *stop-then-start*
path fails, because a still-running xray from a previous session accidentally
satisfies the request.

This also explains the reported "Proxy pane shows all switches off": `cmd_start`
aborts at the subscription step, so it never reaches `plat.enable_proxy()`. The
macOS proxy code is not at fault — verified: with xray up, `networksetup` and
`scutil --proxy` both report all three proxies correctly enabled on Wi-Fi.

**Problem 2 — `corvex.log` is never written.** `config.corvex_log` is
constructed (`config.rs:80`) and its parent directory created (`main.rs:559`),
but nothing ever opens it; `init_logger` targets stderr only. No such file
exists on disk. Every progress line is `debug!` and the default level is `warn`,
so a slow start prints nothing at all.

**Problem 3 — name resolution is unbounded.** `health::check_tcp` applies
`TCP_TIMEOUT` to `connect_timeout` but not to `to_socket_addrs()`
(`health.rs:28-35`). With a wedged resolver each candidate blocks ~60s before
the 5s connect timeout is even reached, and `find_alive_params` walks candidates
strictly sequentially, spawning a full xray process for each.

**Success criteria:** `corvex stop && corvex start` succeeds with a dead
`HTTP_PROXY` exported; a start writes a readable, timestamped `corvex.log`
containing no subscription token; a start against a wedged resolver finishes in
seconds and says why.

## Review outcomes (what the adversarial pass changed)

| # | Finding | Resolution |
|---|---------|-----------|
| 1 | Subscription token would be persisted to a 0644 log | **New Task 2** redacts every URL log site. `write_restricted` truncates, so Task 3 adds a separate 0600 *append* helper |
| 2 | `init_logger` runs before its parent dir is created | Task 3 creates `corvex_log.parent()` before init; fresh-state test added |
| 3 | Abandoned resolver threads bounded by candidate count, not by 6 | Task 5 adds an outstanding-resolution permit, host dedup, literal-IP bypass |
| 4 | Typed DNS-timeout error is discarded before the diagnostic can see it | Task 6 carries a typed aggregate search error through the JSON→URI fallback |
| 5 | xray stderr classification is brittle | Task 7 replaced with disjoint per-worker port ranges |
| 6 | Cross-platform `default_nameservers` is over-built and can misdiagnose | Task 8 reduced to a portable warning; the macOS resolver detail moves to Post-Completion |
| 7 | ANSI escapes possible under `RUST_LOG_STYLE=always` | Task 3 sets `WriteStyle::Never` explicitly |

Confirmed sound by the review and left unchanged: Task 1's `.proxy(None)` and its
test (`Config::proxy()` getter exists, `config.rs:249`); no scope-exit deadlock
between Tasks 5 and 6, because `with_timeout`'s `'static` bound means
`std::thread::spawn`, which `std::thread::scope` never joins; and `TeeWriter`
needs no locking of its own, because env_logger already wraps `Target::Pipe` in
a `Mutex` (env_logger-0.11.10 `writer/mod.rs:143`).

## Context (from discovery)

- files/components involved: `src/subscription.rs`, `src/main.rs`,
  `src/health.rs`, `src/config.rs`
- related patterns found: all parsing functions take `&str` and are unit tested
  without system calls; commands take `&impl Platform` and are tested against
  the `RecordingPlatform` mock in `src/main.rs` tests; `config::write_restricted`
  (`config.rs:7`) is the established 0600 pattern for credential-bearing files,
  but it opens with `.truncate(true)` and so cannot back an append-mode log
- dependencies identified: `ureq` 3.3.0 (`socks-proxy` feature), `log` +
  `env_logger` 0.11, `anyhow`, `tempfile`, `rand`. **No new crates** —
  concurrency and timeouts use `std::thread`, `std::sync::mpsc` and
  `std::thread::scope`, per the standing prefer-stdlib preference
- the `Platform` trait is **not** modified by this plan any more (review #6)

## Development Approach

- **testing approach**: Regular (code first, then tests)
- complete each task fully before moving to the next
- make small, focused changes
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task
  - tests are not optional - they are a required part of the checklist
  - write unit tests for new functions/methods
  - write unit tests for modified functions/methods
  - add new test cases for new code paths
  - update existing test cases if behavior changes
  - tests cover both success and error scenarios
- **CRITICAL: all tests must pass before starting next task** - no exceptions
- **CRITICAL: update this plan file when scope changes during implementation**
- run `cargo test` after each change; `cargo clippy` and `cargo fmt` before each commit
- maintain backward compatibility: no corvex.json key is renamed or removed

## Testing Strategy

- **unit tests**: required for every task (see Development Approach above)
- **e2e tests**: this project has no UI and no Playwright/Cypress suite, so
  there are no e2e tests to add. The equivalent end-to-end check is Task 9's
  manual `corvex stop && corvex start` against a dead port, listed there.
- timing- and network-dependent logic is made testable by injection rather than
  by sleeping: the DNS timeout wrapper takes a resolver closure, and the
  parallel scheduler is asserted via a shared counter, not wall-clock timing
- **secret-leak tests use a sentinel**: a fake token string is put through both
  the success and failure log paths, and the test asserts it never appears in
  the rendered output. This is the only reliable way to keep redaction from
  regressing as new log lines are added.

## Progress Tracking

- mark completed items with `[x]` immediately when done
- add newly discovered tasks with ➕ prefix
- document issues/blockers with ⚠️ prefix
- update plan if implementation deviates from original scope
- keep plan in sync with actual work done

## Solution Overview

Five changes, ordered so the start path is usable after Task 1 and safe to log
after Task 2:

1. **Bypass the environment proxy for subscription downloads.** Corvex's
   subscription fetch is infrastructure for bringing the tunnel up, so it must
   never traverse the tunnel. Set `.proxy(None)` explicitly.
2. **Redact subscription URLs before any of them reach a file.** Must land
   before logging is widened, not after.
3. **Write a real log file.** A `TeeWriter` fans `env_logger` output to both
   stderr and `config.corvex_log` (0600, append), and the default level rises to
   `info` so the start path narrates itself with timestamps and elapsed times.
4. **Bound name resolution and parallelise the search**, with a hard cap on
   outstanding resolutions.
5. **Say why a start stalled** — a portable warning naming the host and the
   timeout. Diagnostic only; corvex never edits routes or DNS.

**Key design decisions:**

- *No new dependencies.* `std::thread::scope`, `std::sync::mpsc::recv_timeout`
  and atomics cover the timeout and the pool.
- *First-to-answer wins* (chosen 2026-08-24). `find_alive_params` returns as
  soon as any candidate passes its tunnel check, cancelling the rest. This is
  the fastest possible start and a deliberate behaviour change: the selected
  server is decided by scheduling, so it can differ between runs and no longer
  honours subscription order. Recorded here because a future reader will
  otherwise read the non-determinism as a bug. Note the scope still joins
  in-flight workers, so a winner can wait out one peer's current check — a
  bounded tail, not a stall.
- *Detached resolver threads, but capped.* A thread blocked in
  `to_socket_addrs()` cannot be killed, so `with_timeout` abandons it. Left
  unbounded that is ~12 abandonments per worker per 60s stall; a permit held by
  the detached thread until it exits caps the total.
- *Never log a URL path.* Subscription tokens live in the path
  (`https://host/sub/<TOKEN>`). Logs get scheme+host only. This applies to
  error contexts too, which is where the token leaks today at `warn` level.
- *Diagnostics stay portable.* No `Platform` trait change, no `scutil` parsing:
  a lookup timeout does not prove the configured nameservers are at fault, and
  "first `resolver #` block" is a heuristic, not a definition.

## Technical Details

**Subscription agent (Task 1).** Extract `subscription_agent_config() ->
ureq::config::Config` so the proxy decision is assertable without a network
call. Body stays capped at `MAX_BODY_SIZE`, `timeout_global` stays 30s.

**Redaction (Task 2).** `redact_url(&str) -> String` keeps scheme and host and
replaces userinfo, path, query and fragment with a fixed marker:
`https://sub.example.com/…`. Applied at every site that interpolates a
subscription URL:

- `subscription.rs:45` (`debug!` download line)
- `subscription.rs:62,67` (the `failed to fetch`/`failed to read body` contexts)
- `main.rs:313`, `main.rs:320` (`debug!` per-subscription lines)
- `main.rs:254` `subscription_failure_message` — **the live leak**: it is
  rendered at `warn!` (`main.rs:327`), which is today's default level

The existing test `test_subscription_failure_message_includes_whole_cause_chain`
(`main.rs:1194`) asserts on a URL containing `/sub/abc` and must be updated.

**Logging (Task 3).** `run()` currently calls `init_logger` before `Config` is
resolved, and the log's parent directory is only created later inside
`cmd_start` (`main.rs:264`) — so on a fresh install the first open fails and
`TeeWriter` degrades to stderr-only permanently. Reorder to: build `Config`
(with the `--settings` override and the `log.xray.error` alias) → create
`corvex_log.parent()` → rotate → open → `init_logger`. The broader
settings-dependent directory creation stays in `cmd_start`.

```
fn init_logger(log_path: &Path, debug: bool)
```

`TeeWriter { file: Option<File> }` implements `io::Write`, writing stderr first
and the file second; a file error degrades to stderr-only for the rest of the
process and is reported once. No internal locking — env_logger already wraps the
pipe in a `Mutex`. Wired via `env_logger::Target::Pipe(Box::new(tee))`, with
`.write_style(WriteStyle::Never)` set explicitly so `RUST_LOG_STYLE=always`
cannot put ESC bytes in the file.

The log needs 0600 like every other credential-bearing file, but
`write_restricted` opens with `.truncate(true)`; add
`config::open_append_restricted(path) -> io::Result<File>` using
`OpenOptionsExt::mode(0o600)`, and additionally `set_permissions` on an
already-existing file so a log created by an older build is tightened on
upgrade. Rotation renames to `corvex.log.1` above `LOG_MAX_BYTES` (5 MB),
carrying the same mode.

Default filter becomes `info`; `CORVEX_DEBUG=1` and `log.corvex.debug` still
select `debug`; `RUST_LOG` continues to override both.

**Timeout helper (Task 5).**

```
fn with_timeout<T, F>(timeout: Duration, work: F) -> Result<T, TimeoutError>
where F: FnOnce() -> T + Send + 'static, T: Send + 'static
```

`mpsc::sync_channel(1)` — capacity 1, not 0, so an abandoned worker's send never
blocks — plus `recv_timeout`. `resolve_host(host, port, timeout)` uses it, and
`check_tcp`'s budget becomes `DNS_TIMEOUT` (5s) + `TCP_TIMEOUT` (5s).

Three things keep abandoned threads bounded, since a 60s OS stall against a 5s
timeout otherwise allows ~12 abandonments per worker:

- a literal-IP fast path that skips resolution entirely
- a per-host result cache, so N candidates on one hostname resolve once
- `MAX_OUTSTANDING_RESOLUTIONS` permits, each held by the detached thread until
  it actually exits; exhaustion returns a typed saturation result rather than
  spawning

**Parallel search (Task 6).** `std::thread::scope` with
`HEALTH_PARALLELISM: usize = 6` workers pulling from an `AtomicUsize` cursor
over the candidate slice. Each worker runs the TCP pre-filter then
`check_tunnel` and sends `(index, Result)` on an `mpsc::Sender`. The scope owner
takes the first `Ok` within `DEGRADED_THRESHOLD`, sets a `stop: AtomicBool`, and
returns that index; workers check `stop` before each new candidate.
`TunnelGuard`'s existing `Drop` already kills the spawned xray.

On total failure the error must not collapse to a bare string: introduce
`SearchFailure { dns_timeouts: Vec<String> /* redacted hosts */, other: usize }`
so Task 8 has something typed to react to. `cmd_start` merges the JSON-entry
attempt and the URI-flow fallback into one `SearchFailure` rather than
discarding the first.

**Port allocation (Task 7).** `find_free_port` binds, drops and returns — a
TOCTOU window six workers will hit. Rather than classify xray's stderr (brittle
across versions and platforms, and it needs pipe draining), give each worker a
disjoint subrange of the 20000–60000 space derived from its worker index, so
corvex workers cannot collide with each other by construction. A residual race
with unrelated processes remains — xray cannot inherit the probe listener — so
that case surfaces as an ordinary early-exit error, and the plan does not claim
global race freedom.

**Stall diagnostic (Task 8).** When a search fails with `SearchFailure` carrying
DNS timeouts, emit one `warn!` naming the redacted host(s) and the timeout, and
advising the user to check system DNS. No `Platform` trait method, no `scutil`
or `resolv.conf` parsing, no fixture. Portable and honest about what it knows.

## What Goes Where

- **Implementation Steps** (`[ ]` checkboxes): code, tests, docs inside this repo
- **Post-Completion** (no checkboxes): the host's broken routes, which are a
  machine-configuration fault outside corvex and need the user's decision

## Implementation Steps

### Task 1: Stop subscription downloads from using the environment proxy

**Files:**
- Modify: `src/subscription.rs`

- [ ] extract `subscription_agent_config() -> ureq::config::Config` from `download_subscription`, keeping `timeout_global(30s)`
- [ ] add `.proxy(None)`, with a comment explaining the self-deadlock: the subscription fetch brings the tunnel up, so it must not traverse it
- [ ] have `download_subscription` build its `Agent` from `subscription_agent_config()`
- [ ] write test asserting `subscription_agent_config().proxy().is_none()`, so a refactor cannot silently reintroduce the env default
- [ ] write test asserting the body cap `MAX_BODY_SIZE` is unchanged
- [ ] verify: `cargo test subscription` - must pass before task 2

### Task 2: Redact subscription tokens from every log and error path

**Files:**
- Modify: `src/subscription.rs`
- Modify: `src/main.rs`

- [ ] add `redact_url(&str) -> String` keeping scheme + host only, replacing userinfo, path, query and fragment with a fixed marker; fall back to the marker alone if the URL will not parse
- [ ] apply it at `subscription.rs:45` and in the `failed to fetch` / `failed to read body` contexts (`subscription.rs:62,67`)
- [ ] apply it in `subscription_failure_message` (`main.rs:254`) — this is the live leak, rendered at `warn!` (`main.rs:327`) under today's default level
- [ ] apply it at the two `debug!` sites `main.rs:313` and `main.rs:320`
- [ ] update `test_subscription_failure_message_includes_whole_cause_chain` (`main.rs:1194`), which currently asserts on a URL containing `/sub/abc`
- [ ] write tests for `redact_url`: token path removed, query removed, userinfo removed, unparseable input, URL with no path
- [ ] write sentinel test: a fake token pushed through both the success and the failure log paths never appears in the rendered string
- [ ] verify: `cargo test` - must pass before task 3

### Task 3: Write corvex.log at 0600 and raise the default level to info

**Files:**
- Modify: `src/config.rs`
- Modify: `src/main.rs`

- [ ] add `open_append_restricted(path) -> io::Result<File>` in `src/config.rs` using `OpenOptionsExt::mode(0o600)` on unix, plain append on Windows; note in a comment why `write_restricted` cannot be reused (it truncates)
- [ ] have it also `set_permissions(0o600)` on an already-existing file, so a log written by an older build is tightened on upgrade
- [ ] add `LOG_MAX_BYTES` (5 MB) and `rotate_if_oversized(path, max)`, renaming to `corvex.log.1`, replacing any existing `.1`, and carrying the same 0600 mode
- [ ] add `TeeWriter` in `src/main.rs` implementing `io::Write` — stderr first, file second, degrading to stderr-only after a file error and reporting that once; no internal lock, env_logger already wraps the pipe in a `Mutex`
- [ ] change `init_logger` to `init_logger(log_path: &Path, debug: bool)`, target `Target::Pipe`, and set `.write_style(WriteStyle::Never)` explicitly
- [ ] reorder `run()`: build `Config` → create `corvex_log.parent()` → rotate → open → `init_logger`, leaving the settings-dependent directory creation in `cmd_start`
- [ ] raise the default filter from `warn` to `info`, keeping `CORVEX_DEBUG=1`, `log.corvex.debug` and `RUST_LOG` as they behave today
- [ ] write tests for `TeeWriter`: writes reach both sinks; a failing file sink still writes stderr and does not error the process
- [ ] write tests for `rotate_if_oversized`: rotates over threshold, leaves a small file alone, overwrites an existing `.1`
- [ ] write fresh-state test: neither directory nor file exists, and the first log record is still persisted
- [ ] write test that the created file is mode 0600 on unix
- [ ] write test that a styled input message leaves no ESC byte in the file
- [ ] verify: `cargo test` - must pass before task 4

### Task 4: Narrate the start path at info level with per-phase timings

**Files:**
- Modify: `src/main.rs`
- Modify: `src/health.rs`
- Modify: `src/xray.rs`
- Modify: `src/platform/macos.rs`

- [ ] add `phase_line(phase: &str, detail: &str, elapsed: Duration) -> String` in `src/main.rs` as the single formatter for progress lines
- [ ] emit `info!` at each start phase: settings loaded, subscription download begin/end (**redacted** URL, byte count, elapsed), candidate count, engine chosen, xray spawned (PID), proxy applied (service, port), total elapsed
- [ ] replace the bare `eprintln!` at `src/health.rs:166` with an `info!` carrying candidate index, host:port and outcome, so progress reaches the log file too
- [ ] add `info!` in `xray.rs` around spawn and in `macos.rs` around the `networksetup` batch, including whether elevation was needed
- [ ] write tests for `phase_line` covering sub-second, multi-second and zero elapsed
- [ ] write sentinel test that a start-path log line built from a tokenised URL contains no token
- [ ] verify: `cargo test` - must pass before task 5

### Task 5: Bound DNS resolution, and bound the threads that outlive it

**Files:**
- Modify: `src/health.rs`

- [ ] add `with_timeout<T, F>(timeout, work)` using `mpsc::sync_channel(1)` and `recv_timeout`; comment why capacity is 1 rather than 0 (an abandoned sender must never block) and why the worker is abandoned rather than joined
- [ ] add `DNS_TIMEOUT` (5s) and `resolve_host(host, port, timeout) -> Result<SocketAddr>` built on `with_timeout`
- [ ] add a literal-IP fast path that skips resolution entirely
- [ ] add a per-host resolution cache so N candidates sharing a hostname resolve once
- [ ] add `MAX_OUTSTANDING_RESOLUTIONS` permits, each held by the detached thread until it exits; on exhaustion return a typed saturation result instead of spawning
- [ ] add a distinct error variant for a resolution timeout, kept separate from other resolve failures
- [ ] change `check_tcp` to use `resolve_host` instead of `to_socket_addrs()` directly
- [ ] write tests for `with_timeout`: fast closure returns its value; slow closure returns the timeout error within the deadline; a panicking closure does not poison the caller
- [ ] write test that live resolver closures never exceed `MAX_OUTSTANDING_RESOLUTIONS`, counting the closures themselves rather than the scoped health workers
- [ ] write tests for the literal-IP bypass and the per-host cache (one lookup for repeated hosts)
- [ ] write test that the resolution-timeout variant is distinguishable from a connect failure
- [ ] verify: `cargo test health` - must pass before task 6

### Task 6: Run candidate health checks in parallel, first to answer wins

**Files:**
- Modify: `src/health.rs`
- Modify: `src/main.rs`

- [ ] add `HEALTH_PARALLELISM: usize = 6` and rewrite `find_alive_params` on `std::thread::scope` with an `AtomicUsize` cursor over the candidate slice
- [ ] send `(index, Result<Duration>)` per candidate over an `mpsc::Sender`; the scope owner returns the first `Ok` within `DEGRADED_THRESHOLD`
- [ ] add a `stop: AtomicBool` that workers check before starting each candidate, so losers stop early and their `TunnelGuard` kills the spawned xray
- [ ] introduce `SearchFailure { dns_timeouts: Vec<String>, other: usize }` carrying **redacted** hosts, and return it instead of a bare `bail!` string
- [ ] merge the JSON-entry attempt and the URI-flow fallback in `cmd_start` into one `SearchFailure` rather than discarding the first
- [ ] document on `find_alive_params` that selection is first-to-answer and so not deterministic across runs, and that scope-join adds a bounded tail
- [ ] keep `find_alive_server`'s signature and URI-skipping behaviour unchanged
- [ ] write test that an all-unreachable candidate list still reports no reachable servers
- [ ] write test that concurrency never exceeds `HEALTH_PARALLELISM`, using a shared counter with a high-water mark rather than wall-clock timing
- [ ] write test that the stop flag halts further candidate starts once a winner is found
- [ ] write test that `SearchFailure` survives the JSON→URI fallback with both attempts represented
- [ ] update `test_find_alive_params_empty_list` and `test_find_alive_server_*` where ordering assumptions no longer hold
- [ ] verify: `cargo test` - must pass before task 7

### Task 7: Give each worker a disjoint port range

**Files:**
- Modify: `src/health.rs`

- [ ] change `find_free_port` to `find_free_port_in(range)` and derive a disjoint subrange of 20000–60000 per worker index, so corvex workers cannot collide with each other
- [ ] thread the worker index through to `check_tunnel`
- [ ] surface a residual collision with an unrelated process as an ordinary early-exit error; do not classify xray's stderr text
- [ ] comment that this removes worker-to-worker collisions only — xray cannot inherit the probe listener, so a small external race remains
- [ ] write test that subranges for all `HEALTH_PARALLELISM` workers are disjoint and within bounds
- [ ] write test that an occupied port inside a worker's range is skipped
- [ ] verify: `cargo test health` - must pass before task 8

### Task 8: Say why a start stalled

**Files:**
- Modify: `src/main.rs`

- [ ] add `stall_warning(failure: &SearchFailure, timeout: Duration) -> Option<String>` returning a message only when DNS timeouts were recorded
- [ ] name the redacted host(s) and the timeout, and advise checking system DNS; do not claim which nameserver is at fault, and do not prescribe a route change
- [ ] emit it as a `warn!` from the start path when the search fails
- [ ] write tests: one timed-out host, several, none (returns `None`), and that the message contains no token
- [ ] verify: `cargo test` - must pass before task 9

### Task 9: Verify acceptance criteria

- [ ] verify `corvex start` succeeds with `HTTP_PROXY=http://localhost:<proxy.port>` exported and nothing listening on that port — the original failure
- [ ] verify `corvex stop && corvex start` succeeds without touching the macOS Proxy pane
- [ ] verify `$XDG_STATE_HOME/corvex/corvex.log` exists after a start, is mode 0600, and holds timestamped per-phase lines
- [ ] verify the log contains **no** subscription token: `grep -c "$YOUR_REAL_TOKEN" "$XDG_STATE_HOME/corvex/corvex.log"` returns 0 (supply the real token from the shell, never from a committed file)
- [ ] verify a fresh-state start works: move the state dir aside, start, confirm the log is created and populated
- [ ] verify a start against the broken resolver finishes in seconds and warns naming the affected host
- [ ] verify no more than `HEALTH_PARALLELISM` xray processes exist during the search, and none survive it (`ps -eww -o pid=,args= | grep xray`)
- [ ] run full test suite: `cargo test`
- [ ] run `cargo clippy -- -D warnings` and `cargo fmt --check`
- [ ] verify `corvex status` and `corvex stop` are unchanged in output and behaviour

### Task 10: [Final] Update documentation

- [ ] update `README.md`: corvex.log is now written, at 0600, and start progress is visible at the default level
- [ ] update `CLAUDE.md`: `subscription.rs` bypasses the environment proxy by design and redacts URLs in all output; `health.rs` is parallel, first-to-answer, with per-worker port ranges
- [ ] update `RELEASE_NOTES.md`, calling out the fixed token leak in warn-level output
- [ ] move this plan to `docs/plans/completed/`

## Post-Completion

*Items requiring manual intervention or external systems - no checkboxes, informational only*

**Host configuration — the actual DNS fault, outside corvex:**

The 60s name lookups are caused by two static host routes on this machine, not
by corvex. Corvex's changes make a wedged resolver fast and legible, not fixed:

```
10.10.20.53     10.10.99.1     UGHS     en0
10.10.20.54     10.10.99.1     UGHS     en0
```

Those two IPs are the system default resolver (`scutil --dns` resolver #1, order
5000 — it serves *every* name, not just corporate ones), pinned to gateway
`10.10.99.1` out `en0`. That gateway is not on en0's `192.0.2.10/24` and
does not answer (100% packet loss). Measured effect:
`dscacheutil -q host -a name <any host>` takes 60.02s.

Removing them lets the corporate nameservers fall back to the
`10.10.20.0/24 → 10.10.20.1` route via utun7:

```
sudo route -n delete 10.10.20.53
sudo route -n delete 10.10.20.54
```

This changes live network configuration and needs the user's decision. One of
the two corporate VPN clients may install these deliberately, in which case the
durable fix is in that client's configuration or in connect order, and the
routes return on the next reconnect.

**Manual verification:**

- confirm the three VPNs (two corporate, one corvex/xray) resolve names once the
  routes are corrected
- confirm the parallel health check does not trip corporate DLP or EDR tooling
  that watches for burst process creation

**Deferred / not in scope:**

- a `subs-proxy` corvex.json key, for a user who genuinely needs an upstream
  proxy to reach their subscription host. Task 1 hard-codes "no proxy", which is
  right here; revisit only if someone reports needing it.
- multi-generation log rotation or a retention policy — Task 3 keeps one
  generation, enough to bound growth.
- runtime discovery of the effective default resolver. Dropped in review: a
  lookup timeout does not prove the configured nameservers are at fault, "first
  `resolver #` block" is a heuristic, and Linux `resolv.conf` often names only a
  local stub. Revisit only if accurate resolver discovery becomes its own
  requirement.
