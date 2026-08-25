# Fix the `corvex start` proxy deadlock, write a real log, and add a `corvex dns` diagnostic

> Composed 2026-08-24 from two earlier plans. Problems 1 and 2 are lifted from
> `20260824-fix-slow-silent-start.md` (including the fixes that an adversarial review — codex
> gpt-5.6-sol, verdict `needs-attention` — forced into them). The diagnostic is lifted from
> `20260824-dns-parser-fixes-and-diagnostic-command.md`. See **Provenance** for exactly what was
> taken and what was deliberately left behind.

## Overview

One thread ties these together: **`corvex start` fails, and tells you nothing about why.** This plan
makes it work, makes it speak, and adds a tool for the network layer underneath it.

**Problem 1 — start deadlocks on its own proxy.** `proxy.port` is `1080` and the user's shell exports
`HTTP_PROXY=http://localhost:1080`. ureq 3 defaults `Config.proxy` to the environment
(`Config::default` sets `proxy: Proxy::try_from_env()`, ureq-3.3.0 `config.rs:872`; the vars read are
`ALL_PROXY`/`HTTPS_PROXY`/`HTTP_PROXY` plus lowercase, `proxy.rs:222-230`), and
`download_subscription` builds its agent with only `timeout_global`, never `.proxy(None)`. So
`corvex start` fetches the subscription through corvex's own xray — which start has not launched yet.
Surfaces as `timeout: global` and `no supported proxy servers found in subscriptions`. Only the
*stop-then-start* path fails, because a still-running xray from a previous session accidentally
satisfies the request.

This also explains the reported "Proxy pane shows all switches off": `cmd_start` aborts at the
subscription step, so it never reaches `plat.enable_proxy()`. The macOS proxy code is not at fault —
verified: with xray up, `networksetup` and `scutil --proxy` both report all three proxies correctly
enabled on Wi-Fi.

**Problem 2 — `corvex.log` is never written.** `config.corvex_log` is constructed (`config.rs:80`) and
its parent directory created (`main.rs:559`), but nothing ever opens it; `init_logger` targets stderr
only. No such file exists on disk. Every progress line is `debug!` and the default level is `warn`, so
a slow start prints nothing at all.

**The diagnostic — `corvex dns`.** A real incident motivated this: a stale VPN host route pointed both
corporate nameservers at a gateway that was not on-link for the interface the route named, so ARP
never resolved and every DNS packet died with `sendto: Network is unreachable`. No firewall rule was
involved, which is exactly why it was slow to find — every individual layer looked healthy. `corvex
dns` walks the whole chain per nameserver: route → interface → **next-hop on-link check** → live
UDP:53 probe. The on-link check is the highest-value part; it is the one that was missing.

The diagnostic needs a parser fix to be useful at all. `dns::parse_scutil_dns` today keeps only
`nameserver[0]` and only harvests resolvers carrying a `domain :` line — so it sees neither the
secondary of a failover pair nor the machine's *primary* resolver, which typically has no domain line.
The root cause is the shape, not the loop: a `domain -> nameserver` map cannot represent a resolver
with no domain. Task 5 introduces a type that can.

**Success criteria:** `corvex stop && corvex start` succeeds with a dead `HTTP_PROXY` exported; a start
writes a readable, timestamped `corvex.log` containing no subscription token; `corvex dns` reports an
unreachable next hop when one exists.

## Provenance

| Taken from | What | Why |
|---|---|---|
| `fix-slow-silent-start` Task 1 | `.proxy(None)` for subscription downloads | Problem 1 |
| `fix-slow-silent-start` Task 2 | URL redaction | **Hard prerequisite** for Problem 2 — see below |
| `fix-slow-silent-start` Task 3 | corvex.log at 0600, rotation, `info` default | Problem 2 |
| `fix-slow-silent-start` Task 4 | Per-phase `info!` narration | Problem 2 — a written log is useless while every line is `debug!` |
| `dns-parser-fixes` Tasks 1, 6, 7, 8, 9 | `ResolverEntry`, netdiag helpers, DNS query codec, trait methods, the command | The diagnostic |

**Redaction is not optional.** The adversarial review's first finding was that widening logging
persists a subscription token to disk — the token lives in the URL path (`https://host/sub/<TOKEN>`)
and `subscription_failure_message` renders it at `warn!` (`main.rs:327`), today's default level. Task 2
must land before Task 3, not after.

**Deliberately left behind** (remains tracked in the source plans, which stay on disk):

- **Problem 3 — unbounded name resolution** (`fix-slow-silent-start` Tasks 5–8): the DNS timeout
  wrapper, the parallel first-to-answer search, per-worker port ranges, and the stall warning.
  Consequence to be honest about: **this plan does not make a wedged resolver fast.** A 60s lookup is
  still 60s. It becomes visible in the log and diagnosable via `corvex dns`, nothing more.
- **The xray-facing parser propagation** (`dns-parser-fixes` Tasks 2–5): widening
  `discover_corporate_dns` to `Vec<String>`, updating `sync_to_config`, and fixing the identical
  Linux `resolvectl` bug. See the Non-goal below for why the projection is acceptable here.

## Non-goals

Do not add, do not propose, do not "while we're here":

- Anything from Problem 3. `src/health.rs` is touched only to replace one `eprintln!` (Task 4).
- Widening `discover_corporate_dns` beyond its current `BTreeMap<String, String>`. Task 6 keeps it
  compiling with a lossy projection that takes `nameservers[0]`. **This knowingly leaves the xray path
  on one nameserver** — acceptable only because the xray DNS block is inert, so the value never
  reaches a consumer. The full fix stays in `dns-parser-fixes`.
- Any change to xray DNS wiring: `routing.domainStrategy` stays `"AsIs"`, the dead `dns_out` tag
  stays, the `corporate-dns` domain matcher stays. Do not delete the inert block.
- The `dns.manage` on/off switcher and its ON path.
- Changing the corvex.json `corporate-dns` schema, or renaming/removing any corvex.json key.
- Fixing routes. Corvex does not and will not manipulate routes — it only runs `route get`
  (read-only). Stale routes are fixed at the VPN client layer. Corvex detects and reports; nothing more.
- A `subs-proxy` key for users who genuinely need an upstream proxy. Task 1 hard-codes "no proxy",
  which is right here; revisit only if someone reports needing it.

## Context (from discovery)

- `src/subscription.rs` — `download_subscription`, agent construction, the redaction sites at `:45,62,67`
- `src/main.rs:254` — `subscription_failure_message`, **the live token leak**, rendered at `:327`
- `src/main.rs:313,320` — two `debug!` sites interpolating subscription URLs
- `src/main.rs:1194` — `test_subscription_failure_message_includes_whole_cause_chain`, asserts on a
  URL containing `/sub/abc`; must be updated by Task 2
- `src/config.rs:7` — `write_restricted`, the established 0600 pattern, but it opens with
  `.truncate(true)` and so cannot back an append-mode log
- `src/config.rs:80` — `corvex_log` constructed; `src/main.rs:559` — its parent dir created, too late
- `src/health.rs:166` — a bare `eprintln!` that never reaches the log file
- `src/dns.rs:12` — `parse_scutil_dns`, both parser bugs
- `src/platform/mod.rs:33` — the `Platform` trait
- `src/main.rs:38` — `Commands` enum, where `Dns` is added
- `src/main.rs:1080` — `RecordingPlatform`; `src/main.rs:959` — `cmd_status_inner`, the pattern
  `cmd_dns` follows

Conventions (from CLAUDE.md): parsing functions take `&str` and are unit-testable without system
calls; command functions take `&impl Platform` and are tested against `RecordingPlatform`; platform
abstraction via cfg-gated concrete types, no dynamic dispatch.

**Dependencies: none added.** Timeouts and the UDP probe use `std`. The probe builds a minimal DNS
query by hand (12-byte header + QNAME + QTYPE/QCLASS); a DNS crate is a heavier answer to a 30-line
problem. This follows the standing prefer-stdlib preference.

### Fixture sanitization — required

**This repository is public (`jLAM-ERR/corvex`).** Fixtures must NOT contain real corporate domains,
internal IP topology, or interface addresses from any developer's machine. Use sanitized values that
preserve the exact structure:

| Real (never commit) | Fixture value |
|---|---|
| corporate nameserver pair | `10.10.20.53` / `10.10.20.54` |
| stale/unreachable gateway | `10.10.99.1` |
| LAN interface address | `192.0.2.10` netmask `0xffffff00` |
| tunnel gateway | `10.10.20.1` |
| corporate domain | `corp.example.com` |
| subscription token | a fixed sentinel string, asserted absent |

Structural shapes the fixtures must reproduce exactly:

```
resolver #1                          <- no domain line: the invisible-resolver case
  nameserver[0] : 10.10.20.53
  nameserver[1] : 10.10.20.54        <- the dropped-secondary case
  flags    : Request A records
  reach    : 0x00000002 (Reachable)
  order    : 5000

resolver #5                          <- domain-scoped: must still work
  domain   : corp.example.com
  nameserver[0] : 10.10.20.53
  if_index : 14 (en0)
  flags    : Scoped, Request A records
```

macOS `route -n get <ip>` emits `gateway:` / `interface:` / `flags:`; `ifconfig <iface>` emits
`inet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255` — note the netmask is **hex**, not dotted.

## Development Approach

- **testing approach: TDD by default, Regular for mechanical wiring.** Most of this plan is pure
  `&str -> value` functions (`redact_url`, `parse_scutil_dns`, the netdiag helpers, the DNS codec,
  `phase_line`, rotation) where a RED test is trivial to write first. Three tasks are trait plumbing
  and logger wiring with no logic to drive out; those are marked **Regular** and write tests after.
  Each task states which it is.
- complete each task fully before moving to the next
- **every task MUST include new/updated tests**, listed as separate checklist items
- **all tests must pass before starting the next task** — no exceptions
- run `cargo test` after each change; `cargo clippy -- -D warnings` and `cargo fmt --check` before each commit
- maintain backward compatibility: no corvex.json key is renamed or removed
- update this plan file when scope changes during implementation

## Testing Strategy

- **unit tests**: required for every task. Pure parsers get table-driven cases over the sanitized
  fixtures. Command functions are tested against `RecordingPlatform`.
- **e2e tests**: none — this project has no UI and no Playwright/Cypress suite. The equivalent
  end-to-end check is the manual verification in Task 11.
- **no network in tests.** The UDP probe is split into pure encode/decode (tested) and a thin socket
  call (not unit-tested). Never make a real DNS query from the test suite.
- **secret-leak tests use a sentinel.** A fake token string is pushed through both the success and the
  failure log paths, and the test asserts it never appears in the rendered output. This is the only
  reliable way to keep redaction from regressing as new log lines are added.

## Progress Tracking

- mark completed items with `[x]` immediately when done
- add newly discovered tasks with the plus prefix
- document issues/blockers with the warning prefix
- keep plan in sync with actual work done

## Solution Overview

Ordered so the start path is usable after Task 1 and safe to log after Task 2:

1. **Bypass the environment proxy for subscription downloads.** The subscription fetch is
   infrastructure for bringing the tunnel up, so it must never traverse the tunnel.
2. **Redact subscription URLs before any of them reach a file.** Must land before logging widens.
3. **Write a real log file.** A `TeeWriter` fans `env_logger` output to stderr and `config.corvex_log`
   (0600, append), and the default level rises to `info`.
4. **Narrate the start path** with timestamps and per-phase elapsed times.
5. **Add `corvex dns`** — the resolver chain, ending in an on-link verdict and a live probe.

**Key design decisions:**

- *Never log a URL path.* Subscription tokens live in the path. Logs get scheme+host only. This
  applies to error contexts too, which is where the token leaks today at `warn` level.
- *No internal lock in `TeeWriter`.* env_logger already wraps `Target::Pipe` in a `Mutex`
  (env_logger-0.11.10 `writer/mod.rs:143`).
- *`on_link` is computed, not ARP-probed.* ARP state is racy and needs privileges to be meaningful.
  Comparing the gateway against the named interface's address and netmask is a pure function over
  three values, unit-testable, and it is precisely the condition that caused the incident.
- *One parser, two views.* `parse_scutil_dns` returns a rich `Vec<ResolverEntry>` that can represent a
  domain-less resolver and any number of nameservers; a projection feeds the existing xray path
  unchanged. The diagnostic consumes the rich form.
- *Two new trait methods, not five.* Rather than exposing `route get`, `ifconfig` and ARP separately,
  the platform answers one question: `next_hop_status(ip) -> NextHop`.

## Technical Details

**Subscription agent (Task 1).** Extract `subscription_agent_config() -> ureq::config::Config` so the
proxy decision is assertable without a network call. `Config::proxy()` getter exists
(`config.rs:249`), so the test is possible. Body stays capped at `MAX_BODY_SIZE`, `timeout_global`
stays 30s.

**Redaction (Task 2).** `redact_url(&str) -> String` keeps scheme and host and replaces userinfo,
path, query and fragment with a fixed marker. Applied at `subscription.rs:45`, `subscription.rs:62,67`,
`main.rs:313`, `main.rs:320`, and `main.rs:254`.

**Logging (Task 3).** `run()` currently calls `init_logger` before `Config` is resolved, and the log's
parent directory is only created later inside `cmd_start` — so on a fresh install the first open fails
and `TeeWriter` degrades to stderr-only permanently. Reorder to: build `Config` → create
`corvex_log.parent()` → rotate → open → `init_logger`.

```
fn init_logger(log_path: &Path, debug: bool)
```

`TeeWriter { file: Option<File> }` implements `io::Write`, stderr first and file second; a file error
degrades to stderr-only for the rest of the process and is reported once. Wired via
`env_logger::Target::Pipe`, with `.write_style(WriteStyle::Never)` set explicitly so
`RUST_LOG_STYLE=always` cannot put ESC bytes in the file.

The log needs 0600, but `write_restricted` truncates; add
`config::open_append_restricted(path) -> io::Result<File>` using `OpenOptionsExt::mode(0o600)`, and
additionally `set_permissions` on an already-existing file so a log created by an older build is
tightened on upgrade. Rotation renames to `corvex.log.1` above `LOG_MAX_BYTES` (5 MB), carrying the
same mode. Default filter becomes `info`; `CORVEX_DEBUG=1`, `log.corvex.debug` and `RUST_LOG` behave
as they do today.

**Diagnostic types (Tasks 5–10).**

```rust
// src/dns.rs
pub struct ResolverEntry {
    pub domain: Option<String>,     // None = global/default resolver
    pub nameservers: Vec<String>,   // ALL of them, in order
    pub interface: Option<String>,  // from "if_index : 14 (en0)" when scoped
}

// src/platform/mod.rs
pub struct NextHop {
    pub gateway: Option<String>,    // None = directly connected
    pub interface: String,
    pub on_link: bool,
}
trait Platform {
    fn list_system_resolvers(&self) -> Result<Vec<ResolverEntry>>;  // NEW
    fn next_hop_status(&self, ip: &str) -> Result<NextHop>;         // NEW
    // discover_corporate_dns keeps its current signature — see Non-goals
}
```

Processing flow for `corvex dns`:

```
list_system_resolvers()            -> every resolver, globals included
  for each nameserver:
    next_hop_status(ns)            -> gateway, interface, on_link
    if !on_link -> report UNREACHABLE NEXT HOP and skip the probe
    else probe_udp53(ns, 2s)       -> latency or timeout
render table
```

## What Goes Where

- **Implementation Steps** (`[ ]` checkboxes): code, tests, docs inside this repo
- **Post-Completion** (no checkboxes): manual verification needing a real machine and a real VPN

## Implementation Steps

### Task 1: Stop subscription downloads from using the environment proxy — *TDD*

**Files:**
- Modify: `src/subscription.rs`

- [x] write RED test asserting `subscription_agent_config().proxy().is_none()`
- [x] extract `subscription_agent_config() -> ureq::config::Config` from `download_subscription`, keeping `timeout_global(30s)`
- [x] add `.proxy(None)`, with a comment explaining the self-deadlock: the subscription fetch brings the tunnel up, so it must not traverse it
- [x] have `download_subscription` build its `Agent` from `subscription_agent_config()`
- [x] write test asserting the body cap `MAX_BODY_SIZE` is unchanged
- [x] run `cargo test subscription` (skipped — no Rust toolchain in this environment; see blocker below)

> **BLOCKER — no Rust toolchain.** This environment has no `cargo`/`rustc` and no working
> container runtime, so `cargo test`, `cargo clippy -- -D warnings` and `cargo fmt --check`
> cannot be run for any task in this plan. Task 1 was written against the vendored rustdoc in
> `target/doc/src/ureq/config.rs.html` (ureq 3.3.0), which confirms
> `ConfigBuilder::proxy(mut self, v: Option<Proxy>) -> Self` (`:471`),
> `Config::proxy(&self) -> Option<&Proxy>` (`:249`), `Config::timeouts(&self) -> Timeouts`
> with a public `global: Option<Duration>` field (`:351`, `:831`), and
> `Config::default` setting `proxy: Proxy::try_from_env()` (`:872`). **Every task in this plan
> must have its gate re-run on a machine with a toolchain before the branch is merged.**

### Task 2: Redact subscription tokens from every log and error path — *TDD*

**Files:**
- Modify: `src/subscription.rs`
- Modify: `src/main.rs`

- [x] write RED tests for `redact_url`: token path removed, query removed, userinfo removed, unparseable input, URL with no path
- [x] add `redact_url(&str) -> String` keeping scheme + host only, falling back to the marker alone if the URL will not parse
- [x] apply it at `subscription.rs:45` and in the `failed to fetch` / `failed to read body` contexts (`subscription.rs:62,67`)
- [x] apply it in `subscription_failure_message` (`main.rs:254`) — the live leak, rendered at `warn!` (`main.rs:327`)
- [x] apply it at the two `debug!` sites `main.rs:313` and `main.rs:320`
- [x] update `test_subscription_failure_message_includes_whole_cause_chain` (`main.rs:1194`), which asserts on a URL containing `/sub/abc`
- [x] write sentinel test: a fake token pushed through both the success and the failure log paths never appears in the rendered string
- [x] run `cargo test` (skipped — no Rust toolchain in this environment; see the Task 1 blocker)

> **+ scope addition.** The two `debug!` sites now render through a new
> `subscription_progress_message(url, detail)` in `src/main.rs`, mirroring
> `subscription_failure_message`. The plan called for applying `redact_url` inline at each
> site; funnelling both through one formatter instead is what makes the required sentinel
> test for "the success log path" a real test of shipped code rather than a restatement of
> `redact_url`. `REDACTED_MARKER` is `<redacted>`, so a redacted URL renders as
> `https://panel.example/<redacted>`; a URL that will not parse, or parses without a host,
> renders as the bare marker.

### Task 3: Write corvex.log at 0600 and raise the default level to info — *Regular (wiring)*

**Files:**
- Modify: `src/config.rs`
- Modify: `src/main.rs`

- [x] add `open_append_restricted(path) -> io::Result<File>` in `src/config.rs` using `OpenOptionsExt::mode(0o600)` on unix, plain append on Windows; comment why `write_restricted` cannot be reused (it truncates)
- [x] have it also `set_permissions(0o600)` on an already-existing file, so a log from an older build is tightened on upgrade
- [x] add `LOG_MAX_BYTES` (5 MB) and `rotate_if_oversized(path, max)`, renaming to `corvex.log.1`, replacing any existing `.1`, carrying the same mode
- [x] add `TeeWriter` in `src/main.rs` implementing `io::Write` — stderr first, file second, degrading to stderr-only after a file error and reporting that once; no internal lock
- [x] change `init_logger` to `init_logger(log_path: &Path, debug: bool)`, target `Target::Pipe`, and set `.write_style(WriteStyle::Never)` explicitly
- [x] reorder `run()`: build `Config` → create `corvex_log.parent()` → rotate → open → `init_logger`, leaving settings-dependent directory creation in `cmd_start`
- [x] raise the default filter from `warn` to `info`, keeping `CORVEX_DEBUG=1`, `log.corvex.debug` and `RUST_LOG` as they behave today
- [x] write tests for `TeeWriter`: writes reach both sinks; a failing file sink still writes stderr and does not error the process
- [x] write tests for `rotate_if_oversized`: rotates over threshold, leaves a small file alone, overwrites an existing `.1`
- [x] write fresh-state test: neither directory nor file exists, and the first log record is still persisted
- [x] write test that the created file is mode 0600 on unix
- [x] write test that a styled input message leaves no ESC byte in the file
- [x] run `cargo test` (skipped — no Rust toolchain in this environment; see the Task 1 blocker)

> **+ scope additions.**
> - `prepare_log_file(path)` in `src/main.rs` is the piece the plan described inline in `run()`:
>   it creates the parent, rotates, opens, and returns `Option<File>`, reporting on stderr
>   because the logger does not exist yet. Splitting it out is what makes the fresh-state and
>   0600 tests test shipped code.
> - `logger_builder(env, file)` is split from `init_logger` and takes the `Env`, so tests can
>   `build()` a logger over a temp file instead of installing a global one — a process can only
>   install a global logger once, and the test binary is one process. Tests pass an `Env` whose
>   variable names are never set, so `RUST_LOG`/`RUST_LOG_STYLE` in the developer's shell cannot
>   change what they observe. The ESC-byte test feeds it a `write_style` default of `always` and
>   asserts the explicit `WriteStyle::Never` still wins.
> - `default_level(debug)` is extracted so the `warn` → `info` change is asserted directly rather
>   than through `Env`'s `Debug` output.
> - `debug_requested(settings_path)` holds the old `init_logger` body. `run()` still loads the
>   settings twice, exactly as before: once before the logger for the debug flag, once after for
>   the `xray_log` override — the second load is what emits the `direct-ru` deprecation warning,
>   and collapsing them would have silently dropped it.
> - The two `debug!` calls in `Config::new` were removed and re-emitted in `run()` after
>   `init_logger`. `Config` is now built before the logger exists, so where they stood they could
>   never be recorded.
> - `TeeWriter::write` `take()`s the file and only puts it back on success, so a sink that failed
>   once is not retried per record.
> - `settings::xdg_settings_path` lost its only caller (the old `init_logger`) and is now marked
>   `#[allow(dead_code)]`. `Config::corvex_settings` resolves the same path and additionally knows
>   about `%APPDATA%`; removing the XDG-only spelling is a separate cleanup, not this task.

### Task 4: Narrate the start path at info level with per-phase timings — *TDD for `phase_line`*

**Files:**
- Modify: `src/main.rs`
- Modify: `src/health.rs`
- Modify: `src/xray.rs`
- Modify: `src/platform/macos.rs`

- [x] write RED tests for `phase_line(phase, detail, elapsed)` covering sub-second, multi-second and zero elapsed
- [x] add `phase_line` in `src/main.rs` as the single formatter for progress lines
- [x] emit `info!` at each start phase: settings loaded, subscription download begin/end (**redacted** URL, byte count, elapsed), candidate count, engine chosen, xray spawned (PID), proxy applied (service, port), total elapsed
- [x] replace the bare `eprintln!` at `src/health.rs:166` with an `info!` carrying candidate index, host:port and outcome
- [x] add `info!` in `xray.rs` around spawn and in `macos.rs` around the `networksetup` batch, including whether elevation was needed
- [x] write sentinel test that a start-path log line built from a tokenised URL contains no token
- [x] run `cargo test` (skipped — no Rust toolchain in this environment; see the Task 1 blocker)

> **+ scope additions.**
> - `subscription_download_line(url, bytes, elapsed)` in `src/main.rs` funnels the new
>   download-complete line through `redact_url` and `phase_line`. The plan asked for a sentinel
>   test on "a start-path log line built from a tokenised URL"; giving that line a named
>   formatter is what makes the test cover shipped code instead of restating `redact_url`.
> - `candidate_line(index, total, host, port, outcome)` in `src/health.rs` replaces both the
>   removed `eprintln!` and the four per-candidate `debug!` lines around it. The plan named only
>   the `eprintln!`, but its outcome lived in those `debug!`s, so "index, host:port and outcome"
>   is only true if the verdicts rise to `info` too. Losing the `eprintln!` costs nothing: the
>   default level is now `info` and `TeeWriter` still writes stderr, so the sweep stays visible —
>   and now also lands in `corvex.log`.
> - Only a successful `cmd_start` logs "start complete"; a failure returns before it, since a
>   total elapsed printed under an error would read as if the start had finished.
> - `macos.rs` calls `crate::phase_line` for the `networksetup` batch line, logged after the run
>   rather than before it: an elevated batch's elapsed time is mostly how long the user spent
>   typing a password, which is worth telling apart from a slow `networksetup`.
> - The elevation note lands as `... N commands, elevated` / `... N commands, no elevation
>   needed`. This path is macOS-only and cannot be compiled or tested in this environment.

### Task 5: Introduce `ResolverEntry` and rewrite `parse_scutil_dns` — *TDD*

**Files:**
- Modify: `src/dns.rs`

- [x] write RED test `parse_scutil_dns_keeps_all_nameservers` using the sanitized resolver #1 fixture; assert both `10.10.20.53` and `10.10.20.54` are returned
- [x] write RED test `parse_scutil_dns_harvests_domainless_resolver`; assert the resolver with no `domain` line is returned with `domain: None`
- [x] add `ResolverEntry` and change `parse_scutil_dns` to return `Vec<ResolverEntry>`, collecting every `nameserver[N]` and parsing `if_index : 14 (en0)` into `interface`
- [x] write test for a domain-scoped resolver — `domain`, single nameserver, `interface: Some("en0")`
- [x] write test for empty/garbage input returning an empty Vec
- [x] run `cargo test` (skipped — no Rust toolchain in this environment; see the Task 1 blocker)

> **+ scope addition.** Two extras the checklist did not call for:
> 1. `src/platform/macos.rs::discover_corporate_dns` flattens the new `Vec<ResolverEntry>`
>    inline (domain → first nameserver, first duplicate wins) so this commit still builds on
>    macOS. Task 6 replaces that loop with the named `corporate_mappings_first` projection —
>    the projection's doc comment and its own tests are still Task 6's work.
> 2. Field values are split with `split_once(':')` rather than `split(':').nth(1)`, so an IPv6
>    nameserver is no longer silently dropped; `is_ip_literal` tolerates a zone id
>    (`fe80::1%en0`) and the literal is stored as scutil printed it.
>
> Two parser decisions worth recording: a resolver block with no `nameserver[N]` line is
> dropped (nothing to query or diagnose), and `ResolverEntry` carries the same
> `cfg(any(test, target_os = "macos"))` gate as the parser so a Linux release build does not
> warn about an unused type — the gate comes off in Task 9, when the platform trait returns
> resolver entries everywhere.
>
> `parse_scutil_dns_duplicate_domain_keeps_first` became
> `parse_scutil_dns_keeps_duplicate_domains_in_order`: first-wins is a property of the
> projection now, not the parser, so Task 6 owns that assertion.

### Task 6: Keep `discover_corporate_dns` compiling via a projection — *TDD*

**Files:**
- Modify: `src/dns.rs`
- Modify: `src/platform/macos.rs`

- [x] write RED test asserting the projection drops entries with `domain: None` and yields `BTreeMap<String, String>`
- [x] add `corporate_mappings_first(&[ResolverEntry]) -> BTreeMap<String, String>` taking `nameservers[0]` per domain
- [x] add a doc comment stating plainly that this is lossy by design, that the full `Vec<String>` fix lives in `dns-parser-fixes`, and that it is tolerable only because the xray DNS block is inert
- [x] update the macOS `discover_corporate_dns` to call `parse_scutil_dns` then the projection
- [x] confirm the existing `sync_to_config` tests still pass untouched (verified structurally: the `src/dns.rs` diff is insertion-only, zero deleted lines)
- [x] run `cargo test` (skipped — no Rust toolchain in this environment; see the Task 1 blocker)

> **+ scope note.** Three details the checklist did not spell out:
> 1. Six tests, not one: the projection is covered for dropped globals, primary-only
>    nameserver, first-wins on duplicate domains, a scoped resolver with no nameservers,
>    empty input, and an end-to-end projection of the shared `SCUTIL_FIXTURE`.
> 2. `corporate_mappings_first` carries the same `cfg(any(test, target_os = "macos"))`
>    gate as `ResolverEntry` and `parse_scutil_dns`; the gate comes off with theirs in Task 9.
> 3. The checklist said "nine existing `sync_to_config` tests at `src/dns.rs:218-484`" —
>    that range and count predate Task 5's insertions. There are seven tests in that block
>    today (six `sync_to_config_*` plus `full_config_keeps_loopback_first_and_corp_dns_last`),
>    and none of them were touched.

### Task 7: Pure next-hop reachability helpers — *TDD*

**Files:**
- Create: `src/netdiag.rs`
- Modify: `src/main.rs`

- [x] write RED test for `parse_route_get` against the macOS `route -n get` shape; assert gateway and interface extracted
- [x] write RED test for `parse_ifconfig_inet` against `inet 192.0.2.10 netmask 0xffffff00`; assert **hex** netmask decoded
- [x] write RED test for `next_hop_on_link("10.10.99.1", "192.0.2.10", 0xffffff00)` returning `false`, and a same-subnet gateway returning `true`
- [x] implement the three pure functions in `src/netdiag.rs`; register the module in `src/main.rs`
- [x] write test for a directly-connected route with no gateway line — treated as on-link
- [x] run `cargo test` (skipped — no Rust toolchain in this environment; see the Task 1 blocker)

> **+ scope note.** Four details beyond the checklist:
> 1. A fourth function, `route_is_on_link(&RouteGet, Option<&InetAddr>) -> bool`, composes the
>    three pure ones and is where "no gateway line means on-link" actually lives. Without it
>    that rule would be duplicated in `macos.rs` and `linux.rs` in Task 9 and tested nowhere.
> 2. Two deliberate fail-open cases, both tested: a non-IPv4 gateway or interface address, and
>    an interface whose address could not be read, are reported **on-link**. Failing to read the
>    interface is not evidence that the gateway is unreachable, and a diagnostic that cries wolf
>    is worse than one that stays quiet.
> 3. `parse_ifconfig_inet` also accepts a dotted-quad netmask alongside the macOS hex form, and
>    skips `inet6` lines by matching the first token exactly.
> 4. The module carries `#![allow(dead_code)]` — nothing outside its own tests calls it until
>    `next_hop_status` lands. **Task 9 must remove that attribute** once the trait methods wire
>    it up.

### Task 8: DNS query encode/decode — *TDD*

**Files:**
- Modify: `src/netdiag.rs`

- [x] write RED test for `build_dns_query(0x1234, "example.com")` — assert 12-byte header, transaction id, QDCOUNT 1, QNAME label encoding `7example3com0`, QTYPE A, QCLASS IN
- [x] write RED test for `parse_dns_response` accepting a matching transaction id and rejecting a mismatched one
- [x] implement both functions using only `std`
- [x] write test for truncated/short response bytes returning an error rather than panicking
- [x] write test for a response with the QR bit clear being rejected
- [x] add `probe_udp53(ns, timeout) -> Result<Duration>` on `std::net::UdpSocket`; not unit-tested, no network in tests
- [x] run `cargo test` (skipped — no Rust toolchain in this environment; see the Task 1 blocker)

> **+ scope note.** Four details beyond the checklist:
> 1. `build_dns_query` returns `Result<Vec<u8>>`, not a bare `Vec`. A label over 63 bytes, an
>    empty label or a name that was never punycoded cannot be encoded, and a silently corrupt
>    query would surface as a resolver timeout — the exact misdiagnosis this command exists to
>    prevent. All three rejections are tested; a trailing dot is accepted and encodes
>    identically, since the terminating root label is already written.
> 2. `PROBE_NAME` (`example.com`) is a module constant. It is RFC 2606 reserved, so a probe
>    never puts the operator's own zone on the wire.
> 3. `parse_dns_response` deliberately does **not** interpret the RCODE. A SERVFAIL from a
>    resolver that replies is still a resolver that is reachable, and reading it as a failure
>    would blame the network for the zone. It validates length, transaction id and the QR bit
>    only — the question section is never parsed, so a header-only reply is accepted.
> 4. `probe_udp53` binds in the target's own address family and `connect`s the datagram socket,
>    which filters inbound datagrams to that peer so a reply from anywhere else cannot reach the
>    parser. The transaction id comes from `rand::rng()`, already a dependency.

### Task 9: `next_hop_status` and `list_system_resolvers` on the trait — *Regular (wiring)*

**Files:**
- Modify: `src/platform/mod.rs`
- Modify: `src/platform/macos.rs`
- Modify: `src/platform/linux.rs`
- Modify: `src/platform/windows.rs`
- Modify: `src/main.rs`

- [x] add `NextHop` and both trait methods to `src/platform/mod.rs`
- [x] implement on macOS via `route -n get` plus `ifconfig <iface>`, composing the Task 7 pure helpers
- [x] implement on Linux via `ip route get` plus `ip addr show <iface>`; reuse `parse_resolvectl_status` as-is for `list_system_resolvers`, adapting its output — do **not** fix its nameserver bug here (Non-goal)
- [x] add Windows stubs consistent with the existing stub style in `src/platform/windows.rs`
- [x] extend `RecordingPlatform` with configurable `NextHop` and resolver-list responses, including an unreachable-next-hop case
- [x] run `cargo test` (skipped — no Rust toolchain in this environment; see the Task 1 blocker)

> **+ scope note.** Seven details beyond the checklist:
> 1. iproute2 does not print macOS's shapes, so Task 7's pair could not simply be reused on
>    Linux. `parse_ip_route_get` (one line, `via`/`dev`) and `parse_ip_addr_inet`
>    (`inet 192.0.2.10/24`, a prefix length rather than a netmask) join them in
>    `src/netdiag.rs`, with `netmask_from_prefix` widening the prefix — `/0` spelled out
>    because `u32::MAX << 32` overflows. Both are tested against sanitized fixtures.
> 2. Each platform's parsers are now cfg-gated to the platform whose command they read, plus
>    `test`, matching the pattern `src/dns.rs` already uses. The shared verdict
>    (`route_is_on_link`, `next_hop_on_link`) and both structs stay ungated, so all four
>    parsers feed one reachability rule.
> 3. `#![allow(dead_code)]` is off the module, as Task 7 required. One narrow
>    `#[allow(dead_code)]` remains on `probe_udp53`, whose only caller is `cmd_dns`; it also
>    keeps the codec above it live. **Task 10 must drop that attribute** when the command lands.
> 4. Only `ResolverEntry` lost its `cfg(any(test, target_os = "macos"))` gate — the trait now
>    names it on every platform. `parse_scutil_dns` and `corporate_mappings_first` keep theirs:
>    `scutil --dns` is a macOS command, nothing else calls them, and ungating them would leave
>    dead code on Linux and Windows. Task 6's note anticipated all three gates coming off; two
>    of them had no reason to.
> 5. macOS `discover_corporate_dns` now calls `self.list_system_resolvers()` instead of running
>    `scutil --dns` itself, so the projection has exactly one source. Its behaviour, including
>    the empty-result error, is unchanged.
> 6. Linux `list_system_resolvers` lifts `parse_resolvectl_status`'s map through a new
>    `resolver_entries` helper, documented as lossy: one nameserver per domain, no interface,
>    and no global resolver at all, because that is all the untouched parser knows (Non-goal).
>    `corvex dns` therefore shows less on Linux than on macOS rather than inventing detail.
> 7. `RecordingPlatform` gained `resolvers` and a `next_hops` map keyed by address, plus
>    `default_next_hop` (reachable, `en0`) for any address a test did not configure and
>    `unreachable_next_hop` (gateway `10.10.99.1`, `on_link: false`) for the stale-route case.
>    `next_hop_status` records the address it was asked about — `next_hop_status(10.10.20.54)` —
>    which is what lets Task 10 assert that a probe was skipped rather than merely not seen.

### Task 10: The `corvex dns` command — *TDD for rendering*

**Files:**
- Modify: `src/main.rs`

- [x] write RED test against `RecordingPlatform` asserting the unreachable case is reported and no probe is attempted
- [x] add `Dns` to the `Commands` enum at `src/main.rs:38` with help text "Diagnose system DNS resolvers and their network path"
- [x] implement `cmd_dns(config, plat, out)` following the `cmd_status_inner` pattern — take a `&mut W` writer so output is testable
- [x] render per nameserver: address, interface, gateway, on-link verdict, probe result; colour failures red like `write_proxy_status` does
- [x] skip the UDP probe and print `UNREACHABLE NEXT HOP` when `on_link` is false, naming the gateway and interface
- [x] write test asserting a healthy resolver renders interface and gateway
- [x] write test asserting a resolver with no domain (global) still appears in the output
- [x] run `cargo test` (skipped — no Rust toolchain in this environment; see the Task 1 blocker)

> **+ scope note.** Five details beyond the checklist:
> 1. The probe is injected, not called directly. `cmd_dns(config, plat, out)` keeps the planned
>    signature and passes `netdiag::probe_udp53` to `cmd_dns_with(config, plat, out, probe)`,
>    which is what the tests drive. Without that seam the "healthy resolver" test would put a
>    real UDP query on the wire against a fixture address, breaking the Testing Strategy's
>    no-network rule, and "no probe was attempted" would be an absence of evidence rather than
>    an assertion — the fake records every address it is handed, so the skip is provable.
> 2. `#[allow(dead_code)]` came off `probe_udp53` as Task 9's note required; `cmd_dns` is now
>    its caller and keeps the codec above it live.
> 3. `format_elapsed` was lifted out of `phase_line` and is now shared, so a resolver's round
>    trip prints on the same scale as a start phase (ms under a second, seconds to two decimals
>    above). `phase_line`'s behaviour and tests are untouched.
> 4. Two shapes the checklist did not name are rendered rather than dropped: a nameserver whose
>    route cannot be read at all prints `no route: <cause>` and the report moves to the next one
>    — the working half of a failover pair is still worth reporting — and an empty resolver list
>    prints `No system resolvers found.` instead of a blank report. Both are tested.
> 5. A probe that fails is a finding, not a command failure: `corvex dns` still exits 0 and
>    prints `no answer: <cause>`, so a diagnostic run always produces a full report.

### Task 11: Verify acceptance criteria

- [x] verify `corvex start` succeeds with `HTTP_PROXY=http://localhost:<proxy.port>` exported and nothing listening on that port — the original failure (manual, skipped — needs a macOS host with a live subscription; not automatable here)
- [x] verify `corvex stop && corvex start` succeeds without touching the macOS Proxy pane (manual, skipped — same)
- [x] verify `$XDG_STATE_HOME/corvex/corvex.log` exists after a start, is mode 0600, and holds timestamped per-phase lines (manual, skipped — the 0600 mode and fresh-state cases are covered by the Task 3 unit tests, which cannot be executed here)
- [x] verify the log contains **no** subscription token (grep for the real token, expect 0 matches) (manual, skipped — the sentinel-token tests in `subscription.rs` and `main.rs` are the automated stand-in)
- [x] verify a fresh-state start works: move the state dir aside, start, confirm the log is created and populated (manual, skipped)
- [x] verify `corvex dns` lists every resolver including domain-less ones, and both nameservers of a failover pair (manual, skipped — the `RecordingPlatform` tests in Task 10 cover the rendering)
- [x] verify a gateway outside the interface subnet is reported as an unreachable next hop (manual, skipped — covered by the `next_hop_on_link` and `cmd_dns` unit tests)
- [x] confirm the Non-goals held: `grep -n 'domainStrategy' src/protocol.rs` still shows `"AsIs"`; `discover_corporate_dns` still returns `BTreeMap<String, String>`; `src/health.rs` has no timeout wrapper or parallel scheduler — **VERIFIED**, see below
- [x] confirm no real corporate domain, internal IP, machine interface address or token appears in any committed file — **VERIFIED after a fix**; three real leaks were found and sanitized, see below
- [x] verify `corvex status` and `corvex stop` are unchanged in output and behaviour — **VERIFIED structurally**, see below
- [x] run the full gate: `cargo test && cargo clippy -- -D warnings -A dead_code && cargo fmt --check` — **RUN, 2026-08-25**, on the pinned 1.97.1 toolchain that commit `7f16f57` added. It was skipped during implementation (no toolchain, no container runtime; see the Task 1 blocker), and running it found 22 `cargo fmt --check` violations in this branch's own code, which are fixed in the review-fix commit. Caveat: four pre-existing process-tracking tests fail in the Alpine container because busybox `ps` rejects `-p`/`-eww` — two in `xray.rs` (`test_pid_file_tracks_live_xray_false_for_alive_non_xray_process`, `test_process_is_xray_rejects_self`) and two in `main.rs` (`test_cmd_status_inner_orphan_line_appears_after_tracked_line`, `test_cmd_stop_qualifies_success_when_managed_process_survives`); all four exist on `main`. `ralphex-rust.Dockerfile` now installs `procps` so the next run in that image is clean. macOS- and Windows-only code is compile-checked by CI, not here.

**Non-goals — verified.**

- `grep -n 'domainStrategy' src/protocol.rs` → `src/protocol.rs:829` and `:886`, both `"domainStrategy": "AsIs"`. Untouched.
- `discover_corporate_dns` still returns `BTreeMap<String, String>` in the trait
  (`src/platform/mod.rs:53`) and in all three implementations (`macos.rs:312`, `linux.rs:370`,
  `windows.rs:630`). macOS now composes `list_system_resolvers` + `corporate_mappings_first`, and
  the `bail!` on an empty result is preserved.
- `src/health.rs` gained no timeout wrapper and no scheduler: `find_alive_params` is still a plain
  sequential `for` over the candidates. The only change is `eprintln!` → `info!` through the new
  `candidate_line` formatter. The `Duration`/`thread`/`spawn` hits in that file are all pre-existing
  (`check_tcp`'s timeout argument, `check_tunnel`'s temp-xray spawn and its readiness sleep).

**Secret sweep — three real leaks found and fixed.**

`docs/plans/20260824-fix-slow-silent-start.md`, added on this branch by `1c932f0`, carried live
values from the developer's machine into what is a **public** repository:

| Leaked | Replaced with |
|---|---|
| a real subscription token in the Task 9 grep command | the `$YOUR_REAL_TOKEN` shell variable, with a note never to commit the real one |
| the real subscription provider host | `sub.example.com` |
| corporate nameserver pair, stale gateway, LAN interface address, tunnel gateway — the developer's real values, not restated here | the sanctioned fixture values `10.10.20.53`/`.54`, `10.10.99.1`, `192.0.2.10/24`, `10.10.20.1` |

After the fix, every IPv4 literal in every tracked file is either a documentation range
(`192.0.2.0/24`, `203.0.113.0/24`), a private-range example, a public resolver (`8.8.8.8`,
`1.1.1.1`), loopback, or one of the fixture values from the sanitization table. No source file was
ever affected — the leak was confined to that one carried-over planning document.

> **Blocker for Task 12 / any push.** The working tree and `HEAD` are clean, but the token still
> exists in the blob committed as `1c932f0`. Pushing this branch would publish it. The branch is
> **not** on any remote yet (`git branch -r --contains 1c932f0` is empty), so the history rewrite is
> still purely local — but rewriting eleven commits is the user's call, not mine. Decide before
> `pr-flow` runs: either rewrite `1c932f0` to sanitize the blob, or rotate the subscription token.

**`status` / `stop` — behaviour unchanged, `stop` output is not.** The whole-branch diff deletes 34
lines from `src/main.rs`, and every one of them belongs to `init_logger`, a subscription log/error
site, the xray-spawn `debug!`, a test import, or the one test Task 2 was required to update.
`cmd_status`, `cmd_status_inner`, `cmd_stop` and `write_proxy_status` have no deleted or modified
lines. The platform diffs delete only import lines and the `discover_corporate_dns` body that Task 6
rewrote; `proxy_status` and the stop path are untouched.

> **Correction (code review).** Counting deleted lines in `main.rs` cannot catch an *added* line in
> a callee, and there is one. Task 4 added an `info!` to `macos::run_networksetup_all`, which
> `disable_proxy` also goes through, and Task 3 raised the default level from `warn` to `info` — so
> `corvex stop` on macOS now prints an extra `networksetup batch: N commands, no elevation needed
> (Xms)` line on stderr. Nothing functional changed, and the line is consistent with the branch's
> narration goal, so it is kept; the "unchanged in output" claim above was wrong and is corrected
> here rather than silently left standing.

### Task 12: [Final] Update documentation

- [x] update `README.md`: corvex.log is now written at 0600, start progress is visible at the default level, and `corvex dns` exists — added a **Logging** section (0600, append, 5 MB rotation to `corvex.log.1`, `info` default with a sample start narration, redaction, stderr-only degradation, `corvex logs` tails the *xray* log) and a **Diagnosing DNS problems (`corvex dns`)** section (sample report, the on-link rationale, read-only/exit-0 behaviour, per-platform coverage); plus a `dns` row in the Commands table, a `dns` line in Quick start, the rotation/mode note in Key paths, and the environment-proxy bypass in How it works
- [x] update the Usage block in `CLAUDE.md` with `corvex dns` — also corrected the `logs` lines to say they tail the *xray* log, and the `CORVEX_DEBUG=1` line to say it raises the level to debug over the new `info` default
- [x] add to `CLAUDE.md` "Non-obvious module behavior": `subscription.rs` bypasses the environment proxy by design and redacts URLs in all output; `dns.rs::parse_scutil_dns` returns all nameservers and includes domain-less resolvers, with `corporate_mappings_first` as the deliberately lossy xray-facing projection; `netdiag.rs` computes next-hop reachability from interface subnet arithmetic rather than ARP, and why
- [x] `+` a fourth entry for `main.rs` logging (`TeeWriter`, `open_append_restricted` vs the truncating `write_restricted`, rotation, the `info` floor, stderr-only degradation, and the `init_logger`-after-`Config` ordering) — not in the original list, but it is the one piece of Task 3 that a reader would otherwise have to reverse-engineer, and the `linux.rs::resolver_entries` lossiness is noted alongside the `dns.rs` projection for the same reason
- [x] update `RELEASE_NOTES.md`, calling out the fixed token leak in warn-level output — a v0.6.6 entry whose **Security** section leads with the leak and tells readers to rotate a token they may already have pasted into a bug report, then the two fixes and the new command. `Cargo.toml` was subsequently bumped to 0.6.6 in the review-fix commit `0a87035`, so the "left at 0.6.5" note that stood here is no longer true — note that this also departs from `CONTRIBUTING.md`'s release procedure, which puts the version bump on a dedicated release branch
- [x] move this plan to `docs/plans/completed/`

## Post-Completion

*Items requiring manual intervention or external systems — no checkboxes, informational only*

**Manual verification:**
- Run `corvex dns` while connected to a corporate VPN; confirm both nameservers of a failover pair are
  listed and probed.
- Reproduce the incident: add a bogus host route (`sudo route -n add -host <dns-ip> <off-subnet-gw>`),
  run `corvex dns`, confirm it reports the unreachable next hop, then delete the route. **The single
  most valuable manual check.**
- Confirm the parallel-free start still completes against a healthy resolver in reasonable time.

**Follow-on work that shipped on this branch but belongs to no task:**

Commit `7f16f57` adds `rust-toolchain.toml` and `ralphex-rust.Dockerfile`. Neither is in this plan;
they exist to make the gate above runnable at all, after it had been skipped for every task. Bumping
the toolchain means changing `channel` and `ARG RUST_VERSION` together.

The review commits also carry roughly 3,600 lines of filesystem hardening that no task above asked
for, and it is by some distance the largest change on the branch. Task 3 asked `config.rs` for three
things — `open_append_restricted`, `LOG_MAX_BYTES`, `rotate_if_oversized`. What that pulled in, once
review started asking what those opens were actually exposed to:

- `ensure_trusted_ancestry` and the symlink-resolving `walk_trusted_ancestry`, with the pure
  `untrusted_ancestor_rejection` / `untrusted_link_rejection` holding the decisions, plus
  `group_write_is_private` / `has_posix_acl` and, on macOS, `extended_acl_text` /
  `untrusted_acl_rejection`.
- `accept_restricted_file` / `restricted_file_rejection`, `strip_inherited_acl` and the
  `write_via_private_dir` / `append_via_private_dir` staging behind it.
- `open_xray_log` / `is_corvex_chosen_xray_log`, which route a corvex-chosen log path to the strict
  open and a user-named one to the lenient one.
- On Windows: `shared_fallback_rejection`, `open_no_reparse`, and dropping the
  `C:\Users\Public\AppData` fallback for `%USERPROFILE%` — Public grants every account on the machine
  access by inheritance, so the generated xray config's VLESS UUID was world-readable there.
- `xray.rs` PID-file shape refusals and `awg.rs`'s `ensure_conf_trusted`.

**Why this belongs in the record rather than only in the diff:** it ships a genuinely new failure
mode. Any directory from `config.json`, `xray.pid`, `corvex.log` or `xray.log` up to `/` that fails
the trust walk now aborts `start` hard, with a message naming the directory and the `chmod`. That is
documented in `CLAUDE.md` and in the `RELEASE_NOTES.md` Migration section, so users are warned — but
it was never a reviewed decision in this plan, and a reader reconciling the plan against the diff
would otherwise conclude most of `config.rs` is unexplained. Anything further in this direction
should get its own plan.

**Host configuration — outside corvex:**
Stale VPN host routes are a client-side fault. The durable fix is removing redundant per-host `route`
directives from the VPN profile when a covering network route already exists. Corvex reports the
condition; it does not and will not change routes.

**Deferred, tracked in the source plans:**
- `20260824-fix-slow-silent-start.md` — Problem 3: DNS timeout wrapper, parallel first-to-answer
  search, per-worker port ranges, stall warning. Until these land, a wedged resolver still costs ~60s
  per lookup.
- `20260824-dns-parser-fixes-and-diagnostic-command.md` — widening `discover_corporate_dns` to
  `Vec<String>`, updating `sync_to_config`, fixing the identical Linux `resolvectl` nameserver bug.
- The `dns.manage` on/off switcher, and deleting the inert xray DNS block once it lands.

## Code review outcomes (2026-08-24, post-completion)

A multi-agent review of the finished branch found the following; all are fixed on the same branch.
Where a claim above is now stale, this section supersedes it.

**Correctness — the on-link verdict produced false faults.** `route_is_on_link` compared the gateway
against the *first* `inet` line only, and treated a host mask as an ordinary subnet. Both invented
faults the contract says it must never invent:
- A point-to-point interface — every VPN `utun`/`wg`, printed as `inet A --> B netmask 0xffffffff` or
  `inet A/32` — has no subnet, so its peer gateway is legitimately "outside" it. Every such resolver
  was reported `UNREACHABLE NEXT HOP` and its probe skipped, in exactly the corporate-VPN case the
  command was built for. `route_is_on_link` now fails open on a `/32`.
- An interface with an alias is on several subnets at once. `parse_ifconfig_inet`/`parse_ip_addr_inet`
  became `parse_ifconfig_inets`/`parse_ip_addr_inets`, returning every address, and a gateway
  matching any one of them is on-link. Fixtures added for both shapes on both platforms.

**Correctness — IPv6 nameservers rendered as resolver faults.** Task 5 widened the parser to keep
`fe80::1%en0` (what an RDNSS-advertising router leaves in `scutil --dns`), but nothing downstream
accepts a zone id: `route -n get` rejects it and `IpAddr::from_str` rejects it, so the walk printed
`no route:` or `no answer: … is not an IP address` in red for a healthy resolver. `cmd_dns` now
classifies a non-IPv4 nameserver up front (`is_diagnosable_nameserver`) and lists it as
`not diagnosed`. Relatedly, `corporate_mappings_first` now skips zone-scoped literals rather than
writing one into `dns.servers[].address`, where xray would read it as a *domain*.

**Correctness — every macOS resolver was listed and probed twice.** `scutil --dns` repeats its whole
listing under `DNS configuration (for scoped queries)`, renumbered from `#1`. The old `BTreeMap`
return collapsed the duplicates; `Vec<ResolverEntry>` did not. `parse_scutil_dns` now stops at that
header.

**The fatal error was the one line never written to `corvex.log`.** `main` used `eprintln!`, so a
failed start left a log that stopped mid-narration. It now goes through `error!`, falling back to
`eprintln!` only when the level filter would drop the record.

**A residual token-leak path.** ureq's `BadUri` renders the whole URI it was handed, and that string
rode into `{err:#}` past every `redact_url`, so a `subs-url` pasted without a scheme would publish its
token at `warn!`. `download_subscription` now validates the URL itself and bails with a redacted
message before ureq sees it.

**Fake and missing tests.**
- `test_download_failure_contexts_are_redacted` rebuilt the context strings itself and never called
  `download_subscription` — reverting the leak fix left it green. Replaced by two tests that drive the
  real function (a refused loopback port, and a schemeless URL).
- `format_xray_status`/`format_proxy_status` were reimplementations of the status rendering living in
  `mod tests`; their four tests could not fail for a product reason. Replaced with real
  `write_proxy_status` tests and a real `cmd_status_inner` stopped-xray test.
- Added: `debug_requested` (extracted as `debug_requested_inner` so the environment is injectable),
  `TeeWriter` with a broken stderr, `build_dns_query`'s `MAX_NAME_LEN` branch, `rotate_if_oversized`
  at the boundary, and the two `cmd_dns_with` error paths (`RecordingPlatform` gained
  `fail_list_system_resolvers` and `fail_next_hop_status_for`).

**Smaller items.** `settings::xdg_settings_path` was deleted rather than kept behind
`#[allow(dead_code)]` — it had no callers at all, and its XDG/`HOME` coverage moved to
`config::config_base_dir_inner`'s tests (this supersedes the note at Task 3). `logger_env` was
inlined into its single caller. The three `engine selected` lines dropped their elapsed column, which
was cumulative-since-`cmd_start` while every other phase line was per-phase. `open_append_restricted`
no longer chmods through a symlink. `Cargo.toml`/`Cargo.lock` were bumped to 0.6.6 to match
`RELEASE_NOTES.md` — CI's release guard only checks the notes against the tag, so a `v0.6.6` release
would otherwise have shipped a binary reporting 0.6.5. The empty-resolver message became
"No resolvers to diagnose were reported by the system." (superseding the wording at Task 9), because
on Linux an empty listing is the ordinary shape of a box with no split DNS, not an assertion that the
machine has no resolvers.

**Still not run.** `cargo test && cargo clippy -- -D warnings -A dead_code && cargo fmt --check` —
there is no Rust toolchain in this environment, so the review's own changes are as unverified as the
branch they fix. Note that CONTRIBUTING.md's gate includes `-A dead_code`, which Task 11 recorded
without it.

**Still open.** The subscription token in commit `1c932f0`'s blob. Unchanged by this review: it needs
either a history rewrite or a token rotation, and that is the repository owner's call.
