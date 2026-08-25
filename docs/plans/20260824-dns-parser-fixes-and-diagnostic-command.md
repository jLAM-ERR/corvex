# Fix DNS resolver parsing and add a `corvex dns` diagnostic command

## Status (2026-08-24)

**Partly delivered.** Task 1 (`ResolverEntry` and the `parse_scutil_dns`
rewrite), Task 6 (the pure next-hop helpers), Task 7 (the DNS query codec),
Task 8 (`next_hop_status` and `list_system_resolvers` on the trait) and Task 9
(the `corvex dns` command) shipped on branch `docs/start-and-dns-plans`; see
`docs/plans/completed/20260824-start-deadlock-logging-and-dns-diagnostic.md`,
the plan that was actually executed. The checkboxes below were never ticked.

Task 2 was **superseded, not done**: what shipped is
`dns::corporate_mappings_first`, returning `BTreeMap<String, String>` and
keeping one nameserver per domain, not the planned `corporate_mappings`
returning `BTreeMap<String, Vec<String>>`. It is documented as a knowingly
lossy projection precisely because Task 3 has not happened yet.

**What remains here** is the widening this file is cited for in CLAUDE.md:
Task 3 (widen the `Platform` trait to `BTreeMap<String, Vec<String>>`), Task 4
(`sync_to_config` for multiple nameservers) and Task 5 (the Linux `resolvectl`
parser, which still has both original bugs — one nameserver per domain, and no
global resolver — and is why `corvex dns` shows less on Linux than on macOS).

## Overview

Two parser bugs cause corvex to silently misread the system's DNS configuration, and there is no
command that shows what corvex actually sees. This plan fixes both bugs and adds a standalone
`corvex dns` diagnostic.

**Bug 1 — only the first nameserver survives.** `dns::parse_scutil_dns` keeps `nameserver[0]` only
(the `current_nameserver.is_none()` guard) and merges with `or_insert`. Corporate DNS is commonly a
failover pair; the secondary is dropped without a warning. `platform/linux.rs::parse_resolvectl_status`
has the identical bug (`rest.split_whitespace().next()`).

**Bug 2 — domain-less resolvers are invisible.** `parse_scutil_dns` only harvests resolvers that carry
a `domain :` line. The *primary* resolver on macOS typically has no domain line — just nameservers —
so the machine's main DNS servers are never seen. The root cause is the shape, not the loop: a
`domain -> nameserver` map cannot represent a resolver that has no domain. Fixing this requires a
richer type, which is why Task 1 introduces one.

**The diagnostic.** A real incident motivated this: a stale VPN host route pointed both corporate
nameservers at a gateway that was not on-link for the interface the route named, so ARP never resolved
and every DNS packet died with `sendto: Network is unreachable`. No firewall rule was involved, which
is exactly why it was slow to find — every individual layer looked healthy. `corvex dns` walks the
whole chain per nameserver: route -> interface -> **next-hop on-link check** -> live UDP:53 probe. The
on-link check is the highest-value part; it is the one that was missing.

**Why these three belong in one plan.** The xray DNS block stays inert (see Non-goals), so the two
parser fixes have *no user-visible runtime effect on their own* — their output feeds a block xray
ignores. `corvex dns` is their real consumer. That is what makes this scope coherent rather than
three unrelated edits.

## Non-goals

Explicitly out of scope. Do not add, do not propose, do not "while we're here":

- The `dns.manage` on/off switcher and its ON path — deferred to a later plan.
- Any change to xray DNS wiring: `routing.domainStrategy` stays `"AsIs"`, the dead `dns_out` tag
  stays, the `corporate-dns` domain matcher stays.
- Deleting the inert xray DNS block.
- Changing the corvex.json `corporate-dns` schema. It stays `domain -> single string`; the static
  value is wrapped into a one-element `Vec` at the merge point. Accepting arrays there is a breaking
  config change and belongs with the switcher work.
- Fixing routes. Corvex does not and will not manipulate routes — it only runs `route get`
  (read-only). The stale-route problem is fixed at the VPN client layer. Corvex's job here is to
  *detect and report* the condition, nothing more.

## Context (from discovery)

- `src/dns.rs:12` — `parse_scutil_dns`, both bugs live here
- `src/platform/mod.rs:33` — `discover_corporate_dns() -> Result<BTreeMap<String, String>>`, the
  signature that forces the data loss
- `src/platform/macos.rs:289`, `src/platform/linux.rs:368`, `src/platform/windows.rs:628` — the three impls
- `src/main.rs:235`, `src/main.rs:443` — the two production call sites
- `src/main.rs:1080` — `RecordingPlatform` mock; `src/main.rs:1140` — its `discover_corporate_dns`
- `src/dns.rs:67` — `sync_to_config`, plus nine tests at `src/dns.rs:218-484` that pin the current map type
- `src/main.rs:38` — `Commands` enum, where `Dns` is added

Conventions to follow (from CLAUDE.md):
- parsing functions take `&str` and are unit-testable without system calls
- command functions take `&impl Platform`, tested against `RecordingPlatform`
- platform abstraction via cfg-gated concrete types, no dynamic dispatch

**Dependencies:** none added. The UDP:53 probe uses `std::net::UdpSocket` with a hand-built minimal
DNS query (12-byte header + QNAME + QTYPE/QCLASS). A DNS crate would be a heavier answer to a
30-line problem.

### Fixture sanitization — required

**This repository is public (`jLAM-ERR/corvex`).** Test fixtures must NOT contain real corporate
domains, internal IP topology, or interface addresses from any developer's machine. Use sanitized
values that preserve the exact structure:

| Real (never commit) | Fixture value |
|---|---|
| corporate nameserver pair | `10.10.20.53` / `10.10.20.54` |
| stale/unreachable gateway | `10.10.99.1` |
| LAN interface address | `192.0.2.10` netmask `0xffffff00` |
| tunnel gateway | `10.10.20.1` |
| corporate domain | `corp.example.com` |

Structural shapes the fixtures must reproduce exactly:

```
resolver #1                          <- no domain line: the Bug 2 case
  nameserver[0] : 10.10.20.53
  nameserver[1] : 10.10.20.54        <- the Bug 1 case
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

- **testing approach**: **TDD — tests first.** Every unit here is a pure `&str -> value` function, and
  the two bugs are trivially expressible as failing assertions against the fixtures above. Write the
  RED test, then make it GREEN.
- complete each task fully before moving to the next
- **every task MUST include new/updated tests**; tests are listed as separate checklist items
- **all tests must pass before starting the next task** — no exceptions
- run `cargo test && cargo clippy && cargo fmt --check` after each change
- update this plan file when scope changes during implementation

## Testing Strategy

- **unit tests**: required for every task. Pure parsers get table-driven cases over the sanitized
  fixtures. Command functions are tested against `RecordingPlatform`.
- **e2e tests**: none — this project has no UI-based e2e suite.
- **no network in tests.** The UDP probe is split into pure encode/decode (tested) and a thin socket
  call (not unit-tested). Never make a real DNS query from the test suite.

## Progress Tracking

- mark completed items with `[x]` immediately when done
- add newly discovered tasks with the plus prefix
- document issues/blockers with the warning prefix
- keep plan in sync with actual work done

## Solution Overview

**One parser, two views.** `parse_scutil_dns` returns a rich `Vec<ResolverEntry>` that can represent a
domain-less resolver and any number of nameservers. `corporate_mappings()` projects it down to the
domain-scoped subset that feeds xray. This fixes both bugs at their shared root and keeps globals out
of the xray config, so **generated xray config semantics are unchanged apart from the secondary
nameserver now appearing**.

**Two new trait methods, not five.** Rather than exposing `route get`, `ifconfig`, and ARP separately,
the platform answers one question: `next_hop_status(ip) -> NextHop { gateway, interface, on_link }`.
The platform-specific commands stay inside the platform module; the on-link arithmetic is a pure
shared helper. `list_system_resolvers()` serves the diagnostic without disturbing
`discover_corporate_dns`.

**Key design decision — why `on_link` is computed, not probed.** ARP state is racy and needs
privileges to be meaningful. Instead, compare the gateway against the named interface's address and
netmask: if the gateway is not inside that interface's subnet, the next hop is structurally
unreachable regardless of ARP. That is a pure function over three values, unit-testable, and it is
precisely the condition that caused the incident.

## Technical Details

```rust
// src/dns.rs
pub struct ResolverEntry {
    pub domain: Option<String>,     // None = global/default resolver (Bug 2)
    pub nameservers: Vec<String>,   // ALL of them, in order (Bug 1)
    pub interface: Option<String>,  // from "if_index : 14 (en0)" when scoped
}

pub fn parse_scutil_dns(output: &str) -> Vec<ResolverEntry>;
pub fn corporate_mappings(entries: &[ResolverEntry]) -> BTreeMap<String, Vec<String>>;

// src/platform/mod.rs
pub struct NextHop {
    pub gateway: Option<String>,   // None = directly connected
    pub interface: String,
    pub on_link: bool,
}
trait Platform {
    fn discover_corporate_dns(&self) -> Result<BTreeMap<String, Vec<String>>>;  // CHANGED
    fn list_system_resolvers(&self) -> Result<Vec<ResolverEntry>>;              // NEW
    fn next_hop_status(&self, ip: &str) -> Result<NextHop>;                     // NEW
}
```

`sync_to_config` takes `&BTreeMap<String, Vec<String>>` and emits one xray `dns.servers` entry per
nameserver, each carrying the same `domains` list. That is valid xray and is purely additive.

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

- **Implementation Steps**: code, tests, docs inside this repo
- **Post-Completion**: manual verification that needs a real machine and a real VPN

## Implementation Steps

### Task 1: Introduce `ResolverEntry` and rewrite `parse_scutil_dns`

**Files:**
- Modify: `src/dns.rs`

- [ ] write RED test `parse_scutil_dns_keeps_all_nameservers` using the sanitized resolver #1 fixture; assert both `10.10.20.53` and `10.10.20.54` are returned
- [ ] write RED test `parse_scutil_dns_harvests_domainless_resolver`; assert the resolver with no `domain` line is returned with `domain: None`
- [ ] add `ResolverEntry` struct and change `parse_scutil_dns` to return `Vec<ResolverEntry>`, collecting every `nameserver[N]` and parsing `if_index : 14 (en0)` into `interface`
- [ ] write test for a domain-scoped resolver — `domain`, single nameserver, `interface: Some("en0")`
- [ ] write test for empty/garbage input returning an empty Vec
- [ ] run `cargo test` — must pass before Task 2

### Task 2: Add `corporate_mappings` projection

**Files:**
- Modify: `src/dns.rs`

- [ ] write RED test asserting `corporate_mappings` drops entries with `domain: None`
- [ ] write RED test asserting a domain with two nameservers yields a two-element `Vec`, order preserved
- [ ] implement `corporate_mappings(&[ResolverEntry]) -> BTreeMap<String, Vec<String>>`
- [ ] write test for two resolvers sharing one domain — nameservers concatenated, deduplicated
- [ ] run `cargo test` — must pass before Task 3

### Task 3: Widen the `Platform` trait to `Vec<String>`

**Files:**
- Modify: `src/platform/mod.rs`
- Modify: `src/platform/macos.rs`
- Modify: `src/platform/linux.rs`
- Modify: `src/platform/windows.rs`
- Modify: `src/main.rs`

- [ ] change trait signature to `discover_corporate_dns(&self) -> Result<BTreeMap<String, Vec<String>>>`
- [ ] update the macOS impl to call `parse_scutil_dns` then `corporate_mappings`
- [ ] update the Linux and Windows impls to compile against the new signature
- [ ] update `RecordingPlatform` at `src/main.rs:1140` to the new return type
- [ ] update both call sites (`src/main.rs:235`, `src/main.rs:443`) — wrap the static `corporate-dns` string value in a one-element `Vec` at the merge point; keep `or_insert` semantics so explicit config still wins per key
- [ ] run `cargo test` — must pass before Task 4

### Task 4: Update `sync_to_config` for multiple nameservers

**Files:**
- Modify: `src/dns.rs`

- [ ] write RED test asserting a domain with two nameservers emits two `dns.servers` entries, both carrying the same `domains` list
- [ ] change `sync_to_config` to accept `&BTreeMap<String, Vec<String>>` and iterate nameservers
- [ ] update the nine existing tests at `src/dns.rs:218-484` to the new map type
- [ ] write test asserting the `corporate-dns` routing rule is unchanged — same `ruleTag`, `port: 53`, `outboundTag: "direct"` (guards the Non-goal)
- [ ] write test asserting non-corp `dns.servers` entries are still preserved
- [ ] run `cargo test` — must pass before Task 5

### Task 5: Fix the Linux `resolvectl` parser

**Files:**
- Modify: `src/platform/linux.rs`

- [ ] write RED test asserting `DNS Servers: 10.10.20.53 10.10.20.54` yields both, not just the first
- [ ] write RED test asserting a link with DNS servers but no domain entry is still harvested
- [ ] change `parse_resolvectl_status` to return `Vec<ResolverEntry>` and collect all whitespace-separated servers
- [ ] write test for multi-link output — global block plus two `Link N` blocks
- [ ] run `cargo test` — must pass before Task 6

### Task 6: Pure next-hop reachability helpers

**Files:**
- Create: `src/netdiag.rs`
- Modify: `src/main.rs`

- [ ] write RED test for `parse_route_get` against the macOS `route -n get` shape; assert gateway and interface extracted
- [ ] write RED test for `parse_ifconfig_inet` against `inet 192.0.2.10 netmask 0xffffff00`; assert **hex** netmask decoded
- [ ] write RED test for `next_hop_on_link("10.10.99.1", "192.0.2.10", 0xffffff00)` returning `false`, and for a same-subnet gateway returning `true`
- [ ] implement the three pure functions in `src/netdiag.rs`; register the module in `src/main.rs`
- [ ] write test for a directly-connected route with no gateway line — treated as on-link
- [ ] run `cargo test` — must pass before Task 7

### Task 7: DNS query encode/decode

**Files:**
- Modify: `src/netdiag.rs`

- [ ] write RED test for `build_dns_query(0x1234, "example.com")` — assert 12-byte header, transaction id, QDCOUNT 1, QNAME label encoding `7example3com0`, QTYPE A, QCLASS IN
- [ ] write RED test for `parse_dns_response` accepting a matching transaction id and rejecting a mismatched one
- [ ] implement both functions using only `std`
- [ ] write test for truncated/short response bytes returning an error rather than panicking
- [ ] write test for a response with the QR bit clear being rejected
- [ ] run `cargo test` — must pass before Task 8

### Task 8: `next_hop_status` and `list_system_resolvers` on the trait

**Files:**
- Modify: `src/platform/mod.rs`
- Modify: `src/platform/macos.rs`
- Modify: `src/platform/linux.rs`
- Modify: `src/platform/windows.rs`
- Modify: `src/main.rs`

- [ ] add `NextHop` struct and both trait methods to `src/platform/mod.rs`
- [ ] implement on macOS via `route -n get` plus `ifconfig <iface>`, composing the Task 6 pure helpers
- [ ] implement on Linux via `ip route get` plus `ip addr show <iface>`
- [ ] add Windows stubs consistent with the existing stub style in `src/platform/windows.rs`
- [ ] extend `RecordingPlatform` with configurable `NextHop` and resolver-list responses, including an unreachable-next-hop case
- [ ] run `cargo test` — must pass before Task 9

### Task 9: The `corvex dns` command

**Files:**
- Modify: `src/main.rs`
- Modify: `src/netdiag.rs`

- [ ] add `Dns` to the `Commands` enum at `src/main.rs:38` with help text "Diagnose system DNS resolvers and their network path"
- [ ] implement `cmd_dns(config, plat, out)` following the `cmd_status_inner` pattern — take a `&mut W` writer so output is testable
- [ ] render per nameserver: address, interface, gateway, on-link verdict, probe result; colour failures red like `write_proxy_status` does
- [ ] skip the UDP probe and print `UNREACHABLE NEXT HOP` when `on_link` is false, naming the gateway and interface
- [ ] write test against `RecordingPlatform` asserting the unreachable case is reported and no probe is attempted
- [ ] write test asserting a healthy resolver renders interface and gateway
- [ ] write test asserting a resolver with no domain (global) still appears in the output
- [ ] run `cargo test` — must pass before Task 10

### Task 10: Verify acceptance criteria

- [ ] a failover nameserver pair survives end to end — both appear in `corvex dns` and both reach `dns.servers`
- [ ] a domain-less resolver appears in `corvex dns` output
- [ ] a gateway outside the interface subnet is reported as an unreachable next hop
- [ ] confirm the Non-goals held: `grep -n 'domainStrategy' src/protocol.rs` still shows `"AsIs"`, the `dns_out` tag is untouched, no switcher key exists in `src/settings.rs`
- [ ] confirm no real corporate domain, internal IP, or machine interface address appears in any committed file
- [ ] run the full gate: `cargo test && cargo clippy && cargo fmt --check`

### Task 11: [Final] Update documentation

- [ ] add `corvex dns` to the Usage block in `CLAUDE.md` and `README.md`
- [ ] add a `dns.rs` entry to the "Non-obvious module behavior" section noting that `parse_scutil_dns` returns all nameservers and includes domain-less resolvers, and that `corporate_mappings` is the xray-facing projection
- [ ] note in `CLAUDE.md` that `netdiag.rs` computes next-hop reachability from interface subnet arithmetic rather than ARP, and why
- [ ] update `RELEASE_NOTES.md`
- [ ] move this plan to `docs/plans/completed/`

## Post-Completion

*Items requiring manual intervention — no checkboxes, informational only*

**Manual verification:**
- Run `corvex dns` while connected to a corporate VPN; confirm both nameservers of a failover pair are listed and probed.
- Reproduce the incident: add a bogus host route
  (`sudo route -n add -host <dns-ip> <off-subnet-gw>`), run `corvex dns`, confirm it reports the
  unreachable next hop, then delete the route. This is the single most valuable manual check.
- Verify on Linux with systemd-resolved that `parse_resolvectl_status` handles a real multi-link setup.

**Deferred work, tracked elsewhere:**
- The `dns.manage` on/off switcher and its ON path.
- Deleting the inert xray DNS block once the switcher lands.
- Whether corvex.json `corporate-dns` should accept arrays — revisit with the switcher, as it is a
  breaking config change.
