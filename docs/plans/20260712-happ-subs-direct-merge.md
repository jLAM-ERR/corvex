# Happ-Format Subscriptions + Direct-Rules Merge

## Overview

Two related v0.6.0 features, designed against a real panel response (structure verified from `~/work/tmp/subs.txt` — that file holds live credentials and must NEVER be committed or used in tests):

1. **Subscription request identity.** Panels content-negotiate on `User-Agent`: unknown agents (curl, and corvex today — `download_subscription` sends no UA) get filtered/broken output. New corvex.json keys `subs-user-agent` (default: v2rayNG-compatible, which reliably yields plain base64) and `subs-headers` (extra headers such as `X-Hwid`, `X-Device-Os`, `X-Ver-Os`, `X-Device-Model` that some panels require).
2. **Happ-format subscription support + direct-rules merge.** With a Happ UA the panel returns a JSON **array of complete xray configs** (one per server): `outbounds[0]` carries the connection params, `remarks` the name, and `routing.rules` the provider's routing. corvex auto-detects this format, extracts server candidates from the JSON (no URIs exist in this format, so parsing it is mandatory once a Happ UA is configured), health-checks them through the existing machinery, and — **only when `routes.merge-subs: true`** — merges the subscription's *direct* rules (domain + ip lists with `outboundTag: "direct"`) into corvex's own routing. The sub's proxy/protocol rules are always ignored.

Plus a prerequisite fix: `install.sh` installs only the xray binary, but `geosite:*`/`geoip:*` rules (including corvex's own `geoip:private`) need `geoip.dat`/`geosite.dat` from the same Xray zip.

## Context (from discovery)

- `src/subscription.rs:8` — `download_subscription(url)` builds a ureq agent with no User-Agent
- `src/settings.rs:9-33` — `CorvexSettings` (uri, subs_url, corporate_dns, routes, log, proxy) and `RoutesSettings` (direct_ru, proxy_traffic, corporate_traffic)
- `src/protocol.rs:7` — `ProxyParams` (protocol, host, port, name, uuid/encryption/flow/alter_id/vmess_security/password/method, network/security/sni/fingerprint/alpn, path/host_header/service_name/mode/header_type); `parse_uri` at `:44`; `build_stream_settings`/`build_outbound_settings` are the *writers* of the outbound JSON this feature must *read back*
- `src/health.rs:89` — `check_tunnel(&ProxyParams, xray_bin)`; `:160` — `find_alive_server(&[String], xray_bin) -> Result<String>` parses each URI to ProxyParams then check_tcp + check_tunnel — the internals are already ProxyParams-based
- `src/traffic.rs:17` — `build_routing_rules(ctraffic, ptraffic, proxy_tag, ru_direct)`; rule 0 is the unconditional `loopback-and-private-direct` rule
- `src/main.rs:130-200` — subs flow: validate → download each `subs_url` → decode base64 → filter → `find_alive_server` → `resolved_uri: String` → engine dispatch → `parse_uri`
- `src/xray.rs` — `start()` spawns the xray process (place for `XRAY_LOCATION_ASSET`)
- `install.sh` — extracts only the `xray` binary from the Xray zip; the zip also contains `geoip.dat` + `geosite.dat`
- Happ response shape (sanitized): `[{"remarks": "...", "dns": {...}, "inbounds": [...], "log": {...}, "outbounds": [{"protocol": "vless", "settings": {"vnext": [...]}, "streamSettings": {...}, "tag": "proxy"}, ...], "routing": {"rules": [{"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"}, {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}, {"type": "field", "domain": ["geosite:category-ru", "domain:ru", ...46 entries], "outboundTag": "direct"}, {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"}, {"type": "field", "domain": ["geosite:meta"], "outboundTag": "proxy"}]}}, ...]`

## Development Approach

- **execution**: implement via `/IL-workflow:plan docs/plans/20260712-happ-subs-direct-merge.md` — implementer agent loop, one task per invocation
- **testing approach**: Regular (code first, then tests in same task)
- complete each task fully before moving to the next
- **CRITICAL: every task MUST include new/updated tests**; parsing/merge logic in pure functions taking `&str`/`&serde_json::Value` — no network or system calls in tests
- **CRITICAL: all tests must pass before starting next task**
- **CRITICAL: update this plan file when scope changes during implementation**
- CI gates: `cargo test`, `cargo clippy -- -D warnings -A dead_code`, `cargo fmt --check`, `shellcheck install.sh`
- backward compatibility: default behavior for plain base64 subscriptions is unchanged; merge is opt-in
- prefer Rust stdlib over custom helpers
- ⚠️ NEVER commit or reference `~/work/tmp/subs.txt` — tests use a sanitized inline fixture

## Testing Strategy

- **unit tests**: sanitized Happ-format JSON fixture (inline `&str` in the test module) covering: multi-entry array, vless outbound extraction, direct domain/ip harvesting, proxy/protocol rules ignored, malformed entries skipped
- **merge tests**: dedup, local proxy-traffic exclusion, empty-merge no-op, rule ordering (loopback rule stays first)
- **e2e tests**: none in this project; live panel verification is Post-Completion

## Progress Tracking

- mark completed items with `[x]` immediately when done; ➕ for discovered tasks; ⚠️ for blockers

## Solution Overview

- **Request identity**: `download_subscription(url, user_agent, extra_headers)`; `user_agent` = `subs-user-agent` or `DEFAULT_SUBS_USER_AGENT` (`"v2rayNG/1.10.2"`); `extra_headers` = `subs-headers` map. Pure helper `resolve_user_agent(Option<&str>) -> &str`.
- **Format detection**: `happ::parse_happ_subscription(body: &str) -> Option<Vec<HappEntry>>` — `Some` when the body parses as a JSON array of objects each containing `outbounds`; `None` falls through to the existing base64 path. `HappEntry { params: ProxyParams, direct_domains: Vec<String>, direct_ips: Vec<String> }`.
- **Params extraction**: `protocol::params_from_outbound(outbound: &serde_json::Value, name: &str) -> Result<ProxyParams>` — the read-side inverse of `build_outbound_settings`/`build_stream_settings` for vless/vmess/trojan/shadowsocks; `remarks` → `params.name`.
- **Server selection**: refactor `health::find_alive_server` into a thin URI wrapper around new `health::find_alive_params(&[ProxyParams], xray_bin) -> Result<usize>` (returns index of first healthy candidate) so both paths share check_tcp/check_tunnel. Happ entries are always Xray engine mode (the format cannot carry `vpn://`).
- **Merge**: `build_routing_rules` gains two slices: `subs_direct_domains: &[String]`, `subs_direct_ips: &[String]` (empty unless `routes.merge-subs == true` and the chosen entry had rules). Inside: direct domain rule = local corporate-traffic ∪ subs domains, deduped, MINUS any entry present in local proxy-traffic (local proxy wins); subs ip entries become one additional `outboundTag: direct` ip rule placed AFTER the unconditional loopback rule. Log at start: "merged N direct domains + M direct ip entries from subscription".
- **Geo data**: install.sh extracts `geoip.dat` + `geosite.dat` → `/usr/local/share/xray/`; `xray::start` sets `XRAY_LOCATION_ASSET=/usr/local/share/xray` on the child process ONLY when the env var is unset and the directory exists (brew installs manage their own assets).
- Version bump NOT in this plan.

## Technical Details

- New corvex.json keys:
  ```jsonc
  {
    "subs-user-agent": "Happ/3.13.0",                  // optional; default "v2rayNG/1.10.2"
    "subs-headers": { "X-Hwid": "abc", "X-Device-Os": "Android" },  // optional
    "routes": { "merge-subs": true }                    // optional; default false
  }
  ```
- `RoutesSettings` gains `#[serde(rename = "merge-subs")] pub merge_subs: Option<bool>`
- `CorvexSettings` gains `#[serde(rename = "subs-user-agent")] pub subs_user_agent: Option<String>` and `#[serde(rename = "subs-headers")] pub subs_headers: Option<BTreeMap<String, String>>`
- Happ direct-rule harvest: for each `routing.rules[]` with `type=="field"` and `outboundTag=="direct"`: collect `domain[]` into direct_domains, `ip[]` into direct_ips; skip rules with `protocol` key; skip everything with other outboundTags
- Security invariant: merge only widens DIRECT routing when the user opted in; loopback/RFC1918 rule remains rule 0 and cannot be displaced

## What Goes Where

- **Implementation Steps**: code, tests, docs in this repo
- **Post-Completion**: live panel verification, PR mechanics, release

## Implementation Steps

### Task 1: Settings keys for subscription identity and merge opt-in

**Files:**
- Modify: `src/settings.rs`

- [x] add `subs_user_agent: Option<String>` (`rename = "subs-user-agent"`) and `subs_headers: Option<BTreeMap<String, String>>` (`rename = "subs-headers"`) to `CorvexSettings`
- [x] add `merge_subs: Option<bool>` (`rename = "merge-subs"`) to `RoutesSettings`
- [x] write tests: config with all three new keys parses; config without them parses (all None); merge-subs defaults absent
- [x] run tests — must pass before task 2

### Task 2: Send User-Agent and extra headers on subscription downloads

**Files:**
- Modify: `src/subscription.rs`
- Modify: `src/main.rs`

- [x] add `pub const DEFAULT_SUBS_USER_AGENT: &str = "v2rayNG/1.10.2"` and pure `resolve_user_agent(configured: Option<&str>) -> &str`
- [x] change `download_subscription(url, user_agent: &str, extra_headers: &BTreeMap<String, String>)` — set the UA and each extra header on the ureq request (ureq v3 `.header(name, value)` builder; no existing usage in src/ to copy — check ureq 3 docs). Note: sending a default UA is a deliberate request-behavior change for ALL subscriptions (previously ureq's default); the DECODE path for base64 panels stays byte-identical
- [x] update the call site in `src/main.rs` (pass values from settings)
- [x] write tests: `resolve_user_agent` returns default when None/configured value when Some; DEFAULT constant is v2rayNG-flavored
- [x] run tests — must pass before task 3

### Task 3: ProxyParams extraction from an xray outbound JSON

**Files:**
- Modify: `src/protocol.rs`

- [x] add `pub fn params_from_outbound(outbound: &serde_json::Value, name: &str) -> Result<ProxyParams>` — read-side inverse of `build_outbound_settings` + `build_stream_settings`: vless (vnext: address/port/users[0] id/encryption/flow), vmess (vnext + alterId/security), trojan (servers: address/port/password), shadowsocks (servers: address/port/method/password); streamSettings → network, security, sni, fingerprint, alpn, path, host_header, service_name
- [x] ⚠️ lossy-writer mappings (from review): grpc `multiMode: true` → `mode = "multi"` (writer emits `multiMode = (mode == "multi")`, so `"gun"`/empty are NOT recoverable — accept `multiMode:false` → `mode = ""`); tcp+http: `header.type == "http"` → `header_type = "http"`, and writer-injected defaults (`path = "/"`, `Host = server address`) read back as-is, not as the original empty strings
- [x] FAIL CLOSED on unrepresentable configs: `security == "reality"` (ProxyParams has no REALITY fields) and unknown `network` values (kcp, xhttp/splithttp, httpupgrade) → descriptive error, so Task 4's per-entry skip drops them instead of building a broken config
- [x] unsupported protocol or missing address/port → descriptive error
- [x] write round-trip tests: `parse_uri(uri)` → `build_outbound_settings`/`build_stream_settings` → `params_from_outbound` reproduces the original params for vless/vmess/trojan/ss with REPRESENTABLE fixtures (ws/grpc-multi/plain-tcp); for grpc non-multi and tcp-http assert functional equality (regenerated outbound JSON identical), not field equality
- [x] write error tests: freedom outbound rejected; missing vnext rejected; reality security rejected; unknown network rejected
- [x] run tests — must pass before task 4

### Task 4: Happ subscription format parsing

**Files:**
- Create: `src/happ.rs`
- Modify: `src/main.rs` (module declaration)

- [x] `pub struct HappEntry { pub params: ProxyParams, pub direct_domains: Vec<String>, pub direct_ips: Vec<String> }`
- [x] `pub fn parse_happ_subscription(body: &str) -> Option<Vec<HappEntry>>` — Some only for a JSON array of objects with `outbounds`; per entry: `params_from_outbound(outbounds[0], remarks)`; harvest routing.rules with `type=="field" && outboundTag=="direct"`: `domain[]` → direct_domains, `ip[]` → direct_ips, skip rules carrying `protocol`; entries whose outbound fails to parse are skipped with a debug log (not fatal)
- [x] sanitized inline fixture mirroring the real panel response (2 entries, 5 rules incl. bittorrent-protocol rule, geoip:private, 46→3 sample direct domains, geoip:ru, geosite:meta→proxy) with placeholder uuid/host
- [x] write tests: fixture parses to 2 entries with correct params/name; direct_domains exclude proxy-rule domains; direct_ips == [geoip:private, geoip:ru]; protocol rule ignored; base64 body → None; JSON object (not array) → None; array entry without outbounds → None
- [x] run tests — must pass before task 5

### Task 5: Health selection over ProxyParams

**Files:**
- Modify: `src/health.rs`

- [x] add `pub fn find_alive_params(candidates: &[ProxyParams], xray_bin: &str) -> Result<usize>` — same TCP pre-filter + tunnel-latency logic, returns index of first healthy candidate
- [x] refactor `find_alive_server` to parse URIs into `(uri, ProxyParams)` pairs and delegate to the shared selection logic (behavior unchanged: returns the URI string)
- [x] ⚠️ keep the error message containing "no reachable" — `test_find_alive_server_all_unreachable` (health.rs:333-336) asserts `.contains("no reachable")` against the current "no reachable servers found" (health.rs:212); progress-line numbering may shift cosmetically after pre-filtering unparseable URIs, which is acceptable
- [x] write test: `find_alive_params` on an empty slice errors; existing find_alive_server tests still pass
- [x] run tests — must pass before task 6

### Task 6: Routing merge in build_routing_rules

**Files:**
- Modify: `src/traffic.rs`

- [x] extend `build_routing_rules(ctraffic, ptraffic, proxy_tag, ru_direct, subs_direct_domains: &[String], subs_direct_ips: &[String])`
- [x] direct domain rule = normalized(ctraffic) ∪ normalized(subs_direct_domains), deduped, minus any entry whose normalized form appears in normalized(ptraffic) — local proxy wins
- [x] subs_direct_ips (deduped, minus `geoip:private` which rule 0 already covers) → one additional `{"type": "field", "ip": [...], "outboundTag": "direct"}` rule placed immediately after rule 0
- [x] all existing call sites pass `&[], &[]` (no behavior change) — 2 production: `main.rs:233` (AWG branch, stays empty), `main.rs:273` (Xray branch, Task 7 later feeds real slices); 14 tests: `main.rs:652,746,766`, `dns.rs:463`, `protocol.rs:1330,1350,1373`, `traffic.rs:105,115,126,135,147,157,172` (compiler-enforced via E0061, list for completeness)
- [x] write tests: merge dedup; proxy-traffic exclusion; geoip:private filtered from ip rule; empty slices produce identical output to pre-change snapshots; loopback rule still index 0
- [x] run tests — must pass before task 7

### Task 7: Wire Happ flow into cmd_start

**Files:**
- Modify: `src/main.rs`

- [x] in the subs download loop: after each successful download, try `happ::parse_happ_subscription` FIRST; on Some, collect HappEntry candidates; on None, existing base64→URI path
- [x] ⚠️ restructure (from review): the current flow funnels everything through `resolved_uri: String` → `detect_engine_mode` → `parse_uri` (main.rs:150-265); Happ entries have NO URI. Extract (a) a pure decision helper `choose_source(has_happ, has_xray_uris, has_vpn_uris) -> SourceDecision` (unit-testable), and (b) a shared tail `fn start_xray_engine(params: ProxyParams, subs_direct: (&[String], &[String]), ...)` containing the existing Xray-branch body (apply_to_config/create_config, DNS sync, main_algorithm — main.rs:263-306) — called by both the parse_uri path and the Happ path
- [x] if Happ candidates exist: `health::find_alive_params` picks one → `start_xray_engine` directly with those ProxyParams; mixed case (some subs Happ, some base64): prefer Happ candidates, fall back to URI flow if none healthy
- [x] all-sources-empty case: a Happ body where every entry was skipped (unrepresentable) with no base64/vpn URIs must still hit the existing `bail!("no supported proxy servers found in subscriptions")` (main.rs:182-184)
- [x] merge gating: `routes.merge_subs == Some(true)` → pass the chosen entry's direct_domains/direct_ips into `build_routing_rules`; otherwise pass empty slices; log "merged N direct domains + M direct ip entries from subscription" (info) when non-empty
- [x] AWG path and direct-uri path: pass empty slices (merge applies only to Happ subscriptions)
- [x] note in docs task: merged rules are baked at `start`/`restart` time; `reload` keeps the last-generated config (consistent with existing subscription behavior)
- [x] write tests: `choose_source` decision table; full flow covered by round-trip tests from tasks 3-6
- [x] run tests — must pass before task 8

### Task 8: Geo data files — install.sh + XRAY_LOCATION_ASSET

**Files:**
- Modify: `install.sh`
- Modify: `src/xray.rs`

- [x] install.sh xray step: also extract `geoip.dat` and `geosite.dat` from the Xray zip and install (0644) to `/usr/local/share/xray/` (same sudo-only-when-needed logic; failure → warning + manual hint, not fatal, since brew setups don't need it)
- [x] `src/xray.rs::start`: when spawning xray, set `XRAY_LOCATION_ASSET=/usr/local/share/xray` on the child ONLY if the env var is unset AND that directory exists; pure helper `asset_dir_override(env_set: bool, dir_exists: bool) -> Option<&'static str>` for the decision
- [x] `sh -n install.sh` + `shellcheck install.sh` clean
- [x] write tests: `asset_dir_override` truth table (4 cases)
- [x] run tests — must pass before task 9

### Task 9: Verify acceptance criteria

- [x] full suite: `cargo test`; `cargo clippy -- -D warnings -A dead_code`; `cargo fmt --check`; `shellcheck install.sh`
- [x] fixture round-trip: Happ fixture → chosen entry → generated xray config contains merged direct domains when merge-subs on, and does NOT when off
- [x] plain base64 subscription path byte-identical behavior (regression: existing tests untouched/passing)
- [x] grep: no reference to `~/work/tmp/subs.txt` or real panel hostnames/uuids anywhere in the repo

### Task 10: Update documentation

- [ ] README.md: document `subs-user-agent` + `subs-headers` (why: panels filter unknown agents — broken config from curl/default corvex), Happ-format auto-detection, `routes.merge-subs` with explicit security warning (a compromised subscription can route chosen domains OUTSIDE the tunnel; default off), geo-files note for install.sh setups
- [ ] README.md: note that merged direct rules are baked at `start`/`restart` time — `reload` keeps the last-generated config (deferred from Task 7)
- [ ] CLAUDE.md: new keys in the corvex.json example, `happ.rs` in the architecture listing, subscription.rs description update
- [ ] move this plan to `docs/plans/completed/`

➕ (discovered in Task 7 review, pre-existing, OUT OF SCOPE for this plan) switching AWG→Xray with a stale AWG-mode `config.json` on disk makes `apply_to_config` fail with "no proxy outbound found" — identical behavior before and after this work; candidate for a future bug-fix plan.

## Post-Completion

**Branch/PR mechanics:**
- PR #7 was OPEN at planning time — branch `feature/happ-subs-direct-merge` stacks on `feature/installer-restart-subs-url`; if #7 merges first, rebase onto updated main and target main; squash merge

**Manual verification (live panel — cannot be automated):**
- set `subs-user-agent: "Happ/3.13.0"` + the X-* headers in corvex.json → `corvex start` picks a server from the Happ JSON (no base64 involved)
- with `routes.merge-subs: true` → generated config.json contains the panel's 46 direct domains + geoip:ru; with it false/absent → does not
- install.sh on a clean machine → `/usr/local/share/xray/{geoip,geosite}.dat` present; `corvex start` with a geosite: rule works without brew xray

**Future release:**
- ships in v0.6.0 together with PR #7 content via the tag-push workflow
