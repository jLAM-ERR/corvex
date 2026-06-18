# Loopback + private-IP DIRECT routing rule (always-on)

> Self-contained brief for a fresh Claude Code session. Implementer should be able to land this without prior conversation context.

## Overview

Corvex generates xray's `routing.rules` from corvex.json. Today, requests destined for loopback (`127.0.0.0/8`, `::1`) or RFC1918 private networks have **no matching rule**. Xray's first-match-then-fallback semantics send them to the first outbound in the array — which is typically the VLESS/proxy outbound. The remote tunnel exit then tries to connect to `127.0.0.1:...` from *its own* perspective, which fails. Symptom: anything the user tries to run on a local port (a demo gateway, a dev server, a local model proxy) returns connection errors or HTTP 503 / "API error" through the proxy.

**Concrete repro that surfaced this:** Claude Code talking to `http://127.0.0.1:4000` (a local LiteLLM proxy used by the corp-llm-gateway demo) with `HTTPS_PROXY=http://127.0.0.1:1080` (corvex/xray SOCKS5 inbound) returns "API error" / `HTTP 503 (no body)`. The litellm container logs show *zero* `POST /v1/messages` entries for the failing window — proof that the request never reached the local destination, it was tunneled through the VLESS exit and dropped.

**Fix:** always prepend a `direct` rule covering loopback + IPv6 loopback + `geoip:private` as the **first** rule in `routing.rules`. It cannot be disabled — tunneling RFC1918 through a public VPN exit never makes sense, and quietly tunneling localhost has bitten users in real demos (see `docs/plans/completed/` or the corp-llm-gateway demo session notes for the original repro).

The fix is one function: `src/traffic.rs::build_routing_rules`. The change is additive (a new leading rule), backwards-compatible with the existing rule set, and unconditional.

## Context (from discovery)

**Files involved (only):**
- `src/traffic.rs` — the routing-rules builder. Function `build_routing_rules(...)` returns `Vec<serde_json::Value>` that becomes xray's `routing.rules`. This is the single insertion point.
- (verify) `src/protocol.rs` — the xray config creator/updater. Calls `build_routing_rules` and assembles the final config. **No change expected** unless the implementer finds that protocol.rs reorders the returned rules; in that case, fix the order so the loopback rule stays at index 0.
- `CLAUDE.md` — short note in the routing/architecture section that "loopback + RFC1918 are unconditionally routed DIRECT".

**Existing patterns to match:**
- Tests live inline at the bottom of `src/traffic.rs` under `#[cfg(test)] mod tests`. Use that pattern — do not introduce a new test file.
- `serde_json::json!` macro is used to build rule objects. Match that style for the new rule.
- Rule emission style:
  - When a rule has a stable identity / docs reference, it carries a `ruleTag` (see `ru-tld-direct`). Use one here too: `"loopback-and-private-direct"`.
  - Rule keys used elsewhere in this builder: `outboundTag`, `domain`, `ruleTag`. The new rule uses `ip` instead of `domain` (this is the xray routing-rule field for IP/CIDR matches; valid alongside the other keys).

**Existing test coverage that asserts `routing.rules` shape and WILL break:**

Inside `src/traffic.rs` (the function under change):
- `test_build_routing_rules_ctraffic_only`
- `test_build_routing_rules_ptraffic_only`
- `test_build_routing_rules_both`
- `test_build_routing_rules_with_ru_flag`
- `test_build_routing_rules_both_with_ru`

Inside `src/protocol.rs` (callers that build a full xray config and assert into `routing.rules`):
- `create_config_with_routing_rules` (≈lines 1322-1345) — asserts `r.len() == 3` and indexes into `r[0..2]`.
- `awg_mode_config_applies_routing_rules` (≈lines 1371-1381) — asserts `r.len() == 3`.

Inside `src/main.rs` (end-to-end builders that assert the same shape):
- `test_traffic_rules_in_create_config` (≈lines 632-658) — asserts `r.len() == 3` and indexes into `r[0..2]`.
- `test_uri_flow_creates_config` (≈lines 714-732) — asserts `r.len() == 3`.
- `test_routing_rules_from_settings_values` (≈lines 734-743) — asserts `rules.len() == 3` and indexed `outboundTag` values.

All of these currently assert `rules.len()` and indices into `rules[0]`, `rules[1]`, etc. After this change, **every** result vector will have the loopback rule at index 0, so existing index assertions shift by one. The implementer **must** update assertions in all three files as part of Task 1 — they are not flaky tests, they pin the rule order. Line numbers above are approximate (drift expected over time) — `grep -n 'r\.len()\|rules\.len()\|outboundTag' src/protocol.rs src/main.rs` to ground-truth them.

**Dependencies:**
- No new crates. `serde_json` is already in `Cargo.toml`.

## Development Approach

- **Testing approach:** Regular (code first, then tests). Implement the rule emission, run existing tests, watch them fail because of the index shift, update them in the same task, add new dedicated tests.
- Complete each task fully before moving to the next.
- Small focused changes, one task per logical unit.
- **Every task MUST include new/updated tests for code changes in that task.** Tests are required, not optional. They cover success AND error/edge scenarios where applicable.
- **All tests must pass before starting the next task** — `cargo test` is the gate.
- Run `cargo fmt && cargo clippy && cargo test` after every change.
- Maintain backward compatibility — corvex.json schema does **not** change. No new fields, no new CLI flags. The rule is unconditional.

## Testing Strategy

- **Unit tests** in `src/traffic.rs` — required for every task. Match the existing inline `#[cfg(test)] mod tests` pattern. Use `serde_json::Value` indexing assertions like the existing tests do.
- **No e2e tests in scope.** Corvex doesn't have a Playwright/Cypress UI layer; the xray config generation is verified via unit tests against `serde_json::Value`.
- **Integration check (manual, one-shot, no committed test):** after `cargo run -- start`, the generated `$XDG_CONFIG_HOME/xray/config.json` must contain the new rule at `routing.rules[0]`. Listed under Post-Completion.

## Progress Tracking

- Mark completed items with `[x]` immediately when done.
- Add newly discovered tasks with ➕ prefix.
- Document issues/blockers with ⚠️ prefix.
- Update this plan if implementation deviates from original scope.

## What Goes Where

- **Implementation Steps** (`[ ]` checkboxes): everything achievable inside this repo — Rust code, inline tests, CLAUDE.md update.
- **Post-Completion** (no checkboxes): manual verification against a running xray, and downstream coordination (the corp-llm-gateway demo that surfaced this bug).

## Implementation Steps

### Task 1: Emit `loopback-and-private-direct` rule as routing.rules[0]

**Files:**
- Modify: `src/traffic.rs`

- [ ] In `build_routing_rules`, prepend a single rule before any other emission. Use:
  ```rust
  rules.push(serde_json::json!({
      "ruleTag": "loopback-and-private-direct",
      "outboundTag": "direct",
      "ip": ["127.0.0.0/8", "::1/128", "geoip:private"],
  }));
  ```
  This MUST be the first `push`, so it lands at index 0 regardless of which other branches fire.
- [ ] Verify with `cargo build` that the function still compiles and `routing.rules` shape matches xray's expected schema (IP rule with `outboundTag` and optional `ruleTag`).
- [ ] Run existing tests — expect failures on index assertions (`rules[0]`, `rules.len()`). Do NOT proceed until next step.
- [ ] Update existing tests in `src/traffic.rs` to account for the leading rule:
  - `test_build_routing_rules_ctraffic_only`: `rules.len()` becomes `2`, ctraffic rule moves from `rules[0]` to `rules[1]`.
  - `test_build_routing_rules_ptraffic_only`: `rules.len()` becomes `2`, ptraffic at `rules[1]`.
  - `test_build_routing_rules_both`: `rules.len()` becomes `3`, ctraffic at `rules[1]`, ptraffic at `rules[2]`.
  - `test_build_routing_rules_with_ru_flag`: `rules.len()` becomes `2`, ru rule at `rules[1]`.
  - `test_build_routing_rules_both_with_ru`: `rules.len()` becomes `4`, ru at `rules[3]`.
  - In each test, also assert that `rules[0]["ruleTag"] == "loopback-and-private-direct"` and `rules[0]["outboundTag"] == "direct"`. This pins the order and prevents future regressions where someone "cleans up" the rule emission and accidentally moves it.
- [ ] Update existing tests in `src/protocol.rs` (full-config builders) the same way: every `r.len() == 3` assertion becomes `r.len() == 4`, every index in `r[0..2]` shifts to `r[1..3]`, and a new `assert_eq!(r[0]["ruleTag"], "loopback-and-private-direct")` is added at the top of each test body. Tests to touch: `create_config_with_routing_rules`, `awg_mode_config_applies_routing_rules`.
- [ ] Update existing tests in `src/main.rs` the same way. Tests to touch: `test_traffic_rules_in_create_config`, `test_uri_flow_creates_config`, `test_routing_rules_from_settings_values`. Same shift-by-one pattern; same loopback-rule assertion added.
- [ ] Add new dedicated tests:
  - `test_build_routing_rules_always_emits_loopback_rule_first`: call with all-empty inputs and `ru_direct=false`. Assert `rules.len() == 1`, `rules[0]["ruleTag"] == "loopback-and-private-direct"`, `rules[0]["outboundTag"] == "direct"`, and that `rules[0]["ip"]` is an array containing exactly `["127.0.0.0/8", "::1/128", "geoip:private"]` (use `as_array()` + `.iter().map(|v| v.as_str().unwrap()).collect::<Vec<_>>()`).
  - `test_build_routing_rules_loopback_rule_uses_ip_field_not_domain`: assert `rules[0].get("domain").is_none()` (clearer than `Value::Null` indexing — robust to future key additions) and `rules[0]["ip"]` is an array. Pins the schema — `ip` is what xray reads for CIDR matches; `domain` would silently no-op for `127.0.0.0/8`.
- [ ] Run `cargo fmt && cargo clippy -- -D warnings && cargo test` — all green before next task.

### Task 2: Verify downstream call sites and pin the final ordering

**Files:**
- Modify (only if reordering is found): `src/protocol.rs`, `src/main.rs`
- Inspect (known mutator, no fix expected): `src/dns.rs`

Known mutators of `routing.rules` (already discovered — confirm each behaves as expected after Task 1, do NOT skip):

1. `src/traffic.rs::build_routing_rules` — emits the rules in order, vec returned to caller. (Changed in Task 1.)
2. `src/protocol.rs` — fresh-config creation path: writes the returned vec into `routing.rules` as-is.
3. `src/main.rs::update_routing_rules` (≈line 337) — existing-config path: **wholesale replaces** `routing.rules` with the freshly-built vec on every `corvex start`. So on every run, the loopback rule lands at index 0 even if a previous DNS sync had appended a rule at the end.
4. `src/dns.rs::sync_to_config` (≈lines 111-147) — runs **after** rule build/replace. **Pushes** a `corporate-dns` rule (port 53) onto `routing.rules` if absent, or replaces it in place if present. Uses `as_array_mut()` on `xray_config["routing"]["rules"]`. This is a real coupling point but does NOT reorder existing entries — append-only or in-place mutation.

Expected final ordering of `routing.rules` after a full `corvex start` (on either fresh or existing config), with corporate-dns sync enabled:

```
[0] loopback-and-private-direct   ← new, this task
[1] corporate-traffic (direct)    ← if ctraffic non-empty
[2] proxy-traffic (proxy outbound)← if ptraffic non-empty
[3] ru-tld-direct                 ← if direct-ru: true
[N] corporate-dns                 ← appended by dns.rs::sync_to_config
```

Indices 1..3 are conditional. Index 0 and the corporate-dns tail are unconditional in their respective branches.

- [ ] Broaden the grep beyond Task 1's narrow patterns: `grep -nE 'routing.*rules|as_array_mut|build_routing_rules' src/` and read every hit. Confirm every site that mutates `routing.rules` matches one of items 1–4 above. If anything else turns up (e.g., a sort, a dedupe, a partition), fix it so the loopback rule stays at index 0.
- [ ] Confirm `src/engine/awg.rs` does NOT emit or mutate xray routing rules (it should not — AWG uses its own .conf, not xray's routing). Quick check: `grep -n 'routing\|rules' src/engine/awg.rs` — expect zero matches.
- [ ] Add (or extend) one test that builds a **full** xray config via `protocol::create_config(...)` AND runs `dns::sync_to_config(...)` against it with a non-empty `corporate-dns` map, then asserts:
  - `routing.rules[0]["ruleTag"] == "loopback-and-private-direct"`
  - The last rule has `ruleTag == "corporate-dns"` (or equivalent — match what dns.rs actually emits).
  - This pins the end-to-end ordering across the two mutators.
- [ ] If no unexpected reordering is found (expected), record this finding inline in this task (e.g., "✅ confirmed: only protocol.rs:create_config, main.rs:update_routing_rules, and dns.rs:sync_to_config mutate routing.rules; none reorder").
- [ ] Run `cargo test` — all green.

### Task 3: Document the rule in CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] In the **Architecture** section, under the description of `traffic.rs`, add a one-line note:
  > Always emits a leading rule that routes `127.0.0.0/8`, `::1/128`, and `geoip:private` to the `direct` outbound. This rule is unconditional and cannot be disabled via corvex.json — tunneling loopback or RFC1918 through a public VPN exit never works.
- [ ] Also add a short bullet under **Design principles**:
  > Loopback and RFC1918 are short-circuited to `direct` at the top of `routing.rules` (see `traffic.rs::build_routing_rules`).
- [ ] No code change here; just docs. Run `cargo test` once more as a final sanity check.

### Task 4: Verify acceptance criteria

- [ ] All requirements from **Overview** implemented: rule emitted, always-on, scope covers `127.0.0.0/8 + ::1/128 + geoip:private`, ordered at `routing.rules[0]`, no corvex.json knob added.
- [ ] Edge cases checked: empty ctraffic + empty ptraffic + `ru_direct=false` still yields a 1-element vec with the loopback rule.
- [ ] Run full test suite: `cargo fmt --check && cargo clippy -- -D warnings && cargo test`.
- [ ] Verify all `[ ]` boxes above are `[x]`.

### Task 5: [Final] Close the plan

- [ ] Update README.md only if the corvex.json schema section there mentions routing semantics (likely not).
- [ ] Move this plan: `mkdir -p docs/plans/completed && git mv docs/plans/20260618-loopback-direct-routing-rule.md docs/plans/completed/`.
- [ ] Commit message suggestion: `fix(traffic): unconditional loopback + RFC1918 direct routing rule`.

## Technical Details

**The rule shape (exact JSON, as it should appear in `$XDG_CONFIG_HOME/xray/config.json`):**

```json
{
  "ruleTag": "loopback-and-private-direct",
  "outboundTag": "direct",
  "ip": [
    "127.0.0.0/8",
    "::1/128",
    "geoip:private"
  ]
}
```

**Why these three entries:**

| Entry | Covers | Why DIRECT |
|---|---|---|
| `127.0.0.0/8` | IPv4 loopback (`127.0.0.1`, `127.0.0.2`, …) | Tunnel exit interprets `127.0.0.1` as itself. Always fails. |
| `::1/128` | IPv6 loopback | Same as above for IPv6. |
| `geoip:private` | RFC1918 — `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | Not routable across a public VPN exit. Local LAN / docker bridge / corp internal IPs only resolve from the user's network. |

**Why this is a first-class rule, not a domain rule:**
- Xray applies rules in order; first match wins. If a domain rule resolves to a loopback IP via sniffing, the IP rule still wins because routing decisions are evaluated at the IP layer after the `sniffing.routeOnly` step.
- Using `domain: ["domain:localhost"]` would only catch the literal hostname `localhost` — not the much more common case of a direct `127.0.0.1:PORT` connection from a tool that has already DNS-resolved.

**Why no corvex.json opt-out:**
- The only reason to tunnel loopback would be to test the VPN exit's own loopback view — a debugging case, not a normal one. If a future user needs that, they can comment out the rule in the generated `xray/config.json` for one session. We keep the corvex.json schema small.

**xray version compatibility:**
- `ip` field with CIDR notation is supported in all xray-core releases corvex targets.
- `geoip:private` is a built-in xray category and is always available without an external geoip data file.

**Reload semantics:**
- After this change ships, `corvex reload` (SIGHUP) will pick up the new rule on the next start. Users with a running xray must restart corvex once. This is acceptable — the same is true for any other config rule we add.

## Post-Completion

*Items requiring manual intervention or external systems. No checkboxes.*

**Manual verification:**

1. Build corvex with this change, run `cargo run -- start` against a corvex.json that has a non-trivial proxy outbound. Note `proxy.port` from your corvex.json (call it `$PORT` below — default in most demo configs is `21080`; check with `jq '.proxy.port' ~/.config/corvex/corvex.json`).

2. Inspect the generated `$XDG_CONFIG_HOME/xray/config.json`:
   ```bash
   jq '.routing.rules[0]' $XDG_CONFIG_HOME/xray/config.json
   # Expected output, byte-identical:
   # {
   #   "ruleTag": "loopback-and-private-direct",
   #   "outboundTag": "direct",
   #   "ip": ["127.0.0.0/8", "::1/128", "geoip:private"]
   # }
   ```

3. In a second terminal, start any local HTTP listener:
   ```bash
   python3 -m http.server 8080
   # serves directory listing on http://127.0.0.1:8080
   ```

4. With xray running, prove loopback goes DIRECT (and not via the VPN exit):
   ```bash
   curl --socks5 127.0.0.1:$PORT http://127.0.0.1:8080/ -o /dev/null -w '%{http_code}\n'
   # → 200 (or 403 with index listing — anything that comes from python3's HTTP server)
   # Pre-fix: this would 503 / connect-error because the VLESS exit can't reach your laptop's :8080.
   ```

5. Public traffic still goes via the proxy:
   ```bash
   curl --socks5 127.0.0.1:$PORT -I https://api.anthropic.com/ -m 10
   # → real anthropic response headers (401 without auth is normal); proves the proxy outbound still works.
   ```

6. Stop the python listener (`Ctrl-C` in that terminal).

**External system updates:**

- The corp-llm-gateway demo (separate repo `~/ai_repo/corp-llm-gateway/`) added `NO_PROXY=localhost,127.0.0.1` to `scripts/demo.sh presenter-env` as a client-side workaround for this exact bug. Once corvex ships this fix, that workaround becomes redundant — but should be **kept** anyway, because it makes the demo work for users running other proxy stacks. No action required there; just a note for the historical record.
- No other consuming projects need updates.
