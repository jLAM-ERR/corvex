# PLAN.md — Release 0.3.0

> Full plan: [docs/plans/20260407-release-0.3.0.md](docs/plans/20260407-release-0.3.0.md)

## Scope

| ID | Type | Summary | Branch |
|----|------|---------|--------|
| B1 | Bug | Ensure directories exist on start | `feature/b1-ensure-directories` |
| B2 | Bug | Add corporate-dns routing rule (port 53) | `feature/b2-dns-routing-rule` |
| B3 | Bug | Propagate xray log level on config update | `feature/b3-log-level` |
| F1 | Feature | Static proxy port (`proxy.port` required) | `feature/f1-static-port` |
| F2 | Feature | AmneziaWG support (`vpn://` URI) | `feature/f2-amneziawg` |
| F3 | Feature | Windows corporate DNS discovery | `feature/f3-windows-dns` |
| F4 | Feature | Windows build (platform abstraction) | `feature/f4-windows-build` |

## Architecture

```
src/
├── main.rs              — CLI, command routing, engine dispatch
├── config.rs            — Config paths (platform-aware)
├── settings.rs          — CorvexSettings (+ proxy.port)
├── protocol.rs          — URI parsing + xray config builder
├── dns.rs               — DNS sync to xray config (cross-platform)
├── traffic.rs           — Routing rules builder
├── subscription.rs      — Subscription download
├── health.rs            — Health checks
├── xray.rs              — Xray process lifecycle (cfg-gated signals)
├── engine/
│   ├── mod.rs           — EngineMode enum (Xray | Awg)
│   └── awg.rs           — vpn:// parser, .conf generator, awg-quick lifecycle
├── platform/
│   ├── mod.rs           — Platform trait, PlatformImpl type alias
│   ├── macos.rs         — proxy, network, DNS via networksetup/scutil
│   └── windows.rs       — proxy, network, DNS via WinAPI/registry
```

**Key decisions:**
- `EngineMode` enum with match dispatch (not trait — only 2 engines)
- AWG mode: AWG tunnel + xray as routing layer (freedom outbound)
- Platform: cfg-gated concrete types (no dynamic dispatch)
- Windows DNS: `GetAdaptersAddresses` + registry NRPT (no PowerShell)
- Static port required in `proxy.port` — no random fallback
- Silent auto-install for xray and amneziawg on both macOS and Windows

## Phases

```
Phase 1: Bug fixes (B1 → B3 sequential, B2 parallel)
Phase 2: F1 — static port
Phase 3: F4 — platform refactor (Tasks 5-7)
Phase 4: F2 — AmneziaWG (Tasks 8-11)
Phase 5: F3 — Windows DNS (Task 12)
         F4 — Windows full impl (Task 13)
Final:   Verify + docs + examples (Tasks 14-15)
```

## Tasks

- [x] **Task 1** [B1] Ensure directories exist on start + remove `check_deprecated_files`
- [x] **Task 2** [B2] Add corporate-dns routing rule (port 53) in `dns::sync_to_config`
- [x] **Task 3** [B3] Propagate log level in `apply_to_config`
- [x] **Task 4** [F1] Static proxy port — `proxy.port` required, remove `port.rs`
- [x] **Task 5** [F4] Platform trait + move macOS code from proxy.rs/network.rs
- [x] **Task 6** [F4] Cfg-gate `nix`/`windows-sys`, xray process mgmt, health.rs fix
- [x] **Task 7** [F4] Platform-aware config paths + Windows stubs
- [x] **Task 8** [F2] vpn:// URI parser + AWG .conf generator
- [x] **Task 9** [F2] AWG tunnel lifecycle (awg-quick up/down, auto-install)
- [x] **Task 10** [F2] Xray config for AWG mode (freedom outbound)
- [x] **Task 11** [F2] Integrate AWG engine into main.rs
- [x] **Task 12** [F3] Windows corporate DNS (GetAdaptersAddresses + NRPT)
- [x] **Task 13** [F4] Windows platform full impl (proxy, network, process)
- [x] **Task 14** Verify acceptance criteria
- [x] **Task 15** Docs, README, examples

## Breaking Changes

- `proxy.port` is now **required** in corvex.json (no random port fallback)
- `check_deprecated_files` removed (old config files no longer warned about)
- `port.rs` module removed
- `proxy.rs` and `network.rs` moved to `platform/` module
