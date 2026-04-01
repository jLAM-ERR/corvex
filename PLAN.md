# Plan: Rewrite xray-proxy from Bash to Rust CLI

## Context

The current `xray-proxy` is a single bash script (~213 lines) that manages the Xray VPN daemon and macOS system proxy settings. It has silent failure modes, no config reload, no restart command, hardcoded paths, and Russian-only messages. The rewrite to Rust provides type-safe error handling, testable parsing, proper PID management, and new commands (restart, reload).

## Commands Mapping

| Bash | Rust | Description |
|------|------|-------------|
| `-up` | `start` | Start xray + enable system proxy |
| `-down` | `stop` | Disable system proxy + stop xray |
| *(new)* | `restart` | stop + start |
| *(new)* | `reload` | Validate config JSON, send SIGHUP to xray |
| `-status` | `status` | Show xray process, ports, proxy settings |
| `-log` | `logs [-f]` | Show/follow xray log |
| *(new)* | `load <URI>` | Parse VLESS URI, update server params in xray config |
| *(new)* | `domain <subcommand>` | Manage domain routing rules (direct/proxy lists) |
| *(new)* | `dns <subcommand>` | Manage corporate DNS mappings |

## Project Structure

```
xray-proxy/
├── Cargo.toml
├── src/
│   ├── main.rs      — clap CLI, command routing, colored output
│   ├── config.rs    — Config struct with defaults + optional overrides
│   ├── network.rs   — detect active macOS network service
│   ├── xray.rs      — xray process lifecycle (start/stop/restart/reload, PID file)
│   ├── proxy.rs     — macOS system proxy via networksetup
│   ├── vless.rs     — VLESS URI parser + xray config updater
│   ├── domain.rs    — domain routing rules management (direct.json / proxy.json)
│   └── dns.rs       — corporate DNS management (corp-dns.json)
```

## Implementation Status

- [x] Phase 0: Save plan
- [ ] Phase 1: Scaffold
- [ ] Phase 2: config.rs
- [ ] Phase 3: network.rs
- [ ] Phase 4: xray.rs
- [ ] Phase 5: proxy.rs
- [ ] Phase 6: vless.rs
- [ ] Phase 7: domain.rs
- [ ] Phase 8: dns.rs
- [ ] Phase 9: Wire main.rs
- [ ] Phase 10: Polish
