# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Rust CLI tool (`xray-proxy`) that manages the Xray VPN daemon and macOS system proxy settings. Targets macOS only (uses `networksetup`).

## Build & Test

```bash
cargo build           # Build
cargo test            # Run all unit tests (23 tests)
cargo clippy          # Lint
cargo fmt             # Format
cargo run -- --help   # Show CLI help
```

## Usage

```bash
cargo run -- start                          # Start xray + enable system proxy
cargo run -- stop                           # Disable system proxy + stop xray
cargo run -- restart                        # Stop + start
cargo run -- reload                         # Validate config, send SIGHUP
cargo run -- status                         # Show xray process, ports, proxy settings
cargo run -- logs                           # Show last 20 log lines
cargo run -- logs -f                        # Follow log (tail -f)
cargo run -- load "vless://uuid@host:443?..." # Parse VLESS URI, update xray config
cargo run -- domain list direct             # List direct domain entries
cargo run -- domain add proxy "domain:x.com" # Add proxy domain entry
cargo run -- domain remove direct "domain:x.com"
cargo run -- domain find proxy "example"
cargo run -- dns list                       # List DNS mappings
cargo run -- dns add corp.example.com 10.0.0.1
cargo run -- dns remove corp.example.com
```

## Architecture

```
src/
├── main.rs      — clap CLI, command routing, colored output
├── config.rs    — Config struct with defaults + optional overrides
├── network.rs   — detect active macOS network service (route + networksetup)
├── xray.rs      — xray process lifecycle (start/stop/reload, PID file)
├── proxy.rs     — macOS system proxy via networksetup
├── vless.rs     — VLESS URI parser + xray config updater
├── domain.rs    — domain routing rules management (direct.json / proxy.json)
└── dns.rs       — corporate DNS management (corp-dns.json)
```

**Design principles:**
- All parsing functions take `&str` — unit testable without system calls
- PID-based process tracking with stale PID cleanup via `kill(pid, 0)`
- Config validation before reload (parse JSON before sending SIGHUP)
- Port availability check before start

## Key paths (configurable via `--config`)

- Xray config: `~/.config/xray/config.json`
- Xray log: `/var/log/xray/xray.log`
- PID file: `~/.config/xray/xray.pid`
- Domain lists: `~/.config/xray/direct.json`, `~/.config/xray/proxy.json`
- DNS mappings: `~/.config/xray/corp-dns.json`
- Default proxy: `127.0.0.1:1080` (SOCKS5 and HTTP share the same port)

## Dependencies

clap (CLI), anyhow/thiserror (errors), colored (output), serde/serde_json (config), nix (signals/PID), url (VLESS parsing)
