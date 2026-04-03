# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Rust CLI tool (`corvex`) that manages the Xray VPN daemon and macOS system proxy settings. Targets macOS only (uses `networksetup`).

## Build & Test

```bash
cargo build           # Build
cargo test            # Run all unit tests
cargo clippy          # Lint
cargo fmt             # Format
cargo run -- --help   # Show CLI help
```

## Usage

```bash
cargo run -- start                              # Load corvex.json, resolve server, start
cargo run -- stop                               # Disable system proxy + stop xray
cargo run -- reload                             # Validate config, send SIGHUP
cargo run -- status                             # Show xray process, ports, proxy settings, config paths
cargo run -- logs                               # Show last 20 log lines
cargo run -- logs -f                            # Follow log (tail -f)
cargo run -- --settings /path/to/corvex.json start  # Use custom settings file
CORVEX_DEBUG=1 cargo run -- start               # Enable debug logging to stderr
```

### corvex.json

All configuration is in a single JSONC file at `$XDG_CONFIG_HOME/corvex/corvex.json`:

```jsonc
{
  "uri": "vless://uuid@host:443?...",           // Proxy URI (or use file-url)
  "file-url": ["https://sub1.com/link"],        // Subscription URLs for auto-discovery
  "corporate-dns": { "corp.com": "10.0.0.1" },  // Domain -> nameserver mappings
  "routes": {
    "direct-ru": true,                           // Route .ru TLD directly
    "proxy-traffic": ["domain:ext.com"],         // Force through proxy
    "corporate-traffic": ["domain:corp.com"]     // Bypass proxy (direct)
  },
  "log": {
    "xray": { "loglevel": "warning", "access": "/var/log/xray/access.log", "error": "/var/log/xray/error.log" },
    "corvex": { "debug": false }
  }
}
```

## Architecture

```
src/
├── main.rs          — clap CLI, command routing, start/stop/status/reload/logs
├── config.rs        — Config struct with XDG paths (config, state, xray)
├── settings.rs      — CorvexSettings struct, JSONC parser, corvex.json loader
├── network.rs       — detect active macOS network service (route + networksetup)
├── xray.rs          — xray process lifecycle (start/stop/reload, PID file, auto-install)
├── proxy.rs         — macOS system proxy via networksetup
├── protocol.rs      — multi-protocol URI parser + xray config creator/updater
├── dns.rs           — corporate DNS discovery (scutil) + xray config sync
├── port.rs          — dynamic port allocation (20000-60000)
├── traffic.rs       — routing rule builder from domain lists
├── subscription.rs  — subscription download, base64 decode, protocol filter
└── health.rs        — server health checks (TCP pre-filter + tunnel latency)
```

**Design principles:**
- All parsing functions take `&str` — unit testable without system calls
- PID-based process tracking with stale PID cleanup via `kill(pid, 0)`
- Config validation before reload (parse JSON before sending SIGHUP)
- Dynamic port allocation per start (no fixed port)

## Key paths (XDG Base Directory)

- corvex.json: `$XDG_CONFIG_HOME/corvex/corvex.json` (default `~/.config/corvex/corvex.json`), overridable via `--settings`
- Xray config: `$XDG_CONFIG_HOME/xray/config.json` (default `~/.config/xray/config.json`)
- PID file: `$XDG_CONFIG_HOME/xray/xray.pid`
- Corvex log: `$XDG_STATE_HOME/corvex/corvex.log` (default `~/.local/state/corvex/corvex.log`)
- Xray error log: configurable via corvex.json `log.xray.error`, default `/var/log/xray/error.log`
- Xray access log: configurable via corvex.json `log.xray.access`, default `/var/log/xray/access.log`

## Dependencies

clap (CLI), anyhow/thiserror (errors), colored (output), log/env_logger (debug logging), serde/serde_json (config), json_comments (JSONC parsing), nix (signals/PID), url (URI parsing), ureq (HTTP + SOCKS proxy), base64 (subscription decoding), rand (port selection)
