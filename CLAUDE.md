# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Rust CLI tool (`corvex`) that manages the Xray VPN daemon and system proxy settings on macOS, Linux, and Windows. Supports AmneziaWG as an alternative tunnel engine.

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
cargo run -- stop                               # Disable system proxy + stop xray (+ AWG if active)
cargo run -- restart                            # Full stop + start: restarts xray, re-applies system proxy
cargo run -- reload                             # Validate config, send SIGHUP
cargo run -- status                             # Show engine type, xray process, ports, proxy settings
cargo run -- logs                               # Show last 20 log lines
cargo run -- logs -f                            # Follow log (tail -f)
cargo run -- --settings /path/to/corvex.json start  # Use custom settings file
CORVEX_DEBUG=1 cargo run -- start               # Enable debug logging to stderr
```

### corvex.json

All configuration is in a single JSONC file at `$XDG_CONFIG_HOME/corvex/corvex.json`:

```jsonc
{
  "uri": "vless://uuid@host:443?...",           // Proxy URI (vless/vmess/trojan/ss/vpn)
  "subs-url": ["https://sub1.com/link"],        // Subscription URLs for auto-discovery (legacy alias: file-url)
  "proxy": { "port": 21080 },                   // REQUIRED: static proxy port
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
install.sh                — installs the corvex binary + xray dependency (macOS/Linux); see README
src/
├── main.rs              — clap CLI, command routing, engine dispatch
├── config.rs            — Config paths (platform-aware: XDG on unix, APPDATA on Windows)
├── settings.rs          — CorvexSettings (+ proxy.port), JSONC parser
├── protocol.rs          — multi-protocol URI parser + xray config creator/updater
├── dns.rs               — corporate DNS parsing (scutil) + xray config sync
├── traffic.rs           — routing rule builder from domain lists. Always emits a leading rule that routes `127.0.0.0/8`, `::1/128`, and `geoip:private` to the `direct` outbound. This rule is unconditional and cannot be disabled via corvex.json — tunneling loopback or RFC1918 through a public VPN exit never works.
├── subscription.rs      — subscription download, base64 decode, protocol filter
├── health.rs            — server health checks (TCP pre-filter + tunnel latency)
├── xray.rs              — xray process lifecycle (cfg-gated: nix signals on unix, WinAPI on windows); presence check only, no auto-install — missing binary is a hard error pointing to install.sh
├── engine/
│   ├── mod.rs           — EngineMode enum (Xray | Awg)
│   └── awg.rs           — vpn:// parser, .conf generator, awg-quick lifecycle; presence check only, no auto-install — missing awg-quick is a hard error pointing to manual amneziawg-tools install
├── platform/
│   ├── mod.rs           — Platform trait, PlatformImpl type alias
│   ├── linux.rs         — proxy via env file + DE detection (GNOME/KDE), DNS via resolvectl
│   ├── macos.rs         — proxy, network, DNS via networksetup/scutil
│   └── windows.rs       — proxy, network, DNS stubs (WinAPI/registry)
```

**Design principles:**
- All parsing functions take `&str` — unit testable without system calls
- PID-based process tracking with stale PID cleanup
- Config validation before reload (parse JSON before sending SIGHUP)
- Static proxy port from `proxy.port` in corvex.json (required)
- EngineMode enum with match dispatch (Xray vs AWG)
- Platform abstraction via cfg-gated concrete types (no dynamic dispatch)
- Loopback and RFC1918 are short-circuited to `direct` at the top of `routing.rules` (see `traffic.rs::build_routing_rules`)

## Key paths

### Unix (XDG Base Directory)
- corvex.json: `$XDG_CONFIG_HOME/corvex/corvex.json` (default `~/.config/corvex/corvex.json`), overridable via `--settings`
- Xray config: `$XDG_CONFIG_HOME/xray/config.json`
- PID file: `$XDG_CONFIG_HOME/xray/xray.pid`
- Corvex log: `$XDG_STATE_HOME/corvex/corvex.log`
- Xray logs: configurable via corvex.json `log.xray.*`, default `/var/log/xray/`

### Windows
- corvex.json: `%APPDATA%\corvex\corvex.json`
- Xray config: `%APPDATA%\xray\config.json`
- Logs: `%LOCALAPPDATA%\corvex\corvex.log`

## Dependencies

clap (CLI), anyhow/thiserror (errors), colored (output), log/env_logger (debug logging), serde/serde_json (config), json_comments (JSONC parsing), nix (unix signals/PID), windows-sys (Windows API), url (URI parsing), ureq (HTTP + SOCKS proxy), base64 (subscription/vpn decoding), rand (health check port selection)
