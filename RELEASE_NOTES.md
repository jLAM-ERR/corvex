# Corvex v0.3.0 Release Notes

## Highlights

Cross-platform release: corvex now runs on macOS, Linux, and Windows. New AmneziaWG tunnel engine, platform abstraction layer, and hardened security across the board.

## What's New

### Cross-Platform Support
- **Linux**: proxy via environment file + desktop environment detection (GNOME gsettings, KDE kwriteconfig), DNS via `resolvectl`
- **Windows**: proxy via registry (Internet Settings), DNS via adapter queries and NRPT registry rules
- **macOS**: unchanged — `networksetup` and `scutil`

### AmneziaWG Engine
New `vpn://` URI scheme routes traffic through AmneziaWG tunnels:
- Parses `vpn://base64json` URIs with obfuscation parameters (Jc, Jmin, Jmax, S1, S2, H1-H4)
- Generates `.conf` files and manages `awg-quick up/down` lifecycle
- Xray runs as a local routing layer with a `freedom` outbound on top of the AWG tunnel
- Auto-installs `amneziawg-tools` via brew (macOS) or prompts for manual install (Linux)

### Subscription vpn:// Handling
Subscriptions containing `vpn://` URIs are now handled correctly. Xray-compatible URIs are health-checked first; if none are reachable, corvex falls back to the first available `vpn://` URI via the AWG engine.

### Static Proxy Port
The proxy port is now configured explicitly via `"proxy": {"port": 21080}` in corvex.json (required). This eliminates the TOCTOU race from dynamic port allocation. Health checks retain private ephemeral ports.

### Security Hardening
- All credential-bearing files (xray config, AWG conf, health-check temp configs) use `0o600` permissions on unix
- Health-check temp configs use auto-deleting temp files to prevent credential leakage on crash
- AWG config fields are validated for newline injection before writing `.conf` files
- Windows process management uses proper null-pointer checks for handle validation

### Engine Mode Type Safety
Engine dispatch uses a proper `EngineMode` enum instead of string matching, preventing silent fallthrough from typos.

### CI/CD
GitHub Actions workflow runs tests, clippy, and fmt on both macOS and Windows. Release builds produce:
- macOS universal binary (x86_64 + aarch64)
- Windows x86_64 binary

## Commands

```
corvex start                                    # Load corvex.json, resolve server, start
corvex stop                                     # Disable system proxy + stop xray (+ AWG if active)
corvex reload                                   # Validate config, send SIGHUP
corvex status                                   # Show engine type, process, ports, proxy settings
corvex logs                                     # Show last 20 log lines
corvex logs -f                                  # Follow log output
corvex --settings /path/to/corvex.json start    # Use custom settings file
CORVEX_DEBUG=1 corvex start                     # Enable debug logging
```

## Breaking Changes

- **`proxy.port` is now required** in corvex.json — dynamic port allocation removed
- **Config paths on Windows** follow `%APPDATA%` / `%LOCALAPPDATA%` conventions

## Migration from v0.2.0

1. Add `"proxy": {"port": 21080}` to your corvex.json (pick any port >= 1024)
2. For AWG usage: add a `vpn://` URI to `"uri"` or subscription, and ensure `awg-quick` is installed
3. No other config changes required — existing corvex.json files are compatible
