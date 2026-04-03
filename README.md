# corvex

Manage Xray VPN proxy and macOS system proxy from the command line.

corvex starts/stops the [Xray](https://github.com/XTLS/Xray-core) daemon, configures it from a single `corvex.json` settings file, supports multiple proxy protocols (VLESS, VMess, Trojan, Shadowsocks), allocates a dynamic local port, and toggles macOS system proxy settings automatically.

## Installation

```bash
cargo build --release
cp target/release/corvex /usr/local/bin/
```

Xray is auto-installed via Homebrew on first `corvex start` if not already present.

## Quick start

Create `~/.config/corvex/corvex.json`:

```jsonc
{
  // Direct URI — connect to a specific server
  "uri": "vless://uuid@host:443?encryption=none&type=grpc&security=tls&sni=example.com#Name"
}
```

Or use subscription-based auto-discovery:

```jsonc
{
  // Subscription URLs — corvex downloads, decodes, health-checks, and picks the best server
  "file-url": ["https://example.com/subscription.txt"]
}
```

Then:

```bash
corvex start    # Load config, resolve server, start xray, enable system proxy
corvex stop     # Disable system proxy, stop xray
corvex status   # Show process state, ports, proxy settings, config paths
```

## Commands

| Command | Description |
|---------|-------------|
| `start` | Load `corvex.json`, resolve server, start xray, enable system proxy |
| `stop` | Disable system proxy, stop xray |
| `reload` | Validate config and send SIGHUP to xray |
| `status` | Show xray process state, ports, proxy settings, config paths |
| `logs` | Show last 20 log lines |
| `logs -f` | Follow log output |

## Flags

| Flag | Description |
|------|-------------|
| `--settings <path>` | Use a custom `corvex.json` path (overrides default) |

Environment: `CORVEX_DEBUG=1` enables debug logging to stderr.

## Configuration

All settings live in a single JSONC file (comments allowed) at `$XDG_CONFIG_HOME/corvex/corvex.json` (defaults to `~/.config/corvex/corvex.json`).

```jsonc
{
  // Option A: direct proxy URI (VLESS, VMess, Trojan, or Shadowsocks)
  "uri": "vless://uuid@host:443?encryption=none&type=grpc&security=tls&sni=host.com#Name",

  // Option B: subscription URLs for auto-discovery (picks fastest healthy server)
  "file-url": ["https://example.com/sub1.txt", "https://example.com/sub2.txt"],

  // Corporate DNS: domain -> nameserver (merged with macOS scutil --dns discovery)
  "corporate-dns": {
    "corp.example.com": "10.0.0.1",
    "internal.local": "172.16.0.1"
  },

  // Routing rules
  "routes": {
    "direct-ru": true,                              // Route .ru TLD directly (bypass proxy)
    "proxy-traffic": ["domain:youtube.com"],         // Force through proxy
    "corporate-traffic": ["domain:corp.example.com"] // Bypass proxy (direct)
  },

  // Logging
  "log": {
    "xray": {
      "loglevel": "warning",
      "access": "/var/log/xray/access.log",
      "error": "/var/log/xray/error.log"
    },
    "corvex": { "debug": false }
  }
}
```

Provide either `uri` (connect to a specific server) or `file-url` (auto-discover from subscriptions). If both are present, `uri` takes precedence.

### Routing entries format

Routing entries in `proxy-traffic` and `corporate-traffic` support xray domain matching prefixes. Entries without a prefix get `domain:` prepended automatically:

```
domain:corp.example.com   # Exact domain + subdomains
corp-internal.local        # Same as domain:corp-internal.local
regexp:.*\.corp$           # Regex pattern
full:exact.host.com        # Exact match only
```

## Key paths

| Path | Purpose |
|------|---------|
| `$XDG_CONFIG_HOME/corvex/corvex.json` | Settings file (default `~/.config/corvex/corvex.json`) |
| `$XDG_CONFIG_HOME/xray/config.json` | Xray daemon config (auto-generated) |
| `$XDG_CONFIG_HOME/xray/xray.pid` | PID file for running xray process |
| `$XDG_STATE_HOME/corvex/corvex.log` | Corvex log (default `~/.local/state/corvex/corvex.log`) |
| Xray logs | Configurable via `log.xray` in corvex.json |

## How it works

1. **Load config**: reads `corvex.json` settings
2. **Resolve server**: uses the `uri` directly, or downloads subscriptions, decodes base64, filters supported protocols, and health-checks candidates (TCP pre-filter + tunnel latency)
3. **Generate xray config**: creates or updates xray `config.json` with proxy settings, routing rules, and DNS
4. **Auto-install**: ensures xray is available (installs via `brew` if missing)
5. **Port**: allocates a random free port in 20000-60000
6. **Start**: launches xray with the config
7. **Proxy**: enables macOS system proxy (HTTP, HTTPS, SOCKS) on the allocated port

## Supported protocols

- **VLESS** — `vless://uuid@host:port?params#name`
- **VMess** — `vmess://base64json`
- **Trojan** — `trojan://password@host:port?params#name`
- **Shadowsocks** — `ss://base64(method:password)@host:port#name` (SIP002 and legacy formats)

## Requirements

- macOS (uses `networksetup` for system proxy)
- Rust toolchain (for building)
- Homebrew (for auto-installing xray)
