# corvex

Manage Xray VPN proxy and system proxy from the command line.

corvex starts/stops the [Xray](https://github.com/XTLS/Xray-core) daemon, configures it from a single `corvex.json` settings file, supports multiple proxy protocols (VLESS, VMess, Trojan, Shadowsocks), and toggles system proxy settings automatically. It also supports [AmneziaWG](https://amnezia.org/) as an alternative tunnel engine.

## Installation

```bash
cargo build --release
cp target/release/corvex /usr/local/bin/
```

Xray is auto-installed via Homebrew (macOS) or winget (Windows) on first `corvex start` if not already present.

## Quick start

Create `~/.config/corvex/corvex.json`:

```jsonc
{
  // Direct URI — connect to a specific server
  "uri": "vless://uuid@host:443?encryption=none&type=grpc&security=tls&sni=example.com#Name",
  // Required: static proxy port
  "proxy": { "port": 21080 }
}
```

Or use subscription-based auto-discovery:

```jsonc
{
  // Subscription URLs — corvex downloads, decodes, health-checks, and picks the best server
  "file-url": ["https://example.com/subscription.txt"],
  "proxy": { "port": 21080 }
}
```

For AmneziaWG tunnel:

```jsonc
{
  "uri": "vpn://<base64-encoded-config>",
  "proxy": { "port": 21080 }
}
```

Then:

```bash
corvex start    # Load config, resolve server, start xray, enable system proxy
corvex stop     # Disable system proxy, stop xray
corvex status   # Show engine type, process state, ports, proxy settings
```

## Commands

| Command | Description |
|---------|-------------|
| `start` | Load `corvex.json`, resolve server, start xray (+ AWG tunnel if vpn://), enable system proxy |
| `stop` | Disable system proxy, stop xray, stop AWG tunnel if running |
| `reload` | Validate config and send SIGHUP to xray |
| `status` | Show engine type (xray / AWG+xray), process state, ports, proxy settings |
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
  // Option A: direct proxy URI (VLESS, VMess, Trojan, Shadowsocks, or AmneziaWG)
  "uri": "vless://uuid@host:443?encryption=none&type=grpc&security=tls&sni=host.com#Name",

  // Option B: subscription URLs for auto-discovery (picks fastest healthy server)
  "file-url": ["https://example.com/sub1.txt", "https://example.com/sub2.txt"],

  // Required: static proxy port
  "proxy": { "port": 21080 },

  // Corporate DNS: domain -> nameserver (merged with OS DNS discovery)
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

Loopback (`127.0.0.0/8`, `::1`) and RFC1918 private networks (`10/8`, `172.16/12`, `192.168/16`) are always routed `direct`, ahead of every other rule. This is unconditional and cannot be disabled — tunneling localhost or private IPs through a public VPN exit never works.

## Supported protocols

- **VLESS** — `vless://uuid@host:port?params#name`
- **VMess** — `vmess://base64json`
- **Trojan** — `trojan://password@host:port?params#name`
- **Shadowsocks** — `ss://base64(method:password)@host:port#name` (SIP002 and legacy formats)
- **AmneziaWG** — `vpn://base64json` (AWG tunnel + xray as routing layer)

## AmneziaWG support

When using a `vpn://` URI, corvex runs in AWG mode:
1. Parses the `vpn://` URI and extracts AmneziaWG configuration
2. Writes an AWG `.conf` file and starts the tunnel via `awg-quick up` (requires sudo)
3. Starts xray as a local routing layer with a `freedom` outbound (traffic exits through the AWG tunnel)
4. Enables system proxy pointing to xray's SOCKS port

AWG mode requires `awg-quick` to be installed (auto-installed via brew on macOS).

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
2. **Resolve server**: uses the `uri` directly, or downloads subscriptions, decodes base64, filters supported protocols, and health-checks candidates
3. **Engine dispatch**: detects engine mode from URI scheme (`vpn://` → AWG, others → Xray)
4. **Generate xray config**: creates xray `config.json` with proxy settings, routing rules, DNS, and corporate-dns routing rule (port 53)
5. **Auto-install**: ensures xray (and awg-quick for AWG mode) are available
6. **Start**: launches xray (and AWG tunnel if applicable) with the config
7. **Proxy**: enables system proxy (HTTP, HTTPS, SOCKS) on the configured port

## Requirements

- macOS or Windows
- Rust toolchain (for building)
- Homebrew (macOS, for auto-installing xray/amneziawg-tools)
- `proxy.port` must be set in corvex.json
