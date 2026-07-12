<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-vertical-dark.svg">
    <img src="assets/logo-vertical-light.svg" alt="Corvex" width="240">
  </picture>
</p>

# corvex

Manage Xray VPN proxy and system proxy from the command line.

corvex starts/stops the [Xray](https://github.com/XTLS/Xray-core) daemon (the default engine), configures it from a single `corvex.json` settings file, supports multiple proxy protocols (VLESS, VMess, Trojan, Shadowsocks), and toggles system proxy settings automatically. It also supports [AmneziaWG](https://amnezia.org/) as an optional alternative tunnel engine.

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/jLAM-ERR/corvex/main/install.sh | sh
```

Or, from a checkout:

```bash
./install.sh
```

This installs the `corvex` binary and, as a dependency, the `xray` engine binary (only when `xray` isn't already installed). Re-running the script always upgrades `corvex` to the latest release; an existing `xray` install is left untouched.

When it installs `xray`, install.sh also installs xray's `geoip.dat`/`geosite.dat` to `/usr/local/share/xray` (needed for `geosite:`/`geoip:` routing rules, including corvex's own loopback/RFC1918 direct rule). A failure to install these files is a warning, not fatal — set `XRAY_LOCATION_ASSET` yourself (e.g. a brew-managed `xray` already provides its own geo data).

Supported platforms: macOS (arm64, x86_64) and Linux (x86_64). On Windows, download the release zip from [Releases](https://github.com/jLAM-ERR/corvex/releases) manually.

### Installation from source

```bash
cargo build --release
cp target/release/corvex /usr/local/bin/
```

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
  "subs-url": ["https://example.com/subscription.txt"],
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
| `restart` | Same flow as `start`: stops the running xray (and stale AWG tunnel), re-reads config, re-resolves server, re-applies system proxy |
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
  "subs-url": ["https://example.com/sub1.txt", "https://example.com/sub2.txt"],

  // Optional: identity used when downloading subs-url (see "Subscription request
  // identity" below); default "v2rayNG/1.10.2"
  "subs-user-agent": "Happ/3.13.0",
  "subs-headers": { "X-Hwid": "abc", "X-Device-Os": "Android" },

  // Required: static proxy port
  "proxy": { "port": 21080 },

  // Corporate DNS: domain -> nameserver (merged with OS DNS discovery)
  "corporate-dns": {
    "corp.example.com": "10.0.0.1",
    "internal.local": "172.16.0.1"
  },

  // Routing rules
  "routes": {
    "direct-ru": true,                               // Route .ru TLD directly (bypass proxy)
    "proxy-traffic": ["domain:youtube.com"],          // Force through proxy
    "corporate-traffic": ["domain:corp.example.com"], // Bypass proxy (direct)
    "merge-subs": false                               // Merge subscription's own direct-routing rules; SEE WARNING below; default off
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

Provide either `uri` (connect to a specific server) or `subs-url` (auto-discover from subscriptions). If both are present, `uri` takes precedence.

`file-url` is a deprecated alias for `subs-url` and still works.

### Subscription request identity

Subscription panels commonly content-negotiate on the `User-Agent` header: an unknown or missing UA (plain `curl`, or corvex without this setting) can get a filtered or broken response instead of the real subscription. `subs-user-agent` sets the UA corvex sends when downloading `subs-url`/`file-url`; it defaults to `"v2rayNG/1.10.2"`, which reliably yields a plain base64 response from most panels. `subs-headers` adds extra request headers some panels require (e.g. `X-Hwid`, `X-Device-Os`, `X-Ver-Os`, `X-Device-Model`). A `User-Agent` key inside `subs-headers` (case-insensitive) wins over `subs-user-agent`.

### Happ-format subscriptions

Some panels serve a Happ-compatible response instead of base64: a JSON array of complete xray configs, one per server (there are no URIs to parse in this format). corvex auto-detects it and extracts server candidates directly from the JSON — health-checked the same way as URI-based candidates. No extra configuration is needed beyond `subs-user-agent`/`subs-headers` (the panel decides which format to serve based on those).

### Merging subscription routing rules (`routes.merge-subs`)

Happ-format subscriptions can carry their own routing rules, including domains/IPs the panel routes `direct` (bypassing the tunnel). When `routes.merge-subs: true`, corvex merges the chosen subscription entry's direct-routing domains and IPs into its own routing. Default is `false`.

**Security warning:** turning this on means whoever controls the subscription can route the domains/IPs it lists OUTSIDE the tunnel — only enable it for a subscription provider you trust with that decision. Local `proxy-traffic` entries always win over subscription domains (so you can force a domain back through the tunnel regardless of what the subscription says), and the loopback/RFC1918 direct rule can never be displaced by a merge.

Merged rules are baked into `config.json` at `start`/`restart` time, when corvex re-downloads and re-resolves the subscription. `reload` only re-validates the existing `config.json` and sends SIGHUP — it does not re-download subscriptions, so a change in the subscription's rules takes effect on the next `start`/`restart`, not on `reload`.

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

AmneziaWG is an optional alternative engine. corvex never installs it — install `amneziawg-tools` manually with your package manager.

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
5. **Verify**: checks the xray binary is present (installed by install.sh); in AWG mode also checks `awg-quick`
6. **Start**: launches xray (and AWG tunnel if applicable) with the config
7. **Proxy**: enables system proxy (HTTP, HTTPS, SOCKS) on the configured port

## macOS privilege escalation

Setting system proxy on macOS requires admin privileges. When running without `sudo`, corvex automatically shows a native macOS authorization dialog (Touch ID or password) via `osascript`. The system caches authorization for ~5 minutes, so only one dialog appears per session even though multiple `networksetup` calls are made.

- `corvex start` / `corvex stop` — triggers auth dialog if not running as root
- `sudo corvex start` — bypasses the dialog entirely
- SSH (no GUI) — falls back to a clear error message suggesting `sudo`
- Canceling the dialog — reports "Authorization denied" without partial changes

## Requirements

- macOS, Linux, or Windows
- Rust toolchain (for building from source)
- `curl` and `tar` (for `install.sh`); `unzip` only when it needs to install xray
- `proxy.port` must be set in corvex.json
