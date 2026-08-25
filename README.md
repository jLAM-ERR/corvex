<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-vertical-dark.svg">
    <img src="assets/logo-vertical-light.svg" alt="Corvex" width="240">
  </picture>
</p>

# corvex

Manage Xray VPN proxy and system proxy from the command line.

corvex configures everything from a single `corvex.json` settings file, resolves the best server (directly or from subscriptions), and toggles system proxy settings automatically. Under the hood it drives one of two tunnel engines:

- **[Xray](https://github.com/XTLS/Xray-core) — the default engine.** Used for every VLESS, VMess, Trojan, and Shadowsocks URI and for all subscription-based configs. corvex generates its config, manages its process, and `install.sh` installs the binary for you.
- **[AmneziaWG](https://amnezia.org/) — an optional alternative engine.** Used only when the configured URI is `vpn://`. corvex never installs it — see [AmneziaWG support](#amneziawg-support).

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/jLAM-ERR/corvex/main/install.sh | sh
```

Or, from a checkout:

```bash
./install.sh
```

This installs the `corvex` binary and, as a dependency, the `xray` engine binary (only when `xray` isn't already installed). Re-running the script always upgrades `corvex` to the latest release; an existing `xray` install is left untouched.

When it installs `xray`, install.sh also installs xray's `geoip.dat`/`geosite.dat` to `/usr/local/share/xray` (needed for `geosite:`/`geoip:` routing rules, including corvex's own loopback/RFC1918 direct rule). A failure to install these files is a warning, not fatal: point `XRAY_LOCATION_ASSET` at a directory containing the `.dat` files yourself, or use a package-manager xray (a brew-managed `xray` already ships its own geo data).

The script needs `curl` and `tar`; `unzip` is required only when it has to install xray.

### Supported platforms

`install.sh` supports macOS (arm64, x86_64) and Linux (x86_64). On Windows, download the release zip from [Releases](https://github.com/jLAM-ERR/corvex/releases) manually. corvex itself runs on macOS, Linux, and Windows.

### Installation from source

Requires [rustup](https://rustup.rs). The toolchain is pinned in `rust-toolchain.toml`, so rustup installs that exact version — and the cross-compilation targets the release job builds — on your first `cargo` command in the checkout. A cargo installed outside rustup ignores the pin and may format and lint differently from CI:

```bash
cargo build --release
cp target/release/corvex /usr/local/bin/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, test gates, and workflow.

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
corvex stop     # Stop xray, then disable system proxy
corvex status   # Show engine type, process state, ports, proxy settings
corvex dns      # Diagnose the system resolvers when name resolution misbehaves
```

## Commands

| Command | Description |
|---------|-------------|
| `start` | Load `corvex.json`, resolve server, start xray (+ AWG tunnel if vpn://), enable system proxy |
| `stop` | Stop xray first; only if that succeeds, disable system proxy and stop AWG tunnel |
| `restart` | Same flow as `start`: stops the running xray (and stale AWG tunnel), re-reads config, re-resolves server, re-applies system proxy |
| `reload` | Validate config and send SIGHUP to xray |
| `status` | Show engine type (xray / AWG+xray), process state, ports, proxy settings |
| `dns` | Diagnose the system resolvers: route, interface, next-hop reachability, live UDP/53 probe |
| `logs` | Show last 20 lines of the xray log |
| `logs -f` | Follow the xray log |

A failed `stop` (e.g. xray owned by another user) leaves the system proxy untouched; if disabling the proxy fails after xray stopped, the AWG tunnel is likewise left running.

## Flags

| Flag | Description |
|------|-------------|
| `--settings <path>` | Use a custom `corvex.json` path (overrides default) |

Environment: `CORVEX_DEBUG=1` enables debug logging (see [Logging](#logging)).

## Logging

corvex writes its own log to `$XDG_STATE_HOME/corvex/corvex.log` (`%LOCALAPPDATA%\corvex\corvex.log` on Windows). Every *log* line goes to both the terminal and that file. Command output printed on stdout — the `corvex status` and `corvex dns` reports, and the green `xray started` / `proxy enabled` confirmations — is terminal-only and is not recorded. On macOS and Linux the file is created with mode `0600` — owner read/write only — and a file already at that path with a looser mode is tightened to `0600` on the next run. Windows has no mode bits; there the file inherits the per-user ACL of `%LOCALAPPDATA%`.

The location is not configurable. A `log.corvex.path` key in `corvex.json` parses without complaint but is ignored; corvex always writes the path above.

The default level is `info`, so a `start` narrates what it is doing and how long each phase took. This matters when a start is slow or fails: it used to print nothing at all between "invoked" and "failed", which made a stalled subscription download and a stalled server sweep look identical.

```
2026-08-24T09:12:03Z [INFO] settings loaded: /home/you/.config/corvex/corvex.json (2ms)
2026-08-24T09:12:03Z [INFO] subscription https://panel.example/<redacted>: downloading
2026-08-24T09:12:04Z [INFO] subscription downloaded: 4821 bytes from https://panel.example/<redacted> (612ms)
2026-08-24T09:12:04Z [INFO] subscription candidates: 12 json entries, 0 xray uris, 0 vpn uris (615ms)
2026-08-24T09:12:04Z [INFO] candidate 1/12 example.net:443: testing
2026-08-24T09:12:07Z [INFO] candidate 1/12 example.net:443: alive (284.31ms)
2026-08-24T09:12:07Z [INFO] engine selected: xray (json subscription entry)
2026-08-24T09:12:08Z [INFO] xray started: PID 40321 (1.03s)
2026-08-24T09:12:09Z [INFO] proxy applied: Wi-Fi -> 127.0.0.1:21080 (1.02s)
2026-08-24T09:12:09Z [INFO] start complete (6.29s)
```

**Subscription URLs are never written in full.** Panels put the access token in the URL path (`https://panel.example/sub/<TOKEN>`), so every line that mentions a subscription — success, progress, and failure alike — keeps the scheme and host and replaces userinfo, path, query and fragment with `<redacted>`. A URL corvex cannot parse is rendered as `<redacted>` alone rather than echoed back.

**Levels.** `CORVEX_DEBUG=1`, or `"log": { "corvex": { "debug": true } }` in `corvex.json`, raises the level to `debug`. `RUST_LOG` overrides both. Note that `RUST_LOG=warn corvex start` is now *quieter* than the old default, not equal to it: the server-testing progress lines used to print unconditionally and now go through the log level like everything else.

**Rotation.** Once `corvex.log` passes 5 MB it is renamed to `corvex.log.1`, replacing any previous `.1`. One past generation is kept; there is no compression and no dated archive.

**If the log file cannot be written** — an unwritable state directory, a full disk — corvex reports it once on the terminal and carries on with terminal output only. Logging never aborts a command.

Note that `corvex logs` tails the **xray** log, not this one. Read `corvex.log` directly (`tail -f ~/.local/state/corvex/corvex.log`).

## Diagnosing DNS problems (`corvex dns`)

`corvex dns` walks the whole path to each of your system resolvers and reports where it breaks:

```
$ corvex dns
Settings: /home/you/.config/corvex/corvex.json

Resolver: domain corp.example.com on en0
  10.10.20.53  via 10.10.99.1 on en0  UNREACHABLE NEXT HOP: gateway 10.10.99.1 is outside en0's subnet, probe skipped
  10.10.20.54  via 192.0.2.1 on en0  answered in 34ms

Resolver: global (no domain scope) on en0
  192.0.2.1  directly connected on en0  answered in 4ms
  fe80::1%en0  not diagnosed: the route check and the probe are IPv4-only
```

For every nameserver of every resolver it reads the route (`route -n get` on macOS, `ip route get` on Linux), finds the interface that route names, and checks whether the gateway is actually **on-link** — inside that interface's own subnet. A gateway outside it can never be ARP-resolved, so every query to that nameserver dies with `sendto: Network is unreachable` even though the route, the interface and the nameserver each look healthy in isolation. That is the failure this command exists to catch; a stale per-host route left behind by a VPN client is the usual cause. Only a nameserver whose next hop is on-link is probed with a real UDP/53 query (2 s timeout).

**The check is IPv4-only, and it never invents a fault.** Whenever the arithmetic cannot be done, the next hop is reported reachable and the probe runs anyway: an interface whose IPv4 address cannot be read, and a point-to-point tunnel (`utun`, `wg`), whose `/32` has no subnet for a peer gateway to be outside of. A `/32` sitting *beside* a real subnet is a service alias rather than a tunnel, so it is skipped and the subnet still decides. An interface carrying several addresses is on-link if the gateway matches *any* of them. A nameserver that is not an IPv4 literal — including the `fe80::1%en0` a router advertising RDNSS puts in `scutil --dns` — is listed as `not diagnosed` rather than walked, because neither `route get` nor the probe socket accepts a zone id.

The report is read-only and exits 0 even when it finds problems — a resolver that does not answer prints `no answer: <cause>`, one whose route cannot be read prints `no route: <cause>`, and the walk continues either way, so one dead half of a failover pair never hides the working half. A system that reports no resolvers at all prints `No resolvers to diagnose were reported by the system.` Every probe asks for `example.com`, reserved for documentation by RFC 2606, so a diagnostic never puts your own zone on the wire. **corvex never changes routes.** Fixing a stale route is a job for the VPN client that installed it (typically by dropping a redundant per-host `route` directive from the profile when a covering network route already exists).

**Platform support.** On macOS the listing comes from `scutil --dns` and covers every resolver the system reports — the default one with no domain scope included, and every nameserver of a failover pair, not just the first of each. On Linux it comes from `resolvectl status` and is currently narrower: one nameserver per search domain, no interface name, and no global resolver, because the `resolvectl` parser still returns a domain-to-nameserver map. The next-hop check and the probe work fully on both. In all, `corvex dns` shells out to `scutil --dns`, `route -n get` and `ifconfig` on macOS, and to `resolvectl status`, `ip route get` and `ip addr show` on Linux — all read-only. A Linux box without systemd-resolved has no `resolvectl`, and `corvex dns` reports that failure instead of a report. On Windows `corvex dns` reports that it is not implemented; every other command is unaffected.

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
    "proxy-traffic": ["domain:youtube.com"],          // Force through proxy
    "corporate-traffic": ["domain:corp.example.com"], // Bypass proxy (direct)
    "merge-subs": false                               // Merge subscription's own direct-routing rules; SEE WARNING below; default off
  },

  // Logging
  "log": {
    "xray": {
      "loglevel": "warning"
      // "access"/"error" default to $XDG_STATE_HOME/xray/{access,error}.log
      // (%LOCALAPPDATA%\xray\ on Windows); set them here to log elsewhere,
      // e.g. "/var/log/xray/access.log" (needs the directory to be
      // user-writable)
    },
    "corvex": { "debug": false }  // "path" is parsed but ignored: the log location is fixed
  }
}
```

Provide either `uri` (connect to a specific server) or `subs-url` (auto-discover from subscriptions). If both are present, `uri` takes precedence.

`file-url` is a deprecated alias for `subs-url` and still works.

### Subscription request identity

Subscription panels commonly content-negotiate on the `User-Agent` header: an unknown or missing UA (plain `curl`, or corvex without this setting) can get a filtered or broken response instead of the real subscription. `subs-user-agent` sets the UA corvex sends when downloading `subs-url`/`file-url`; it defaults to `"v2rayNG/1.10.2"`, which reliably yields a plain base64 response from most panels. `subs-headers` adds extra request headers some panels require (e.g. `X-Hwid`, `X-Device-Os`, `X-Ver-Os`, `X-Device-Model`). A `User-Agent` key inside `subs-headers` (case-insensitive) wins over `subs-user-agent`.

### JSON-array subscription format

Some panels serve a JSON-array response instead of base64: a JSON array of complete xray configs, one per server (there are no URIs to parse in this format). This is the format panels serve to mobile clients such as Happ. corvex auto-detects it and extracts server candidates directly from the JSON — health-checked the same way as URI-based candidates. No extra configuration is needed beyond `subs-user-agent`/`subs-headers` (the panel decides which format to serve based on those).

### Merging subscription routing rules (`routes.merge-subs`)

JSON-array subscriptions can carry their own routing rules, including domains/IPs the panel routes `direct` (bypassing the tunnel). When `routes.merge-subs: true`, corvex merges the chosen subscription entry's direct-routing domains and IPs into its own routing. Default is `false`.

**This setting is transitional.** Merging is expected to become the default behavior in a future release, at which point `routes.merge-subs` will be removed. For now it stays opt-in (default off) — see the security warning below.

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

AmneziaWG is an optional alternative engine and corvex never installs it. **If you plan to use a `vpn://` config, install `amneziawg-tools` with your package manager (e.g. `brew install amneziawg-tools`, `apt install amneziawg-tools`) before launching corvex** — `corvex start` refuses to bring up AWG mode when `awg-quick` is not in PATH.

## Key paths

| Path | Purpose |
|------|---------|
| `$XDG_CONFIG_HOME/corvex/corvex.json` | Settings file (default `~/.config/corvex/corvex.json`) |
| `$XDG_CONFIG_HOME/xray/config.json` | Xray daemon config (auto-generated) |
| `$XDG_CONFIG_HOME/xray/xray.pid` | PID file for running xray process |
| `$XDG_STATE_HOME/corvex/corvex.log` | Corvex log (default `~/.local/state/corvex/corvex.log`), mode `0600` on unix, rotated to `corvex.log.1` past 5 MB — see [Logging](#logging) |
| `$XDG_STATE_HOME/xray/{access,error}.log` | Xray logs (default; `%LOCALAPPDATA%\xray\` on Windows); override via `log.xray` in corvex.json |

## How it works

1. **Load config**: reads `corvex.json` settings
2. **Resolve server**: uses the `uri` directly, or downloads subscriptions, decodes base64, filters supported protocols, and health-checks candidates. Subscription downloads deliberately ignore `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` — the fetch is what brings the tunnel up, so sending it through the tunnel (which a shell exporting `HTTP_PROXY=http://localhost:<proxy.port>` would do) deadlocks `start` against itself
3. **Engine dispatch**: detects engine mode from URI scheme (`vpn://` → AWG, others → Xray)
4. **Generate xray config**: creates xray `config.json` with proxy settings, routing rules, DNS, and corporate-dns routing rule (port 53)
5. **Verify**: checks the xray binary is present (installed by install.sh); in AWG mode also checks `awg-quick`
6. **Start**: launches xray (and AWG tunnel if applicable) with the config
7. **Proxy**: enables system proxy (HTTP, HTTPS, SOCKS) on the configured port

## macOS privilege escalation

Setting the system proxy on macOS requires admin privileges. When running without `sudo`, corvex shows a native macOS authorization dialog via `osascript`. Enabling the proxy takes six `networksetup` calls and disabling it takes three; corvex applies each group inside a single `osascript` invocation, so you are asked **once** per command, not once per `networksetup` call.

- `corvex start` / `corvex stop` — one dialog each, if not running as root
- `sudo corvex start` — bypasses the dialog entirely
- SSH (no GUI) — falls back to a clear error message suggesting `sudo`
- Canceling the dialog — reports "Authorization denied". In the normal case nothing has been applied yet and the message says so, because the very first `networksetup` call is the one that asks for the password. If some commands had already gone through before the dialog appeared, the message says instead that earlier settings may already have been applied — corvex tracks the difference rather than promising the proxy is untouched.

**The dialog asks for a password and cannot offer Touch ID.** This is not a corvex setting. The dialog authorizes the system's `system.privilege.admin` right, which is password-only; there is no flag that adds biometrics to it. Touch ID would require corvex to elevate through `sudo` instead, which needs a terminal, excludes users who are not in `sudoers`, and depends on you enabling `pam_tid.so` in `/etc/pam.d/sudo_local` yourself. That trade is not currently worth it, so the single prompt is a password prompt.

## Recovering from a mixed sudo/user state

If xray has ever been started with `sudo`, a plain `corvex start` can fail because a root-owned xray is still around:

- **A tracked root-owned xray is running** (`start` reports it's already running as another user): run `sudo corvex stop` once, then plain `corvex start`. Do **not** run `sudo corvex start` — that starts another root-owned xray and you're back where you started. If `sudo corvex stop` instead reports xray isn't running while `corvex status` still shows the root-owned process, `sudo` reset your environment (common on Linux) — use `sudo kill <pid>` directly, or `sudo -E corvex stop` to preserve it.
- **An untracked xray is running** (an orphan, reported by `status` or a failed `start`): orphan detection and the lifecycle commands (`start`/`stop`/`reload`) only ever signal the daemon recorded in the PID file, so none of them can stop this one for you — corvex's own short-lived health-check processes are a separate matter, owned and cleaned up by the check itself. Stop the orphan yourself with `sudo kill <pid>` (or plain `kill <pid>` if you own it) — check with `ps -p <pid>` first, since the report is a snapshot and PIDs get reused.

**Killing a process leaves the system proxy enabled.** `kill` stops xray and nothing else, so the proxy still points at `127.0.0.1:<port>`. If the process you killed was the one serving that port, everything using the system proxy fails with connection errors until you run `corvex start` again. Note that `corvex stop` will not clear it either: with no xray running it reports `xray is not running` and returns before disabling the proxy, so run `corvex start` (then `corvex stop`, if you wanted it off) to get back to a consistent state.

In practice an orphan is usually *not* the process serving your port — two xray instances cannot both bind it, which is why a failed `start` reporting a port conflict means the orphan holds it and the tracked process never came up. Killing the orphan there frees the port with nothing to interrupt. `sudo corvex stop` remains the right command for a tracked process, precisely because it disables the proxy as well.

Going forward, avoid `sudo corvex start` entirely — corvex already prompts for a password via the graphical dialog above when it needs admin rights.

