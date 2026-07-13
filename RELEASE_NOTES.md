# Corvex v0.6.0 Release Notes

## Highlights

One-command installation with `install.sh`, a new `restart` command, smarter subscriptions (panel-friendly request identity, JSON-array format support, opt-in routing merge), and the first Linux binaries.

## What's New

### install.sh installer
```bash
curl -fsSL https://raw.githubusercontent.com/jLAM-ERR/corvex/main/install.sh | sh
```
Installs the latest corvex release and — as a dependency — the xray engine when it's missing, including xray's `geoip.dat`/`geosite.dat` (required for `geosite:`/`geoip:` routing rules). Re-runs upgrade corvex and top up missing geo data without touching an existing xray. Supports macOS (arm64/x86_64) and Linux (x86_64).

### No more auto-install at runtime
corvex no longer silently runs `brew install` / `winget install` during `start`. Missing xray → a clear error pointing at install.sh. AmneziaWG is optional and never installed by corvex — install `amneziawg-tools` manually before using `vpn://` configs.

### restart command
`corvex restart` runs the full start flow: stops the running xray (and a stale AWG tunnel — previously leaked when switching engine modes), re-reads corvex.json, re-resolves the server, regenerates the config, and re-applies the system proxy.

### Subscriptions
- **`subs-url` replaces `file-url`** (the old key still works as an alias).
- **Request identity**: `subs-user-agent` (default `v2rayNG/1.10.2`) and `subs-headers` — subscription panels content-negotiate on User-Agent and may filter unknown clients; these keys make corvex look like a client your panel accepts.
- **JSON-array subscription format**: panels that serve complete xray configs (the format sent to mobile clients such as Happ) are auto-detected; servers are extracted straight from the JSON and health-checked as usual.
- **`routes.merge-subs`** (opt-in, default off, transitional): merges the subscription's own direct-routing domains/IPs into corvex routing. Local `proxy-traffic` always wins; the loopback/RFC1918 rule can never be displaced. See the README security warning before enabling.

### Removed: `routes.direct-ru`
Route .ru directly via `routes.corporate-traffic` or a subscription's direct rules instead. A leftover `direct-ru` key in old configs still parses and logs a warning.

### Reliability fixes
- Switching from an AWG session to an xray server no longer fails after tearing down the tunnel — an un-updatable config is regenerated from scratch.
- Routing rules and the proxy outbound tag can no longer desync when an unnamed server replaces a named one.

### CI / packaging
- First **Linux (x86_64, static musl)** release binaries.
- Tests run on macOS, Linux, and Windows; CI triggers once per PR and once per version tag.

## Migration from v0.5.x

- corvex.json needs no changes: `file-url` keeps working (renamed to `subs-url`), `direct-ru` is ignored with a warning.
- If you relied on `direct-ru`, add the .ru entries you need to `routes.corporate-traffic` or enable `routes.merge-subs` with a subscription that carries them.
- If you relied on xray being auto-installed by brew/winget: run `install.sh` once, or install xray yourself.
