# Corvex v0.2.0 Release Notes

## Highlights

Major redesign: all configuration consolidated into a single `corvex.json` (JSONC) file, multi-protocol support added, and the CLI simplified to a clean `start`/`stop`/`reload`/`status`/`logs` interface.

## What's New

### Unified corvex.json Configuration
All settings are now in one JSONC file at `~/.config/corvex/corvex.json`. The separate text files (`free.txt`, `ctraffic.txt`, `ptraffic.txt`) and `corp-dns.json` are replaced by fields in corvex.json. JSONC format allows comments for documenting your config.

### Multi-Protocol Support
In addition to VLESS, corvex now supports:
- **VMess** — `vmess://base64json`
- **Trojan** — `trojan://password@host:port?params#name`
- **Shadowsocks** — `ss://base64(method:password)@host:port#name` (SIP002 and legacy)

Subscription auto-discovery filters and health-checks all supported protocols, not just VLESS gRPC.

### Subscription Auto-Discovery with Health Checks
Configure `"file-url"` in corvex.json with subscription URLs. corvex downloads, base64-decodes, filters for supported protocols, and picks the best server via a two-stage health check:
1. **TCP reachability** — fast socket connect to filter unreachable servers
2. **Tunnel latency** — temporary xray instance per candidate measures actual round-trip time

### Dynamic Port Allocation
Each `corvex start` picks a random free port in the 20000-60000 range. No more fixed ports or conflicts on restart.

### Traffic-Based Routing via corvex.json
Define per-domain routing rules directly in corvex.json:
- `"corporate-traffic"` — domains that bypass the proxy (direct)
- `"proxy-traffic"` — domains forced through the proxy
- `"direct-ru"` — route `.ru` TLD directly

### Corporate DNS
Configure `"corporate-dns"` in corvex.json for domain-to-nameserver mappings. These are merged with auto-discovered entries from macOS `scutil --dns`.

### Debug Logging
Enable via `"log": {"corvex": {"debug": true}}` in corvex.json or `CORVEX_DEBUG=1` environment variable. Xray log paths and levels are also configurable in corvex.json.

### Custom Settings Path
Use `corvex --settings /path/to/corvex.json start` to override the default settings file location.

### Status Command Shows Config Paths
`corvex status` now displays the paths for corvex.json, xray config, and xray log file.

### XDG Base Directory Support
Config and state files follow XDG conventions:
- Settings: `$XDG_CONFIG_HOME/corvex/corvex.json`
- Xray config: `$XDG_CONFIG_HOME/xray/config.json`
- Corvex log: `$XDG_STATE_HOME/corvex/corvex.log`

## Commands

```
corvex start                                    # Load corvex.json, resolve server, start
corvex stop                                     # Disable system proxy + stop xray
corvex reload                                   # Validate config and send SIGHUP
corvex status                                   # Show process, ports, proxy settings, config paths
corvex logs                                     # Show last 20 log lines
corvex logs -f                                  # Follow log output
corvex --settings /path/to/corvex.json start    # Use custom settings file
CORVEX_DEBUG=1 corvex start                     # Enable debug logging
```

## Breaking Changes

- **CLI simplified**: removed positional URI argument, `start free` subcommand, `--ru` and `--config` flags
- **Config consolidated**: `free.txt`, `ctraffic.txt`, `ptraffic.txt`, and `corp-dns.json` replaced by `corvex.json`
- **Config location**: corvex settings moved from `~/.config/xray/` to `~/.config/corvex/corvex.json`
- **Port allocation**: no longer fixed, allocated dynamically each start

## Migration from v0.1.0

1. Create `~/.config/corvex/corvex.json` (see `examples/corvex.json`)
2. Move subscription URLs from `free.txt` into `"file-url"` array
3. Move domain lists from `ctraffic.txt`/`ptraffic.txt` into `"routes"`
4. Move DNS mappings from `corp-dns.json` into `"corporate-dns"`
5. Replace `--ru` flag usage with `"routes": {"direct-ru": true}`
6. Remove old files from `~/.config/xray/` (corvex warns if they still exist)
