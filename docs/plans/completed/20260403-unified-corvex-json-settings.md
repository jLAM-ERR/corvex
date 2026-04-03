# Unified corvex.json Settings File

## Overview
- Consolidate all independent config files (free.txt, corp-dns.json, ctraffic.txt, ptraffic.txt) and CLI flags (`--ru`, `--debug`) into a single `corvex.json` JSONC settings file
- Simplify `corvex start` to a single command with no arguments — reads corvex.json and determines the flow automatically
- Add configurable xray log settings and corvex log path with `XDG_STATE_HOME` default
- Remove `--ru`, `--debug` CLI flags and `start <URI>` / `start free` argument variants

## Context (from discovery)
- **Config struct** (`src/config.rs:3-12`): holds paths to 5 separate files + xray binary/log paths
- **CLI** (`src/main.rs:20-65`): `Cli` struct with `--config`, `--ru`, `--debug` flags; `Commands::Start { uri: Option<String> }` with 4 dispatch flows
- **DNS** (`src/dns.rs`): reads/writes corp-dns.json as `BTreeMap<String, String>`, syncs to xray config
- **Traffic** (`src/traffic.rs`): parses ctraffic.txt/ptraffic.txt line-by-line, builds routing rules
- **Subscription** (`src/subscription.rs`): loads URLs from free.txt, downloads/decodes base64 subscriptions
- **Protocol** (`src/protocol.rs:634-715`): `create_config()` hardcodes xray log paths and level
- **Xray** (`src/xray.rs:109-116`): `start()` redirects stdout/stderr to `Config.xray_log` path

## corvex.json Schema

Location: `$XDG_CONFIG_HOME/corvex/corvex.json` (default `~/.config/corvex/corvex.json`)
Generated xray config: `$XDG_CONFIG_HOME/xray/config.json` (unchanged)

```jsonc
{
  // At least one of uri or file-url must be present for `corvex start`
  "uri": "vless://uuid@host:443?...",           // Optional. Proxy URI (vless/vmess/trojan/ss)
  "file-url": ["https://sub1.com/link", ...],   // Optional. Subscription URLs for auto-discovery

  "corporate-dns": {                             // Optional. Domain -> nameserver IP
    "corp.example.com": "10.0.0.1",
    "internal.local": "10.0.0.2"
  },

  "routes": {                                    // Optional
    "direct-ru": true,                           // Optional. Default false
    "proxy-traffic": ["domain:ext.com"],         // Optional. Force through proxy
    "corporate-traffic": ["domain:corp.com"]     // Optional. Bypass proxy (direct)
  },

  "log": {                                       // Optional
    "xray": {                                    // Optional
      "loglevel": "warning",                     // Optional. Default "warning"
      "access": "/var/log/xray/access.log",      // Optional. Default "/var/log/xray/access.log"
      "error": "/var/log/xray/error.log"         // Optional. Default "/var/log/xray/error.log"
    },
    "corvex": {                                  // Optional
      "path": "/path/to/corvex.log",             // Optional. Default $XDG_STATE_HOME/corvex/corvex.log
      "debug": false                             // Optional. Default false. Override: CORVEX_DEBUG=1
    }
  }
}
```

**Key naming**: all kebab-case throughout (`file-url`, `direct-ru`, `proxy-traffic`, `corporate-traffic`, `corporate-dns`).

## Xray log model

There are three distinct log concerns:

1. **xray access/error logs** (in xray JSON config `log` section): configured via `log.xray.*` in corvex.json, written by xray itself. These are the primary operational logs.
2. **xray stdout/stderr redirect** (`xray::start()` redirects to a file): captures console output from the xray binary (startup errors, crashes). This file uses the `log.xray.error` path — so all xray diagnostic output goes to one place.
3. **corvex debug log** (env_logger to stderr): configured via `log.corvex.debug` in corvex.json. Corvex's own step-by-step diagnostic output.

`cmd_logs` tails the xray error log path (from corvex.json or default `/var/log/xray/error.log`).
`Config.xray_log` is updated to derive from `log.xray.error` setting.

## Debug initialization sequence

```
main()
  1. Compute corvex.json path from XDG_CONFIG_HOME (no Config struct needed)
  2. Try to load corvex.json — if missing/invalid, use defaults
  3. Extract debug flag: CORVEX_DEBUG=1 env var overrides corvex.json setting
  4. Call init_logger(debug)
  5. Proceed with Config::new() and command dispatch
```

## Development Approach
- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- Make small, focused changes
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task
- **CRITICAL: all tests must pass before starting next task**
- **CRITICAL: update this plan file when scope changes during implementation**
- Run `cargo test` and `cargo clippy` after each change

## Progress Tracking
- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with + prefix
- Document issues/blockers with ! prefix
- Update plan if implementation deviates from original scope

## Implementation Steps

### Task 1: Define CorvexSettings struct and JSONC parser

**Files:**
- Create: `src/settings.rs`
- Modify: `src/main.rs` (add `mod settings;`)

Uses existing `json_comments` crate (already in Cargo.toml).

- [ ] Create `src/settings.rs` with `CorvexSettings` struct using serde Deserialize:
  ```rust
  pub struct CorvexSettings {
      pub uri: Option<String>,
      pub file_url: Option<Vec<String>>,       // JSON: "file-url"
      pub corporate_dns: Option<BTreeMap<String, String>>,  // JSON: "corporate-dns"
      pub routes: Option<RoutesSettings>,
      pub log: Option<LogSettings>,
  }
  pub struct RoutesSettings {
      pub direct_ru: Option<bool>,             // JSON: "direct-ru"
      pub proxy_traffic: Option<Vec<String>>,  // JSON: "proxy-traffic"
      pub corporate_traffic: Option<Vec<String>>, // JSON: "corporate-traffic"
  }
  pub struct LogSettings {
      pub xray: Option<XrayLogSettings>,
      pub corvex: Option<CorvexLogSettings>,
  }
  pub struct XrayLogSettings {
      pub loglevel: Option<String>,
      pub access: Option<String>,
      pub error: Option<String>,
  }
  pub struct CorvexLogSettings {
      pub path: Option<String>,
      pub debug: Option<bool>,
  }
  ```
- [ ] Add `load(path: &Path) -> Result<CorvexSettings>` that strips JSONC comments via `json_comments::StripComments` then deserializes
- [ ] Add `xdg_settings_path()` helper that computes corvex.json path from `$XDG_CONFIG_HOME` without needing Config struct
- [ ] No validation in `load()` — validation of uri/file_url deferred to `cmd_start()` where it is needed
- [ ] Add `mod settings;` to `src/main.rs`
- [ ] Write tests: load valid JSONC with all fields populated
- [ ] Write tests: load minimal config (uri only, file-url only, empty config)
- [ ] Write tests: JSONC comments are stripped correctly
- [ ] Write tests: `xdg_settings_path()` respects `$XDG_CONFIG_HOME` and falls back correctly
- [ ] Run tests - must pass before next task

### Task 2: Refactor DNS module to accept inline data

**Files:**
- Modify: `src/dns.rs`

- [ ] Change `sync_to_config` signature to `sync_to_config(xray_config_path: &Path, mappings: &BTreeMap<String, String>) -> Result<usize>` — accepts mappings directly instead of reading from corp-dns.json
- [ ] Remove `read_mappings()` and `write_mappings()` functions (file I/O for corp-dns.json)
- [ ] Change `init()` signature to `init() -> Result<BTreeMap<String, String>>` — no `&Config` parameter, returns discovered mappings without writing to file
- [ ] Keep `parse_scutil_dns()` unchanged (pure parsing function)
- [ ] Update `sync_to_config` tests to pass mappings and xray config path directly
- [ ] Remove tests that relied on corp-dns.json file I/O
- [ ] Run tests - must pass before next task

### Task 3: Remove file-based traffic and subscription loading

**Files:**
- Modify: `src/traffic.rs`
- Modify: `src/subscription.rs`

- [ ] Remove `parse_traffic_file()` function from `traffic.rs` (file I/O for ctraffic.txt/ptraffic.txt)
- [ ] Keep `normalize_entry()` and `build_routing_rules()` unchanged — they already work on `&[String]`
- [ ] Remove `load_free_urls()` function from `subscription.rs` (file I/O for free.txt)
- [ ] Keep `download_subscription()`, `decode_subscription()`, `filter_supported()` unchanged
- [ ] Remove tests for `parse_traffic_file()` and `load_free_urls()`
- [ ] Run tests - must pass before next task

### Task 4: Update Config struct — add new fields, remove old ones

**Files:**
- Modify: `src/config.rs`

After Tasks 2-3, no module references `config.corp_dns`, `config.free_urls`, `config.ctraffic`, or `config.ptraffic`, so they can be safely removed.

- [ ] Remove fields: `corp_dns`, `free_urls`, `ctraffic`, `ptraffic` from Config struct
- [ ] Add field: `corvex_settings: PathBuf` (path to corvex.json)
- [ ] Add field: `corvex_log: PathBuf` (default `$XDG_STATE_HOME/corvex/corvex.log`)
- [ ] Add `xdg_state_dir()` / `xdg_state_dir_inner()` helper (checks `$XDG_STATE_HOME`, falls back to `~/.local/state`)
- [ ] Update `Config::new()` to set `corvex_settings` path as `{xdg_config}/corvex/corvex.json`
- [ ] Update `Config::new()` to set `corvex_log` path as `{xdg_state}/corvex/corvex.log`
- [ ] Update existing tests for new Config shape
- [ ] Write tests: `xdg_state_dir()` respects `$XDG_STATE_HOME` and falls back correctly
- [ ] Run tests - must pass before next task

### Task 5: Wire xray log settings into protocol::create_config

**Files:**
- Modify: `src/protocol.rs`

- [ ] Add struct or parameters for xray log settings with defaults: loglevel="warning", access="/var/log/xray/access.log", error="/var/log/xray/error.log"
- [ ] Change `create_config` signature to accept xray log settings
- [ ] Replace hardcoded log section with values from parameter (using defaults for None)
- [ ] Update all callers in `src/main.rs` to pass log settings (use defaults for now, will wire to corvex.json in Task 7)
- [ ] Update tests for `create_config` to pass log settings
- [ ] Write test: custom log settings are reflected in generated config
- [ ] Write test: default log settings used when None
- [ ] Run tests - must pass before next task

### Task 6: Simplify CLI struct — remove flags and start args

**Files:**
- Modify: `src/main.rs`

- [ ] Remove `--ru` flag from Cli struct
- [ ] Remove `--debug` flag from Cli struct
- [ ] Repurpose `--config` to `--settings` flag pointing to corvex.json path (override for corvex.json location)
- [ ] Change `Commands::Start { uri: Option<String> }` to `Start` (no args)
- [ ] Update `init_logger()`: compute corvex.json path from XDG (or `--settings`), try to load settings, extract debug flag. Support `CORVEX_DEBUG=1` env var override. If file missing/invalid, default to non-debug.
- [ ] Update the `run()` function to pass settings path through, remove `ru` and `debug` from dispatch
- [ ] Update tests for CLI parsing
- [ ] Write test: `corvex start` parses with no arguments
- [ ] Write test: `--settings` flag overrides default corvex.json path
- [ ] Run tests - must pass before next task

### Task 7: Rewrite cmd_start as single flow

**Files:**
- Modify: `src/main.rs`

- [ ] Remove `start_with_uri()`, `start_from_free()`, `start_auto_discover()`, `fetch_subscription_uris()` functions
- [ ] Remove `update_routing_rules()` helper
- [ ] Rewrite `cmd_start(config: &Config)` as single flow:
  1. Load corvex.json via `settings::load(&config.corvex_settings)`
  2. Validate: at least one of `uri` or `file_url` must be present, bail with clear message if not
  3. If `uri` is set: parse it with `protocol::parse_uri()`
  4. If `uri` is None but `file_url` is set: download subscriptions, find alive server via `health::find_alive_server()`
  5. Extract routing settings: `direct_ru`, `proxy_traffic`, `corporate_traffic` from `routes` (defaulting to empty/false)
  6. Build routing rules via `traffic::build_routing_rules()`
  7. If xray config exists: `protocol::apply_to_config()` + write routing rules
  8. If xray config doesn't exist: `protocol::create_config()` with xray log settings, write config.json
  9. Handle corporate DNS: merge corvex.json `corporate_dns` with `dns::init()` discovery, sync via `dns::sync_to_config()`
- [ ] Update `Config.xray_log` to derive from corvex.json `log.xray.error` path (so `cmd_logs` and `xray::start()` use the configured path)
- [ ] Add deprecation warning: if old config files exist (free.txt, corp-dns.json, ctraffic.txt, ptraffic.txt in `$XDG_CONFIG_HOME/xray/`), print a warning suggesting migration to corvex.json
- [ ] Write test: uri-only flow produces correct config
- [ ] Write test: routing rules built from settings match expected output
- [ ] Write test: validation fails when neither uri nor file-url present
- [ ] Run tests - must pass before next task

### Task 8: Update remaining commands (status, logs, stop, reload)

**Files:**
- Modify: `src/main.rs`
- Modify: `src/xray.rs`

- [ ] Update `cmd_logs` to tail the xray error log path (derived from corvex.json or default)
- [ ] Update `xray::start()` to redirect stdout/stderr to the error log path from `Config.xray_log`
- [ ] Update `cmd_status` to show corvex.json path and configured log paths
- [ ] Ensure `cmd_stop`, `cmd_reload` work with updated Config struct (they use `xray_config`, `xray_pid_file` which are unchanged)
- [ ] Write test: verify stop/reload still function with new Config
- [ ] Run tests - must pass before next task

### Task 9: Verify acceptance criteria

- [ ] Verify all requirements from Overview are implemented
- [ ] Verify `corvex start` works with uri-only corvex.json
- [ ] Verify `corvex start` works with file-url-only corvex.json (unit test level)
- [ ] Verify old CLI flags (`--ru`, `--debug`, `start <URI>`, `start free`) are removed
- [ ] Verify old file references (free.txt, corp-dns.json, ctraffic.txt, ptraffic.txt) are removed from code
- [ ] Run full test suite: `cargo test`
- [ ] Run linter: `cargo clippy`
- [ ] Run formatter: `cargo fmt --check`

### Task 10: Update documentation

**Files:**
- Modify: `CLAUDE.md`

- [ ] Update Architecture section: remove references to corp-dns.json, ctraffic.txt, ptraffic.txt, free.txt
- [ ] Add `settings.rs` to architecture diagram with description
- [ ] Update Key paths section: add corvex.json path, corvex log path, remove old file paths
- [ ] Update Usage section: remove `start <URI>`, `start free`, `--ru`, `--debug` examples
- [ ] Add corvex.json example to Usage section
- [ ] Update Dependencies section if any added/removed
- [ ] Move this plan to `docs/plans/completed/`

## Technical Details

### Config file location hierarchy
- corvex.json: `$XDG_CONFIG_HOME/corvex/corvex.json` (default `~/.config/corvex/corvex.json`), overridable via `--settings`
- xray config.json: `$XDG_CONFIG_HOME/xray/config.json` (unchanged)
- corvex debug log: stderr via env_logger (controlled by `log.corvex.debug` or `CORVEX_DEBUG=1`)
- xray error log: configurable via corvex.json `log.xray.error`, default `/var/log/xray/error.log`
- xray access log: configurable via corvex.json `log.xray.access`, default `/var/log/xray/access.log`
- xray PID: `$XDG_CONFIG_HOME/xray/xray.pid` (unchanged)

### Start flow (simplified)
```
corvex start
    |
    v
Load corvex.json (JSONC parse)
    |
    v
Validate: uri or file-url present
    |
    v
uri present? ----yes----> parse_uri() -> ProxyParams
    |                          |
    no                         |
    |                          |
    v                          |
file-url present? -yes--> download + decode + filter + find_alive_server()
    |                          |
    no                         |
    |                          v
    v                    ProxyParams ready
  ERROR                        |
                               v
                    Build routing rules from routes.*
                               |
                               v
                    config.json exists?
                    /                    \
                  yes                     no
                  /                        \
          apply_to_config()          create_config() with log settings
          update routing rules       write config.json
                  \                        /
                   \                      /
                    v                    v
              Sync corporate DNS (inline + scutil)
                         |
                         v
                   main_algorithm()
                   (ensure xray, port, start, proxy)
```

### Removed items
- CLI: `--ru`, `--debug`, `--config` (replaced by `--settings`), `start <URI>`, `start free`
- Files: free.txt, corp-dns.json, ctraffic.txt, ptraffic.txt (no longer read/written)
- Functions: `load_free_urls()`, `read_mappings()`, `write_mappings()`, `parse_traffic_file()`, `start_with_uri()`, `start_from_free()`, `start_auto_discover()`, `fetch_subscription_uris()`
- Config fields: `corp_dns`, `free_urls`, `ctraffic`, `ptraffic`

### Kept unchanged
- `protocol.rs`: URI parsing, config building (except log settings parameter added)
- `health.rs`: TCP/tunnel checks, find_alive_server
- `xray.rs`: process lifecycle (start/stop/reload — xray_log path derivation updated)
- `proxy.rs`: macOS proxy management
- `network.rs`: active service detection
- `port.rs`: dynamic port allocation

## Post-Completion

**Manual verification:**
- Test `corvex start` with corvex.json containing only `uri`
- Test `corvex start` with corvex.json containing only `file-url` (requires live subscription)
- Test corporate DNS auto-discovery on macOS with split-DNS configured
- Verify xray log paths are respected in generated config
- Verify `corvex logs` tails the correct log file
- Verify `CORVEX_DEBUG=1 corvex start` enables debug output
- Verify deprecation warning appears when old config files (free.txt etc.) exist
