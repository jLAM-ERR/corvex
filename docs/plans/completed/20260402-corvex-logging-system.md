# Corvex Logging System

## Overview
- Add structured logging to corvex using `log` + `env_logger` crates
- Add global `--debug` / `-d` flag that enables debug-level output to stderr
- Instrument all currently-silent operations (health checks, DNS discovery, subscriptions, port allocation, proxy setup) with appropriate log levels
- Without `--debug`, corvex behaves exactly as today (only user-facing println! output)
- Format: custom timestamped — `2026-04-02 14:30:01 [DEBUG] message`

## Context (from discovery)
- **No logging framework** currently — raw `println!`/`eprintln!` with `colored` crate
- **Silent operations** that need visibility: health checks (health.rs), DNS init (dns.rs), subscription download/decode (subscription.rs), port allocation (port.rs), server selection (main.rs), proxy enable/disable (proxy.rs), xray lifecycle (xray.rs), network detection (network.rs), config path resolution (config.rs), traffic file loading (traffic.rs)
- **CLI structure**: clap derive API with global flags `--config` and `--ru` (main.rs:18-31)
- **Error handling**: `anyhow` + `thiserror` — errors propagate up, final handler at main.rs:430

## Development Approach
- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- Make small, focused changes
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task
- **CRITICAL: all tests must pass before starting next task**
- **CRITICAL: update this plan file when scope changes during implementation**
- Run tests after each change
- Maintain backward compatibility — without `--debug`, output is identical to current behavior

## Testing Strategy
- **Unit tests**: test env_logger initialization with debug flag, verify log level mapping
- **Integration**: `cargo test` must pass after each task — existing tests must not break
- **No e2e tests** in this project

## Progress Tracking
- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with ➕ prefix
- Document issues/blockers with ⚠️ prefix
- Update plan if implementation deviates from original scope

## Implementation Steps

### Task 1: Add dependencies and --debug flag

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/main.rs`

- [x] Add `log = "0.4"` and `env_logger = "0.11"` to `[dependencies]` in Cargo.toml
- [x] Add `--debug` / `-d` global flag to `Cli` struct: `#[arg(short = 'd', long, global = true)] debug: bool`
- [x] Initialize env_logger in `run()` immediately after CLI parsing but before command dispatch: when `--debug` is set, configure env_logger with `debug` filter level, timestamped format, writing to stderr; when not set, configure with `warn` filter (silent — only errors/warnings reach stderr). Use `try_init()` instead of `.init()` to avoid panics in tests.
- [x] Verify that `RUST_LOG` env var overrides the flag (inherent from `Builder::from_env()`)
- [x] Verify `cargo build` succeeds
- [x] Verify `cargo test` passes — no existing tests broken
- [x] Write test that verifies debug flag is parsed by clap (unit test with `try_parse_from`)

### Task 2: Add logging to main.rs command flows

**Files:**
- Modify: `src/main.rs`

- [x] Add `use log::{debug, info};` import
- [x] `cmd_start`: log which flow is taken (URI, free, auto-discover, existing config)
- [x] `start_with_uri`: log URI parsing, traffic file loading, config creation vs update, DNS init
- [x] `start_from_free`: log subscription URL count, URI download results, server count, alive server found
- [x] `start_auto_discover`: log discovery start, subscription results, alive server
- [x] `main_algorithm`: log xray install check, stopping old instance, port allocation, config port update, xray start, proxy enable
- [x] `cmd_stop`: log proxy disable + xray stop steps
- [x] `cmd_reload`: log config validation + SIGHUP
- [x] `cmd_status`: log command entry
- [x] `cmd_logs`: log command entry
- [x] Write test verifying log macros don't panic (compile check — log macros with no subscriber are no-ops)
- [x] Run `cargo test` — all tests pass

### Task 3: Add logging to health.rs

**Files:**
- Modify: `src/health.rs`

- [x] Add `use log::debug;` import
- [x] `check_tcp`: log host:port being checked, success/failure
- [x] `check_tunnel`: log temp config path, xray spawn, readiness polling, HTTP check result with latency
- [x] `find_alive_server`: log total URI count, each server being tried (TCP result, tunnel result with latency), final selected server or failure
- [x] Write tests verifying log statements don't interfere with existing test logic
- [x] Run `cargo test` — all tests pass

### Task 4: Add logging to subscription.rs

**Files:**
- Modify: `src/subscription.rs`

- [x] Add `use log::debug;` import
- [x] `load_free_urls`: log file path and URL count loaded
- [x] `download_subscription`: log URL being fetched, body size on success
- [x] `decode_subscription`: log decoded URI count
- [x] `filter_supported`: log input count vs filtered count
- [x] Write tests verifying log statements don't affect existing test results
- [x] Run `cargo test` — all tests pass

### Task 5: Add logging to dns.rs, xray.rs, proxy.rs, network.rs, port.rs, config.rs, traffic.rs

**Files:**
- Modify: `src/dns.rs`
- Modify: `src/xray.rs`
- Modify: `src/proxy.rs`
- Modify: `src/network.rs`
- Modify: `src/port.rs`
- Modify: `src/config.rs`
- Modify: `src/traffic.rs`

- [x] **config.rs**: log resolved config directory path in `Config::new()`
- [x] **dns.rs**: log `init()` scutil output parsing, discovered mapping count, `sync_to_config()` merge details
- [x] **xray.rs**: log `ensure_installed()` which/brew check, `is_running()` PID read + status, `start()` spawn + PID write + verification, `stop()` SIGTERM/SIGKILL steps, `reload()` validation + SIGHUP
- [x] Run `cargo test` — verify dns.rs, xray.rs, config.rs tests pass
- [x] **proxy.rs**: log `enable()` each networksetup call (service, host, port), `disable()` each call
- [x] **network.rs**: log `detect_active_service()` interface found, service name resolved
- [x] **port.rs**: log `find_free_port()` selected port (and retry count if > 1)
- [x] **traffic.rs**: log `parse_traffic_file()` file path and entry count, `build_routing_rules()` rule count
- [x] Run `cargo test` — verify all tests pass

### Task 6: Verify acceptance criteria

- [x] Verify `corvex start` without `--debug` produces identical output to before (no extra stderr)
- [x] Verify `corvex -d start` shows timestamped debug output on stderr
- [x] Verify `RUST_LOG=debug corvex start` also enables debug output
- [x] Run full test suite: `cargo test`
- [x] Run `cargo clippy` — no warnings
- [x] Run `cargo fmt --check` — no formatting issues

### Task 7: [Final] Update documentation

- [ ] Update CLAUDE.md with `--debug` flag in usage section
- [ ] Update CLAUDE.md dependencies list to include `log` and `env_logger`
- [ ] Move this plan to `docs/plans/completed/`

## Technical Details

### Log level mapping
| Flag | Level filter | What's visible |
|------|-------------|----------------|
| (none) | `warn` | Warnings + errors only (info/debug suppressed — current behavior) |
| `--debug` / `-d` | `debug` | Debug + info + warn + error |
| `RUST_LOG=trace` | `trace` | Everything (for future use) |

### env_logger format (custom with brackets)
Uses a custom format closure for `[LEVEL]` bracketed output:
```
2026-04-02 14:30:01 [DEBUG] checking subscription: https://sub.example.com/free
2026-04-02 14:30:02 [DEBUG] downloaded 3 URIs from subscription
2026-04-02 14:30:02 [DEBUG] testing server 1.2.3.4:443 (TCP)...
2026-04-02 14:30:03 [DEBUG] server 1.2.3.4:443 alive (latency: 120ms)
2026-04-02 14:30:03 [INFO]  allocated port 34521
```

### env_logger initialization pattern
```rust
use env_logger::Env;
use std::io::Write;

let default_level = if cli.debug { "debug" } else { "warn" };
let _ = env_logger::Builder::from_env(Env::default().default_filter_or(default_level))
    .format(|buf, record| {
        let ts = buf.timestamp_seconds();
        writeln!(buf, "{} [{}] {}", ts, record.level(), record.args())
    })
    .try_init();
```

### Log statement conventions
- `debug!()` — step-by-step operation details (majority of new logs)
- `info!()` — key milestones (port allocated, server selected, config created)
- `warn!()` — recoverable issues (subscription download failed, DNS init skipped)
- `error!()` — not used directly (errors propagate via `anyhow::Result`)

## Post-Completion

**Manual verification:**
- Run `corvex -d start` and verify debug output shows full operation trace
- Run `corvex start` and verify output is identical to pre-change behavior
- Run `corvex -d status` and verify debug output for status checks
