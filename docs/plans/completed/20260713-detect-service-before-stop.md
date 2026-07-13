# Resolve proxy service before stopping xray (PR #12 review follow-up)

## Overview
- Codex review comment (P2) on PR #12: `detect_active_service()` runs after `xray::stop`, so if service discovery itself fails (`networksetup`/`route`/`ip` broken), stop errors out with xray already dead but the OS proxy still enabled — the last remaining path where a failed `stop` strands networking.
- Fix: call `detect_active_service()` (read-only, no mutation, no password prompt) BEFORE `xray::stop`. Mutation ordering is unchanged: proxy is disabled and AWG stopped only after a successful xray stop. A detection failure now aborts before anything is touched.
- User approved applying the comment ("did u fix that?").

## Development Approach
- testing approach: Regular (code first, then tests) — established preference
- validation gates: `cargo test`, `cargo clippy --all-targets`, `cargo fmt --check`

## Implementation Steps

### Task 1: Reorder detection and update tests

**Files:**
- Modify: `src/main.rs`

- [x] `cmd_stop`: move `let service = plat.detect_active_service()?;` above `xray::stop(config)?`; update the ordering comment to explain detection is read-only and runs first so a detection failure changes nothing
- [x] mock: apply `pid_file_must_be_gone` assertion only to the mutating call (`disable_proxy`), not to read-only `detect_active_service`
- [x] `test_cmd_stop_without_running_xray_never_touches_proxy`: allow one `detect_active_service` call; keep asserting zero `disable_proxy` calls (the regression guarantee is about mutations)
- [x] `test_cmd_stop_propagates_detect_active_service_error`: detection failure now happens before the stop — assert error propagates, `disable_proxy` never called, spawned xray still alive and PID file preserved (then kill/reap the child)
- [x] `test_cmd_stop_disables_proxy_after_successful_xray_stop`: call-sequence assertion `["detect_active_service", "disable_proxy"]` stays valid; keep
- [x] run `cargo test`, `cargo clippy --all-targets`, `cargo fmt --check` — all clean
- [x] verify docs need no change (README stop row and RELEASE_NOTES trade-offs describe mutations only; still accurate)

### Task 2: Ship
- [x] commit on `fix/stop-xray-before-proxy` (plain-language message, no co-author lines), push, confirm CI green
- [x] reply to the Codex inline comment that it's addressed, with the commit hash
- [x] move this plan to `docs/plans/completed/`
