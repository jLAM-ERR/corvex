# Stop xray before touching system proxy

## Overview
- `corvex stop` currently disables the system proxy BEFORE trying to stop the xray process (`src/main.rs:648-662`). When stopping fails — e.g., xray was started under root and `corvex stop` runs as a regular user (`EPERM` → "xray (PID: N) is running as another user - try again with sudo") — the user has already typed the admin password 3 times and the proxy is already off, while xray keeps running. Inconsistent state.
- Desired behavior (user decision, strict):
  1. Try to stop xray first. Only if that succeeds → disable the system proxy.
  2. If stopping xray fails for ANY reason (permission error, not running, etc.) → do NOT touch the proxy (and do not touch the AWG tunnel), just show the error.
- Start side already conforms: `main_algorithm` (`src/main.rs:587-615`) enables the proxy only after `xray::start` succeeds, in both xray and AWG engine modes.

## Context (from discovery)
- Files involved: `src/main.rs` (`cmd_stop`, `main_algorithm`), `src/xray.rs` (`stop`, `XrayError::NotPermitted` at line 427-ish, `is_running`), `src/platform/mod.rs` (`Platform` trait), `src/platform/macos.rs` (`disable_proxy` = 3 `networksetup` calls, each prompting for admin password).
- Patterns found: `cmd_stop` takes `&impl Platform` — a `cfg(test)` mock implementing the 5-method `Platform` trait can record whether/when `disable_proxy` is called. `Config` (`src/config.rs:30`) has public fields — trivially constructible in tests with temp paths.
- `xray::is_running` reads the PID file, checks liveness via `kill(pid, 0)` (EPERM counts as alive), and rejects PID reuse via `ps -p <pid> -o comm=` matched against `config.xray_bin` — so a success-path test can spawn `/bin/sleep`, write its PID to a temp PID file, and set `xray_bin = "sleep"`.
- Dependencies: none new.

## Development Approach
- **testing approach**: Regular (code first, then tests) — user preference
- complete each task fully before moving to the next
- make small, focused changes
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task
  - tests are not optional - they are a required part of the checklist
  - tests cover both success and error scenarios
- **CRITICAL: all tests must pass before starting next task** - no exceptions
- **CRITICAL: update this plan file when scope changes during implementation**
- run tests after each change
- maintain backward compatibility of CLI surface (same commands, same error messages)

## Testing Strategy
- **unit tests**: required for every task. New `RecordingPlatform` mock in `src/main.rs` test module records `Platform` method calls; `cmd_stop` tested against it with temp-dir `Config`s.
- **e2e tests**: none in this project (CLI + system calls); manual verification listed in Post-Completion.

## Progress Tracking
- mark completed items with `[x]` immediately when done
- add newly discovered tasks with ➕ prefix
- document issues/blockers with ⚠️ prefix
- update plan if implementation deviates from original scope

## Solution Overview
- Reorder `cmd_stop` to a strict sequential flow with early return:
  1. `xray::stop(config)?` — first action; any error (NotPermitted, NotRunning, …) returns immediately. No proxy calls, no password prompts, no AWG changes.
  2. `plat.detect_active_service()?` then `plat.disable_proxy(&service)?` — only after xray is confirmed stopped.
  3. `stop_awg_if_running(config)` — best-effort AWG cleanup, only reached after successful xray stop.
  4. Print "corvex stopped!" only when everything succeeded.
- No change to the start path: proxy enabling already happens last. Verified during discovery; a checkbox confirms it stays untouched.

## Technical Details
- Current code collects both results and reports errors after both side effects ran:
  ```rust
  let proxy_result = plat.disable_proxy(&service);   // side effect happens first
  let xray_result = xray::stop(config);
  proxy_result?;
  xray_result?;
  ```
  New code is a plain `?`-chain in the user-approved order (stop → detect service → disable proxy → AWG).
- Behavior change (intentional, user-approved): when xray is NOT running but the proxy is still on (e.g., xray crashed), `corvex stop` now errors with "xray is not running" and leaves the proxy enabled. The same applies to a still-running AWG tunnel — `stop_awg_if_running` is only reached after a successful xray stop, so on failure the AWG tunnel is also left untouched. Cleanup in that state = `sudo corvex stop` of the root instance, or `corvex start` + `corvex stop`.
- `detect_active_service` is read-only (no password prompt, no mutation); calling it after `xray::stop` keeps "xray first" semantics literal.
- Out of scope (explicitly): rollback of a partially applied `enable_proxy` on the start side (e.g., user cancels one of the 6 `networksetup` prompts). Existing behavior kept: error is reported, xray stays running.

## What Goes Where
- **Implementation Steps** (`[ ]` checkboxes): code changes and tests in this repo
- **Post-Completion** (no checkboxes): manual verification on a machine with a root-owned xray

## Implementation Steps

### Task 1: Create working branch

- [x] create a topic branch off `main` before any code change: `git checkout -b fix/stop-xray-before-proxy` (already done — worktree branch verified via `git branch --show-current`)
- [x] commit the plan file on this branch ("docs: add stop-before-proxy implementation plan") (already done — commit fff6052 verified via `git log --oneline`)

### Task 2: Reorder cmd_stop so proxy is only touched after xray stops

**Files:**
- Modify: `src/main.rs`

- [x] rewrite `cmd_stop` (`src/main.rs:648`): call `xray::stop(config)?` first; on error return immediately without calling `detect_active_service`/`disable_proxy`/`stop_awg_if_running`
- [x] on successful xray stop: `detect_active_service()?` → `disable_proxy(&service)?` → `stop_awg_if_running(config)` → print success message
- [x] fix the now-stale `debug!("disabling system proxy")` at the top of `cmd_stop` (`src/main.rs:649`): first log becomes `debug!("stopping xray")`, keep "disabling system proxy" right before `disable_proxy`
- [x] verify `main_algorithm` start path needs no change (proxy enabled only after `xray::start`; failed stop of an existing instance bails before any proxy call; `Commands::Restart` routes to `cmd_start`, not `cmd_stop`)
- [x] add `cfg(test)` `RecordingPlatform` mock in `src/main.rs` implementing `Platform`, recording method calls in `RefCell<Vec<String>>`, with configurable `disable_proxy` failure
- [x] write test: `cmd_stop` with no PID file (temp-dir `Config`) → returns "not running" error AND mock recorded zero `disable_proxy` calls (regression test for this bug; platform-independent)
- [x] write test `#[cfg(unix)]`: spawn `/bin/sleep` child, write its PID to temp PID file, `xray_bin = "sleep"` → `cmd_stop` succeeds and mock recorded `disable_proxy` exactly once; reap the child with `child.wait()` after `cmd_stop` returns (zombie answers `kill(pid, 0)` as alive — pattern from `test_process_dead_after_exit`, `src/xray.rs:561-573`) before any liveness assertion
- [x] write test `#[cfg(unix)]`: same spawned-child setup, mock `disable_proxy` returns Err → `cmd_stop` propagates the error (needs a real successful stop, hence unix-only)
- [x] run tests - must pass before next task (`cargo test` — 253 passed, 0 failed; clippy + fmt clean)

### Task 3: Verify acceptance criteria
- [x] verify: failed stop (any `xray::stop` error) performs no `networksetup` side effects — confirmed by `test_cmd_stop_without_running_xray_never_touches_proxy` (0 `disable_proxy`, 0 `detect_active_service` calls after error)
- [x] verify: successful stop disables proxy and stops AWG, prints "corvex stopped!" — `cmd_stop` order is stop → detect service → disable proxy → AWG → success message; `test_cmd_stop_disables_proxy_after_successful_xray_stop` confirms `disable_proxy` called exactly once and PID file removed
- [x] verify: start path unchanged (proxy enabled only after successful start) — commit 018b562 touched only `cmd_stop` and the test module; `main_algorithm` still calls `enable_proxy` only after `xray::start` succeeds
- [x] run full test suite: `cargo test` — 253 passed, 0 failed
- [x] run `cargo clippy` and `cargo fmt --check` — clean

### Task 4: [Final] Update documentation
- [x] update `CLAUDE.md` usage line for `stop` ("Stop xray first; system proxy is disabled only if the stop succeeded")
- [x] update `README.md` if it describes stop ordering (quick-start line + `stop` row in the Commands table)
- [x] add entry to `RELEASE_NOTES.md` under the next (unreleased) version describing the behavior change
- [x] move this plan to `docs/plans/completed/` (skipped - the harness moves the plan after all phases finish; moving it mid-run breaks later phases)

## Post-Completion
*Items requiring manual intervention - informational only*

**Manual verification:**
- On macOS with xray started via `sudo corvex start`: run `corvex stop` as regular user → expect the "running as another user - try again with sudo" error with NO admin-password prompts and proxy still enabled (`corvex status` shows proxy on).
- `sudo corvex stop` → xray stops, proxy disabled.
- With no xray running and proxy manually enabled: `corvex stop` → "xray is not running" error, proxy stays on (accepted trade-off of the strict rule). Same for an orphaned AWG tunnel: it is not stopped when `xray::stop` fails.
