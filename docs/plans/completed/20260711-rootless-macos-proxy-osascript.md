# Rootless macOS Proxy Settings via osascript

## Overview
- `networksetup` write operations require admin privileges on macOS, causing `corvex start` / `corvex stop` to fail without `sudo`
- Add transparent privilege escalation via `osascript -e 'do shell script ... with administrator privileges'` as a fallback when direct `networksetup` calls are denied
- Users see a native macOS Touch ID / password dialog once per session; macOS caches the auth for ~5 minutes so subsequent calls succeed silently
- Read operations (`-getwebproxy`, `-getsocksfirewallproxy`) continue to work directly without any escalation

## Context (from discovery)
- Files involved: `src/platform/macos.rs` (all changes isolated here)
- Current `run_networksetup()` runs `Command::new("networksetup")` directly and propagates the "requires admin privileges" error
- `enable_proxy()` makes 6 `networksetup` calls; macOS auth cache means only the first triggers a dialog
- `disable_proxy()` makes 3 calls; same caching behavior
- Read operations in `proxy_status()` and `detect_active_service()` already work without admin

## Development Approach
- **Testing approach**: Regular (code first, then tests)
- **Execution**: via `/IL-workflow:plan docs/plans/20260711-rootless-macos-proxy-osascript.md` — spawns implementer agents per task, marks `[x]` on completion
- Complete each task fully before moving to the next
- Make small, focused changes
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task
- **CRITICAL: all tests must pass before starting next task**
- **CRITICAL: after each task is completed, run revdiff to show the diff for user review before proceeding**
- **CRITICAL: update this plan file when scope changes during implementation**
- Run tests after each change
- Maintain backward compatibility

## Testing Strategy
- **Unit tests**: test all new pure functions (shell escaping, admin error detection, osascript command building)
- System-level behavior (actual osascript dialog) cannot be unit tested; verified manually
- Existing tests for `parse_proxy_info`, `parse_default_interface`, `parse_service_for_interface` must continue to pass

## Progress Tracking
- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with + prefix
- Document issues/blockers with warning prefix
- Update plan if implementation deviates from original scope

## Implementation Steps

### Task 1: Add shell escaping and error detection helpers

**Files:**
- Modify: `src/platform/macos.rs`

- [x] Add `shell_escape(arg: &str) -> String` that always single-quotes every argument (safest approach — zero overhead from unnecessary quotes). Escape embedded single quotes as `'\''`
- [x] Add `applescript_escape(s: &str) -> String` that escapes `\` as `\\` and `"` as `\"` for the AppleScript string layer (prevents double-quote injection in the `do shell script "..."` string)
- [x] Add `is_admin_required_error(stderr: &str) -> bool` pure function that checks stderr for "requires admin privileges"
- [x] Add `is_user_cancel_error(stderr: &str) -> bool` pure function that checks stderr for "User canceled"
- [x] Add `is_no_gui_error(stderr: &str) -> bool` pure function that checks stderr for "connection" errors indicating no window server
- [x] Add `build_osascript_command(args: &[&str]) -> String` that constructs the AppleScript string: `do shell script "/usr/sbin/networksetup arg1 arg2 ..." with administrator privileges` (uses full path to prevent PATH hijacking in privileged context; applies both shell_escape and applescript_escape)
- [x] Write tests for `shell_escape` (plain arg, arg with spaces, arg with single quotes, arg with double quotes)
- [x] Write tests for `applescript_escape` (plain string, string with double quotes, string with backslashes)
- [x] Write tests for `is_admin_required_error`, `is_user_cancel_error`, `is_no_gui_error` (positive and negative cases each)
- [x] Write tests for `build_osascript_command` (single arg, multiple args, args with spaces and special chars)
- [x] Run tests: `cargo test` - must pass before task 2

### Task 2: Add osascript fallback to `run_networksetup`

**Files:**
- Modify: `src/platform/macos.rs`

- [x] Add `run_networksetup_elevated(args: &[&str]) -> Result<String>` that runs `osascript -e <script>` using the string from `build_osascript_command`
- [x] Use `is_user_cancel_error` to detect cancel and return: "Authorization denied — proxy settings were not changed"
- [x] Use `is_no_gui_error` to detect headless and return: "No GUI session available — run with sudo instead"
- [x] Modify `run_networksetup`: on failure, check `is_admin_required_error` on stderr; if true, `debug!` log the escalation and call `run_networksetup_elevated`; all escalation messages must be `debug!` level only (the 6 calls in `enable_proxy` would produce confusing output at `warn!` or higher)
- [x] Run tests: `cargo test` - must pass before task 3

### Task 3: Verify acceptance criteria

- [x] Verify read operations (`proxy_status`, `detect_active_service`) still work without any escalation
- [x] Verify write operations trigger osascript dialog when run without sudo
- [x] Verify `sudo corvex start` bypasses osascript entirely (direct call succeeds)
- [x] Run full test suite: `cargo test`
- [x] Run linter: `cargo clippy`
- [x] Run formatter: `cargo fmt --check`

### Task 4: [Final] Update documentation

- [x] Update README.md
- [x] Update CLAUDE.md if new patterns discovered
- [x] Move this plan to `docs/plans/completed/`

## Technical Details

**Two-layer escaping:**
The osascript command has two string layers that both need escaping:
1. **Shell layer** (`/bin/sh` inside `do shell script`): all arguments are single-quoted; embedded `'` → `'\''`
2. **AppleScript layer** (the `"..."` string passed to `do shell script`): `\` → `\\`, `"` → `\"`

Example for a service named `Thunderbolt "Pro" Bridge` — this is the Rust string that `build_osascript_command` returns (passed to `osascript -e`):
```
do shell script "/usr/sbin/networksetup -setsocksfirewallproxy 'Thunderbolt \"Pro\" Bridge' '127.0.0.1' '1080'" with administrator privileges
```

The elevated path uses `/usr/sbin/networksetup` (full path) to prevent PATH hijacking in the privileged context. The direct path uses bare `networksetup` (existing behavior).

**Error detection (all pure functions taking `&str`):**
- `is_admin_required_error(stderr)`: stderr contains "requires admin privileges"
- `is_user_cancel_error(stderr)`: stderr contains "User canceled"
- `is_no_gui_error(stderr)`: stderr contains "connection is invalid" (NSAppleScript error when no window server)

**Escalation logging:**
All "admin required, escalating via osascript" messages must be `debug!` level only. Since `enable_proxy` makes 6 calls that each fail-then-retry, `warn!`/`error!` would produce 6 confusing lines of output before the operation succeeds.

**Auth caching:**
- macOS caches authorization for ~5 minutes after successful authentication
- `enable_proxy()` makes 6 calls → user sees 1 dialog, remaining 5 succeed from cache
- `disable_proxy()` makes 3 calls → same behavior

## Post-Completion

**Manual verification:**
- Test `corvex start` without sudo on macOS — should show native auth dialog
- Test clicking "Cancel" on the auth dialog — should show clear error message
- Test over SSH (no GUI) — should suggest using `sudo`
- Test `sudo corvex start` — should work without any dialog
- Test `corvex stop` after start — verify auth cache covers the disable calls
