# Collapse macOS admin prompts into a single password dialog

## Overview

Running `corvex start` as a normal user on macOS pops the "corvex wants to make changes" password dialog **six times in a row**. `corvex stop` pops it three times. Every dialog asks for the same password to grant the same privilege.

**Cause.** `MacOsPlatform::enable_proxy` (`src/platform/macos.rs:108-122`) issues six separate `networksetup` invocations. Each goes through `run_networksetup`, each independently fails with `** Error: Command requires admin privileges.`, and each independently calls `run_networksetup_elevated`, which spawns its own `osascript -e "do shell script ... with administrator privileges"`. AppleScript caches the entered password only for the remainder of *the same script execution*, so six separate `osascript` processes mean six separate authorization contexts and six dialogs. `disable_proxy` (`src/platform/macos.rs:124-130`) has the identical defect with three calls.

**Fix.** Attempt the commands unelevated as today; the moment one reports "requires admin privileges", re-run the **whole sequence** inside a single `osascript` call, chained with `&&`. macOS asks once. Six `networksetup` setters all require the exact same privilege, so re-running the ones that already ran is not a concern — in practice the first command is the one that fails and nothing has been applied yet, and the setters are idempotent regardless.

**Benefits.**
- `corvex start` as a normal user: 6 dialogs → 1.
- `corvex stop` as a normal user: 3 dialogs → 1.
- Running as root (`sudo corvex …`) still prompts zero times — the unelevated attempt keeps succeeding, so escalation never triggers.

## Context (from discovery)

- **files/components involved**
  - `src/platform/macos.rs` — the whole change lives here: `run_networksetup`, `run_networksetup_elevated`, `build_osascript_command`, `enable_proxy`, `disable_proxy`
  - `src/platform/mod.rs` — `Platform` trait; **unchanged**, the trait signatures stay the same
  - `src/main.rs` — call sites `cmd_start` → `enable_proxy` (line 807), `cmd_stop` → `disable_proxy` (line 900); **unchanged**
- **related patterns found**
  - project principle "all parsing functions take `&str` — unit testable without system calls"; `macos.rs` already follows this with pure builders (`build_osascript_command`, `shell_escape`, `applescript_escape`, `parse_proxy_info`) tested inline in `mod tests`
  - `run_networksetup` already handles macOS's inconsistent error reporting: `** Error` can appear on stdout with a zero exit code, so `join_output` merges both streams before classification
  - error classification helpers already exist: `is_admin_required_error`, `is_user_cancel_error`, `is_no_gui_error`
- **dependencies identified**
  - no new crates; `std::process::Command`, `anyhow`, `log::debug` only
  - `proxy_status` uses the read-only getters (`-getwebproxy` etc.) which do not require admin on macOS — it keeps using the existing single-command path

## Development Approach

- **testing approach**: Regular (code first, then tests)
- complete each task fully before moving to the next
- make small, focused changes
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task
  - tests are not optional - they are a required part of the checklist
  - write unit tests for new functions
  - write unit tests for modified functions
  - add new test cases for new code paths
  - update existing test cases if behavior changes
  - tests cover both success and error scenarios
- **CRITICAL: all tests must pass before starting next task** - no exceptions
- **CRITICAL: update this plan file when scope changes during implementation**
- run `cargo test` after each change
- maintain backward compatibility: the `Platform` trait signatures do not change, and the generated script for a **single** command must stay byte-identical to today's output

## Testing Strategy

- **unit tests**: required for every task, added to the existing `mod tests` in `src/platform/macos.rs`
- **no e2e tests**: this project has no UI and no e2e harness; `cargo test` is the gate
- **the load-bearing assertion** is that a batched script contains `with administrator privileges` **exactly once**. That single test is what fails if anyone ever reverts to per-command escalation, so it must be written as a counting assertion, not a `contains` check
- **escaping must be re-verified per command inside a batch**, not just for the first one — a service name like `Thunderbolt "Pro" Bridge` has to survive both shell and AppleScript quoting in every position of the chain
- **ordering matters**: the proxy host/port must be set before the corresponding state is switched on. Tests assert exact command order, not set membership
- **cannot be unit tested** (needs a real macOS GUI session): that the dialog actually appears once. Covered under Post-Completion manual verification

## Progress Tracking

- mark completed items with `[x]` immediately when done
- add newly discovered tasks with ➕ prefix
- document issues/blockers with ⚠️ prefix
- update plan if implementation deviates from original scope
- keep plan in sync with actual work done

## Solution Overview

Three pieces, introduced in dependency order:

1. **`build_osascript_command` takes a slice of commands instead of one.** It renders each as `/usr/sbin/networksetup 'arg' 'arg'`, joins them with ` && `, and wraps the result in one `do shell script "…" with administrator privileges`. Passing a one-element slice reproduces today's exact output, so the existing tests keep their assertions.

2. **Error classification is separated from escalation.** Today `run_networksetup` decides "admin required" and escalates in the same breath, which is precisely why escalation happens per command. A new `try_networksetup` returns a three-way outcome — succeeded / needs admin / failed — and leaves the decision to the caller.

3. **`run_networksetup_all` drives a sequence.** It runs each command unelevated. On the first `NeedsAdmin`, it escalates the *entire* sequence in one `osascript` and returns. On a genuine failure it bails, naming the command that failed.

`enable_proxy` and `disable_proxy` then become thin wrappers over pure command-list builders, which is what makes the ordering and content testable without touching the system.

**Rejected alternative — a preflight probe.** Running one extra harmless `networksetup` up front purely to learn whether admin is needed. It guards a partial-application case (command #1 succeeds unelevated but #4 demands admin) that cannot occur because all six setters require the identical privilege. Cost is an extra invocation on every start/stop plus a second code path. Not worth it.

**Rejected alternative — several `do shell script` lines inside one `osascript`.** AppleScript would cache the password across them, so this also yields one dialog, but it spawns one shell per command for no benefit over `&&` chaining.

### Touch ID: investigated and deliberately out of scope

The single dialog this plan produces is password-only. Touch ID was evaluated and rejected; recording the findings here so this is not re-opened without new information.

- **The osascript dialog cannot show Touch ID.** It authorizes the `system.privilege.admin` right, whose rule is `class: user`, `authenticate-user: true`, `shared: false`, `timeout: 300`. There is no option that adds biometrics to it. (`shared: false` is also the direct reason six `osascript` processes each re-prompt — an unshared credential is not reusable across processes.)
- **Setting `shared: true` on that right was rejected.** Apple's definition: *"the Security Server may use any shared credentials to authorize this right. For maximum security, set sharing to false."* It would let any process running as the user obtain root without a prompt for 300s after corvex authenticates — a machine-wide local privilege-escalation window, affecting every app that uses this right, persisted in `/var/db/auth.db` and revertible by OS updates. It also does not add Touch ID; it only suppresses repeat prompts, which batching already achieves with no system changes.
- **Switching the privileged step to `sudo` was rejected for now.** It is the only realistic route to Touch ID (`/etc/pam.d/sudo_local` containing `auth sufficient pam_tid.so`), but it needs a controlling terminal, requires the invoking user to be in sudoers (the osascript dialog accepts any admin's credentials, so standard users would lose a capability), silently degrades to a password inside tmux/screen without `pam_reattach`, and depends on a one-time root setup corvex cannot perform itself. It would also be an additional privileged path to maintain rather than a replacement.
- **Native LocalAuthentication + Authorization Services FFI was rejected.** Release binaries are ad-hoc signed (`Signature=adhoc`, `flags=0x20002(adhoc,linker-signed)`) and CI has no codesign or notarize step, which makes the Touch ID sheet unreliable; `AuthorizationExecuteWithPrivileges` has been deprecated since 10.7 and its sanctioned replacement (`SMJobBless` + privileged helper) requires a signed app bundle rather than a single binary; and the headless `macos-14` CI runner cannot test any of it.

## Technical Details

### New outcome type

```rust
/// Result of one `networksetup` invocation, with "needs admin" separated from
/// a real failure so the caller decides when (and how widely) to escalate.
enum NsOutcome {
    Ok(String),
    NeedsAdmin,
    Failed(String),
}
```

`try_networksetup(args: &[&str]) -> Result<NsOutcome>` returns `Err` only when the process could not be spawned at all; everything else is an `NsOutcome`. It keeps the current stdout+stderr merging and the `stdout.contains("** Error")` check.

### Signature changes

| before | after |
| --- | --- |
| `build_osascript_command(args: &[&str]) -> String` | `build_osascript_command(commands: &[Vec<&str>]) -> String` |
| `run_networksetup_elevated(args: &[&str]) -> Result<String>` | `run_networksetup_elevated(commands: &[Vec<&str>]) -> Result<String>` |
| — | `run_networksetup_all(commands: &[Vec<&str>]) -> Result<()>` |
| — | `enable_proxy_commands<'a>(service: &'a str, host: &'a str, port: &'a str) -> Vec<Vec<&'a str>>` |
| — | `disable_proxy_commands<'a>(service: &'a str) -> Vec<Vec<&'a str>>` |

`run_networksetup(args: &[&str]) -> Result<String>` stays for the single read-only getters used by `proxy_status`; internally it now calls `try_networksetup` and, on `NeedsAdmin`, escalates a one-element batch.

### Generated script shape

Single command (unchanged from today, byte for byte):

```
do shell script "/usr/sbin/networksetup '-getwebproxy'" with administrator privileges
```

Batched (new):

```
do shell script "/usr/sbin/networksetup '-setsocksfirewallproxy' 'Wi-Fi' '127.0.0.1' '21080' && /usr/sbin/networksetup '-setsocksfirewallproxystate' 'Wi-Fi' 'on' && …" with administrator privileges
```

Note the phrase `with administrator privileges` appears **once**, and `applescript_escape` is applied to the fully-joined shell string so embedded quotes in a service name are escaped consistently across the whole chain.

### Processing flow for `enable_proxy`

```
enable_proxy(service, host, port)
  └─ enable_proxy_commands(...)          -> 6 command vectors, ordered
     └─ run_networksetup_all(commands)
        ├─ for each: try_networksetup(cmd)
        │    ├─ Ok      -> continue
        │    ├─ Failed  -> bail "networksetup <cmd> failed: <detail>"
        │    └─ NeedsAdmin ─┐
        └───────────────────┴─> run_networksetup_elevated(ALL 6 commands)
                                 └─ ONE osascript, ONE password dialog
```

### Error handling inside a batch

`&&` chaining stops at the first failing command, and `do shell script` surfaces that command's output in the AppleScript error. Since the failing invocation's own `** Error: …` text is included, the message identifies itself. The wrapper adds the full attempted sequence for context:

```
networksetup batch failed (elevated): <detail>
commands: -setsocksfirewallproxy Wi-Fi 127.0.0.1 21080; -setsocksfirewallproxystate Wi-Fi on; …
```

The two special cases keep their current friendly messages, checked before the generic one:
- `is_user_cancel_error` → `Authorization denied — proxy settings were not changed`
- `is_no_gui_error` → `No GUI session available — run with sudo instead`

### Edge cases

- **empty command slice** — `run_networksetup_all(&[])` returns `Ok(())` without spawning anything. Guard this explicitly; otherwise `build_osascript_command` would emit `do shell script "" with administrator privileges`, which prompts for a password and runs nothing.
- **partial application on elevated failure** — if command #4 of 6 fails inside the batch, the first three are already applied. This matches today's behaviour exactly (the sequential calls have the same property), so it is not a regression and is not in scope.
- **running as root** — the unelevated attempts all succeed, `NeedsAdmin` never fires, no `osascript` runs, zero dialogs. Preserved.

## What Goes Where

- **Implementation Steps** (`[ ]` checkboxes): changes to `src/platform/macos.rs`, its unit tests, and repository documentation
- **Post-Completion** (no checkboxes): manual verification on a real macOS GUI session, and the release/tag step which the maintainer performs

## Implementation Steps

### Task 1: Make the osascript builder accept a batch of commands

**Files:**
- Modify: `src/platform/macos.rs`

- [x] change `build_osascript_command` to take `commands: &[Vec<&str>]`, render each as `/usr/sbin/networksetup <shell-escaped args>`, join with ` && `, and wrap the joined string in one `do shell script "…" with administrator privileges`
- [x] change `run_networksetup_elevated` to take `commands: &[Vec<&str>]` and update its generic error message to name every command in the batch
- [x] update the single existing caller in `run_networksetup` to pass a one-element batch so the crate still compiles
- [x] update the three existing `build_osascript_command` tests (`osascript_single_arg`, `osascript_multiple_args`, `osascript_args_with_special_chars`) to the new signature, keeping their expected strings unchanged — this proves single-command output did not drift
- [x] write a test that a 6-command batch renders as one `do shell script`, with the six invocations joined by ` && ` in the given order
- [x] write a test asserting `with administrator privileges` occurs **exactly once** in a batched script (use `matches(...).count()`, not `contains`)
- [x] write a test that a service name containing a double quote and a space is correctly escaped in **every** position of a 3-command batch, not just the first
- [x] run `cargo test` - must pass before task 2

### Task 2: Separate error classification from escalation and add the batch runner

**Files:**
- Modify: `src/platform/macos.rs`

- [x] add `enum NsOutcome { Ok(String), NeedsAdmin, Failed(String) }`
- [x] add `try_networksetup(args: &[&str]) -> Result<NsOutcome>` holding the current stdout/stderr merge, the `** Error` on-stdout check, and `is_admin_required_error` classification; it returns `Err` only when the process cannot be spawned
- [x] rewrite `run_networksetup` to call `try_networksetup` and, on `NeedsAdmin`, escalate a one-element batch — external behaviour for `proxy_status`'s getters is unchanged
- [x] add `run_networksetup_all(commands: &[Vec<&str>]) -> Result<()>`: returns `Ok(())` immediately on an empty slice; runs each command unelevated; on the first `NeedsAdmin` escalates the entire slice via `run_networksetup_elevated` and returns; on `Failed` bails naming that command
- [x] add a `debug!` line when escalating that records how many commands are being batched into the one prompt
- [x] extract the classification decision into a pure helper (e.g. `classify_networksetup_output(exit_ok: bool, stdout: &str, stderr: &str) -> NsOutcome`) so it is testable without spawning a process
- [x] write tests for the pure classifier: success, `** Error: Command requires admin privileges.` on stdout with exit 0, the same on stderr, and an unrelated failure
- [x] write a test that an empty command slice produces no script at all — ⚠️ the first attempt was vacuous (an empty slice skips the `for` loop, so the test passed with the guard deleted; confirmed by mutation). Replaced with a real empty-batch rejection inside `run_networksetup_elevated`, which is the layer where the hazard actually exists.
- [x] run `cargo test` - must pass before task 3

### Task 3: Route enable_proxy and disable_proxy through the batch runner

**Files:**
- Modify: `src/platform/macos.rs`

- [x] add pure `enable_proxy_commands<'a>(service: &'a str, host: &'a str, port: &'a str) -> Vec<Vec<&'a str>>` returning the six setters in order: socks host/port, socks state on, web host/port, web state on, secure-web host/port, secure-web state on
- [x] add pure `disable_proxy_commands<'a>(service: &'a str) -> Vec<Vec<&'a str>>` returning the three state-off commands in order: socks, web, secure-web
- [x] rewrite `Platform::enable_proxy` to build the port string, call `enable_proxy_commands`, and hand the result to `run_networksetup_all`
- [x] rewrite `Platform::disable_proxy` to call `disable_proxy_commands` and hand the result to `run_networksetup_all`
- [x] write a test that `enable_proxy_commands` returns exactly 6 commands in the exact expected order, with the service, host and port substituted into the right positions
- [x] write a test that each host/port setter precedes its matching state-on command (the ordering invariant: switching state on before the host is set would enable a proxy pointing at a stale address)
- [x] write a test that `disable_proxy_commands` returns exactly 3 commands, all `…state off`, in the expected order
- [x] write a test feeding `enable_proxy_commands` output straight into `build_osascript_command` and asserting the result prompts once — the end-to-end string a user's single dialog will execute
- [x] run `cargo test` - must pass before task 4

### Task 4: Verify acceptance criteria

- [x] verify `corvex start` as a normal user now produces exactly one password dialog — verified by code path and generated-script text; the on-screen count is a Post-Completion manual check, since spawning a real dialog cannot be automated
- [x] verify `corvex stop` as a normal user produces exactly one password dialog
- [x] verify running under `sudo` still produces zero dialogs — confirm by code path: every unelevated attempt succeeds so `NeedsAdmin` never fires
- [x] verify the user-cancel and no-GUI messages still appear unchanged for a batched escalation
- [x] verify the empty-batch guard prevents a password prompt for a no-op
- [x] run `cargo fmt --check`
- [x] run `cargo clippy --all-targets` and confirm no new warnings
- [x] run the full suite: `cargo test`

### Task 5: [Final] Update documentation

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`
- Modify: `RELEASE_NOTES.md`

- [x] update the `src/platform/macos.rs` line in CLAUDE.md's architecture tree to say proxy changes are applied as one batched, single-prompt escalation
- [x] check README for any text describing the macOS password prompt and correct it if it implies repeated prompts
- [x] state in README that the single prompt is password-only and that Touch ID is not available for this dialog, so the behaviour is not filed as a bug
- [x] prepend a `# Corvex v0.6.4 Release Notes` section to RELEASE_NOTES.md describing the fix (the release-guard CI job reads `head -1 RELEASE_NOTES.md`, so the new heading must be the first line)
- [x] move this plan to `docs/plans/completed/`

## Post-Completion

*Items requiring manual intervention or external systems - no checkboxes, informational only*

**Manual verification** (requires a real macOS GUI session; cannot be unit tested):
- with the proxy off, run plain `corvex start` as a normal user and count the dialogs — expect exactly one
- run plain `corvex stop` and count again — expect exactly one
- cancel the dialog at the prompt and confirm the message is `Authorization denied — proxy settings were not changed` and that `networksetup -getsocksfirewallproxy` shows the proxy unchanged
- run `sudo corvex start` and confirm no dialog appears at all
- exercise a machine whose active service name contains a space (e.g. `Thunderbolt Bridge`) to confirm quoting survives the batch

**External system updates:**
- version bump in `Cargo.toml` and the `v0.6.4` tag push are the maintainer's step; releases are published by pushing a `v*` tag, never via `gh release create`

## Outcome

Landed on `releases/0.6.4`. Final gate: `cargo fmt --check` clean, `cargo clippy --all-targets` no warnings, **361 tests passing** (up from 332 at branch point).

### Review rounds

Three codex review rounds ran, each followed by fixes:

- **Round 1** — no CRITICAL/HIGH. Fixed: the user-cancel message claimed "proxy settings were not changed" unconditionally, which the code cannot guarantee (now driven by an `already_applied` flag); the mid-batch failure message implied every listed command had run; two test names overclaimed to prove a single `osascript` spawn when they only check script text; composed quoting coverage was thin on a path that executes as root (five tests added for `'`, `\`, `$()`, backtick, and a combination — verified inert by round-tripping the generated script through `shlex.split`); one vacuous test deleted.
- **Round 2** — no CRITICAL/HIGH. Found a real bug: `classify_networksetup_output` checked only stdout for `** Error`, so an error on stderr with exit code 0 was classified as success. Fixed by classifying on the combined output. Message construction extracted into pure functions and tested directly.
- **Round 3** — **HIGH, DO NOT SHIP**: `run_networksetup_elevated` trusted only `osascript`'s exit status, so a zero-exit `** Error` from one command in the `&&` chain was masked by the commands that ran after it — corvex would print `proxy enabled` with a setting silently unapplied. Fixed with `classify_elevated_output`, mirroring the unelevated classifier. Re-confirmed: **SHIP**.

### Deviation from the plan

The plan did not anticipate the elevated path needing its own output classification — it assumed a nonzero exit was sufficient there. Batching made that assumption unsafe, because chaining with `&&` lets a zero-exit error hide behind later successes. `ElevatedOutcome` / `classify_elevated_output` were added beyond the original three tasks.
