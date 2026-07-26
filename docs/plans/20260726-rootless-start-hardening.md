# Rootless start hardening: orphan detection, honest sudo advice, writable log defaults

> Revised through three review rounds (2026-07-26): two by the plan-review agent, one independent pass by Codex.
> All Critical and Important findings are folded in; see "Review corrections" at the end of Solution Overview for the
> ones that changed the design rather than the wording. Every claim they made was re-verified against the source
> before being applied — one Codex recommendation (`ps -o comm=` as a separate column) was verified as wrong and
> implemented differently.

## Overview

Four defects, found while diagnosing a real failure on macOS 26.5.2 with corvex 0.6.2 installed at `/usr/local/bin/corvex`, that together make `corvex start` unusable as a normal user once the machine has ever run `sudo corvex start`:

1. **The sudo advice is a trap.** When `start` finds a running xray owned by another user, it fails with `xray (PID: N) is running as another user - try again with sudo`. Following that advice (`sudo corvex start`) creates *another* root-owned xray, so the next rootless start fails identically. The user is looped into permanent sudo. The correct recovery is `sudo corvex stop` once, then plain `corvex start`.

2. **Orphaned corvex-owned xray processes are invisible.** Only the PID recorded in `xray.pid` is ever considered. On the reporting machine two root-owned xray processes were running against corvex's own config (PID 5556 from today, PID 7597 orphaned since Jul 19); `xray.pid` knew about one. `sudo corvex stop` retires the tracked one, reports `corvex stopped!`, and silently leaves the orphan holding the proxy port — after which the next start fails with the unrelated-looking `xray failed to start - check the log`.

3. **corvex creates orphans itself.** `xray::start` spawns the child (`src/xray.rs:375-377`) and only then writes the PID file (line 385) with `fs::write`, which opens with truncate and fails with `EACCES` on a root-owned `xray.pid` — precisely the state on the reporting machine. The `?` returns and the freshly started xray keeps running untracked. This is the most likely origin of the Jul 19 orphan, and it means defect 2 regenerates itself even after cleanup.

4. **xray logs default to a root-only directory.** `default_xray_log()` (`src/config.rs:139`) returns `/var/log/xray/xray.log` and `XrayLogConfig::default()` (`src/protocol.rs:755-760`) defaults access/error to `/var/log/xray/*.log`. A normal user cannot write there. When xray cannot open its access log it exits immediately and corvex reports `xray failed to start - check the log` — where "the log" is the file it just failed to write. On the reporting machine `/etc/newsyslog.d/xray.conf` also rotates these files as root (owner field `:admin`, i.e. empty owner), so even a manual `chown` is undone at the next rotation.

Benefit: after a single `sudo corvex stop`, `corvex start` works rootless on a machine with sudo history — and whenever it cannot, every failure names the exact command that fixes it instead of pointing at an unwritable log.

**Why the fix is not "allow only one xray process".** This was considered and deliberately rejected. corvex itself runs several xray processes at once by design: `src/health.rs:97-103` spawns a temporary `xray run -c <NamedTempFile>` probe on a random port for every candidate server during subscription health checks (visible in the debug trace as `tunnel check via temp config …`, `socks5://127.0.0.1:21304`). A global single-instance rule would kill corvex's own probes mid-selection. It would also kill unrelated third-party xray instances — V2rayU, Nekoray, Happ desktop and `brew services xray` all ship their own xray — which is hostile and unsafe. Instead, "corvex-owned" is defined narrowly as *a process whose command line runs xray against corvex's own `config.json` path*. Health-check probes use temp configs and are excluded automatically; other apps use their own configs and are excluded too.

Per the answered design question, detected processes are **reported, never killed**: corvex never signals a process it does not track. No new code path calls `signal::kill`.

## Context (from discovery)

- files/components involved:
  - `src/xray.rs` — `XrayError::NotRunning`/`StartFailed`/`NotPermitted` (lines 22-28), `is_running` (195), `is_process_alive` (237), `process_is_xray` (250) / `command_matches` (275), `start` (329, spawn at 359-363, `StartFailed` at 390-395), `stop` (399), `stop_process` (423)
  - `src/protocol.rs` — `impl Default for XrayLogConfig` (753-760): the real `/var/log/xray/{access,error}.log` literals
  - `src/config.rs` — `default_xray_log` (139), `state_dir` , `Config::new` (60)
  - `src/main.rs` — `xray_log` aliasing to `log.xray.error` (93-103), `cmd_start` (247), `build_xray_log_config` (473, delegates to `XrayLogConfig::default()` — holds no literals of its own), `ensure_directories` (539), `main_algorithm` (586), `cmd_stop` (653-672), `cmd_status` (681)
  - `src/health.rs` — `generate_temp_config` (44) / `check_tunnel` (97), the reason a global single-instance rule is wrong
  - `README.md`, `CLAUDE.md`, `examples/corvex.json`, `RELEASE_NOTES.md`
- related patterns found:
  - all parsing functions take `&str` and are unit-tested without system calls (`parse_scutil_dns`, `parse_proxy_info`, `command_matches`)
  - user-facing hint text lives in `const` items (`XRAY_NOT_INSTALLED_MSG` at `src/xray.rs:43`, `AWG_NOT_INSTALLED_MSG`); anything needing interpolation must be a `const` template plus a small builder fn
  - platform-specific bodies are `#[cfg(unix)]` / `#[cfg(windows)]` pairs in the same module (`process_is_xray`, `is_process_alive`, `stop_process`)
  - command functions take `&impl Platform` and are tested against `RecordingPlatform` in `src/main.rs` tests
  - `is_process_alive` already treats `EPERM` as alive — cross-user awareness exists, it is just not surfaced
- dependencies identified: **no new crates**. Process listing uses `ps` (already used by `process_is_xray`); file ownership uses `std::os::unix::fs::MetadataExt::uid()` from the standard library, not `nix` (whose `user` feature is not enabled — `Cargo.toml:23` declares only `["signal", "process"]`).
  - **The `sysinfo` crate was evaluated for the process listing and rejected on evidence, not on a no-dependencies rule.** It is the nicer API — real `argv` as a `Vec<String>`, cross-platform, no text parsing — but it *cannot see what this feature needs*. Probed on this Mac as a normal user, it returned `argv=[]` and `owner=None` for both root-owned xray processes (and argv for only 1 of 322 other-user processes, versus 500 of 500 of the user's own). macOS restricts `KERN_PROCARGS2` to the process owner; `/bin/ps` gets around it by being setuid root. Since the whole point is identifying root-owned xray by its `-c` config path and telling the user who owns it, `sysinfo` would return nothing in exactly the case that matters. Full numbers and the re-evaluation trigger are in Technical Details.
- CI gates that constrain this work (`.github/workflows/rust.yml`): test matrix is `[macos-14, ubuntu-latest, windows-latest]` (line 41), clippy runs as `cargo clippy -- -D warnings -A dead_code` (line 70), and `release-guard` reads `head -1 RELEASE_NOTES.md` (line 117).
- release context: branch `releases/0.6.3` currently holds only a version bump (`f59285f`) with no content, and `RELEASE_NOTES.md` line 1 is still `# Corvex v0.6.2 Release Notes`. The `release-guard` job fails a tag push until v0.6.3 is the first line, so the notes update in the final task is a release blocker, not a nicety.

## Development Approach

- **testing approach**: Regular (code first, then tests) — matches the existing repo convention of pure `&str` parsers with unit tests alongside
- complete each task fully before moving to the next
- make small, focused changes
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task
  - tests are not optional - they are a required part of the checklist
  - write unit tests for new functions/methods
  - write unit tests for modified functions/methods
  - add new test cases for new code paths
  - update existing test cases if behavior changes
  - tests cover both success and error scenarios
- **CRITICAL: all tests must pass before starting next task** - no exceptions
- **CRITICAL: update this plan file when scope changes during implementation**
- run tests after each change
- **show the diff after each completed task**: once a task's tests pass and it is committed, present that task's diff for review before starting the next one. A task is not "done" until its diff has been shown
- **every new module-level function must compile on Windows**: the test matrix includes `windows-latest`, so `ps`-based and permission-based code needs `#[cfg(unix)]` bodies with `#[cfg(windows)]` stubs, following the existing `process_is_xray` pattern
- maintain backward compatibility: an explicit `log.xray.access` / `log.xray.error` in an existing `corvex.json` keeps working unchanged; only the built-in defaults move, and no existing log file is moved or deleted

## Testing Strategy

- **unit tests**: required for every task (see Development Approach above)
- **e2e tests**: none — this is a CLI with no UI-based e2e suite. The equivalent gates are `cargo test`, `cargo clippy -- -D warnings -A dead_code`, `cargo fmt --check`, `cargo build`
- process-listing, message-building and permission-classification logic must each be split into a **named pure function** (listed explicitly in the task checkboxes) plus a thin IO caller, so the interesting behavior is tested without root, without spawning processes, and without touching `/var/log`
- permission tests that rely on unix modes must be `#[cfg(unix)]`-gated so the Windows CI job stays green

## Progress Tracking

- mark completed items with `[x]` immediately when done
- add newly discovered tasks with ➕ prefix
- document issues/blockers with ⚠️ prefix
- update plan if implementation deviates from original scope
- keep plan in sync with actual work done

## Solution Overview

**Ownership is defined by config path, not by binary name.** A pure parser turns `ps -eww -o pid=,user=,args=` output into a list of xray processes together with the `-c` argument each one is running. corvex's daemon always spawns `xray run -c <Config::xray_config>` with the config path as the final argument (`src/xray.rs:359-363`), so that path is an exact discriminator:

| process | command line | classified as |
|---|---|---|
| corvex daemon | `xray run -c ~/.config/xray/config.json` | managed |
| corvex health probe | `xray run -c /var/folders/…/tmpXXXX.json` | other xray |
| V2rayU / brew xray | `xray run -c /opt/homebrew/etc/xray/config.json` | other xray |

Only *managed* processes are ever called orphans. *Other xray* processes are never named as orphans and never proposed for killing; they appear only in the start-failure diagnostic, where "some other xray is running, here is its config and your port" is exactly the information the user needs. `status` deliberately does not list them: `ps` cannot show what port another process listens on, so any claim there about port ownership would be a guess.

**Reporting, never killing.** `find_managed_processes` is read-only. `start`, `stop` and `status` use it to explain state. `stop` keeps signalling only the tracked PID, exactly as today.

**Advice is command-specific and, above all, has to actually work.** Three distinct situations, three distinct hints:

| situation | condition | hint |
|---|---|---|
| tracked xray owned by another user | `stop` → `NotPermitted` | `sudo corvex stop`, then `corvex start` — and *not* `sudo corvex start`, which recreates the problem |
| untracked managed xray (orphan) | in `find_managed_processes`, not the tracked PID | `sudo kill <pid>` (or `kill <pid>` when the owner is the current user) — **never** `corvex stop`, which cannot touch it |
| start failed for any reason | `xray::start` → `StartFailed` | always name the configured `proxy.port` and log path; additionally list every running xray with its PID, owner and `-c` argument when any exist |

The middle row is the one the previous draft got wrong: `xray::stop` (`src/xray.rs:399-403`) only ever signals the PID read from `xray.pid`, so telling a user to run `sudo corvex stop` for an orphan would ship a second generation of the exact looping-advice defect this plan exists to remove.

**Log defaults move to user-writable state, and unwritable targets fail loudly and early.** Unix defaults become `$XDG_STATE_HOME/xray/{xray.log,access.log,error.log}`, mirroring the Windows layout (`%LOCALAPPDATA%\xray\…`, `src/config.rs:146`, `src/protocol.rs:761-769`) so there is one mental model per platform. Independently, a preflight check runs before spawning xray and reports an unwritable log target by name, with its owner and the fix, instead of letting xray die and pointing at a log it could not write. The preflight is what rescues existing configs that still point at `/var/log/xray/`.

**Review corrections that changed the design** (not just wording):

Round three (independent Codex review) added one task and corrected four contracts:

- **corvex's own orphan-production path** (new Task 6): `xray::start` spawns first and writes the PID file after, so an unwritable `xray.pid` — the exact state on the reporting machine — leaves a live untracked xray. Detection alone would have reported this forever without stopping it.
- `status_process_lines` returns **orphan lines only**; the earlier contract both re-rendered the tracked line and asked to be called after it, which would have printed it twice.
- `start_failure_diagnostics` takes `log_path` — it was required to name the log path with no parameter carrying it.
- Every failed log append-open is fatal, not just `PermissionDenied`; this deletes the `LogPreflight`/`classify_log_error` pair as dead classification.
- The `0o500`-directory permission test could not fail as written: directory mode governs creation, not appending to an existing file. The test now chmods the file itself to `0o400`.
- `command_matches` is applied to argv[0] only. Codex proposed adding a `comm=` column instead; I verified that breaks — `ps` truncates non-final columns, yielding `/opt/homebrew/Ce` on this machine, so `args=` must stay last and argv[0] is parsed from it.

Round two and one:

- Task 4 retargeted from `src/main.rs::build_xray_log_config` (which holds no literals — it delegates to `XrayLogConfig::default()`) to `src/protocol.rs` + `src/config.rs`, with every assertion and doc site enumerated.
- Orphan hint changed from `sudo corvex stop` to `sudo kill <pid>`, with a test that asserts the orphan hint never mentions `corvex stop`.
- Diagnostics attached to `StartFailed` and to successful `cmd_stop`, not only to `NotPermitted` — the `StartFailed` path is where the reporting machine lands *after* following the new advice.
- `ps` contract pinned to `ps -eww -o pid=,user=,args=`: `-o pid,user,args=` still prints a `PID USER` header (verified on this machine), and `-ww` prevents procps truncating the args column on Linux, which would silently turn a trailing-suffix match into a false negative.
- Matching rule reduced to one unambiguous form (trailing segment after the first ` -c `), because "whitespace-delimited token" contradicts the required support for config paths containing spaces.
- File owner resolved via stdlib `MetadataExt::uid()` rather than `nix::unistd::User` (feature not enabled; also unix-only in a cross-platform module).

From the second review round:

- `state_dir()` must become `pub(crate)`: it is private today, which is exactly why `XrayLogConfig::default()` open-codes its own `LOCALAPPDATA` lookup. Without this the implementer would write a third copy of the XDG fallback.
- `status` no longer tries to list other-config xray "on the same port" — `ps` cannot show a listening port, so that clause was not implementable and contradicted the ownership model.
- The ` -c ` split takes the **first** occurrence, not the last: a config path containing the literal `" -c "` would otherwise truncate and make corvex's own daemon invisible to its own detector.
- `port_conflict_message` renamed to `start_failure_diagnostics` and its conflict language gated on a non-empty process list — `StartFailed` also fires on an invalid config, missing geo assets, or an unwritable log, so the old name would have asserted a conflict that was never observed.
- The `ensure_directories` claim was wrong and is corrected: `src/main.rs:563-583` already creates both the `xray_log` parent and the settings access/error parents, so Task 4 needs no change there.

**Known limitation to document, not solve:** `sudo` resets the environment. `XDG_CONFIG_HOME` does not survive it, and on Linux `HOME` becomes `/root`, so a root corvex may use `/root/.config/xray/config.json` and write its PID file there too. In that case the user's corvex sees no tracked PID and no path match, and the root process is classified as *other xray* — it will still surface in the start-failure diagnostic with its config path, which is enough for the user to act. Making sudo-launched instances discoverable across HOME boundaries is out of scope.

## Technical Details

New surface in `src/xray.rs`:

```rust
pub struct XrayProcess { pub pid: i32, pub user: String, pub config_arg: String }

/// Pure: parse `ps -eww -o pid=,user=,args=` output into every xray process, with its -c argument.
pub fn parse_xray_processes(ps_output: &str, xray_bin: &str) -> Vec<XrayProcess>;

/// Runs ps, returns all xray processes. Read-only; never signals. Windows: returns empty.
/// Takes `&str` (not `&Config`) to match the module's `&str`-first convention — it needs only xray_bin.
pub fn list_xray_processes(xray_bin: &str) -> Vec<XrayProcess>;

/// Processes whose config_arg matches corvex's own config path.
pub fn managed_processes(all: &[XrayProcess], config_path: &str) -> Vec<XrayProcess>;

/// Managed processes other than the tracked PID.
pub fn orphans(all: &[XrayProcess], config_path: &str, tracked: Option<i32>) -> Vec<XrayProcess>;
```

**Matching rule (single, unambiguous).** For each `ps` line: field 1 is the PID, field 2 the user, and the entire remainder is the args string. `argv[0]` is the **first whitespace token of that remainder**, and a line belongs to xray when `command_matches(argv0, xray_bin)` holds. `config_arg` is the remainder after the **first** ` -c ` separator, trimmed. A process is *managed* when `config_arg == config_path`.

`command_matches` must be applied to `argv[0]` alone, never to the whole args string: it runs `Path::file_name()` and then a substring test (`src/xray.rs:275-285`), so feeding it a full command line would test the basename of whatever the line happens to end with. That is why the parser extracts argv[0] explicitly.

**Why `ps` and not the `sysinfo` crate.** Raised in review, and settled by experiment rather than preference — `sysinfo` would be the obvious choice, since it returns real `argv` as a `Vec<String>` (no text parsing, no truncation, no space-in-path problems) and works on Windows, removing the cfg stubs. It cannot do the job here. Probing `sysinfo` 0.32 on this Mac as a normal user, with `refresh_processes_specifics` and `ProcessRefreshKind::everything().with_cmd(Always).with_user(Always)`:

| processes | argv available |
|---|---|
| owned by the current user | 500 of 500 |
| owned by other users | 1 of 322 |
| **the two root-owned xray processes** | **`argv=[]`, `owner=None`** |

macOS restricts `KERN_PROCARGS2` to the process owner, so a normal-user Rust binary gets neither the command line nor the uid for a root-owned process. Both are exactly what this feature needs: `argv` carries the `-c` config path that defines ownership, and the owner decides whether the hint says `kill` or `sudo kill`. `/bin/ps` succeeds only because it is **setuid root** (`-rwsr-xr-x 1 root wheel`, verified). `sysinfo` does still expose `exe()` for root processes, so it could report "an xray is running" — but not which config it uses or who owns it, which is not enough to act on.

`libproc` 0.14.11 was probed the same way against a live root-owned xray and fails harder: `pidpath()` works, but `pidinfo::<BSDInfo>()` returns **EPERM** for the owner uid, and the crate has **no argv API at all** (zero source matches for `procargs`, `argv`, `cmdline`). Also macOS/Linux only, so it would not remove the Windows stubs either.

The limit is a kernel permission boundary, not a missing library, so no crate can route around it: `procfs` would work but is Linux-only (`/proc/<pid>/cmdline` is world-readable there), and `psutil`/`heim`/hand-rolled `sysctl` all inherit the same macOS restriction. Shelling out to a setuid-root tool is the correct answer here, and it is consistent with how corvex already drives `networksetup`, `scutil`, `route`, `awg-quick` and `ps`. **Re-evaluate only if corvex ever ships a privileged helper**, or if the feature is ever narrowed to "some xray is running", which `sysinfo`/`libproc` can answer via `exe()` alone.

**Do not add `comm=` as a separate `ps` column for this.** `ps` truncates every non-final column to a fixed width, and on macOS `comm` is the full executable path: `ps -eww -o pid=,user=,comm=,args=` yields `/opt/homebrew/Ce` for a Homebrew xray (verified on the reporting machine), which `command_matches` then rejects. The existing `process_is_xray` escapes this only because `comm=` is its *only* column there. Keeping `args=` last and parsing argv[0] out of it is the form that survives both platforms.

Taking a trailing segment rather than a whitespace-delimited token is what keeps home directories containing spaces working, and it relies on corvex always passing the config path as the final argument. Both of corvex's spawn sites do exactly that and pass `-c` exactly once — `src/xray.rs:359-363` (daemon) and `src/health.rs:97-99` (probe). Splitting on the *first* occurrence rather than the last matters for the pathological case of a config path that itself contains `" -c "` (e.g. `~/my -c dir/config.json`): a last-occurrence split would truncate the path and make corvex's own daemon invisible to its own detector, silently reintroducing the bug being fixed. Requiring the trailing space in `" -c "` also means `-config`, `-c=` and `-confdir` cannot match, so third-party flag styles degrade to an empty `config_arg` (never managed) instead of a wrong one. Lines with no ` -c ` at all yield an empty `config_arg` and can never be managed.

**Documented false negatives** (acceptable, because every one of them fails toward "report nothing" rather than toward a wrong kill suggestion): an executable path containing spaces breaks the argv[0] token split; a config path reached via symlink, relative path, or non-normalized components will not compare equal to corvex's own path; and `-c=<path>` style is not parsed. corvex's own two spawn sites produce none of these forms.

**`ps` is a snapshot.** A listed process may exit between the listing and the user acting on it, and PIDs are reused. Recovery advice must therefore be worded as an observation ("as of now") and tell the user to re-check with `ps` before running `kill`. corvex itself never signals these PIDs, so the risk is confined to the copy-pasted command. This does not close the pre-existing PID-reuse hole in `is_running` (`src/xray.rs:219-229` validates that a tracked PID looks like xray, but not that it uses the same config) — out of scope here, worth a follow-up.

Two deliberate non-issues, worth knowing while reading the code: `command_matches` uses `contains` on the basename (`src/xray.rs:284`), so siblings like `xray-knife` or `xray-plugin` pass the binary test — but they only become *managed* if actually run against corvex's own `config.json`, in which case reporting them is accurate. And a shell wrapper named `xray` appears in `ps` as `/bin/sh /path/xray run -c …`, so argv[0] is the interpreter and only the real child is counted; the same holds for `sudo xray …`, whose own line starts with `sudo`. Neither produces a double listing.

**Fail closed.** When `ps` is unavailable or errors, `list_xray_processes` returns an empty vec: an unavailable `ps` must never invent a phantom orphan. (This is the opposite stance from `process_is_xray`, which fails *open* by returning `true` to avoid deleting a live PID file — different question, different safe default.)

New hint text in `src/xray.rs`, as `const` templates plus builder fns (interpolation rules out plain `const &str` messages):

```rust
const ROOT_XRAY_ON_START_HINT: &str = "…run `sudo corvex stop`, then `corvex start`. \
    Do not run `sudo corvex start` — it starts another root-owned xray and the problem repeats.";
const ORPHAN_XRAY_HINT: &str = "…corvex does not track this process and cannot stop it.";

pub fn start_blocked_message(pid: i32, owner: Option<&str>, orphans: &[XrayProcess]) -> String;
pub fn orphan_lines(orphans: &[XrayProcess], current_user: &str) -> Vec<String>; // `sudo kill N` / `kill N`
pub fn start_failure_diagnostics(all: &[XrayProcess], port: u16, config_path: &str, log_path: &Path) -> String;
```

All of the above are `pub(crate)`, not `pub` — including `XrayProcess`'s fields. Nothing here is part of a public API.

`current_user` comes from `std::env::var("USER")` with a `LOGNAME` fallback: `ps` reports user *names*, so names are the right comparison axis, and `nix::unistd::getuid` sits behind the `user` feature that this plan deliberately does not enable. The `owner` passed to `start_blocked_message` must be looked up in the **full** process list, not in `managed_processes` — under the documented sudo/HOME blind spot the tracked PID can classify as *other xray*, which is precisely the situation the message exists to explain, and a managed-only lookup would render it as an unknown owner.

`start_failure_diagnostics` is named for what triggers it, not for one cause: `StartFailed` also fires on an invalid config, missing geo assets, or an unwritable log. It always prints the configured port and log path; the "another xray is holding your port" sentence and the process listing appear **only** when the process list is non-empty, so corvex never asserts a conflict it has not observed.

Status/stop rendering in `src/main.rs`:

```rust
fn status_process_lines(tracked: Option<i32>, all: &[XrayProcess], config_path: &str, current_user: &str) -> Vec<String>;
```

Log preflight in `src/main.rs`:

```rust
fn log_open_error_message(path: &Path, err: &std::io::Error, owner_uid: Option<u32>) -> String;
fn preflight_log_paths(paths: &[PathBuf]) -> anyhow::Result<()>;
```

Called from `cmd_start` before `main_algorithm`, over `config.xray_log` plus `log.xray.access` and `log.xray.error`. **The path list must be deduplicated first**: `src/main.rs:93-103` aliases `config.xray_log` to `log.xray.error` whenever that setting exists, so an undeduped list reports the same file twice.

**Every failed append-open is fatal**, not just `PermissionDenied`. A target that is a directory, on a read-only filesystem, behind a symlink loop, or whose parent could not be created is just as certainly fatal to xray — and `ensure_directories` deliberately swallows those errors (`src/main.rs:539-583`), so downgrading them to warnings would funnel the user straight back into the opaque `xray failed to start - check the log`. Only the *remediation text* varies: `PermissionDenied` adds the owner uid and the `sudo chown $(id -un) <path>` hint, everything else reports the underlying error. This is why there is no `LogPreflight` enum or `classify_log_error` — an earlier draft had both, and once every failure is fatal they classify nothing.

Default path changes:

- `src/config.rs:139` `default_xray_log()` unix: `/var/log/xray/xray.log` → `state_dir().join("xray").join("xray.log")`
- `src/protocol.rs:755-760` `XrayLogConfig::default()` unix: → `state_dir()`-based `xray/access.log` and `xray/error.log`

Sites asserting or documenting the old values, all of which must change with them: `src/protocol.rs:1687-1688`, `src/config.rs:172`, `src/main.rs:1126-1127`, `examples/corvex.json:43-44`, `README.md:149-150`, `CLAUDE.md:51`, `CLAUDE.md:99`. Note `src/settings.rs:130-131` and `171-172` use the strings only as *parser fixtures* (proving an explicit setting is read back) — they must stay as they are, since explicit `/var/log` paths remain fully supported.

## What Goes Where

- **Implementation Steps** (`[ ]` checkboxes): code changes, tests, documentation updates in this repo
- **Post-Completion** (no checkboxes): the machine-level cleanup and manual verification the user performs on the affected Mac

## Implementation Steps

### Task 1: Add xray process listing with config-path classification

**Files:**
- Modify: `src/xray.rs`

- [x] add `pub(crate) struct XrayProcess { pid, user, config_arg }` and pure `parse_xray_processes(ps_output, xray_bin)` over `ps -eww -o pid=,user=,args=` text: PID = field 1, user = field 2, args = remainder; apply `command_matches` to **argv[0] only** (the first whitespace token of args, never the whole args string), and take `config_arg` as the trimmed remainder after the **first** ` -c `. Keep `args=` as the final `ps` column — a separate `comm=` column is truncated to 16 chars
- [x] add pure `managed_processes(all, config_path)` (exact `config_arg` match) and `orphans(all, config_path, tracked)`
- [x] add `#[cfg(unix)] list_xray_processes(xray_bin)` running `ps -eww -o pid=,user=,args=`, returning an empty vec on any `ps` failure (fail closed — never invent an orphan), plus a `#[cfg(windows)]` stub returning an empty vec, following the existing `process_is_xray` cfg pattern
- [x] write tests for `parse_xray_processes` success cases: corvex's own `run -c <config>` line is managed; a health-probe line with a `/var/folders/…tmp.json` config is parsed but not managed; a third-party xray with a different config is not managed; a config path containing a space is matched correctly; **a config path containing the literal `" -c "` is matched correctly** (regression guard for the first-vs-last split)
- [x] write tests for error/edge cases: empty output, a stray `PID USER` header line, a malformed line with no PID column, an xray line with no ` -c ` at all (empty `config_arg`, never managed), a non-xray process, a `/bin/sh` wrapper line (argv[0] is the interpreter, so not counted), **a non-xray command line that merely mentions `xray` in a later argument (must not match — the argv[0]-only regression guard)**, and `orphans` excluding the tracked PID while keeping two untracked ones in order
- [x] run `cargo test` - must pass before task 2

### Task 2: Replace start-path advice and add start-failure diagnostics

**Files:**
- Modify: `src/xray.rs`
- Modify: `src/main.rs`

- [x] add `ROOT_XRAY_ON_START_HINT` / `ORPHAN_XRAY_HINT` const templates plus builders `start_blocked_message(pid, owner, orphans)`, `orphan_lines(orphans, current_user)` (emitting `sudo kill N`, or `kill N` when the owner is the current user, worded as a snapshot with "re-check with `ps` first"), and `start_failure_diagnostics(all, port, config_path, log_path)`; resolve `current_user` from `std::env::var("USER")` with a `LOGNAME` fallback, and look the blocked PID's owner up in the **full** process list, not the managed subset
- [x] keep `XrayError::NotPermitted`'s existing text for `stop`/`reload` (there "try again with sudo" is correct advice) and surface `start_blocked_message` instead when the pre-start `xray::stop` fails with `NotPermitted` in `main_algorithm`
- [x] surface `start_failure_diagnostics` when `xray::start` returns `StartFailed`, passing `config.xray_log` explicitly so the message can always name the port *and* the log path, and listing running xray processes with the port-conflict sentence **only when that list is non-empty** — `StartFailed` also fires on an invalid config, missing geo assets, or an unwritable log
- [x] print orphan lines as a non-fatal warning on an otherwise successful start
- [x] write tests for the builders (success cases): `start_blocked_message` names the PID, the owner, `sudo corvex stop` and `corvex start`; `orphan_lines` emits `sudo kill` for another user's PID and bare `kill` for the current user's; `start_failure_diagnostics` lists each process's config path and the port
- [x] write tests for error/edge cases: `start_blocked_message` with no orphans emits no orphan text; **`orphan_lines` output never contains the substring `corvex stop`** (regression guard for the looping-advice defect); `start_failure_diagnostics` with an empty process list names the port and log path but claims no conflict
- [x] run `cargo test` - must pass before task 3

### Task 3: Report surviving processes in `status` and `stop`

**Files:**
- Modify: `src/main.rs`

- [x] add pure `status_process_lines(tracked, all, config_path, current_user)` returning **orphan lines only** — the existing `xray: started (PID: N)` line at `src/main.rs:705` stays exactly where it is and is not re-rendered here, so an empty return means byte-identical output to today. Managed processes only: `ps` cannot reveal what port another process listens on, so listing *other xray* here is not derivable; that stays in `start_failure_diagnostics`, where the user is already told the port
- [x] wire it into `cmd_status` immediately after that existing line
- [x] in `cmd_stop`, after a successful `xray::stop`, list any surviving managed processes and qualify the `corvex stopped!` line instead of claiming a clean stop — `stop` is the command the new hint sends users to, so it must not lie
- [x] write tests for `status_process_lines` success cases: single tracked process and no orphans → **empty vec** (no duplicate of the tracked line); tracked + one root-owned orphan → one line carrying `sudo kill`
- [x] write tests for error/edge cases: orphan present with no tracked PID; no processes at all; an xray running against a different config is never listed by `status`
- [x] run `cargo test` - must pass before task 4

### Task 4: Move default xray log paths to the user state directory

**Files:**
- Modify: `src/config.rs`
- Modify: `src/protocol.rs`
- Modify: `src/main.rs` (test assertions only)
- Modify: `examples/corvex.json`

- [x] make `state_dir()` (`src/config.rs:109`) `pub(crate)` — it is private today, which is why `XrayLogConfig::default()` open-codes its own `LOCALAPPDATA` lookup; exposing it avoids a third copy of the XDG fallback logic and keeps `state_dir_inner`'s existing tests (`src/config.rs:197-218`) covering the paths that actually ship
- [x] change `default_xray_log()` (`src/config.rs:139`) on unix to `state_dir().join("xray").join("xray.log")`, leaving the Windows branch untouched
- [x] change `XrayLogConfig::default()` (`src/protocol.rs:755-769`) to call `config::state_dir()` for **both** branches, giving unix `xray/access.log` and `xray/error.log` and removing the duplicated Windows `LOCALAPPDATA` lookup — note `src/main.rs:473 build_xray_log_config` needs no literal changes, it already delegates here
- [x] verify `ensure_directories` needs no change: `src/main.rs:563-572` already creates `config.xray_log.parent()` and 574-583 the settings access/error parents, so the new directory is created once the defaults move (no change expected)
- [x] update the assertions holding the old literals: `src/protocol.rs:1687-1688`, `src/config.rs:172`, `src/main.rs:1126-1127`; leave `src/settings.rs:130-131,171-172` unchanged (parser fixtures proving explicit `/var/log` paths still work)
- [x] update `examples/corvex.json:43-44` to the new defaults
- [x] write tests asserting the new defaults live under `state_dir()/xray/` and that an explicit `log.xray.*` in settings still overrides them
- [x] write tests for edge cases: `XDG_STATE_HOME` unset falls back to `~/.local/state`; the Windows default is unaffected
- [x] run `cargo test` - must pass before task 5

### Task 5: Preflight unwritable log targets before spawning xray

**Files:**
- Modify: `src/main.rs`

- [x] add pure `log_open_error_message(path, err, owner_uid)` naming the file and, for `PermissionDenied` only, its owner uid (via stdlib `std::os::unix::fs::MetadataExt::uid()`, no new crate) plus the `sudo chown $(id -un) <path>` fix; on Windows the uid is always `None` and the message omits the chown line, since `MetadataExt` is unix-only and `preflight_log_paths` lives in the cross-platform `main.rs`
- [x] add `preflight_log_paths(paths)` opening each target append+create and treating **any** failure as fatal (a directory, read-only filesystem, symlink loop or uncreatable parent all kill xray just as surely as a permission error); **deduplicate the path list first**, since `src/main.rs:93-103` aliases `config.xray_log` to `log.xray.error` and would otherwise report one file twice
- [x] call it from `cmd_start` before `main_algorithm`, covering `config.xray_log` plus the configured access/error paths
- [x] write tests for `log_open_error_message` (success cases): a `PermissionDenied` error yields path, uid and chown command; a non-permission error yields the path and the underlying error but no chown line
- [x] write `#[cfg(unix)]`-gated tests: an **existing file chmod'd `0o400`** is rejected (note a `0o500` *directory* does not prevent appending to a file that already exists inside it — directory permissions govern creation, not append); creation inside a `0o500` directory is rejected; a writable target passes; a duplicated path is reported once
- [x] run `cargo test` - must pass before task 6

### Task 6: Stop corvex from creating orphans (PID-file preflight)

**Files:**
- Modify: `src/xray.rs`

corvex has its own orphan-production path, and it is almost certainly how the reporting machine ended up with an untracked xray from Jul 19. `xray::start` spawns the child at `src/xray.rs:375-377`, then writes the PID file at line 385 with `fs::write(...)?`. `fs::write` opens with truncate, which fails with `EACCES` on a **root-owned `xray.pid`** — exactly the state on that machine (`-rw-r--r-- root staff`). The `?` returns immediately and the freshly spawned xray keeps running, untracked, forever. Detection alone would only report the mess this creates; this task stops making it.

- [x] before spawning, verify `config.xray_pid_file` is writable — openable write+create, or removable when it exists and is owned by another user (its directory is user-owned, so unlink generally succeeds where truncate fails) — and fail with a clear message naming the file and `sudo rm <path>` if not
- [x] on that pre-spawn failure, return before `cmd.spawn()` so no untracked process can be created
- [x] keep the existing post-spawn `fs::write` and its `?`, but make the error text say that an xray was started and is now untracked, naming the PID and `sudo kill <pid>` — the window is much smaller after the preflight but is not zero (TOCTOU)
- [x] write tests for the pure message builders (success: preflight message names the pid file and `sudo rm`; post-spawn message names the PID and `sudo kill`)
- [x] write `#[cfg(unix)]`-gated tests: a `0o400` PID file in a writable directory is accepted (removable), a PID file in a `0o500` directory is rejected, a normal writable path passes
- [x] run `cargo test` - must pass before task 7

### Task 7: Verify acceptance criteria

- [ ] verify all requirements from Overview are implemented: start advice never says bare "sudo"; orphan advice never says `corvex stop`; `start`, `stop` and `status` all report surviving processes; defaults are user-writable; unwritable targets fail naming the file; and corvex can no longer spawn an untracked xray via an unwritable PID file
- [ ] verify no code path signals an untracked process: grep `signal::kill` / `force_kill_process` call sites and confirm the set is unchanged from before this branch
- [ ] verify health-check probes are never classified as managed (Task 1 tests plus a manual `CORVEX_DEBUG=1 corvex start` trace showing probe temp configs)
- [ ] run full test suite: `cargo test`
- [ ] run `cargo clippy --all-targets -- -D warnings -A dead_code` (matching CI at `.github/workflows/rust.yml:70`) and `cargo fmt --check` — both clean
- [ ] run `cargo build --release`, and confirm the Windows cfg stubs compile via `cargo check --target x86_64-pc-windows-msvc` if a toolchain is available, otherwise rely on the CI matrix before merge

### Task 8: [Final] Update documentation and release notes

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `RELEASE_NOTES.md`

- [ ] update `README.md:149-150` and the key-paths table to the new log defaults; add a short "recovering from a mixed sudo/user state" section covering `sudo corvex stop` for a tracked process and `sudo kill <pid>` for an orphan
- [ ] update `CLAUDE.md:51` and `CLAUDE.md:99` for the new defaults, and the `xray.rs` architecture note (process listing is read-only, classification is by `-c` config path, sudo/HOME blind spot documented)
- [ ] **prepend** `# Corvex v0.6.3 Release Notes` as line 1 of `RELEASE_NOTES.md` (the `release-guard` job reads `head -1`), covering all four fixes and stating explicitly that existing logs under `/var/log/xray/` are left in place — nothing is moved or deleted, and explicit `log.xray.*` settings still win
- [ ] move this plan to `docs/plans/completed/`

## Post-Completion

*Items requiring manual intervention or external systems - no checkboxes, informational only*

**Manual verification on the affected Mac** (macOS 26.5.2, corvex at `/usr/local/bin/corvex`):

- clear the current mixed state before testing: `sudo corvex stop`, then `sudo kill 7597` for the Jul 19 orphan, then `sudo rm -f ~/.config/xray/xray.pid`
- remove the stale `~/bin/corvex` (0.4.0), which still precedes `/usr/local/bin` in `PATH` and shadows the installed build
- confirm plain `corvex start` shows the osascript password dialog and enables the proxy
- confirm `corvex status` reports a lone tracked process with no orphan noise
- re-test the failure paths deliberately: (a) `sudo corvex start` then plain `corvex start` → message names `sudo corvex stop`, not bare sudo; (b) leave an orphan running, `sudo corvex stop`, then `corvex start` → start-failure diagnostic lists the orphan with `sudo kill <pid>`; (c) `sudo touch ~/.config/xray/xray.pid` to recreate a root-owned PID file, then `corvex start` → refuses **before** spawning, naming the file and `sudo rm`, and `ps` confirms no new xray was left behind

**External system updates:**

- `/etc/newsyslog.d/xray.conf` on the affected Mac rotates `/var/log/xray/*.log` with an empty owner field (`:admin  644`), so rotation recreates them root-owned. Users who keep explicit `/var/log/xray` paths in `corvex.json` need `<user>:admin  664` for rootless operation to survive rotation. The new defaults sidestep this entirely; the README note should mention it for users who deliberately log to `/var/log`.
- after upgrading, existing installs without an explicit `log.xray` config start writing to `$XDG_STATE_HOME/xray/` — historical logs stay in `/var/log/xray/` and are not migrated, so `corvex logs` will look empty at first. This must be stated in the release notes.
- releasing v0.6.3 remains tag-driven (`git tag v0.6.3 && git push origin v0.6.3`); never `gh release create/edit`
