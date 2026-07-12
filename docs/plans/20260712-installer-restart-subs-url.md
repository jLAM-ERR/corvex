# install.sh Installer, No Auto-Install at Runtime, `restart` Command, `subs-url` Rename

## Overview

Four related changes prepared for v0.6.0 (decided across two brainstorm sessions + plan reviews):

1. **New `install.sh` installer.** No installer exists today; README only documents building from source. `install.sh` installs the latest corvex release binary AND — nix-style dependency resolution — the xray engine binary if missing. Works via `./install.sh` or `curl -fsSL .../install.sh | sh` on macOS and Linux.
2. **No auto-install at runtime, no install tips.** corvex currently runs `brew install xray` / `winget install xray` silently during `start` (same for amneziawg-tools). All of that is deleted. xray missing → one short error pointing to install.sh. AmneziaWG is optional, checked ONLY in the AWG engine path, and NEVER installed by corvex — missing `awg-quick` → error telling the user to install `amneziawg-tools` manually via their package manager, with no direct link. (This supersedes the earlier "install tips" design per user's revdiff annotations.)
3. **New `restart` command.** Full stop + start via the existing `cmd_start` flow; `reload` stays as the cheap SIGHUP path. Includes fixing a pre-existing gap: `cmd_start` does not stop a running AWG tunnel (only `cmd_stop` does), so switching engine modes leaves a stale tunnel up.
4. **Rename `file-url` → `subs-url`.** New primary key `subs-url` with `file-url` kept working forever as a hidden serde alias — zero breakage for existing configs.

Plus CI changes: a Linux (musl) release build so install.sh works on Linux, and workflow trigger cleanup so CI runs once per PR and once per version tag — nothing on branch pushes or merges.

Docs must highlight everywhere: **xray is the default engine; AmneziaWG is an optional alternative installed only manually.**

## Context (from discovery)

- `src/xray.rs:43` — `ensure_installed()`: resolves binary via `resolve_binary()`; on miss, macOS runs brew, Windows runs winget, Linux bails with tips — all replaced by one short error
- `src/engine/awg.rs:188` — `ensure_awg_installed()`: same auto-install pattern for `awg-quick`; called only from the AWG engine branch (verify call site during implementation)
- `src/main.rs:33-48` — `Commands` enum (Start/Stop/Reload/Status/Logs); dispatch at `main.rs:100-106`
- `src/main.rs:396-404` — `main_algorithm()` pre-stops running xray only; AWG-tunnel stop logic lives solely in `cmd_stop` (`main.rs:449-460`)
- `src/settings.rs:11-12` — `#[serde(rename = "file-url")] pub file_url: Option<Vec<String>>`; consumed in `main.rs:126-152`
- `.github/workflows/rust.yml` — release jobs publish `corvex-<ver>-darwin-universal.tar.gz` + `corvex-<ver>-windows-x86_64.zip` (+ `.sha256`) — NO Linux binary today; `on.push` currently fires for `main` and `release/**`, giving redundant runs: a second run per release-branch push (on top of the PR run) and a post-merge run on main that re-tests the tree the PR already validated
- Xray-core releases publish version-less per-platform zips (`Xray-macos-arm64-v8a.zip`, `Xray-macos-64.zip`, `Xray-linux-64.zip`) → `releases/latest/download/` URL works directly; corvex asset names embed the version → install.sh resolves the tag via one GitHub API call
- User preference: use Rust stdlib functionality instead of self-written helpers wherever it exists

## Development Approach

- **execution**: implement via `/IL-workflow:plan docs/plans/20260712-installer-restart-subs-url.md` — it loops the implementer agent through every `[ ]` task, runs the test gate, and marks each `[x]` on completion (requires tmux for agent swarms)
- **testing approach**: Regular (code first, then tests in same task)
- complete each task fully before moving to the next
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task (shell script: `sh -n` + shellcheck if available; Rust: unit tests)
- **CRITICAL: all tests must pass before starting next task** — no exceptions
- **CRITICAL: update this plan file when scope changes during implementation**
- CI gates must stay green: `cargo test`, `cargo clippy -- -D warnings -A dead_code`, `cargo fmt --check`
- maintain backward compatibility (`file-url` alias must keep working)
- prefer Rust stdlib over custom helpers

## Testing Strategy

- **unit tests**: required for every Rust task; error-message content lives in constants/pure builders so tests are environment-independent
- **install.sh**: `sh -n` syntax check (+ `shellcheck` when installed); full behavior verified manually post-merge (Post-Completion)
- **e2e tests**: none in this project

## Progress Tracking

- mark completed items with `[x]` immediately when done
- add newly discovered tasks with ➕ prefix
- document issues/blockers with ⚠️ prefix

## Solution Overview

- **install.sh** (repo root, `#!/bin/sh`, `set -eu`): detect OS/arch via `uname -s`/`uname -m` → download corvex (GitHub API `releases/latest` → `tag_name` via `sed`, then versioned asset URL; verify `.sha256` with `shasum -a 256 -c` on macOS / `sha256sum -c` on Linux) → install to `/usr/local/bin` via `install -m 755` (`sudo` only when the dir isn't writable) → if `command -v xray` fails, download xray from `https://github.com/XTLS/Xray-core/releases/latest/download/<per-platform zip>`, unzip, install alongside. Re-runs: corvex always refreshed to latest (upgrade path); xray skipped when present. Work in `mktemp -d` with `trap` cleanup; polite error if `unzip` missing.
- **runtime**: `ensure_installed` / `ensure_awg_installed` become presence checks with short, message-constant errors. No tip-builder functions, no platform matrices.
- **restart**: `Commands::Restart => cmd_start(&config, &plat)`. Extract `cmd_stop`'s AWG-tunnel block into `stop_awg_if_running(config)` and call it from `cmd_stop` AND from `cmd_start` **before** the `detect_engine_mode` branch (`main.rs:209`). ⚠️ NOT inside `main_algorithm` — in the AWG branch `main_algorithm` runs at `main.rs:252`, *after* `start_tunnel` (`main.rs:220`), so a pre-stop there would tear down the tunnel that was just brought up.
- **subs-url**: field rename to `subs_url` + `#[serde(rename = "subs-url", alias = "file-url")]`. serde rejects configs containing both keys as a duplicate field — acceptable hard error, encoded in a test.
- **CI**: new `release-linux` job (`x86_64-unknown-linux-musl`, static); `on.push` narrowed to tags only.
- Version bump is **not** part of this plan; release to v0.6.0 happens later via the tag-push workflow.

## Technical Details

- xray missing error: `'xray' is not installed — run the corvex installer (install.sh) or see README`
- awg-quick missing error (no URL, manual-only): `'awg-quick' is not installed. AmneziaWG is optional and is never installed by corvex — install amneziawg-tools manually with your package manager.`
- xray asset mapping in install.sh: Darwin+arm64 → `Xray-macos-arm64-v8a.zip`; Darwin+x86_64 → `Xray-macos-64.zip`; Linux+x86_64 → `Xray-linux-64.zip`; anything else → clear unsupported-platform error
- corvex asset mapping: Darwin (any arch) → `corvex-<ver>-darwin-universal.tar.gz`; Linux x86_64 → `corvex-<ver>-linux-x86_64.tar.gz` (new)
- Linux aarch64 is UNSUPPORTED (no corvex arm64 Linux build exists) — platform detection must error clearly on it BEFORE any download; do not list an xray aarch64 asset the corvex step can never reach
- `restart` help text: "Restart xray and re-apply system proxy (full stop + start)"
- Error message `main.rs:129` becomes: `corvex.json must contain "uri" or "subs-url".`
- New workflow triggers: `on: push: tags: ["v*"]` + `pull_request: branches: [main]` + existing `workflow_dispatch`

## What Goes Where

- **Implementation Steps** (`[ ]` checkboxes): code, tests, docs in this repo
- **Post-Completion** (no checkboxes): branch/PR mechanics, manual smoke tests, future release

## Implementation Steps

### Task 1: Create install.sh

**Files:**
- Create: `install.sh`

- [x] platform detection (`uname -s` / `uname -m`) with clear unsupported-platform error (incl. Linux aarch64 — no corvex build for it)
- [x] corvex install: API tag query (`curl` + `sed`, no jq), download versioned tar.gz + `.sha256`, verify checksum, `install -m 755` to `/usr/local/bin` (sudo fallback only when not writable)
- [x] ⚠️ checksum gotcha: the published `.sha256` embeds the bare archive filename (`shasum`/`sha256sum` output) — download the tarball under exactly that name in the same directory or `-c` verification fails
- [x] xray dependency: skip when `command -v xray` succeeds; otherwise download per-platform zip from `releases/latest/download/`, unzip (polite error if `unzip` missing), install alongside corvex
- [x] `mktemp -d` workdir + `trap` cleanup; every failure path prints a manual-install hint
- [x] syntax check `sh -n install.sh` (+ `shellcheck install.sh` if installed) — must pass before task 2

### Task 2: Simplify xray presence check (delete auto-install)

**Files:**
- Modify: `src/xray.rs`

- [ ] rewrite `ensure_installed()`: keep `resolve_binary()` check; on miss, `bail!` with a message constant `'xray' is not installed — run the corvex installer (install.sh) or see README`; delete all brew/winget `Command` invocations and platform `cfg` blocks
- [ ] update the doc comment (both lines `src/xray.rs:41-42` → check-only semantics)
- [ ] write test: missing-binary error message mentions `install.sh` (message constant asserted directly, environment-independent)
- [ ] keep/verify existing found-binary tests (`src/xray.rs:459+`)
- [ ] run tests — must pass before task 3

### Task 3: Simplify AWG presence check (manual install only)

**Files:**
- Modify: `src/engine/awg.rs`

- [ ] rewrite `ensure_awg_installed()`: keep PATH check (`which`/`where`); on miss, `bail!` with message constant (amneziawg-tools, manual, package manager, NO direct link); delete brew/winget invocations
- [ ] change `use log::{debug, info};` (`src/engine/awg.rs:2`) to `use log::debug;` — `info!` only lives in the deleted blocks and the unused import fails `clippy -D warnings`
- [ ] update the doc comment (`/// Ensure awg-quick is installed; auto-install silently if not found.`)
- [ ] verify `ensure_awg_installed` is called only from the AWG engine branch (per design: AWG checked ONLY when engine is awg)
- [ ] write test: missing-binary error message mentions manual install of `amneziawg-tools` and contains no URL
- [ ] run tests — must pass before task 4

### Task 4: Add `restart` command and close the AWG pre-stop gap

**Files:**
- Modify: `src/main.rs`

- [ ] add `Restart` variant to `Commands` enum with help text "Restart xray and re-apply system proxy (full stop + start)"
- [ ] dispatch `Commands::Restart => cmd_start(&config, &plat)` in `run()`
- [ ] extract the AWG-tunnel stop block from `cmd_stop` (`main.rs:449-460`) into `fn stop_awg_if_running(config: &Config)` and call it from `cmd_stop`
- [ ] call `stop_awg_if_running` in `cmd_start` BEFORE the `match detect_engine_mode(...)` branch (`main.rs:209`) — ⚠️ NOT in `main_algorithm`, which runs after `start_tunnel` in the AWG branch and would kill the fresh tunnel
- [ ] ⚠️ note: the AWG pre-stop has no automated test (`stop_awg_if_running` wraps system calls) — the AWG→xray and AWG→AWG manual smoke tests in Post-Completion are the guard
- [ ] write CLI parse test: `corvex restart` → `Commands::Restart` (alongside existing parse tests at `main.rs:664+`)
- [ ] write parse test for error case: unknown command still rejected
- [ ] run tests — must pass before task 5

### Task 5: Rename `file-url` to `subs-url` with legacy alias

**Files:**
- Modify: `src/settings.rs`
- Modify: `src/main.rs`

- [ ] change field to `#[serde(rename = "subs-url", alias = "file-url")] pub subs_url: Option<Vec<String>>` in `src/settings.rs`
- [ ] update all `file_url` references in `src/main.rs` (validation `:127`, error message `:129` → `"uri" or "subs-url"`, subscription flow `:149-152` incl. the `bug:` context string)
- [ ] update ALL remaining `.file_url` field accesses or the build breaks (E0609): `src/settings.rs:163,175,184,202` and the `src/main.rs:676-678` test (`test_settings_validation_requires_uri_or_file_url`, incl. its `_file_url` variable name)
- [ ] update existing settings tests using `file-url` (`src/settings.rs:100,127-129`) to the new key; keep at least one `"file-url"` JSON key in tests (e.g. settings.rs:171/197) as explicit alias coverage
- [ ] write test: config with `subs-url` parses
- [ ] write test: legacy config with `file-url` parses into `subs_url` (backward compat)
- [ ] write test: config with BOTH keys fails with serde duplicate-field error
- [ ] run tests — must pass before task 6

### Task 6: CI — Linux release build and single-trigger cleanup

**Files:**
- Modify: `.github/workflows/rust.yml`

- [ ] add `release-linux` job: `ubuntu-latest`, `needs: [test, release-guard]`, same explicit `if: startsWith(github.ref, 'refs/tags/v') || github.event_name == 'workflow_dispatch'` guard as the sibling release jobs, install `musl-tools`, target `x86_64-unknown-linux-musl`, package `corvex-<ver>-linux-x86_64.tar.gz` + `.sha256` (mirror the macOS Package step), upload artifact
- [ ] add `release-linux` to `publish-release`'s `needs:` (artifact glob already picks up the files)
- [ ] add a Linux snippet (curl | tar + install.sh mention) to the composed release body in the "Compose release body" step
- [ ] narrow triggers: `on.push` → tags `v*` only (drop `branches: [main, "release/**"]`); keep `pull_request` and `workflow_dispatch` — one CI run per PR, one per version tag, none on merge (accepted tradeoff: release branches get no push CI; their PR run + the tag run cover them)
- [ ] validate workflow YAML parses (python3 yaml.safe_load or actionlint if installed) — must pass before task 7

### Task 7: Verify acceptance criteria

- [ ] no `brew`/`winget` install invocations remain anywhere in `src/` (grep)
- [ ] `sh -n install.sh` clean; `corvex restart` works end-to-end locally (manual: start → restart → status)
- [ ] a config using `file-url` still starts (backward compat smoke check)
- [ ] run full test suite: `cargo test`
- [ ] run `cargo clippy -- -D warnings -A dead_code` and `cargo fmt --check`

### Task 8: Update documentation

- [ ] README.md: new "Installation" section with `curl -fsSL https://raw.githubusercontent.com/jLAM-ERR/corvex/main/install.sh | sh`, noting it installs corvex + the xray engine (dependency), re-runs upgrade corvex and skip existing xray; rename current build section (line 14) to "Installation from source" and delete the auto-install claim (line 21)
- [ ] README.md: state xray is the DEFAULT engine in the intro (line 12); AmneziaWG section (line 145-153): "AmneziaWG is an optional alternative engine. corvex never installs it — install amneziawg-tools manually with your package manager."; drop Requirements Homebrew-for-auto-install line (line 188); "How it works" step 5 (line 171) → "Verify: checks the xray binary is present (installed by install.sh)"
- [ ] README.md: add `restart` row to Commands table; switch all `file-url` examples/mentions to `subs-url` (incl. line 122), note `file-url` as deprecated alias
- [ ] CLAUDE.md: same corrections (usage, corvex.json example, architecture notes) + document `install.sh` in the repo layout
- [ ] move this plan to `docs/plans/completed/`

## Post-Completion

**Branch/PR mechanics:**
- work on `feature/installer-restart-subs-url` off `main`; PR to protected main; squash merge

**Manual verification:**
- on a machine without xray: `./install.sh` installs corvex + xray to /usr/local/bin; re-run refreshes corvex and skips xray
- on a machine without xray: `corvex start` errors mentioning install.sh (no brew invocation)
- AWG mode → edit corvex.json to a vless URI → `corvex restart` → old AWG tunnel is down, xray mode active
- AWG config without awg-quick installed → error tells manual amneziawg-tools install, no URL

**Future release:**
- these features ship in v0.6.0 later via the release branch + tag-push workflow (version bump NOT in this plan)
- ⚠️ install.sh's Linux corvex download only works once the FIRST release containing `corvex-<ver>-linux-x86_64.tar.gz` is published (v0.6.0) — document macOS-only until then or note in install.sh error
