# Finalize and Merge feature/init Branch

## Overview
- Commit remaining uncommitted changes, clean up the repo, and squash-merge feature/init into main
- Produces a clean single-commit main branch ready for remote push
- Covers: uncommitted code, .gitignore updates, test/lint verification, squash merge

## Context (from discovery)
- Branch: `feature/init` (4 commits, no main branch exists yet)
- Uncommitted changes: Cargo.toml, Cargo.lock, src/dns.rs, src/vless.rs (dns_out tag, port/skipFallback fields, preserve_order feature)
- Untracked files: `.claude/`, `config.json_temp`, `xray-proxy` binary
- No git remote configured (user will add later)
- .gitignore only has `/target`

## Development Approach
- **testing approach**: Regular (verify all tests pass before merge)
- Complete each task fully before moving to the next
- All tests must pass before squash merge

## Progress Tracking
- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with + prefix
- Document issues/blockers with warning prefix

## Implementation Steps

### Task 1: Commit remaining changes

**Files:**
- Modify: `.gitignore`
- Modify: `Cargo.toml` (already modified, just staging)
- Modify: `Cargo.lock` (already modified, just staging)
- Modify: `src/dns.rs` (already modified, just staging)
- Modify: `src/vless.rs` (already modified, just staging)

- [ ] Add `xray-proxy` and `config.json_temp` to `.gitignore`
- [ ] Stage and commit `.gitignore` changes
- [ ] Stage and commit Cargo.toml, Cargo.lock, src/dns.rs, src/vless.rs (dns_out tag, port/skipFallback, preserve_order)

### Task 2: Verify quality

- [ ] Run `cargo test` — all tests must pass
- [ ] Run `cargo clippy` — no warnings
- [ ] Run `cargo fmt --check` — properly formatted

### Task 3: Squash-merge into main

- [ ] Create `main` branch as orphan or at initial point
- [ ] Squash all feature/init commits into a single commit on main
- [ ] Commit message: "Rust CLI tool for managing Xray proxy and macOS system proxy"
- [ ] Verify main has single clean commit with all code

### Task 4: Clean up

- [ ] Verify `main` branch has correct content (`cargo test` on main)
- [ ] Delete `feature/init` branch after merge
- [ ] Confirm repo is on `main` branch and clean

## Post-Completion

**Manual steps:**
- Add git remote when ready: `git remote add origin <url>`
- Push main: `git push -u origin main`
