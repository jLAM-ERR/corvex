# Contributing

## Development setup

A stable [Rust toolchain](https://rustup.rs) is all you need:

```bash
cargo build           # Build
cargo run -- --help   # Run the CLI from the checkout
```

For shell-script changes, `shellcheck` is recommended (`brew install shellcheck`).

## Test gates

Every change must keep all of these green — CI enforces them on macOS, Linux, and Windows:

```bash
cargo test                                # Unit tests
cargo clippy -- -D warnings -A dead_code  # Lint (warnings are errors)
cargo fmt --check                         # Formatting
shellcheck install.sh                     # When touching install.sh
```

## Code conventions

- Parsing and message-building logic lives in pure functions taking `&str`/`&serde_json::Value` — unit-testable without network or system calls.
- Prefer the Rust standard library over hand-written helpers when it already provides the functionality.
- Every code change ships with tests in the same commit: success and error cases, environment-independent (no reliance on installed binaries or network).
- corvex never installs software at runtime — dependency installation belongs to `install.sh`.
- The loopback/RFC1918 → direct routing rule is always rule 0 and must never be displaceable by any feature.

## Workflow

- `main` is protected: changes land via PRs (squash merge) from feature branches.
- One CI run per PR and one per version tag — branch pushes and merges trigger nothing.
- Larger features go through a reviewed plan in `docs/plans/` first; completed plans move to `docs/plans/completed/`.

## Releases

1. Create a release branch, bump the version in `Cargo.toml`, and update `RELEASE_NOTES.md` (its header must mention the new version — CI's release guard checks this).
2. Merge the release PR into `main`.
3. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`. The workflow builds macOS/Linux/Windows binaries, composes the release body from `RELEASE_NOTES.md` plus generated notes, and publishes the GitHub release.
4. Never create releases manually with `gh release create` — releases are immutable, and a release published without assets can never receive them (its tag name is burned permanently).

## Windows testing

### Prerequisites

```powershell
winget install Rustlang.Rustup
rustup default stable
```

### Build and test

```powershell
cargo build
cargo test
cargo clippy
cargo fmt --check
```

### Manual platform verification

#### DNS discovery

```powershell
# Compare corvex output with system
cargo run -- status
ipconfig /all | findstr "DNS Suffix"
ipconfig /all | findstr "DNS Servers"

# Check NRPT rules (domain-joined machines)
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig" /s
```

#### Proxy control

```powershell
cargo run -- start

# Verify registry
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer
netsh winhttp show proxy

cargo run -- stop

# Verify cleared
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable
```

#### Network detection

```powershell
cargo run -- status
route print 0.0.0.0
```

### Minimal corvex.json for testing

Create `%APPDATA%\corvex\corvex.json`:

```jsonc
{
  "uri": "vless://test-uuid@your-server:443?encryption=none&type=grpc&security=tls&sni=your-server.com#test",
  "proxy": { "port": 21080 }
}
```

### Key platform-specific files

| File | What to verify |
|------|----------------|
| `src/platform/windows.rs` | WinAPI calls: `GetAdaptersAddresses`, registry read/write |
| `src/xray.rs` | `#[cfg(windows)]`: `is_process_alive`, `stop_process`; `ensure_installed` is a presence check only |
| `src/config.rs` | Paths use `%APPDATA%` and `%LOCALAPPDATA%` |
| `src/health.rs` | `#[cfg(windows)]` OpenOptions without `.mode()` |
| `src/engine/awg.rs` | `ensure_awg_installed` is a presence check only — corvex never installs awg |

### Troubleshooting

- **Registry access denied** -- run terminal as Administrator
- **xray not found** -- corvex does not install it; download the Xray release zip and add `xray.exe` to PATH (or `winget install xray` yourself)
- **awg-quick not found** -- corvex does not install it; `winget install AmneziaVPN.AmneziaWG` yourself
- **Empty DNS discovery** -- normal without VPN/domain; `discover_corporate_dns` returns an error
