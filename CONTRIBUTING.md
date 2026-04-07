# Contributing

## Windows Testing

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
| `src/xray.rs` | `#[cfg(windows)]`: `is_process_alive`, `stop_process`, `ensure_installed` |
| `src/config.rs` | Paths use `%APPDATA%` and `%LOCALAPPDATA%` |
| `src/health.rs` | `#[cfg(windows)]` OpenOptions without `.mode()` |
| `src/engine/awg.rs` | `awg-quick` install via `winget install AmneziaVPN.AmneziaWG` |

### Troubleshooting

- **Registry access denied** -- run terminal as Administrator
- **xray not found** -- `winget install --silent xray` or add to PATH
- **awg-quick not found** -- `winget install --silent AmneziaVPN.AmneziaWG`
- **Empty DNS discovery** -- normal without VPN/domain; `discover_corporate_dns` returns an error
