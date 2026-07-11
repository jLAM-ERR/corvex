# Corvex v0.5.1 Release Notes

## Highlights

Rootless macOS proxy management — no more `sudo` required. Native Touch ID / password dialog for privilege escalation.

This release contains the same code as v0.5.0 plus binary downloads. v0.5.0 was published without binaries due to a release process error — the release was created manually before the build workflow ran, and immutable releases cannot receive assets after publishing. Use v0.5.1 instead of v0.5.0.

## What's New

### Rootless macOS Proxy
corvex no longer requires `sudo` to set system proxy on macOS. When `networksetup` write operations fail due to missing admin privileges, corvex automatically falls back to `osascript` which shows a native macOS authorization dialog (Touch ID or password).

- macOS caches authorization for ~5 minutes — only one dialog per session even though `enable_proxy` makes 6 `networksetup` calls
- `sudo corvex start` bypasses the dialog entirely (direct call succeeds)
- SSH / headless — clear error message: "No GUI session available — run with sudo instead"
- User cancel — clean abort: "Authorization denied — proxy settings were not changed"
- Read operations (`corvex status`) continue to work without any escalation
- Uses full path `/usr/sbin/networksetup` in privileged context to prevent PATH hijacking

### Windows Improvements
- Fixed config paths for `%APPDATA%` / `%LOCALAPPDATA%`
- Reworked xray process lifecycle on Windows (direct `TerminateProcess` instead of unreliable `GenerateConsoleCtrlEvent`)
- Clippy fixes

## Commands

```
corvex start                                    # Shows auth dialog if needed (macOS)
sudo corvex start                               # Bypasses dialog
corvex stop                                     # Same auth behavior
corvex status                                   # No auth needed (read-only)
corvex reload                                   # Validate config, send SIGHUP
corvex logs                                     # Show last 20 log lines
corvex logs -f                                  # Follow log output
corvex --settings /path/to/corvex.json start    # Use custom settings file
CORVEX_DEBUG=1 corvex start                     # Enable debug logging
```

## Migration from v0.4.0 / v0.5.0

No configuration changes required. Existing corvex.json files are fully compatible.
