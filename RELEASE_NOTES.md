# Corvex Unreleased (next version)

## Changes

### `corvex stop` stops xray before touching the system proxy
`corvex stop` now stops the xray process first and disables the system proxy (and stops an AWG tunnel, if one is running) only after the stop succeeded. Previously the proxy was disabled first, so a failed stop — for example, xray started with `sudo` while `corvex stop` runs as a regular user — left you with the proxy already off (after typing the admin password) while xray kept running.

Now, when stopping xray fails for any reason, corvex reports the error and changes nothing: no password prompts, proxy and AWG tunnel stay as they were.

Trade-off: if xray is not running but the proxy is still enabled (for example, after a crash), `corvex stop` reports `xray is not running` and leaves the proxy on. To clean up, run `corvex start` followed by `corvex stop`, or `sudo corvex stop` for a root-owned instance.

# Corvex v0.6.1 Release Notes

## Highlights

A bug-fix release. `corvex start` now works as a normal user on macOS again — corvex asks for your password with a graphical prompt when it needs to change system proxy settings, instead of failing with a blank error and pushing you toward `sudo`. It also no longer mistakes a copy of xray started by another user for a dead process.

## Fixes

### Rootless start on macOS works again
On current macOS, `networksetup` reports "Command requires admin privileges." on standard output rather than the error channel. corvex only inspected the error channel, so it never recognized the message, skipped its built-in graphical password prompt, and stopped with an empty `networksetup … failed:` error. The most common reaction — re-running with `sudo` — then left an xray process owned by root, which set up the problem below.

corvex now inspects both output channels (and treats an `** Error` on standard output as a failure even when the exit code is zero). When macOS asks for administrator rights to change proxy settings, corvex shows the password dialog and continues. No `sudo` needed for `corvex start`.

### An xray started by another user is recognized as running
corvex checks whether xray is already running by signalling the recorded process. When that process belongs to another user (for example, one started earlier with `sudo`), the operating system answers "not permitted" — the process is alive, just not yours to signal. corvex read that answer as "the process is dead", deleted its record, and started a second xray, which then failed to bind the proxy port with `address already in use`.

corvex now treats "not permitted" as "running":

- `start` reports `xray is already running` instead of starting a duplicate.
- `stop` and `reload` report `xray (PID: N) is running as another user - try again with sudo` and leave the record in place, instead of silently reporting success while the other xray keeps running.

### `corvex --version`
`corvex --version` now prints the version. It previously errored with "unexpected argument '--version'".

### Installer retries downloads
`install.sh` now retries each download up to three times with a connect timeout, so a single dropped connection to GitHub no longer aborts the whole install partway through. A failed checksum download can also no longer be mistaken for a failed archive download.

## Upgrading from a mixed sudo/user state

If you had been starting corvex with `sudo` to work around the macOS proxy error, run `sudo corvex stop` once to retire the root-owned xray, then use plain `corvex start` from now on — a password dialog appears when corvex updates the system proxy.

## Migration

corvex.json needs no changes.
