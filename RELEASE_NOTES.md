# Corvex v0.6.3 Release Notes

A bug-fix release that finishes the rootless-start work started in 0.6.1: `corvex start` can now recover fully on a machine that has ever run `sudo corvex start`, instead of needing `sudo` forever.

## Fixes

### The sudo advice used to make things worse
When `start` found an xray already running as another user (typically root, left over from an earlier `sudo corvex start`), it said "try again with sudo". Doing that started a second root-owned xray, so the next plain `corvex start` failed the exact same way — you were stuck running everything with `sudo`.

corvex now tells you what actually fixes it: run `sudo corvex stop` once, then plain `corvex start`. It also says explicitly not to run `sudo corvex start` again, since that recreates the problem. (On Linux, `sudo` can reset `HOME` to `/root`, in which case `sudo corvex stop` looks at root's own state and reports xray isn't running while a root-owned one still is — if that happens, use `sudo kill <pid>` with the PID from `corvex status` instead.)

When `start` fails for any reason, it now always names the configured port and the log file it checked, and lists any xray processes it found running (with PID, owner, and which config file each one uses) so you can tell whether one of them is already using your port.

### Orphaned xray processes were invisible
corvex only ever tracked the one xray process recorded in its own PID file. If a second xray ended up running against the same config — for example after a crash, or from the bug described below — corvex had no way to see it. `stop` reported a clean stop while the extra process kept holding the proxy port, and the next `start` then failed with an unrelated-looking "xray failed to start" error.

corvex now looks for other xray processes running against its own config file. This is read-only: it only ever signals the one process it tracks, never anything else. `status` lists any it finds, a successful `stop` now warns if one survives instead of claiming a clean stop, and each one comes with the exact command to remove it — `sudo kill <pid>`, or plain `kill <pid>` if you own it.

### corvex could create an orphan itself
`start` used to launch xray first and write its PID file second. If the PID file could not be written — for example a root-owned `xray.pid` left over from an earlier `sudo` run — the xray that had just started kept running, untracked, forever. This is very likely how orphaned processes were appearing in the first place.

corvex now checks that it can write the PID file before starting xray, and refuses to start — naming the file and the fix — if it cannot.

### Xray logs defaulted to a directory you can't write to
Xray's default log files used to be `/var/log/xray/access.log` and `/var/log/xray/error.log`, which a normal user cannot write to. When xray could not open its log, it exited immediately, and corvex reported the unhelpful "xray failed to start - check the log" — pointing at a file that was never created.

Xray logs now default to your user state directory instead: `$XDG_STATE_HOME/xray/` on Linux/macOS (typically `~/.local/state/xray/`), `%LOCALAPPDATA%\xray\` on Windows. corvex also checks its log files before starting xray, so an unwritable one is now reported by name, with the fix, instead of blaming "the log" in general.

**If you already set `log.xray.access`/`log.xray.error` explicitly in `corvex.json`, nothing changes — your setting still wins.** Existing log files under `/var/log/xray/` are left exactly where they are; corvex never moves or deletes them. If you were relying on the old default and don't set `log.xray` yourself, `corvex logs` may look empty right after upgrading — new logging starts at the new location, and the old history is still sitting under `/var/log/xray/`.

## Upgrading from a mixed sudo/user state

Same recovery as 0.6.1, now backed by better diagnostics: run `sudo corvex stop` once to retire any root-owned xray, use `sudo kill <pid>` for any orphan that `corvex status` or a failed `start` reports, and go back to plain `corvex start` from now on — never `sudo corvex start`. If `sudo corvex stop` reports xray isn't running but `corvex status` still shows a root-owned process, `sudo` reset your environment — use `sudo kill <pid>` directly, or `sudo -E corvex stop`.

## Migration

corvex.json needs no changes. If you want to keep using your existing `/var/log/xray/` logs, set `log.xray.access`/`log.xray.error` explicitly.

# Corvex v0.6.2 Release Notes

A bug-fix release for the 0.6.x line.

## Fixes

### `corvex stop` stops xray before touching the system proxy
`corvex stop` now stops the xray process first and disables the system proxy (and stops an AWG tunnel, if one is running) only after the stop succeeded. Previously the proxy was disabled first, so a failed stop — for example, xray started with `sudo` while `corvex stop` runs as a regular user — left you with the proxy already off (after typing the admin password) while xray kept running.

Now, when stopping xray fails for any reason, corvex reports the error and changes nothing: no password prompts, proxy and AWG tunnel stay as they were.

Trade-off: if xray is not running but the proxy is still enabled (for example, after a crash), `corvex stop` reports `xray is not running` and leaves the proxy on. To clean up, run `corvex start` followed by `corvex stop`, or `sudo corvex stop` for a root-owned instance. Likewise, if disabling the proxy fails after xray already stopped (for example, a cancelled password prompt), the AWG tunnel is left running; the same `corvex start` + `corvex stop` recovery applies.

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
