# Corvex v0.7.0 Release Notes

`corvex start` works again on machines whose shell exports a proxy, it now writes a real log of what it did, and a new `corvex dns` command diagnoses the network path to your resolvers.

## Security

### Subscription tokens were written to the log at the default level

When a subscription failed to download, the warning printed the subscription URL in full:

```
[WARN] subscription https://panel.example/sub/9f3c…/ failed: failed to fetch …
```

Subscription panels put the access token in the URL path, so that line published a credential — at `warn`, which was the default level, so it needed no debugging flag to appear. Anyone who pasted a failing `corvex start` into a bug report or a chat message handed over their subscription along with it.

corvex now reduces every subscription URL it mentions to scheme and host, replacing the rest with a marker:

```
[WARN] subscription https://panel.example/<redacted> failed: failed to fetch https://panel.example/<redacted>: dns error: no record found
```

This applies to every path that names a subscription — progress lines, success lines and errors alike — and a URL corvex cannot parse is rendered as `<redacted>` alone rather than echoed back. Two different subscriptions are still told apart by their host, which is all a diagnostic line needs.

**If you have shared corvex output before upgrading, treat the token in it as exposed and rotate it with your panel.** Because the leak predates this release, it can also be sitting in your shell scrollback or terminal logs.

## Fixes

### `corvex start` deadlocked against its own proxy

If your shell exported `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY` pointing at corvex's own port — a very common setup, since that is the port corvex configures — then `corvex start` tried to download your subscription *through the tunnel it was in the middle of starting*. Nothing was listening yet, so the fetch sat until it timed out and the start died with:

```
timeout: global
Error: no supported proxy servers found in subscriptions
```

The confusing part was that it did not always fail. A leftover xray from a previous session happened to serve the request, so `corvex restart` looked fine while `corvex stop` followed by `corvex start` did not. It also explained a second symptom that looked unrelated: with the start aborting at the subscription step, it never reached the point of enabling the system proxy, so the macOS Proxy pane showed every switch off.

Subscription downloads now ignore the environment's proxy settings entirely. The fetch is what brings the tunnel up, so it must never travel through it. Nothing else about downloads changed — the same timeout, the same body cap, the same headers.

If you genuinely need an upstream proxy for subscription downloads, say so in an issue; it would be an explicit setting rather than a silent read of the environment.

### `corvex.log` was never actually written

corvex worked out where its log file should live and created the directory for it, and then never opened it. The file simply did not exist. On top of that, every progress line was logged at `debug` while the default level was `warn`, so a successful start printed nothing and a slow one printed nothing either — a start stuck downloading a subscription and a start stuck testing servers looked exactly alike.

Both halves are fixed:

- corvex now writes `$XDG_STATE_HOME/corvex/corvex.log` (`%LOCALAPPDATA%\corvex\corvex.log` on Windows), appending to it and mirroring every log line to the terminal (command output on stdout — `status`, `dns`, the green start confirmations — stays terminal-only). The file is created with mode `0600` — owner-only — and a file already at that path with a looser mode is tightened on the next run. Past 5 MB it is rotated to `corvex.log.1`.
- The default level is now `info`, and each phase of a start reports what it did and how long it took:

```
2026-08-24T09:12:04Z [INFO] subscription downloaded: 4821 bytes from https://panel.example/<redacted> (612ms)
2026-08-24T09:12:07Z [INFO] engine selected: xray (json subscription entry)
2026-08-24T09:12:08Z [INFO] xray started: PID 40321 (1.03s)
2026-08-24T09:12:09Z [INFO] proxy applied: Wi-Fi -> 127.0.0.1:21080 (1.02s)
2026-08-24T09:12:09Z [INFO] start complete (6.29s)
```

If the log file cannot be opened or written, corvex says so once and carries on with terminal output only — logging never aborts a command. `RUST_LOG=warn` turns the narration off; note that it is now *quieter* than the old default, because the server-testing progress lines used to bypass the log level and now go through it.

Note that `corvex logs` still tails the **xray** log, not this one; read `corvex.log` directly.

## New

### `corvex dns` — diagnose the path to your resolvers

```
$ corvex dns
Settings: /home/you/.config/corvex/corvex.json

Resolver: domain corp.example.com on en0
  10.10.20.53  via 10.10.99.1 on en0  UNREACHABLE NEXT HOP: gateway 10.10.99.1 is outside en0's subnet, probe skipped
  10.10.20.54  via 192.0.2.1 on en0  answered in 34ms

Resolver: global (no domain scope) on en0
  192.0.2.1  directly connected on en0  answered in 4ms
  fe80::1%en0  not diagnosed: the route check and the probe are IPv4-only
```

For each nameserver the system is configured to use, `corvex dns` reads the route to it, finds the interface that route names, checks whether the gateway is on that interface's subnet, and — if it is — sends a real DNS query and times the answer.

The on-link check is the point of the command. It comes from a real incident: a stale VPN host route pointed two corporate nameservers at a gateway that was not on the wire for the interface the route named, so ARP never resolved and every query died with `sendto: Network is unreachable`. No firewall rule was involved, which is exactly why it took so long to find — the route existed, the interface was up, the nameservers were correct, and each layer looked healthy on its own.

A few things worth knowing:

- It is entirely read-only, and exits successfully even when it finds a problem. A resolver that does not answer is reported as `no answer: <cause>`, one whose route cannot be read as `no route: <cause>`, and the walk continues either way, so the working half of a failover pair is never hidden behind the broken half.
- The check is IPv4-only and never invents a fault: when the subnet arithmetic cannot be done — an unreadable interface address, or an interface whose addresses are all `/32`, as a point-to-point `utun`/`wg` is — the next hop is called reachable and the probe runs anyway. A `/32` alongside a real subnet does not count: the subnet still decides. A nameserver that is not an IPv4 literal, such as the `fe80::1%en0` an RDNSS-advertising router leaves in `scutil --dns`, is listed as `not diagnosed` rather than walked. Every probe asks for `example.com` (RFC 2606), never a name of yours.
- **corvex does not change routes and will not.** A stale route is fixed at the VPN client that installed it — usually by dropping a redundant per-host `route` directive from the profile when a covering network route already exists.
- The listing itself got better on macOS as part of this: corvex previously kept only the first nameserver of each resolver and ignored any resolver without a domain scope, which meant it could not see the second half of a failover pair or your machine's primary resolver at all.
- On Linux the listing is narrower (one nameserver per search domain, no interface name, no global resolver) because the `resolvectl` side still has that limitation; the next-hop check and the probe work fully. On Windows the command reports that it is not implemented — every other command is unaffected.

## Migration

corvex.json needs no changes. Five behavior changes to be aware of:

- corvex is more talkative on the terminal by default (`RUST_LOG=warn` silences it, and then some — the server-testing progress lines used to ignore the log level).
- Subscription downloads no longer honour `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`.
- **corvex now refuses to write into a directory other accounts can tamper with.** Everything it writes without asking you where — `config.json`, `xray.pid`, `corvex.log`, and `xray.log` with the default `access.log`/`error.log` beside it — is now written only after every directory from it up to `/` has been checked: each must be owned by you (or root) and grant write to nobody else. A chain that fails is a hard error naming the directory and the `chmod go-w` that fixes it.

  Two exceptions keep the ordinary cases working. Sticky directories such as `/tmp` (1777) pass, because sticky is exactly what stops one user replacing another's entry. And the group write bit passes when the group is your own private group — `gid == euid`, no other members listed, and no POSIX ACL on the directory — which is the default shape of a Debian or Ubuntu home, where `pam_umask` gives you umask 002 precisely because your primary group holds you alone. On macOS, where every local account shares `staff`, a group-writable directory is still refused.

  If you hit this, the fix is usually the `chmod go-w` in the message. When it is a directory you would rather not change, point `XDG_CONFIG_HOME` and `XDG_STATE_HOME` somewhere you own. A log directory you named yourself in `log.xray.*` is exempt — that path is yours to place, `/var/log/xray` included.
- **Windows: the fallback location for corvex's files moved off `C:\Users\Public`.** This affects you only if `%APPDATA%` or `%LOCALAPPDATA%` is unset — where they are set, nothing moves. Previously an unset variable fell back to `C:\Users\Public\AppData\Roaming` (corvex.json, the generated xray config) and `C:\Users\Public\AppData\Local` (the logs). `Public` grants every account on the machine full access by inheritance, so the generated `config.json` — which carries your VLESS UUID or Trojan password — was readable by anyone who could log in, and the directories were plantable before corvex ever created them. The fallback is now `%USERPROFILE%\AppData\Roaming` and `%USERPROFILE%\AppData\Local`, which belong to you.

  If you were relying on the old fallback, corvex will not find your existing `corvex.json` and will start from a default: move it from `C:\Users\Public\AppData\Roaming\corvex\corvex.json` to the same path under `%USERPROFILE%`, or set `%APPDATA%` and `%LOCALAPPDATA%` explicitly. With `%USERPROFILE%` unset as well, corvex now **refuses** to write rather than fall back to `%TEMP%`, which on a service account is the machine-wide `C:\Windows\Temp`; the error names the variables to set.
- The line that reports a failed command changed shape, for **every** command and not just `start`. It used to be `Error: <message>` and is now a log record — `2026-08-24T09:12:09Z [ERROR] <message>` — so that the failure which ended a run is recorded in `corvex.log` rather than only on the terminal. A script matching `^Error:` on stderr needs updating; the exit status is unchanged. Under `RUST_LOG=off`, where no log record would be emitted, the old `Error: <message>` line is printed instead.

# Corvex v0.6.5 Release Notes

A small bug-fix release. When a subscription fails to download, corvex now tells you why.

## Fixes

### "failed to fetch" said nothing about what had actually failed

When a subscription URL could not be downloaded, the warning repeated the URL back at you and stopped there:

```
[WARN] subscription https://panel.example/sub/abc failed: failed to fetch https://panel.example/sub/abc
Error: no supported proxy servers found in subscriptions
```

The real reason was discarded before it reached the screen. Whether the host name failed to resolve, the connection was refused, or the secure channel could not be set up, you saw the same line — which made a blocked panel, a mistyped URL, and a network that was simply down all look identical.

The warning now carries the full chain of causes, so the same failure reads:

```
[WARN] subscription https://panel.example/sub/abc failed: failed to fetch https://panel.example/sub/abc: dns error: no record found
```

## Migration

corvex.json needs no changes.

# Corvex v0.6.4 Release Notes

A bug-fix release. Starting corvex as a normal user on macOS now asks for your password **once** instead of six times.

## Fixes

### The password dialog appeared six times on every start

Enabling the system proxy takes six separate `networksetup` calls (address and on-switch for SOCKS, HTTP, and HTTPS). Each one hit "Command requires admin privileges" on its own, and each one independently opened its own `osascript` authorization dialog — so `corvex start` asked for the same password six times in a row. `corvex stop` asked three times.

The reason the dialogs never collapsed is that macOS marks the underlying `system.privilege.admin` right as unshared, so authorizing one process grants nothing to the next one. Six processes meant six prompts.

corvex now runs the whole group inside a single `osascript` invocation, so macOS asks once: one dialog for `start`, one for `stop`. Running as root still asks nothing at all.

Note that this dialog asks for a password and cannot offer Touch ID — that right is password-only, and no corvex setting changes it. See the README for why using Touch ID would mean elevating through `sudo` and what that would cost.

### Failed proxy changes could be reported as success

`networksetup` sometimes prints `** Error: ...` while still exiting with a success status. corvex checked for that on one output stream but not the other, so an error written only to the error channel with a successful exit code was read as "worked". The same gap existed after an authorized dialog: only the exit status was checked, so with the commands now chained together, one failing setting could be hidden behind the ones that ran after it — corvex would print `proxy enabled` while, say, the HTTPS proxy had never been set.

corvex now treats `** Error` on either output channel as a real failure, before and after authorization. A proxy change that does not apply is reported instead of silently passing.

### Clearer messages when a proxy change does not complete

- Canceling the password dialog previously always said "proxy settings were not changed". corvex now only says that when nothing had been applied yet, and tells you settings may already have changed when that is possible.
- When one command in the group fails, the error now makes clear that the commands run in order and stop at the first failure, rather than listing every command as though all of them ran.

## Migration

corvex.json needs no changes.

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

One thing to know before using those commands: `kill` stops the process and nothing else, so your system proxy stays switched on and still points at `127.0.0.1:<port>`. If the process you killed was the one serving that port, everything using the system proxy fails with connection errors until you run `corvex start` again — and `corvex stop` will not clear it either, since with no xray running it reports `xray is not running` and returns before disabling the proxy. Usually this does not arise, because an orphan is normally not the process holding your port (two xray instances cannot both bind it). For a tracked process, prefer `sudo corvex stop`, which disables the proxy as part of stopping.

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
