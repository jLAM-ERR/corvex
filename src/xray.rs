use crate::config::{self, Config};
use anyhow::{Context, Result};
use log::{debug, info};
#[cfg(unix)]
use nix::sys::signal::{self, Signal};
#[cfg(unix)]
use nix::unistd::Pid;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum XrayError {
    #[error("config file not found: {0}")]
    ConfigNotFound(String),
    #[error("xray is already running (PID: {0})")]
    AlreadyRunning(i32),
    #[error("xray is not running")]
    NotRunning,
    #[error("xray failed to start - check the log")]
    StartFailed,
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("xray (PID: {0}) is running as another user - try again with sudo")]
    NotPermitted(i32),
}

/// Resolve an xray executable from PATH or common install locations.
pub fn resolve_binary(xray_bin: &str) -> Option<PathBuf> {
    let bin_path = PathBuf::from(xray_bin);
    if bin_path.is_absolute() || bin_path.components().count() > 1 {
        return bin_path.exists().then_some(bin_path);
    }

    resolve_from_path(xray_bin).or_else(|| resolve_from_common_locations(xray_bin))
}

/// Message shown when the xray binary cannot be found on the system.
pub const XRAY_NOT_INSTALLED_MSG: &str =
    "'xray' is not installed — run the corvex installer (install.sh) or see README";

/// Check if the xray binary is installed; no side effects.
pub fn ensure_installed(xray_bin: &str) -> Result<()> {
    debug!("checking if '{}' is installed", xray_bin);

    if let Some(path) = resolve_binary(xray_bin) {
        debug!("resolved '{}' to {}", xray_bin, path.display());
        return Ok(());
    }

    anyhow::bail!(XRAY_NOT_INSTALLED_MSG)
}

#[cfg(unix)]
fn resolve_from_path(bin: &str) -> Option<PathBuf> {
    let output = Command::new("which").arg(bin).output().ok()?;
    if !output.status.success() {
        return None;
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(PathBuf::from)
}

#[cfg(windows)]
fn resolve_from_path(bin: &str) -> Option<PathBuf> {
    for candidate in windows_binary_candidates(bin) {
        let output = Command::new("where").arg(&candidate).output().ok()?;
        if !output.status.success() {
            continue;
        }

        if let Some(path) = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
        {
            return Some(PathBuf::from(path));
        }
    }

    None
}

#[cfg(unix)]
fn resolve_from_common_locations(_bin: &str) -> Option<PathBuf> {
    None
}

#[cfg(windows)]
fn resolve_from_common_locations(bin: &str) -> Option<PathBuf> {
    let file_name = windows_exe_name(bin);
    let mut candidates = Vec::new();

    if let Ok(program_files) = std::env::var("ProgramFiles") {
        candidates.push(PathBuf::from(&program_files).join("Xray").join(&file_name));
        candidates.push(PathBuf::from(&program_files).join("xray").join(&file_name));
        candidates.push(
            PathBuf::from(&program_files)
                .join("Xray-core")
                .join(&file_name),
        );
    }

    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
        candidates.push(
            PathBuf::from(&local_appdata)
                .join("Programs")
                .join("Xray")
                .join(&file_name),
        );
        candidates.push(
            PathBuf::from(&local_appdata)
                .join("Programs")
                .join("xray")
                .join(&file_name),
        );

        let winget_packages = PathBuf::from(local_appdata)
            .join("Microsoft")
            .join("WinGet")
            .join("Packages");
        if let Some(path) = find_file_in_children(&winget_packages, &file_name) {
            candidates.push(path);
        }
    }

    candidates.into_iter().find(|path| path.exists())
}

#[cfg(windows)]
fn find_file_in_children(root: &Path, file_name: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && path.file_name().and_then(|name| name.to_str()) == Some(file_name) {
            return Some(path);
        }
        if !path.is_dir() {
            continue;
        }

        let direct = path.join(file_name);
        if direct.exists() {
            return Some(direct);
        }

        let nested_entries = fs::read_dir(&path).ok()?;
        for nested in nested_entries.flatten() {
            let nested_path = nested.path();
            if nested_path.is_file()
                && nested_path.file_name().and_then(|name| name.to_str()) == Some(file_name)
            {
                return Some(nested_path);
            }
            if nested_path.is_dir() {
                let deep = nested_path.join(file_name);
                if deep.exists() {
                    return Some(deep);
                }
            }
        }
    }

    None
}

#[cfg(windows)]
fn windows_binary_candidates(bin: &str) -> Vec<String> {
    let mut candidates = vec![bin.to_string()];
    if Path::new(bin).extension().is_none() {
        candidates.push(format!("{bin}.exe"));
    }
    candidates
}

#[cfg(windows)]
fn windows_exe_name(bin: &str) -> String {
    if Path::new(bin).extension().is_some() {
        bin.to_string()
    } else {
        format!("{bin}.exe")
    }
}

/// Reads the PID file and checks if the process is actually running.
/// Cleans up stale PID files.
pub fn is_running(config: &Config) -> Option<i32> {
    let pid_str = match fs::read_to_string(&config.xray_pid_file) {
        Ok(s) => s,
        Err(_) => {
            debug!("no PID file found");
            return None;
        }
    };

    let pid: i32 = match pid_str.trim().parse() {
        Ok(p) => p,
        Err(_) => {
            debug!("invalid PID file content, removing");
            let _ = fs::remove_file(&config.xray_pid_file);
            return None;
        }
    };

    if !is_process_alive(pid) {
        debug!("stale PID file (process {} dead), removing", pid);
        let _ = fs::remove_file(&config.xray_pid_file);
        return None;
    }

    // Guard against PID reuse: a stale xray.pid that outlived a crash or reboot
    // may now point at an unrelated process (possibly owned by another user, so
    // alive but not ours to signal). Confirm the process is actually xray
    // before trusting the PID file, or we would block start/status on a stranger.
    if !process_is_xray(pid, &config.xray_bin) {
        debug!(
            "PID {} is alive but is not xray (reused PID), removing stale PID file",
            pid
        );
        let _ = fs::remove_file(&config.xray_pid_file);
        return None;
    }

    debug!("xray process {} is running", pid);
    Some(pid)
}

#[cfg(unix)]
fn is_process_alive(pid: i32) -> bool {
    // EPERM means the process exists but belongs to another user (e.g. started
    // via sudo) - it is alive, we just cannot signal it. Only ESRCH means dead.
    match signal::kill(Pid::from_raw(pid), None) {
        Ok(()) | Err(nix::errno::Errno::EPERM) => true,
        Err(_) => false,
    }
}

/// Whether the running process `pid` looks like an xray process, used to reject
/// a reused PID from a stale PID file. Works across user boundaries: `ps` can
/// read another user's command even when we cannot signal that process.
#[cfg(unix)]
fn process_is_xray(pid: i32, xray_bin: &str) -> bool {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            command_matches(&String::from_utf8_lossy(&o.stdout), xray_bin)
        }
        // If ps is unavailable or errors, we cannot disprove the identity;
        // assume it is xray so we never delete a live xray's PID file and start
        // a duplicate (the bug this whole check protects against).
        _ => true,
    }
}

#[cfg(windows)]
fn process_is_xray(_pid: i32, _xray_bin: &str) -> bool {
    true
}

/// Does a process command (e.g. from `ps -o comm=`) belong to the xray binary?
/// Compares basenames so a full path like `/opt/.../xray` matches `xray`. The
/// real binary is always named `xray` (short, never truncated by `ps`), so a
/// substring match on the configured basename is reliable.
///
/// The truncation caveat is real, just not for the real binary: on Linux
/// `ps -o comm=` reads /proc/<pid>/comm, which the kernel caps at 15
/// characters, while macOS reports the full path. A configured binary whose
/// name exceeds 15 characters therefore cannot match on Linux. Tests that
/// stand in a fake xray must keep its file name under that limit.
fn command_matches(process_comm: &str, xray_bin: &str) -> bool {
    let comm = process_comm.trim();
    let name = Path::new(comm)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(comm);
    let expected = Path::new(xray_bin)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(xray_bin);
    !name.is_empty() && !expected.is_empty() && name.contains(expected)
}

#[cfg(windows)]
fn is_process_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }

    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    const STILL_ACTIVE: u32 = 259;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32);
        if handle.is_null() {
            return false;
        }
        let mut exit_code: u32 = 0;
        let ok = GetExitCodeProcess(handle, &mut exit_code);
        CloseHandle(handle);
        ok != 0 && exit_code == STILL_ACTIVE
    }
}

/// An xray process found via `ps`, together with the config it was started
/// against. Read-only detection data - never used to signal a process.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct XrayProcess {
    pub(crate) pid: i32,
    pub(crate) user: String,
    pub(crate) config_arg: String,
}

/// Split a `ps -eww -o pid=,user=,args=` line into (pid, user, args), or
/// `None` if it does not have at least a pid and a user field. `args` keeps
/// its original spacing verbatim (only leading whitespace is trimmed) so a
/// config path containing spaces round-trips unchanged.
fn split_ps_line(line: &str) -> Option<(&str, &str, &str)> {
    let line = line.trim_start();
    if line.is_empty() {
        return None;
    }
    let pid_end = line.find(char::is_whitespace)?;
    let (pid, rest) = line.split_at(pid_end);
    let rest = rest.trim_start();
    if rest.is_empty() {
        return None;
    }
    let user_end = rest.find(char::is_whitespace)?;
    let (user, rest) = rest.split_at(user_end);
    let args = rest.trim_start();
    Some((pid, user, args))
}

/// Pure: parse `ps -eww -o pid=,user=,args=` output into every xray process,
/// with the `-c` config argument each one is running. `command_matches` is
/// applied to argv[0] only (the first whitespace token of args) - never to
/// the whole args string, or a later argument that merely mentions the xray
/// binary name would falsely match. `config_arg` is the trimmed remainder
/// after the *first* " -c " separator, so a config path that itself contains
/// the literal " -c " is still captured whole; a line with no " -c " gets an
/// empty `config_arg` and can never be managed.
pub(crate) fn parse_xray_processes(ps_output: &str, xray_bin: &str) -> Vec<XrayProcess> {
    ps_output
        .lines()
        .filter_map(split_ps_line)
        .filter_map(|(pid_str, user, args)| {
            let pid: i32 = pid_str.parse().ok()?;
            let argv0 = args.split_whitespace().next().unwrap_or("");
            if !command_matches(argv0, xray_bin) {
                return None;
            }
            let config_arg = match args.find(" -c ") {
                Some(idx) => args[idx + " -c ".len()..].trim().to_string(),
                None => String::new(),
            };
            Some(XrayProcess {
                pid,
                user: user.to_string(),
                config_arg,
            })
        })
        .collect()
}

/// Processes whose `config_arg` matches corvex's own config path exactly.
/// An empty `config_arg` (no ` -c ` on the command line) never matches, and
/// an empty `config_path` matches nothing rather than every such process.
pub(crate) fn managed_processes(all: &[XrayProcess], config_path: &str) -> Vec<XrayProcess> {
    if config_path.is_empty() {
        return Vec::new();
    }
    all.iter()
        .filter(|p| !p.config_arg.is_empty() && p.config_arg == config_path)
        .cloned()
        .collect()
}

/// Managed processes other than the tracked PID.
pub(crate) fn orphans(
    all: &[XrayProcess],
    config_path: &str,
    tracked: Option<i32>,
) -> Vec<XrayProcess> {
    managed_processes(all, config_path)
        .into_iter()
        .filter(|p| Some(p.pid) != tracked)
        .collect()
}

/// Lists every xray process on the system, read-only - never signals. Fails
/// closed: any `ps` failure yields an empty vec, since an unavailable `ps`
/// must never invent a phantom orphan.
#[cfg(unix)]
pub(crate) fn list_xray_processes(xray_bin: &str) -> Vec<XrayProcess> {
    let output = Command::new("ps")
        .args(["-eww", "-o", "pid=,user=,args="])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            parse_xray_processes(&String::from_utf8_lossy(&o.stdout), xray_bin)
        }
        _ => Vec::new(),
    }
}

#[cfg(windows)]
pub(crate) fn list_xray_processes(_xray_bin: &str) -> Vec<XrayProcess> {
    Vec::new()
}

/// Shown when the tracked xray is owned by another user and `stop` cannot
/// signal it. The only working recovery is a one-time privileged stop
/// followed by a plain start - `sudo corvex start` just recreates the problem
/// with a new root-owned process.
const ROOT_XRAY_ON_START_HINT: &str = "run `sudo corvex stop`, then `corvex start`. \
    Do not run `sudo corvex start` - it starts another root-owned xray and the problem repeats.";

/// Shown for an untracked corvex-managed xray (an orphan). `xray::stop` only
/// ever signals the PID recorded in `xray.pid`, so it cannot touch these -
/// telling the user to run it here would recreate the looping-advice defect.
const ORPHAN_XRAY_HINT: &str =
    "corvex does not track this process (it is not the PID in xray.pid) and cannot stop it.";

/// Message shown when `start` cannot proceed because the tracked xray is
/// owned by another user. `owner` must come from the *full* process list
/// (`list_xray_processes`), not `managed_processes` - under the sudo/HOME
/// blind spot the tracked PID can classify as "other xray", which is exactly
/// the case this message exists for.
pub(crate) fn start_blocked_message(
    pid: i32,
    owner: Option<&str>,
    orphans: &[XrayProcess],
) -> String {
    let owner_desc = match owner {
        Some(user) => format!("as user '{user}'"),
        None => "as another user".to_string(),
    };
    let mut msg =
        format!("xray (PID: {pid}) is already running {owner_desc}; {ROOT_XRAY_ON_START_HINT}");
    if !orphans.is_empty() {
        let listed = orphans
            .iter()
            .map(|p| format!("{} (owner: {})", p.pid, p.user))
            .collect::<Vec<_>>()
            .join(", ");
        msg.push_str(&format!(
            "\nAlso found {} other untracked corvex xray process(es), not affected by \
             `sudo corvex stop`: {listed}.",
            orphans.len()
        ));
    }
    msg
}

/// One line per orphan, each naming the command that removes it: `kill <pid>`
/// when the orphan is owned by the current user, `sudo kill <pid>` otherwise.
/// Worded as a snapshot ("as of now") since `ps` output can be stale by the
/// time the user acts on it and PIDs get reused.
pub(crate) fn orphan_lines(orphans: &[XrayProcess], current_user: &str) -> Vec<String> {
    orphans
        .iter()
        .map(|p| {
            let kill_cmd = if p.user == current_user {
                format!("kill {}", p.pid)
            } else {
                format!("sudo kill {}", p.pid)
            };
            format!(
                "xray (PID: {}, owner: {}) is an untracked corvex-managed process; {ORPHAN_XRAY_HINT} \
                 As of now, this looks safe to stop with `{kill_cmd}` - re-check with `ps -p {}` \
                 first, since this is a snapshot and PIDs can be reused.",
                p.pid, p.user, p.pid
            )
        })
        .collect()
}

/// Diagnostics shown when `xray::start` returns `StartFailed`. Always names
/// the configured port and log path; `StartFailed` also fires on an invalid
/// config, a missing geo asset, or an unwritable log, so the "another xray is
/// holding your port" sentence and the process listing appear only when
/// `all` is non-empty - never asserting a conflict that was not observed.
pub(crate) fn start_failure_diagnostics(
    all: &[XrayProcess],
    port: u16,
    config_path: &str,
    log_path: &Path,
) -> String {
    let mut msg = format!(
        "xray failed to start using config {config_path} on port {port}. Check the log at {}.",
        log_path.display()
    );
    if !all.is_empty() {
        msg.push_str(&format!(
            "\nAnother xray process may already be holding port {port}:\n"
        ));
        for p in all {
            msg.push_str(&format!(
                "  PID {} (owner: {}, config: {})\n",
                p.pid, p.user, p.config_arg
            ));
        }
        msg.pop();
    }
    msg
}

/// Directory where install.sh places geoip.dat/geosite.dat for non-brew setups.
const INSTALLED_ASSET_DIR: &str = "/usr/local/share/xray";

/// Decide whether to override XRAY_LOCATION_ASSET for the spawned xray process.
/// Only applies when the env var is unset AND both geoip.dat and geosite.dat
/// are present in the installer-managed asset dir, so brew/manual installs
/// that already manage their own geo assets are left untouched, and a
/// partially-populated dir doesn't get pointed to.
fn asset_dir_override(env_set: bool, both_dat_files_exist: bool) -> Option<&'static str> {
    if !env_set && both_dat_files_exist {
        Some(INSTALLED_ASSET_DIR)
    } else {
        None
    }
}

/// Verify the PID file can actually be written before spawning xray, so an
/// unwritable `xray.pid` is caught here - before a freshly spawned xray keeps
/// running untracked - rather than after (see the post-spawn `fs::write`
/// below, which this narrows but cannot eliminate). Accepts a file that
/// opens for writing directly, or, failing that, an *existing* file that is
/// both readable and confirmed - by the same liveness check `is_running`
/// already performs - not to track a live xray.
///
/// A file we cannot even read is never removed on a guess: `is_running`
/// treats a read failure exactly like "no PID file" and returns `None`
/// without deleting anything, so an unreadable root-owned `xray.pid` may
/// still be tracking a live xray. An earlier version of this preflight
/// unlinked any existing-but-unwritable file whenever the containing
/// directory allowed it, regardless of whether the file could be read -
/// which could delete a live xray's own PID file and let a second xray spawn
/// in its place, orphaning the first. That is the exact inverse of the bug
/// this preflight exists to prevent.
///
/// Existence is checked with `symlink_metadata`, not `Path::exists`: the
/// latter follows symlinks, so a PID symlink would read as "does not exist"
/// and the "newly created, clean it up" branch would delete the symlink
/// itself instead of the file it had just created.
///
/// The writability probe is `config::open_write_restricted`, not a plain
/// `OpenOptions`, and that is the difference between a preflight and a
/// vulnerability. `xray.pid` sits in the xray config directory, which falls
/// back to a world-writable `/tmp` path exactly as the log does (see
/// `config::open_append_restricted`), and its path is not configurable, so
/// nothing but corvex has any business creating it. A plain open follows a
/// symlink planted there: the probe would create the *target*, and the
/// post-spawn write below would then truncate it and write a PID into it —
/// an arbitrary-file clobber with corvex's privileges, and worse if corvex
/// is running as root.
fn preflight_pid_file(path: &Path, xray_bin: &str) -> Result<()> {
    let existed_before = fs::symlink_metadata(path).is_ok();

    // The refusal is bound, not reduced to `is_ok()`: `open_write_restricted`
    // is where `config::ensure_trusted_ancestry` speaks, and its message is
    // the only one that names the offending directory, its mode and the exact
    // `chmod` that fixes it. Discarding it left every such failure reported as
    // "sudo rm a file that does not exist".
    let refusal = match crate::config::open_write_restricted(path) {
        Ok(_) => {
            if !existed_before {
                let _ = fs::remove_file(path);
            }
            return Ok(());
        }
        Err(e) => e,
    };

    if !existed_before {
        anyhow::bail!(pid_file_unwritable_path_message(path, &refusal));
    }

    // Everything below treats what is at `path` as an ordinary file: it reads
    // it, and on a dead PID removes it. A shape corvex never writes there is
    // refused by name instead, rather than being read through (a symlink's
    // target is someone else's file, and its contents are not a PID corvex
    // wrote) or silently unlinked.
    if let Some(shape) = unsupported_pid_file_shape(path) {
        anyhow::bail!(pid_file_shape_message(path, shape));
    }

    match fs::read_to_string(path) {
        Ok(contents) => {
            if pid_file_tracks_live_xray(&contents, xray_bin) {
                anyhow::bail!(pid_file_tracks_live_process_message(path));
            }
            if fs::remove_file(path).is_ok() {
                // Unlinking the entry only cures a refusal that was *about*
                // the entry - the read-only file in a writable directory this
                // branch was written for. `open_write_restricted` also refuses
                // on a property of the directory *chain*
                // (`config::ensure_trusted_ancestry`), which removing a file
                // inside it does nothing about, and `write_pid_file` makes
                // this very same open *after* `cmd.spawn()`. Returning `Ok`
                // on a chain refusal would hand back a preflight that passed
                // and a start that leaves xray running and untracked - the one
                // outcome this function exists to prevent. So re-probe rather
                // than assume, and report what the open actually said.
                return match crate::config::open_write_restricted(path) {
                    Ok(_) => {
                        let _ = fs::remove_file(path);
                        Ok(())
                    }
                    Err(e) => Err(anyhow::anyhow!(pid_file_unwritable_path_message(path, &e))),
                };
            }
            anyhow::bail!(pid_file_preflight_message(path));
        }
        Err(_) => anyhow::bail!(pid_file_unreadable_message(path)),
    }
}

/// Whether raw PID-file `contents` currently name a live xray process.
/// Mirrors `is_running`'s liveness check with no side effect (no removal),
/// so `preflight_pid_file` can decide whether an unwritable-but-readable
/// file is safe to remove without ever guessing.
fn pid_file_tracks_live_xray(contents: &str, xray_bin: &str) -> bool {
    match contents.trim().parse::<i32>() {
        Ok(pid) => is_process_alive(pid) && process_is_xray(pid, xray_bin),
        Err(_) => false,
    }
}

/// Message for a PID file that was read, shown not to track a live xray, and
/// is still neither writable nor removable. Names `sudo rm`, not `sudo
/// corvex stop`: the file itself is the obstacle, not a running process, and
/// `stop` cannot touch it either.
fn pid_file_preflight_message(path: &Path) -> String {
    format!(
        "PID file {} cannot be written and cannot be removed either (likely owned by another \
         user, e.g. from a prior `sudo corvex start`). Fix with: sudo rm -- {}",
        path.display(),
        config::shell_quote(&path.display().to_string())
    )
}

/// Message for a PID *path* that cannot be written for a reason removing the
/// file would not cure: an untrusted ancestor, a read-only filesystem, an
/// uncreatable parent. Carries the underlying error, because that is where the
/// actionable part lives - `config::ensure_trusted_ancestry` names the
/// offending directory, its mode and the exact `chmod`, and none of that
/// reaches the user otherwise. Deliberately never suggests `sudo rm`: that is
/// advice for a file in the way, and here either there is no file or removing
/// it has already been shown to change nothing.
fn pid_file_unwritable_path_message(path: &Path, err: &std::io::Error) -> String {
    format!(
        "PID file {} cannot be written ({err}), and removing it would not help - the obstacle is \
         the path, not the file. corvex will not start an xray it cannot track.",
        path.display()
    )
}

/// What is at `path`, when it is not the plain file corvex writes there.
/// `None` means an ordinary regular file, which is the only shape the read /
/// remove path below is written for. A dangling symlink counts as a symlink,
/// not as "missing", which is the whole reason this reads
/// `symlink_metadata`.
///
/// Advisory, not the enforcement: `open_write_restricted` already refused
/// this descriptor, and a path checked here and swapped a microsecond later
/// is refused there again on the next open. What this adds is a message that
/// names what is in the way.
fn unsupported_pid_file_shape(path: &Path) -> Option<&'static str> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() {
        return Some("a symbolic link");
    }
    if !metadata.is_file() {
        return Some("not a regular file");
    }
    None
}

/// Message for a PID path holding something other than the regular file
/// corvex writes there. Never suggests `rm` on its own: in the world-writable
/// `/tmp` fallback the thing in the way was planted by someone else, and the
/// point is that corvex neither follows it nor quietly deletes it.
fn pid_file_shape_message(path: &Path, shape: &str) -> String {
    format!(
        "PID file {} is {shape}, and corvex will not write a PID through it. Check what put it \
         there, then remove it with: rm -- {}",
        path.display(),
        config::shell_quote(&path.display().to_string())
    )
}

/// Message for a PID file corvex cannot read at all, so it cannot rule out
/// that it names a live xray. Deliberately never suggests removing it
/// directly - only a manual check first, since deleting it on a guess could
/// orphan a process that is actually still running.
fn pid_file_unreadable_message(path: &Path) -> String {
    format!(
        "PID file {} cannot be read, so corvex cannot tell whether it tracks a running xray. \
         Check with `ps` for a matching xray process before removing it manually - corvex will \
         not remove a PID file it cannot read.",
        path.display()
    )
}

/// Message for a PID file that reads back as a genuinely live xray corvex
/// cannot write to. `is_running` (called earlier in `start`) should already
/// have turned this into `AlreadyRunning` before the preflight ever runs;
/// this message exists so the preflight itself never removes a file naming
/// a live process, regardless of what ran before it.
fn pid_file_tracks_live_process_message(path: &Path) -> String {
    format!(
        "PID file {} names a running xray process that corvex cannot write to, and will not \
         remove since that would orphan it. Stop that xray first, then retry.",
        path.display()
    )
}

/// Write `pid` to the PID file through the same vetted, no-follow open the
/// preflight probes with. `set_len` rather than an `OpenOptions::truncate`
/// for the reason `config::write_restricted` gives: truncation happens inside
/// `open`, before anything has looked at what was opened.
fn write_pid_file(path: &Path, pid: i32) -> std::io::Result<()> {
    let mut file = crate::config::open_write_restricted(path)?;
    file.set_len(0)?;
    std::io::Write::write_all(&mut file, pid.to_string().as_bytes())
}

/// Error text for the post-spawn PID-file write. By this point xray is
/// already running, so simply returning here - like the bug this preflight
/// fixes - would leave it orphaned. Names the PID and the command that
/// reclaims it. The preflight above shrinks this window a lot but cannot
/// close it (a genuine TOCTOU), so the message has to stay honest about what
/// already happened.
fn pid_file_write_failed_message(pid: i32, path: &Path, err: &std::io::Error) -> String {
    format!(
        "xray (PID: {pid}) started, but its PID file {} could not be written ({err}), so corvex \
         does not track it and cannot manage it. Stop it with: sudo kill {pid} (or `kill {pid}` \
         if you own the process)",
        path.display()
    )
}

/// Error text for the (practically unreachable on unix, but real on Windows,
/// where native PIDs are `u32`) case where the spawned PID does not fit in
/// the `i32` corvex tracks internally. xray is already running by this
/// point, so - exactly like the post-spawn write failure above - this has to
/// say so and name a command that reclaims it, using the original `u32`
/// value since it never became an `i32`.
fn pid_out_of_range_message(native_pid: u32) -> String {
    format!(
        "xray started with PID {native_pid}, but that PID does not fit in the range corvex \
         tracks internally, so no PID file was written and corvex does not track this process. \
         Stop it with: sudo kill {native_pid} (or `kill {native_pid}` if you own the process)"
    )
}

/// Start the xray process.
pub fn start(config: &Config) -> Result<i32> {
    if !config.xray_config.exists() {
        return Err(XrayError::ConfigNotFound(config.xray_config.display().to_string()).into());
    }

    if let Some(pid) = is_running(config) {
        return Err(XrayError::AlreadyRunning(pid).into());
    }

    // The PID directory must exist before the preflight runs, not only
    // before the post-spawn write: on a path whose directory does not exist
    // yet, the preflight's create-if-missing open would otherwise fail with
    // NotFound and refuse a start that used to work fine.
    if let Some(pid_dir) = config.xray_pid_file.parent() {
        let _ = crate::config::create_dir_restricted(pid_dir);
    }
    preflight_pid_file(&config.xray_pid_file, &config.xray_bin)?;

    if let Some(log_dir) = config.xray_log.parent() {
        let _ = crate::config::create_dir_restricted(log_dir);
    }

    let xray_bin =
        resolve_binary(&config.xray_bin).unwrap_or_else(|| PathBuf::from(&config.xray_bin));

    info!(
        "spawning xray via {} with config {}",
        xray_bin.display(),
        config.xray_config.display()
    );
    // `config::open_xray_log`, not a bare `OpenOptions`: at corvex's own
    // default path that open is `O_NOFOLLOW`ed and shape-checked like every
    // other file corvex owns, and at a user-configured one it is at least
    // non-blocking, so a FIFO with no reader cannot wedge the spawn instead
    // of failing it.
    let log_file =
        crate::config::open_xray_log(&config.xray_log).context("Failed to open log file")?;
    let log_stderr = log_file
        .try_clone()
        .context("Failed to clone log file handle")?;

    let mut cmd = Command::new(&xray_bin);
    cmd.args(["run", "-c"])
        .arg(&config.xray_config)
        .stdout(log_file)
        .stderr(log_stderr);

    let both_dat_files_exist = Path::new(INSTALLED_ASSET_DIR).join("geoip.dat").is_file()
        && Path::new(INSTALLED_ASSET_DIR).join("geosite.dat").is_file();
    if let Some(dir) = asset_dir_override(
        std::env::var_os("XRAY_LOCATION_ASSET").is_some(),
        both_dat_files_exist,
    ) {
        debug!("setting XRAY_LOCATION_ASSET={}", dir);
        cmd.env("XRAY_LOCATION_ASSET", dir);
    }

    let child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn xray process via {}", xray_bin.display()))?;

    let native_pid = child.id();
    let pid: i32 = native_pid
        .try_into()
        .map_err(|_| anyhow::anyhow!(pid_out_of_range_message(native_pid)))?;
    debug!("xray spawned with PID {}", pid);

    // The same vetted open as the preflight rather than `fs::write`, which
    // follows a symlink at the path and truncates whatever it points at. The
    // window between the two opens is the TOCTOU this write's error message
    // has always been honest about; what changes is that losing that race no
    // longer hands an attacker a write to a file of their choosing.
    write_pid_file(&config.xray_pid_file, pid).map_err(|e| {
        anyhow::anyhow!(pid_file_write_failed_message(
            pid,
            &config.xray_pid_file,
            &e
        ))
    })?;

    debug!("waiting 1s for xray to stabilize");
    thread::sleep(Duration::from_secs(1));

    if is_running(config).is_some() {
        info!("xray still up 1s after spawn (PID {pid})");
        Ok(pid)
    } else {
        let _ = fs::remove_file(&config.xray_pid_file);
        Err(XrayError::StartFailed.into())
    }
}

/// Stop the xray process.
pub fn stop(config: &Config) -> Result<()> {
    let pid = match is_running(config) {
        Some(pid) => pid,
        None => return Err(XrayError::NotRunning.into()),
    };

    stop_process(pid)?;

    for _ in 0..20 {
        thread::sleep(Duration::from_millis(100));
        if !is_process_alive(pid) {
            debug!("xray process {} terminated", pid);
            let _ = fs::remove_file(&config.xray_pid_file);
            return Ok(());
        }
    }

    force_kill_process(pid);
    thread::sleep(Duration::from_millis(100));
    let _ = fs::remove_file(&config.xray_pid_file);
    Ok(())
}

#[cfg(unix)]
fn stop_process(pid: i32) -> Result<()> {
    debug!("sending SIGTERM to xray (PID {})", pid);
    match signal::kill(Pid::from_raw(pid), Signal::SIGTERM) {
        // Keep the PID file: the process is alive, we just lack the rights.
        Err(nix::errno::Errno::EPERM) => Err(XrayError::NotPermitted(pid).into()),
        // ESRCH (already gone) is fine - the wait loop below sees it as dead.
        _ => Ok(()),
    }
}

#[cfg(windows)]
fn stop_process(pid: i32) -> Result<()> {
    // Xray is spawned without CREATE_NEW_PROCESS_GROUP, so terminate directly.
    force_kill_process(pid);
    Ok(())
}

#[cfg(unix)]
fn force_kill_process(pid: i32) {
    debug!("SIGTERM timeout, sending SIGKILL to PID {}", pid);
    let _ = signal::kill(Pid::from_raw(pid), Signal::SIGKILL);
}

#[cfg(windows)]
fn force_kill_process(pid: i32) {
    debug!("force-killing xray (PID {})", pid);
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid as u32);
        if !handle.is_null() {
            TerminateProcess(handle, 1);
            CloseHandle(handle);
        }
    }
}

/// Validate config and send SIGHUP to reload (unix) or restart (windows).
pub fn reload(config: &Config) -> Result<()> {
    debug!("validating config {}", config.xray_config.display());
    let content = fs::read_to_string(&config.xray_config).context("Failed to read config file")?;
    let _: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| XrayError::InvalidConfig(e.to_string()))?;
    debug!("config JSON is valid");

    let pid = match is_running(config) {
        Some(pid) => pid,
        None => return Err(XrayError::NotRunning.into()),
    };

    #[cfg(unix)]
    {
        debug!("sending SIGHUP to xray (PID {})", pid);
        match signal::kill(Pid::from_raw(pid), Signal::SIGHUP) {
            Err(nix::errno::Errno::EPERM) => {
                return Err(XrayError::NotPermitted(pid).into());
            }
            r => r.context("Failed to send SIGHUP to xray")?,
        }
    }

    #[cfg(windows)]
    {
        debug!("restarting xray for reload (PID {})", pid);
        stop(config)?;
        start(config)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_binary_in_path(bin: &str) -> bool {
        resolve_from_path(bin).is_some()
    }

    /// Linux caps /proc/<pid>/comm at 15 characters, so `ps -o comm=` there
    /// reports a truncated name while macOS reports the full path. The real
    /// binary is `xray` and is unaffected, but a fake xray with a long file
    /// name matches on macOS and silently fails on Linux - which is exactly
    /// how a green local run turned into a red ubuntu CI job. Encoded here so
    /// the asymmetry is a test failure rather than a rediscovery.
    #[test]
    fn command_matches_is_defeated_by_linux_comm_truncation() {
        const LINUX_COMM_CAP: usize = 15;
        let truncate = |name: &str| name.chars().take(LINUX_COMM_CAP).collect::<String>();

        let long = "fake_xray_missing_dir_test";
        assert!(long.len() > LINUX_COMM_CAP);
        assert!(
            !command_matches(&truncate(long), &format!("/tmp/{long}")),
            "a name over {LINUX_COMM_CAP} chars cannot match once Linux truncates comm"
        );

        for short in ["xray", "fake_xray_ord", "fake_xray_dir"] {
            assert!(short.len() <= LINUX_COMM_CAP);
            assert!(
                command_matches(&truncate(short), &format!("/tmp/{short}")),
                "{short} must still match after truncation"
            );
        }
    }

    #[test]
    fn test_known_binary_found() {
        #[cfg(unix)]
        assert!(is_binary_in_path("ls"));
        #[cfg(windows)]
        assert!(is_binary_in_path("cmd"));
    }

    #[test]
    fn test_nonexistent_binary_not_found() {
        assert!(!is_binary_in_path("nonexistent_binary_xyz_999"));
    }

    #[test]
    fn test_process_alive_self() {
        assert!(is_process_alive(std::process::id() as i32));
    }

    /// PID 1 (launchd/init) always exists and is owned by root, so signalling
    /// it from an unprivileged test yields EPERM - which must count as alive.
    /// Regression test: EPERM used to be treated as dead, so a root-owned xray
    /// (started via `sudo corvex start`) got its PID file wrongly removed.
    #[test]
    #[cfg(unix)]
    fn test_process_alive_root_owned() {
        assert!(is_process_alive(1));
    }

    #[test]
    fn test_command_matches_xray() {
        assert!(command_matches(
            "/opt/homebrew/Cellar/xray/26.3.27/libexec/xray",
            "xray"
        ));
        assert!(command_matches("xray\n", "xray")); // Linux `ps -o comm=` form
        assert!(command_matches(
            "/opt/homebrew/bin/xray",
            "/opt/homebrew/bin/xray"
        )); // full-path xray_bin
    }

    #[test]
    fn test_command_matches_rejects_other_processes() {
        assert!(!command_matches("/bin/zsh", "xray"));
        assert!(!command_matches("/usr/sbin/sshd", "xray"));
        assert!(!command_matches("", "xray"));
    }

    /// A stale PID reused by an unrelated process must not be reported as xray.
    /// Our own test binary stands in for the reused-PID process; its command is
    /// not xray, so process_is_xray must reject it (Codex PR #10 P2).
    #[test]
    #[cfg(unix)]
    fn test_process_is_xray_rejects_self() {
        assert!(!process_is_xray(std::process::id() as i32, "xray"));
    }

    #[test]
    fn test_process_dead_after_exit() {
        let mut child = Command::new(if cfg!(windows) { "cmd" } else { "true" })
            .args(if cfg!(windows) {
                &["/C", "exit"][..]
            } else {
                &[][..]
            })
            .spawn()
            .expect("failed to spawn test process");
        let pid = child.id() as i32;
        child.wait().expect("failed to wait for test process");
        assert!(!is_process_alive(pid));
    }

    #[test]
    fn test_ensure_installed_known_binary() {
        #[cfg(unix)]
        let result = ensure_installed("ls");
        #[cfg(windows)]
        let result = ensure_installed("cmd");
        assert!(result.is_ok());
    }

    #[test]
    fn test_ensure_installed_missing_binary_message() {
        let result = ensure_installed("nonexistent_binary_xyz_999");
        let err = result.expect_err("missing binary must error");
        assert_eq!(err.to_string(), XRAY_NOT_INSTALLED_MSG);
    }

    #[test]
    fn test_xray_not_installed_msg_mentions_install_sh() {
        assert!(XRAY_NOT_INSTALLED_MSG.contains("install.sh"));
    }

    #[test]
    fn test_asset_dir_override_env_unset_both_dat_files_exist() {
        assert_eq!(
            asset_dir_override(false, true),
            Some("/usr/local/share/xray")
        );
    }

    #[test]
    fn test_asset_dir_override_env_unset_dat_files_missing() {
        assert_eq!(asset_dir_override(false, false), None);
    }

    #[test]
    fn test_asset_dir_override_env_set_both_dat_files_exist() {
        assert_eq!(asset_dir_override(true, true), None);
    }

    #[test]
    fn test_asset_dir_override_env_set_dat_files_missing() {
        assert_eq!(asset_dir_override(true, false), None);
    }

    // -- parse_xray_processes / managed_processes / orphans --

    #[test]
    fn test_parse_xray_processes_corvex_own_line_is_managed() {
        let ps_output =
            "12345 alice   /opt/homebrew/bin/xray run -c /Users/alice/.config/xray/config.json\n";
        let all = parse_xray_processes(ps_output, "xray");
        assert_eq!(all.len(), 1);
        let managed = managed_processes(&all, "/Users/alice/.config/xray/config.json");
        assert_eq!(managed.len(), 1);
        assert_eq!(managed[0].pid, 12345);
        assert_eq!(managed[0].user, "alice");
    }

    #[test]
    fn test_parse_xray_processes_health_probe_parsed_but_not_managed() {
        let ps_output =
            "23456 alice   /opt/homebrew/bin/xray run -c /var/folders/xx/yy/tmpABC123.json\n";
        let all = parse_xray_processes(ps_output, "xray");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].config_arg, "/var/folders/xx/yy/tmpABC123.json");
        let managed = managed_processes(&all, "/Users/alice/.config/xray/config.json");
        assert!(managed.is_empty());
    }

    #[test]
    fn test_parse_xray_processes_third_party_config_not_managed() {
        let ps_output =
            "34567 root    /opt/homebrew/bin/xray run -c /opt/homebrew/etc/xray/config.json\n";
        let all = parse_xray_processes(ps_output, "xray");
        let managed = managed_processes(&all, "/Users/alice/.config/xray/config.json");
        assert!(managed.is_empty());
        assert_eq!(all[0].user, "root");
    }

    #[test]
    fn test_parse_xray_processes_config_path_with_space_is_matched() {
        let config_path = "/Users/alice/My Configs/config.json";
        let ps_output = format!("100 alice   /opt/homebrew/bin/xray run -c {config_path}\n");
        let all = parse_xray_processes(&ps_output, "xray");
        assert_eq!(all[0].config_arg, config_path);
        let managed = managed_processes(&all, config_path);
        assert_eq!(managed.len(), 1);
    }

    #[test]
    fn test_parse_xray_processes_padded_pid_and_tab_separated_columns() {
        // real `ps -eww` right-justifies the pid column with leading spaces;
        // this also checks tab works as a column separator (args themselves
        // still use plain spaces, as any real command line does)
        let ps_output = "   900\tfrank\t/opt/homebrew/bin/xray run -c /path/to/config.json\n";
        let all = parse_xray_processes(ps_output, "xray");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].pid, 900);
        assert_eq!(all[0].user, "frank");
        assert_eq!(all[0].config_arg, "/path/to/config.json");
    }

    /// Regression guard for the first-vs-last ` -c ` split: a config path
    /// that itself contains the literal " -c " must still be captured whole.
    #[test]
    fn test_parse_xray_processes_config_path_containing_literal_dash_c_is_matched() {
        let config_path = "/Users/alice/my -c dir/config.json";
        let ps_output = format!("200 alice   /opt/homebrew/bin/xray run -c {config_path}\n");
        let all = parse_xray_processes(&ps_output, "xray");
        let managed = managed_processes(&all, config_path);
        assert_eq!(managed.len(), 1);
        assert_eq!(managed[0].config_arg, config_path);
    }

    #[test]
    fn test_parse_xray_processes_empty_output() {
        assert!(parse_xray_processes("", "xray").is_empty());
    }

    #[test]
    fn test_parse_xray_processes_skips_header_line() {
        let ps_output = "  PID USER             ARGS\n";
        assert!(parse_xray_processes(ps_output, "xray").is_empty());
    }

    #[test]
    fn test_parse_xray_processes_skips_malformed_line_no_pid() {
        // fields shifted left - no numeric pid present at all
        let ps_output = "   alice   /opt/homebrew/bin/xray run -c /path/config.json\n";
        assert!(parse_xray_processes(ps_output, "xray").is_empty());
    }

    #[test]
    fn test_parse_xray_processes_no_dash_c_yields_empty_config_arg() {
        let ps_output = "300 alice   /opt/homebrew/bin/xray run\n";
        let all = parse_xray_processes(ps_output, "xray");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].config_arg, "");
        let managed = managed_processes(&all, "/Users/alice/.config/xray/config.json");
        assert!(
            managed.is_empty(),
            "empty config_arg must never be treated as managed"
        );
    }

    /// An empty `config_arg` must never match, and an empty `config_path`
    /// must match nothing rather than every no-`-c` process.
    #[test]
    fn test_managed_and_orphans_reject_empty_config_arg_and_empty_config_path() {
        let ps_output = "301 alice   /opt/homebrew/bin/xray run\n";
        let all = parse_xray_processes(ps_output, "xray");
        assert_eq!(all[0].config_arg, "");
        assert!(managed_processes(&all, "").is_empty());
        assert!(orphans(&all, "", None).is_empty());
    }

    #[test]
    fn test_parse_xray_processes_non_xray_process_excluded() {
        let ps_output = "400 carol   /usr/sbin/sshd -i\n";
        assert!(parse_xray_processes(ps_output, "xray").is_empty());
    }

    /// A shell wrapper named `xray` shows up in `ps` as `/bin/sh /path/xray run
    /// -c ...` - argv[0] is the interpreter, so it must not be counted. The
    /// line's trailing basename ("xray") itself contains "xray" so this fails
    /// if `command_matches` is ever applied to the whole args string instead
    /// of argv[0] alone.
    #[test]
    fn test_parse_xray_processes_shell_wrapper_not_counted() {
        let ps_output = "500 dave    /bin/sh /usr/local/bin/xray run -c /etc/xray\n";
        assert!(parse_xray_processes(ps_output, "xray").is_empty());
    }

    /// argv[0]-only regression guard: a command line that merely mentions
    /// "xray" in a later argument must not match. The trailing token's
    /// basename is "xray" itself, so a buggy whole-args-string match would
    /// wrongly pass this test; only an argv[0]-only match rejects it.
    #[test]
    fn test_parse_xray_processes_xray_mentioned_in_later_arg_not_matched() {
        let ps_output = "600 eve     /usr/bin/tail -f /tmp/xray\n";
        assert!(parse_xray_processes(ps_output, "xray").is_empty());
    }

    // -- start_blocked_message / orphan_lines / start_failure_diagnostics --

    #[test]
    fn test_start_blocked_message_names_pid_owner_and_recovery_commands() {
        // Owner name deliberately avoids "root": the hint text itself contains
        // "root-owned", so a plain `.contains("root")` would pass even if the
        // owner argument were ignored entirely.
        let msg = start_blocked_message(5556, Some("carol"), &[]);
        assert!(msg.contains("5556"));
        assert!(msg.contains("'carol'"));
        assert!(msg.contains("sudo corvex stop"));
        // Assert the positive recovery clause and the negative warning
        // separately: `msg.contains("corvex start")` alone is also satisfied
        // by the warning text ("Do not run `sudo corvex start`"), so it would
        // still pass if the positive "then `corvex start`" clause were lost.
        assert!(msg.contains("then `corvex start`"));
        assert!(msg.contains("Do not run `sudo corvex start`"));
    }

    #[test]
    fn test_start_blocked_message_no_orphans_emits_no_orphan_text() {
        let msg = start_blocked_message(5556, Some("root"), &[]);
        assert!(!msg.contains("untracked"));
        assert!(!msg.contains("Also found"));
    }

    #[test]
    fn test_start_blocked_message_lists_orphans_when_present() {
        let orphans = vec![XrayProcess {
            pid: 7597,
            user: "root".to_string(),
            config_arg: "/Users/alice/.config/xray/config.json".to_string(),
        }];
        let msg = start_blocked_message(5556, Some("root"), &orphans);
        assert!(msg.contains("7597"));
    }

    #[test]
    fn test_orphan_lines_sudo_kill_for_another_user() {
        let orphans = vec![XrayProcess {
            pid: 7597,
            user: "root".to_string(),
            config_arg: "/Users/alice/.config/xray/config.json".to_string(),
        }];
        let lines = orphan_lines(&orphans, "alice");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("sudo kill 7597"));
    }

    #[test]
    fn test_orphan_lines_bare_kill_for_current_user() {
        let orphans = vec![XrayProcess {
            pid: 7597,
            user: "alice".to_string(),
            config_arg: "/Users/alice/.config/xray/config.json".to_string(),
        }];
        let lines = orphan_lines(&orphans, "alice");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("kill 7597"));
        assert!(!lines[0].contains("sudo kill"));
    }

    /// Regression guard for the looping-advice defect: an orphan hint must
    /// never send the user to `corvex stop`, since `xray::stop` only signals
    /// the tracked PID and cannot touch an orphan. Uses a real orphan (one
    /// owned by another user, so recovery text is actually produced) so an
    /// implementation that wrongly emitted "corvex stop" here would fail.
    #[test]
    fn test_orphan_lines_never_says_corvex_stop() {
        let orphans = vec![XrayProcess {
            pid: 7597,
            user: "root".to_string(),
            config_arg: "/Users/alice/.config/xray/config.json".to_string(),
        }];
        let lines = orphan_lines(&orphans, "alice");
        assert!(!lines.is_empty());
        assert!(!lines.join("\n").contains("corvex stop"));
    }

    #[test]
    fn test_start_failure_diagnostics_lists_processes_and_port() {
        let all = vec![
            XrayProcess {
                pid: 1,
                user: "alice".to_string(),
                config_arg: "/Users/alice/.config/xray/config.json".to_string(),
            },
            XrayProcess {
                pid: 2,
                user: "root".to_string(),
                config_arg: "/opt/homebrew/etc/xray/config.json".to_string(),
            },
        ];
        let msg = start_failure_diagnostics(
            &all,
            21080,
            "/Users/alice/.config/xray/config.json",
            Path::new("/Users/alice/.local/state/xray/xray.log"),
        );
        assert!(msg.contains("21080"));
        assert!(msg.contains("/Users/alice/.config/xray/config.json"));
        assert!(msg.contains("/opt/homebrew/etc/xray/config.json"));
        assert!(msg.contains("xray.log"));
    }

    #[test]
    fn test_start_failure_diagnostics_empty_list_names_port_and_log_no_conflict_claim() {
        let msg = start_failure_diagnostics(
            &[],
            21080,
            "/Users/alice/.config/xray/config.json",
            Path::new("/Users/alice/.local/state/xray/xray.log"),
        );
        assert!(msg.contains("21080"));
        assert!(msg.contains("xray.log"));
        assert!(!msg.contains("Another xray process"));
    }

    #[test]
    fn test_orphans_excludes_tracked_keeps_others_in_order() {
        let config_path = "/Users/alice/.config/xray/config.json";
        let all = vec![
            XrayProcess {
                pid: 1,
                user: "alice".to_string(),
                config_arg: config_path.to_string(),
            },
            XrayProcess {
                pid: 2,
                user: "root".to_string(),
                config_arg: config_path.to_string(),
            },
            XrayProcess {
                pid: 3,
                user: "root".to_string(),
                config_arg: config_path.to_string(),
            },
        ];
        let result = orphans(&all, config_path, Some(1));
        assert_eq!(result.iter().map(|p| p.pid).collect::<Vec<_>>(), vec![2, 3]);
    }

    // -- preflight_pid_file and its message builders --

    #[test]
    fn test_pid_file_preflight_message_names_file_and_sudo_rm() {
        let msg = pid_file_preflight_message(Path::new("/Users/alice/.config/xray/xray.pid"));
        assert!(msg.contains("/Users/alice/.config/xray/xray.pid"));
        assert!(msg.contains("sudo rm"));
    }

    #[test]
    fn test_pid_file_unwritable_path_message_carries_the_error_and_never_says_rm() {
        let err = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "/Users/alice is writable by other users (mode 0775), so anything corvex leaves in \
             it can be swapped; fix with: chmod go-w '/Users/alice'",
        );
        let msg =
            pid_file_unwritable_path_message(Path::new("/Users/alice/.config/xray/xray.pid"), &err);

        assert!(msg.contains("/Users/alice/.config/xray/xray.pid"));
        // The actionable part of the refusal is inside the error, so it has to
        // survive into the message the user sees.
        assert!(msg.contains("chmod go-w '/Users/alice'"), "{msg}");
        assert!(
            !msg.contains("rm"),
            "removing the file cannot fix a path problem: {msg}"
        );
    }

    /// A directory the ancestry walk refuses is not cured by unlinking the
    /// file inside it - and `write_pid_file` makes the same
    /// `open_write_restricted` call *after* xray has been spawned. So the
    /// preflight has to fail here rather than pass on a removal that changed
    /// nothing, otherwise `start` reaches the spawn and orphans xray, which is
    /// exactly what the preflight exists to prevent.
    #[test]
    #[cfg(unix)]
    fn test_preflight_pid_file_rejects_an_untrusted_dir_it_can_still_unlink_in() {
        use std::os::unix::fs::PermissionsExt;

        let dir = crate::config::test_tempdir();
        let path = dir.path().join("xray.pid");
        fs::write(&path, definitely_dead_pid().to_string()).unwrap();
        // World-writable and not sticky, which `untrusted_ancestor_rejection`
        // refuses - while the file inside stays perfectly removable, so the
        // read / remove branch runs to completion and would have returned
        // `Ok`.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();

        let result = preflight_pid_file(&path, "xray");

        // Restore before asserting, so a failure still leaves a removable dir.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

        let err =
            result.expect_err("an untrusted PID directory must fail the preflight, not pass it");
        let rendered = err.to_string();
        assert!(
            rendered.contains("cannot be written"),
            "the refusal must name the path problem: {rendered}"
        );
        assert!(
            rendered.contains("chmod go-w"),
            "the ancestry advice must reach the user: {rendered}"
        );
    }

    #[test]
    fn test_pid_file_write_failed_message_names_pid_and_sudo_kill() {
        let err = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let msg = pid_file_write_failed_message(
            5556,
            Path::new("/Users/alice/.config/xray/xray.pid"),
            &err,
        );
        assert!(msg.contains("5556"));
        assert!(msg.contains("sudo kill 5556"));
    }

    #[test]
    fn test_pid_out_of_range_message_names_pid_and_sudo_kill() {
        let msg = pid_out_of_range_message(4_294_967_295);
        assert!(msg.contains("4294967295"));
        assert!(msg.contains("sudo kill 4294967295"));
    }

    /// Never a bare `sudo rm`: an unreadable PID file might still be tracking
    /// a live xray, so corvex must not suggest deleting it outright.
    #[test]
    fn test_pid_file_unreadable_message_never_suggests_bare_rm() {
        let msg = pid_file_unreadable_message(Path::new("/Users/alice/.config/xray/xray.pid"));
        assert!(msg.contains("/Users/alice/.config/xray/xray.pid"));
        assert!(!msg.contains("sudo rm"));
    }

    #[test]
    fn test_pid_file_tracks_live_process_message_never_suggests_rm() {
        let msg =
            pid_file_tracks_live_process_message(Path::new("/Users/alice/.config/xray/xray.pid"));
        assert!(msg.contains("/Users/alice/.config/xray/xray.pid"));
        assert!(!msg.contains("sudo rm"));
    }

    #[test]
    fn test_pid_file_tracks_live_xray_rejects_garbage_content() {
        assert!(!pid_file_tracks_live_xray("not-a-pid", "xray"));
    }

    /// Spawn a trivial child and wait for it, giving a real PID that is
    /// guaranteed dead - used instead of an arbitrary literal so these tests
    /// never depend on which PIDs happen to be free on the test machine.
    #[cfg(unix)]
    fn definitely_dead_pid() -> i32 {
        let mut child = Command::new("true")
            .spawn()
            .expect("failed to spawn test process");
        let pid = child.id() as i32;
        child.wait().expect("failed to wait for test process");
        pid
    }

    #[test]
    #[cfg(unix)]
    fn test_pid_file_tracks_live_xray_false_for_dead_pid() {
        assert!(!pid_file_tracks_live_xray(
            &definitely_dead_pid().to_string(),
            "xray"
        ));
    }

    #[test]
    #[cfg(unix)]
    fn test_pid_file_tracks_live_xray_false_for_alive_non_xray_process() {
        // Our own test process is alive but is not xray.
        assert!(!pid_file_tracks_live_xray(
            &std::process::id().to_string(),
            "xray"
        ));
    }

    #[test]
    #[cfg(unix)]
    fn test_preflight_pid_file_accepts_readonly_file_in_writable_dir() {
        let dir = crate::config::test_tempdir();
        let path = dir.path().join("xray.pid");
        fs::write(&path, definitely_dead_pid().to_string()).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o400);
        fs::set_permissions(&path, perms).unwrap();

        let result = preflight_pid_file(&path, "xray");

        assert!(
            result.is_ok(),
            "a 0o400 file naming a dead PID in a writable directory must be accepted as removable: {result:?}"
        );
    }

    /// A file we cannot open for writing (0o400) inside a directory that
    /// disallows unlink too (0o500): neither path to acceptance works, so
    /// this must be rejected. This is the case a writable-but-not-user-owned
    /// directory does not cover - see the "removable" test above for that.
    #[test]
    #[cfg(unix)]
    fn test_preflight_pid_file_rejects_neither_writable_nor_removable() {
        let dir = crate::config::test_tempdir();
        let sub = dir.path().join("pid_dir");
        fs::create_dir_all(&sub).unwrap();
        let path = sub.join("xray.pid");
        fs::write(&path, definitely_dead_pid().to_string()).unwrap();

        let mut file_perms = fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut file_perms, 0o400);
        fs::set_permissions(&path, file_perms).unwrap();

        let mut dir_perms = fs::metadata(&sub).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut dir_perms, 0o500);
        fs::set_permissions(&sub, dir_perms).unwrap();

        let result = preflight_pid_file(&path, "xray");

        // Restore before the temp dir drops, or cleanup fails.
        let mut dir_perms = fs::metadata(&sub).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut dir_perms, 0o700);
        fs::set_permissions(&sub, dir_perms).unwrap();

        let err = result.expect_err("neither writable nor removable must be rejected");
        assert!(err.to_string().contains(&path.display().to_string()));
    }

    /// Critical regression guard: a PID file we cannot even read must never
    /// be deleted, since it might still be tracking a live xray process -
    /// deleting it and letting a duplicate spawn in its place is the exact
    /// inverse of the bug this preflight exists to fix.
    #[test]
    #[cfg(unix)]
    fn test_preflight_pid_file_rejects_unreadable_file_without_deleting_it() {
        let dir = crate::config::test_tempdir();
        let path = dir.path().join("xray.pid");
        fs::write(&path, "12345").unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o000);
        fs::set_permissions(&path, perms).unwrap();

        let result = preflight_pid_file(&path, "xray");

        // Restore before the temp dir drops, or cleanup fails.
        let mut perms = fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o600);
        fs::set_permissions(&path, perms).unwrap();

        result.expect_err("an unreadable PID file must never be silently accepted");
        assert!(
            path.exists(),
            "an unreadable PID file might still track a live xray and must not be deleted"
        );
    }

    /// A symlink at the PID path is refused, and neither followed nor
    /// deleted. It used to be accepted: the probe open followed it and
    /// created the target, and the post-spawn write then truncated that
    /// target and wrote a PID into it. The PID path is not configurable, so a
    /// link there is nobody's legitimate setup - and in the world-writable
    /// `/tmp` fallback it is an arbitrary-file clobber someone else planted.
    ///
    /// Not deleting it matters as much as not following it: corvex refusing
    /// to write is a start that fails loudly, while corvex unlinking whatever
    /// it finds would make the plant a way to get files removed too.
    #[test]
    #[cfg(unix)]
    fn test_preflight_pid_file_refuses_a_dangling_symlink_without_creating_its_target() {
        let dir = crate::config::test_tempdir();
        let target = dir.path().join("nonexistent-target.pid");
        let link = dir.path().join("xray.pid");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = preflight_pid_file(&link, "xray")
            .expect_err("a symlink at the PID path must be refused");

        assert!(
            err.to_string().contains("is a symbolic link"),
            "the message must name what is in the way: {err}"
        );
        assert!(
            !target.exists(),
            "the probe must not create the symlink's target"
        );
        assert!(
            fs::symlink_metadata(&link).is_ok(),
            "the symlink itself must not be deleted either"
        );
    }

    /// The same plant pointed at a file that exists: the shape corvex would
    /// otherwise truncate. The victim keeps its contents, and its own mode -
    /// nothing in this path resolves the link a second time.
    #[test]
    #[cfg(unix)]
    fn test_preflight_pid_file_refuses_a_symlink_to_an_existing_file() {
        let dir = crate::config::test_tempdir();
        let victim = dir.path().join("crontab");
        let link = dir.path().join("xray.pid");
        fs::write(&victim, "not corvex's\n").unwrap();
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        preflight_pid_file(&link, "xray").expect_err("a symlinked PID path must be refused");

        assert_eq!(
            fs::read_to_string(&victim).unwrap(),
            "not corvex's\n",
            "the symlink target must be left exactly as it was"
        );
    }

    /// A FIFO at the PID path: the other shape the same world-writable
    /// directory admits. `O_NONBLOCK` is what keeps the probe open from
    /// blocking forever on a reader that never comes - a regression here does
    /// not fail the suite, it hangs it, hence the bounded join.
    #[test]
    #[cfg(unix)]
    fn test_preflight_pid_file_refuses_a_readerless_fifo_without_blocking() {
        let dir = crate::config::test_tempdir();
        let path = dir.path().join("xray.pid");
        crate::config::make_fifo(&path);

        let (sender, receiver) = std::sync::mpsc::channel();
        let probe = path.clone();
        std::thread::spawn(move || {
            let _ = sender.send(preflight_pid_file(&probe, "xray").map_err(|e| e.to_string()));
        });

        let err = receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("the preflight must return, not block waiting for a reader")
            .expect_err("a FIFO at the PID path must be refused");
        assert!(
            err.contains("not a regular file"),
            "the message must name what is in the way: {err}"
        );
    }

    /// The post-spawn write goes through the same no-follow open as the
    /// probe, so losing the race between them is a failed write rather than a
    /// write to someone else's file.
    #[test]
    #[cfg(unix)]
    fn test_write_pid_file_refuses_a_symlink() {
        let dir = crate::config::test_tempdir();
        let victim = dir.path().join("authorized_keys");
        let link = dir.path().join("xray.pid");
        fs::write(&victim, "ssh-ed25519 AAAA...\n").unwrap();
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let err = write_pid_file(&link, 4242).expect_err("a symlinked PID path must be refused");
        assert_eq!(
            err.raw_os_error(),
            Some(nix::libc::ELOOP),
            "expected ELOOP from O_NOFOLLOW, got {err}"
        );
        assert_eq!(
            fs::read_to_string(&victim).unwrap(),
            "ssh-ed25519 AAAA...\n",
            "the symlink target must be neither truncated nor written to"
        );
    }

    /// The ordinary path still works end to end: the PID lands in the file,
    /// at 0600, ready for `is_running` to read back.
    #[test]
    #[cfg(unix)]
    fn test_write_pid_file_writes_the_pid_at_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::config::test_tempdir();
        let path = dir.path().join("xray.pid");

        write_pid_file(&path, 4242).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "4242");
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }

    /// A shorter PID written over a longer one must not leave the tail of the
    /// old one behind: `is_running` would parse `123` out of `12345` and
    /// signal a process corvex never started.
    #[test]
    #[cfg(unix)]
    fn test_write_pid_file_truncates_a_longer_previous_pid() {
        let dir = crate::config::test_tempdir();
        let path = dir.path().join("xray.pid");

        write_pid_file(&path, 123456).unwrap();
        write_pid_file(&path, 42).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "42");
    }

    #[test]
    #[cfg(unix)]
    fn test_preflight_pid_file_accepts_normal_writable_path() {
        let dir = crate::config::test_tempdir();
        let path = dir.path().join("xray.pid");
        fs::write(&path, "999").unwrap();

        preflight_pid_file(&path, "xray").expect("a normal writable existing file must pass");
    }

    #[test]
    #[cfg(unix)]
    fn test_preflight_pid_file_accepts_nonexistent_path_in_writable_dir() {
        let dir = crate::config::test_tempdir();
        let path = dir.path().join("xray.pid");

        preflight_pid_file(&path, "xray")
            .expect("a nonexistent path in a writable directory must pass");
        assert!(
            !path.exists(),
            "a probe file created only to check writability must be removed"
        );
    }

    /// Builds a real executable at `path` that ignores its arguments and
    /// sleeps, standing in for a real, observable xray process in the tests
    /// below. Deliberately not a `#!/bin/sh` script: a shebang script execs
    /// through the interpreter, so both `ps -o comm=` (used by
    /// `process_is_xray`) and argv[0] (used by `parse_xray_processes`) would
    /// report `sh`, never the script's own name - `command_matches` would
    /// then never recognize it as the configured `xray_bin`, regardless of
    /// what that is set to. Compiling a tiny real binary avoids that
    /// entirely; `rustc` is a hard dependency of this project's own build,
    /// so it is always available wherever these tests run.
    #[cfg(unix)]
    fn build_sleeping_fake_xray(path: &Path) {
        let src = path.with_extension("rs");
        fs::write(
            &src,
            "fn main() { std::thread::sleep(std::time::Duration::from_secs(5)); }",
        )
        .unwrap();
        let status = Command::new("rustc")
            .args(["-O", "-o"])
            .arg(path)
            .arg(&src)
            .status()
            .expect("failed to invoke rustc to build the fake xray test binary");
        assert!(
            status.success(),
            "rustc failed to build the fake xray test binary"
        );
    }

    /// Poll briefly for a process matching `xray_bin` via the same
    /// `list_xray_processes` corvex itself uses, returning its PID. Detects a
    /// spawned child through its presence in the process table - visible
    /// within milliseconds of `fork()` - rather than waiting for its script
    /// body to actually execute, which made an earlier version of this poll
    /// slow (300-400ms) and, under load, right at the edge of flaky.
    #[cfg(unix)]
    fn poll_for_process(xray_bin: &str) -> Option<i32> {
        for _ in 0..10 {
            if let Some(p) = list_xray_processes(xray_bin).first() {
                return Some(p.pid);
            }
            thread::sleep(Duration::from_millis(20));
        }
        None
    }

    /// SIGKILL and reap `pid` if it is `Some`. `start()` never hands back a
    /// `Child` on its error paths, so a test that provokes a real spawn (by
    /// design, to prove one did or did not happen) has to identify and reap
    /// the OS process directly - dropping a `std::process::Child` does not
    /// reap it on Unix, and it would otherwise sit as a zombie for the rest
    /// of the test run. Modeled on the `FakeProcess` RAII guard in
    /// `main.rs`'s tests, adapted because there is no `Child` value here to
    /// hang a `Drop` off.
    #[cfg(unix)]
    fn reap_if_spawned(pid: Option<i32>) {
        if let Some(pid) = pid {
            let _ = signal::kill(Pid::from_raw(pid), Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(Pid::from_raw(pid), None);
        }
    }

    /// Regression guard for the ordering guarantee itself: `start` must
    /// return the preflight failure *before* `cmd.spawn()` ever runs. Stands
    /// in a real, spawnable "xray" binary, so a regression that moved the
    /// preflight after `cmd.spawn()` would actually spawn it - a plain
    /// error-message assertion could not tell the two apart.
    #[test]
    #[cfg(unix)]
    fn test_start_returns_before_spawn_when_pid_file_preflight_fails() {
        let dir = crate::config::test_tempdir();
        let base = dir.path();

        // Name kept under 15 characters: on Linux `ps -o comm=` reads
        // /proc/<pid>/comm, which the kernel caps at 15 chars, so a longer
        // name is truncated and `command_matches` can never match it. macOS
        // reports the full path and does not show the problem.
        let script = base.join("fake_xray_ord");
        build_sleeping_fake_xray(&script);
        let script_name = script.file_name().unwrap().to_str().unwrap();

        let xray_config = base.join("xray/config.json");
        fs::create_dir_all(xray_config.parent().unwrap()).unwrap();
        fs::write(&xray_config, "{}").unwrap();

        // A PID file that is neither writable nor removable, as in
        // test_preflight_pid_file_rejects_neither_writable_nor_removable.
        let pid_dir = base.join("pid_dir");
        fs::create_dir_all(&pid_dir).unwrap();
        let pid_file = pid_dir.join("xray.pid");
        fs::write(&pid_file, definitely_dead_pid().to_string()).unwrap();
        let mut file_perms = fs::metadata(&pid_file).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut file_perms, 0o400);
        fs::set_permissions(&pid_file, file_perms).unwrap();
        let mut dir_perms = fs::metadata(&pid_dir).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut dir_perms, 0o500);
        fs::set_permissions(&pid_dir, dir_perms).unwrap();

        let config = Config {
            xray_bin: script.display().to_string(),
            xray_config,
            xray_log: base.join("logs/xray.log"),
            xray_pid_file: pid_file.clone(),
            corvex_settings: base.join("corvex/corvex.json"),
            corvex_log: base.join("state/corvex/corvex.log"),
        };

        let result = start(&config);

        // If the ordering regression this test guards against were present,
        // `cmd.spawn()` would already have run: detect that via `ps` instead
        // of a fixed sleep, so the passing case (nothing to find) stays fast.
        let spawned_pid = poll_for_process(script_name);
        reap_if_spawned(spawned_pid);

        // Restore before the temp dir drops, or cleanup fails.
        let mut dir_perms = fs::metadata(&pid_dir).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut dir_perms, 0o700);
        fs::set_permissions(&pid_dir, dir_perms).unwrap();

        let err = result
            .expect_err("start must fail when the PID file is neither writable nor removable");
        assert!(err.to_string().contains(&pid_file.display().to_string()));
        assert!(
            spawned_pid.is_none(),
            "xray must never be spawned when the PID-file preflight fails"
        );
    }

    /// Regression guard for Finding 2: a PID directory that does not exist
    /// yet must not block `start` - the directory has to be created before
    /// the preflight runs, not only before the post-spawn write.
    #[test]
    #[cfg(unix)]
    fn test_start_succeeds_when_pid_directory_does_not_exist_yet() {
        let dir = crate::config::test_tempdir();
        let base = dir.path();

        // Under 15 characters - see the note in the ordering test above.
        let script = base.join("fake_xray_dir");
        build_sleeping_fake_xray(&script);

        let xray_config = base.join("xray/config.json");
        fs::create_dir_all(xray_config.parent().unwrap()).unwrap();
        fs::write(&xray_config, "{}").unwrap();

        let pid_file = base.join("newdir/xray.pid");
        assert!(
            !pid_file.parent().unwrap().exists(),
            "the PID directory must not exist yet for this test to be meaningful"
        );

        let config = Config {
            xray_bin: script.display().to_string(),
            xray_config,
            xray_log: base.join("logs/xray.log"),
            xray_pid_file: pid_file.clone(),
            corvex_settings: base.join("corvex/corvex.json"),
            corvex_log: base.join("state/corvex/corvex.log"),
        };

        let result = start(&config);

        let pid =
            result.expect("start must succeed even when the PID directory does not exist yet");
        reap_if_spawned(Some(pid));

        assert!(pid_file.exists(), "the PID file must have been written");
    }
}
