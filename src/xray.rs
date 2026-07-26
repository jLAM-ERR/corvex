use crate::config::Config;
use anyhow::{Context, Result};
use log::debug;
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
pub(crate) fn managed_processes(all: &[XrayProcess], config_path: &str) -> Vec<XrayProcess> {
    all.iter()
        .filter(|p| p.config_arg == config_path)
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

/// Start the xray process.
pub fn start(config: &Config) -> Result<i32> {
    if !config.xray_config.exists() {
        return Err(XrayError::ConfigNotFound(config.xray_config.display().to_string()).into());
    }

    if let Some(pid) = is_running(config) {
        return Err(XrayError::AlreadyRunning(pid).into());
    }

    if let Some(log_dir) = config.xray_log.parent() {
        let _ = fs::create_dir_all(log_dir);
    }

    let xray_bin =
        resolve_binary(&config.xray_bin).unwrap_or_else(|| PathBuf::from(&config.xray_bin));

    debug!(
        "spawning xray via {} with config {}",
        xray_bin.display(),
        config.xray_config.display()
    );
    let log_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&config.xray_log)
        .context("Failed to open log file")?;
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

    let pid: i32 = child.id().try_into().context("PID exceeds i32 range")?;
    debug!("xray spawned with PID {}", pid);

    if let Some(pid_dir) = config.xray_pid_file.parent() {
        let _ = fs::create_dir_all(pid_dir);
    }
    fs::write(&config.xray_pid_file, pid.to_string()).context("Failed to write PID file")?;

    debug!("waiting 1s for xray to stabilize");
    thread::sleep(Duration::from_secs(1));

    if is_running(config).is_some() {
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
        let managed = managed_processes(&all, config_path);
        assert_eq!(managed.len(), 1);
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

    #[test]
    fn test_parse_xray_processes_non_xray_process_excluded() {
        let ps_output = "400 carol   /usr/sbin/sshd -i\n";
        assert!(parse_xray_processes(ps_output, "xray").is_empty());
    }

    /// A shell wrapper named `xray` shows up in `ps` as `/bin/sh /path/xray run
    /// -c ...` - argv[0] is the interpreter, so it must not be counted.
    #[test]
    fn test_parse_xray_processes_shell_wrapper_not_counted() {
        let ps_output = "500 dave    /bin/sh /usr/local/bin/xray run -c /path/config.json\n";
        assert!(parse_xray_processes(ps_output, "xray").is_empty());
    }

    /// argv[0]-only regression guard: a command line that merely mentions
    /// "xray" in a later argument must not match.
    #[test]
    fn test_parse_xray_processes_xray_mentioned_in_later_arg_not_matched() {
        let ps_output = "600 eve     /usr/bin/tail -f /var/log/xray/error.log\n";
        assert!(parse_xray_processes(ps_output, "xray").is_empty());
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
}
