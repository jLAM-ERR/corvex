use crate::config::Config;
use anyhow::{Context, Result};
use log::debug;
#[cfg(unix)]
use nix::sys::signal::{self, Signal};
#[cfg(unix)]
use nix::unistd::Pid;
use std::fs;
#[cfg(windows)]
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

    if is_process_alive(pid) {
        debug!("xray process {} is running", pid);
        Some(pid)
    } else {
        debug!("stale PID file (process {} dead), removing", pid);
        let _ = fs::remove_file(&config.xray_pid_file);
        None
    }
}

#[cfg(unix)]
fn is_process_alive(pid: i32) -> bool {
    signal::kill(Pid::from_raw(pid), None).is_ok()
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

    let child = Command::new(&xray_bin)
        .args(["run", "-c"])
        .arg(&config.xray_config)
        .stdout(log_file)
        .stderr(log_stderr)
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

    stop_process(pid);

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
fn stop_process(pid: i32) {
    debug!("sending SIGTERM to xray (PID {})", pid);
    let _ = signal::kill(Pid::from_raw(pid), Signal::SIGTERM);
}

#[cfg(windows)]
fn stop_process(pid: i32) {
    // Xray is spawned without CREATE_NEW_PROCESS_GROUP, so terminate directly.
    force_kill_process(pid);
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
        signal::kill(Pid::from_raw(pid), Signal::SIGHUP)
            .context("Failed to send SIGHUP to xray")?;
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
}
