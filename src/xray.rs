use crate::config::Config;
use anyhow::{Context, Result};
use log::debug;
#[cfg(unix)]
use nix::sys::signal::{self, Signal};
#[cfg(unix)]
use nix::unistd::Pid;
use std::fs;
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
    #[error("xray failed to start — check the log")]
    StartFailed,
    #[error("invalid config: {0}")]
    InvalidConfig(String),
}

/// Check if xray binary is installed; if not, install silently.
/// On macOS: uses brew. On Windows: checks PATH.
pub fn ensure_installed(xray_bin: &str) -> Result<()> {
    debug!("checking if '{}' is installed", xray_bin);

    #[cfg(unix)]
    {
        let which_output = Command::new("which")
            .arg(xray_bin)
            .output()
            .context("Failed to run 'which'")?;

        if which_output.status.success() {
            debug!("'{}' found in PATH", xray_bin);
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            debug!("'{}' not found, installing via brew", xray_bin);
            let brew_output = Command::new("brew")
                .args(["install", "--quiet", "xray"])
                .output()
                .context("Failed to run 'brew install xray' — is Homebrew installed?")?;

            if !brew_output.status.success() {
                let stderr = String::from_utf8_lossy(&brew_output.stderr);
                anyhow::bail!("brew install xray failed: {}", stderr.trim());
            }
        }

        #[cfg(target_os = "linux")]
        {
            anyhow::bail!(
                "'{}' not found in PATH. Install xray-core:\n\
                 - Snap:   sudo snap install xray\n\
                 - Manual: https://github.com/XTLS/Xray-core/releases",
                xray_bin
            );
        }

        Ok(())
    }

    #[cfg(windows)]
    {
        let where_output = Command::new("where")
            .arg(xray_bin)
            .output()
            .context("Failed to run 'where'")?;

        if where_output.status.success() {
            debug!("'{}' found in PATH", xray_bin);
            return Ok(());
        }

        // Not found — try winget
        debug!("'{}' not found, installing via winget", xray_bin);
        let winget_output = Command::new("winget")
            .args(["install", "--silent", "xray"])
            .output()
            .context("Failed to run 'winget install xray'")?;

        if !winget_output.status.success() {
            let stderr = String::from_utf8_lossy(&winget_output.stderr);
            anyhow::bail!("winget install xray failed: {}", stderr.trim());
        }

        Ok(())
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

    // Check if process is alive
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

    debug!("spawning xray with config {}", config.xray_config.display());
    let log_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&config.xray_log)
        .context("Failed to open log file")?;
    let log_stderr = log_file
        .try_clone()
        .context("Failed to clone log file handle")?;

    let child = Command::new(&config.xray_bin)
        .args(["run", "-c"])
        .arg(&config.xray_config)
        .stdout(log_file)
        .stderr(log_stderr)
        .spawn()
        .context("Failed to spawn xray process")?;

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

    // Wait up to 2 seconds for process to exit
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(100));
        if !is_process_alive(pid) {
            debug!("xray process {} terminated", pid);
            let _ = fs::remove_file(&config.xray_pid_file);
            return Ok(());
        }
    }

    // Force kill
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
    // GenerateConsoleCtrlEvent takes a process *group* ID, not a PID.
    // Since xray is spawned without CREATE_NEW_PROCESS_GROUP, the call
    // would either fail silently or hit the wrong group.  Go straight
    // to TerminateProcess, which is what happened in practice anyway
    // (the 2-second timeout always expired).
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
        Command::new("which")
            .arg(bin)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn test_known_binary_found() {
        assert!(is_binary_in_path("ls"));
    }

    #[test]
    fn test_nonexistent_binary_not_found() {
        assert!(!is_binary_in_path("nonexistent_binary_xyz_999"));
    }

    #[test]
    fn test_ensure_installed_known_binary() {
        let result = ensure_installed("ls");
        assert!(result.is_ok());
    }
}
