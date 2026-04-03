use crate::config::Config;
use anyhow::{Context, Result};
use log::debug;
use nix::sys::signal::{self, Signal};
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

/// Check if xray binary is installed; if not, install via brew.
/// Returns Ok silently on success.
pub fn ensure_installed(xray_bin: &str) -> Result<()> {
    debug!("checking if '{}' is installed", xray_bin);
    let which_output = Command::new("which")
        .arg(xray_bin)
        .output()
        .context("Failed to run 'which'")?;

    if which_output.status.success() {
        debug!("'{}' found in PATH", xray_bin);
        return Ok(());
    }

    // Not found — try to install via brew
    debug!("'{}' not found, installing via brew", xray_bin);
    let brew_output = Command::new("brew")
        .args(["install", "--quiet", "xray"])
        .output()
        .context("Failed to run 'brew install xray' — is Homebrew installed?")?;

    if !brew_output.status.success() {
        let stderr = String::from_utf8_lossy(&brew_output.stderr);
        anyhow::bail!("brew install xray failed: {}", stderr.trim());
    }

    Ok(())
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

    // Check if process is alive with signal 0
    match signal::kill(Pid::from_raw(pid), None) {
        Ok(()) => {
            debug!("xray process {} is running", pid);
            Some(pid)
        }
        Err(_) => {
            debug!("stale PID file (process {} dead), removing", pid);
            let _ = fs::remove_file(&config.xray_pid_file);
            None
        }
    }
}

/// Start the xray process.
/// Caller must ensure the xray binary is installed (via `ensure_installed`).
pub fn start(config: &Config) -> Result<i32> {
    // Check config exists
    if !config.xray_config.exists() {
        return Err(XrayError::ConfigNotFound(config.xray_config.display().to_string()).into());
    }

    // Check not already running
    if let Some(pid) = is_running(config) {
        return Err(XrayError::AlreadyRunning(pid).into());
    }

    // Ensure log directory exists
    if let Some(log_dir) = config.xray_log.parent() {
        let _ = fs::create_dir_all(log_dir);
    }

    // Spawn xray
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

    let pid: i32 = child
        .id()
        .try_into()
        .context("PID exceeds i32 range")?;
    debug!("xray spawned with PID {}", pid);

    // Write PID file
    if let Some(pid_dir) = config.xray_pid_file.parent() {
        let _ = fs::create_dir_all(pid_dir);
    }
    fs::write(&config.xray_pid_file, pid.to_string()).context("Failed to write PID file")?;

    // Wait and verify
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

    let nix_pid = Pid::from_raw(pid);

    // Send SIGTERM
    debug!("sending SIGTERM to xray (PID {})", pid);
    let _ = signal::kill(nix_pid, Signal::SIGTERM);

    // Wait up to 2 seconds
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(100));
        if signal::kill(nix_pid, None).is_err() {
            debug!("xray process {} terminated", pid);
            let _ = fs::remove_file(&config.xray_pid_file);
            return Ok(());
        }
    }

    // Force kill
    debug!("SIGTERM timeout, sending SIGKILL to PID {}", pid);
    let _ = signal::kill(nix_pid, Signal::SIGKILL);
    thread::sleep(Duration::from_millis(100));
    let _ = fs::remove_file(&config.xray_pid_file);
    Ok(())
}

/// Validate config and send SIGHUP to reload.
pub fn reload(config: &Config) -> Result<()> {
    // Validate config JSON
    debug!("validating config {}", config.xray_config.display());
    let content = fs::read_to_string(&config.xray_config).context("Failed to read config file")?;
    let _: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| XrayError::InvalidConfig(e.to_string()))?;
    debug!("config JSON is valid");

    let pid = match is_running(config) {
        Some(pid) => pid,
        None => return Err(XrayError::NotRunning.into()),
    };

    debug!("sending SIGHUP to xray (PID {})", pid);
    signal::kill(Pid::from_raw(pid), Signal::SIGHUP).context("Failed to send SIGHUP to xray")?;

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
