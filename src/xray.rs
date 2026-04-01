use crate::config::Config;
use anyhow::{Context, Result};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::fs;
use std::net::TcpListener;
use std::process::Command;
use std::thread;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum XrayError {
    #[error("xray binary not found in PATH")]
    BinaryNotFound,
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
    #[error("port {0} is already in use")]
    PortInUse(u16),
}

/// Reads the PID file and checks if the process is actually running.
/// Cleans up stale PID files.
pub fn is_running(config: &Config) -> Option<i32> {
    let pid_str = match fs::read_to_string(&config.xray_pid_file) {
        Ok(s) => s,
        Err(_) => return None,
    };

    let pid: i32 = match pid_str.trim().parse() {
        Ok(p) => p,
        Err(_) => {
            let _ = fs::remove_file(&config.xray_pid_file);
            return None;
        }
    };

    // Check if process is alive with signal 0
    match signal::kill(Pid::from_raw(pid), None) {
        Ok(()) => Some(pid),
        Err(_) => {
            // Stale PID file — process is dead
            let _ = fs::remove_file(&config.xray_pid_file);
            None
        }
    }
}

/// Check if a port is available for binding.
pub fn check_port_available(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

/// Start the xray process.
pub fn start(config: &Config) -> Result<i32> {
    // Check binary exists
    if Command::new("which")
        .arg(&config.xray_bin)
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        return Err(XrayError::BinaryNotFound.into());
    }

    // Check config exists
    if !config.xray_config.exists() {
        return Err(XrayError::ConfigNotFound(config.xray_config.display().to_string()).into());
    }

    // Check not already running
    if let Some(pid) = is_running(config) {
        return Err(XrayError::AlreadyRunning(pid).into());
    }

    // Check port available
    if !check_port_available(config.socks_port) {
        return Err(XrayError::PortInUse(config.socks_port).into());
    }
    if config.http_port != config.socks_port && !check_port_available(config.http_port) {
        return Err(XrayError::PortInUse(config.http_port).into());
    }

    // Ensure log directory exists
    if let Some(log_dir) = config.xray_log.parent() {
        let _ = fs::create_dir_all(log_dir);
    }

    // Spawn xray
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

    let pid = child.id() as i32;

    // Write PID file
    if let Some(pid_dir) = config.xray_pid_file.parent() {
        let _ = fs::create_dir_all(pid_dir);
    }
    fs::write(&config.xray_pid_file, pid.to_string()).context("Failed to write PID file")?;

    // Wait and verify
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
    let _ = signal::kill(nix_pid, Signal::SIGTERM);

    // Wait up to 2 seconds
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(100));
        if signal::kill(nix_pid, None).is_err() {
            let _ = fs::remove_file(&config.xray_pid_file);
            return Ok(());
        }
    }

    // Force kill
    let _ = signal::kill(nix_pid, Signal::SIGKILL);
    thread::sleep(Duration::from_millis(100));
    let _ = fs::remove_file(&config.xray_pid_file);
    Ok(())
}

/// Validate config and send SIGHUP to reload.
pub fn reload(config: &Config) -> Result<()> {
    // Validate config JSON
    let content = fs::read_to_string(&config.xray_config).context("Failed to read config file")?;
    let _: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| XrayError::InvalidConfig(e.to_string()))?;

    let pid = match is_running(config) {
        Some(pid) => pid,
        None => return Err(XrayError::NotRunning.into()),
    };

    signal::kill(Pid::from_raw(pid), Signal::SIGHUP).context("Failed to send SIGHUP to xray")?;

    Ok(())
}
