use anyhow::{Context, Result};
use log::debug;
use std::path::{Path, PathBuf};

/// Write content to a file with restricted permissions (0o600 on unix).
/// Use for files containing credentials (xray config, AWG conf, etc.).
pub fn write_restricted(path: &Path, content: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("failed to create {}", path.display()))?;
        std::io::Write::write_all(&mut file, content.as_bytes())
            .with_context(|| format!("failed to write {}", path.display()))?;
    }
    #[cfg(windows)]
    {
        std::fs::write(path, content)
            .with_context(|| format!("failed to write {}", path.display()))?;
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct Config {
    pub xray_bin: String,
    pub xray_config: PathBuf,
    pub xray_log: PathBuf,
    pub xray_pid_file: PathBuf,
    pub corvex_settings: PathBuf,
    #[allow(dead_code)]
    pub corvex_log: PathBuf,
}

impl Config {
    /// Path for the AWG .conf file, derived from the xray config directory.
    pub fn awg_conf_path(&self) -> Result<PathBuf> {
        let parent = self
            .xray_config
            .parent()
            .context("xray_config has no parent directory")?;
        Ok(parent.join("corvex-awg.conf"))
    }

    pub fn new(config_override: Option<&str>) -> Self {
        let xray_dir = xray_config_dir();
        let config_base = config_base_dir();
        let state = state_dir();
        debug!("config dir: {}", xray_dir.display());

        let xray_config = match config_override {
            Some(path) => {
                debug!("config override: {}", path);
                PathBuf::from(path)
            }
            None => xray_dir.join("config.json"),
        };

        Config {
            xray_bin: "xray".to_string(),
            xray_config,
            xray_log: default_xray_log(),
            xray_pid_file: default_xray_pid_file(&xray_dir, &state),
            corvex_settings: config_base.join("corvex").join("corvex.json"),
            corvex_log: state.join("corvex").join("corvex.log"),
        }
    }
}

fn config_base_dir() -> PathBuf {
    config_base_dir_inner(
        #[cfg(unix)]
        std::env::var("XDG_CONFIG_HOME").ok(),
        #[cfg(windows)]
        std::env::var("APPDATA").ok(),
    )
}

#[cfg(unix)]
fn config_base_dir_inner(xdg_home: Option<String>) -> PathBuf {
    if let Some(xdg) = xdg_home {
        if !xdg.is_empty() {
            return PathBuf::from(xdg);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".config")
}

#[cfg(windows)]
fn config_base_dir_inner(appdata: Option<String>) -> PathBuf {
    if let Some(dir) = appdata {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    PathBuf::from(r"C:\Users\Public\AppData\Roaming")
}

fn xray_config_dir() -> PathBuf {
    config_base_dir().join("xray")
}

fn state_dir() -> PathBuf {
    state_dir_inner(
        #[cfg(unix)]
        std::env::var("XDG_STATE_HOME").ok(),
        #[cfg(windows)]
        std::env::var("LOCALAPPDATA").ok(),
    )
}

#[cfg(unix)]
fn state_dir_inner(xdg_state: Option<String>) -> PathBuf {
    if let Some(xdg) = xdg_state {
        if !xdg.is_empty() {
            return PathBuf::from(xdg);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".local/state")
}

#[cfg(windows)]
fn state_dir_inner(local_appdata: Option<String>) -> PathBuf {
    if let Some(dir) = local_appdata {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    PathBuf::from(r"C:\Users\Public\AppData\Local")
}

fn default_xray_log() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/var/log/xray/xray.log")
    }
    #[cfg(windows)]
    {
        state_dir().join("xray").join("xray.log")
    }
}

fn default_xray_pid_file(_xray_dir: &Path, _state: &Path) -> PathBuf {
    #[cfg(unix)]
    {
        _xray_dir.join("xray.pid")
    }
    #[cfg(windows)]
    {
        _state.join("xray").join("xray.pid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_values() {
        let config = Config::new(None);
        assert_eq!(config.xray_bin, "xray");
        assert!(config.xray_config.ends_with("xray/config.json"));
        assert!(config.xray_pid_file.ends_with("xray/xray.pid"));
        #[cfg(unix)]
        assert_eq!(config.xray_log, PathBuf::from("/var/log/xray/xray.log"));
        #[cfg(windows)]
        assert!(config.xray_log.ends_with("xray/xray.log"));
    }

    #[test]
    fn config_override_replaces_xray_config_path() {
        let config = Config::new(Some("/custom/config.json"));
        assert_eq!(config.xray_config, PathBuf::from("/custom/config.json"));
    }

    #[test]
    fn config_base_respects_override() {
        let dir = config_base_dir_inner(Some("/tmp/test-xdg".to_string()));
        assert_eq!(dir, PathBuf::from("/tmp/test-xdg"));
    }

    #[test]
    fn new_fields_have_expected_defaults() {
        let config = Config::new(None);
        assert!(config.corvex_settings.ends_with("corvex/corvex.json"));
        assert!(config.corvex_log.ends_with("corvex/corvex.log"));
    }

    #[test]
    fn state_dir_respects_env_var() {
        let dir = state_dir_inner(Some("/tmp/test-state".to_string()));
        assert_eq!(dir, PathBuf::from("/tmp/test-state"));
    }

    #[test]
    fn state_dir_falls_back_to_default() {
        let dir = state_dir_inner(None);
        #[cfg(unix)]
        assert!(dir.ends_with(".local/state"));
        #[cfg(windows)]
        assert_eq!(dir, PathBuf::from(r"C:\Users\Public\AppData\Local"));
    }

    #[test]
    fn state_dir_ignores_empty_env_var() {
        let dir = state_dir_inner(Some(String::new()));
        #[cfg(unix)]
        assert!(dir.ends_with(".local/state"));
        #[cfg(windows)]
        assert_eq!(dir, PathBuf::from(r"C:\Users\Public\AppData\Local"));
    }
}
