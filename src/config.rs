use log::debug;
use std::path::PathBuf;

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
    pub fn new(config_override: Option<&str>) -> Self {
        let xray_dir = xdg_config_dir();
        let config_base = xdg_config_base();
        let state_dir = xdg_state_dir();
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
            xray_log: PathBuf::from("/var/log/xray/xray.log"),
            xray_pid_file: xray_dir.join("xray.pid"),
            corvex_settings: config_base.join("corvex/corvex.json"),
            corvex_log: state_dir.join("corvex/corvex.log"),
        }
    }
}

fn xdg_config_base() -> PathBuf {
    xdg_config_base_inner(std::env::var("XDG_CONFIG_HOME").ok())
}

fn xdg_config_base_inner(xdg_home: Option<String>) -> PathBuf {
    if let Some(xdg) = xdg_home {
        if !xdg.is_empty() {
            return PathBuf::from(xdg);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".config")
}

fn xdg_config_dir() -> PathBuf {
    xdg_config_dir_inner(std::env::var("XDG_CONFIG_HOME").ok())
}

fn xdg_config_dir_inner(xdg_home: Option<String>) -> PathBuf {
    xdg_config_base_inner(xdg_home).join("xray")
}

fn xdg_state_dir() -> PathBuf {
    xdg_state_dir_inner(std::env::var("XDG_STATE_HOME").ok())
}

fn xdg_state_dir_inner(xdg_state: Option<String>) -> PathBuf {
    if let Some(xdg) = xdg_state {
        if !xdg.is_empty() {
            return PathBuf::from(xdg);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".local/state")
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
        assert_eq!(config.xray_log, PathBuf::from("/var/log/xray/xray.log"));
    }

    #[test]
    fn config_override_replaces_xray_config_path() {
        let config = Config::new(Some("/custom/config.json"));
        assert_eq!(config.xray_config, PathBuf::from("/custom/config.json"));
    }

    #[test]
    fn xdg_config_home_is_respected() {
        let dir = xdg_config_dir_inner(Some("/tmp/test-xdg".to_string()));
        assert_eq!(dir, PathBuf::from("/tmp/test-xdg/xray"));
    }

    #[test]
    fn new_fields_have_expected_defaults() {
        let config = Config::new(None);
        assert!(config.corvex_settings.ends_with("corvex/corvex.json"));
        assert!(config.corvex_log.ends_with("corvex/corvex.log"));
    }

    #[test]
    fn xdg_state_dir_respects_env_var() {
        let dir = xdg_state_dir_inner(Some("/tmp/test-state".to_string()));
        assert_eq!(dir, PathBuf::from("/tmp/test-state"));
    }

    #[test]
    fn xdg_state_dir_falls_back_to_local_state() {
        let dir = xdg_state_dir_inner(None);
        assert!(dir.ends_with(".local/state"));
    }

    #[test]
    fn xdg_state_dir_ignores_empty_env_var() {
        let dir = xdg_state_dir_inner(Some(String::new()));
        assert!(dir.ends_with(".local/state"));
    }
}
