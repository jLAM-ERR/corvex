use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub socks_host: String,
    pub socks_port: u16,
    pub http_host: String,
    pub http_port: u16,
    pub xray_bin: String,
    pub xray_config: PathBuf,
    pub xray_log: PathBuf,
    pub xray_pid_file: PathBuf,
    pub direct_domains: PathBuf,
    pub proxy_domains: PathBuf,
    pub corp_dns: PathBuf,
}

impl Config {
    pub fn new(config_override: Option<&str>) -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let xray_dir = PathBuf::from(&home).join(".config/xray");

        let xray_config = match config_override {
            Some(path) => PathBuf::from(path),
            None => xray_dir.join("config.json"),
        };

        Config {
            socks_host: "127.0.0.1".to_string(),
            socks_port: 1080,
            http_host: "127.0.0.1".to_string(),
            http_port: 1080,
            xray_bin: "xray".to_string(),
            xray_config,
            xray_log: PathBuf::from("/var/log/xray/xray.log"),
            xray_pid_file: xray_dir.join("xray.pid"),
            direct_domains: xray_dir.join("direct.json"),
            proxy_domains: xray_dir.join("proxy.json"),
            corp_dns: xray_dir.join("corp-dns.json"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_values() {
        let config = Config::new(None);
        assert_eq!(config.socks_host, "127.0.0.1");
        assert_eq!(config.socks_port, 1080);
        assert_eq!(config.http_port, 1080);
        assert_eq!(config.xray_bin, "xray");
        assert!(config.xray_config.ends_with(".config/xray/config.json"));
        assert!(config.xray_pid_file.ends_with(".config/xray/xray.pid"));
        assert_eq!(config.xray_log, PathBuf::from("/var/log/xray/xray.log"));
    }

    #[test]
    fn config_override_replaces_xray_config_path() {
        let config = Config::new(Some("/custom/config.json"));
        assert_eq!(config.xray_config, PathBuf::from("/custom/config.json"));
    }
}
