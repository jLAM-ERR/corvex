use anyhow::Context;
use json_comments::StripComments;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Default)]
pub struct CorvexSettings {
    pub uri: Option<String>,
    #[serde(rename = "file-url")]
    pub file_url: Option<Vec<String>>,
    #[serde(rename = "corporate-dns")]
    pub corporate_dns: Option<BTreeMap<String, String>>,
    pub routes: Option<RoutesSettings>,
    pub log: Option<LogSettings>,
}

#[derive(Debug, Deserialize)]
pub struct RoutesSettings {
    #[serde(rename = "direct-ru")]
    pub direct_ru: Option<bool>,
    #[serde(rename = "proxy-traffic")]
    pub proxy_traffic: Option<Vec<String>>,
    #[serde(rename = "corporate-traffic")]
    pub corporate_traffic: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct LogSettings {
    pub xray: Option<XrayLogSettings>,
    pub corvex: Option<CorvexLogSettings>,
}

#[derive(Debug, Deserialize)]
pub struct XrayLogSettings {
    pub loglevel: Option<String>,
    pub access: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CorvexLogSettings {
    #[allow(dead_code)]
    pub path: Option<String>,
    pub debug: Option<bool>,
}

pub fn load(path: &Path) -> anyhow::Result<CorvexSettings> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let stripped = StripComments::new(content.as_bytes());
    let mut buf = String::new();
    std::io::BufReader::new(stripped)
        .read_to_string(&mut buf)
        .with_context(|| format!("failed to strip comments from {}", path.display()))?;
    let settings: CorvexSettings = serde_json::from_str(&buf)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(settings)
}

pub fn xdg_settings_path() -> PathBuf {
    xdg_settings_path_inner(std::env::var("XDG_CONFIG_HOME").ok())
}

fn xdg_settings_path_inner(xdg_home: Option<String>) -> PathBuf {
    if let Some(xdg) = xdg_home {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("corvex/corvex.json");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".config/corvex/corvex.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(content: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corvex.json");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        (dir, path)
    }

    #[test]
    fn load_full_jsonc_config() {
        let json = r#"{
            // This is a comment
            "uri": "vless://uuid@host:443?type=grpc",
            "file-url": ["https://example.com/sub1", "https://example.com/sub2"],
            "corporate-dns": {
                "corp.internal": "10.0.0.1",
                "dev.corp": "10.0.0.2"
            },
            "routes": {
                "direct-ru": true,
                "proxy-traffic": ["example.com", "github.com"],
                "corporate-traffic": ["corp.internal", "dev.corp"]
            },
            "log": {
                "xray": {
                    "loglevel": "warning",
                    "access": "/var/log/xray/access.log",
                    "error": "/var/log/xray/error.log"
                },
                "corvex": {
                    "path": "/var/log/corvex.log",
                    "debug": true
                }
            }
        }"#;
        let (_dir, path) = write_temp(json);
        let s = load(&path).unwrap();

        assert_eq!(s.uri.as_deref(), Some("vless://uuid@host:443?type=grpc"));

        let file_url = s.file_url.unwrap();
        assert_eq!(file_url.len(), 2);
        assert_eq!(file_url[0], "https://example.com/sub1");

        let dns = s.corporate_dns.unwrap();
        assert_eq!(
            dns.get("corp.internal").map(|s| s.as_str()),
            Some("10.0.0.1")
        );
        assert_eq!(dns.get("dev.corp").map(|s| s.as_str()), Some("10.0.0.2"));

        let routes = s.routes.unwrap();
        assert_eq!(routes.direct_ru, Some(true));
        assert_eq!(routes.proxy_traffic.as_ref().unwrap().len(), 2);
        assert_eq!(
            routes.corporate_traffic.as_ref().unwrap()[0],
            "corp.internal"
        );

        let log = s.log.unwrap();
        let xray_log = log.xray.unwrap();
        assert_eq!(xray_log.loglevel.as_deref(), Some("warning"));
        assert_eq!(xray_log.access.as_deref(), Some("/var/log/xray/access.log"));
        assert_eq!(xray_log.error.as_deref(), Some("/var/log/xray/error.log"));

        let corvex_log = log.corvex.unwrap();
        assert_eq!(corvex_log.path.as_deref(), Some("/var/log/corvex.log"));
        assert_eq!(corvex_log.debug, Some(true));
    }

    #[test]
    fn load_uri_only() {
        let json = r#"{"uri": "vless://abc@host:443"}"#;
        let (_dir, path) = write_temp(json);
        let s = load(&path).unwrap();
        assert_eq!(s.uri.as_deref(), Some("vless://abc@host:443"));
        assert!(s.file_url.is_none());
        assert!(s.corporate_dns.is_none());
        assert!(s.routes.is_none());
        assert!(s.log.is_none());
    }

    #[test]
    fn load_file_url_only() {
        let json = r#"{"file-url": ["https://sub.example.com"]}"#;
        let (_dir, path) = write_temp(json);
        let s = load(&path).unwrap();
        assert!(s.uri.is_none());
        assert_eq!(s.file_url.unwrap(), vec!["https://sub.example.com"]);
    }

    #[test]
    fn load_empty_config() {
        let json = r#"{}"#;
        let (_dir, path) = write_temp(json);
        let s = load(&path).unwrap();
        assert!(s.uri.is_none());
        assert!(s.file_url.is_none());
        assert!(s.corporate_dns.is_none());
        assert!(s.routes.is_none());
        assert!(s.log.is_none());
    }

    #[test]
    fn jsonc_comments_are_stripped() {
        let json = r#"{
            // single-line comment
            "uri": "vless://x@y:1",
            /* block
               comment */
            "file-url": ["https://a.com"]
        }"#;
        let (_dir, path) = write_temp(json);
        let s = load(&path).unwrap();
        assert_eq!(s.uri.as_deref(), Some("vless://x@y:1"));
        assert_eq!(s.file_url.unwrap(), vec!["https://a.com"]);
    }

    #[test]
    fn xdg_settings_path_uses_xdg_config_home() {
        let path = xdg_settings_path_inner(Some("/custom/xdg".to_string()));
        assert_eq!(path, PathBuf::from("/custom/xdg/corvex/corvex.json"));
    }

    #[test]
    fn xdg_settings_path_falls_back_to_home() {
        let path = xdg_settings_path_inner(None);
        assert!(path.ends_with(".config/corvex/corvex.json"));
    }

    #[test]
    fn xdg_settings_path_ignores_empty_xdg_config_home() {
        let path = xdg_settings_path_inner(Some(String::new()));
        assert!(path.ends_with(".config/corvex/corvex.json"));
    }
}
