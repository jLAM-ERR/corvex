use anyhow::{bail, Context, Result};
use log::{debug, info};
use std::path::Path;
use std::process::Command;

/// Parsed AmneziaWG configuration from a `vpn://` URI.
#[derive(Debug, Clone)]
pub struct AwgConfig {
    // WireGuard standard fields
    pub private_key: String,
    pub address: String,
    pub dns: String,
    pub public_key: String,
    pub endpoint: String,
    pub allowed_ips: String,
    pub preshared_key: String,

    // AmneziaWG obfuscation fields
    pub jc: String,
    pub jmin: String,
    pub jmax: String,
    pub s1: String,
    pub s2: String,
    pub h1: String,
    pub h2: String,
    pub h3: String,
    pub h4: String,
}

/// Parse a `vpn://` URI into an AwgConfig.
///
/// Format: `vpn://<base64url-encoded-json>`
/// The decoded JSON contains a `containers` array; we find the entry whose
/// `container` field contains `"awg"`.
pub fn parse_vpn_uri(uri: &str) -> Result<AwgConfig> {
    let encoded = uri
        .strip_prefix("vpn://")
        .context("URI must start with vpn://")?;

    let decoded_bytes = crate::protocol::decode_base64(encoded.trim())?;
    let decoded_str =
        String::from_utf8(decoded_bytes).context("vpn:// URI decoded to invalid UTF-8")?;
    let json: serde_json::Value =
        serde_json::from_str(&decoded_str).context("vpn:// URI decoded to invalid JSON")?;

    let containers = json["containers"]
        .as_array()
        .context("vpn:// JSON missing 'containers' array")?;

    // Find the container with "awg" in the container field
    let awg_container = containers
        .iter()
        .find(|c| {
            c.get("container")
                .and_then(|v| v.as_str())
                .map(|s| s.contains("awg"))
                .unwrap_or(false)
        })
        .context("no AWG container found in vpn:// URI")?;

    let awg = &awg_container["awg"];
    if awg.is_null() {
        bail!("AWG container has no 'awg' field");
    }

    let host = awg["hostName"]
        .as_str()
        .context("missing hostName")?
        .to_string();
    let port = awg["port"].as_u64().context("missing port")?;

    Ok(AwgConfig {
        private_key: str_field(awg, "client_priv_key")?,
        address: str_field(awg, "client_ip")?,
        dns: "8.8.8.8".to_string(),
        public_key: str_field(awg, "server_pub_key")?,
        endpoint: format!("{host}:{port}"),
        allowed_ips: "0.0.0.0/0, ::/0".to_string(),
        preshared_key: str_field(awg, "psk_key")?,
        jc: str_field(awg, "Jc")?,
        jmin: str_field(awg, "Jmin")?,
        jmax: str_field(awg, "Jmax")?,
        s1: str_field(awg, "S1")?,
        s2: str_field(awg, "S2")?,
        h1: str_field(awg, "H1")?,
        h2: str_field(awg, "H2")?,
        h3: str_field(awg, "H3")?,
        h4: str_field(awg, "H4")?,
    })
}

fn str_field(json: &serde_json::Value, field: &str) -> Result<String> {
    // Fields may be strings or numbers in the JSON
    if let Some(s) = json.get(field).and_then(|v| v.as_str()) {
        Ok(s.to_string())
    } else if let Some(n) = json.get(field).and_then(|v| v.as_u64()) {
        Ok(n.to_string())
    } else if let Some(n) = json.get(field).and_then(|v| v.as_i64()) {
        Ok(n.to_string())
    } else {
        bail!("missing or invalid field: {field}")
    }
}

/// Generate a WireGuard .conf file content with AmneziaWG extensions.
pub fn generate_conf(config: &AwgConfig) -> String {
    format!(
        "[Interface]\n\
         PrivateKey = {}\n\
         Address = {}\n\
         DNS = {}\n\
         Jc = {}\n\
         Jmin = {}\n\
         Jmax = {}\n\
         S1 = {}\n\
         S2 = {}\n\
         H1 = {}\n\
         H2 = {}\n\
         H3 = {}\n\
         H4 = {}\n\
         \n\
         [Peer]\n\
         PublicKey = {}\n\
         PresharedKey = {}\n\
         Endpoint = {}\n\
         AllowedIPs = {}\n\
         PersistentKeepalive = 25\n",
        config.private_key,
        config.address,
        config.dns,
        config.jc,
        config.jmin,
        config.jmax,
        config.s1,
        config.s2,
        config.h1,
        config.h2,
        config.h3,
        config.h4,
        config.public_key,
        config.preshared_key,
        config.endpoint,
        config.allowed_ips,
    )
}

/// Write the AWG .conf file to disk with restricted permissions (0o600 on unix).
pub fn write_conf(config: &AwgConfig, path: &Path) -> Result<()> {
    let content = generate_conf(config);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create dir {}", parent.display()))?;
    }

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
            .with_context(|| format!("failed to write conf to {}", path.display()))?;
    }

    Ok(())
}

/// Ensure awg-quick is installed; auto-install silently if not found.
pub fn ensure_awg_installed() -> Result<()> {
    debug!("checking if awg-quick is installed");

    #[cfg(unix)]
    {
        let which = Command::new("which")
            .arg("awg-quick")
            .output()
            .context("failed to check for awg-quick")?;

        if which.status.success() {
            debug!("awg-quick found in PATH");
            return Ok(());
        }

        info!("awg-quick not found, installing amneziawg-tools via brew");
        let brew = Command::new("brew")
            .args(["install", "--quiet", "amneziawg-tools"])
            .output()
            .context("failed to run 'brew install amneziawg-tools' — is Homebrew installed?")?;

        if !brew.status.success() {
            let stderr = String::from_utf8_lossy(&brew.stderr);
            anyhow::bail!("brew install amneziawg-tools failed: {}", stderr.trim());
        }
    }

    #[cfg(windows)]
    {
        let where_cmd = Command::new("where")
            .arg("awg-quick")
            .output()
            .context("failed to check for awg-quick")?;

        if where_cmd.status.success() {
            debug!("awg-quick found in PATH");
            return Ok(());
        }

        info!("awg-quick not found, installing via winget");
        let winget = Command::new("winget")
            .args(["install", "--silent", "AmneziaVPN.AmneziaWG"])
            .output()
            .context("failed to run 'winget install AmneziaWG'")?;

        if !winget.status.success() {
            let stderr = String::from_utf8_lossy(&winget.stderr);
            anyhow::bail!("winget install AmneziaWG failed: {}", stderr.trim());
        }
    }

    Ok(())
}

/// Start AWG tunnel. Requires root/sudo.
pub fn start_tunnel(conf_path: &Path) -> Result<()> {
    debug!("starting AWG tunnel: {}", conf_path.display());
    let output = Command::new("sudo")
        .args(["awg-quick", "up"])
        .arg(conf_path)
        .output()
        .context("failed to run 'sudo awg-quick up'")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("ermission") || stderr.contains("not permitted") {
            anyhow::bail!(
                "AWG tunnel requires sudo. Run with: sudo corvex start\n{}",
                stderr.trim()
            );
        }
        anyhow::bail!("awg-quick up failed: {}", stderr.trim());
    }

    debug!("AWG tunnel started");
    Ok(())
}

/// Stop AWG tunnel. Requires root/sudo.
pub fn stop_tunnel(conf_path: &Path) -> Result<()> {
    debug!("stopping AWG tunnel: {}", conf_path.display());
    let output = Command::new("sudo")
        .args(["awg-quick", "down"])
        .arg(conf_path)
        .output()
        .context("failed to run 'sudo awg-quick down'")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("awg-quick down failed: {}", stderr.trim());
    }

    debug!("AWG tunnel stopped");
    Ok(())
}

/// Check if AWG tunnel interface is running.
pub fn is_tunnel_running(interface: &str) -> bool {
    Command::new("awg")
        .args(["show", interface])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Get AWG tunnel status output for display.
#[allow(dead_code)]
pub fn tunnel_status(interface: &str) -> Result<String> {
    let output = Command::new("awg")
        .args(["show", interface])
        .output()
        .context("failed to run 'awg show'")?;

    if !output.status.success() {
        bail!("AWG interface '{}' is not running", interface);
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Derive the AWG interface name from the conf file path.
/// E.g., `/path/to/corvex.conf` → `corvex`
pub fn conf_interface_name(conf_path: &Path) -> String {
    conf_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("corvex")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_json() -> serde_json::Value {
        serde_json::json!({
            "containers": [{
                "container": "amnezia-awg",
                "awg": {
                    "client_priv_key": "test_priv_key",
                    "client_pub_key": "test_pub_key",
                    "client_ip": "10.8.1.2/32",
                    "server_pub_key": "server_pub_key",
                    "psk_key": "psk_key_value",
                    "hostName": "server.example.com",
                    "port": 443,
                    "Jc": "7",
                    "Jmin": "150",
                    "Jmax": "1000",
                    "S1": "117",
                    "S2": "321",
                    "H1": "2008066467",
                    "H2": "2351746464",
                    "H3": "3053333659",
                    "H4": "1789444460"
                }
            }]
        })
    }

    fn make_vpn_uri(json: &serde_json::Value) -> String {
        let json_str = serde_json::to_string(json).unwrap();
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            json_str.as_bytes(),
        );
        format!("vpn://{encoded}")
    }

    #[test]
    fn parse_valid_vpn_uri() {
        let json = make_test_json();
        let uri = make_vpn_uri(&json);
        let config = parse_vpn_uri(&uri).unwrap();

        assert_eq!(config.private_key, "test_priv_key");
        assert_eq!(config.address, "10.8.1.2/32");
        assert_eq!(config.public_key, "server_pub_key");
        assert_eq!(config.preshared_key, "psk_key_value");
        assert_eq!(config.endpoint, "server.example.com:443");
        assert_eq!(config.jc, "7");
        assert_eq!(config.jmin, "150");
        assert_eq!(config.jmax, "1000");
        assert_eq!(config.s1, "117");
        assert_eq!(config.s2, "321");
        assert_eq!(config.h1, "2008066467");
        assert_eq!(config.h2, "2351746464");
        assert_eq!(config.h3, "3053333659");
        assert_eq!(config.h4, "1789444460");
    }

    #[test]
    fn parse_vpn_uri_wrong_prefix() {
        let result = parse_vpn_uri("vless://something");
        assert!(result.is_err());
    }

    #[test]
    fn parse_vpn_uri_invalid_base64() {
        let result = parse_vpn_uri("vpn://!!!invalid!!!");
        assert!(result.is_err());
    }

    #[test]
    fn parse_vpn_uri_no_awg_container() {
        let json = serde_json::json!({
            "containers": [{
                "container": "wireguard",
                "wg": {}
            }]
        });
        let uri = make_vpn_uri(&json);
        let result = parse_vpn_uri(&uri);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no AWG container"));
    }

    #[test]
    fn parse_vpn_uri_numeric_fields() {
        // Some servers send numeric fields as numbers instead of strings
        let json = serde_json::json!({
            "containers": [{
                "container": "awg",
                "awg": {
                    "client_priv_key": "key",
                    "client_ip": "10.0.0.1/32",
                    "server_pub_key": "spk",
                    "psk_key": "psk",
                    "hostName": "host.com",
                    "port": 443,
                    "Jc": 7,
                    "Jmin": 150,
                    "Jmax": 1000,
                    "S1": 117,
                    "S2": 321,
                    "H1": 2008066467,
                    "H2": 2351746464u64,
                    "H3": 3053333659u64,
                    "H4": 1789444460
                }
            }]
        });
        let uri = make_vpn_uri(&json);
        let config = parse_vpn_uri(&uri).unwrap();
        assert_eq!(config.jc, "7");
        assert_eq!(config.h1, "2008066467");
    }

    #[test]
    fn generate_conf_format() {
        let config = AwgConfig {
            private_key: "priv".to_string(),
            address: "10.8.1.2/32".to_string(),
            dns: "8.8.8.8".to_string(),
            public_key: "pub".to_string(),
            endpoint: "host:443".to_string(),
            allowed_ips: "0.0.0.0/0, ::/0".to_string(),
            preshared_key: "psk".to_string(),
            jc: "7".to_string(),
            jmin: "150".to_string(),
            jmax: "1000".to_string(),
            s1: "117".to_string(),
            s2: "321".to_string(),
            h1: "1".to_string(),
            h2: "2".to_string(),
            h3: "3".to_string(),
            h4: "4".to_string(),
        };

        let conf = generate_conf(&config);
        assert!(conf.contains("[Interface]"));
        assert!(conf.contains("PrivateKey = priv"));
        assert!(conf.contains("Address = 10.8.1.2/32"));
        assert!(conf.contains("DNS = 8.8.8.8"));
        assert!(conf.contains("Jc = 7"));
        assert!(conf.contains("S1 = 117"));
        assert!(conf.contains("[Peer]"));
        assert!(conf.contains("PublicKey = pub"));
        assert!(conf.contains("PresharedKey = psk"));
        assert!(conf.contains("Endpoint = host:443"));
        assert!(conf.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        assert!(conf.contains("PersistentKeepalive = 25"));
    }

    #[test]
    fn write_conf_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let conf_path = dir.path().join("awg/corvex.conf");

        let config = AwgConfig {
            private_key: "pk".to_string(),
            address: "10.0.0.1/32".to_string(),
            dns: "8.8.8.8".to_string(),
            public_key: "spk".to_string(),
            endpoint: "h:443".to_string(),
            allowed_ips: "0.0.0.0/0".to_string(),
            preshared_key: "psk".to_string(),
            jc: "1".to_string(),
            jmin: "2".to_string(),
            jmax: "3".to_string(),
            s1: "4".to_string(),
            s2: "5".to_string(),
            h1: "6".to_string(),
            h2: "7".to_string(),
            h3: "8".to_string(),
            h4: "9".to_string(),
        };

        write_conf(&config, &conf_path).unwrap();
        assert!(conf_path.exists());

        let content = std::fs::read_to_string(&conf_path).unwrap();
        assert!(content.contains("[Interface]"));
        assert!(content.contains("[Peer]"));
    }

    #[test]
    fn conf_interface_name_from_path() {
        let path = std::path::PathBuf::from("/tmp/awg/corvex.conf");
        assert_eq!(conf_interface_name(&path), "corvex");
    }

    #[test]
    fn conf_interface_name_custom() {
        let path = std::path::PathBuf::from("/tmp/myiface.conf");
        assert_eq!(conf_interface_name(&path), "myiface");
    }
}
