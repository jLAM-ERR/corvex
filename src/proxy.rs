use anyhow::{Context, Result};
use log::debug;
use std::process::Command;

fn run_networksetup(args: &[&str]) -> Result<String> {
    let output = Command::new("networksetup")
        .args(args)
        .output()
        .with_context(|| format!("Failed to run: networksetup {}", args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("networksetup {} failed: {}", args.join(" "), stderr);
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Enable SOCKS5, HTTP, and HTTPS system proxies on the given host:port.
pub fn enable(service: &str, host: &str, port: u16) -> Result<()> {
    debug!("enabling proxies on '{}' -> {}:{}", service, host, port);
    let port_str = port.to_string();

    run_networksetup(&["-setsocksfirewallproxy", service, host, &port_str])?;
    run_networksetup(&["-setsocksfirewallproxystate", service, "on"])?;

    run_networksetup(&["-setwebproxy", service, host, &port_str])?;
    run_networksetup(&["-setwebproxystate", service, "on"])?;

    run_networksetup(&["-setsecurewebproxy", service, host, &port_str])?;
    run_networksetup(&["-setsecurewebproxystate", service, "on"])?;

    Ok(())
}

/// Disable SOCKS5, HTTP, and HTTPS system proxies.
pub fn disable(service: &str) -> Result<()> {
    debug!("disabling proxies on '{}'", service);
    run_networksetup(&["-setsocksfirewallproxystate", service, "off"])?;
    run_networksetup(&["-setwebproxystate", service, "off"])?;
    run_networksetup(&["-setsecurewebproxystate", service, "off"])?;
    Ok(())
}

/// Proxy info for a single proxy type.
#[derive(Debug)]
pub struct ProxyInfo {
    pub enabled: bool,
    pub server: String,
    pub port: String,
}

/// Parse output from networksetup -getwebproxy / -getsocksfirewallproxy / etc.
pub fn parse_proxy_info(output: &str) -> ProxyInfo {
    let mut enabled = false;
    let mut server = String::new();
    let mut port = String::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("Enabled:") {
            enabled = val.trim().eq_ignore_ascii_case("yes");
        } else if let Some(val) = trimmed.strip_prefix("Server:") {
            server = val.trim().to_string();
        } else if let Some(val) = trimmed.strip_prefix("Port:") {
            port = val.trim().to_string();
        }
    }

    ProxyInfo {
        enabled,
        server,
        port,
    }
}

/// Query status of all three proxy types.
pub fn status(service: &str) -> Result<(ProxyInfo, ProxyInfo, ProxyInfo)> {
    let socks = run_networksetup(&["-getsocksfirewallproxy", service])?;
    let http = run_networksetup(&["-getwebproxy", service])?;
    let https = run_networksetup(&["-getsecurewebproxy", service])?;

    Ok((
        parse_proxy_info(&socks),
        parse_proxy_info(&http),
        parse_proxy_info(&https),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proxy_info_enabled() {
        let output =
            "Enabled: Yes\nServer: 127.0.0.1\nPort: 1080\nAuthenticated Proxy Enabled: 0\n";
        let info = parse_proxy_info(output);
        assert!(info.enabled);
        assert_eq!(info.server, "127.0.0.1");
        assert_eq!(info.port, "1080");
    }

    #[test]
    fn parse_proxy_info_disabled() {
        let output = "Enabled: No\nServer: \nPort: 0\n";
        let info = parse_proxy_info(output);
        assert!(!info.enabled);
        assert_eq!(info.server, "");
        assert_eq!(info.port, "0");
    }
}
