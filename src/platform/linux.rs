use super::{Platform, ProxyInfo, ProxyStatus};
use anyhow::{Context, Result};
use log::debug;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

pub struct LinuxPlatform;

impl LinuxPlatform {
    pub fn new() -> Self {
        LinuxPlatform
    }
}

// ---------------------------------------------------------------------------
// Proxy env file — universal mechanism (works on any Linux)
// ---------------------------------------------------------------------------

/// Path to the proxy environment file: `$XDG_CONFIG_HOME/corvex/proxy.env`
fn proxy_env_path() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/.config", home)
    });
    PathBuf::from(base).join("corvex/proxy.env")
}

/// Generate proxy.env file content with standard environment variables.
pub fn generate_proxy_env(host: &str, port: u16) -> String {
    format!(
        "# Corvex proxy — source this in your shell profile\n\
         export http_proxy=\"http://{host}:{port}\"\n\
         export https_proxy=\"http://{host}:{port}\"\n\
         export all_proxy=\"socks5://{host}:{port}\"\n\
         export HTTP_PROXY=\"http://{host}:{port}\"\n\
         export HTTPS_PROXY=\"http://{host}:{port}\"\n\
         export ALL_PROXY=\"socks5://{host}:{port}\"\n"
    )
}

/// Parse proxy.env content to extract host and port from the all_proxy line.
pub fn parse_proxy_env(content: &str) -> Option<(String, String)> {
    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line
            .strip_prefix("export all_proxy=")
            .or_else(|| line.strip_prefix("export ALL_PROXY="))
        {
            let value = rest.trim_matches('"');
            if let Some(addr) = value.strip_prefix("socks5://") {
                if let Some((host, port)) = addr.rsplit_once(':') {
                    return Some((host.to_string(), port.to_string()));
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Desktop environment proxy integration (best-effort)
// ---------------------------------------------------------------------------

/// Attempt to set proxy in the active desktop environment.
/// Failures are logged but never propagated — env file is the primary mechanism.
fn try_set_desktop_proxy(host: &str, port: u16) {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .to_uppercase();

    if desktop.contains("GNOME")
        || desktop.contains("UNITY")
        || desktop.contains("BUDGIE")
        || desktop.contains("CINNAMON")
    {
        debug!("detected GTK-based DE, setting gsettings proxy");
        try_gsettings_set_proxy(host, port);
    } else if desktop.contains("KDE") {
        debug!("detected KDE, setting kwriteconfig proxy");
        try_kde_set_proxy(host, port);
    } else {
        debug!("no known DE detected (XDG_CURRENT_DESKTOP={:?})", desktop);
    }
}

/// Attempt to unset proxy in the active desktop environment.
fn try_unset_desktop_proxy() {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .to_uppercase();

    if desktop.contains("GNOME")
        || desktop.contains("UNITY")
        || desktop.contains("BUDGIE")
        || desktop.contains("CINNAMON")
    {
        try_gsettings_unset_proxy();
    } else if desktop.contains("KDE") {
        try_kde_unset_proxy();
    }
}

/// Attempt to read proxy status from the active desktop environment.
fn try_read_desktop_proxy() -> Option<ProxyStatus> {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .to_uppercase();

    if desktop.contains("GNOME")
        || desktop.contains("UNITY")
        || desktop.contains("BUDGIE")
        || desktop.contains("CINNAMON")
    {
        try_gsettings_read_proxy()
    } else {
        None
    }
}

// --- GNOME (gsettings) ---

fn run_gsettings(args: &[&str]) -> Option<String> {
    Command::new("gsettings")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn try_gsettings_set_proxy(host: &str, port: u16) {
    let port_str = port.to_string();
    let cmds: &[&[&str]] = &[
        &["set", "org.gnome.system.proxy", "mode", "manual"],
        &["set", "org.gnome.system.proxy.socks", "host", host],
        &["set", "org.gnome.system.proxy.socks", "port", &port_str],
        &["set", "org.gnome.system.proxy.http", "host", host],
        &["set", "org.gnome.system.proxy.http", "port", &port_str],
        &["set", "org.gnome.system.proxy.https", "host", host],
        &["set", "org.gnome.system.proxy.https", "port", &port_str],
    ];
    for args in cmds {
        if run_gsettings(args).is_none() {
            debug!("gsettings {} failed, skipping", args.join(" "));
            return;
        }
    }
    debug!("gsettings proxy configured");
}

fn try_gsettings_unset_proxy() {
    if run_gsettings(&["set", "org.gnome.system.proxy", "mode", "none"]).is_some() {
        debug!("gsettings proxy disabled");
    }
}

fn try_gsettings_read_proxy() -> Option<ProxyStatus> {
    let mode = run_gsettings(&["get", "org.gnome.system.proxy", "mode"])?;
    let enabled = mode.trim_matches('\'') == "manual";

    let read_proto = |proto: &str| -> ProxyInfo {
        let schema = format!("org.gnome.system.proxy.{}", proto);
        let host = run_gsettings(&["get", &schema, "host"])
            .unwrap_or_default()
            .trim_matches('\'')
            .to_string();
        let port = run_gsettings(&["get", &schema, "port"]).unwrap_or_else(|| "0".to_string());
        ProxyInfo {
            enabled: enabled && !host.is_empty(),
            server: host,
            port,
        }
    };

    Some(ProxyStatus {
        socks: read_proto("socks"),
        http: read_proto("http"),
        https: read_proto("https"),
    })
}

// --- KDE (kwriteconfig) ---

fn kde_write_tool() -> Option<&'static str> {
    ["kwriteconfig6", "kwriteconfig5"].into_iter().find(|tool| {
        Command::new("which")
            .arg(tool)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

fn try_kde_set_proxy(host: &str, port: u16) {
    let Some(tool) = kde_write_tool() else {
        debug!("kwriteconfig not found, skipping KDE proxy");
        return;
    };

    let socks = format!("socks://{}:{}", host, port);
    let http = format!("http://{}:{}", host, port);
    let cmds: Vec<Vec<&str>> = vec![
        vec![
            "--file",
            "kioslaverc",
            "--group",
            "Proxy Settings",
            "--key",
            "ProxyType",
            "1",
        ],
        vec![
            "--file",
            "kioslaverc",
            "--group",
            "Proxy Settings",
            "--key",
            "socksProxy",
            &socks,
        ],
        vec![
            "--file",
            "kioslaverc",
            "--group",
            "Proxy Settings",
            "--key",
            "httpProxy",
            &http,
        ],
        vec![
            "--file",
            "kioslaverc",
            "--group",
            "Proxy Settings",
            "--key",
            "httpsProxy",
            &http,
        ],
    ];

    for args in &cmds {
        let _ = Command::new(tool).args(args).output();
    }
    debug!("KDE proxy configured via {}", tool);
}

fn try_kde_unset_proxy() {
    let Some(tool) = kde_write_tool() else {
        return;
    };
    let _ = Command::new(tool)
        .args([
            "--file",
            "kioslaverc",
            "--group",
            "Proxy Settings",
            "--key",
            "ProxyType",
            "0",
        ])
        .output();
    debug!("KDE proxy disabled via {}", tool);
}

// ---------------------------------------------------------------------------
// Platform trait implementation
// ---------------------------------------------------------------------------

impl Platform for LinuxPlatform {
    fn detect_active_service(&self) -> Result<String> {
        let output = Command::new("ip")
            .args(["route", "get", "1.1.1.1"])
            .output()
            .context("Failed to run 'ip route get 1.1.1.1'")?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        match parse_default_interface(&stdout) {
            Some(iface) => {
                debug!("default interface: {}", iface);
                Ok(iface)
            }
            None => {
                debug!("no default interface found, falling back to eth0");
                Ok("eth0".to_string())
            }
        }
    }

    fn enable_proxy(&self, _service: &str, host: &str, port: u16) -> Result<()> {
        debug!("enabling proxy {}:{}", host, port);

        // 1. Write proxy.env (always works, any Linux)
        let env_path = proxy_env_path();
        if let Some(parent) = env_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let content = generate_proxy_env(host, port);
        std::fs::write(&env_path, &content)
            .with_context(|| format!("failed to write {}", env_path.display()))?;
        debug!("wrote proxy env to {}", env_path.display());

        // 2. Best-effort DE integration
        try_set_desktop_proxy(host, port);

        eprintln!(
            "hint: source {} to apply proxy to your shell",
            env_path.display()
        );

        Ok(())
    }

    fn disable_proxy(&self, _service: &str) -> Result<()> {
        debug!("disabling proxy");

        // 1. Remove proxy.env
        let env_path = proxy_env_path();
        if env_path.exists() {
            std::fs::remove_file(&env_path)
                .with_context(|| format!("failed to remove {}", env_path.display()))?;
            debug!("removed {}", env_path.display());
        }

        // 2. Best-effort DE integration
        try_unset_desktop_proxy();

        Ok(())
    }

    fn proxy_status(&self, _service: &str) -> Result<ProxyStatus> {
        // Try DE-specific status first (more detailed)
        if let Some(status) = try_read_desktop_proxy() {
            return Ok(status);
        }

        // Fall back to reading proxy.env
        let env_path = proxy_env_path();
        if let Ok(content) = std::fs::read_to_string(&env_path) {
            if let Some((host, port)) = parse_proxy_env(&content) {
                let make_info = || ProxyInfo {
                    enabled: true,
                    server: host.clone(),
                    port: port.clone(),
                };
                return Ok(ProxyStatus {
                    socks: make_info(),
                    http: make_info(),
                    https: make_info(),
                });
            }
        }

        // No proxy configured
        let off = || ProxyInfo {
            enabled: false,
            server: String::new(),
            port: "0".to_string(),
        };
        Ok(ProxyStatus {
            socks: off(),
            http: off(),
            https: off(),
        })
    }

    fn discover_corporate_dns(&self) -> Result<BTreeMap<String, String>> {
        debug!("running resolvectl status to discover corp DNS");
        let output = Command::new("resolvectl")
            .arg("status")
            .output()
            .context("Failed to run 'resolvectl status'")?;

        if !output.status.success() {
            anyhow::bail!("resolvectl status exited with status {}", output.status);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let discovered = parse_resolvectl_status(&stdout);
        debug!("discovered {} split-DNS resolvers", discovered.len());

        if discovered.is_empty() {
            anyhow::bail!("No split-DNS resolvers found in resolvectl output");
        }

        Ok(discovered)
    }
}

// ---------------------------------------------------------------------------
// Pure parsing helpers — testable on any platform
// ---------------------------------------------------------------------------

/// Parse `ip route get` output to extract the default interface name.
/// Example input: "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.100 uid 1000"
pub fn parse_default_interface(output: &str) -> Option<String> {
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            if *part == "dev" {
                return parts.get(i + 1).map(|s| s.to_string());
            }
        }
    }
    None
}

/// Parse `resolvectl status` output into domain -> nameserver mappings.
/// Extracts per-link DNS configurations that have domain search entries
/// (split-DNS / corporate DNS).
pub fn parse_resolvectl_status(output: &str) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    let mut current_dns: Option<String> = None;
    let mut in_domain_section = false;

    for line in output.lines() {
        let trimmed = line.trim();

        // New link or global section resets state
        if trimmed.starts_with("Link ") || trimmed.starts_with("Global") {
            current_dns = None;
            in_domain_section = false;
            continue;
        }

        // "DNS Servers: 10.0.0.1" or "DNS Servers: 10.0.0.1 10.0.0.2"
        if let Some(rest) = trimmed.strip_prefix("DNS Servers:") {
            in_domain_section = false;
            if let Some(server) = rest.split_whitespace().next() {
                if server.parse::<std::net::IpAddr>().is_ok() {
                    current_dns = Some(server.to_string());
                }
            }
            continue;
        }

        // "Current DNS Server: 10.0.0.1"
        if let Some(rest) = trimmed.strip_prefix("Current DNS Server:") {
            in_domain_section = false;
            if current_dns.is_none() {
                if let Some(server) = rest.split_whitespace().next() {
                    if server.parse::<std::net::IpAddr>().is_ok() {
                        current_dns = Some(server.to_string());
                    }
                }
            }
            continue;
        }

        // "DNS Domain: ~corp.example.com ~internal.local"
        if let Some(rest) = trimmed.strip_prefix("DNS Domain:") {
            in_domain_section = true;
            collect_domains(rest, &current_dns, &mut result);
            continue;
        }

        // Continuation lines for DNS Domain (indented domain names)
        if in_domain_section {
            if trimmed.is_empty() || trimmed.contains(':') {
                in_domain_section = false;
            } else {
                collect_domains(trimmed, &current_dns, &mut result);
            }
            continue;
        }
    }

    result
}

fn collect_domains(text: &str, dns: &Option<String>, result: &mut BTreeMap<String, String>) {
    if let Some(ref dns_server) = dns {
        for token in text.split_whitespace() {
            let domain = token.trim_start_matches('~');
            if !domain.is_empty() && domain.contains('.') {
                result
                    .entry(domain.to_string())
                    .or_insert_with(|| dns_server.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_default_interface ---

    #[test]
    fn parse_default_interface_eth0() {
        let output = "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.100 uid 1000\n    cache\n";
        assert_eq!(parse_default_interface(output), Some("eth0".to_string()));
    }

    #[test]
    fn parse_default_interface_wlan0() {
        let output = "1.1.1.1 via 10.0.0.1 dev wlan0 src 10.0.0.55\n";
        assert_eq!(parse_default_interface(output), Some("wlan0".to_string()));
    }

    #[test]
    fn parse_default_interface_missing() {
        let output = "Error: no route to host\n";
        assert_eq!(parse_default_interface(output), None);
    }

    #[test]
    fn parse_default_interface_empty() {
        assert_eq!(parse_default_interface(""), None);
    }

    // --- generate_proxy_env / parse_proxy_env ---

    #[test]
    fn generate_and_parse_proxy_env_roundtrip() {
        let content = generate_proxy_env("127.0.0.1", 21080);
        let parsed = parse_proxy_env(&content);
        assert_eq!(parsed, Some(("127.0.0.1".to_string(), "21080".to_string())));
    }

    #[test]
    fn generate_proxy_env_contains_all_vars() {
        let content = generate_proxy_env("127.0.0.1", 1080);
        assert!(content.contains("http_proxy="));
        assert!(content.contains("https_proxy="));
        assert!(content.contains("all_proxy="));
        assert!(content.contains("HTTP_PROXY="));
        assert!(content.contains("HTTPS_PROXY="));
        assert!(content.contains("ALL_PROXY="));
        assert!(content.contains("socks5://127.0.0.1:1080"));
        assert!(content.contains("http://127.0.0.1:1080"));
    }

    #[test]
    fn parse_proxy_env_empty() {
        assert_eq!(parse_proxy_env(""), None);
    }

    #[test]
    fn parse_proxy_env_no_all_proxy() {
        let content = "export http_proxy=\"http://127.0.0.1:8080\"\n";
        assert_eq!(parse_proxy_env(content), None);
    }

    #[test]
    fn parse_proxy_env_uppercase_fallback() {
        let content = "export ALL_PROXY=\"socks5://10.0.0.1:9999\"\n";
        assert_eq!(
            parse_proxy_env(content),
            Some(("10.0.0.1".to_string(), "9999".to_string()))
        );
    }

    // --- parse_resolvectl_status ---

    #[test]
    fn parse_resolvectl_with_split_dns() {
        let output = "\
Link 2 (eth0)
      Current Scopes: DNS
Current DNS Server: 192.168.1.1
       DNS Servers: 192.168.1.1

Link 5 (tun0)
      Current Scopes: DNS
Current DNS Server: 10.0.0.1
       DNS Servers: 10.0.0.1
       DNS Domain: corp.example.com internal.local
";
        let map = parse_resolvectl_status(output);
        assert_eq!(map.len(), 2);
        assert_eq!(map["corp.example.com"], "10.0.0.1");
        assert_eq!(map["internal.local"], "10.0.0.1");
    }

    #[test]
    fn parse_resolvectl_with_tilde_domains() {
        let output = "\
Link 5 (tun0)
       DNS Servers: 10.0.0.1
       DNS Domain: ~corp.example.com ~internal.local
";
        let map = parse_resolvectl_status(output);
        assert_eq!(map.len(), 2);
        assert_eq!(map["corp.example.com"], "10.0.0.1");
        assert_eq!(map["internal.local"], "10.0.0.1");
    }

    #[test]
    fn parse_resolvectl_multiline_domains() {
        let output = "\
Link 3 (wg0)
       DNS Servers: 10.0.0.1
       DNS Domain: ~corp.example.com
                   ~internal.local
                   ~dev.corp
";
        let map = parse_resolvectl_status(output);
        assert_eq!(map.len(), 3);
        assert_eq!(map["corp.example.com"], "10.0.0.1");
        assert_eq!(map["internal.local"], "10.0.0.1");
        assert_eq!(map["dev.corp"], "10.0.0.1");
    }

    #[test]
    fn parse_resolvectl_no_split_dns() {
        let output = "\
Link 2 (eth0)
       DNS Servers: 192.168.1.1
";
        let map = parse_resolvectl_status(output);
        assert!(map.is_empty());
    }

    #[test]
    fn parse_resolvectl_empty() {
        let map = parse_resolvectl_status("");
        assert!(map.is_empty());
    }

    #[test]
    fn parse_resolvectl_global_section_ignored() {
        let output = "\
Global
       DNS Servers: 8.8.8.8

Link 2 (eth0)
       DNS Servers: 192.168.1.1

Link 5 (tun0)
       DNS Servers: 10.0.0.1
       DNS Domain: corp.example.com
";
        let map = parse_resolvectl_status(output);
        assert_eq!(map.len(), 1);
        assert_eq!(map["corp.example.com"], "10.0.0.1");
    }

    #[test]
    fn parse_resolvectl_duplicate_domain_keeps_first() {
        let output = "\
Link 3 (tun0)
       DNS Servers: 10.0.0.1
       DNS Domain: corp.example.com

Link 4 (tun1)
       DNS Servers: 10.0.0.99
       DNS Domain: corp.example.com
";
        let map = parse_resolvectl_status(output);
        assert_eq!(map.len(), 1);
        assert_eq!(map["corp.example.com"], "10.0.0.1");
    }
}
