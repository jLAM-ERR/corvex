use crate::config::Config;
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;

fn read_mappings(config: &Config) -> Result<BTreeMap<String, String>> {
    if !config.corp_dns.exists() {
        return Ok(BTreeMap::new());
    }
    let content = fs::read_to_string(&config.corp_dns).context("Failed to read corp-dns file")?;
    let map: BTreeMap<String, String> =
        serde_json::from_str(&content).context("Failed to parse corp-dns JSON")?;
    Ok(map)
}

fn write_mappings(config: &Config, map: &BTreeMap<String, String>) -> Result<()> {
    if let Some(parent) = config.corp_dns.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(map).context("Failed to serialize DNS mappings")?;
    fs::write(&config.corp_dns, json).context("Failed to write corp-dns file")?;
    Ok(())
}

pub fn list(config: &Config) -> Result<BTreeMap<String, String>> {
    read_mappings(config)
}

pub fn add(domain: &str, server: &str, config: &Config) -> Result<bool> {
    // Validate IP
    server
        .parse::<IpAddr>()
        .map_err(|_| anyhow::anyhow!("Invalid IP address: {server}"))?;

    let mut map = read_mappings(config)?;
    let was_update = map.contains_key(domain);
    map.insert(domain.to_string(), server.to_string());
    write_mappings(config, &map)?;
    Ok(was_update)
}

pub fn remove(domain: &str, config: &Config) -> Result<()> {
    let mut map = read_mappings(config)?;
    if map.remove(domain).is_none() {
        bail!("Domain not found: {domain}");
    }
    write_mappings(config, &map)
}

/// Parse `scutil --dns` output into domain → nameserver mappings.
/// Extracts resolvers that have a `domain` entry (split-DNS / corp DNS),
/// mapping each domain to its first nameserver.
pub fn parse_scutil_dns(output: &str) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    let mut current_domain: Option<String> = None;
    let mut current_nameserver: Option<String> = None;

    for line in output.lines() {
        let trimmed = line.trim();

        // New resolver block resets state
        if trimmed.starts_with("resolver #") {
            if let (Some(domain), Some(ns)) = (current_domain.take(), current_nameserver.take()) {
                result.entry(domain).or_insert(ns);
            }
            current_domain = None;
            current_nameserver = None;
            continue;
        }

        // "domain   : corp.example.com" — split-DNS domain (not "search domain")
        if trimmed.starts_with("domain") && !trimmed.starts_with("domain_") {
            if let Some(value) = trimmed.split(':').nth(1) {
                let value = value.trim();
                if !value.is_empty() {
                    current_domain = Some(value.to_string());
                }
            }
            continue;
        }

        // "nameserver[0] : 10.0.0.1" — take the first nameserver only
        if trimmed.starts_with("nameserver[") && current_nameserver.is_none() {
            if let Some(value) = trimmed.split(':').nth(1) {
                let value = value.trim();
                if value.parse::<IpAddr>().is_ok() {
                    current_nameserver = Some(value.to_string());
                }
            }
        }
    }

    // Flush last resolver
    if let (Some(domain), Some(ns)) = (current_domain, current_nameserver) {
        result.entry(domain).or_insert(ns);
    }

    result
}

/// Sync corp-dns.json mappings into xray config.json's dns.servers section.
/// Each mapping becomes a DNS server entry with a domain matcher.
pub fn sync_to_config(config: &Config) -> Result<usize> {
    let mappings = read_mappings(config)?;
    if mappings.is_empty() {
        return Ok(0);
    }

    let content = fs::read_to_string(&config.xray_config).context("Failed to read xray config")?;
    let mut xray_config: serde_json::Value =
        serde_json::from_str(&content).context("Failed to parse xray config JSON")?;

    // Build DNS servers from corp mappings
    let mut servers: Vec<serde_json::Value> = Vec::new();
    for (domain, server) in &mappings {
        servers.push(serde_json::json!({
            "address": server,
            "port": 53,
            "domains": [format!("domain:{domain}")],
            "skipFallback": true,
        }));
    }

    // Merge with existing dns.servers (keep non-corp entries)
    if let Some(existing) = xray_config
        .pointer("/dns/servers")
        .and_then(|s| s.as_array())
    {
        for entry in existing {
            // Keep string entries (like "1.1.1.1") and entries not from corp-dns
            if entry.is_string() {
                servers.push(entry.clone());
            } else if let Some(addr) = entry.get("address").and_then(|a| a.as_str()) {
                if !mappings.values().any(|v| v == addr) {
                    servers.push(entry.clone());
                }
            }
        }
    }

    xray_config["dns"] = serde_json::json!({ "servers": servers });

    let pretty =
        serde_json::to_string_pretty(&xray_config).context("Failed to serialize xray config")?;
    fs::write(&config.xray_config, pretty).context("Failed to write xray config")?;

    Ok(mappings.len())
}

/// Discover corp DNS mappings from macOS `scutil --dns` and write to corp-dns.json.
/// Returns the discovered mappings.
pub fn init(config: &Config) -> Result<BTreeMap<String, String>> {
    let output = std::process::Command::new("scutil")
        .arg("--dns")
        .output()
        .context("Failed to run scutil --dns")?;

    if !output.status.success() {
        bail!("scutil --dns exited with status {}", output.status);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let discovered = parse_scutil_dns(&stdout);

    if discovered.is_empty() {
        bail!("No split-DNS resolvers found in scutil --dns output");
    }

    write_mappings(config, &discovered)?;
    Ok(discovered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_config(dir: &std::path::Path) -> Config {
        let mut config = Config::new(None);
        config.corp_dns = PathBuf::from(dir).join("corp-dns.json");
        config
    }

    #[test]
    fn add_list_remove_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());

        let was_update = add("corp.example.com", "10.0.0.1", &config).unwrap();
        assert!(!was_update);

        let map = list(&config).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map["corp.example.com"], "10.0.0.1");

        remove("corp.example.com", &config).unwrap();
        let map = list(&config).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn update_existing_mapping() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());

        add("corp.example.com", "10.0.0.1", &config).unwrap();
        let was_update = add("corp.example.com", "10.0.0.2", &config).unwrap();
        assert!(was_update);

        let map = list(&config).unwrap();
        assert_eq!(map["corp.example.com"], "10.0.0.2");
    }

    #[test]
    fn invalid_ip_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());

        let err = add("domain.com", "not-an-ip", &config).unwrap_err();
        assert!(err.to_string().contains("Invalid IP"));
    }

    #[test]
    fn remove_nonexistent_domain() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());

        let err = remove("nope.com", &config).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn list_empty_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());

        let map = list(&config).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn parse_scutil_dns_with_split_resolvers() {
        let output = "\
DNS configuration

resolver #1
  search domain[0] : home.lan
  nameserver[0] : 192.168.1.1
  if_index : 6 (en0)
  flags    : Request A records

resolver #2
  domain   : corp.example.com
  nameserver[0] : 10.0.0.1
  nameserver[1] : 10.0.0.2
  if_index : 18 (utun3)
  flags    : Request A records

resolver #3
  domain   : internal.local
  nameserver[0] : 172.16.0.1
  if_index : 18 (utun3)

resolver #4
  nameserver[0] : 8.8.8.8
  flags    : Request A records
";

        let map = parse_scutil_dns(output);
        assert_eq!(map.len(), 2);
        assert_eq!(map["corp.example.com"], "10.0.0.1");
        assert_eq!(map["internal.local"], "172.16.0.1");
    }

    #[test]
    fn parse_scutil_dns_no_split_resolvers() {
        let output = "\
DNS configuration

resolver #1
  search domain[0] : home.lan
  nameserver[0] : 192.168.1.1
  if_index : 6 (en0)
";

        let map = parse_scutil_dns(output);
        assert!(map.is_empty());
    }

    #[test]
    fn parse_scutil_dns_empty_output() {
        let map = parse_scutil_dns("");
        assert!(map.is_empty());
    }

    #[test]
    fn sync_to_config_adds_dns_servers() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config(dir.path());
        config.xray_config = dir.path().join("config.json");

        // Write a minimal xray config
        let xray_cfg = serde_json::json!({
            "inbounds": [],
            "outbounds": [],
        });
        fs::write(
            &config.xray_config,
            serde_json::to_string_pretty(&xray_cfg).unwrap(),
        )
        .unwrap();

        // Add corp DNS mappings
        add("corp.example.com", "10.0.0.1", &config).unwrap();
        add("internal.local", "172.16.0.1", &config).unwrap();

        let count = sync_to_config(&config).unwrap();
        assert_eq!(count, 2);

        // Verify xray config has dns.servers
        let updated: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&config.xray_config).unwrap()).unwrap();
        let servers = updated["dns"]["servers"].as_array().unwrap();
        assert_eq!(servers.len(), 2);

        // Check one of the entries
        assert_eq!(servers[0]["address"], "10.0.0.1");
        assert_eq!(servers[0]["port"], 53);
        assert_eq!(servers[0]["domains"][0], "domain:corp.example.com");
        assert_eq!(servers[0]["skipFallback"], true);
    }

    #[test]
    fn sync_to_config_preserves_non_corp_entries() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config(dir.path());
        config.xray_config = dir.path().join("config.json");

        // Write xray config with existing DNS
        let xray_cfg = serde_json::json!({
            "inbounds": [],
            "outbounds": [],
            "dns": {
                "servers": [
                    "1.1.1.1",
                    { "address": "8.8.8.8", "domains": ["domain:google.com"] },
                ],
            },
        });
        fs::write(
            &config.xray_config,
            serde_json::to_string_pretty(&xray_cfg).unwrap(),
        )
        .unwrap();

        add("corp.example.com", "10.0.0.1", &config).unwrap();
        sync_to_config(&config).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&config.xray_config).unwrap()).unwrap();
        let servers = updated["dns"]["servers"].as_array().unwrap();

        // corp entry + "8.8.8.8" entry + "1.1.1.1" string
        assert_eq!(servers.len(), 3);

        // Corp entry is first
        assert_eq!(servers[0]["address"], "10.0.0.1");
        // Existing non-corp entries preserved (strings before objects in iteration order)
        assert_eq!(servers[1], "1.1.1.1");
        assert_eq!(servers[2]["address"], "8.8.8.8");
    }

    #[test]
    fn sync_to_config_no_mappings_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        // No corp-dns.json exists, read_mappings returns empty
        let count = sync_to_config(&config).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn parse_scutil_dns_duplicate_domain_keeps_first() {
        let output = "\
resolver #1
  domain   : corp.example.com
  nameserver[0] : 10.0.0.1

resolver #2
  domain   : corp.example.com
  nameserver[0] : 10.0.0.99
";

        let map = parse_scutil_dns(output);
        assert_eq!(map.len(), 1);
        assert_eq!(map["corp.example.com"], "10.0.0.1");
    }
}
