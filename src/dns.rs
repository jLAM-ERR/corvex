use anyhow::{Context, Result};
use log::debug;
use std::collections::BTreeMap;
use std::fs;
#[cfg(any(test, target_os = "macos"))]
use std::net::IpAddr;
use std::path::Path;

/// Parse `scutil --dns` output into domain → nameserver mappings.
/// Extracts resolvers that have a `domain` entry (split-DNS / corp DNS),
/// mapping each domain to its first nameserver.
#[cfg(any(test, target_os = "macos"))]
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

/// Sync DNS mappings into xray config.json's dns.servers section.
/// Each mapping becomes a DNS server entry with a domain matcher.
///
/// **Call ordering:** This function reads and rewrites `config.json`. In `cmd_start`,
/// the required order is: write config -> `sync_to_config` -> `update_config_port`.
/// Changing this order will silently overwrite earlier mutations.
pub fn sync_to_config(
    xray_config_path: &Path,
    mappings: &BTreeMap<String, String>,
) -> Result<usize> {
    debug!("read {} corp DNS mappings", mappings.len());
    if mappings.is_empty() {
        return Ok(0);
    }

    let content = fs::read_to_string(xray_config_path).context("Failed to read xray config")?;
    let mut xray_config: serde_json::Value =
        serde_json::from_str(&content).context("Failed to parse xray config JSON")?;

    // Build DNS servers from corp mappings
    let mut servers: Vec<serde_json::Value> = Vec::new();
    for (domain, server) in mappings {
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

    if xray_config.get("dns").is_none() {
        xray_config["dns"] = serde_json::json!({});
    }
    xray_config["dns"]["servers"] = serde_json::json!(servers);

    // Add corporate-dns routing rule (port 53) for all mapped domains
    let mut domains: Vec<String> = mappings.keys().map(|d| format!("domain:{d}")).collect();
    domains.sort();
    domains.dedup();

    let corp_dns_rule = serde_json::json!({
        "ruleTag": "corporate-dns",
        "port": 53,
        "domain": domains,
        "network": ["tcp", "udp"],
        "outboundTag": "direct",
    });

    // Ensure routing.rules exists
    if xray_config.get("routing").is_none() {
        xray_config["routing"] = serde_json::json!({
            "domainStrategy": "AsIs",
            "rules": [],
        });
    }
    if xray_config["routing"].get("rules").is_none() {
        xray_config["routing"]["rules"] = serde_json::json!([]);
    }

    let rules = xray_config["routing"]["rules"]
        .as_array_mut()
        .context("routing.rules is not an array")?;

    // Replace existing corporate-dns rule, or append
    if let Some(pos) = rules
        .iter()
        .position(|r| r.get("ruleTag").and_then(|t| t.as_str()) == Some("corporate-dns"))
    {
        rules[pos] = corp_dns_rule;
    } else {
        rules.push(corp_dns_rule);
    }

    let pretty =
        serde_json::to_string_pretty(&xray_config).context("Failed to serialize xray config")?;
    crate::config::write_restricted(xray_config_path, &pretty)?;

    Ok(mappings.len())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let xray_config_path = dir.path().join("config.json");

        // Write a minimal xray config
        let xray_cfg = serde_json::json!({
            "inbounds": [],
            "outbounds": [],
        });
        fs::write(
            &xray_config_path,
            serde_json::to_string_pretty(&xray_cfg).unwrap(),
        )
        .unwrap();

        let mut mappings = BTreeMap::new();
        mappings.insert("corp.example.com".to_string(), "10.0.0.1".to_string());
        mappings.insert("internal.local".to_string(), "172.16.0.1".to_string());

        let count = sync_to_config(xray_config_path.as_path(), &mappings).unwrap();
        assert_eq!(count, 2);

        // Verify xray config has dns.servers
        let updated: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&xray_config_path).unwrap()).unwrap();
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
        let xray_config_path = dir.path().join("config.json");

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
            &xray_config_path,
            serde_json::to_string_pretty(&xray_cfg).unwrap(),
        )
        .unwrap();

        let mut mappings = BTreeMap::new();
        mappings.insert("corp.example.com".to_string(), "10.0.0.1".to_string());

        sync_to_config(xray_config_path.as_path(), &mappings).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&xray_config_path).unwrap()).unwrap();
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
    fn sync_to_config_adds_routing_rule_with_port_53() {
        let dir = tempfile::tempdir().unwrap();
        let xray_config_path = dir.path().join("config.json");

        let xray_cfg = serde_json::json!({
            "inbounds": [],
            "outbounds": [],
            "routing": { "domainStrategy": "AsIs", "rules": [] },
        });
        fs::write(
            &xray_config_path,
            serde_json::to_string_pretty(&xray_cfg).unwrap(),
        )
        .unwrap();

        let mut mappings = BTreeMap::new();
        mappings.insert("corp.example.com".to_string(), "10.0.0.1".to_string());
        mappings.insert("internal.local".to_string(), "172.16.0.1".to_string());

        sync_to_config(xray_config_path.as_path(), &mappings).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&xray_config_path).unwrap()).unwrap();
        let rules = updated["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["ruleTag"], "corporate-dns");
        assert_eq!(rules[0]["port"], 53);
        assert_eq!(rules[0]["outboundTag"], "direct");

        let domains = rules[0]["domain"].as_array().unwrap();
        assert_eq!(domains.len(), 2);
        assert!(domains.contains(&serde_json::json!("domain:corp.example.com")));
        assert!(domains.contains(&serde_json::json!("domain:internal.local")));

        let network = rules[0]["network"].as_array().unwrap();
        assert_eq!(
            network,
            &vec![serde_json::json!("tcp"), serde_json::json!("udp")]
        );
    }

    #[test]
    fn sync_to_config_replaces_existing_corporate_dns_rule() {
        let dir = tempfile::tempdir().unwrap();
        let xray_config_path = dir.path().join("config.json");

        let xray_cfg = serde_json::json!({
            "inbounds": [],
            "outbounds": [],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    { "ruleTag": "corporate-dns", "port": 53, "domain": ["domain:old.com"], "outboundTag": "direct" },
                    { "outboundTag": "proxy", "domain": ["domain:ext.com"] },
                ],
            },
        });
        fs::write(
            &xray_config_path,
            serde_json::to_string_pretty(&xray_cfg).unwrap(),
        )
        .unwrap();

        let mut mappings = BTreeMap::new();
        mappings.insert("new.corp.com".to_string(), "10.0.0.1".to_string());

        sync_to_config(xray_config_path.as_path(), &mappings).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&xray_config_path).unwrap()).unwrap();
        let rules = updated["routing"]["rules"].as_array().unwrap();
        // Should still be 2 rules (replaced, not duplicated)
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["ruleTag"], "corporate-dns");
        assert_eq!(rules[0]["domain"][0], "domain:new.corp.com");
        // Other rule preserved
        assert_eq!(rules[1]["outboundTag"], "proxy");
    }

    #[test]
    fn sync_to_config_adds_routing_when_section_missing() {
        let dir = tempfile::tempdir().unwrap();
        let xray_config_path = dir.path().join("config.json");

        // No routing section at all
        let xray_cfg = serde_json::json!({
            "inbounds": [],
            "outbounds": [],
        });
        fs::write(
            &xray_config_path,
            serde_json::to_string_pretty(&xray_cfg).unwrap(),
        )
        .unwrap();

        let mut mappings = BTreeMap::new();
        mappings.insert("corp.example.com".to_string(), "10.0.0.1".to_string());

        sync_to_config(xray_config_path.as_path(), &mappings).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&xray_config_path).unwrap()).unwrap();
        assert_eq!(updated["routing"]["domainStrategy"], "AsIs");
        let rules = updated["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["ruleTag"], "corporate-dns");
        assert_eq!(rules[0]["port"], 53);
    }

    #[test]
    fn sync_to_config_domains_are_deduplicated() {
        let dir = tempfile::tempdir().unwrap();
        let xray_config_path = dir.path().join("config.json");

        let xray_cfg = serde_json::json!({
            "inbounds": [],
            "outbounds": [],
        });
        fs::write(
            &xray_config_path,
            serde_json::to_string_pretty(&xray_cfg).unwrap(),
        )
        .unwrap();

        // BTreeMap already ensures unique keys, so domains will be unique
        let mut mappings = BTreeMap::new();
        mappings.insert("corp.example.com".to_string(), "10.0.0.1".to_string());

        sync_to_config(xray_config_path.as_path(), &mappings).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&xray_config_path).unwrap()).unwrap();
        let rules = updated["routing"]["rules"].as_array().unwrap();
        let domains = rules[0]["domain"].as_array().unwrap();
        // No duplicates
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0], "domain:corp.example.com");
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

    // Pins the end-to-end ordering across both mutators of routing.rules:
    // traffic::build_routing_rules (loopback rule at index 0) feeds
    // protocol::create_config, then dns::sync_to_config appends corporate-dns
    // at the tail without reordering. Loopback stays first, corporate-dns last.
    #[test]
    fn full_config_keeps_loopback_first_and_corp_dns_last() {
        let dir = tempfile::tempdir().unwrap();
        let xray_config_path = dir.path().join("config.json");

        let uri =
            "vless://uuid@host.com:443?encryption=none&type=grpc&security=tls&sni=host.com#proxy";
        let params = crate::protocol::parse_uri(uri).unwrap();
        let rules = crate::traffic::build_routing_rules(
            &["corp.com".to_string()],
            &["ext.com".to_string()],
            "proxy",
            true,
        );
        let config = crate::protocol::create_config(
            &params,
            30000,
            &rules,
            &crate::protocol::XrayLogConfig::default(),
        );
        fs::write(
            &xray_config_path,
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let mut mappings = BTreeMap::new();
        mappings.insert("corp.example.com".to_string(), "10.0.0.1".to_string());
        sync_to_config(xray_config_path.as_path(), &mappings).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&xray_config_path).unwrap()).unwrap();
        let rules = updated["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["ruleTag"], "loopback-and-private-direct");
        assert_eq!(rules.last().unwrap()["ruleTag"], "corporate-dns");
    }
}
