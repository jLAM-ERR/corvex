use anyhow::{Context, Result};
use log::debug;
use std::collections::BTreeMap;
use std::fs;
#[cfg(any(test, target_os = "macos"))]
use std::net::IpAddr;
use std::path::Path;

/// One resolver block from `scutil --dns`.
///
/// A resolver may be scoped to a domain (split-DNS / corp DNS) or global, and it
/// may list any number of nameservers. Both are preserved here: `domain: None`
/// marks a global resolver, and `nameservers` keeps every `nameserver[N]` line in
/// the order scutil printed them, so a failover pair survives parsing.
///
/// Every platform's `Platform::list_system_resolvers` speaks in these, so the
/// type is unconditional even though the scutil parser below it is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverEntry {
    /// `None` for a global/default resolver — one with no `domain` line.
    pub domain: Option<String>,
    /// Every nameserver of this resolver, in scutil's order.
    pub nameservers: Vec<String>,
    /// Interface name from `if_index : 14 (en0)`, when the resolver is scoped.
    pub interface: Option<String>,
}

/// Parse `scutil --dns` output into one [`ResolverEntry`] per resolver block.
///
/// Every resolver that lists at least one nameserver is returned, global ones
/// included; a resolver with no nameservers is dropped because there is nothing
/// to query or diagnose. Lines other than `domain`, `nameserver[N]` and
/// `if_index` are ignored.
///
/// Parsing stops at `DNS configuration (for scoped queries)`. scutil prints the
/// same resolvers a second time in that section, renumbered from `#1`, so
/// reading it too would list — and probe — every nameserver twice.
///
/// Gated to macOS plus `test`: `scutil --dns` is a macOS command, so nothing
/// else calls this, but every platform's test run still covers the fixtures.
#[cfg(any(test, target_os = "macos"))]
pub fn parse_scutil_dns(output: &str) -> Vec<ResolverEntry> {
    let mut resolvers: Vec<ResolverEntry> = Vec::new();
    let mut current: Option<ResolverEntry> = None;

    // Keeps a resolver only once it has somewhere to send a query.
    fn flush(resolvers: &mut Vec<ResolverEntry>, entry: Option<ResolverEntry>) {
        if let Some(entry) = entry.filter(|entry| !entry.nameservers.is_empty()) {
            resolvers.push(entry);
        }
    }

    for line in output.lines() {
        let trimmed = line.trim();

        // "DNS configuration (for scoped queries)" — the repeat listing. The
        // plain "DNS configuration" header has no parenthesis and is kept.
        if trimmed.starts_with("DNS configuration (") {
            break;
        }

        // New resolver block flushes the previous one
        if trimmed.starts_with("resolver #") {
            flush(&mut resolvers, current.take());
            current = Some(ResolverEntry {
                domain: None,
                nameservers: Vec::new(),
                interface: None,
            });
            continue;
        }

        let Some(entry) = current.as_mut() else {
            // Preamble before the first "resolver #" header
            continue;
        };

        // "domain   : corp.example.com" — split-DNS domain (not "search domain")
        if trimmed.starts_with("domain") && !trimmed.starts_with("domain_") {
            if let Some(value) = field_value(trimmed).filter(|value| !value.is_empty()) {
                entry.domain = Some(value.to_string());
            }
            continue;
        }

        // "nameserver[0] : 10.10.20.53" — every one of them, in order.
        if trimmed.starts_with("nameserver[") {
            if let Some(value) = field_value(trimmed).filter(|value| is_ip_literal(value)) {
                entry.nameservers.push(value.to_string());
            }
            continue;
        }

        // "if_index : 14 (en0)" — the interface name lives in the parentheses
        if trimmed.starts_with("if_index") {
            if let Some(name) = trimmed
                .split_once('(')
                .and_then(|(_, rest)| rest.split_once(')'))
                .map(|(name, _)| name.trim())
                .filter(|name| !name.is_empty())
            {
                entry.interface = Some(name.to_string());
            }
        }
    }

    flush(&mut resolvers, current);
    resolvers
}

/// The value side of a `key : value` scutil line, trimmed.
///
/// `split_once`, not `split(':').nth(1)`, so an IPv6 nameserver survives.
#[cfg(any(test, target_os = "macos"))]
fn field_value(line: &str) -> Option<&str> {
    line.split_once(':').map(|(_, value)| value.trim())
}

/// True if `value` is an IP address, with or without an IPv6 zone id
/// (`fe80::1%en0`). The zone is stripped only for validation; callers keep the
/// literal scutil printed.
#[cfg(any(test, target_os = "macos"))]
fn is_ip_literal(value: &str) -> bool {
    let addr = value.split_once('%').map_or(value, |(head, _)| head);
    addr.parse::<IpAddr>().is_ok()
}

/// Project resolver entries down to the one-nameserver-per-domain map the xray
/// DNS block still takes.
///
/// **This is lossy by design.** Global resolvers (`domain: None`) are dropped
/// entirely, every nameserver after the first usable one is discarded, and the
/// first resolver scoped to a given domain wins over any later one. A failover
/// pair therefore collapses to its primary, and the interface is lost.
///
/// Zone-scoped IPv6 literals (`fe80::1%en0`) are skipped rather than collapsed:
/// [`sync_to_config`] writes the string straight into `dns.servers[].address`,
/// and xray reads anything that is not a bare IP literal as a *domain*, so a
/// zone id would land in the config as a silently wrong server.
///
/// That is tolerable only because the xray DNS block this feeds is inert today:
/// `domainStrategy` is `"AsIs"`, so the servers written by
/// [`sync_to_config`] are never actually consulted for resolution. The real fix
/// — carrying the full `Vec<String>` of nameservers through to the config —
/// belongs to the `dns-parser-fixes` plan, not here. Diagnostics read the rich
/// [`ResolverEntry`] list directly and must not go through this projection.
#[cfg(any(test, target_os = "macos"))]
pub fn corporate_mappings_first(resolvers: &[ResolverEntry]) -> BTreeMap<String, String> {
    let mut mappings = BTreeMap::new();
    for entry in resolvers {
        let usable = entry
            .nameservers
            .iter()
            .find(|nameserver| !nameserver.contains('%'));
        if let (Some(domain), Some(nameserver)) = (&entry.domain, usable) {
            // `or_insert`, not `insert`: first resolver scoped to a domain wins.
            mappings
                .entry(domain.clone())
                .or_insert_with(|| nameserver.clone());
        }
    }
    mappings
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

    // Sanitized shape of a real `scutil --dns`: a global resolver with a
    // failover nameserver pair and no domain line, then a domain-scoped one.
    // Values are fixtures only — see the plan's sanitization table.
    const SCUTIL_FIXTURE: &str = "\
DNS configuration

resolver #1
  nameserver[0] : 10.10.20.53
  nameserver[1] : 10.10.20.54
  flags    : Request A records
  reach    : 0x00000002 (Reachable)
  order    : 5000

resolver #5
  domain   : corp.example.com
  nameserver[0] : 10.10.20.53
  if_index : 14 (en0)
  flags    : Scoped, Request A records
";

    #[test]
    fn parse_scutil_dns_keeps_all_nameservers() {
        let resolvers = parse_scutil_dns(SCUTIL_FIXTURE);

        assert_eq!(
            resolvers[0].nameservers,
            vec!["10.10.20.53".to_string(), "10.10.20.54".to_string()]
        );
    }

    #[test]
    fn parse_scutil_dns_harvests_domainless_resolver() {
        let resolvers = parse_scutil_dns(SCUTIL_FIXTURE);

        assert_eq!(resolvers.len(), 2);
        assert_eq!(resolvers[0].domain, None);
        assert_eq!(resolvers[0].interface, None);
    }

    #[test]
    fn parse_scutil_dns_scoped_resolver_carries_domain_and_interface() {
        let resolvers = parse_scutil_dns(SCUTIL_FIXTURE);

        let scoped = &resolvers[1];
        assert_eq!(scoped.domain.as_deref(), Some("corp.example.com"));
        assert_eq!(scoped.nameservers, vec!["10.10.20.53".to_string()]);
        assert_eq!(scoped.interface.as_deref(), Some("en0"));
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
  nameserver[0] : 10.10.20.53
  nameserver[1] : 10.10.20.54
  if_index : 18 (utun3)
  flags    : Request A records

resolver #3
  domain   : internal.example
  nameserver[0] : 10.10.20.1
  if_index : 18 (utun3)

resolver #4
  nameserver[0] : 8.8.8.8
  flags    : Request A records
";

        let resolvers = parse_scutil_dns(output);

        // Every resolver survives now, scoped and global alike.
        assert_eq!(resolvers.len(), 4);
        assert_eq!(resolvers[0].domain, None);
        assert_eq!(resolvers[0].interface.as_deref(), Some("en0"));
        assert_eq!(resolvers[1].domain.as_deref(), Some("corp.example.com"));
        assert_eq!(resolvers[1].nameservers.len(), 2);
        assert_eq!(resolvers[2].domain.as_deref(), Some("internal.example"));
        assert_eq!(resolvers[3].domain, None);
        assert_eq!(resolvers[3].nameservers, vec!["8.8.8.8".to_string()]);
        assert_eq!(resolvers[3].interface, None);
    }

    #[test]
    fn parse_scutil_dns_drops_resolver_without_nameservers() {
        let output = "\
resolver #1
  domain   : corp.example.com
  if_index : 14 (en0)

resolver #2
  nameserver[0] : 10.10.20.53
";

        let resolvers = parse_scutil_dns(output);
        assert_eq!(resolvers.len(), 1);
        assert_eq!(resolvers[0].nameservers, vec!["10.10.20.53".to_string()]);
    }

    #[test]
    fn parse_scutil_dns_stops_at_the_scoped_queries_section() {
        // scutil repeats the same resolvers in a second section, renumbered
        // from #1. Reading both would list and probe every nameserver twice.
        let output = "\
DNS configuration

resolver #1
  nameserver[0] : 10.10.20.53
  if_index : 14 (en0)

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 10.10.20.53
  if_index : 14 (en0)
  flags    : Scoped, Request A records
";

        let resolvers = parse_scutil_dns(output);
        assert_eq!(resolvers.len(), 1, "the scoped repeat is not a resolver");
        assert_eq!(resolvers[0].nameservers, vec!["10.10.20.53".to_string()]);
    }

    #[test]
    fn parse_scutil_dns_empty_output() {
        assert!(parse_scutil_dns("").is_empty());
    }

    #[test]
    fn parse_scutil_dns_garbage_output() {
        let output = "\
not a resolver block
  domain   : corp.example.com
  nameserver[0] : 10.10.20.53
";

        // Without a "resolver #" header there is no block to attach lines to.
        assert!(parse_scutil_dns(output).is_empty());
    }

    fn entry(domain: Option<&str>, nameservers: &[&str]) -> ResolverEntry {
        ResolverEntry {
            domain: domain.map(str::to_string),
            nameservers: nameservers.iter().map(|ns| ns.to_string()).collect(),
            interface: None,
        }
    }

    #[test]
    fn corporate_mappings_first_drops_global_resolvers() {
        let resolvers = vec![
            entry(None, &["10.10.20.53", "10.10.20.54"]),
            entry(Some("corp.example.com"), &["10.10.20.53"]),
        ];

        let mappings = corporate_mappings_first(&resolvers);

        // A BTreeMap<String, String> holding only the domain-scoped resolver.
        let mut expected: BTreeMap<String, String> = BTreeMap::new();
        expected.insert("corp.example.com".to_string(), "10.10.20.53".to_string());
        assert_eq!(mappings, expected);
    }

    #[test]
    fn corporate_mappings_first_takes_only_the_primary_nameserver() {
        let resolvers = vec![entry(
            Some("corp.example.com"),
            &["10.10.20.53", "10.10.20.54"],
        )];

        let mappings = corporate_mappings_first(&resolvers);

        assert_eq!(mappings.len(), 1);
        assert_eq!(
            mappings.get("corp.example.com").map(String::as_str),
            Some("10.10.20.53")
        );
    }

    #[test]
    fn corporate_mappings_first_keeps_the_first_of_duplicate_domains() {
        let resolvers = vec![
            entry(Some("corp.example.com"), &["10.10.20.53"]),
            entry(Some("corp.example.com"), &["10.10.20.54"]),
        ];

        let mappings = corporate_mappings_first(&resolvers);

        assert_eq!(
            mappings.get("corp.example.com").map(String::as_str),
            Some("10.10.20.53")
        );
    }

    #[test]
    fn corporate_mappings_first_skips_scoped_resolver_without_nameservers() {
        let resolvers = vec![entry(Some("corp.example.com"), &[])];

        assert!(corporate_mappings_first(&resolvers).is_empty());
    }

    #[test]
    fn corporate_mappings_first_on_empty_input() {
        assert!(corporate_mappings_first(&[]).is_empty());
    }

    #[test]
    fn corporate_mappings_first_skips_a_zone_scoped_nameserver() {
        // xray reads a `dns.servers[].address` that is not a bare IP literal as
        // a domain, so `fe80::1%en0` would land in config.json as a silently
        // wrong server. The failover partner behind it is used instead.
        let resolvers = vec![entry(
            Some("corp.example.com"),
            &["fe80::1%en0", "10.10.20.53"],
        )];

        let mappings = corporate_mappings_first(&resolvers);

        assert_eq!(
            mappings.get("corp.example.com").map(String::as_str),
            Some("10.10.20.53")
        );
    }

    #[test]
    fn corporate_mappings_first_drops_a_resolver_with_only_zone_scoped_nameservers() {
        let resolvers = vec![entry(Some("corp.example.com"), &["fe80::1%en0"])];

        assert!(
            corporate_mappings_first(&resolvers).is_empty(),
            "no usable literal means no mapping, not a broken one"
        );
    }

    // The projection is what the macOS discover_corporate_dns feeds to
    // sync_to_config, so drive it straight off the parser fixture.
    #[test]
    fn corporate_mappings_first_projects_the_scutil_fixture() {
        let mappings = corporate_mappings_first(&parse_scutil_dns(SCUTIL_FIXTURE));

        assert_eq!(mappings.len(), 1);
        assert_eq!(
            mappings.get("corp.example.com").map(String::as_str),
            Some("10.10.20.53")
        );
    }

    #[test]
    fn parse_scutil_dns_keeps_ipv6_nameserver_with_zone() {
        let output = "\
resolver #1
  nameserver[0] : fe80::1%en0
  nameserver[1] : not-an-ip
";

        let resolvers = parse_scutil_dns(output);
        assert_eq!(resolvers[0].nameservers, vec!["fe80::1%en0".to_string()]);
    }

    #[test]
    fn sync_to_config_adds_dns_servers() {
        let dir = crate::config::test_tempdir();
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
        let dir = crate::config::test_tempdir();
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
        let dir = crate::config::test_tempdir();
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
        let dir = crate::config::test_tempdir();
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
        let dir = crate::config::test_tempdir();
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
        let dir = crate::config::test_tempdir();
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

    // The parser no longer de-duplicates: two resolvers scoped to the same
    // domain are two entries, in scutil's order. Collapsing them to one
    // nameserver is the xray-facing projection's job (see Task 6).
    #[test]
    fn parse_scutil_dns_keeps_duplicate_domains_in_order() {
        let output = "\
resolver #1
  domain   : corp.example.com
  nameserver[0] : 10.10.20.53

resolver #2
  domain   : corp.example.com
  nameserver[0] : 10.10.20.54
";

        let resolvers = parse_scutil_dns(output);
        assert_eq!(resolvers.len(), 2);
        assert_eq!(resolvers[0].nameservers, vec!["10.10.20.53".to_string()]);
        assert_eq!(resolvers[1].nameservers, vec!["10.10.20.54".to_string()]);
    }

    // Pins the end-to-end ordering across both mutators of routing.rules:
    // traffic::build_routing_rules (loopback rule at index 0) feeds
    // protocol::create_config, then dns::sync_to_config appends corporate-dns
    // at the tail without reordering. Loopback stays first, corporate-dns last.
    #[test]
    fn full_config_keeps_loopback_first_and_corp_dns_last() {
        let dir = crate::config::test_tempdir();
        let xray_config_path = dir.path().join("config.json");

        let uri =
            "vless://uuid@host.com:443?encryption=none&type=grpc&security=tls&sni=host.com#proxy";
        let params = crate::protocol::parse_uri(uri).unwrap();
        let rules = crate::traffic::build_routing_rules(
            &["corp.com".to_string()],
            &["ext.com".to_string()],
            "proxy",
            &[],
            &[],
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
