use crate::protocol::{params_from_outbound, ProxyParams};
use log::debug;
use serde_json::Value;

/// A single server candidate extracted from a Happ-format subscription entry.
pub struct HappEntry {
    pub params: ProxyParams,
    pub direct_domains: Vec<String>,
    pub direct_ips: Vec<String>,
}

/// Detect and parse a Happ-format subscription body: a JSON array of complete
/// xray configs, one per server. Returns `None` when the body does not match
/// this format (base64, a JSON object, or an array whose entries lack
/// `outbounds`), so callers can fall through to the plain base64 path.
pub fn parse_happ_subscription(body: &str) -> Option<Vec<HappEntry>> {
    let value: Value = serde_json::from_str(body).ok()?;
    let array = value.as_array()?;

    // Structural check: every element must be an object carrying an
    // "outbounds" array. `Value::get` returns None for non-object values, so
    // this also rejects arrays of non-objects and non-array "outbounds".
    if !array
        .iter()
        .all(|entry| entry.get("outbounds").and_then(|o| o.as_array()).is_some())
    {
        return None;
    }
    // Empty top-level array matches the format vacuously and yields Some(vec![]);
    // the caller (Task 7) treats an all-sources-empty result as "no servers found".

    let mut entries = Vec::new();
    for entry in array {
        let name = entry.get("remarks").and_then(|r| r.as_str()).unwrap_or("");
        let outbound = match entry
            .get("outbounds")
            .and_then(|o| o.as_array())
            .and_then(|a| a.first())
        {
            Some(ob) => ob,
            None => {
                debug!("happ entry has no outbounds[0], skipping");
                continue;
            }
        };

        let params = match params_from_outbound(outbound, name) {
            Ok(p) => p,
            Err(e) => {
                debug!("happ entry outbound could not be parsed, skipping: {e}");
                continue;
            }
        };

        let (direct_domains, direct_ips) = harvest_direct_rules(entry);
        entries.push(HappEntry {
            params,
            direct_domains,
            direct_ips,
        });
    }

    Some(entries)
}

/// Harvest `routing.rules[]` entries with `type == "field"` and
/// `outboundTag == "direct"`. Rules carrying a `protocol` key are skipped
/// entirely (protocol-based rules like bittorrent are not domain/ip lists).
fn harvest_direct_rules(entry: &Value) -> (Vec<String>, Vec<String>) {
    let mut domains = Vec::new();
    let mut ips = Vec::new();

    let Some(rules) = entry
        .get("routing")
        .and_then(|r| r.get("rules"))
        .and_then(|r| r.as_array())
    else {
        return (domains, ips);
    };

    for rule in rules {
        if rule.get("type").and_then(|t| t.as_str()) != Some("field") {
            continue;
        }
        if rule.get("outboundTag").and_then(|t| t.as_str()) != Some("direct") {
            continue;
        }
        if rule.get("protocol").is_some() {
            continue;
        }

        if let Some(list) = rule.get("domain").and_then(|d| d.as_array()) {
            domains.extend(list.iter().filter_map(|v| v.as_str().map(String::from)));
        }
        if let Some(list) = rule.get("ip").and_then(|d| d.as_array()) {
            ips.extend(list.iter().filter_map(|v| v.as_str().map(String::from)));
        }
    }

    (domains, ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sanitized fixture mirroring a real Happ panel response shape: an array
    // of complete xray configs, one per server. Placeholder uuids/hosts only.
    const HAPP_FIXTURE: &str = r#"[
      {
        "remarks": "Server One",
        "dns": {},
        "inbounds": [],
        "log": {},
        "outbounds": [
          {
            "protocol": "vless",
            "settings": {
              "vnext": [
                {
                  "address": "example.com",
                  "port": 443,
                  "users": [
                    { "id": "00000000-0000-0000-0000-000000000000", "encryption": "none" }
                  ]
                }
              ]
            },
            "streamSettings": { "network": "tcp", "security": "" },
            "tag": "proxy"
          },
          { "protocol": "freedom", "tag": "direct" }
        ],
        "routing": {
          "rules": [
            { "type": "field", "protocol": ["bittorrent"], "outboundTag": "direct" },
            { "type": "field", "ip": ["geoip:private"], "outboundTag": "direct" },
            { "type": "field", "domain": ["geosite:category-ru", "domain:ru", "domain:yandex.com"], "outboundTag": "direct" },
            { "type": "field", "ip": ["geoip:ru"], "outboundTag": "direct" },
            { "type": "field", "domain": ["geosite:meta"], "outboundTag": "proxy" }
          ]
        }
      },
      {
        "remarks": "Server Two",
        "dns": {},
        "inbounds": [],
        "log": {},
        "outbounds": [
          {
            "protocol": "vless",
            "settings": {
              "vnext": [
                {
                  "address": "example.org",
                  "port": 8443,
                  "users": [
                    { "id": "11111111-1111-1111-1111-111111111111", "encryption": "none" }
                  ]
                }
              ]
            },
            "streamSettings": { "network": "tcp", "security": "" },
            "tag": "proxy"
          },
          { "protocol": "freedom", "tag": "direct" }
        ],
        "routing": { "rules": [] }
      }
    ]"#;

    #[test]
    fn fixture_parses_to_two_entries() {
        let entries = parse_happ_subscription(HAPP_FIXTURE).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn fixture_params_match_first_entry() {
        let entries = parse_happ_subscription(HAPP_FIXTURE).unwrap();
        let p = &entries[0].params;
        assert_eq!(p.protocol, "vless");
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, 443);
        assert_eq!(p.name, "Server One");
        assert_eq!(p.uuid, "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn fixture_params_match_second_entry() {
        let entries = parse_happ_subscription(HAPP_FIXTURE).unwrap();
        let p = &entries[1].params;
        assert_eq!(p.protocol, "vless");
        assert_eq!(p.host, "example.org");
        assert_eq!(p.port, 8443);
        assert_eq!(p.name, "Server Two");
        assert_eq!(p.uuid, "11111111-1111-1111-1111-111111111111");
    }

    #[test]
    fn direct_domains_exclude_proxy_rule() {
        let entries = parse_happ_subscription(HAPP_FIXTURE).unwrap();
        assert_eq!(
            entries[0].direct_domains,
            vec!["geosite:category-ru", "domain:ru", "domain:yandex.com"]
        );
        assert!(!entries[0]
            .direct_domains
            .iter()
            .any(|d| d == "geosite:meta"));
    }

    #[test]
    fn direct_ips_from_direct_rules_only() {
        let entries = parse_happ_subscription(HAPP_FIXTURE).unwrap();
        assert_eq!(entries[0].direct_ips, vec!["geoip:private", "geoip:ru"]);
    }

    #[test]
    fn second_entry_has_no_direct_rules() {
        let entries = parse_happ_subscription(HAPP_FIXTURE).unwrap();
        assert!(entries[1].direct_domains.is_empty());
        assert!(entries[1].direct_ips.is_empty());
    }

    #[test]
    fn protocol_rule_with_domain_is_skipped_entirely() {
        let body = r#"[{
            "remarks": "Server",
            "outbounds": [{
                "protocol": "vless",
                "settings": { "vnext": [{ "address": "example.com", "port": 443,
                    "users": [{ "id": "00000000-0000-0000-0000-000000000000", "encryption": "none" }] }] },
                "streamSettings": { "network": "tcp", "security": "" }
            }],
            "routing": { "rules": [
                { "type": "field", "protocol": ["bittorrent"], "domain": ["bt.example.com"], "outboundTag": "direct" }
            ] }
        }]"#;
        let entries = parse_happ_subscription(body).unwrap();
        assert!(entries[0].direct_domains.is_empty());
    }

    #[test]
    fn base64_body_returns_none() {
        let body = "dmxlc3M6Ly9leGFtcGxl";
        assert!(parse_happ_subscription(body).is_none());
    }

    #[test]
    fn json_object_returns_none() {
        let body = r#"{"outbounds": []}"#;
        assert!(parse_happ_subscription(body).is_none());
    }

    #[test]
    fn array_without_outbounds_key_returns_none() {
        let body = r#"[{"remarks": "Server", "routing": {"rules": []}}]"#;
        assert!(parse_happ_subscription(body).is_none());
    }

    #[test]
    fn empty_outbounds_array_entry_is_skipped() {
        let body = r#"[
            { "remarks": "Empty", "outbounds": [] },
            { "remarks": "Good", "outbounds": [{
                "protocol": "vless",
                "settings": { "vnext": [{ "address": "example.com", "port": 443,
                    "users": [{ "id": "00000000-0000-0000-0000-000000000000", "encryption": "none" }] }] },
                "streamSettings": { "network": "tcp", "security": "" }
            }] }
        ]"#;
        let entries = parse_happ_subscription(body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].params.name, "Good");
    }

    #[test]
    fn mixed_array_one_entry_missing_outbounds_returns_none() {
        let body = r#"[
            { "remarks": "Good", "outbounds": [{ "protocol": "vless" }] },
            { "remarks": "NoOutbounds" }
        ]"#;
        assert!(parse_happ_subscription(body).is_none());
    }

    #[test]
    fn outbounds_non_array_returns_none() {
        let body = r#"[{"remarks": "Server", "outbounds": 5}]"#;
        assert!(parse_happ_subscription(body).is_none());
    }

    #[test]
    fn empty_top_level_array_returns_some_empty() {
        let entries = parse_happ_subscription("[]").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn non_string_domain_entries_dropped_non_string_remarks_falls_back() {
        let body = r#"[{
            "remarks": 123,
            "outbounds": [{
                "protocol": "vless",
                "settings": { "vnext": [{ "address": "example.com", "port": 443,
                    "users": [{ "id": "00000000-0000-0000-0000-000000000000", "encryption": "none" }] }] },
                "streamSettings": { "network": "tcp", "security": "" }
            }],
            "routing": { "rules": [
                { "type": "field", "domain": ["domain:ru", 42], "outboundTag": "direct" }
            ] }
        }]"#;
        let entries = parse_happ_subscription(body).unwrap();
        assert_eq!(entries[0].direct_domains, vec!["domain:ru"]);
        assert_eq!(entries[0].params.name, "");
    }

    #[test]
    fn unparseable_entry_is_skipped_others_kept() {
        let body = r#"[
            { "remarks": "Bad", "outbounds": [{ "protocol": "freedom", "settings": {} }] },
            { "remarks": "Good", "outbounds": [{
                "protocol": "vless",
                "settings": { "vnext": [{ "address": "example.com", "port": 443,
                    "users": [{ "id": "00000000-0000-0000-0000-000000000000", "encryption": "none" }] }] },
                "streamSettings": { "network": "tcp", "security": "" }
            }] }
        ]"#;
        let entries = parse_happ_subscription(body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].params.name, "Good");
    }
}
