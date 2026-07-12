use log::debug;
use std::collections::HashSet;

const KNOWN_PREFIXES: &[&str] = &[
    "domain:", "regexp:", "full:", "keyword:", "geosite:", "ext:",
];

/// Normalize a traffic entry: prepend `domain:` if no recognized prefix is present.
pub fn normalize_entry(entry: &str) -> String {
    if KNOWN_PREFIXES.iter().any(|p| entry.starts_with(p)) {
        entry.to_string()
    } else {
        format!("domain:{entry}")
    }
}

/// Union `ctraffic` and `subs_direct_domains` (normalized, deduped), dropping
/// any `subs_direct_domains` entry that also appears in `ptraffic` — local
/// proxy-traffic wins. `ctraffic` entries are never excluded: they are the
/// user's own config and must keep matching the direct rule first, even if
/// the same domain is also listed under proxy-traffic.
fn merge_direct_domains(
    ctraffic: &[String],
    subs_direct_domains: &[String],
    ptraffic: &[String],
) -> Vec<serde_json::Value> {
    let excluded: HashSet<String> = ptraffic.iter().map(|e| normalize_entry(e)).collect();
    let mut seen = HashSet::new();
    let mut merged = Vec::new();
    for entry in ctraffic {
        let normalized = normalize_entry(entry);
        if seen.insert(normalized.clone()) {
            merged.push(serde_json::Value::String(normalized));
        }
    }
    for entry in subs_direct_domains {
        let normalized = normalize_entry(entry);
        if excluded.contains(&normalized) {
            continue;
        }
        if seen.insert(normalized.clone()) {
            merged.push(serde_json::Value::String(normalized));
        }
    }
    merged
}

/// Dedup subscription direct-ip entries case-insensitively, dropping
/// `geoip:private` (any case) since rule 0 already covers it.
fn dedup_subs_direct_ips(subs_direct_ips: &[String]) -> Vec<serde_json::Value> {
    let mut seen = HashSet::new();
    let mut ips = Vec::new();
    for entry in subs_direct_ips {
        if entry.eq_ignore_ascii_case("geoip:private") {
            continue;
        }
        if seen.insert(entry.to_ascii_lowercase()) {
            ips.push(serde_json::Value::String(entry.clone()));
        }
    }
    ips
}

/// Build xray routing rules from corporate-traffic and proxy-traffic domain lists,
/// merging in any subscription-provided direct domain/ip entries.
pub fn build_routing_rules(
    ctraffic: &[String],
    ptraffic: &[String],
    proxy_tag: &str,
    ru_direct: bool,
    subs_direct_domains: &[String],
    subs_direct_ips: &[String],
) -> Vec<serde_json::Value> {
    let mut rules = Vec::new();

    // Always route loopback + RFC1918 private networks DIRECT. This MUST be the
    // first rule (index 0) so it wins xray's first-match routing. Tunneling
    // localhost or private IPs through a public VPN exit never works — the exit
    // interprets 127.0.0.1 as itself and private ranges aren't routable across it.
    rules.push(serde_json::json!({
        "ruleTag": "loopback-and-private-direct",
        "outboundTag": "direct",
        "ip": ["127.0.0.0/8", "::1/128", "geoip:private"],
    }));

    let subs_ips = dedup_subs_direct_ips(subs_direct_ips);
    if !subs_ips.is_empty() {
        rules.push(serde_json::json!({
            "outboundTag": "direct",
            "ip": subs_ips,
        }));
    }

    let merged_domains = merge_direct_domains(ctraffic, subs_direct_domains, ptraffic);
    if !merged_domains.is_empty() {
        rules.push(serde_json::json!({
            "outboundTag": "direct",
            "domain": merged_domains,
        }));
    }

    if !ptraffic.is_empty() {
        let domains: Vec<serde_json::Value> = ptraffic
            .iter()
            .map(|e| serde_json::Value::String(normalize_entry(e)))
            .collect();
        rules.push(serde_json::json!({
            "outboundTag": proxy_tag,
            "domain": domains,
        }));
    }

    if ru_direct {
        rules.push(serde_json::json!({
            "ruleTag": "ru-tld-direct",
            "domain": ["regexp:\\.ru$"],
            "outboundTag": "direct",
        }));
    }

    debug!("built {} routing rules", rules.len());
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_entry_domain_prefix() {
        assert_eq!(normalize_entry("domain:x.com"), "domain:x.com");
    }

    #[test]
    fn test_normalize_entry_no_prefix() {
        assert_eq!(normalize_entry("x.com"), "domain:x.com");
    }

    #[test]
    fn test_normalize_entry_regexp_prefix() {
        assert_eq!(normalize_entry("regexp:.*\\.corp$"), "regexp:.*\\.corp$");
    }

    #[test]
    fn test_normalize_entry_all_known_prefixes() {
        assert_eq!(normalize_entry("full:example.com"), "full:example.com");
        assert_eq!(normalize_entry("keyword:example"), "keyword:example");
        assert_eq!(normalize_entry("geosite:cn"), "geosite:cn");
        assert_eq!(normalize_entry("ext:file.dat:tag"), "ext:file.dat:tag");
    }

    /// Assert the unconditional loopback/private rule is always at index 0.
    fn assert_loopback_rule_first(rules: &[serde_json::Value]) {
        assert_eq!(rules[0]["ruleTag"], "loopback-and-private-direct");
        assert_eq!(rules[0]["outboundTag"], "direct");
    }

    #[test]
    fn test_build_routing_rules_ctraffic_only() {
        let ct = vec!["corp.example.com".to_string()];
        let rules = build_routing_rules(&ct, &[], "proxy", false, &[], &[]);
        assert_eq!(rules.len(), 2);
        assert_loopback_rule_first(&rules);
        assert_eq!(rules[1]["outboundTag"], "direct");
        assert_eq!(rules[1]["domain"][0], "domain:corp.example.com");
    }

    #[test]
    fn test_build_routing_rules_ptraffic_only() {
        let pt = vec!["external.com".to_string()];
        let rules = build_routing_rules(&[], &pt, "proxy-out", false, &[], &[]);
        assert_eq!(rules.len(), 2);
        assert_loopback_rule_first(&rules);
        assert_eq!(rules[1]["outboundTag"], "proxy-out");
        assert_eq!(rules[1]["domain"][0], "domain:external.com");
    }

    #[test]
    fn test_build_routing_rules_both() {
        let ct = vec!["corp.com".to_string()];
        let pt = vec!["ext.com".to_string()];
        let rules = build_routing_rules(&ct, &pt, "proxy", false, &[], &[]);
        assert_eq!(rules.len(), 3);
        assert_loopback_rule_first(&rules);
        assert_eq!(rules[1]["outboundTag"], "direct");
        assert_eq!(rules[2]["outboundTag"], "proxy");
    }

    #[test]
    fn test_build_routing_rules_with_ru_flag() {
        let rules = build_routing_rules(&[], &[], "proxy", true, &[], &[]);
        assert_eq!(rules.len(), 2);
        assert_loopback_rule_first(&rules);
        assert_eq!(rules[1]["ruleTag"], "ru-tld-direct");
        assert_eq!(rules[1]["domain"][0], "regexp:\\.ru$");
        assert_eq!(rules[1]["outboundTag"], "direct");
    }

    #[test]
    fn test_build_routing_rules_both_with_ru() {
        let ct = vec!["corp.com".to_string()];
        let pt = vec!["ext.com".to_string()];
        let rules = build_routing_rules(&ct, &pt, "proxy", true, &[], &[]);
        assert_eq!(rules.len(), 4);
        assert_loopback_rule_first(&rules);
        assert_eq!(rules[1]["outboundTag"], "direct");
        assert_eq!(rules[2]["outboundTag"], "proxy");
        assert_eq!(rules[3]["ruleTag"], "ru-tld-direct");
    }

    #[test]
    fn test_build_routing_rules_always_emits_loopback_rule_first() {
        let rules = build_routing_rules(&[], &[], "proxy", false, &[], &[]);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["ruleTag"], "loopback-and-private-direct");
        assert_eq!(rules[0]["outboundTag"], "direct");
        let ips: Vec<&str> = rules[0]["ip"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(ips, vec!["127.0.0.0/8", "::1/128", "geoip:private"]);
    }

    #[test]
    fn test_build_routing_rules_loopback_rule_uses_ip_field_not_domain() {
        let rules = build_routing_rules(&[], &[], "proxy", false, &[], &[]);
        assert!(rules[0].get("domain").is_none());
        assert!(rules[0]["ip"].is_array());
    }

    #[test]
    fn test_build_routing_rules_merge_dedup() {
        let ct = vec!["corp.com".to_string()];
        let subs_domains = vec!["corp.com".to_string(), "other.com".to_string()];
        let rules = build_routing_rules(&ct, &[], "proxy", false, &subs_domains, &[]);
        assert_eq!(rules.len(), 2);
        assert_loopback_rule_first(&rules);
        let domains = rules[1]["domain"].as_array().unwrap();
        assert_eq!(domains.len(), 2);
        assert_eq!(domains[0], "domain:corp.com");
        assert_eq!(domains[1], "domain:other.com");
    }

    #[test]
    fn test_build_routing_rules_proxy_traffic_excludes_subs_direct_domain() {
        let pt = vec!["shared.com".to_string()];
        let subs_domains = vec!["shared.com".to_string(), "unique.com".to_string()];
        let rules = build_routing_rules(&[], &pt, "proxy", false, &subs_domains, &[]);
        assert_eq!(rules.len(), 3);
        assert_loopback_rule_first(&rules);
        let direct_domains = rules[1]["domain"].as_array().unwrap();
        assert_eq!(direct_domains.len(), 1);
        assert_eq!(direct_domains[0], "domain:unique.com");
        assert_eq!(rules[2]["outboundTag"], "proxy");
        assert_eq!(rules[2]["domain"][0], "domain:shared.com");
    }

    #[test]
    fn test_build_routing_rules_subs_direct_ip_filters_geoip_private() {
        let subs_ips = vec!["geoip:private".to_string(), "geoip:ru".to_string()];
        let rules = build_routing_rules(&[], &[], "proxy", false, &[], &subs_ips);
        assert_eq!(rules.len(), 2);
        assert_loopback_rule_first(&rules);
        let ips = rules[1]["ip"].as_array().unwrap();
        assert_eq!(
            ips,
            &vec![serde_json::Value::String("geoip:ru".to_string())]
        );
    }

    #[test]
    fn test_build_routing_rules_subs_direct_ip_placed_right_after_loopback() {
        let ct = vec!["corp.com".to_string()];
        let subs_ips = vec!["geoip:ru".to_string()];
        let rules = build_routing_rules(&ct, &[], "proxy", true, &[], &subs_ips);
        assert_eq!(rules.len(), 4);
        assert_loopback_rule_first(&rules);
        assert_eq!(rules[1]["outboundTag"], "direct");
        assert_eq!(rules[1]["ip"][0], "geoip:ru");
        assert_eq!(rules[2]["outboundTag"], "direct");
        assert_eq!(rules[2]["domain"][0], "domain:corp.com");
        assert_eq!(rules[3]["ruleTag"], "ru-tld-direct");
    }

    #[test]
    fn test_build_routing_rules_geosite_prefix_preserved_unnormalized() {
        let subs_domains = vec!["geosite:category-ru".to_string()];
        let rules = build_routing_rules(&[], &[], "proxy", false, &subs_domains, &[]);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[1]["domain"][0], "geosite:category-ru");
    }

    // Regression: a domain present in both ctraffic and ptraffic must stay in
    // the direct rule (xray first-match routes it direct) — this held before
    // the merge feature and must not change on the empty-slices path.
    #[test]
    fn test_build_routing_rules_ctraffic_ptraffic_overlap_stays_direct() {
        let ct = vec!["shared.com".to_string()];
        let pt = vec!["shared.com".to_string()];
        let rules = build_routing_rules(&ct, &pt, "proxy", false, &[], &[]);
        assert_eq!(rules.len(), 3);
        assert_loopback_rule_first(&rules);
        assert_eq!(rules[1]["outboundTag"], "direct");
        assert_eq!(rules[1]["domain"][0], "domain:shared.com");
        assert_eq!(rules[2]["outboundTag"], "proxy");
        assert_eq!(rules[2]["domain"][0], "domain:shared.com");
    }

    #[test]
    fn test_build_routing_rules_exclusion_ignores_prefix_mismatch_bare_ptraffic() {
        let pt = vec!["yandex.com".to_string()];
        let subs_domains = vec!["domain:yandex.com".to_string()];
        let rules = build_routing_rules(&[], &pt, "proxy", false, &subs_domains, &[]);
        // subs domain excluded via normalized match -> no direct rule, only proxy rule
        assert_eq!(rules.len(), 2);
        assert_loopback_rule_first(&rules);
        assert_eq!(rules[1]["outboundTag"], "proxy");
        assert_eq!(rules[1]["domain"][0], "domain:yandex.com");
    }

    #[test]
    fn test_build_routing_rules_exclusion_ignores_prefix_mismatch_prefixed_ptraffic() {
        let pt = vec!["domain:x.com".to_string()];
        let subs_domains = vec!["x.com".to_string()];
        let rules = build_routing_rules(&[], &pt, "proxy", false, &subs_domains, &[]);
        assert_eq!(rules.len(), 2);
        assert_loopback_rule_first(&rules);
        assert_eq!(rules[1]["outboundTag"], "proxy");
        assert_eq!(rules[1]["domain"][0], "domain:x.com");
    }

    #[test]
    fn test_build_routing_rules_subs_direct_ip_geoip_private_filter_case_insensitive() {
        let subs_ips = vec!["GEOIP:PRIVATE".to_string(), "geoip:ru".to_string()];
        let rules = build_routing_rules(&[], &[], "proxy", false, &[], &subs_ips);
        assert_eq!(rules.len(), 2);
        let ips = rules[1]["ip"].as_array().unwrap();
        assert_eq!(
            ips,
            &vec![serde_json::Value::String("geoip:ru".to_string())]
        );
    }

    #[test]
    fn test_build_routing_rules_subs_direct_ip_dedup_case_insensitive() {
        let subs_ips = vec!["geoip:ru".to_string(), "GeoIP:RU".to_string()];
        let rules = build_routing_rules(&[], &[], "proxy", false, &[], &subs_ips);
        let ips = rules[1]["ip"].as_array().unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], "geoip:ru");
    }
}
