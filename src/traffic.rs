use log::debug;

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

/// Build xray routing rules from corporate-traffic and proxy-traffic domain lists.
pub fn build_routing_rules(
    ctraffic: &[String],
    ptraffic: &[String],
    proxy_tag: &str,
    ru_direct: bool,
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

    if !ctraffic.is_empty() {
        let domains: Vec<serde_json::Value> = ctraffic
            .iter()
            .map(|e| serde_json::Value::String(normalize_entry(e)))
            .collect();
        rules.push(serde_json::json!({
            "outboundTag": "direct",
            "domain": domains,
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
        let rules = build_routing_rules(&ct, &[], "proxy", false);
        assert_eq!(rules.len(), 2);
        assert_loopback_rule_first(&rules);
        assert_eq!(rules[1]["outboundTag"], "direct");
        assert_eq!(rules[1]["domain"][0], "domain:corp.example.com");
    }

    #[test]
    fn test_build_routing_rules_ptraffic_only() {
        let pt = vec!["external.com".to_string()];
        let rules = build_routing_rules(&[], &pt, "proxy-out", false);
        assert_eq!(rules.len(), 2);
        assert_loopback_rule_first(&rules);
        assert_eq!(rules[1]["outboundTag"], "proxy-out");
        assert_eq!(rules[1]["domain"][0], "domain:external.com");
    }

    #[test]
    fn test_build_routing_rules_both() {
        let ct = vec!["corp.com".to_string()];
        let pt = vec!["ext.com".to_string()];
        let rules = build_routing_rules(&ct, &pt, "proxy", false);
        assert_eq!(rules.len(), 3);
        assert_loopback_rule_first(&rules);
        assert_eq!(rules[1]["outboundTag"], "direct");
        assert_eq!(rules[2]["outboundTag"], "proxy");
    }

    #[test]
    fn test_build_routing_rules_with_ru_flag() {
        let rules = build_routing_rules(&[], &[], "proxy", true);
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
        let rules = build_routing_rules(&ct, &pt, "proxy", true);
        assert_eq!(rules.len(), 4);
        assert_loopback_rule_first(&rules);
        assert_eq!(rules[1]["outboundTag"], "direct");
        assert_eq!(rules[2]["outboundTag"], "proxy");
        assert_eq!(rules[3]["ruleTag"], "ru-tld-direct");
    }

    #[test]
    fn test_build_routing_rules_always_emits_loopback_rule_first() {
        let rules = build_routing_rules(&[], &[], "proxy", false);
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
        let rules = build_routing_rules(&[], &[], "proxy", false);
        assert!(rules[0].get("domain").is_none());
        assert!(rules[0]["ip"].is_array());
    }
}
