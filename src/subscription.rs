use anyhow::{Context, Result};
use log::debug;
use std::collections::BTreeMap;
use std::io::Read;

const MAX_BODY_SIZE: u64 = 5 * 1024 * 1024; // 5 MB

/// Default User-Agent for subscription downloads; v2rayNG-compatible so panels
/// that content-negotiate on UA return plain base64 rather than filtered/broken output.
pub const DEFAULT_SUBS_USER_AGENT: &str = "v2rayNG/1.10.2";

/// Resolve the User-Agent to send: the configured value when present and non-empty,
/// otherwise the default.
pub fn resolve_user_agent(configured: Option<&str>) -> &str {
    match configured {
        Some(ua) if !ua.trim().is_empty() => ua,
        _ => DEFAULT_SUBS_USER_AGENT,
    }
}

/// The value of the `User-Agent` key in extra_headers, if any (case-insensitive).
fn user_agent_override(extra_headers: &BTreeMap<String, String>) -> Option<&str> {
    extra_headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
        .map(|(_, value)| value.as_str())
}

/// The User-Agent that will actually be sent: an extra_headers override wins over
/// the resolved value, so a caller-supplied `User-Agent`/`user-agent` header is
/// never duplicated alongside the resolved one.
pub fn effective_user_agent<'a>(
    resolved: &'a str,
    extra_headers: &'a BTreeMap<String, String>,
) -> &'a str {
    user_agent_override(extra_headers).unwrap_or(resolved)
}

/// Download a subscription from the given URL, returning the raw body.
pub fn download_subscription(
    url: &str,
    user_agent: &str,
    extra_headers: &BTreeMap<String, String>,
) -> Result<String> {
    debug!("downloading subscription from {}", url);
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let ua = effective_user_agent(user_agent, extra_headers);
    let mut request = agent.get(url).header("User-Agent", ua);
    for (name, value) in extra_headers {
        // already set above (either the resolved UA or this override) — skip to avoid a duplicate header
        if name.eq_ignore_ascii_case("user-agent") {
            continue;
        }
        request = request.header(name, value);
    }
    let mut body = String::new();
    request
        .call()
        .with_context(|| format!("failed to fetch {url}"))?
        .body_mut()
        .as_reader()
        .take(MAX_BODY_SIZE)
        .read_to_string(&mut body)
        .with_context(|| format!("failed to read body from {url}"))?;
    debug!("downloaded {} bytes from {}", body.len(), url);
    Ok(body)
}

/// Decode a base64-encoded subscription into a list of URIs.
pub fn decode_subscription(data: &str) -> Result<Vec<String>> {
    let decoded_bytes = crate::protocol::decode_base64(data.trim())
        .context("failed to decode base64 subscription data")?;
    let decoded =
        String::from_utf8(decoded_bytes).context("subscription data is not valid UTF-8")?;
    let uris: Vec<String> = decoded
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    debug!("decoded {} URIs from subscription", uris.len());
    Ok(uris)
}

/// Keep only URIs with supported proxy protocols (VLESS, VMess, Trojan, Shadowsocks).
pub fn filter_supported(uris: &[String]) -> Vec<String> {
    let filtered: Vec<String> = uris
        .iter()
        .filter(|uri| {
            crate::protocol::SUPPORTED_SCHEMES
                .iter()
                .any(|scheme| uri.starts_with(scheme))
        })
        .cloned()
        .collect();
    debug!("filtered {}/{} supported URIs", filtered.len(), uris.len());
    filtered
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    #[test]
    fn test_decode_subscription() {
        let raw = "vless://uuid@host:443?type=grpc\nvmess://data\ntrojan://pass@host:443\n";
        let encoded = STANDARD.encode(raw);
        let result = decode_subscription(&encoded).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], "vless://uuid@host:443?type=grpc");
        assert_eq!(result[1], "vmess://data");
        assert_eq!(result[2], "trojan://pass@host:443");
    }

    #[test]
    fn test_decode_subscription_with_whitespace() {
        let raw = "vless://a\n\nvless://b\n";
        let encoded = format!("  {}  ", STANDARD.encode(raw));
        let result = decode_subscription(&encoded).unwrap();
        assert_eq!(result, vec!["vless://a", "vless://b"]);
    }

    #[test]
    fn test_decode_subscription_invalid_base64() {
        let result = decode_subscription("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_filter_supported_keeps_all_protocols() {
        let uris = vec![
            "vless://uuid@host:443?type=grpc#VLESS".to_string(),
            "vmess://base64data".to_string(),
            "trojan://password@host:443#Trojan".to_string(),
            "ss://base64data@host:8388#SS".to_string(),
            "http://not-a-proxy".to_string(),
        ];
        let filtered = filter_supported(&uris);
        assert_eq!(filtered.len(), 4);
        assert!(filtered[0].starts_with("vless://"));
        assert!(filtered[1].starts_with("vmess://"));
        assert!(filtered[2].starts_with("trojan://"));
        assert!(filtered[3].starts_with("ss://"));
    }

    #[test]
    fn test_filter_supported_none_match() {
        let uris = vec![
            "http://example.com".to_string(),
            "socks5://proxy:1080".to_string(),
        ];
        let filtered = filter_supported(&uris);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_default_subs_user_agent_is_v2rayng_flavored() {
        assert!(DEFAULT_SUBS_USER_AGENT.starts_with("v2rayNG/"));
    }

    #[test]
    fn test_resolve_user_agent_none_returns_default() {
        assert_eq!(resolve_user_agent(None), DEFAULT_SUBS_USER_AGENT);
    }

    #[test]
    fn test_resolve_user_agent_some_returns_configured() {
        assert_eq!(resolve_user_agent(Some("Happ/3.13.0")), "Happ/3.13.0");
    }

    #[test]
    fn test_resolve_user_agent_empty_string_falls_back_to_default() {
        assert_eq!(resolve_user_agent(Some("")), DEFAULT_SUBS_USER_AGENT);
        assert_eq!(resolve_user_agent(Some("   ")), DEFAULT_SUBS_USER_AGENT);
    }

    #[test]
    fn test_effective_user_agent_no_override_uses_resolved() {
        let headers = BTreeMap::new();
        assert_eq!(
            effective_user_agent("v2rayNG/1.10.2", &headers),
            "v2rayNG/1.10.2"
        );
    }

    #[test]
    fn test_effective_user_agent_header_override_wins() {
        let mut headers = BTreeMap::new();
        headers.insert("User-Agent".to_string(), "Happ/3.13.0".to_string());
        assert_eq!(
            effective_user_agent("v2rayNG/1.10.2", &headers),
            "Happ/3.13.0"
        );
    }

    #[test]
    fn test_effective_user_agent_header_override_case_insensitive() {
        let mut headers = BTreeMap::new();
        headers.insert("user-agent".to_string(), "Happ/3.13.0".to_string());
        assert_eq!(
            effective_user_agent("v2rayNG/1.10.2", &headers),
            "Happ/3.13.0"
        );
    }

    #[test]
    fn test_effective_user_agent_unrelated_headers_ignored() {
        let mut headers = BTreeMap::new();
        headers.insert("X-Hwid".to_string(), "abc".to_string());
        assert_eq!(
            effective_user_agent("v2rayNG/1.10.2", &headers),
            "v2rayNG/1.10.2"
        );
    }
}
