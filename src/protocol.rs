use anyhow::{bail, Context, Result};
use base64::Engine;
use std::path::Path;

/// Parsed proxy URI parameters, supporting VLESS, VMess, Trojan, and Shadowsocks.
#[derive(Debug, Clone)]
pub struct ProxyParams {
    /// Protocol: "vless", "vmess", "trojan", "shadowsocks"
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub name: String,

    // Auth (protocol-specific, use whichever applies)
    pub uuid: String,
    pub encryption: String,
    pub flow: String,
    pub alter_id: u32,
    pub vmess_security: String,
    pub password: String,
    pub method: String,

    // Transport
    pub network: String,
    pub security: String,
    pub sni: String,
    pub fingerprint: String,
    pub alpn: Vec<String>,

    // Network-specific transport
    pub path: String,
    pub host_header: String,
    pub service_name: String,
    pub mode: String,
    pub header_type: String,
}

/// URI scheme prefixes for all supported protocols.
/// Schemes that xray's `parse_uri` can handle (used by subscription filter + health checks).
/// `vpn://` is handled separately via the AWG engine path.
pub const SUPPORTED_SCHEMES: &[&str] = &["vless://", "vmess://", "trojan://", "ss://"];

/// Parse a proxy URI (VLESS, VMess, Trojan, or Shadowsocks).
pub fn parse_uri(uri: &str) -> Result<ProxyParams> {
    if uri.starts_with("vless://") {
        parse_vless_uri(uri)
    } else if uri.starts_with("vmess://") {
        parse_vmess_uri(uri)
    } else if uri.starts_with("trojan://") {
        parse_trojan_uri(uri)
    } else if uri.starts_with("ss://") {
        parse_ss_uri(uri)
    } else {
        bail!("unsupported URI scheme, expected vless://, vmess://, trojan://, or ss://")
    }
}

fn default_params() -> ProxyParams {
    ProxyParams {
        protocol: String::new(),
        host: String::new(),
        port: 0,
        name: String::new(),
        uuid: String::new(),
        encryption: "none".to_string(),
        flow: String::new(),
        alter_id: 0,
        vmess_security: "auto".to_string(),
        password: String::new(),
        method: String::new(),
        network: "tcp".to_string(),
        security: String::new(),
        sni: String::new(),
        fingerprint: String::new(),
        alpn: vec![],
        path: String::new(),
        host_header: String::new(),
        service_name: String::new(),
        mode: String::new(),
        header_type: String::new(),
    }
}

/// Parse common query parameters shared by VLESS and Trojan URI formats.
fn parse_common_query(parsed: &url::Url, params: &mut ProxyParams) {
    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "type" => params.network = value.to_string(),
            "security" => params.security = value.to_string(),
            "sni" => params.sni = value.to_string(),
            "fp" => params.fingerprint = value.to_string(),
            "alpn" => params.alpn = value.split(',').map(|s| s.to_string()).collect(),
            "path" => params.path = value.to_string(),
            "host" => params.host_header = value.to_string(),
            "serviceName" => params.service_name = value.to_string(),
            "mode" => params.mode = value.to_string(),
            "headerType" => params.header_type = value.to_string(),
            "encryption" => params.encryption = value.to_string(),
            "flow" => params.flow = value.to_string(),
            _ => {}
        }
    }
}

fn parse_fragment(parsed: &url::Url) -> String {
    parsed
        .fragment()
        .map(|f| {
            urlencoding::decode(f)
                .unwrap_or_else(|_| f.into())
                .to_string()
        })
        .unwrap_or_default()
}

/// Decode base64 that may be standard or URL-safe, with or without padding.
pub(crate) fn decode_base64(input: &str) -> Result<Vec<u8>> {
    // Normalize URL-safe chars to standard base64
    let normalized: String = input
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            _ => c,
        })
        .collect();
    // Add padding if needed
    let padded = match normalized.len() % 4 {
        2 => format!("{normalized}=="),
        3 => format!("{normalized}="),
        _ => normalized,
    };
    base64::engine::general_purpose::STANDARD
        .decode(&padded)
        .context("failed to decode base64")
}

// --- VLESS ---

fn parse_vless_uri(uri: &str) -> Result<ProxyParams> {
    let parsed = url::Url::parse(uri).context("failed to parse VLESS URI")?;
    let mut params = default_params();
    params.protocol = "vless".to_string();

    params.uuid = parsed.username().to_string();
    if params.uuid.is_empty() {
        bail!("UUID is missing from VLESS URI");
    }

    params.host = parsed
        .host_str()
        .context("host missing from VLESS URI")?
        .to_string();
    params.port = parsed.port().context("port missing from VLESS URI")?;
    params.name = parse_fragment(&parsed);
    parse_common_query(&parsed, &mut params);

    Ok(params)
}

// --- VMess ---

fn parse_vmess_uri(uri: &str) -> Result<ProxyParams> {
    let encoded = uri.strip_prefix("vmess://").context("not a vmess:// URI")?;
    let decoded = decode_base64(encoded.trim())?;
    let json_str = String::from_utf8(decoded).context("VMess data is not valid UTF-8")?;
    let v: serde_json::Value =
        serde_json::from_str(&json_str).context("failed to parse VMess JSON")?;

    let mut params = default_params();
    params.protocol = "vmess".to_string();

    params.host = v["add"]
        .as_str()
        .context("VMess missing 'add' field")?
        .to_string();
    params.port = match &v["port"] {
        serde_json::Value::Number(n) => {
            let p = n.as_u64().context("invalid port")?;
            u16::try_from(p).context("port out of range (must be 0-65535)")?
        }
        serde_json::Value::String(s) => s.parse().context("invalid port string")?,
        _ => bail!("VMess missing 'port' field"),
    };
    params.uuid = v["id"]
        .as_str()
        .context("VMess missing 'id' field")?
        .to_string();
    params.name = v["ps"].as_str().unwrap_or("").to_string();
    params.alter_id = match &v["aid"] {
        serde_json::Value::Number(n) => n.as_u64().unwrap_or(0) as u32,
        serde_json::Value::String(s) => s.parse().unwrap_or(0),
        _ => 0,
    };
    params.vmess_security = v["scy"].as_str().unwrap_or("auto").to_string();
    params.network = v["net"].as_str().unwrap_or("tcp").to_string();
    params.header_type = v["type"].as_str().unwrap_or("none").to_string();
    params.host_header = v["host"].as_str().unwrap_or("").to_string();
    params.path = v["path"].as_str().unwrap_or("").to_string();
    params.security = v["tls"].as_str().unwrap_or("").to_string();
    params.sni = v["sni"].as_str().unwrap_or("").to_string();
    params.fingerprint = v["fp"].as_str().unwrap_or("").to_string();
    if let Some(alpn_str) = v["alpn"].as_str() {
        if !alpn_str.is_empty() {
            params.alpn = alpn_str.split(',').map(|s| s.to_string()).collect();
        }
    }

    Ok(params)
}

// --- Trojan ---

fn parse_trojan_uri(uri: &str) -> Result<ProxyParams> {
    let parsed = url::Url::parse(uri).context("failed to parse Trojan URI")?;
    let mut params = default_params();
    params.protocol = "trojan".to_string();

    let raw_password = parsed.username().to_string();
    if raw_password.is_empty() {
        bail!("password is missing from Trojan URI");
    }
    params.password = urlencoding::decode(&raw_password)
        .unwrap_or_else(|_| raw_password.clone().into())
        .to_string();

    params.host = parsed
        .host_str()
        .context("host missing from Trojan URI")?
        .to_string();
    params.port = parsed.port().context("port missing from Trojan URI")?;
    params.name = parse_fragment(&parsed);

    // Trojan defaults to TLS
    params.security = "tls".to_string();
    parse_common_query(&parsed, &mut params);

    Ok(params)
}

// --- Shadowsocks ---

fn parse_ss_uri(uri: &str) -> Result<ProxyParams> {
    let rest = uri.strip_prefix("ss://").context("not an ss:// URI")?;
    let mut params = default_params();
    params.protocol = "shadowsocks".to_string();

    // Split fragment (name)
    let (main, fragment) = match rest.rfind('#') {
        Some(pos) => (&rest[..pos], Some(&rest[pos + 1..])),
        None => (rest, None),
    };
    if let Some(frag) = fragment {
        params.name = urlencoding::decode(frag)
            .unwrap_or_else(|_| frag.into())
            .to_string();
    }

    // SIP002 format: base64(method:password)@host:port
    if let Some(at_pos) = main.rfind('@') {
        let userinfo = &main[..at_pos];
        let hostport = &main[at_pos + 1..];

        // Strip query string
        let hostport = hostport.split('?').next().unwrap_or(hostport);

        let decoded = decode_base64(userinfo.trim())?;
        let userinfo_str = String::from_utf8(decoded).context("SS userinfo is not valid UTF-8")?;

        let (method, password) = userinfo_str
            .split_once(':')
            .context("SS userinfo missing method:password")?;
        params.method = method.to_string();
        params.password = password.to_string();

        // Parse host:port (handle IPv6 [host]:port)
        if hostport.starts_with('[') {
            let bracket_end = hostport.find(']').context("malformed IPv6 in SS URI")?;
            params.host = hostport[1..bracket_end].to_string();
            let port_str = hostport[bracket_end + 1..]
                .strip_prefix(':')
                .context("port missing after IPv6 address")?;
            params.port = port_str.parse().context("invalid port in SS URI")?;
        } else {
            let (host, port_str) = hostport
                .rsplit_once(':')
                .context("host:port missing from SS URI")?;
            params.host = host.to_string();
            params.port = port_str.parse().context("invalid port in SS URI")?;
        }
    } else {
        // Legacy format: base64(method:password@host:port)
        let decoded = decode_base64(main.trim())?;
        let decoded_str = String::from_utf8(decoded).context("SS data is not valid UTF-8")?;

        let (method_pass, hostport) = decoded_str
            .split_once('@')
            .context("SS legacy format missing @")?;
        let (method, password) = method_pass
            .split_once(':')
            .context("SS legacy format missing method:password")?;
        params.method = method.to_string();
        params.password = password.to_string();

        let (host, port_str) = hostport
            .rsplit_once(':')
            .context("host:port missing from SS URI")?;
        params.host = host.to_string();
        params.port = port_str.parse().context("invalid port in SS URI")?;
    }

    Ok(params)
}

// --- Config builders ---

/// Build xray streamSettings JSON from params.
pub fn build_stream_settings(params: &ProxyParams) -> serde_json::Value {
    let mut stream = serde_json::json!({
        "network": params.network,
        "security": params.security,
    });

    // TLS settings
    if !params.sni.is_empty() || !params.fingerprint.is_empty() || !params.alpn.is_empty() {
        let mut tls = serde_json::Map::new();
        if !params.sni.is_empty() {
            tls.insert("serverName".into(), serde_json::json!(params.sni));
        }
        if !params.fingerprint.is_empty() {
            tls.insert("fingerprint".into(), serde_json::json!(params.fingerprint));
        }
        if !params.alpn.is_empty() {
            tls.insert("alpn".into(), serde_json::json!(params.alpn));
        }
        stream["tlsSettings"] = serde_json::Value::Object(tls);
    }

    // Network-specific settings
    match params.network.as_str() {
        "grpc" => {
            let mut grpc = serde_json::Map::new();
            if !params.service_name.is_empty() {
                grpc.insert("serviceName".into(), serde_json::json!(params.service_name));
            }
            if !params.mode.is_empty() {
                grpc.insert(
                    "multiMode".into(),
                    serde_json::json!(params.mode == "multi"),
                );
            }
            if !grpc.is_empty() {
                stream["grpcSettings"] = serde_json::Value::Object(grpc);
            }
        }
        "ws" => {
            let mut ws = serde_json::Map::new();
            if !params.path.is_empty() {
                ws.insert("path".into(), serde_json::json!(params.path));
            }
            if !params.host_header.is_empty() {
                ws.insert(
                    "headers".into(),
                    serde_json::json!({"Host": params.host_header}),
                );
            }
            if !ws.is_empty() {
                stream["wsSettings"] = serde_json::Value::Object(ws);
            }
        }
        "h2" => {
            let mut h2 = serde_json::Map::new();
            if !params.path.is_empty() {
                h2.insert("path".into(), serde_json::json!(params.path));
            }
            if !params.host_header.is_empty() {
                h2.insert("host".into(), serde_json::json!([params.host_header]));
            }
            if !h2.is_empty() {
                stream["httpSettings"] = serde_json::Value::Object(h2);
            }
        }
        "tcp" if params.header_type == "http" => {
            let path = if params.path.is_empty() {
                "/"
            } else {
                &params.path
            };
            let host = if params.host_header.is_empty() {
                &params.host
            } else {
                &params.host_header
            };
            stream["tcpSettings"] = serde_json::json!({
                "header": {
                    "type": "http",
                    "request": {
                        "path": [path],
                        "headers": { "Host": [host] }
                    }
                }
            });
        }
        _ => {}
    }

    stream
}

/// Build protocol-specific outbound settings JSON.
pub fn build_outbound_settings(params: &ProxyParams) -> serde_json::Value {
    match params.protocol.as_str() {
        "vless" => {
            let mut user = serde_json::json!({
                "id": params.uuid,
                "encryption": params.encryption,
            });
            if !params.flow.is_empty() {
                user["flow"] = serde_json::json!(params.flow);
            }
            serde_json::json!({
                "vnext": [{
                    "address": params.host,
                    "port": params.port,
                    "users": [user],
                }]
            })
        }
        "vmess" => serde_json::json!({
            "vnext": [{
                "address": params.host,
                "port": params.port,
                "users": [{
                    "id": params.uuid,
                    "alterId": params.alter_id,
                    "security": params.vmess_security,
                }],
            }]
        }),
        "trojan" => serde_json::json!({
            "servers": [{
                "address": params.host,
                "port": params.port,
                "password": params.password,
            }]
        }),
        "shadowsocks" => serde_json::json!({
            "servers": [{
                "address": params.host,
                "port": params.port,
                "method": params.method,
                "password": params.password,
            }]
        }),
        _ => serde_json::json!({}),
    }
}

/// Xray log configuration for create_config.
pub struct XrayLogConfig {
    pub loglevel: String,
    pub access: String,
    pub error: String,
}

impl Default for XrayLogConfig {
    fn default() -> Self {
        #[cfg(unix)]
        let (access, error) = (
            "/var/log/xray/access.log".to_string(),
            "/var/log/xray/error.log".to_string(),
        );
        #[cfg(windows)]
        let (access, error) = {
            let state = std::env::var("LOCALAPPDATA")
                .unwrap_or_else(|_| r"C:\Users\Public\AppData\Local".to_string());
            let base = std::path::PathBuf::from(state).join("xray");
            (
                base.join("access.log").to_string_lossy().to_string(),
                base.join("error.log").to_string_lossy().to_string(),
            )
        };

        Self {
            loglevel: "warning".to_string(),
            access,
            error,
        }
    }
}

/// Create a complete xray config from proxy parameters.
pub fn create_config(
    params: &ProxyParams,
    port: u16,
    routing_rules: &[serde_json::Value],
    log_config: &XrayLogConfig,
) -> serde_json::Value {
    let stream_settings = build_stream_settings(params);
    let outbound_settings = build_outbound_settings(params);

    let tag = if params.name.is_empty() {
        "proxy"
    } else {
        &params.name
    };

    let rules: Vec<serde_json::Value> = routing_rules.to_vec();

    serde_json::json!({
        "log": {
            "loglevel": log_config.loglevel,
            "access": log_config.access,
            "error": log_config.error,
        },
        "dns": {
            "servers": ["8.8.8.8"],
            "tag": "dns_out",
        },
        "inbounds": [{
            "listen": "127.0.0.1",
            "tag": "socks",
            "port": port,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": true,
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": true,
            },
        }],
        "outbounds": [
            {
                "protocol": params.protocol,
                "tag": tag,
                "settings": outbound_settings,
                "streamSettings": stream_settings,
            },
            {
                "protocol": "freedom",
                "tag": "direct",
            },
            {
                "protocol": "blackhole",
                "tag": "block",
            },
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": rules,
        },
    })
}

/// Create xray config for AWG mode — proxy outbound uses `freedom` protocol.
/// Traffic routed to "proxy" tag exits through the OS network stack,
/// where AWG's routing table sends it through the tunnel.
pub fn create_config_awg_mode(
    port: u16,
    routing_rules: &[serde_json::Value],
    log_config: &XrayLogConfig,
) -> serde_json::Value {
    let rules: Vec<serde_json::Value> = routing_rules.to_vec();

    serde_json::json!({
        "log": {
            "loglevel": log_config.loglevel,
            "access": log_config.access,
            "error": log_config.error,
        },
        "dns": {
            "servers": ["8.8.8.8"],
            "tag": "dns_out",
        },
        "inbounds": [{
            "listen": "127.0.0.1",
            "tag": "socks",
            "port": port,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": true,
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": true,
            },
        }],
        "outbounds": [
            {
                "protocol": "freedom",
                "tag": "proxy",
                "settings": {},
            },
            {
                "protocol": "freedom",
                "tag": "direct",
            },
            {
                "protocol": "blackhole",
                "tag": "block",
            },
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": rules,
        },
    })
}

/// Apply proxy parameters to an existing xray config file.
/// Replaces the first matching (or first proxy) outbound entirely.
/// Also updates the log section from the provided log config.
pub fn apply_to_config(
    params: &ProxyParams,
    config_path: &Path,
    log_config: &XrayLogConfig,
) -> Result<()> {
    let content =
        std::fs::read_to_string(config_path).context("failed to read xray config file")?;
    let mut config: serde_json::Value =
        serde_json::from_str(&content).context("failed to parse xray config JSON")?;

    let outbounds = config
        .get_mut("outbounds")
        .and_then(|v| v.as_array_mut())
        .context("config missing 'outbounds' array")?;

    // Find first outbound matching protocol, or first proxy outbound
    let idx = outbounds
        .iter()
        .position(|o| o.get("protocol").and_then(|p| p.as_str()) == Some(&params.protocol))
        .or_else(|| {
            outbounds.iter().position(|o| {
                let proto = o.get("protocol").and_then(|p| p.as_str()).unwrap_or("");
                proto != "freedom" && proto != "blackhole" && proto != "dns"
            })
        })
        .context("no proxy outbound found in config")?;

    // Preserve existing tag if new params have no name
    let tag = if params.name.is_empty() {
        outbounds[idx]
            .get("tag")
            .and_then(|t| t.as_str())
            .unwrap_or("proxy")
            .to_string()
    } else {
        params.name.clone()
    };

    let stream_settings = build_stream_settings(params);
    let outbound_settings = build_outbound_settings(params);

    outbounds[idx] = serde_json::json!({
        "protocol": params.protocol,
        "tag": tag,
        "settings": outbound_settings,
        "streamSettings": stream_settings,
    });

    // Update log section
    if config.get("log").is_none() {
        config["log"] = serde_json::json!({});
    }
    config["log"]["loglevel"] = serde_json::json!(log_config.loglevel);
    config["log"]["access"] = serde_json::json!(log_config.access);
    config["log"]["error"] = serde_json::json!(log_config.error);

    let pretty = serde_json::to_string_pretty(&config).context("failed to serialize config")?;
    crate::config::write_restricted(config_path, &pretty)?;

    Ok(())
}

// --- URL decoding helper ---

mod urlencoding {
    use std::borrow::Cow;

    pub fn decode(input: &str) -> Result<Cow<'_, str>, std::string::FromUtf8Error> {
        let bytes = input.as_bytes();
        if !bytes.contains(&b'%') {
            return Ok(Cow::Borrowed(input));
        }

        let mut decoded = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    decoded.push(hi << 4 | lo);
                    i += 3;
                    continue;
                }
            }
            decoded.push(bytes[i]);
            i += 1;
        }
        String::from_utf8(decoded).map(Cow::Owned)
    }

    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // --- VLESS parsing ---

    #[test]
    fn parse_vless_full() {
        let uri = "vless://550e8400-e29b-41d4-a716-446655440000@example.com:443?encryption=none&type=grpc&mode=multi&security=tls&fp=chrome&sni=example.com&alpn=h2,http/1.1#MyServer";
        let p = parse_uri(uri).unwrap();

        assert_eq!(p.protocol, "vless");
        assert_eq!(p.uuid, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, 443);
        assert_eq!(p.name, "MyServer");
        assert_eq!(p.encryption, "none");
        assert_eq!(p.network, "grpc");
        assert_eq!(p.mode, "multi");
        assert_eq!(p.security, "tls");
        assert_eq!(p.fingerprint, "chrome");
        assert_eq!(p.sni, "example.com");
        assert_eq!(p.alpn, vec!["h2", "http/1.1"]);
    }

    #[test]
    fn parse_vless_minimal() {
        let uri = "vless://some-uuid@host.net:8443#basic";
        let p = parse_uri(uri).unwrap();

        assert_eq!(p.protocol, "vless");
        assert_eq!(p.uuid, "some-uuid");
        assert_eq!(p.host, "host.net");
        assert_eq!(p.port, 8443);
        assert_eq!(p.name, "basic");
        assert_eq!(p.encryption, "none");
        assert_eq!(p.network, "tcp");
        assert!(p.alpn.is_empty());
    }

    #[test]
    fn parse_vless_encoded_fragment() {
        let uri = "vless://uuid@host.net:443#My%20Server%20Name";
        let p = parse_uri(uri).unwrap();
        assert_eq!(p.name, "My Server Name");
    }

    #[test]
    fn parse_vless_with_flow() {
        let uri = "vless://uuid@host.net:443?type=tcp&security=tls&flow=xtls-rprx-vision#FlowTest";
        let p = parse_uri(uri).unwrap();
        assert_eq!(p.flow, "xtls-rprx-vision");
    }

    // --- VMess parsing ---

    #[test]
    fn parse_vmess_full() {
        let json = serde_json::json!({
            "v": "2",
            "ps": "VMess Server",
            "add": "vmess.example.com",
            "port": 443,
            "id": "abcd-1234",
            "aid": 0,
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": "ws.example.com",
            "path": "/websocket",
            "tls": "tls",
            "sni": "vmess.example.com",
            "fp": "chrome",
            "alpn": "h2,http/1.1"
        });
        let encoded = base64::engine::general_purpose::STANDARD.encode(json.to_string());
        let uri = format!("vmess://{encoded}");

        let p = parse_uri(&uri).unwrap();
        assert_eq!(p.protocol, "vmess");
        assert_eq!(p.host, "vmess.example.com");
        assert_eq!(p.port, 443);
        assert_eq!(p.uuid, "abcd-1234");
        assert_eq!(p.name, "VMess Server");
        assert_eq!(p.alter_id, 0);
        assert_eq!(p.vmess_security, "auto");
        assert_eq!(p.network, "ws");
        assert_eq!(p.host_header, "ws.example.com");
        assert_eq!(p.path, "/websocket");
        assert_eq!(p.security, "tls");
        assert_eq!(p.sni, "vmess.example.com");
        assert_eq!(p.fingerprint, "chrome");
        assert_eq!(p.alpn, vec!["h2", "http/1.1"]);
    }

    #[test]
    fn parse_vmess_port_as_string() {
        let json = serde_json::json!({
            "v": "2", "ps": "", "add": "host.com", "port": "8443",
            "id": "uuid", "aid": "64", "scy": "chacha20-poly1305", "net": "tcp",
        });
        let encoded = base64::engine::general_purpose::STANDARD.encode(json.to_string());
        let uri = format!("vmess://{encoded}");

        let p = parse_uri(&uri).unwrap();
        assert_eq!(p.port, 8443);
        assert_eq!(p.alter_id, 64);
        assert_eq!(p.vmess_security, "chacha20-poly1305");
    }

    // --- Trojan parsing ---

    #[test]
    fn parse_trojan_full() {
        let uri = "trojan://myP%40ssword@trojan.example.com:443?security=tls&type=grpc&sni=trojan.example.com&serviceName=grpc-service&mode=gun&fp=firefox#TrojanServer";
        let p = parse_uri(uri).unwrap();

        assert_eq!(p.protocol, "trojan");
        assert_eq!(p.password, "myP@ssword");
        assert_eq!(p.host, "trojan.example.com");
        assert_eq!(p.port, 443);
        assert_eq!(p.name, "TrojanServer");
        assert_eq!(p.security, "tls");
        assert_eq!(p.network, "grpc");
        assert_eq!(p.sni, "trojan.example.com");
        assert_eq!(p.service_name, "grpc-service");
        assert_eq!(p.mode, "gun");
        assert_eq!(p.fingerprint, "firefox");
    }

    #[test]
    fn parse_trojan_minimal() {
        let uri = "trojan://password123@host.net:443#basic";
        let p = parse_uri(uri).unwrap();

        assert_eq!(p.protocol, "trojan");
        assert_eq!(p.password, "password123");
        assert_eq!(p.host, "host.net");
        assert_eq!(p.port, 443);
        assert_eq!(p.security, "tls"); // Trojan defaults to TLS
    }

    #[test]
    fn parse_trojan_ws() {
        let uri =
            "trojan://pass@host.com:443?type=ws&path=%2Fws&host=cdn.example.com&security=tls#ws";
        let p = parse_uri(uri).unwrap();

        assert_eq!(p.network, "ws");
        assert_eq!(p.path, "/ws");
        assert_eq!(p.host_header, "cdn.example.com");
    }

    // --- Shadowsocks parsing ---

    #[test]
    fn parse_ss_sip002() {
        let userinfo =
            base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:mypassword123");
        let uri = format!("ss://{userinfo}@ss.example.com:8388#SS%20Server");

        let p = parse_uri(&uri).unwrap();
        assert_eq!(p.protocol, "shadowsocks");
        assert_eq!(p.method, "aes-256-gcm");
        assert_eq!(p.password, "mypassword123");
        assert_eq!(p.host, "ss.example.com");
        assert_eq!(p.port, 8388);
        assert_eq!(p.name, "SS Server");
    }

    #[test]
    fn parse_ss_legacy() {
        let payload = base64::engine::general_purpose::STANDARD
            .encode("chacha20-ietf-poly1305:secret@legacy.example.com:9090");
        let uri = format!("ss://{payload}#LegacySS");

        let p = parse_uri(&uri).unwrap();
        assert_eq!(p.protocol, "shadowsocks");
        assert_eq!(p.method, "chacha20-ietf-poly1305");
        assert_eq!(p.password, "secret");
        assert_eq!(p.host, "legacy.example.com");
        assert_eq!(p.port, 9090);
        assert_eq!(p.name, "LegacySS");
    }

    #[test]
    fn parse_ss_sip002_ipv6() {
        let userinfo = base64::engine::general_purpose::STANDARD.encode("aes-128-gcm:pass");
        let uri = format!("ss://{userinfo}@[::1]:8388#IPv6");

        let p = parse_uri(&uri).unwrap();
        assert_eq!(p.host, "::1");
        assert_eq!(p.port, 8388);
    }

    // --- Dispatcher ---

    #[test]
    fn parse_uri_unsupported_scheme() {
        let result = parse_uri("http://example.com");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported URI scheme"));
    }

    // --- Config creation ---

    #[test]
    fn create_config_vless() {
        let params = ProxyParams {
            protocol: "vless".to_string(),
            host: "server.example.com".to_string(),
            port: 443,
            name: "MyProxy".to_string(),
            uuid: "test-uuid".to_string(),
            encryption: "none".to_string(),
            flow: String::new(),
            alter_id: 0,
            vmess_security: "auto".to_string(),
            password: String::new(),
            method: String::new(),
            network: "grpc".to_string(),
            security: "tls".to_string(),
            sni: "server.example.com".to_string(),
            fingerprint: "chrome".to_string(),
            alpn: vec!["h2".to_string()],
            path: String::new(),
            host_header: String::new(),
            service_name: String::new(),
            mode: "multi".to_string(),
            header_type: String::new(),
        };

        let config = create_config(&params, 1080, &[], &XrayLogConfig::default());
        let ob = &config["outbounds"][0];
        assert_eq!(ob["protocol"], "vless");
        assert_eq!(ob["tag"], "MyProxy");
        assert_eq!(ob["settings"]["vnext"][0]["address"], "server.example.com");
        assert_eq!(ob["settings"]["vnext"][0]["users"][0]["id"], "test-uuid");
        assert_eq!(ob["settings"]["vnext"][0]["users"][0]["encryption"], "none");
        assert_eq!(ob["streamSettings"]["network"], "grpc");
        assert_eq!(ob["streamSettings"]["security"], "tls");
        assert_eq!(
            ob["streamSettings"]["tlsSettings"]["serverName"],
            "server.example.com"
        );
        assert_eq!(ob["streamSettings"]["grpcSettings"]["multiMode"], true);

        // freedom + blackhole outbounds
        assert_eq!(config["outbounds"][1]["protocol"], "freedom");
        assert_eq!(config["outbounds"][2]["protocol"], "blackhole");
    }

    #[test]
    fn create_config_vmess() {
        let mut params = default_params();
        params.protocol = "vmess".to_string();
        params.host = "vmess.host.com".to_string();
        params.port = 443;
        params.uuid = "vm-uuid".to_string();
        params.alter_id = 64;
        params.vmess_security = "aes-128-gcm".to_string();
        params.network = "ws".to_string();
        params.security = "tls".to_string();
        params.path = "/ws".to_string();
        params.host_header = "cdn.example.com".to_string();

        let config = create_config(&params, 1080, &[], &XrayLogConfig::default());
        let ob = &config["outbounds"][0];
        assert_eq!(ob["protocol"], "vmess");
        assert_eq!(ob["settings"]["vnext"][0]["users"][0]["id"], "vm-uuid");
        assert_eq!(ob["settings"]["vnext"][0]["users"][0]["alterId"], 64);
        assert_eq!(
            ob["settings"]["vnext"][0]["users"][0]["security"],
            "aes-128-gcm"
        );
        assert_eq!(ob["streamSettings"]["wsSettings"]["path"], "/ws");
        assert_eq!(
            ob["streamSettings"]["wsSettings"]["headers"]["Host"],
            "cdn.example.com"
        );
    }

    #[test]
    fn create_config_trojan() {
        let mut params = default_params();
        params.protocol = "trojan".to_string();
        params.host = "trojan.host.com".to_string();
        params.port = 443;
        params.password = "trojan-pass".to_string();
        params.security = "tls".to_string();
        params.sni = "trojan.host.com".to_string();

        let config = create_config(&params, 1080, &[], &XrayLogConfig::default());
        let ob = &config["outbounds"][0];
        assert_eq!(ob["protocol"], "trojan");
        assert_eq!(ob["settings"]["servers"][0]["address"], "trojan.host.com");
        assert_eq!(ob["settings"]["servers"][0]["password"], "trojan-pass");
        assert_eq!(ob["settings"]["servers"][0]["port"], 443);
        assert_eq!(
            ob["streamSettings"]["tlsSettings"]["serverName"],
            "trojan.host.com"
        );
    }

    #[test]
    fn create_config_shadowsocks() {
        let mut params = default_params();
        params.protocol = "shadowsocks".to_string();
        params.host = "ss.host.com".to_string();
        params.port = 8388;
        params.method = "aes-256-gcm".to_string();
        params.password = "ss-pass".to_string();

        let config = create_config(&params, 1080, &[], &XrayLogConfig::default());
        let ob = &config["outbounds"][0];
        assert_eq!(ob["protocol"], "shadowsocks");
        assert_eq!(ob["settings"]["servers"][0]["address"], "ss.host.com");
        assert_eq!(ob["settings"]["servers"][0]["method"], "aes-256-gcm");
        assert_eq!(ob["settings"]["servers"][0]["password"], "ss-pass");
        assert_eq!(ob["settings"]["servers"][0]["port"], 8388);
    }

    #[test]
    fn create_config_minimal_vless() {
        let mut params = default_params();
        params.protocol = "vless".to_string();
        params.host = "host.net".to_string();
        params.port = 8443;
        params.uuid = "uuid".to_string();

        let config = create_config(&params, 1080, &[], &XrayLogConfig::default());
        // Tag falls back to "proxy" when name is empty
        assert_eq!(config["outbounds"][0]["tag"], "proxy");
        // No tlsSettings when sni/fp/alpn are all empty
        assert!(config["outbounds"][0]["streamSettings"]["tlsSettings"].is_null());
        // No grpcSettings when network is tcp
        assert!(config["outbounds"][0]["streamSettings"]["grpcSettings"].is_null());
    }

    #[test]
    fn create_config_writes_valid_json() {
        let mut params = default_params();
        params.protocol = "vless".to_string();
        params.host = "example.com".to_string();
        params.port = 443;
        params.uuid = "test-uuid".to_string();

        let config = create_config(&params, 1080, &[], &XrayLogConfig::default());
        let json_str = serde_json::to_string_pretty(&config).unwrap();
        let reparsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(config, reparsed);
    }

    // --- Stream settings ---

    #[test]
    fn stream_settings_ws() {
        let mut params = default_params();
        params.network = "ws".to_string();
        params.path = "/ws-path".to_string();
        params.host_header = "ws.example.com".to_string();

        let stream = build_stream_settings(&params);
        assert_eq!(stream["wsSettings"]["path"], "/ws-path");
        assert_eq!(stream["wsSettings"]["headers"]["Host"], "ws.example.com");
    }

    #[test]
    fn stream_settings_h2() {
        let mut params = default_params();
        params.network = "h2".to_string();
        params.path = "/h2-path".to_string();
        params.host_header = "h2.example.com".to_string();

        let stream = build_stream_settings(&params);
        assert_eq!(stream["httpSettings"]["path"], "/h2-path");
        assert_eq!(stream["httpSettings"]["host"][0], "h2.example.com");
    }

    #[test]
    fn stream_settings_tcp_http() {
        let mut params = default_params();
        params.host = "tcp.example.com".to_string();
        params.network = "tcp".to_string();
        params.header_type = "http".to_string();
        params.path = "/index".to_string();
        params.host_header = "cdn.example.com".to_string();

        let stream = build_stream_settings(&params);
        assert_eq!(stream["tcpSettings"]["header"]["type"], "http");
        assert_eq!(
            stream["tcpSettings"]["header"]["request"]["path"][0],
            "/index"
        );
        assert_eq!(
            stream["tcpSettings"]["header"]["request"]["headers"]["Host"][0],
            "cdn.example.com"
        );
    }

    #[test]
    fn stream_settings_grpc_service_name() {
        let mut params = default_params();
        params.network = "grpc".to_string();
        params.service_name = "my-service".to_string();
        params.mode = "gun".to_string();

        let stream = build_stream_settings(&params);
        assert_eq!(stream["grpcSettings"]["serviceName"], "my-service");
        assert_eq!(stream["grpcSettings"]["multiMode"], false);
    }

    // --- apply_to_config ---

    #[test]
    fn apply_to_config_replaces_outbound() {
        let config_json = serde_json::json!({
            "inbounds": [{"port": 1080, "protocol": "socks"}],
            "outbounds": [{
                "protocol": "vless",
                "tag": "old-tag",
                "settings": {
                    "vnext": [{"address": "old.host.com", "port": 443, "users": [{"id": "old-uuid"}]}]
                },
                "streamSettings": {"network": "tcp", "security": "tls"}
            }, {
                "protocol": "freedom",
                "tag": "direct"
            }]
        });

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmpfile,
            "{}",
            serde_json::to_string_pretty(&config_json).unwrap()
        )
        .unwrap();

        let mut params = default_params();
        params.protocol = "trojan".to_string();
        params.host = "new.host.com".to_string();
        params.port = 8443;
        params.password = "new-pass".to_string();
        params.name = "NewServer".to_string();
        params.security = "tls".to_string();
        params.sni = "new.host.com".to_string();

        let log_cfg = XrayLogConfig {
            loglevel: "debug".to_string(),
            access: "/tmp/access.log".to_string(),
            error: "/tmp/error.log".to_string(),
        };
        apply_to_config(&params, tmpfile.path(), &log_cfg).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(tmpfile.path()).unwrap()).unwrap();

        // Protocol changed from vless to trojan
        assert_eq!(updated["outbounds"][0]["protocol"], "trojan");
        assert_eq!(updated["outbounds"][0]["tag"], "NewServer");
        assert_eq!(
            updated["outbounds"][0]["settings"]["servers"][0]["address"],
            "new.host.com"
        );
        assert_eq!(
            updated["outbounds"][0]["settings"]["servers"][0]["password"],
            "new-pass"
        );
        // Inbounds untouched
        assert_eq!(updated["inbounds"][0]["port"], 1080);
        // Freedom outbound untouched
        assert_eq!(updated["outbounds"][1]["protocol"], "freedom");
        // Log section updated
        assert_eq!(updated["log"]["loglevel"], "debug");
        assert_eq!(updated["log"]["access"], "/tmp/access.log");
        assert_eq!(updated["log"]["error"], "/tmp/error.log");
    }

    #[test]
    fn apply_to_config_preserves_tag_when_name_empty() {
        let config_json = serde_json::json!({
            "inbounds": [],
            "outbounds": [{
                "protocol": "vless",
                "tag": "keep-this-tag",
                "settings": {"vnext": [{"address": "h", "port": 1, "users": [{"id": "u"}]}]},
                "streamSettings": {"network": "tcp", "security": ""}
            }]
        });

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmpfile,
            "{}",
            serde_json::to_string_pretty(&config_json).unwrap()
        )
        .unwrap();

        let mut params = default_params();
        params.protocol = "vless".to_string();
        params.host = "new.host".to_string();
        params.port = 443;
        params.uuid = "new-uuid".to_string();
        // name is empty — should preserve existing tag

        apply_to_config(&params, tmpfile.path(), &XrayLogConfig::default()).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(tmpfile.path()).unwrap()).unwrap();
        assert_eq!(updated["outbounds"][0]["tag"], "keep-this-tag");
    }

    #[test]
    fn apply_to_config_changes_log_level() {
        let config_json = serde_json::json!({
            "inbounds": [],
            "outbounds": [{
                "protocol": "vless",
                "tag": "proxy",
                "settings": {"vnext": [{"address": "h", "port": 1, "users": [{"id": "u"}]}]},
                "streamSettings": {"network": "tcp", "security": ""}
            }],
            "log": {
                "loglevel": "warning",
                "access": "/old/access.log",
                "error": "/old/error.log",
            }
        });

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmpfile,
            "{}",
            serde_json::to_string_pretty(&config_json).unwrap()
        )
        .unwrap();

        let mut params = default_params();
        params.protocol = "vless".to_string();
        params.host = "host".to_string();
        params.port = 443;
        params.uuid = "uuid".to_string();

        let log_cfg = XrayLogConfig {
            loglevel: "debug".to_string(),
            access: "/new/access.log".to_string(),
            error: "/new/error.log".to_string(),
        };
        apply_to_config(&params, tmpfile.path(), &log_cfg).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(tmpfile.path()).unwrap()).unwrap();
        assert_eq!(updated["log"]["loglevel"], "debug");
        assert_eq!(updated["log"]["access"], "/new/access.log");
        assert_eq!(updated["log"]["error"], "/new/error.log");
    }

    #[test]
    fn apply_to_config_creates_log_section_if_missing() {
        let config_json = serde_json::json!({
            "inbounds": [],
            "outbounds": [{
                "protocol": "vless",
                "tag": "proxy",
                "settings": {"vnext": [{"address": "h", "port": 1, "users": [{"id": "u"}]}]},
                "streamSettings": {"network": "tcp", "security": ""}
            }]
        });

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmpfile,
            "{}",
            serde_json::to_string_pretty(&config_json).unwrap()
        )
        .unwrap();

        let mut params = default_params();
        params.protocol = "vless".to_string();
        params.host = "host".to_string();
        params.port = 443;
        params.uuid = "uuid".to_string();

        let log_cfg = XrayLogConfig {
            loglevel: "info".to_string(),
            access: "/var/log/access.log".to_string(),
            error: "/var/log/error.log".to_string(),
        };
        apply_to_config(&params, tmpfile.path(), &log_cfg).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(tmpfile.path()).unwrap()).unwrap();
        assert_eq!(updated["log"]["loglevel"], "info");
        assert_eq!(updated["log"]["access"], "/var/log/access.log");
        assert_eq!(updated["log"]["error"], "/var/log/error.log");
    }

    // --- Routing rules ---

    #[test]
    fn create_config_with_routing_rules() {
        let mut params = default_params();
        params.protocol = "vless".to_string();
        params.host = "host.com".to_string();
        params.port = 443;
        params.uuid = "uuid".to_string();
        params.name = "proxy".to_string();

        let rules = crate::traffic::build_routing_rules(
            &["corp.com".to_string()],
            &["ext.com".to_string()],
            "proxy",
            true,
        );
        let config = create_config(&params, 30000, &rules, &XrayLogConfig::default());

        let r = config["routing"]["rules"].as_array().unwrap();
        assert_eq!(r.len(), 4);
        assert_eq!(r[0]["ruleTag"], "loopback-and-private-direct");
        assert_eq!(r[1]["outboundTag"], "direct");
        assert_eq!(r[1]["domain"][0], "domain:corp.com");
        assert_eq!(r[2]["outboundTag"], "proxy");
        assert_eq!(r[2]["domain"][0], "domain:ext.com");
        assert_eq!(r[3]["ruleTag"], "ru-tld-direct");
    }

    #[test]
    fn awg_mode_config_has_freedom_outbound() {
        let rules = crate::traffic::build_routing_rules(&[], &[], "proxy", false);
        let config = create_config_awg_mode(21080, &rules, &XrayLogConfig::default());

        // Proxy outbound should be freedom
        assert_eq!(config["outbounds"][0]["protocol"], "freedom");
        assert_eq!(config["outbounds"][0]["tag"], "proxy");
        // Direct and block still present
        assert_eq!(config["outbounds"][1]["protocol"], "freedom");
        assert_eq!(config["outbounds"][1]["tag"], "direct");
        assert_eq!(config["outbounds"][2]["protocol"], "blackhole");
        assert_eq!(config["outbounds"][2]["tag"], "block");
    }

    #[test]
    fn awg_mode_config_has_correct_inbound() {
        let config = create_config_awg_mode(21080, &[], &XrayLogConfig::default());
        assert_eq!(config["inbounds"][0]["protocol"], "socks");
        assert_eq!(config["inbounds"][0]["port"], 21080);
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
    }

    #[test]
    fn awg_mode_config_applies_routing_rules() {
        let rules = crate::traffic::build_routing_rules(
            &["corp.com".to_string()],
            &["ext.com".to_string()],
            "proxy",
            true,
        );
        let config = create_config_awg_mode(21080, &rules, &XrayLogConfig::default());
        let r = config["routing"]["rules"].as_array().unwrap();
        assert_eq!(r.len(), 4);
        assert_eq!(r[0]["ruleTag"], "loopback-and-private-direct");
    }

    #[test]
    fn create_config_default_log_settings() {
        let mut params = default_params();
        params.protocol = "vless".to_string();
        params.host = "host.com".to_string();
        params.port = 443;
        params.uuid = "uuid".to_string();

        let config = create_config(&params, 1080, &[], &XrayLogConfig::default());
        assert_eq!(config["log"]["loglevel"], "warning");
        #[cfg(unix)]
        {
            assert_eq!(config["log"]["access"], "/var/log/xray/access.log");
            assert_eq!(config["log"]["error"], "/var/log/xray/error.log");
        }
        #[cfg(windows)]
        {
            let access = config["log"]["access"].as_str().unwrap();
            let error = config["log"]["error"].as_str().unwrap();
            assert!(access.ends_with("access.log"), "got: {access}");
            assert!(error.ends_with("error.log"), "got: {error}");
        }
    }

    #[test]
    fn create_config_custom_log_settings() {
        let mut params = default_params();
        params.protocol = "vless".to_string();
        params.host = "host.com".to_string();
        params.port = 443;
        params.uuid = "uuid".to_string();

        let log_config = XrayLogConfig {
            loglevel: "debug".to_string(),
            access: "/tmp/access.log".to_string(),
            error: "/tmp/error.log".to_string(),
        };
        let config = create_config(&params, 1080, &[], &log_config);
        assert_eq!(config["log"]["loglevel"], "debug");
        assert_eq!(config["log"]["access"], "/tmp/access.log");
        assert_eq!(config["log"]["error"], "/tmp/error.log");
    }
}
