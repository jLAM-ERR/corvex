use anyhow::{bail, Context, Result};
use std::path::Path;

/// Parsed VLESS URI parameters.
#[derive(Debug, Clone)]
pub struct VlessParams {
    pub uuid: String,
    pub host: String,
    pub port: u16,
    pub name: String,
    pub encryption: String,
    pub network: String,
    pub security: String,
    pub sni: String,
    pub fingerprint: String,
    pub alpn: Vec<String>,
    pub mode: String,
}

/// Parse a VLESS URI into structured parameters.
pub fn parse_vless_uri(uri: &str) -> Result<VlessParams> {
    if !uri.starts_with("vless://") {
        bail!("URI must start with vless://");
    }

    let parsed = url::Url::parse(uri).context("Failed to parse VLESS URI")?;

    let uuid = parsed.username().to_string();
    if uuid.is_empty() {
        bail!("UUID is missing from URI");
    }

    let host = parsed
        .host_str()
        .context("Host is missing from URI")?
        .to_string();

    let port = parsed.port().context("Port is missing from URI")?;

    let name = parsed
        .fragment()
        .map(|f| {
            urlencoding::decode(f)
                .unwrap_or_else(|_| f.into())
                .to_string()
        })
        .unwrap_or_default();

    let mut encryption = "none".to_string();
    let mut network = "tcp".to_string();
    let mut security = String::new();
    let mut sni = String::new();
    let mut fingerprint = String::new();
    let mut alpn = Vec::new();
    let mut mode = String::new();

    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "encryption" => encryption = value.to_string(),
            "type" => network = value.to_string(),
            "security" => security = value.to_string(),
            "sni" => sni = value.to_string(),
            "fp" => fingerprint = value.to_string(),
            "alpn" => {
                alpn = value.split(',').map(|s| s.to_string()).collect();
            }
            "mode" => mode = value.to_string(),
            _ => {}
        }
    }

    Ok(VlessParams {
        uuid,
        host,
        port,
        name,
        encryption,
        network,
        security,
        sni,
        fingerprint,
        alpn,
        mode,
    })
}

/// Create a complete xray config from VLESS parameters.
/// Used when config.json doesn't exist yet.
pub fn create_config(params: &VlessParams, socks_port: u16, http_port: u16) -> serde_json::Value {
    let mut stream_settings = serde_json::json!({
        "network": params.network,
        "security": params.security,
    });

    if !params.sni.is_empty() || !params.fingerprint.is_empty() || !params.alpn.is_empty() {
        let mut tls = serde_json::Map::new();
        if !params.sni.is_empty() {
            tls.insert("serverName".to_string(), serde_json::json!(params.sni));
        }
        if !params.fingerprint.is_empty() {
            tls.insert(
                "fingerprint".to_string(),
                serde_json::json!(params.fingerprint),
            );
        }
        if !params.alpn.is_empty() {
            tls.insert("alpn".to_string(), serde_json::json!(params.alpn));
        }
        stream_settings["tlsSettings"] = serde_json::Value::Object(tls);
    }

    if !params.mode.is_empty() && params.network == "grpc" {
        stream_settings["grpcSettings"] = serde_json::json!({
            "multiMode": params.mode == "multi",
        });
    }

    let tag = if params.name.is_empty() {
        "proxy"
    } else {
        &params.name
    };

    let mut inbounds = vec![serde_json::json!({
        "listen": "127.0.0.1",
        "tag": "socks",
        "port": socks_port,
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
    })];

    if http_port != socks_port {
        inbounds.push(serde_json::json!({
            "listen": "127.0.0.1",
            "tag": "http-in",
            "port": http_port,
            "protocol": "http",
            "settings": {},
        }));
    }

    serde_json::json!({
        "log": {
            "loglevel": "warning",
            "access": "/var/log/xray/access.log",
            "error": "/var/log/xray/error.log",
        },
        "dns": {
            "servers": ["8.8.8.8"],
            "tag": "dns_out",
        },
        "inbounds": inbounds,
        "outbounds": [
            {
                "protocol": "vless",
                "tag": tag,
                "settings": {
                    "vnext": [{
                        "address": params.host,
                        "port": params.port,
                        "users": [{
                            "id": params.uuid,
                            "encryption": params.encryption,
                        }],
                    }],
                },
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
            "rules": [
                {
                    "ruleTag": "ru-tld-direct",
                    "domain": ["regexp:\\.ru$"],
                    "outboundTag": "direct",
                },
            ],
        },
    })
}

/// Apply VLESS parameters to an xray config file.
/// Finds the first outbound with protocol "vless" and updates its fields.
pub fn apply_to_config(params: &VlessParams, config_path: &Path) -> Result<()> {
    let content =
        std::fs::read_to_string(config_path).context("Failed to read xray config file")?;

    let mut config: serde_json::Value =
        serde_json::from_str(&content).context("Failed to parse xray config JSON")?;

    let outbounds = config
        .get_mut("outbounds")
        .and_then(|v| v.as_array_mut())
        .context("Config missing 'outbounds' array")?;

    // Find first vless outbound, or fall back to first outbound
    let idx = outbounds
        .iter()
        .position(|o| o.get("protocol").and_then(|p| p.as_str()) == Some("vless"))
        .or(if outbounds.is_empty() { None } else { Some(0) })
        .context("No outbounds found in config")?;
    let outbound = &mut outbounds[idx];

    // Update tag
    if !params.name.is_empty() {
        outbound["tag"] = serde_json::json!(params.name);
    }

    // Update settings.vnext[0]
    let vnext = outbound
        .pointer_mut("/settings/vnext/0")
        .context("Config missing settings.vnext[0]")?;

    vnext["address"] = serde_json::json!(params.host);
    vnext["port"] = serde_json::json!(params.port);

    // Update users[0]
    if let Some(user) = vnext.pointer_mut("/users/0") {
        user["id"] = serde_json::json!(params.uuid);
        user["encryption"] = serde_json::json!(params.encryption);
    }

    // Update streamSettings
    let stream = outbound
        .get_mut("streamSettings")
        .context("Config missing streamSettings")?;

    stream["network"] = serde_json::json!(params.network);
    stream["security"] = serde_json::json!(params.security);

    // Update tlsSettings
    if !params.sni.is_empty() || !params.fingerprint.is_empty() || !params.alpn.is_empty() {
        let tls = stream
            .as_object_mut()
            .unwrap()
            .entry("tlsSettings")
            .or_insert_with(|| serde_json::json!({}));

        if !params.sni.is_empty() {
            tls["serverName"] = serde_json::json!(params.sni);
        }
        if !params.fingerprint.is_empty() {
            tls["fingerprint"] = serde_json::json!(params.fingerprint);
        }
        if !params.alpn.is_empty() {
            tls["alpn"] = serde_json::json!(params.alpn);
        }
    }

    // Update grpcSettings if mode is set
    if !params.mode.is_empty() && params.network == "grpc" {
        let grpc = stream
            .as_object_mut()
            .unwrap()
            .entry("grpcSettings")
            .or_insert_with(|| serde_json::json!({}));

        grpc["multiMode"] = serde_json::json!(params.mode == "multi");
    }

    // Write back
    let pretty = serde_json::to_string_pretty(&config).context("Failed to serialize config")?;
    std::fs::write(config_path, pretty).context("Failed to write config file")?;

    Ok(())
}

// We need urlencoding for fragment decoding; let's use percent_decode from url crate instead.
// Actually url::Url already decodes query params but not fragments. Let's handle it manually.
mod urlencoding {
    use std::borrow::Cow;

    pub fn decode(input: &str) -> Result<Cow<'_, str>, std::string::FromUtf8Error> {
        let bytes = input.as_bytes();
        let mut has_percent = false;
        for &b in bytes {
            if b == b'%' {
                has_percent = true;
                break;
            }
        }
        if !has_percent {
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

    #[test]
    fn parse_valid_vless_uri() {
        let uri = "vless://550e8400-e29b-41d4-a716-446655440000@example.com:443?encryption=none&type=grpc&mode=multi&security=tls&fp=chrome&sni=example.com&alpn=h2,http/1.1#MyServer";
        let params = parse_vless_uri(uri).unwrap();

        assert_eq!(params.uuid, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(params.host, "example.com");
        assert_eq!(params.port, 443);
        assert_eq!(params.name, "MyServer");
        assert_eq!(params.encryption, "none");
        assert_eq!(params.network, "grpc");
        assert_eq!(params.mode, "multi");
        assert_eq!(params.security, "tls");
        assert_eq!(params.fingerprint, "chrome");
        assert_eq!(params.sni, "example.com");
        assert_eq!(params.alpn, vec!["h2", "http/1.1"]);
    }

    #[test]
    fn parse_uri_with_missing_optional_params() {
        let uri = "vless://some-uuid@host.net:8443#basic";
        let params = parse_vless_uri(uri).unwrap();

        assert_eq!(params.uuid, "some-uuid");
        assert_eq!(params.host, "host.net");
        assert_eq!(params.port, 8443);
        assert_eq!(params.name, "basic");
        assert_eq!(params.encryption, "none");
        assert_eq!(params.network, "tcp");
        assert!(params.alpn.is_empty());
    }

    #[test]
    fn parse_uri_with_encoded_fragment() {
        let uri = "vless://uuid@host.net:443#My%20Server%20Name";
        let params = parse_vless_uri(uri).unwrap();
        assert_eq!(params.name, "My Server Name");
    }

    #[test]
    fn apply_to_sample_config() {
        let config_json = serde_json::json!({
            "inbounds": [{"port": 1080, "protocol": "socks"}],
            "outbounds": [{
                "protocol": "vless",
                "tag": "old-tag",
                "settings": {
                    "vnext": [{
                        "address": "old.host.com",
                        "port": 443,
                        "users": [{
                            "id": "old-uuid",
                            "encryption": "none"
                        }]
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "old.host.com"
                    }
                }
            }]
        });

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmpfile,
            "{}",
            serde_json::to_string_pretty(&config_json).unwrap()
        )
        .unwrap();

        let params = VlessParams {
            uuid: "new-uuid".to_string(),
            host: "new.host.com".to_string(),
            port: 8443,
            name: "NewServer".to_string(),
            encryption: "none".to_string(),
            network: "grpc".to_string(),
            security: "tls".to_string(),
            sni: "new.host.com".to_string(),
            fingerprint: "chrome".to_string(),
            alpn: vec!["h2".to_string()],
            mode: "multi".to_string(),
        };

        apply_to_config(&params, tmpfile.path()).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(tmpfile.path()).unwrap()).unwrap();

        // Verify updated fields
        assert_eq!(updated["outbounds"][0]["tag"], "NewServer");
        assert_eq!(
            updated["outbounds"][0]["settings"]["vnext"][0]["address"],
            "new.host.com"
        );
        assert_eq!(
            updated["outbounds"][0]["settings"]["vnext"][0]["port"],
            8443
        );
        assert_eq!(
            updated["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"],
            "new-uuid"
        );
        assert_eq!(updated["outbounds"][0]["streamSettings"]["network"], "grpc");
        assert_eq!(
            updated["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"],
            "new.host.com"
        );
        assert_eq!(
            updated["outbounds"][0]["streamSettings"]["tlsSettings"]["fingerprint"],
            "chrome"
        );
        assert_eq!(
            updated["outbounds"][0]["streamSettings"]["grpcSettings"]["multiMode"],
            true
        );

        // Verify inbounds untouched
        assert_eq!(updated["inbounds"][0]["port"], 1080);
    }

    #[test]
    fn create_config_with_full_params() {
        let params = VlessParams {
            uuid: "test-uuid".to_string(),
            host: "server.example.com".to_string(),
            port: 443,
            name: "MyProxy".to_string(),
            encryption: "none".to_string(),
            network: "grpc".to_string(),
            security: "tls".to_string(),
            sni: "server.example.com".to_string(),
            fingerprint: "chrome".to_string(),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            mode: "multi".to_string(),
        };

        let config = create_config(&params, 1080, 1080);

        // Inbounds: single entry when ports are the same
        let inbounds = config["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0]["port"], 1080);
        assert_eq!(inbounds[0]["protocol"], "socks");

        // Outbounds: vless + freedom + blackhole
        let outbounds = config["outbounds"].as_array().unwrap();
        assert_eq!(outbounds.len(), 3);
        assert_eq!(outbounds[0]["protocol"], "vless");
        assert_eq!(outbounds[0]["tag"], "MyProxy");
        assert_eq!(
            outbounds[0]["settings"]["vnext"][0]["address"],
            "server.example.com"
        );
        assert_eq!(outbounds[0]["settings"]["vnext"][0]["port"], 443);
        assert_eq!(
            outbounds[0]["settings"]["vnext"][0]["users"][0]["id"],
            "test-uuid"
        );
        assert_eq!(outbounds[0]["streamSettings"]["network"], "grpc");
        assert_eq!(outbounds[0]["streamSettings"]["security"], "tls");
        assert_eq!(
            outbounds[0]["streamSettings"]["tlsSettings"]["serverName"],
            "server.example.com"
        );
        assert_eq!(
            outbounds[0]["streamSettings"]["tlsSettings"]["fingerprint"],
            "chrome"
        );
        assert_eq!(
            outbounds[0]["streamSettings"]["tlsSettings"]["alpn"],
            serde_json::json!(["h2", "http/1.1"])
        );
        assert_eq!(
            outbounds[0]["streamSettings"]["grpcSettings"]["multiMode"],
            true
        );

        assert_eq!(outbounds[1]["protocol"], "freedom");
        assert_eq!(outbounds[1]["tag"], "direct");
        assert_eq!(outbounds[2]["protocol"], "blackhole");
        assert_eq!(outbounds[2]["tag"], "block");

        // Routing
        assert_eq!(config["routing"]["domainStrategy"], "AsIs");
        let rules = config["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["ruleTag"], "ru-tld-direct");
        assert_eq!(rules[0]["outboundTag"], "direct");

        // Log section
        assert_eq!(config["log"]["loglevel"], "warning");
        assert_eq!(config["log"]["access"], "/var/log/xray/access.log");
        assert_eq!(config["log"]["error"], "/var/log/xray/error.log");

        // DNS
        assert_eq!(config["dns"]["servers"][0], "8.8.8.8");
        assert_eq!(config["dns"]["tag"], "dns_out");

        // Sniffing enabled
        assert_eq!(inbounds[0]["sniffing"]["enabled"], true);
    }

    #[test]
    fn create_config_with_minimal_params() {
        let params = VlessParams {
            uuid: "uuid".to_string(),
            host: "host.net".to_string(),
            port: 8443,
            name: String::new(),
            encryption: "none".to_string(),
            network: "tcp".to_string(),
            security: String::new(),
            sni: String::new(),
            fingerprint: String::new(),
            alpn: vec![],
            mode: String::new(),
        };

        let config = create_config(&params, 1080, 1080);

        // Tag falls back to "proxy" when name is empty
        assert_eq!(config["outbounds"][0]["tag"], "proxy");

        // No tlsSettings when sni/fp/alpn are all empty
        assert!(config["outbounds"][0]["streamSettings"]["tlsSettings"].is_null());

        // No grpcSettings when mode is empty
        assert!(config["outbounds"][0]["streamSettings"]["grpcSettings"].is_null());
    }

    #[test]
    fn create_config_separate_ports() {
        let params = VlessParams {
            uuid: "uuid".to_string(),
            host: "host.net".to_string(),
            port: 443,
            name: String::new(),
            encryption: "none".to_string(),
            network: "tcp".to_string(),
            security: String::new(),
            sni: String::new(),
            fingerprint: String::new(),
            alpn: vec![],
            mode: String::new(),
        };

        let config = create_config(&params, 1080, 8080);

        let inbounds = config["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 2);
        assert_eq!(inbounds[0]["protocol"], "socks");
        assert_eq!(inbounds[0]["port"], 1080);
        assert_eq!(inbounds[1]["protocol"], "http");
        assert_eq!(inbounds[1]["port"], 8080);
    }

    #[test]
    fn create_config_writes_valid_json() {
        let params = VlessParams {
            uuid: "test-uuid".to_string(),
            host: "example.com".to_string(),
            port: 443,
            name: "test".to_string(),
            encryption: "none".to_string(),
            network: "grpc".to_string(),
            security: "tls".to_string(),
            sni: "example.com".to_string(),
            fingerprint: "chrome".to_string(),
            alpn: vec!["h2".to_string()],
            mode: "multi".to_string(),
        };

        let config = create_config(&params, 1080, 1080);
        let json_str = serde_json::to_string_pretty(&config).unwrap();

        // Verify it round-trips as valid JSON
        let reparsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(config, reparsed);
    }
}
