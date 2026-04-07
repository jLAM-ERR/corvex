use crate::protocol::ProxyParams;
use anyhow::{bail, Context, Result};
use log::debug;
use rand::Rng;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const CHECK_URL: &str = "http://www.gstatic.com/generate_204";

/// Find a free port for temporary xray health check instances.
fn find_free_port() -> Result<u16> {
    let mut rng = rand::rng();
    for _ in 1..=100 {
        let port = rng.random_range(20000..=60000u16);
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    bail!("failed to find a free port for health check")
}

/// Check TCP connectivity to host:port with the given timeout.
pub fn check_tcp(host: &str, port: u16, timeout: Duration) -> Result<()> {
    debug!("TCP check {}:{} (timeout {:?})", host, port, timeout);
    let addr_str = format!("{host}:{port}");
    let addr: SocketAddr = addr_str
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve {addr_str}"))?
        .next()
        .with_context(|| format!("no addresses found for {addr_str}"))?;

    TcpStream::connect_timeout(&addr, timeout)
        .with_context(|| format!("TCP connect to {addr} timed out or failed"))?;

    debug!("TCP check {}:{} succeeded", host, port);
    Ok(())
}

/// Generate a minimal xray config for tunnel checking.
/// Returns a `NamedTempFile` that auto-deletes on drop, preventing credential
/// leakage if the process is killed before the `TunnelGuard` is constructed.
pub fn generate_temp_config(params: &ProxyParams, local_port: u16) -> Result<NamedTempFile> {
    let stream_settings = crate::protocol::build_stream_settings(params);
    let outbound_settings = crate::protocol::build_outbound_settings(params);

    let config = serde_json::json!({
        "log": { "loglevel": "none" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": local_port,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": false },
        }],
        "outbounds": [{
            "protocol": params.protocol,
            "tag": "proxy",
            "settings": outbound_settings,
            "streamSettings": stream_settings,
        }],
    });

    let json = serde_json::to_string_pretty(&config).context("failed to serialize temp config")?;

    let mut file = NamedTempFile::with_suffix(".json").context("failed to create temp config")?;
    std::io::Write::write_all(&mut file, json.as_bytes())
        .context("failed to write temp config")?;

    Ok(file)
}

/// Guard to ensure child process is killed and temp file removed on drop.
/// The `NamedTempFile` auto-deletes when dropped, so credentials never persist.
struct TunnelGuard {
    child: Child,
    _config_file: NamedTempFile,
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // _config_file is auto-deleted by NamedTempFile::drop
    }
}

/// Check tunnel connectivity by spawning a temp xray and making an HTTP request through it.
/// Returns the round-trip latency.
pub fn check_tunnel(params: &ProxyParams, xray_bin: &str) -> Result<Duration> {
    let local_port = find_free_port()?;
    let config_file = generate_temp_config(params, local_port)?;
    debug!("tunnel check via temp config {}", config_file.path().display());

    let child = Command::new(xray_bin)
        .args(["run", "-c"])
        .arg(config_file.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to spawn xray for tunnel check")?;

    let mut guard = TunnelGuard {
        child,
        _config_file: config_file,
    };

    // Poll for xray readiness instead of fixed sleep
    let mut ready = false;
    for _ in 0..20 {
        // Check if child exited early (crash)
        if let Ok(Some(status)) = guard.child.try_wait() {
            anyhow::bail!("xray health check process exited with {status}");
        }
        if TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], local_port)),
            Duration::from_millis(50),
        )
        .is_ok()
        {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    if !ready {
        anyhow::bail!("xray health-check process did not become ready within 1s");
    }

    // Make HTTP request through SOCKS proxy
    let proxy = ureq::Proxy::new(&format!("socks5://127.0.0.1:{local_port}"))
        .context("failed to create SOCKS proxy")?;
    let config = ureq::Agent::config_builder()
        .proxy(Some(proxy))
        .timeout_global(Some(Duration::from_secs(10)))
        .build();
    let agent = ureq::Agent::new_with_config(config);

    let start = Instant::now();
    agent
        .get(CHECK_URL)
        .call()
        .context("tunnel check HTTP request failed")?;
    let latency = start.elapsed();
    debug!("tunnel check latency: {:?}", latency);

    drop(guard);

    Ok(latency)
}

const TCP_TIMEOUT: Duration = Duration::from_secs(5);
const DEGRADED_THRESHOLD: Duration = Duration::from_millis(3000);

/// Find the first alive server from a list of VLESS URIs.
/// Performs TCP pre-filter then tunnel check; returns the first URI with acceptable latency.
pub fn find_alive_server(uris: &[String], xray_bin: &str) -> Result<String> {
    debug!("searching for alive server among {} candidates", uris.len());
    for (i, uri) in uris.iter().enumerate() {
        let params = match crate::protocol::parse_uri(uri) {
            Ok(p) => p,
            Err(_) => {
                debug!("[{}/{}] skipping unparseable URI", i + 1, uris.len());
                continue;
            }
        };

        eprintln!(
            "  testing server {}/{}: {}:{}",
            i + 1,
            uris.len(),
            params.host,
            params.port
        );

        // Fast pre-filter: TCP connect
        if check_tcp(&params.host, params.port, TCP_TIMEOUT).is_err() {
            debug!("[{}/{}] TCP check failed, skipping", i + 1, uris.len());
            continue;
        }

        // Full check: tunnel latency
        match check_tunnel(&params, xray_bin) {
            Ok(latency) if latency <= DEGRADED_THRESHOLD => {
                debug!(
                    "[{}/{}] server alive (latency: {:?})",
                    i + 1,
                    uris.len(),
                    latency
                );
                return Ok(uri.clone());
            }
            Ok(latency) => {
                debug!(
                    "[{}/{}] server too slow (latency: {:?})",
                    i + 1,
                    uris.len(),
                    latency
                );
                continue;
            }
            Err(e) => {
                debug!("[{}/{}] tunnel check failed: {}", i + 1, uris.len(), e);
                continue;
            }
        }
    }

    anyhow::bail!("no reachable servers found")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_valid_address_format_parsing() {
        let addr_str = "127.0.0.1:80";
        let addrs: Vec<SocketAddr> = addr_str.to_socket_addrs().unwrap().collect();
        assert!(!addrs.is_empty());
        assert_eq!(addrs[0].port(), 80);
        assert_eq!(addrs[0].ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn test_timeout_is_respected() {
        let start = std::time::Instant::now();
        let result = check_tcp("192.0.2.1", 12345, Duration::from_millis(200));
        let elapsed = start.elapsed();

        assert!(
            result.is_err(),
            "connect to non-routable address should fail"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "expected timeout around 200ms, but took {:?}",
            elapsed
        );
    }

    fn sample_params() -> ProxyParams {
        crate::protocol::parse_uri(
            "vless://test-uuid-1234@server.example.com:443?encryption=none&type=grpc&mode=multi&security=tls&sni=server.example.com&fp=chrome&alpn=h2#TestServer"
        ).unwrap()
    }

    #[test]
    fn test_generate_temp_config_valid_json() {
        let params = sample_params();
        let port = 30000;
        let file = generate_temp_config(&params, port).unwrap();

        let content = fs::read_to_string(file.path()).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert_eq!(config["log"]["loglevel"], "none");
        assert!(config["inbounds"].is_array());
        assert!(config["outbounds"].is_array());
    }

    #[test]
    fn test_generate_temp_config_correct_port() {
        let params = sample_params();
        let port = 31234;
        let file = generate_temp_config(&params, port).unwrap();

        let content = fs::read_to_string(file.path()).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert_eq!(config["inbounds"][0]["port"], port);
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][0]["protocol"], "socks");
    }

    #[test]
    fn test_generate_temp_config_correct_address() {
        let params = sample_params();
        let port = 31235;
        let file = generate_temp_config(&params, port).unwrap();

        let content = fs::read_to_string(file.path()).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();

        let vnext = &config["outbounds"][0]["settings"]["vnext"][0];
        assert_eq!(vnext["address"], "server.example.com");
        assert_eq!(vnext["port"], 443);
        assert_eq!(vnext["users"][0]["id"], "test-uuid-1234");
        assert_eq!(vnext["users"][0]["encryption"], "none");
    }

    #[test]
    fn test_generate_temp_config_stream_settings() {
        let params = sample_params();
        let port = 31236;
        let file = generate_temp_config(&params, port).unwrap();

        let content = fs::read_to_string(file.path()).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();

        let stream = &config["outbounds"][0]["streamSettings"];
        assert_eq!(stream["network"], "grpc");
        assert_eq!(stream["security"], "tls");
        assert_eq!(stream["tlsSettings"]["serverName"], "server.example.com");
        assert_eq!(stream["tlsSettings"]["fingerprint"], "chrome");
        assert_eq!(stream["grpcSettings"]["multiMode"], true);
    }

    #[test]
    fn test_generate_temp_config_auto_cleanup() {
        let params = sample_params();
        let port = 31237;
        let file = generate_temp_config(&params, port).unwrap();
        let path = file.path().to_path_buf();
        assert!(path.exists());
        drop(file);
        assert!(!path.exists(), "temp config should be deleted on drop");
    }

    #[test]
    fn test_find_alive_server_all_unreachable() {
        // URIs pointing to non-routable addresses — TCP check fails quickly
        let uris = vec![
            "vless://uuid@192.0.2.1:443?type=grpc&security=tls#Server1".to_string(),
            "vless://uuid@192.0.2.2:443?type=grpc&security=tls#Server2".to_string(),
        ];
        let result = find_alive_server(&uris, "xray");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("no reachable"),
            "expected 'no reachable servers' error"
        );
    }

    #[test]
    fn test_find_alive_server_invalid_uris_skipped() {
        let uris = vec![
            "not-a-valid-uri".to_string(),
            "vmess://something".to_string(),
        ];
        let result = find_alive_server(&uris, "xray");
        assert!(result.is_err());
    }

    #[test]
    fn test_find_alive_server_empty_list() {
        let result = find_alive_server(&[], "xray");
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_temp_config_minimal_params() {
        let params = crate::protocol::parse_uri("vless://uuid@host.net:8443").unwrap();
        let port = 31238;
        let file = generate_temp_config(&params, port).unwrap();

        let content = fs::read_to_string(file.path()).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();

        // No tlsSettings or grpcSettings
        assert!(config["outbounds"][0]["streamSettings"]["tlsSettings"].is_null());
        assert!(config["outbounds"][0]["streamSettings"]["grpcSettings"].is_null());
    }
}
