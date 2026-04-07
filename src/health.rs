use crate::protocol::ProxyParams;
use anyhow::{bail, Context, Result};
use log::debug;
use rand::Rng;
use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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
/// Writes to `/tmp/xray-check-{local_port}.json`.
pub fn generate_temp_config(params: &ProxyParams, local_port: u16) -> Result<PathBuf> {
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

    let path = std::env::temp_dir().join(format!("xray-check-{local_port}.json"));
    let json = serde_json::to_string_pretty(&config).context("failed to serialize temp config")?;

    // Create file with restricted permissions from the start to prevent credential leakage
    let mut file = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
                .with_context(|| format!("failed to create {}", path.display()))?
        }
        #[cfg(windows)]
        {
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .with_context(|| format!("failed to create {}", path.display()))?
        }
    };
    std::io::Write::write_all(&mut file, json.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;

    Ok(path)
}

/// Guard to ensure child process is killed and temp file removed on drop.
struct TunnelGuard {
    child: Child,
    config_path: PathBuf,
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.config_path);
    }
}

/// Check tunnel connectivity by spawning a temp xray and making an HTTP request through it.
/// Returns the round-trip latency.
pub fn check_tunnel(params: &ProxyParams, xray_bin: &str) -> Result<Duration> {
    let local_port = find_free_port()?;
    let config_path = generate_temp_config(params, local_port)?;
    debug!("tunnel check via temp config {}", config_path.display());

    let child = Command::new(xray_bin)
        .args(["run", "-c"])
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to spawn xray for tunnel check")?;

    let mut guard = TunnelGuard { child, config_path };

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
        let path = generate_temp_config(&params, port).unwrap();

        // Verify file exists and is valid JSON
        let content = fs::read_to_string(&path).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();

        // Cleanup
        let _ = fs::remove_file(&path);

        // Verify structure
        assert_eq!(config["log"]["loglevel"], "none");
        assert!(config["inbounds"].is_array());
        assert!(config["outbounds"].is_array());
    }

    #[test]
    fn test_generate_temp_config_correct_port() {
        let params = sample_params();
        let port = 31234;
        let path = generate_temp_config(&params, port).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        let _ = fs::remove_file(&path);

        assert_eq!(config["inbounds"][0]["port"], port);
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][0]["protocol"], "socks");
    }

    #[test]
    fn test_generate_temp_config_correct_address() {
        let params = sample_params();
        let port = 31235;
        let path = generate_temp_config(&params, port).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        let _ = fs::remove_file(&path);

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
        let path = generate_temp_config(&params, port).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        let _ = fs::remove_file(&path);

        let stream = &config["outbounds"][0]["streamSettings"];
        assert_eq!(stream["network"], "grpc");
        assert_eq!(stream["security"], "tls");
        assert_eq!(stream["tlsSettings"]["serverName"], "server.example.com");
        assert_eq!(stream["tlsSettings"]["fingerprint"], "chrome");
        assert_eq!(stream["grpcSettings"]["multiMode"], true);
    }

    #[test]
    fn test_generate_temp_config_file_path() {
        let params = sample_params();
        let port = 31237;
        let path = generate_temp_config(&params, port).unwrap();
        let _ = fs::remove_file(&path);

        let expected = std::env::temp_dir().join("xray-check-31237.json");
        assert_eq!(path, expected);
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
        let path = generate_temp_config(&params, port).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        let _ = fs::remove_file(&path);

        // No tlsSettings or grpcSettings
        assert!(config["outbounds"][0]["streamSettings"]["tlsSettings"].is_null());
        assert!(config["outbounds"][0]["streamSettings"]["grpcSettings"].is_null());
    }
}
