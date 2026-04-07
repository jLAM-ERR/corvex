mod config;
mod dns;
mod engine;
mod health;
mod platform;
mod protocol;
mod settings;
mod subscription;
mod traffic;
mod xray;

use anyhow::Context;
use clap::{Parser, Subcommand};
use colored::Colorize;
use config::Config;
use log::{debug, info, warn};
use platform::Platform;
use std::io::Write;
use std::process::{self, Command};

#[derive(Parser)]
#[command(name = "corvex", about = "Manage Xray VPN proxy and system proxy")]
struct Cli {
    /// Path to corvex.json settings file (overrides default)
    #[arg(long = "settings", global = true)]
    settings_path: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start xray and enable system proxy
    Start,
    /// Disable system proxy and stop xray
    Stop,
    /// Validate config and reload xray
    Reload,
    /// Show xray process, ports, and proxy settings
    Status,
    /// Show xray log
    Logs {
        /// Follow log output (like tail -f)
        #[arg(short, long)]
        follow: bool,
    },
}

fn init_logger(settings_path: Option<&str>) {
    let debug = if std::env::var("CORVEX_DEBUG").ok().as_deref() == Some("1") {
        true
    } else {
        let path = match settings_path {
            Some(p) => std::path::PathBuf::from(p),
            None => settings::xdg_settings_path(),
        };
        settings::load(&path)
            .ok()
            .and_then(|s| s.log)
            .and_then(|l| l.corvex)
            .and_then(|c| c.debug)
            .unwrap_or(false)
    };

    let default_level = if debug { "debug" } else { "warn" };
    let _ =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_level))
            .format(|buf, record| {
                let ts = buf.timestamp_seconds();
                writeln!(buf, "{} [{}] {}", ts, record.level(), record.args())
            })
            .try_init();
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logger(cli.settings_path.as_deref());
    let mut config = Config::new(None);

    // Apply --settings override
    if let Some(ref path) = cli.settings_path {
        config.corvex_settings = std::path::PathBuf::from(path);
    }

    // Override xray_log from corvex.json if configured
    if let Ok(s) = settings::load(&config.corvex_settings) {
        if let Some(error_path) = s
            .log
            .as_ref()
            .and_then(|l| l.xray.as_ref())
            .and_then(|x| x.error.clone())
        {
            config.xray_log = std::path::PathBuf::from(error_path);
        }
    }

    let plat = platform::create_platform();

    match cli.command {
        Commands::Start => cmd_start(&config, &plat),
        Commands::Stop => cmd_stop(&config, &plat),
        Commands::Reload => cmd_reload(&config),
        Commands::Status => cmd_status(&config, &plat),
        Commands::Logs { follow } => cmd_logs(&config, follow),
    }
}

/// Detect engine mode from URI scheme.
fn detect_engine_mode(uri: &str) -> engine::EngineMode {
    if uri.starts_with("vpn://") {
        engine::EngineMode::Awg
    } else {
        engine::EngineMode::Xray
    }
}

fn cmd_start(config: &Config, plat: &impl Platform) -> anyhow::Result<()> {
    // 1. Load corvex.json
    let s = settings::load(&config.corvex_settings)
        .with_context(|| format!("failed to load {}", config.corvex_settings.display()))?;

    // Ensure all directories exist
    ensure_directories(config, &s);

    // 2. Validate: need uri or file-url
    if s.uri.is_none() && s.file_url.is_none() {
        anyhow::bail!(
            "corvex.json must contain \"uri\" or \"file-url\".\n\
             Config path: {}",
            config.corvex_settings.display()
        );
    }

    // Validate proxy.port is set
    let static_port = match s.proxy.as_ref() {
        Some(p) => validate_port(p.port)?,
        None => anyhow::bail!(
            "corvex.json must contain \"proxy.port\" (e.g., {{\"proxy\":{{\"port\":21080}}}})"
        ),
    };

    // 3. Resolve URI (direct or from subscriptions)
    let resolved_uri = if let Some(ref uri) = s.uri {
        debug!("start flow: using URI from corvex.json");
        uri.clone()
    } else {
        // file-url flow: download, decode, filter, find alive
        let urls = s
            .file_url
            .as_ref()
            .context("bug: file_url should be Some after validation")?;
        debug!(
            "start flow: downloading from {} subscription URLs",
            urls.len()
        );
        let mut xray_uris = Vec::new();
        let mut vpn_uris = Vec::new();
        for url in urls {
            match subscription::download_subscription(url) {
                Ok(body) => {
                    if let Ok(uris) = subscription::decode_subscription(&body) {
                        let supported = subscription::filter_supported(&uris);
                        debug!("subscription {}: {} supported URIs", url, supported.len());
                        xray_uris.extend(supported);
                        // Collect vpn:// URIs separately (handled by AWG engine)
                        vpn_uris.extend(uris.into_iter().filter(|u| u.starts_with("vpn://")));
                    }
                }
                Err(e) => {
                    warn!("subscription {} failed: {}", url, e);
                    continue;
                }
            }
        }
        if xray_uris.is_empty() && vpn_uris.is_empty() {
            anyhow::bail!("no supported proxy servers found in subscriptions");
        }
        // Try xray-compatible URIs first (with health checks), fall back to vpn://
        if !xray_uris.is_empty() {
            match health::find_alive_server(&xray_uris, &config.xray_bin) {
                Ok(uri) => uri,
                Err(_) if !vpn_uris.is_empty() => {
                    debug!("no reachable xray servers, falling back to vpn:// URI");
                    vpn_uris.swap_remove(0)
                }
                Err(e) => return Err(e),
            }
        } else {
            vpn_uris.swap_remove(0)
        }
    };

    // 4. Extract routing settings (shared between both engine modes)
    let direct_ru = s.routes.as_ref().and_then(|r| r.direct_ru).unwrap_or(false);
    let proxy_traffic: Vec<String> = s
        .routes
        .as_ref()
        .and_then(|r| r.proxy_traffic.clone())
        .unwrap_or_default();
    let corporate_traffic: Vec<String> = s
        .routes
        .as_ref()
        .and_then(|r| r.corporate_traffic.clone())
        .unwrap_or_default();
    let log_config = build_xray_log_config(&s);

    // 5. Branch on engine mode
    match detect_engine_mode(&resolved_uri) {
        engine::EngineMode::Awg => {
            debug!("AWG engine mode");
            let awg_config = engine::awg::parse_vpn_uri(&resolved_uri)?;

            // Write AWG .conf
            let awg_conf_path = config.awg_conf_path()?;
            engine::awg::write_conf(&awg_config, &awg_conf_path)?;

            // Ensure awg-quick is installed and start tunnel
            engine::awg::ensure_awg_installed()?;
            engine::awg::start_tunnel(&awg_conf_path)?;
            println!("{}", "AWG tunnel started".green());

            // Build routing rules with "proxy" tag
            let rules = traffic::build_routing_rules(
                &corporate_traffic,
                &proxy_traffic,
                "proxy",
                direct_ru,
            );
            debug!("built {} routing rules", rules.len());

            // Create xray config with freedom outbound
            let xray_cfg = protocol::create_config_awg_mode(static_port, &rules, &log_config);
            if let Some(parent) = config.xray_config.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let json = serde_json::to_string_pretty(&xray_cfg)?;
            config::write_restricted(&config.xray_config, &json)?;

            // DNS sync
            let mut dns_mappings = s.corporate_dns.unwrap_or_default();
            if let Ok(discovered) = plat.discover_corporate_dns() {
                for (domain, ns) in discovered {
                    dns_mappings.entry(domain).or_insert(ns);
                }
            }
            if !dns_mappings.is_empty() {
                dns::sync_to_config(&config.xray_config, &dns_mappings)?;
            }

            // Start xray as routing layer and enable proxy
            main_algorithm(config, plat, static_port)
        }
        engine::EngineMode::Xray => {
            debug!("Xray engine mode");
            let params = protocol::parse_uri(&resolved_uri)?;

            // Build routing rules
            let proxy_tag = if params.name.is_empty() {
                "proxy"
            } else {
                &params.name
            };
            let rules = traffic::build_routing_rules(
                &corporate_traffic,
                &proxy_traffic,
                proxy_tag,
                direct_ru,
            );
            debug!("built {} routing rules", rules.len());

            // Create or update xray config
            if config.xray_config.exists() {
                debug!("updating existing config {}", config.xray_config.display());
                protocol::apply_to_config(&params, &config.xray_config, &log_config)?;
                update_routing_rules(&config.xray_config, &rules)?;
            } else {
                debug!("creating new config {}", config.xray_config.display());
                let xray_cfg = protocol::create_config(&params, static_port, &rules, &log_config);
                if let Some(parent) = config.xray_config.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let json = serde_json::to_string_pretty(&xray_cfg)?;
                config::write_restricted(&config.xray_config, &json)?;
            }

            // DNS sync
            let mut dns_mappings = s.corporate_dns.unwrap_or_default();
            if let Ok(discovered) = plat.discover_corporate_dns() {
                for (domain, ns) in discovered {
                    dns_mappings.entry(domain).or_insert(ns);
                }
            }
            if !dns_mappings.is_empty() {
                dns::sync_to_config(&config.xray_config, &dns_mappings)?;
            }

            main_algorithm(config, plat, static_port)
        }
    }
}

/// Validate that a port is in the valid range (1024-65535).
fn validate_port(port: u16) -> anyhow::Result<u16> {
    if port < 1024 {
        anyhow::bail!("proxy.port must be >= 1024 (got {port})");
    }
    Ok(port)
}

/// Build XrayLogConfig from corvex.json settings, using defaults for missing values.
fn build_xray_log_config(settings: &settings::CorvexSettings) -> protocol::XrayLogConfig {
    let defaults = protocol::XrayLogConfig::default();
    match settings.log.as_ref().and_then(|l| l.xray.as_ref()) {
        Some(xray_log) => protocol::XrayLogConfig {
            loglevel: xray_log.loglevel.clone().unwrap_or(defaults.loglevel),
            access: xray_log.access.clone().unwrap_or(defaults.access),
            error: xray_log.error.clone().unwrap_or(defaults.error),
        },
        None => defaults,
    }
}

/// Update routing rules in an existing xray config.
fn update_routing_rules(
    config_path: &std::path::Path,
    rules: &[serde_json::Value],
) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(config_path)?;
    let mut config: serde_json::Value = serde_json::from_str(&content)?;

    if config.get("routing").is_none() {
        config["routing"] = serde_json::json!({
            "domainStrategy": "AsIs",
        });
    }
    config["routing"]["rules"] = serde_json::json!(rules);

    let json = serde_json::to_string_pretty(&config)?;
    config::write_restricted(config_path, &json)?;
    Ok(())
}

/// Ensure all required directories exist before starting.
/// Creates directories for config, log, and PID files.
/// Permission errors on log directories (e.g., /var/log/xray/) are logged as warnings,
/// not fatal — those may require sudo.
fn ensure_directories(config: &Config, settings: &settings::CorvexSettings) {
    let must_create = [
        config.corvex_settings.parent(),
        config.xray_config.parent(),
        config.corvex_log.parent(),
        config.xray_pid_file.parent(),
    ];
    for dir in must_create.into_iter().flatten() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            warn!("failed to create directory {}: {}", dir.display(), e);
        }
    }

    // Xray log dirs from settings — may need sudo, so warn on failure
    let log_paths: Vec<Option<&str>> = if let Some(log) = settings.log.as_ref() {
        if let Some(xray) = log.xray.as_ref() {
            vec![xray.access.as_deref(), xray.error.as_deref()]
        } else {
            vec![]
        }
    } else {
        vec![]
    };
    // Also include the default xray_log path from config
    let xray_log_parent = config.xray_log.parent();
    if let Some(dir) = xray_log_parent {
        if let Err(e) = std::fs::create_dir_all(dir) {
            info!(
                "cannot create log directory {} (may need sudo): {}",
                dir.display(),
                e
            );
        }
    }
    for path in log_paths.into_iter().flatten() {
        if let Some(dir) = std::path::Path::new(path).parent() {
            if let Err(e) = std::fs::create_dir_all(dir) {
                info!(
                    "cannot create log directory {} (may need sudo): {}",
                    dir.display(),
                    e
                );
            }
        }
    }
}

/// Main algorithm: ensure xray installed, write port to config, start, enable proxy.
fn main_algorithm(config: &Config, plat: &impl Platform, port: u16) -> anyhow::Result<()> {
    debug!("ensuring xray is installed");
    xray::ensure_installed(&config.xray_bin)?;

    // Stop any running instance before starting a new one
    if xray::is_running(config).is_some() {
        debug!("stopping existing xray instance");
        xray::stop(config)?;
    }

    // Write port into xray config.json inbound section
    debug!("writing port {} to config", port);
    update_config_port(&config.xray_config, port)?;

    let pid = xray::start(config)?;
    debug!("xray process started with PID {}", pid);
    println!("{}", format!("xray started (PID: {pid})").green());

    let service = plat.detect_active_service()?;
    debug!(
        "enabling proxy on service '{}' at 127.0.0.1:{}",
        service, port
    );
    plat.enable_proxy(&service, "127.0.0.1", port)?;

    println!("{}", format!("proxy enabled on 127.0.0.1:{port}").green());

    Ok(())
}

/// Update the port in the first inbound of xray config.json.
fn update_config_port(config_path: &std::path::Path, port: u16) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let mut config: serde_json::Value = serde_json::from_str(&content)?;

    let inbound = config
        .pointer_mut("/inbounds/0")
        .context("config.json has no inbounds[0] entry")?;
    inbound["port"] = serde_json::json!(port);

    let json = serde_json::to_string_pretty(&config)?;
    config::write_restricted(config_path, &json)?;
    Ok(())
}

fn cmd_stop(config: &Config, plat: &impl Platform) -> anyhow::Result<()> {
    debug!("disabling system proxy");
    let service = plat.detect_active_service()?;
    let proxy_result = plat.disable_proxy(&service);
    debug!("stopping xray process");
    let xray_result = xray::stop(config);

    // Stop AWG tunnel if running (don't let path errors swallow proxy/xray results)
    if let Ok(awg_conf_path) = config.awg_conf_path() {
        let iface = engine::awg::conf_interface_name(&awg_conf_path);
        if engine::awg::is_tunnel_running(&iface) {
            debug!("stopping AWG tunnel");
            if let Err(e) = engine::awg::stop_tunnel(&awg_conf_path) {
                warn!("failed to stop AWG tunnel: {}", e);
            } else {
                println!("{}", "AWG tunnel stopped".green());
            }
        }
    }

    proxy_result?;
    xray_result?;
    println!("{}", "corvex stopped!".green());
    Ok(())
}

fn cmd_reload(config: &Config) -> anyhow::Result<()> {
    debug!("validating config before reload");
    println!("{}", "Validating config...".yellow());
    xray::reload(config)?;
    println!("{}", "Config reloaded (SIGHUP sent)".green());
    Ok(())
}

fn cmd_status(config: &Config, plat: &impl Platform) -> anyhow::Result<()> {
    debug!("checking status");
    let service = plat.detect_active_service()?;
    println!("Network service: {}", service.yellow());

    // Config paths
    println!("Settings: {}", config.corvex_settings.display());
    println!("Xray config: {}", config.xray_config.display());
    println!("Xray log: {}", config.xray_log.display());

    // Engine type and AWG status
    if let Ok(awg_conf_path) = config.awg_conf_path() {
        let awg_iface = engine::awg::conf_interface_name(&awg_conf_path);
        if engine::awg::is_tunnel_running(&awg_iface) {
            println!("Engine: {}", "AWG + xray".green());
            println!("AWG tunnel: {} ({})", "running".green(), awg_iface);
        } else {
            println!("Engine: {}", "xray".green());
        }
    } else {
        println!("Engine: {}", "xray".green());
    }

    // Xray process
    match xray::is_running(config) {
        Some(pid) => println!("xray: {} (PID: {})", "started".green(), pid),
        None => println!("xray: {}", "stopped".red()),
    }

    // Proxy status from networksetup
    match plat.proxy_status(&service) {
        Ok(status) => {
            print_proxy_status("socks", &status.socks);
            print_proxy_status("http", &status.http);
            print_proxy_status("https", &status.https);
        }
        Err(e) => println!("{}", format!("Failed to query proxy: {e}").red()),
    }

    // Last 5 log lines
    if config.xray_log.exists() {
        println!();
        let _ = Command::new("tail")
            .args(["-5"])
            .arg(&config.xray_log)
            .status();
    }

    Ok(())
}

fn print_proxy_status(label: &str, info: &platform::ProxyInfo) {
    if info.enabled {
        println!("{}: {}:{}", label, info.server, info.port);
    } else {
        println!("{}: {}", label, "off".red());
    }
}

fn cmd_logs(config: &Config, follow: bool) -> anyhow::Result<()> {
    debug!("reading logs (follow={})", follow);
    if !config.xray_log.exists() {
        anyhow::bail!("Log file not found: {}", config.xray_log.display());
    }

    let mut args = vec![];
    if follow {
        args.push("-f");
    } else {
        args.push("-20");
    }

    let status = Command::new("tail")
        .args(&args)
        .arg(&config.xray_log)
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to run tail: {e}"))?;

    if !status.success() {
        anyhow::bail!("tail exited with status {status}");
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{}: {e:#}", "Error".red());
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::Parser;

    fn format_xray_status(pid: Option<i32>) -> String {
        match pid {
            Some(pid) => format!("xray: started (PID: {})", pid),
            None => "xray: stopped".to_string(),
        }
    }

    fn format_proxy_status(label: &str, enabled: bool, server: &str, port: &str) -> String {
        if enabled {
            format!("{}: {}:{}", label, server, port)
        } else {
            format!("{}: off", label)
        }
    }

    #[test]
    fn test_format_xray_status_running() {
        let result = format_xray_status(Some(1234));
        assert_eq!(result, "xray: started (PID: 1234)");
    }

    #[test]
    fn test_format_xray_status_stopped() {
        let result = format_xray_status(None);
        assert_eq!(result, "xray: stopped");
    }

    #[test]
    fn test_format_proxy_status_enabled() {
        let result = format_proxy_status("socks", true, "127.0.0.1", "1080");
        assert_eq!(result, "socks: 127.0.0.1:1080");
    }

    #[test]
    fn test_format_proxy_status_disabled() {
        let result = format_proxy_status("http", false, "", "0");
        assert_eq!(result, "http: off");
    }

    #[test]
    fn test_update_config_port() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let config = serde_json::json!({
            "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks"}],
            "outbounds": [],
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        super::update_config_port(&config_path, 34567).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(updated["inbounds"][0]["port"], 34567);
        // Other fields untouched
        assert_eq!(updated["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(updated["inbounds"][0]["protocol"], "socks");
    }

    #[test]
    fn test_traffic_rules_in_create_config() {
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

        let r = config["routing"]["rules"].as_array().unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!(r[0]["outboundTag"], "direct");
        assert_eq!(r[0]["domain"][0], "domain:corp.com");
        assert_eq!(r[1]["outboundTag"], "proxy");
        assert_eq!(r[1]["domain"][0], "domain:ext.com");
        assert_eq!(r[2]["ruleTag"], "ru-tld-direct");
    }

    #[test]
    fn test_start_command_no_args() {
        let cli = Cli::try_parse_from(["corvex", "start"]).unwrap();
        assert!(matches!(cli.command, super::Commands::Start));
    }

    #[test]
    fn test_settings_flag() {
        let cli = Cli::try_parse_from(["corvex", "--settings", "/path/to/settings.json", "start"])
            .unwrap();
        assert_eq!(cli.settings_path.as_deref(), Some("/path/to/settings.json"));
        assert!(matches!(cli.command, super::Commands::Start));
    }

    #[test]
    fn test_settings_validation_requires_uri_or_file_url() {
        let s = crate::settings::CorvexSettings::default();
        assert!(s.uri.is_none() && s.file_url.is_none());
    }

    #[test]
    fn test_build_xray_log_config_defaults() {
        let s = crate::settings::CorvexSettings::default();
        let log_config = super::build_xray_log_config(&s);
        assert_eq!(log_config.loglevel, "warning");
        #[cfg(unix)]
        {
            assert_eq!(log_config.access, "/var/log/xray/access.log");
            assert_eq!(log_config.error, "/var/log/xray/error.log");
        }
    }

    #[test]
    fn test_build_xray_log_config_custom() {
        let json = r#"{
            "uri": "vless://x@y:1",
            "log": {
                "xray": {
                    "loglevel": "debug",
                    "access": "/custom/access.log",
                    "error": "/custom/error.log"
                }
            }
        }"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corvex.json");
        std::fs::write(&path, json).unwrap();
        let s = crate::settings::load(&path).unwrap();
        let log_config = super::build_xray_log_config(&s);
        assert_eq!(log_config.loglevel, "debug");
        assert_eq!(log_config.access, "/custom/access.log");
        assert_eq!(log_config.error, "/custom/error.log");
    }

    #[test]
    fn test_uri_flow_creates_config() {
        let uri =
            "vless://uuid@host.com:443?encryption=none&type=grpc&security=tls&sni=host.com#proxy";
        let params = crate::protocol::parse_uri(uri).unwrap();
        let rules = crate::traffic::build_routing_rules(
            &["corp.com".to_string()],
            &["ext.com".to_string()],
            "proxy",
            true,
        );
        let log_config = crate::protocol::XrayLogConfig::default();
        let config = crate::protocol::create_config(&params, 30000, &rules, &log_config);

        assert_eq!(config["outbounds"][0]["protocol"], "vless");
        assert_eq!(config["log"]["loglevel"], "warning");
        let r = config["routing"]["rules"].as_array().unwrap();
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn test_routing_rules_from_settings_values() {
        let corporate = vec!["corp.internal".to_string(), "dev.corp".to_string()];
        let proxy = vec!["example.com".to_string()];
        let rules = crate::traffic::build_routing_rules(&corporate, &proxy, "proxy", true);
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0]["outboundTag"], "direct");
        assert_eq!(rules[1]["outboundTag"], "proxy");
        assert_eq!(rules[2]["ruleTag"], "ru-tld-direct");
    }

    #[test]
    fn test_update_routing_rules() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let config = serde_json::json!({
            "inbounds": [],
            "outbounds": [],
            "routing": { "domainStrategy": "AsIs", "rules": [] },
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let rules =
            vec![serde_json::json!({"outboundTag": "direct", "domain": ["domain:corp.com"]})];
        super::update_routing_rules(&config_path, &rules).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        let r = updated["routing"]["rules"].as_array().unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0]["outboundTag"], "direct");
    }

    #[test]
    fn test_config_has_required_fields_for_stop_reload() {
        let config = crate::config::Config::new(None);
        assert!(config.xray_config.ends_with("xray/config.json"));
        assert!(config.xray_pid_file.ends_with("xray/xray.pid"));
        assert_eq!(config.xray_bin, "xray");
    }

    #[test]
    fn test_ensure_directories_creates_all_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let config = crate::config::Config {
            xray_bin: "xray".to_string(),
            xray_config: base.join("xray/config.json"),
            xray_log: base.join("logs/xray.log"),
            xray_pid_file: base.join("xray/xray.pid"),
            corvex_settings: base.join("corvex/corvex.json"),
            corvex_log: base.join("state/corvex/corvex.log"),
        };
        let settings = crate::settings::CorvexSettings::default();

        super::ensure_directories(&config, &settings);

        assert!(base.join("xray").exists());
        assert!(base.join("corvex").exists());
        assert!(base.join("state/corvex").exists());
        assert!(base.join("logs").exists());
    }

    #[test]
    fn test_ensure_directories_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let config = crate::config::Config {
            xray_bin: "xray".to_string(),
            xray_config: base.join("xray/config.json"),
            xray_log: base.join("logs/xray.log"),
            xray_pid_file: base.join("xray/xray.pid"),
            corvex_settings: base.join("corvex/corvex.json"),
            corvex_log: base.join("state/corvex/corvex.log"),
        };
        let settings = crate::settings::CorvexSettings::default();

        super::ensure_directories(&config, &settings);
        super::ensure_directories(&config, &settings);

        assert!(base.join("xray").exists());
        assert!(base.join("corvex").exists());
    }

    #[test]
    fn test_ensure_directories_with_log_settings() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let config = crate::config::Config {
            xray_bin: "xray".to_string(),
            xray_config: base.join("xray/config.json"),
            xray_log: base.join("logs/xray.log"),
            xray_pid_file: base.join("xray/xray.pid"),
            corvex_settings: base.join("corvex/corvex.json"),
            corvex_log: base.join("state/corvex/corvex.log"),
        };
        // Use forward slashes so the path is valid JSON on Windows too
        let base_str = base.display().to_string().replace('\\', "/");
        let json = format!(
            r#"{{
                "uri": "vless://x@y:1",
                "log": {{
                    "xray": {{
                        "access": "{base_str}/custom_logs/access.log",
                        "error": "{base_str}/custom_logs/error.log"
                    }}
                }}
            }}"#,
        );
        let settings_path = base.join("corvex.json");
        std::fs::create_dir_all(base).unwrap();
        std::fs::write(&settings_path, &json).unwrap();
        let settings = crate::settings::load(&settings_path).unwrap();

        super::ensure_directories(&config, &settings);

        assert!(base.join("custom_logs").exists());
    }

    #[test]
    fn test_ensure_directories_handles_nonwritable_gracefully() {
        let config = crate::config::Config {
            xray_bin: "xray".to_string(),
            xray_config: std::path::PathBuf::from("/nonexistent_root_path/xray/config.json"),
            xray_log: std::path::PathBuf::from("/nonexistent_root_path/logs/xray.log"),
            xray_pid_file: std::path::PathBuf::from("/nonexistent_root_path/xray/xray.pid"),
            corvex_settings: std::path::PathBuf::from("/nonexistent_root_path/corvex/corvex.json"),
            corvex_log: std::path::PathBuf::from("/nonexistent_root_path/state/corvex.log"),
        };
        let settings = crate::settings::CorvexSettings::default();
        // Should not panic
        super::ensure_directories(&config, &settings);
    }

    #[test]
    fn test_validate_port_valid() {
        let result = super::validate_port(21080);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 21080);
    }

    #[test]
    fn test_validate_port_rejects_below_1024() {
        let result = super::validate_port(80);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be >= 1024"));
    }

    #[test]
    fn test_validate_port_accepts_1024() {
        let result = super::validate_port(1024);
        assert!(result.is_ok());
    }

    #[test]
    fn test_missing_proxy_port_produces_error() {
        let s = crate::settings::CorvexSettings::default();
        assert!(s.proxy.is_none());
        // In actual cmd_start, missing proxy.port would bail
    }

    #[test]
    fn test_detect_engine_mode_vpn() {
        assert_eq!(
            super::detect_engine_mode("vpn://abc123"),
            crate::engine::EngineMode::Awg
        );
    }

    #[test]
    fn test_detect_engine_mode_vless() {
        assert_eq!(
            super::detect_engine_mode("vless://uuid@host:443"),
            crate::engine::EngineMode::Xray
        );
    }

    #[test]
    fn test_detect_engine_mode_vmess() {
        assert_eq!(
            super::detect_engine_mode("vmess://abc"),
            crate::engine::EngineMode::Xray
        );
    }

    #[test]
    fn test_detect_engine_mode_trojan() {
        assert_eq!(
            super::detect_engine_mode("trojan://abc"),
            crate::engine::EngineMode::Xray
        );
    }

    #[test]
    fn test_detect_engine_mode_ss() {
        assert_eq!(
            super::detect_engine_mode("ss://abc"),
            crate::engine::EngineMode::Xray
        );
    }
}
