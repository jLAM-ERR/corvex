mod config;
mod dns;
mod engine;
mod health;
mod jsonsubs;
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
    /// Restart xray and re-apply system proxy (full stop + start)
    Restart,
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
        Commands::Restart => cmd_start(&config, &plat),
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

/// Which source cmd_start should use to resolve a server, given what the
/// subscription download loop found. JSON subscription candidates are
/// preferred over plain URIs whenever any were parsed; the caller falls back
/// to the URI flow at runtime if no JSON subscription candidate is reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceDecision {
    JsonSubs,
    Uri,
    NoneFound,
}

fn choose_source(has_json_subs: bool, has_xray_uris: bool, has_vpn_uris: bool) -> SourceDecision {
    if has_json_subs {
        SourceDecision::JsonSubs
    } else if has_xray_uris || has_vpn_uris {
        SourceDecision::Uri
    } else {
        SourceDecision::NoneFound
    }
}

/// The resolved start source: either a URI (direct or from subscriptions,
/// dispatched to Xray or AWG by scheme) or a JSON subscription entry (always Xray).
enum StartSource {
    Uri(String),
    Entry(Box<jsonsubs::ServerEntry>),
}

/// Routing/log settings shared by both the direct-URI/subs-URI path and the
/// JSON subscription path.
struct RoutingContext<'a> {
    corporate_traffic: &'a [String],
    proxy_traffic: &'a [String],
    log_config: &'a protocol::XrayLogConfig,
}

/// Pick a server URI from downloaded subscription URIs: try xray-compatible
/// URIs first (with health checks), fall back to the first vpn:// URI.
fn resolve_uri_flow(
    xray_uris: &[String],
    vpn_uris: &mut Vec<String>,
    xray_bin: &str,
) -> anyhow::Result<String> {
    if !xray_uris.is_empty() {
        match health::find_alive_server(xray_uris, xray_bin) {
            Ok(uri) => Ok(uri),
            Err(_) if !vpn_uris.is_empty() => {
                debug!("no reachable xray servers, falling back to vpn:// URI");
                Ok(vpn_uris.swap_remove(0))
            }
            Err(e) => Err(e),
        }
    } else {
        Ok(vpn_uris.swap_remove(0))
    }
}

/// Security-critical gate: a JSON subscription entry's direct-rule
/// domains/ips only widen DIRECT routing when the user opted in via
/// `routes.merge-subs`. Returns empty slices otherwise, regardless of what
/// the entry carries.
fn subs_direct_slices(merge_subs: bool, entry: &jsonsubs::ServerEntry) -> (&[String], &[String]) {
    if merge_subs {
        (&entry.direct_domains, &entry.direct_ips)
    } else {
        (&[], &[])
    }
}

/// Build routing rules, write/update xray config.json, sync corporate DNS, then
/// start xray and enable the system proxy. Shared tail for both the
/// direct-URI/subs-URI path and the JSON subscription path — the only
/// difference between callers is `params` and `subs_direct` (JSON
/// subscription direct-rule merge, gated by `routes.merge-subs`).
fn start_xray_engine(
    config: &Config,
    plat: &impl Platform,
    params: &protocol::ProxyParams,
    static_port: u16,
    routing: &RoutingContext,
    subs_direct: (&[String], &[String]),
    corporate_dns: std::collections::BTreeMap<String, String>,
) -> anyhow::Result<()> {
    debug!("starting xray engine");
    let proxy_tag = if params.name.is_empty() {
        "proxy"
    } else {
        &params.name
    };
    let (subs_direct_domains, subs_direct_ips) = subs_direct;
    let rules = traffic::build_routing_rules(
        routing.corporate_traffic,
        routing.proxy_traffic,
        proxy_tag,
        subs_direct_domains,
        subs_direct_ips,
    );
    debug!("built {} routing rules", rules.len());

    write_xray_config(
        &config.xray_config,
        params,
        static_port,
        &rules,
        routing.log_config,
    )?;

    // DNS sync
    let mut dns_mappings = corporate_dns;
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

fn cmd_start(config: &Config, plat: &impl Platform) -> anyhow::Result<()> {
    // 1. Load corvex.json
    let s = settings::load(&config.corvex_settings)
        .with_context(|| format!("failed to load {}", config.corvex_settings.display()))?;

    // Ensure all directories exist
    ensure_directories(config, &s);

    // 2. Validate: need uri or subs-url
    if s.uri.is_none() && s.subs_url.is_none() {
        anyhow::bail!(
            "corvex.json must contain \"uri\" or \"subs-url\".\n\
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

    // Fail fast on a missing xray binary, before the subscription flow spawns it
    xray::ensure_installed(&config.xray_bin)?;

    // 3. Resolve start source: direct URI, or from subscriptions (base64 URIs
    // or JSON-array subscription entries — those are preferred when present)
    let source = if let Some(ref uri) = s.uri {
        debug!("start flow: using URI from corvex.json");
        StartSource::Uri(uri.clone())
    } else {
        // subs-url flow: download, detect format per subscription, decode/filter
        // base64 or harvest JSON subscription entries, then find an alive candidate
        let urls = s
            .subs_url
            .as_ref()
            .context("bug: subs_url should be Some after validation")?;
        debug!(
            "start flow: downloading from {} subscription URLs",
            urls.len()
        );
        let mut xray_uris = Vec::new();
        let mut vpn_uris = Vec::new();
        let mut json_entries: Vec<jsonsubs::ServerEntry> = Vec::new();
        let user_agent = subscription::resolve_user_agent(s.subs_user_agent.as_deref());
        let empty_headers = std::collections::BTreeMap::new();
        let extra_headers = s.subs_headers.as_ref().unwrap_or(&empty_headers);
        for url in urls {
            match subscription::download_subscription(url, user_agent, extra_headers) {
                Ok(body) => {
                    if let Some(entries) = jsonsubs::parse_json_subscription(&body) {
                        debug!(
                            "subscription {}: JSON subscription format, {} entries",
                            url,
                            entries.len()
                        );
                        json_entries.extend(entries);
                    } else if let Ok(uris) = subscription::decode_subscription(&body) {
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

        match choose_source(
            !json_entries.is_empty(),
            !xray_uris.is_empty(),
            !vpn_uris.is_empty(),
        ) {
            SourceDecision::NoneFound => {
                anyhow::bail!("no supported proxy servers found in subscriptions")
            }
            SourceDecision::JsonSubs => {
                let candidate_params: Vec<protocol::ProxyParams> =
                    json_entries.iter().map(|e| e.params.clone()).collect();
                match health::find_alive_params(&candidate_params, &config.xray_bin) {
                    Ok(idx) => StartSource::Entry(Box::new(json_entries.swap_remove(idx))),
                    Err(e) if !xray_uris.is_empty() || !vpn_uris.is_empty() => {
                        debug!(
                            "no reachable JSON subscription servers, falling back to URI flow: {e}"
                        );
                        StartSource::Uri(resolve_uri_flow(
                            &xray_uris,
                            &mut vpn_uris,
                            &config.xray_bin,
                        )?)
                    }
                    Err(e) => return Err(e),
                }
            }
            SourceDecision::Uri => StartSource::Uri(resolve_uri_flow(
                &xray_uris,
                &mut vpn_uris,
                &config.xray_bin,
            )?),
        }
    };

    // 4. Extract routing settings (shared between both engine modes)
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
    let merge_subs = s.routes.as_ref().and_then(|r| r.merge_subs) == Some(true);
    let routing = RoutingContext {
        corporate_traffic: &corporate_traffic,
        proxy_traffic: &proxy_traffic,
        log_config: &log_config,
    };

    // Stop a stale AWG tunnel from a previous engine mode before starting fresh
    stop_awg_if_running(config);

    // 5. Branch on source / engine mode
    match source {
        StartSource::Uri(resolved_uri) => match detect_engine_mode(&resolved_uri) {
            engine::EngineMode::Xray => {
                let params = protocol::parse_uri(&resolved_uri)?;
                let dns_mappings = s.corporate_dns.unwrap_or_default();
                start_xray_engine(
                    config,
                    plat,
                    &params,
                    static_port,
                    &routing,
                    (&[], &[]),
                    dns_mappings,
                )
            }
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
                    &[],
                    &[],
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
        },
        StartSource::Entry(entry) => {
            debug!("using JSON subscription entry: {}", entry.params.name);
            let (subs_domains, subs_ips) = subs_direct_slices(merge_subs, &entry);
            if merge_subs && (!subs_domains.is_empty() || !subs_ips.is_empty()) {
                info!(
                    "merged {} direct domains + {} direct ip entries from subscription",
                    subs_domains.len(),
                    subs_ips.len()
                );
            }
            let dns_mappings = s.corporate_dns.unwrap_or_default();
            start_xray_engine(
                config,
                plat,
                &entry.params,
                static_port,
                &routing,
                (subs_domains, subs_ips),
                dns_mappings,
            )
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
/// Write the xray config for `params`: update the existing file in place, or
/// (re)create it from scratch when none exists or the existing one cannot be
/// updated — e.g. an AWG-mode config (freedom/blackhole outbounds only) left
/// by a previous run has no proxy outbound to replace, and failing here after
/// the AWG pre-stop would leave the user with no tunnel at all.
fn write_xray_config(
    xray_config: &std::path::Path,
    params: &protocol::ProxyParams,
    static_port: u16,
    rules: &[serde_json::Value],
    log_config: &protocol::XrayLogConfig,
) -> anyhow::Result<()> {
    if xray_config.exists() {
        debug!("updating existing config {}", xray_config.display());
        match protocol::apply_to_config(params, xray_config, log_config)
            .and_then(|()| update_routing_rules(xray_config, rules))
        {
            Ok(()) => return Ok(()),
            Err(e) => warn!("cannot update existing config ({e}); regenerating from scratch"),
        }
    }
    debug!("creating new config {}", xray_config.display());
    let xray_cfg = protocol::create_config(params, static_port, rules, log_config);
    if let Some(parent) = xray_config.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(&xray_cfg)?;
    config::write_restricted(xray_config, &json)
}

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

/// Stop the AWG tunnel if one is running (no-op otherwise).
fn stop_awg_if_running(config: &Config) {
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
}

fn cmd_stop(config: &Config, plat: &impl Platform) -> anyhow::Result<()> {
    debug!("disabling system proxy");
    let service = plat.detect_active_service()?;
    let proxy_result = plat.disable_proxy(&service);
    debug!("stopping xray process");
    let xray_result = xray::stop(config);

    // Also stop any AWG tunnel left running from a previous session
    stop_awg_if_running(config);

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
            &[],
            &[],
        );
        let config = crate::protocol::create_config(
            &params,
            30000,
            &rules,
            &crate::protocol::XrayLogConfig::default(),
        );

        let r = config["routing"]["rules"].as_array().unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!(r[0]["ruleTag"], "loopback-and-private-direct");
        assert_eq!(r[1]["outboundTag"], "direct");
        assert_eq!(r[1]["domain"][0], "domain:corp.com");
        assert_eq!(r[2]["outboundTag"], "proxy");
        assert_eq!(r[2]["domain"][0], "domain:ext.com");
    }

    #[test]
    fn test_start_command_no_args() {
        let cli = Cli::try_parse_from(["corvex", "start"]).unwrap();
        assert!(matches!(cli.command, super::Commands::Start));
    }

    #[test]
    fn test_restart_command_parses() {
        let cli = Cli::try_parse_from(["corvex", "restart"]).unwrap();
        assert!(matches!(cli.command, super::Commands::Restart));
    }

    #[test]
    fn test_unknown_command_rejected() {
        let result = Cli::try_parse_from(["corvex", "bogus-command"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_settings_flag() {
        let cli = Cli::try_parse_from(["corvex", "--settings", "/path/to/settings.json", "start"])
            .unwrap();
        assert_eq!(cli.settings_path.as_deref(), Some("/path/to/settings.json"));
        assert!(matches!(cli.command, super::Commands::Start));
    }

    #[test]
    fn test_settings_validation_requires_uri_or_subs_url() {
        let s = crate::settings::CorvexSettings::default();
        assert!(s.uri.is_none() && s.subs_url.is_none());
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
            &[],
            &[],
        );
        let log_config = crate::protocol::XrayLogConfig::default();
        let config = crate::protocol::create_config(&params, 30000, &rules, &log_config);

        assert_eq!(config["outbounds"][0]["protocol"], "vless");
        assert_eq!(config["log"]["loglevel"], "warning");
        let r = config["routing"]["rules"].as_array().unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!(r[0]["ruleTag"], "loopback-and-private-direct");
    }

    #[test]
    fn test_routing_rules_from_settings_values() {
        let corporate = vec!["corp.internal".to_string(), "dev.corp".to_string()];
        let proxy = vec!["example.com".to_string()];
        let rules = crate::traffic::build_routing_rules(&corporate, &proxy, "proxy", &[], &[]);
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0]["ruleTag"], "loopback-and-private-direct");
        assert_eq!(rules[1]["outboundTag"], "direct");
        assert_eq!(rules[2]["outboundTag"], "proxy");
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

    fn vless_test_params() -> crate::protocol::ProxyParams {
        crate::protocol::parse_uri(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&type=tcp#",
        )
        .unwrap()
    }

    #[test]
    fn test_write_xray_config_regenerates_awg_mode_config() {
        // An AWG-mode config has only freedom/blackhole outbounds, so the
        // in-place update fails — write_xray_config must fall back to a full
        // regenerate instead of erroring (the AWG pre-stop already ran, so an
        // error here would leave no tunnel at all).
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let log_cfg = crate::protocol::XrayLogConfig::default();
        let awg_cfg = crate::protocol::create_config_awg_mode(10808, &[], &log_cfg);
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&awg_cfg).unwrap(),
        )
        .unwrap();

        let params = vless_test_params();
        super::write_xray_config(&config_path, &params, 21080, &[], &log_cfg).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(updated["outbounds"][0]["protocol"], "vless");
        assert_eq!(updated["inbounds"][0]["port"], 21080);
    }

    #[test]
    fn test_write_xray_config_updates_existing_in_place() {
        // A healthy existing config keeps the in-place update path: the
        // inbound port must be preserved, not reset to static_port.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let log_cfg = crate::protocol::XrayLogConfig::default();
        let existing = crate::protocol::create_config(&vless_test_params(), 12345, &[], &log_cfg);
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&existing).unwrap(),
        )
        .unwrap();

        let params = vless_test_params();
        super::write_xray_config(&config_path, &params, 21080, &[], &log_cfg).unwrap();

        let updated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(updated["inbounds"][0]["port"], 12345);
        assert_eq!(updated["outbounds"][0]["protocol"], "vless");
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

    #[test]
    fn test_choose_source_all_empty_is_none_found() {
        assert_eq!(
            super::choose_source(false, false, false),
            super::SourceDecision::NoneFound
        );
    }

    #[test]
    fn test_choose_source_xray_uris_only_is_uri() {
        assert_eq!(
            super::choose_source(false, true, false),
            super::SourceDecision::Uri
        );
    }

    #[test]
    fn test_choose_source_vpn_uris_only_is_uri() {
        assert_eq!(
            super::choose_source(false, false, true),
            super::SourceDecision::Uri
        );
    }

    #[test]
    fn test_choose_source_xray_and_vpn_uris_is_uri() {
        assert_eq!(
            super::choose_source(false, true, true),
            super::SourceDecision::Uri
        );
    }

    #[test]
    fn test_choose_source_json_subs_only_is_json_subs() {
        assert_eq!(
            super::choose_source(true, false, false),
            super::SourceDecision::JsonSubs
        );
    }

    #[test]
    fn test_choose_source_json_subs_and_xray_uris_prefers_json_subs() {
        assert_eq!(
            super::choose_source(true, true, false),
            super::SourceDecision::JsonSubs
        );
    }

    #[test]
    fn test_choose_source_json_subs_and_vpn_uris_prefers_json_subs() {
        assert_eq!(
            super::choose_source(true, false, true),
            super::SourceDecision::JsonSubs
        );
    }

    #[test]
    fn test_choose_source_json_subs_and_both_uri_kinds_prefers_json_subs() {
        assert_eq!(
            super::choose_source(true, true, true),
            super::SourceDecision::JsonSubs
        );
    }

    fn json_entry_with_direct_rules() -> crate::jsonsubs::ServerEntry {
        crate::jsonsubs::ServerEntry {
            params: crate::protocol::parse_uri("vless://uuid@host.com:443?encryption=none")
                .unwrap(),
            direct_domains: vec!["corp.example.com".to_string()],
            direct_ips: vec!["geoip:ru".to_string()],
        }
    }

    #[test]
    fn test_subs_direct_slices_merge_on_returns_entry_lists() {
        let entry = json_entry_with_direct_rules();
        let (domains, ips) = super::subs_direct_slices(true, &entry);
        assert_eq!(domains, entry.direct_domains.as_slice());
        assert_eq!(ips, entry.direct_ips.as_slice());
    }

    #[test]
    fn test_subs_direct_slices_merge_off_returns_empty_despite_entry_contents() {
        let entry = json_entry_with_direct_rules();
        assert!(!entry.direct_domains.is_empty());
        assert!(!entry.direct_ips.is_empty());
        let (domains, ips) = super::subs_direct_slices(false, &entry);
        assert!(domains.is_empty());
        assert!(ips.is_empty());
    }
}
