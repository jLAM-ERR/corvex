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
#[command(
    name = "corvex",
    version,
    about = "Manage Xray VPN proxy and system proxy"
)]
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
    /// Stop xray, then disable system proxy
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

/// Current OS user name, used to decide `kill` vs `sudo kill` in orphan
/// advice. `ps` reports user names, so names are the right comparison axis;
/// `nix::unistd::getuid` sits behind the `user` feature, which is not enabled.
fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_default()
}

/// Translate an error from the pre-start `xray::stop` or from `xray::start`
/// into a user-facing diagnostic, or `None` to let the error propagate
/// unchanged. Kept pure (no IO, no process listing) so the *routing* - which
/// error becomes which message, and where the owner lookup comes from - is
/// itself tested, not just the message builders it calls into.
fn start_error_message(
    err: &anyhow::Error,
    all: &[xray::XrayProcess],
    tracked: Option<i32>,
    port: u16,
    config_path: &str,
    log_path: &std::path::Path,
) -> Option<String> {
    match err.downcast_ref::<xray::XrayError>() {
        Some(xray::XrayError::NotPermitted(pid)) => {
            // Look the owner up in the *full* process list, not the managed
            // subset: under the sudo/HOME blind spot the tracked PID can
            // classify as "other xray", which is exactly this case.
            let owner = all.iter().find(|p| p.pid == *pid).map(|p| p.user.as_str());
            let orphans = xray::orphans(all, config_path, tracked);
            Some(xray::start_blocked_message(*pid, owner, &orphans))
        }
        Some(xray::XrayError::StartFailed) => Some(xray::start_failure_diagnostics(
            all,
            port,
            config_path,
            log_path,
        )),
        _ => None,
    }
}

/// Main algorithm: ensure xray installed, write port to config, start, enable proxy.
fn main_algorithm(config: &Config, plat: &impl Platform, port: u16) -> anyhow::Result<()> {
    debug!("ensuring xray is installed");
    xray::ensure_installed(&config.xray_bin)?;

    let config_path = config.xray_config.to_string_lossy().to_string();

    // Stop any running instance before starting a new one
    if let Some(tracked_pid) = xray::is_running(config) {
        debug!("stopping existing xray instance");
        if let Err(e) = xray::stop(config) {
            let all = xray::list_xray_processes(&config.xray_bin);
            if let Some(msg) = start_error_message(
                &e,
                &all,
                Some(tracked_pid),
                port,
                &config_path,
                &config.xray_log,
            ) {
                anyhow::bail!(msg);
            }
            return Err(e);
        }
    }

    // Write port into xray config.json inbound section
    debug!("writing port {} to config", port);
    update_config_port(&config.xray_config, port)?;

    let pid = match xray::start(config) {
        Ok(pid) => pid,
        Err(e) => {
            let all = xray::list_xray_processes(&config.xray_bin);
            if let Some(msg) =
                start_error_message(&e, &all, None, port, &config_path, &config.xray_log)
            {
                anyhow::bail!(msg);
            }
            return Err(e);
        }
    };
    debug!("xray process started with PID {}", pid);
    println!("{}", format!("xray started (PID: {pid})").green());

    // Non-fatal: report any untracked corvex-managed xray processes still on
    // the system. corvex never signals them - reporting only.
    let all = xray::list_xray_processes(&config.xray_bin);
    let orphans = xray::orphans(&all, &config_path, Some(pid));
    for line in xray::orphan_lines(&orphans, &current_user()) {
        println!("{}", line.yellow());
    }

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
        // No conf file means there is no tunnel we could stop (`awg-quick
        // down` needs the file), so skip the `awg show` probe entirely.
        if !awg_conf_path.exists() {
            return;
        }
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

/// Lines printed once `stop` has actually stopped xray: a plain success line
/// when no managed process survives, or a qualifying line plus the recovery
/// advice for each survivor. `stop` is exactly where the new hints send
/// users, so it must not claim a clean stop while a corvex-managed xray is
/// still running. Reuses `xray::orphan_lines` for the recovery commands
/// rather than duplicating that text.
fn stop_outcome_lines(survivors: &[xray::XrayProcess], current_user: &str) -> Vec<String> {
    if survivors.is_empty() {
        return vec!["corvex stopped!".to_string()];
    }
    let mut lines = vec![
        "corvex stopped, but other corvex-managed xray process(es) are still running:".to_string(),
    ];
    lines.extend(xray::orphan_lines(survivors, current_user));
    lines
}

fn cmd_stop(config: &Config, plat: &impl Platform) -> anyhow::Result<()> {
    cmd_stop_inner(config, plat, &mut std::io::stdout())
}

/// Takes the output writer as a parameter (defaulting to stdout via
/// `cmd_stop`) so the qualified-vs-clean success message - not just
/// `cmd_stop`'s side effects - can be asserted directly in tests.
fn cmd_stop_inner<W: std::io::Write>(
    config: &Config,
    plat: &impl Platform,
    out: &mut W,
) -> anyhow::Result<()> {
    // Resolve the network service first: detection is read-only, so a
    // detection failure aborts before anything is touched. Then stop xray;
    // if that fails for any reason (not running, owned by another user, ...),
    // the system proxy and the AWG tunnel likewise stay untouched, so a
    // failed stop never half-tears-down a working setup.
    let service = plat.detect_active_service()?;

    debug!("stopping xray");
    xray::stop(config)?;

    // The tracked process is gone (xray::stop just removed the PID file), so
    // any managed process still in `ps` is an orphan `stop` cannot reach -
    // report it instead of claiming a clean stop.
    let config_path = config.xray_config.to_string_lossy().to_string();
    let survivors = xray::orphans(
        &xray::list_xray_processes(&config.xray_bin),
        &config_path,
        None,
    );

    debug!("disabling system proxy");
    plat.disable_proxy(&service)?;

    // Also stop any AWG tunnel left running from a previous session
    stop_awg_if_running(config);

    let lines = stop_outcome_lines(&survivors, &current_user());
    if survivors.is_empty() {
        writeln!(out, "{}", lines[0].green())?;
    } else {
        for line in &lines {
            writeln!(out, "{}", line.yellow())?;
        }
    }
    Ok(())
}

fn cmd_reload(config: &Config) -> anyhow::Result<()> {
    debug!("validating config before reload");
    println!("{}", "Validating config...".yellow());
    xray::reload(config)?;
    println!("{}", "Config reloaded (SIGHUP sent)".green());
    Ok(())
}

/// Orphan lines only - the tracked-process line printed by `cmd_status`
/// itself is not re-rendered here, so an empty return means nothing changes
/// versus today's output. Managed processes only: `ps` cannot show what port
/// another process listens on, so "other xray" reporting stays in
/// `start_failure_diagnostics`, where the port is already named.
fn status_process_lines(
    tracked: Option<i32>,
    all: &[xray::XrayProcess],
    config_path: &str,
    current_user: &str,
) -> Vec<String> {
    let orphans = xray::orphans(all, config_path, tracked);
    xray::orphan_lines(&orphans, current_user)
}

fn cmd_status(config: &Config, plat: &impl Platform) -> anyhow::Result<()> {
    cmd_status_inner(config, plat, &mut std::io::stdout())
}

/// Takes the output writer as a parameter (defaulting to stdout via
/// `cmd_status`) so the wiring of `status_process_lines` - not just its own
/// content - can be asserted directly in tests: that it is called exactly
/// once, and that its lines land after the tracked-process line rather than
/// duplicating or replacing it.
fn cmd_status_inner<W: std::io::Write>(
    config: &Config,
    plat: &impl Platform,
    out: &mut W,
) -> anyhow::Result<()> {
    debug!("checking status");
    let service = plat.detect_active_service()?;
    writeln!(out, "Network service: {}", service.yellow())?;

    // Config paths
    writeln!(out, "Settings: {}", config.corvex_settings.display())?;
    writeln!(out, "Xray config: {}", config.xray_config.display())?;
    writeln!(out, "Xray log: {}", config.xray_log.display())?;

    // Engine type and AWG status
    if let Ok(awg_conf_path) = config.awg_conf_path() {
        let awg_iface = engine::awg::conf_interface_name(&awg_conf_path);
        if engine::awg::is_tunnel_running(&awg_iface) {
            writeln!(out, "Engine: {}", "AWG + xray".green())?;
            writeln!(out, "AWG tunnel: {} ({})", "running".green(), awg_iface)?;
        } else {
            writeln!(out, "Engine: {}", "xray".green())?;
        }
    } else {
        writeln!(out, "Engine: {}", "xray".green())?;
    }

    // Xray process
    let tracked_pid = xray::is_running(config);
    match tracked_pid {
        Some(pid) => writeln!(out, "xray: {} (PID: {})", "started".green(), pid)?,
        None => writeln!(out, "xray: {}", "stopped".red())?,
    }
    let config_path = config.xray_config.to_string_lossy().to_string();
    let all_processes = xray::list_xray_processes(&config.xray_bin);
    for line in status_process_lines(tracked_pid, &all_processes, &config_path, &current_user()) {
        writeln!(out, "{}", line.yellow())?;
    }

    // Proxy status from networksetup
    match plat.proxy_status(&service) {
        Ok(status) => {
            write_proxy_status(out, "socks", &status.socks)?;
            write_proxy_status(out, "http", &status.http)?;
            write_proxy_status(out, "https", &status.https)?;
        }
        Err(e) => writeln!(out, "{}", format!("Failed to query proxy: {e}").red())?,
    }

    // Last 5 log lines
    if config.xray_log.exists() {
        writeln!(out)?;
        let _ = Command::new("tail")
            .args(["-5"])
            .arg(&config.xray_log)
            .status();
    }

    Ok(())
}

fn write_proxy_status<W: std::io::Write>(
    out: &mut W,
    label: &str,
    info: &platform::ProxyInfo,
) -> std::io::Result<()> {
    if info.enabled {
        writeln!(out, "{}: {}:{}", label, info.server, info.port)
    } else {
        writeln!(out, "{}: {}", label, "off".red())
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
    use crate::platform::{Platform, ProxyInfo, ProxyStatus};
    use clap::Parser;
    use std::cell::RefCell;

    /// Test double for `Platform` that records every method call and can be
    /// configured to fail `detect_active_service` or `disable_proxy`. Lets
    /// tests assert whether/when/in what order `cmd_stop` touched the system
    /// proxy without any real system calls. When `pid_file_must_be_gone` is
    /// set, the mutating proxy calls also assert that the xray PID file no
    /// longer exists — pinning "proxy is only touched after xray fully
    /// stopped" (read-only `detect_active_service` runs before the stop).
    #[derive(Default)]
    struct RecordingPlatform {
        calls: RefCell<Vec<String>>,
        fail_detect_active_service: bool,
        fail_disable_proxy: bool,
        pid_file_must_be_gone: Option<std::path::PathBuf>,
    }

    impl RecordingPlatform {
        fn record(&self, method: &str) {
            self.calls.borrow_mut().push(method.to_string());
        }

        fn assert_pid_file_gone(&self, method: &str) {
            if let Some(pid_file) = &self.pid_file_must_be_gone {
                assert!(
                    !pid_file.exists(),
                    "{method} called while the xray PID file still exists"
                );
            }
        }
    }

    impl Platform for RecordingPlatform {
        fn detect_active_service(&self) -> anyhow::Result<String> {
            self.record("detect_active_service");
            if self.fail_detect_active_service {
                anyhow::bail!("detect_active_service failed (test)");
            }
            Ok("Wi-Fi".to_string())
        }

        fn enable_proxy(&self, _service: &str, _host: &str, _port: u16) -> anyhow::Result<()> {
            self.record("enable_proxy");
            self.assert_pid_file_gone("enable_proxy");
            Ok(())
        }

        fn disable_proxy(&self, _service: &str) -> anyhow::Result<()> {
            self.record("disable_proxy");
            self.assert_pid_file_gone("disable_proxy");
            if self.fail_disable_proxy {
                anyhow::bail!("disable_proxy failed (test)");
            }
            Ok(())
        }

        fn proxy_status(&self, _service: &str) -> anyhow::Result<ProxyStatus> {
            self.record("proxy_status");
            let off = || ProxyInfo {
                enabled: false,
                server: String::new(),
                port: String::new(),
            };
            Ok(ProxyStatus {
                socks: off(),
                http: off(),
                https: off(),
            })
        }

        fn discover_corporate_dns(
            &self,
        ) -> anyhow::Result<std::collections::BTreeMap<String, String>> {
            self.record("discover_corporate_dns");
            Ok(std::collections::BTreeMap::new())
        }
    }

    /// Config rooted in a temp dir so tests never touch real state.
    fn temp_config(base: &std::path::Path, xray_bin: &str) -> crate::config::Config {
        crate::config::Config {
            xray_bin: xray_bin.to_string(),
            xray_config: base.join("xray/config.json"),
            xray_log: base.join("logs/xray.log"),
            xray_pid_file: base.join("xray/xray.pid"),
            corvex_settings: base.join("corvex/corvex.json"),
            corvex_log: base.join("state/corvex/corvex.log"),
        }
    }

    /// Spawn a `/bin/sleep` child standing in for a running xray process,
    /// write its PID to the config's PID file (config uses `xray_bin =
    /// "sleep"` so the PID-reuse guard in `xray::is_running` accepts it), and
    /// reap it on a background thread. The reaper matters: without it the
    /// SIGTERM'd child lingers as a zombie, a zombie still answers
    /// `kill(pid, 0)` as alive (see test_process_dead_after_exit in xray.rs),
    /// and `xray::stop` would burn its full 2s wait loop and take the SIGKILL
    /// fallback instead of the graceful-termination branch these tests are
    /// meant to cover. Join the returned handle after `cmd_stop` returns.
    #[cfg(unix)]
    fn spawn_fake_xray(config: &crate::config::Config) -> std::thread::JoinHandle<()> {
        std::fs::create_dir_all(config.xray_pid_file.parent().unwrap()).unwrap();
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("failed to spawn sleep");
        std::fs::write(&config.xray_pid_file, child.id().to_string()).unwrap();
        std::thread::spawn(move || {
            let _ = child.wait();
        })
    }

    // Note on coverage: the motivating NotPermitted case (xray owned by
    // another user, EPERM on SIGTERM) cannot be exercised in a unit test
    // without a root-owned process; it is covered by manual verification
    // (see the plan's Post-Completion section). Every `xray::stop` error
    // takes the same early-return path in `cmd_stop` as the NotRunning case
    // below.

    /// Regression test: a failed stop (here: xray not running) must not touch
    /// the system proxy at all — previously the proxy was disabled first.
    /// Read-only service detection runs before the stop and is allowed; the
    /// mutating `disable_proxy` must never be reached.
    #[test]
    fn test_cmd_stop_without_running_xray_never_touches_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let config = temp_config(dir.path(), "xray");
        let plat = RecordingPlatform::default();

        let err = super::cmd_stop(&config, &plat).expect_err("stop must fail with no PID file");

        assert!(err.to_string().contains("not running"));
        assert_eq!(
            *plat.calls.borrow(),
            ["detect_active_service"],
            "only read-only detection is allowed on a failed stop"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_cmd_stop_disables_proxy_after_successful_xray_stop() {
        let dir = tempfile::tempdir().unwrap();
        let config = temp_config(dir.path(), "sleep");
        let reaper = spawn_fake_xray(&config);

        // The mock asserts that the PID file is already gone when the proxy
        // is mutated, pinning the ordering on the success path too.
        let plat = RecordingPlatform {
            pid_file_must_be_gone: Some(config.xray_pid_file.clone()),
            ..Default::default()
        };
        let result = super::cmd_stop(&config, &plat);

        reaper.join().expect("failed to join reaper thread");

        result.expect("cmd_stop must succeed when xray stops cleanly");
        assert_eq!(
            *plat.calls.borrow(),
            ["detect_active_service", "disable_proxy"]
        );
        assert!(!config.xray_pid_file.exists(), "PID file must be removed");
    }

    /// Service detection runs before the stop, so a detection failure must
    /// leave everything untouched: xray keeps running, PID file preserved,
    /// proxy never mutated.
    #[test]
    #[cfg(unix)]
    fn test_cmd_stop_detect_service_error_leaves_xray_running() {
        let dir = tempfile::tempdir().unwrap();
        let config = temp_config(dir.path(), "sleep");
        std::fs::create_dir_all(config.xray_pid_file.parent().unwrap()).unwrap();
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("failed to spawn sleep");
        std::fs::write(&config.xray_pid_file, child.id().to_string()).unwrap();

        let plat = RecordingPlatform {
            fail_detect_active_service: true,
            ..Default::default()
        };
        let result = super::cmd_stop(&config, &plat);

        let err = result.expect_err("cmd_stop must propagate detect_active_service error");
        assert!(err.to_string().contains("detect_active_service failed"));
        assert_eq!(*plat.calls.borrow(), ["detect_active_service"]);
        assert!(
            config.xray_pid_file.exists(),
            "PID file must be preserved when detection fails before the stop"
        );

        child.kill().expect("failed to kill fake xray");
        let _ = child.wait();
    }

    #[test]
    #[cfg(unix)]
    fn test_cmd_stop_propagates_disable_proxy_error() {
        let dir = tempfile::tempdir().unwrap();
        let config = temp_config(dir.path(), "sleep");
        let reaper = spawn_fake_xray(&config);

        let plat = RecordingPlatform {
            fail_disable_proxy: true,
            ..Default::default()
        };
        let result = super::cmd_stop(&config, &plat);

        reaper.join().expect("failed to join reaper thread");

        let err = result.expect_err("cmd_stop must propagate disable_proxy error");
        assert!(err.to_string().contains("disable_proxy failed"));
        assert_eq!(
            *plat.calls.borrow(),
            ["detect_active_service", "disable_proxy"]
        );
    }

    /// Writes an executable `#!/bin/sh\nsleep 30\n` script at `path`. Its `ps`
    /// comm/argv0 is `/bin/sh`, so a test config with `xray_bin = "sh"`
    /// classifies it as xray without needing a real xray binary.
    #[cfg(unix)]
    fn write_fake_process_script(path: &std::path::Path) {
        std::fs::write(path, "#!/bin/sh\nsleep 30\n").unwrap();
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }

    /// RAII guard around a spawned fake-xray test process. On drop it SIGKILLs
    /// the whole process group (so a shell's descendants can't outlive the
    /// test regardless of whether the shell execs its body or forks a child -
    /// this differs across platforms) and joins the background reaper thread,
    /// so a panicking assertion between spawn and the end of the test can
    /// never leak a process. The reaper thread reaps the process the instant
    /// it exits, following the same convention as `spawn_fake_xray` above:
    /// without it a SIGTERM'd child stays a zombie (`is_process_alive` still
    /// reports a zombie as alive) until something calls `wait()`, and
    /// `xray::stop`'s liveness loop would burn its full ~2s timeout waiting
    /// for that to happen.
    #[cfg(unix)]
    struct FakeProcess {
        pid: i32,
        reaper: Option<std::thread::JoinHandle<()>>,
    }

    #[cfg(unix)]
    impl FakeProcess {
        fn spawn(cmd: &mut std::process::Command) -> Self {
            use std::os::unix::process::CommandExt;
            let mut child = cmd
                .process_group(0)
                .spawn()
                .expect("failed to spawn fake test process");
            let pid = child.id() as i32;
            let reaper = std::thread::spawn(move || {
                let _ = child.wait();
            });
            FakeProcess {
                pid,
                reaper: Some(reaper),
            }
        }
    }

    #[cfg(unix)]
    impl Drop for FakeProcess {
        fn drop(&mut self) {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(-self.pid),
                nix::sys::signal::Signal::SIGKILL,
            );
            if let Some(reaper) = self.reaper.take() {
                let _ = reaper.join();
            }
        }
    }

    // -- status_process_lines --

    #[test]
    fn test_status_process_lines_tracked_only_no_orphans_is_empty() {
        let all = vec![crate::xray::XrayProcess {
            pid: 100,
            user: "alice".to_string(),
            config_arg: "/Users/alice/.config/xray/config.json".to_string(),
        }];
        let lines = super::status_process_lines(
            Some(100),
            &all,
            "/Users/alice/.config/xray/config.json",
            "alice",
        );
        assert!(
            lines.is_empty(),
            "a lone tracked process must not be re-rendered here: {lines:?}"
        );
    }

    #[test]
    fn test_status_process_lines_tracked_plus_root_orphan_lists_sudo_kill() {
        let config_path = "/Users/alice/.config/xray/config.json";
        let all = vec![
            crate::xray::XrayProcess {
                pid: 100,
                user: "alice".to_string(),
                config_arg: config_path.to_string(),
            },
            crate::xray::XrayProcess {
                pid: 7597,
                user: "root".to_string(),
                config_arg: config_path.to_string(),
            },
        ];
        let lines = super::status_process_lines(Some(100), &all, config_path, "alice");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("sudo kill 7597"));
    }

    #[test]
    fn test_status_process_lines_orphan_with_no_tracked_pid() {
        let config_path = "/Users/alice/.config/xray/config.json";
        let all = vec![crate::xray::XrayProcess {
            pid: 7597,
            user: "root".to_string(),
            config_arg: config_path.to_string(),
        }];
        let lines = super::status_process_lines(None, &all, config_path, "alice");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("sudo kill 7597"));
    }

    #[test]
    fn test_status_process_lines_no_processes_is_empty() {
        let lines = super::status_process_lines(
            None,
            &[],
            "/Users/alice/.config/xray/config.json",
            "alice",
        );
        assert!(lines.is_empty());
    }

    #[test]
    fn test_status_process_lines_never_lists_other_config_xray() {
        let all = vec![crate::xray::XrayProcess {
            pid: 999,
            user: "bob".to_string(),
            config_arg: "/opt/homebrew/etc/xray/config.json".to_string(),
        }];
        let lines = super::status_process_lines(
            None,
            &all,
            "/Users/alice/.config/xray/config.json",
            "alice",
        );
        assert!(
            lines.is_empty(),
            "an xray running against a different config must never be listed by status: {lines:?}"
        );
    }

    // -- cmd_status wiring: pure status_process_lines tests above cover
    // *content*; these cover that `cmd_status_inner` actually calls it once,
    // in the right place - a pure-function test alone would still pass if
    // the helper were never called, called twice, or called somewhere that
    // duplicates the tracked line.

    #[test]
    #[cfg(unix)]
    fn test_cmd_status_inner_healthy_output_has_single_tracked_line() {
        let dir = tempfile::tempdir().unwrap();
        let config = temp_config(dir.path(), "sh");
        std::fs::create_dir_all(config.xray_pid_file.parent().unwrap()).unwrap();

        let tracked_script = dir.path().join("tracked.sh");
        write_fake_process_script(&tracked_script);
        let tracked = FakeProcess::spawn(&mut std::process::Command::new(&tracked_script));
        std::fs::write(&config.xray_pid_file, tracked.pid.to_string()).unwrap();

        let plat = RecordingPlatform::default();
        let mut buf: Vec<u8> = Vec::new();
        let result = super::cmd_status_inner(&config, &plat, &mut buf);

        result.expect("cmd_status must succeed");
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(
            output.matches("xray: started (PID:").count(),
            1,
            "the tracked line must appear exactly once: {output}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_cmd_status_inner_orphan_line_appears_after_tracked_line() {
        let dir = tempfile::tempdir().unwrap();
        let config = temp_config(dir.path(), "sh");
        std::fs::create_dir_all(config.xray_pid_file.parent().unwrap()).unwrap();

        let scripts_dir = dir.path().join("scripts");
        std::fs::create_dir_all(&scripts_dir).unwrap();

        let tracked_script = scripts_dir.join("tracked.sh");
        write_fake_process_script(&tracked_script);
        let tracked = FakeProcess::spawn(&mut std::process::Command::new(&tracked_script));
        std::fs::write(&config.xray_pid_file, tracked.pid.to_string()).unwrap();

        let config_path = config.xray_config.to_string_lossy().to_string();
        let orphan_script = scripts_dir.join("orphan.sh");
        write_fake_process_script(&orphan_script);
        let mut orphan_cmd = std::process::Command::new(&orphan_script);
        orphan_cmd.args(["run", "-c", &config_path]);
        let orphan = FakeProcess::spawn(&mut orphan_cmd);

        let plat = RecordingPlatform::default();
        let mut buf: Vec<u8> = Vec::new();
        let result = super::cmd_status_inner(&config, &plat, &mut buf);

        result.expect("cmd_status must succeed");
        let output = String::from_utf8(buf).unwrap();
        let tracked_at = output
            .find("xray: started (PID:")
            .expect("tracked line must be present");
        let orphan_at = output
            .find(&format!("kill {}", orphan.pid))
            .expect("orphan recovery line must be present");
        assert!(
            orphan_at > tracked_at,
            "orphan line must appear after the tracked line: {output}"
        );
    }

    // -- stop_outcome_lines / cmd_stop qualified success --

    #[test]
    fn test_stop_outcome_lines_no_survivors_is_plain_success() {
        let lines = super::stop_outcome_lines(&[], "alice");
        assert_eq!(lines, vec!["corvex stopped!".to_string()]);
    }

    #[test]
    fn test_stop_outcome_lines_survivor_qualifies_and_reuses_orphan_lines() {
        let survivors = vec![crate::xray::XrayProcess {
            pid: 7597,
            user: "root".to_string(),
            config_arg: "/Users/alice/.config/xray/config.json".to_string(),
        }];
        let lines = super::stop_outcome_lines(&survivors, "alice");
        assert_eq!(lines.len(), 2);
        assert_ne!(lines[0], "corvex stopped!", "must not claim a clean stop");
        assert!(lines[1].contains("sudo kill 7597"));
    }

    #[test]
    #[cfg(unix)]
    fn test_cmd_stop_qualifies_success_when_managed_process_survives() {
        let dir = tempfile::tempdir().unwrap();
        let config = temp_config(dir.path(), "sh");
        std::fs::create_dir_all(config.xray_pid_file.parent().unwrap()).unwrap();

        let scripts_dir = dir.path().join("scripts");
        std::fs::create_dir_all(&scripts_dir).unwrap();

        // Tracked process: `xray::stop` signals this one, and its process
        // group is force-killed (harmless if already gone) when `tracked`
        // drops at the end of this function, panic or not.
        let tracked_script = scripts_dir.join("tracked.sh");
        write_fake_process_script(&tracked_script);
        let tracked = FakeProcess::spawn(&mut std::process::Command::new(&tracked_script));
        std::fs::write(&config.xray_pid_file, tracked.pid.to_string()).unwrap();

        // Orphan: same config path, but never written to xray.pid, so `stop`
        // cannot reach it and must report it as a survivor instead.
        let config_path = config.xray_config.to_string_lossy().to_string();
        let orphan_script = scripts_dir.join("orphan.sh");
        write_fake_process_script(&orphan_script);
        let mut orphan_cmd = std::process::Command::new(&orphan_script);
        orphan_cmd.args(["run", "-c", &config_path]);
        let orphan = FakeProcess::spawn(&mut orphan_cmd);

        let plat = RecordingPlatform::default();
        let mut buf: Vec<u8> = Vec::new();
        let result = super::cmd_stop_inner(&config, &plat, &mut buf);

        result.expect("cmd_stop must still succeed when a survivor remains");
        let output = String::from_utf8(buf).unwrap();
        // The test process itself owns the orphan, so the advice is bare
        // `kill`, not `sudo kill` (that only applies to another user's PID).
        assert!(
            output.contains(&format!("kill {}", orphan.pid)),
            "qualified message must carry the survivor's recovery command: {output}"
        );
        assert!(
            !output.contains("corvex stopped!"),
            "must not claim a clean stop while a survivor remains: {output}"
        );
        assert_eq!(
            *plat.calls.borrow(),
            ["detect_active_service", "disable_proxy"]
        );
        // `tracked` and `orphan` drop here: their `Drop` impls SIGKILL each
        // process group and join the reaper threads unconditionally.
    }

    #[test]
    #[cfg(unix)]
    fn test_cmd_stop_clean_path_prints_unqualified_success() {
        let dir = tempfile::tempdir().unwrap();
        let config = temp_config(dir.path(), "sleep");
        let reaper = spawn_fake_xray(&config);

        let plat = RecordingPlatform::default();
        let mut buf: Vec<u8> = Vec::new();
        let result = super::cmd_stop_inner(&config, &plat, &mut buf);

        reaper.join().expect("failed to join reaper thread");

        result.expect("cmd_stop must succeed when xray stops cleanly");
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("corvex stopped!"));
        assert!(!output.contains("sudo kill"));
    }

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

    // -- start_error_message --

    #[test]
    fn test_start_error_message_not_permitted_names_pid_and_owner() {
        // Owner name deliberately avoids "root": ROOT_XRAY_ON_START_HINT's own
        // text contains "root-owned", so asserting on that substring would
        // pass even if the owner lookup were broken.
        let err: anyhow::Error = crate::xray::XrayError::NotPermitted(5556).into();
        let all = vec![crate::xray::XrayProcess {
            pid: 5556,
            user: "carol".to_string(),
            config_arg: "/Users/alice/.config/xray/config.json".to_string(),
        }];
        let msg = super::start_error_message(
            &err,
            &all,
            Some(5556),
            21080,
            "/Users/alice/.config/xray/config.json",
            std::path::Path::new("/Users/alice/.local/state/xray/xray.log"),
        )
        .expect("NotPermitted must produce a message");
        assert!(msg.contains("5556"));
        assert!(msg.contains("'carol'"));
    }

    /// Regression guard: the owner must be looked up in the *full* process
    /// list, not `managed_processes`. Here the tracked PID's `config_arg`
    /// does NOT match `config_path` - the documented sudo/HOME blind spot,
    /// where a root-launched xray's PID file lives under a different HOME and
    /// so the tracked PID classifies as "other xray" rather than managed.
    /// The owner must still be reported; a `managed_processes`-based lookup
    /// would filter this process out first and render the owner unknown.
    /// Owner name is "carol", not "root": the hint text itself contains
    /// "root-owned", which would make a `.contains("root")` assertion pass
    /// even with a broken (managed-subset) owner lookup.
    #[test]
    fn test_start_error_message_not_permitted_owner_from_full_list_not_managed_subset() {
        let err: anyhow::Error = crate::xray::XrayError::NotPermitted(5556).into();
        let all = vec![crate::xray::XrayProcess {
            pid: 5556,
            user: "carol".to_string(),
            config_arg: "/root/.config/xray/config.json".to_string(),
        }];
        let msg = super::start_error_message(
            &err,
            &all,
            Some(5556),
            21080,
            "/Users/alice/.config/xray/config.json",
            std::path::Path::new("/Users/alice/.local/state/xray/xray.log"),
        )
        .expect("NotPermitted must produce a message");
        assert!(
            msg.contains("'carol'"),
            "owner must be resolved from the full process list even when config_arg mismatches"
        );
    }

    #[test]
    fn test_start_error_message_start_failed_names_port_and_log_path() {
        let err: anyhow::Error = crate::xray::XrayError::StartFailed.into();
        let msg = super::start_error_message(
            &err,
            &[],
            None,
            21080,
            "/Users/alice/.config/xray/config.json",
            std::path::Path::new("/Users/alice/.local/state/xray/xray.log"),
        )
        .expect("StartFailed must produce a message");
        assert!(msg.contains("21080"));
        assert!(msg.contains("xray.log"));
    }

    #[test]
    fn test_start_error_message_unrelated_error_returns_none() {
        let not_running: anyhow::Error = crate::xray::XrayError::NotRunning.into();
        assert!(super::start_error_message(
            &not_running,
            &[],
            None,
            21080,
            "/Users/alice/.config/xray/config.json",
            std::path::Path::new("/Users/alice/.local/state/xray/xray.log"),
        )
        .is_none());

        let plain = anyhow::anyhow!("boom");
        assert!(super::start_error_message(
            &plain,
            &[],
            None,
            21080,
            "/Users/alice/.config/xray/config.json",
            std::path::Path::new("/Users/alice/.local/state/xray/xray.log"),
        )
        .is_none());
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
        let base = crate::config::state_dir().join("xray");
        assert_eq!(log_config.access, base.join("access.log").to_string_lossy());
        assert_eq!(log_config.error, base.join("error.log").to_string_lossy());
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
        let config = temp_config(base, "xray");
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
        let config = temp_config(base, "xray");
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
        let config = temp_config(base, "xray");
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
