mod config;
mod dns;
mod engine;
mod health;
mod jsonsubs;
mod netdiag;
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
use log::{debug, error, info, warn};
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
    /// Diagnose system DNS resolvers and their network path
    Dns,
    /// Show xray log
    Logs {
        /// Follow log output (like tail -f)
        #[arg(short, long)]
        follow: bool,
    },
}

/// Fans every log record to stderr and to `corvex.log`.
///
/// The file sink is optional and self-disabling: the first write error drops it
/// for the rest of the process and is reported once on stderr, so a full or
/// read-only state directory degrades logging instead of failing the command
/// that happened to emit the line. Holds no lock of its own — `env_logger`
/// already wraps a `Target::Pipe` in a `Mutex`.
struct TeeWriter<E> {
    stderr: E,
    file: Option<std::fs::File>,
    reported_file_failure: bool,
}

impl<E: Write> TeeWriter<E> {
    fn new(stderr: E, file: Option<std::fs::File>) -> Self {
        TeeWriter {
            stderr,
            file,
            reported_file_failure: false,
        }
    }
}

impl<E: Write> Write for TeeWriter<E> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // stderr first — it is the sink the user is watching. Its result is
        // held back rather than returned early so that a broken stderr (a
        // closed pipe, say) still leaves the durable record in the file.
        let stderr_result = self.stderr.write_all(buf);

        // Taken out and only put back on success: a file that failed once is
        // dropped for good rather than retried on every subsequent record.
        if let Some(mut file) = self.file.take() {
            match file.write_all(buf) {
                Ok(()) => self.file = Some(file),
                Err(e) => {
                    if !self.reported_file_failure {
                        self.reported_file_failure = true;
                        let _ = writeln!(
                            self.stderr,
                            "corvex: log file write failed ({e}); continuing on stderr only"
                        );
                    }
                }
            }
        }

        stderr_result.map(|()| buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let stderr_result = self.stderr.flush();
        // Discarded, not swallowed: `File` holds no user-space buffer, so its
        // `flush` is a no-op that returns `Ok`. A full disk surfaces from
        // `write_all` above, which does drop the sink and report. There is no
        // failure here to take the sink out over, and propagating a result that
        // is always `Ok` would only mask a genuine stderr flush error.
        if let Some(file) = self.file.as_mut() {
            let _ = file.flush();
        }
        stderr_result
    }
}

/// Create the log directory, rotate an oversized log, and open it for
/// appending at 0600. Returns `None` when any of that fails: logging must never
/// be the reason a command aborts, so the caller falls back to stderr only.
/// Reports on stderr directly, since the logger does not exist yet.
fn prepare_log_file(log_path: &std::path::Path) -> Option<std::fs::File> {
    prepare_log_file_at(log_path, config::LOG_MAX_BYTES)
}

/// The body, with the rotation threshold passed in. Split only so a test can
/// name a threshold it can cross in a line of text: the order of the two steps
/// matters — rotating *after* the open would rename the file out from under a
/// handle that then appends to an unlinked inode — and nothing else could
/// verify that the threshold reaching `rotate_if_oversized` is the real one.
fn prepare_log_file_at(log_path: &std::path::Path, max_bytes: u64) -> Option<std::fs::File> {
    if let Some(parent) = log_path.parent() {
        if let Err(e) = config::create_dir_restricted(parent) {
            eprintln!(
                "corvex: cannot create log directory {} ({e}); logging to stderr only",
                parent.display()
            );
            return None;
        }
    }

    if let Err(e) = config::rotate_if_oversized(log_path, max_bytes) {
        eprintln!("corvex: cannot rotate {} ({e})", log_path.display());
    }

    match config::open_append_restricted(log_path) {
        Ok(file) => Some(file),
        Err(e) => {
            eprintln!(
                "corvex: cannot open log file {} ({e}); logging to stderr only",
                log_path.display()
            );
            None
        }
    }
}

/// The level corvex logs at when `RUST_LOG` says nothing. `info` is the floor
/// because the log file is now the record of what a `start` did; `warn` left it
/// silent on a successful run.
fn default_level(debug: bool) -> &'static str {
    if debug {
        "debug"
    } else {
        "info"
    }
}

/// Assemble the logger. Split from `init_logger` so tests can `build()` a
/// logger over a temporary file instead of installing a global one.
fn logger_builder(env: env_logger::Env<'_>, file: Option<std::fs::File>) -> env_logger::Builder {
    let mut builder = env_logger::Builder::from_env(env);
    builder
        .format(|buf, record| {
            let ts = buf.timestamp_seconds();
            writeln!(buf, "{} [{}] {}", ts, record.level(), record.args())
        })
        // Set explicitly, so `RUST_LOG_STYLE=always` cannot write ESC bytes
        // into the log file.
        .write_style(env_logger::WriteStyle::Never)
        .target(env_logger::Target::Pipe(Box::new(TeeWriter::new(
            std::io::stderr(),
            file,
        ))));
    builder
}

fn init_logger(log_path: &std::path::Path, debug: bool) {
    let file = prepare_log_file(log_path);
    // `RUST_LOG` wins, otherwise `default_level` — `debug` when `CORVEX_DEBUG=1`
    // or `log.corvex.debug` is set.
    let env = env_logger::Env::default().default_filter_or(default_level(debug));
    let _ = logger_builder(env, file).try_init();
}

/// Whether debug logging was asked for, by `CORVEX_DEBUG=1` or by
/// `log.corvex.debug` in the settings file.
fn debug_requested(settings_path: &std::path::Path) -> bool {
    debug_requested_inner(std::env::var("CORVEX_DEBUG").ok(), settings_path)
}

/// The decision itself, with the environment passed in so it is testable
/// without mutating a process-wide variable other tests are reading.
///
/// Read before the logger exists, so a failure to load the settings — a missing
/// file on a fresh install, a syntax error — is silently treated as "not asked
/// for" rather than reported through a logger that does not exist yet.
fn debug_requested_inner(corvex_debug: Option<String>, settings_path: &std::path::Path) -> bool {
    if corvex_debug.as_deref() == Some("1") {
        return true;
    }
    settings::load(settings_path)
        .ok()
        .and_then(|s| s.log)
        .and_then(|l| l.corvex)
        .and_then(|c| c.debug)
        .unwrap_or(false)
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut config = Config::new(None);

    // Apply --settings override
    if let Some(ref path) = cli.settings_path {
        config.corvex_settings = std::path::PathBuf::from(path);
    }

    // The logger comes up only now: it needs the resolved settings path to
    // honour `log.corvex.debug`, and the resolved state dir to open
    // `corvex.log` — whose parent it creates itself, so a fresh install still
    // gets a log file. Settings-dependent directories stay in `cmd_start`.
    init_logger(&config.corvex_log, debug_requested(&config.corvex_settings));
    debug!("xray config: {}", config.xray_config.display());
    debug!("settings: {}", config.corvex_settings.display());

    // Override xray_log from corvex.json if configured.
    //
    // Only when the value actually names a file. `log.xray.error` is an *xray*
    // log-config value, so it also carries xray's two special meanings (see
    // `is_special_log_value`), and `config.xray_log` is not an xray config
    // value at all — it is the real file corvex opens for the child's
    // stdout/stderr and tails for `corvex logs`. Copying `"none"` across made
    // corvex create a file literally named `none` in whatever directory it was
    // invoked from; copying `""` across left an empty path that aborted `start`
    // with `cannot open log file  for writing`. Either way the default stays,
    // which is what those values ask for: xray's own log is disabled or sent to
    // stdout, and corvex keeps capturing that stdout where it always does.
    if let Ok(s) = settings::load(&config.corvex_settings) {
        if let Some(error_path) = s
            .log
            .as_ref()
            .and_then(|l| l.xray.as_ref())
            .and_then(|x| x.error.clone())
            .filter(|path| !is_special_log_value(path))
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
        Commands::Dns => cmd_dns(&config, &plat, &mut std::io::stdout()),
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

/// Warning line for a subscription that could not be downloaded.
///
/// Renders the whole anyhow cause chain (`{:#}`), not just the outermost context.
/// `download_subscription` wraps every failure as "failed to fetch <url>", so a
/// plain `{}` prints that and nothing else — the caller never learns whether the
/// fetch died at DNS, at TCP connect, or in the TLS handshake, which is the only
/// part worth reading.
///
/// The URL is redacted: this line is emitted at `warn!`, the default level, so an
/// un-redacted subscription token here reaches every terminal and — once corvex
/// writes a log file — every disk.
fn subscription_failure_message(url: &str, err: &anyhow::Error) -> String {
    format!(
        "subscription {} failed: {err:#}",
        subscription::redact_url(url)
    )
}

/// Progress line for a subscription that downloaded successfully.
///
/// Shares `redact_url` with [`subscription_failure_message`] so the success path
/// cannot leak a token the failure path is careful about.
fn subscription_progress_message(url: &str, detail: &str) -> String {
    format!("subscription {}: {detail}", subscription::redact_url(url))
}

/// The one duration scale corvex prints: whole milliseconds under a second,
/// seconds to two decimals above it.
///
/// Shared by [`phase_line`] and the `corvex dns` report so a resolver's round
/// trip reads in the same units as a start phase's elapsed time.
fn format_elapsed(elapsed: std::time::Duration) -> String {
    if elapsed < std::time::Duration::from_secs(1) {
        format!("{}ms", elapsed.as_millis())
    } else {
        format!("{:.2}s", elapsed.as_secs_f64())
    }
}

/// The single format for every start-path progress line.
///
/// `start` used to say nothing between "invoked" and "failed", so a run that
/// died in the subscription fetch looked identical to one that died resolving a
/// server. Each phase now reports what it did and how long it took, at `info`,
/// which is both the default level and what lands in `corvex.log`.
///
/// Sub-second phases render in whole milliseconds and longer ones in seconds to
/// two decimals: a 40 ms config write and a 12 s server sweep are each readable
/// at a glance, and neither drowns in the other's precision.
fn phase_line(phase: &str, detail: &str, elapsed: std::time::Duration) -> String {
    let took = format_elapsed(elapsed);
    if detail.is_empty() {
        format!("{phase} ({took})")
    } else {
        format!("{phase}: {detail} ({took})")
    }
}

/// Progress line for a subscription that finished downloading: how much came
/// back, from where, and how long it took.
///
/// Goes through `redact_url` like every other line that touches a subscription
/// URL — the byte count and the timing are the diagnostic value here, the token
/// in the path is not.
fn subscription_download_line(url: &str, bytes: usize, elapsed: std::time::Duration) -> String {
    phase_line(
        "subscription downloaded",
        &format!("{bytes} bytes from {}", subscription::redact_url(url)),
        elapsed,
    )
}

fn cmd_start(config: &Config, plat: &impl Platform) -> anyhow::Result<()> {
    let started = std::time::Instant::now();

    // 1. Load corvex.json
    let s = settings::load(&config.corvex_settings)
        .with_context(|| format!("failed to load {}", config.corvex_settings.display()))?;
    info!(
        "{}",
        phase_line(
            "settings loaded",
            &config.corvex_settings.display().to_string(),
            started.elapsed()
        )
    );

    // Ensure all directories exist. The xray log config is resolved first
    // because the directories the logs need are the ones *it* names: the
    // defaults it fills in for an unset `log.xray.access`/`error` are real
    // paths that `preflight_log_paths` will insist on opening below.
    let log_config = build_xray_log_config(&s);
    ensure_directories(config, &log_config);

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
        let subs_started = std::time::Instant::now();
        for url in urls {
            info!("{}", subscription_progress_message(url, "downloading"));
            let download_started = std::time::Instant::now();
            match subscription::download_subscription(url, user_agent, extra_headers) {
                Ok(body) => {
                    info!(
                        "{}",
                        subscription_download_line(url, body.len(), download_started.elapsed())
                    );
                    if let Some(entries) = jsonsubs::parse_json_subscription(&body) {
                        debug!(
                            "{}",
                            subscription_progress_message(
                                url,
                                &format!("JSON subscription format, {} entries", entries.len())
                            )
                        );
                        json_entries.extend(entries);
                    } else if let Ok(uris) = subscription::decode_subscription(&body) {
                        let supported = subscription::filter_supported(&uris);
                        debug!(
                            "{}",
                            subscription_progress_message(
                                url,
                                &format!("{} supported URIs", supported.len())
                            )
                        );
                        xray_uris.extend(supported);
                        // Collect vpn:// URIs separately (handled by AWG engine)
                        vpn_uris.extend(uris.into_iter().filter(|u| u.starts_with("vpn://")));
                    }
                }
                Err(e) => {
                    warn!("{}", subscription_failure_message(url, &e));
                    continue;
                }
            }
        }

        info!(
            "{}",
            phase_line(
                "subscription candidates",
                &format!(
                    "{} json entries, {} xray uris, {} vpn uris",
                    json_entries.len(),
                    xray_uris.len(),
                    vpn_uris.len()
                ),
                subs_started.elapsed()
            )
        );

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
    preflight_log_paths(&xray_log_preflight_targets(
        &config.xray_log,
        &log_config.access,
        &log_config.error,
    ))?;
    let merge_subs = s.routes.as_ref().and_then(|r| r.merge_subs) == Some(true);
    let routing = RoutingContext {
        corporate_traffic: &corporate_traffic,
        proxy_traffic: &proxy_traffic,
        log_config: &log_config,
    };

    // Stop a stale AWG tunnel from a previous engine mode before starting fresh
    stop_awg_if_running(config);

    // 5. Branch on source / engine mode
    //
    // These three lines carry no elapsed column on purpose. Selecting an engine
    // is a `match`, not work, and the only clock in scope here is `started` —
    // cumulative since the top of `cmd_start`. Printing that in the same shape
    // as `proxy applied: … (842ms)` would put two different meanings in the one
    // column the narration exists to make scannable.
    let result = match source {
        StartSource::Uri(resolved_uri) => match detect_engine_mode(&resolved_uri) {
            engine::EngineMode::Xray => {
                info!("engine selected: xray (uri)");
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
                info!("engine selected: awg (vpn:// uri)");
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
                    config::create_dir_restricted(parent)?;
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
            info!("engine selected: xray (json subscription entry)");
            // `remarks` verbatim from the panel, same as the address in
            // `health::candidate_line` - escaped for the same reason.
            debug!(
                "using JSON subscription entry: {}",
                entry.params.name.escape_debug()
            );
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
    };

    // Only on success: a failure already carries its own message, and a total
    // elapsed under it would read as if the start had finished.
    if result.is_ok() {
        info!("{}", phase_line("start complete", "", started.elapsed()));
    }
    result
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
        config::create_dir_restricted(parent)?;
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
fn ensure_directories(config: &Config, log_config: &protocol::XrayLogConfig) {
    let must_create = [
        config.corvex_settings.parent(),
        config.xray_config.parent(),
        config.corvex_log.parent(),
        config.xray_pid_file.parent(),
    ];
    for dir in must_create.into_iter().flatten() {
        if let Err(e) = config::create_dir_restricted(dir) {
            warn!("failed to create directory {}: {}", dir.display(), e);
        }
    }

    // Xray log dirs — may need sudo, so only info on failure
    for dir in xray_log_dirs(&config.xray_log, &log_config.access, &log_config.error) {
        if let Err(e) = config::create_dir_restricted(&dir) {
            info!(
                "cannot create log directory {} (may need sudo): {}",
                dir.display(),
                e
            );
        }
    }
}

/// The directories every xray log target needs, in the order they are created.
///
/// It takes the *effective* `access`/`error` — what [`build_xray_log_config`]
/// produced, with corvex's own defaults filled in for whichever the user did
/// not name — rather than the raw `log.xray.*` options, and that is the whole
/// point of the function. Those defaults live under `$XDG_STATE_HOME/xray`,
/// and the only other thing that used to create that directory was
/// `config.xray_log.parent()` — which `run()` aliases onto `log.xray.error`
/// the moment that setting is present. So naming `log.xray.error` alone left
/// the *default* `access.log`'s parent uncreated, and `preflight_log_paths`
/// then aborted the whole `start` on an `ENOENT` for a path the user never
/// mentioned.
///
/// Special values are skipped for the same reason
/// [`xray_log_preflight_targets`] skips them: there is no file, so there is no
/// directory. A relative path yields an empty parent, which is the process's
/// own working directory and needs no creating. The result is deduplicated
/// because `config.xray_log` and `error` name one path whenever the alias
/// above fired, and reporting one unwritable directory twice reads as two
/// faults.
fn xray_log_dirs(xray_log: &std::path::Path, access: &str, error: &str) -> Vec<std::path::PathBuf> {
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    let mut push = |dir: Option<&std::path::Path>| {
        if let Some(dir) = dir.filter(|d| !d.as_os_str().is_empty()) {
            if !dirs.iter().any(|seen| seen == dir) {
                dirs.push(dir.to_path_buf());
            }
        }
    };
    push(xray_log.parent());
    for value in [access, error] {
        if !is_special_log_value(value) {
            push(std::path::Path::new(value).parent());
        }
    }
    dirs
}

/// Message for a log target xray could not open. `PermissionDenied` with a
/// known *foreign* owner uid gets the `sudo chown` fix; every other case (a
/// directory, a read-only filesystem, a symlink loop, an uncreatable parent,
/// an unknown owner, or a file this uid already owns) only names the file and
/// the underlying error - that advice would be wrong for those. Whether the
/// owner is foreign is decided by [`log_target_foreign_owner_uid`], which is
/// what keeps this function pure: `Some(uid)` here means "someone else".
fn log_open_error_message(
    path: &std::path::Path,
    err: &std::io::Error,
    owner_uid: Option<u32>,
) -> String {
    let base = format!("cannot open log file {} for writing: {err}", path.display());
    match (err.kind(), owner_uid) {
        (std::io::ErrorKind::PermissionDenied, Some(uid)) => format!(
            "{base} (owned by uid {uid}). Fix with: sudo chown -- \"$(id -un)\" {}",
            config::shell_quote(&path.display().to_string())
        ),
        _ => base,
    }
}

/// True when an xray log-config value carries xray's own special meaning
/// rather than naming a real file: empty means "log to stdout", `"none"`
/// disables that log entirely. Matched case-sensitively, exactly as xray
/// does. Neither should be preflighted as an openable file path.
fn is_special_log_value(value: &str) -> bool {
    value.is_empty() || value == "none"
}

/// Targets to preflight before spawning xray. `xray_log` is always a genuine
/// file corvex itself opens for the child's stdout/stderr, so it is always
/// checked. `access`/`error` come from xray's own log config and follow
/// xray's special-value semantics (see `is_special_log_value`), so a special
/// value is skipped - there is nothing to open.
fn xray_log_preflight_targets(
    xray_log: &std::path::Path,
    access: &str,
    error: &str,
) -> Vec<std::path::PathBuf> {
    let mut targets = vec![xray_log.to_path_buf()];
    for value in [access, error] {
        if !is_special_log_value(value) {
            targets.push(std::path::PathBuf::from(value));
        }
    }
    targets
}

#[cfg(unix)]
fn log_target_foreign_owner_uid(path: &std::path::Path) -> Option<u32> {
    // SAFETY: `geteuid` reads the calling process's own credentials, takes no
    // arguments and cannot fail.
    let euid = unsafe { nix::libc::geteuid() };
    std::fs::metadata(path)
        .ok()
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        // Only a *foreign* owner earns the `sudo chown` advice below.
        // `PermissionDenied` is also what `config::ensure_trusted_ancestry`
        // returns, and that refusal is about a *directory* in the chain and
        // carries its own `chmod` fix; appending "chown the log file" to it
        // tells the user to change something they already own, which cannot
        // help and buries the advice that would.
        .filter(|uid| *uid != euid)
}

#[cfg(windows)]
fn log_target_foreign_owner_uid(_path: &std::path::Path) -> Option<u32> {
    None
}

/// Verify every xray log target is writable before spawning xray, so an
/// unwritable log fails loudly here, naming the file, instead of xray dying
/// silently and corvex pointing at the log it just failed to write. Every
/// open failure is fatal, not just `PermissionDenied`: a directory, a
/// read-only filesystem, a symlink loop or an uncreatable parent are just as
/// fatal to xray, and `ensure_directories` above deliberately swallows those
/// errors. The path list is deduplicated first, since `config.xray_log` is
/// aliased to `log.xray.error` above whenever that setting is present.
/// Failures are collected across every path rather than stopping at the
/// first, so the user sees every actionable problem in one run instead of
/// fixing them one at a time. A target that did not exist before the probe
/// and was created only to check it is removed immediately after: a
/// successful check must not leave a (potentially root-owned) empty file
/// behind for a later, unrelated step to fail on. Removal failure is itself
/// fatal - silently leaving that artifact defeats the point of the cleanup.
///
/// What makes any of this more than a snapshot is the directory, not the
/// probe. This function opens a path, closes it, and may remove what it
/// created; xray then opens `access.log` and `error.log` by *name*, out of
/// the config corvex generated, long after the probe looked. Nothing about
/// the file at the instant of the probe survives that. `config::open_xray_log`
/// therefore runs `config::ensure_trusted_ancestry` first on every path
/// corvex chose itself, and refuses to hand xray a path whose directory
/// chain anyone else can write: in a directory only its owner can write,
/// nothing can be planted between the probe and the spawn, and the cleanup
/// above cannot be turned into a window either.
fn preflight_log_paths(paths: &[std::path::PathBuf]) -> anyhow::Result<()> {
    let mut seen = std::collections::HashSet::new();
    let mut errors = Vec::new();
    for path in paths {
        if !seen.insert(path.clone()) {
            continue;
        }
        // symlink_metadata, not exists(): exists() follows the link, so a
        // dangling symlink would report "nothing here", the append-open would
        // create its target, and the cleanup below would then delete the
        // symlink itself - destroying the redirection the user set up and
        // leaving a stray file at the target. Same reasoning as
        // `preflight_pid_file`.
        let existed_before = std::fs::symlink_metadata(path).is_ok();
        // `config::open_xray_log`, so the probe is the open `xray::start`
        // will make and not a laxer one: strict at every path corvex chose
        // itself - `xray.log` and the default `access.log`/`error.log` alike
        // - and merely non-blocking at a path the user named, which is what
        // keeps a readerless FIFO anywhere in the log config from wedging the
        // whole command here, before a single line of output.
        //
        // The strict open is also what stops the walk *creating* anything
        // through a symlink planted at one of the defaults: it refuses the
        // shape, the failure is collected below and `start` never spawns
        // xray, so xray never reopens that path from its generated config
        // either.
        match config::open_xray_log(path) {
            Ok(_) => {
                if !existed_before {
                    if let Err(e) = std::fs::remove_file(path) {
                        errors.push(format!(
                            "created {} to verify it is writable, but could not remove it \
                             afterwards: {e}",
                            path.display()
                        ));
                    }
                }
            }
            Err(e) => {
                let owner_uid = log_target_foreign_owner_uid(path);
                errors.push(log_open_error_message(path, &e, owner_uid));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(errors.join("\n"))
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

    let spawn_started = std::time::Instant::now();
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
    info!(
        "{}",
        phase_line(
            "xray started",
            &format!("PID {pid}"),
            spawn_started.elapsed()
        )
    );
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
    let proxy_started = std::time::Instant::now();
    plat.enable_proxy(&service, "127.0.0.1", port)?;
    info!(
        "{}",
        phase_line(
            "proxy applied",
            &format!("{service} -> 127.0.0.1:{port}"),
            proxy_started.elapsed()
        )
    );

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

/// How long `corvex dns` waits for one resolver to answer.
///
/// Long enough for a corporate resolver reached over a tunnel, short enough
/// that a dead one does not hold the whole report hostage.
const DNS_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// What the diagnostic concluded about a single nameserver.
#[derive(Debug)]
enum NameserverVerdict {
    /// The route's gateway sits outside the interface's subnet, so a query
    /// would be handed to a router that is not on the wire. Reported instead
    /// of probed — the probe could only spend its timeout confirming it.
    UnreachableNextHop,
    /// The resolver answered a UDP/53 query in this long.
    Answered(std::time::Duration),
    /// The probe ran and did not come back with a usable answer: timed out,
    /// refused, or replied with something the codec would not accept.
    Failed(String),
}

/// Heading for one resolver block: what it is scoped to, and where it lives.
///
/// A resolver with no `domain` is the system's default one; it is named as
/// global rather than skipped, because a broken global resolver breaks
/// everything that is not split-DNS.
fn resolver_heading(entry: &dns::ResolverEntry) -> String {
    let scope = match &entry.domain {
        Some(domain) => format!("domain {domain}"),
        None => "global (no domain scope)".to_string(),
    };
    match &entry.interface {
        Some(interface) => format!("Resolver: {scope} on {interface}"),
        None => format!("Resolver: {scope}"),
    }
}

/// One line per nameserver: its address, the path the host would take to it,
/// and what came back.
///
/// Colour follows `write_proxy_status` — failures in red — and wraps whole
/// phrases, so `grep UNREACHABLE` still finds the line when colour is on.
fn nameserver_line(
    nameserver: &str,
    hop: &platform::NextHop,
    verdict: &NameserverVerdict,
) -> String {
    let path = match &hop.gateway {
        Some(gateway) => format!("via {gateway} on {}", hop.interface),
        None => format!("directly connected on {}", hop.interface),
    };
    let outcome = match verdict {
        NameserverVerdict::UnreachableNextHop => format!(
            "UNREACHABLE NEXT HOP: gateway {} is outside {}'s subnet, probe skipped",
            hop.gateway.as_deref().unwrap_or("unknown"),
            hop.interface
        )
        .red()
        .to_string(),
        NameserverVerdict::Answered(elapsed) => format!("answered in {}", format_elapsed(*elapsed))
            .green()
            .to_string(),
        NameserverVerdict::Failed(reason) => format!("no answer: {reason}").red().to_string(),
    };
    format!("  {nameserver}  {path}  {outcome}")
}

/// True when `nameserver` is something the diagnostic can reason about.
///
/// The whole path — `route -n get`/`ip route get`, the on-link arithmetic in
/// [`netdiag::next_hop_on_link`], and the probe socket — is IPv4-only, and a
/// zone-scoped literal (`fe80::1%en0`, what a router advertising RDNSS puts in
/// `scutil --dns`) does not even parse as an `IpAddr`. Running one through the
/// walk produces `no route:` or `no answer: … is not an IP address` in red,
/// which reads as a network fault when it is a limit of this command.
fn is_diagnosable_nameserver(nameserver: &str) -> bool {
    nameserver.parse::<std::net::Ipv4Addr>().is_ok()
}

/// Line for a nameserver the walk deliberately does not touch. Uncoloured:
/// nothing is wrong, there is simply nothing to report.
fn undiagnosed_line(nameserver: &str) -> String {
    format!("  {nameserver}  not diagnosed: the route check and the probe are IPv4-only")
}

fn cmd_dns<W: std::io::Write>(
    config: &Config,
    plat: &impl Platform,
    out: &mut W,
) -> anyhow::Result<()> {
    cmd_dns_with(config, plat, out, netdiag::probe_udp53)
}

/// Walks every system resolver, reports how the host would reach each of its
/// nameservers, and probes the ones that are actually reachable.
///
/// Takes the writer for the same reason `cmd_status_inner` does, and takes the
/// probe as a parameter so the report is testable without touching the network:
/// the command passes `netdiag::probe_udp53`, tests pass a recorder. That is
/// also what makes "an off-link resolver is never probed" an assertion rather
/// than an absence of evidence — the fake records every address it was handed.
fn cmd_dns_with<W, P>(
    config: &Config,
    plat: &impl Platform,
    out: &mut W,
    probe: P,
) -> anyhow::Result<()>
where
    W: std::io::Write,
    P: Fn(&str, std::time::Duration) -> anyhow::Result<std::time::Duration>,
{
    debug!("diagnosing system DNS");
    writeln!(out, "Settings: {}", config.corvex_settings.display())?;

    let resolvers = plat
        .list_system_resolvers()
        .context("failed to list the system resolvers")?;
    if resolvers.is_empty() {
        // Not "the machine has no resolvers" — corvex found none it can list.
        // On Linux that is the ordinary shape of a box with no split DNS.
        writeln!(
            out,
            "{}",
            "No resolvers to diagnose were reported by the system.".red()
        )?;
        if cfg!(target_os = "linux") {
            writeln!(
                out,
                "  Only split-DNS resolvers with a search domain are listed on Linux; a machine with just a global resolver reports none."
            )?;
        }
        return Ok(());
    }

    // One verdict per address, not per mention. macOS emits a separate
    // `resolver #N` block for every split-DNS search domain, and a corporate
    // VPN routinely points a dozen of them at the same failover pair — so the
    // naive walk would run the route check and a 2s UDP probe once per block.
    // A pair that is on-link but silent then makes the report take a minute to
    // say the same two things over and over. The rendered line is what is
    // memoized, so the output is identical either way.
    let mut lines: std::collections::BTreeMap<&str, String> = std::collections::BTreeMap::new();
    for entry in &resolvers {
        writeln!(out)?;
        writeln!(out, "{}", resolver_heading(entry).yellow())?;
        for nameserver in &entry.nameservers {
            if let Some(line) = lines.get(nameserver.as_str()) {
                writeln!(out, "{line}")?;
                continue;
            }
            let line = diagnose_nameserver(plat, nameserver, &probe);
            writeln!(out, "{line}")?;
            lines.insert(nameserver.as_str(), line);
        }
    }

    Ok(())
}

/// The report line for one nameserver: where the route says it lives, and what
/// came back from it. Split out of the walk so the walk can memoize it — every
/// system call this command makes happens in here.
fn diagnose_nameserver<P>(plat: &impl Platform, nameserver: &str, probe: &P) -> String
where
    P: Fn(&str, std::time::Duration) -> anyhow::Result<std::time::Duration>,
{
    // Listed, but stepped over: see `is_diagnosable_nameserver`.
    if !is_diagnosable_nameserver(nameserver) {
        return undiagnosed_line(nameserver);
    }
    // A resolver whose route cannot even be read is reported and stepped over:
    // the remaining nameservers are still worth a look, and one of them may
    // well be the working half of a failover pair.
    let hop = match plat.next_hop_status(nameserver) {
        Ok(hop) => hop,
        Err(e) => return format!("  {nameserver}  {}", format!("no route: {e:#}").red()),
    };
    let verdict = if hop.on_link {
        match probe(nameserver, DNS_PROBE_TIMEOUT) {
            Ok(elapsed) => NameserverVerdict::Answered(elapsed),
            Err(e) => NameserverVerdict::Failed(format!("{e:#}")),
        }
    } else {
        NameserverVerdict::UnreachableNextHop
    };
    nameserver_line(nameserver, &hop, &verdict)
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

/// Report the failure that ended a run, exactly once.
///
/// The log file is the record of what a run did, so the failure that ended it
/// is the one line it most needs — a `corvex.log` that stops mid-narration says
/// nothing about why. `run` installs the logger before anything fallible, so an
/// error record normally reaches both stderr and the file; when the level
/// filter drops it (`RUST_LOG=off`) stderr is still owed a word, and gets it
/// directly. Never both, and never a coloured string through the logger —
/// `WriteStyle::Never` keeps ESC bytes out of the file, but only for what
/// env_logger itself renders.
///
/// `error_is_logged` is passed in rather than read here so the fork is
/// testable: the global level filter is process-wide state a test cannot set
/// without disturbing every other test in the binary.
fn report_terminal_error<W: Write>(message: &str, error_is_logged: bool, stderr: &mut W) {
    if error_is_logged {
        error!("{message}");
    } else {
        let _ = writeln!(stderr, "{}: {message}", "Error".red());
    }
}

fn main() {
    if let Err(e) = run() {
        report_terminal_error(
            &format!("{e:#}"),
            log::log_enabled!(log::Level::Error),
            &mut std::io::stderr(),
        );
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use crate::dns::ResolverEntry;
    use crate::platform::{NextHop, Platform, ProxyInfo, ProxyStatus};
    use clap::Parser;
    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet};

    /// Test double for `Platform` that records every method call and can be
    /// configured to fail `detect_active_service` or `disable_proxy`. Lets
    /// tests assert whether/when/in what order `cmd_stop` touched the system
    /// proxy without any real system calls. When `pid_file_must_be_gone` is
    /// set, the mutating proxy calls also assert that the xray PID file no
    /// longer exists — pinning "proxy is only touched after xray fully
    /// stopped" (read-only `detect_active_service` runs before the stop).
    ///
    /// The diagnostic side is configurable too: `resolvers` is what
    /// `list_system_resolvers` returns, and `next_hops` maps a nameserver to
    /// the verdict `next_hop_status` gives for it. Any address not in that map
    /// gets [`RecordingPlatform::default_next_hop`], an ordinary reachable one,
    /// so a test only has to spell out the hop it actually cares about.
    #[derive(Default)]
    struct RecordingPlatform {
        calls: RefCell<Vec<String>>,
        fail_detect_active_service: bool,
        fail_disable_proxy: bool,
        pid_file_must_be_gone: Option<std::path::PathBuf>,
        resolvers: Vec<ResolverEntry>,
        next_hops: BTreeMap<String, NextHop>,
        fail_list_system_resolvers: bool,
        /// Addresses whose `next_hop_status` lookup fails, so a test can pin
        /// that the walk steps over one bad nameserver and keeps going.
        fail_next_hop_status_for: BTreeSet<String>,
    }

    impl RecordingPlatform {
        fn record(&self, method: &str) {
            self.calls.borrow_mut().push(method.to_string());
        }

        /// A reachable next hop on `en0`, the answer for any address a test
        /// did not configure.
        fn default_next_hop() -> NextHop {
            NextHop {
                gateway: Some("192.0.2.1".to_string()),
                interface: "en0".to_string(),
                on_link: true,
            }
        }

        /// A gateway outside the interface's subnet: the stale-route shape the
        /// diagnostic must report instead of probing through it.
        fn unreachable_next_hop() -> NextHop {
            NextHop {
                gateway: Some("10.10.99.1".to_string()),
                interface: "en0".to_string(),
                on_link: false,
            }
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

        fn list_system_resolvers(&self) -> anyhow::Result<Vec<ResolverEntry>> {
            self.record("list_system_resolvers");
            if self.fail_list_system_resolvers {
                anyhow::bail!("list_system_resolvers failed (test)");
            }
            Ok(self.resolvers.clone())
        }

        fn next_hop_status(&self, ip: &str) -> anyhow::Result<NextHop> {
            // The address is part of the record: a test asserting that no probe
            // was attempted needs to see which hops were even looked up.
            self.record(&format!("next_hop_status({ip})"));
            if self.fail_next_hop_status_for.contains(ip) {
                anyhow::bail!("no route to {ip} (test)");
            }
            Ok(self
                .next_hops
                .get(ip)
                .cloned()
                .unwrap_or_else(Self::default_next_hop))
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

    /// A fake token, never a real one: pushed through the start path's log lines
    /// and asserted absent, so a line that forgets `redact_url` fails the suite
    /// rather than shipping a credential to a terminal or a log file.
    const SENTINEL_TOKEN: &str = "SENTINEL-TOKEN-9f3a2c";

    /// A subscription failure must surface the root cause, not just the
    /// "failed to fetch <url>" context `download_subscription` wraps everything
    /// in. Formatting the error with `{}` printed only that context, which told
    /// the user nothing about *why* the fetch failed.
    ///
    /// The context is built from an already-redacted URL, mirroring what
    /// `download_subscription` now attaches.
    #[test]
    fn test_subscription_failure_message_includes_whole_cause_chain() {
        let err = anyhow::anyhow!("dns error: no record found")
            .context("failed to fetch https://panel.example/<redacted>");

        let msg = super::subscription_failure_message("https://panel.example/sub/abc", &err);

        assert!(
            msg.contains("failed to fetch https://panel.example/<redacted>"),
            "context must survive: {msg}"
        );
        assert!(
            msg.contains("dns error: no record found"),
            "root cause must be visible: {msg}"
        );
        assert!(
            !msg.contains("/sub/abc"),
            "the path must never be rendered: {msg}"
        );
    }

    /// Sub-second phases are the common case — a config write, a proxy batch —
    /// and seconds with two decimals would render all of them as "0.04s".
    #[test]
    fn test_phase_line_renders_sub_second_in_milliseconds() {
        let line = super::phase_line(
            "proxy applied",
            "Wi-Fi -> 127.0.0.1:21080",
            std::time::Duration::from_millis(842),
        );

        assert_eq!(line, "proxy applied: Wi-Fi -> 127.0.0.1:21080 (842ms)");
    }

    /// A server sweep or a subscription fetch runs for seconds, where
    /// milliseconds are noise. The boundary is one second exactly.
    #[test]
    fn test_phase_line_renders_multi_second_in_seconds() {
        let line = super::phase_line(
            "subscription candidates",
            "3 json entries, 0 xray uris, 0 vpn uris",
            std::time::Duration::from_millis(12400),
        );

        assert_eq!(
            line,
            "subscription candidates: 3 json entries, 0 xray uris, 0 vpn uris (12.40s)"
        );

        let boundary = super::phase_line("sweep", "", std::time::Duration::from_secs(1));
        assert_eq!(boundary, "sweep (1.00s)", "one second is not sub-second");
    }

    /// A phase that took no measurable time still gets a timing, so every
    /// progress line has the same shape and can be scanned down a column.
    #[test]
    fn test_phase_line_renders_zero_elapsed() {
        assert_eq!(
            super::phase_line(
                "settings loaded",
                "/tmp/corvex.json",
                std::time::Duration::ZERO
            ),
            "settings loaded: /tmp/corvex.json (0ms)"
        );
    }

    /// Milestones like "start complete" carry no detail; the line must not end
    /// up with a dangling separator.
    #[test]
    fn test_phase_line_omits_empty_detail() {
        assert_eq!(
            super::phase_line("start complete", "", std::time::Duration::from_millis(2500)),
            "start complete (2.50s)"
        );
    }

    /// The download progress line is new in the start narration and interpolates
    /// the configured subscription URL, so it is one more place a token could
    /// reach `corvex.log`. It must redact like every other line that does.
    #[test]
    fn test_subscription_download_line_never_contains_the_token() {
        let url = format!("https://panel.example/sub/{SENTINEL_TOKEN}?key={SENTINEL_TOKEN}");

        let line =
            super::subscription_download_line(&url, 4096, std::time::Duration::from_millis(120));

        assert!(
            !line.contains(SENTINEL_TOKEN),
            "token leaked into the start narration: {line}"
        );
        assert_eq!(
            line,
            "subscription downloaded: 4096 bytes from https://panel.example/<redacted> (120ms)"
        );
    }

    /// Subscription tokens live in the URL path, and both start-path log lines
    /// interpolate the configured URL. Neither may render it.
    ///
    /// The failure line is the one that matters most: it is emitted at `warn!`,
    /// which is on by default, so before this it leaked on every failed fetch.
    #[test]
    fn test_subscription_log_lines_never_contain_the_token() {
        let url = format!("https://panel.example/sub/{SENTINEL_TOKEN}?key={SENTINEL_TOKEN}");

        let success = super::subscription_progress_message(&url, "3 supported URIs");
        assert!(
            !success.contains(SENTINEL_TOKEN),
            "token leaked on the success path: {success}"
        );
        assert_eq!(
            success,
            "subscription https://panel.example/<redacted>: 3 supported URIs"
        );

        let err = anyhow::anyhow!("connection refused");
        let failure = super::subscription_failure_message(&url, &err);
        assert!(
            !failure.contains(SENTINEL_TOKEN),
            "token leaked on the failure path: {failure}"
        );
        assert!(
            failure.contains("https://panel.example"),
            "the host must survive so the user can tell subscriptions apart: {failure}"
        );
        assert!(
            failure.contains("connection refused"),
            "root cause must be visible: {failure}"
        );
    }

    /// Regression test: a failed stop (here: xray not running) must not touch
    /// the system proxy at all — previously the proxy was disabled first.
    /// Read-only service detection runs before the stop and is allowed; the
    /// mutating `disable_proxy` must never be reached.
    #[test]
    fn test_cmd_stop_without_running_xray_never_touches_proxy() {
        let dir = crate::config::test_tempdir();
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
        let dir = crate::config::test_tempdir();
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
        let dir = crate::config::test_tempdir();
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
        let dir = crate::config::test_tempdir();
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
        /// Retries on `ExecutableFileBusy`. Cargo runs these tests as threads
        /// of one process, and each writes its own fake executable just before
        /// running it. If another thread forks in the window while that file
        /// is still open for writing, the forked child inherits the descriptor
        /// and Linux refuses to exec the file until it closes, with ETXTBSY.
        /// The window is short (Rust marks the descriptor close-on-exec, so it
        /// only lasts from fork to the child's own exec) but real: it failed a
        /// CI run once while passing on macOS, which does not enforce this.
        fn spawn(cmd: &mut std::process::Command) -> Self {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
            let mut attempt = 0;
            let mut child = loop {
                match cmd.spawn() {
                    Ok(child) => break child,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::ExecutableFileBusy && attempt < 50 =>
                    {
                        attempt += 1;
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                    Err(e) => panic!("failed to spawn fake test process: {e}"),
                }
            };
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
        let dir = crate::config::test_tempdir();
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
        let dir = crate::config::test_tempdir();
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
        let dir = crate::config::test_tempdir();
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
        let dir = crate::config::test_tempdir();
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

    /// The stopped half of the xray status line, which only a test-local
    /// reimplementation used to cover.
    #[test]
    #[cfg(unix)]
    fn cmd_status_inner_reports_a_stopped_xray() {
        let dir = crate::config::test_tempdir();
        let config = temp_config(dir.path(), "xray");
        // No PID file, so nothing is tracked and nothing is running.
        assert!(!config.xray_pid_file.exists());

        let plat = RecordingPlatform::default();
        let mut buf: Vec<u8> = Vec::new();
        super::cmd_status_inner(&config, &plat, &mut buf).expect("cmd_status must succeed");

        let output = String::from_utf8(buf).unwrap();
        let line = output
            .lines()
            .find(|line| line.starts_with("xray: "))
            .expect("the xray status line must be present");
        // `stopped` is coloured, so match inside the line rather than on it.
        assert!(line.contains("stopped"), "{line:?}");
    }

    /// These four used to assert against `format_xray_status` and
    /// `format_proxy_status`, two reimplementations of the status rendering
    /// that lived here in `mod tests` — so changing the real renderer could not
    /// break them. They drive the production code now. The xray line is
    /// covered where it is actually produced, in the `cmd_status_inner` tests.
    #[test]
    fn write_proxy_status_renders_an_enabled_proxy() {
        let mut buf: Vec<u8> = Vec::new();
        super::write_proxy_status(
            &mut buf,
            "socks",
            &ProxyInfo {
                enabled: true,
                server: "127.0.0.1".to_string(),
                port: "1080".to_string(),
            },
        )
        .unwrap();

        assert_eq!(String::from_utf8(buf).unwrap(), "socks: 127.0.0.1:1080\n");
    }

    #[test]
    fn write_proxy_status_renders_a_disabled_proxy() {
        let mut buf: Vec<u8> = Vec::new();
        super::write_proxy_status(
            &mut buf,
            "http",
            &ProxyInfo {
                enabled: false,
                server: String::new(),
                port: String::new(),
            },
        )
        .unwrap();

        // `off` is coloured, so match around it rather than on an exact string:
        // whether ANSI codes are emitted depends on the test runner's tty.
        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with("http: "), "{output:?}");
        assert!(output.contains("off"), "{output:?}");
        assert!(output.ends_with('\n'), "{output:?}");
    }

    #[test]
    fn test_update_config_port() {
        let dir = crate::config::test_tempdir();
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
        let state = crate::config::state_dir();
        let access = std::path::PathBuf::from(&log_config.access);
        let error = std::path::PathBuf::from(&log_config.error);
        assert_eq!(
            access.strip_prefix(&state).unwrap(),
            std::path::Path::new("xray").join("access.log")
        );
        assert_eq!(
            error.strip_prefix(&state).unwrap(),
            std::path::Path::new("xray").join("error.log")
        );
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
        let dir = crate::config::test_tempdir();
        let path = dir.path().join("corvex.json");
        std::fs::write(&path, json).unwrap();
        let s = crate::settings::load(&path).unwrap();
        let log_config = super::build_xray_log_config(&s);
        assert_eq!(log_config.loglevel, "debug");
        assert_eq!(log_config.access, "/custom/access.log");
        assert_eq!(log_config.error, "/custom/error.log");
    }

    #[test]
    fn test_build_xray_log_config_access_only() {
        let json = r#"{
            "uri": "vless://x@y:1",
            "log": { "xray": { "access": "/custom/access.log" } }
        }"#;
        let dir = crate::config::test_tempdir();
        let path = dir.path().join("corvex.json");
        std::fs::write(&path, json).unwrap();
        let s = crate::settings::load(&path).unwrap();
        let log_config = super::build_xray_log_config(&s);
        let defaults = crate::protocol::XrayLogConfig::default();
        assert_eq!(log_config.loglevel, defaults.loglevel);
        assert_eq!(log_config.access, "/custom/access.log");
        assert_eq!(log_config.error, defaults.error);
    }

    #[test]
    fn test_build_xray_log_config_error_only() {
        let json = r#"{
            "uri": "vless://x@y:1",
            "log": { "xray": { "error": "/custom/error.log" } }
        }"#;
        let dir = crate::config::test_tempdir();
        let path = dir.path().join("corvex.json");
        std::fs::write(&path, json).unwrap();
        let s = crate::settings::load(&path).unwrap();
        let log_config = super::build_xray_log_config(&s);
        let defaults = crate::protocol::XrayLogConfig::default();
        assert_eq!(log_config.loglevel, defaults.loglevel);
        assert_eq!(log_config.access, defaults.access);
        assert_eq!(log_config.error, "/custom/error.log");
    }

    #[test]
    fn test_build_xray_log_config_loglevel_only() {
        let json = r#"{
            "uri": "vless://x@y:1",
            "log": { "xray": { "loglevel": "debug" } }
        }"#;
        let dir = crate::config::test_tempdir();
        let path = dir.path().join("corvex.json");
        std::fs::write(&path, json).unwrap();
        let s = crate::settings::load(&path).unwrap();
        let log_config = super::build_xray_log_config(&s);
        let defaults = crate::protocol::XrayLogConfig::default();
        assert_eq!(log_config.loglevel, "debug");
        assert_eq!(log_config.access, defaults.access);
        assert_eq!(log_config.error, defaults.error);
    }

    #[test]
    fn test_build_xray_log_config_empty_xray_object_uses_all_defaults() {
        let json = r#"{
            "uri": "vless://x@y:1",
            "log": { "xray": {} }
        }"#;
        let dir = crate::config::test_tempdir();
        let path = dir.path().join("corvex.json");
        std::fs::write(&path, json).unwrap();
        let s = crate::settings::load(&path).unwrap();
        let log_config = super::build_xray_log_config(&s);
        let defaults = crate::protocol::XrayLogConfig::default();
        assert_eq!(log_config.loglevel, defaults.loglevel);
        assert_eq!(log_config.access, defaults.access);
        assert_eq!(log_config.error, defaults.error);
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
        let dir = crate::config::test_tempdir();
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
        let dir = crate::config::test_tempdir();
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
        let dir = crate::config::test_tempdir();
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

    /// An [`XrayLogConfig`] whose two log targets sit under `base`. Tests must
    /// not use `XrayLogConfig::default()` here: its paths are corvex's real
    /// `$XDG_STATE_HOME/xray` picks, and `ensure_directories` would create
    /// them in the home of whoever ran the suite.
    fn temp_log_config(base: &std::path::Path) -> crate::protocol::XrayLogConfig {
        crate::protocol::XrayLogConfig {
            loglevel: "warning".to_string(),
            access: base.join("logs/access.log").display().to_string(),
            error: base.join("logs/error.log").display().to_string(),
        }
    }

    #[test]
    fn test_ensure_directories_creates_all_dirs() {
        let dir = crate::config::test_tempdir();
        let base = dir.path();
        let config = temp_config(base, "xray");
        let log_config = temp_log_config(base);

        super::ensure_directories(&config, &log_config);

        assert!(base.join("xray").exists());
        assert!(base.join("corvex").exists());
        assert!(base.join("state/corvex").exists());
        assert!(base.join("logs").exists());
    }

    #[test]
    fn test_ensure_directories_idempotent() {
        let dir = crate::config::test_tempdir();
        let base = dir.path();
        let config = temp_config(base, "xray");
        let log_config = temp_log_config(base);

        super::ensure_directories(&config, &log_config);
        super::ensure_directories(&config, &log_config);

        assert!(base.join("xray").exists());
        assert!(base.join("corvex").exists());
    }

    /// The regression the `xray_log_dirs` rewrite fixed: naming
    /// `log.xray.error` alone re-points `config.xray_log` at it, and the
    /// *default* `access.log`'s parent then had nothing left to create it.
    /// `preflight_log_paths` opens that default regardless, so `start` died on
    /// an `ENOENT` for a path the user never mentioned.
    #[test]
    fn test_ensure_directories_creates_parent_of_unnamed_default_log() {
        let dir = crate::config::test_tempdir();
        let base = dir.path();
        // `run()` has already aliased xray_log onto the configured error path.
        let mut config = temp_config(base, "xray");
        config.xray_log = base.join("named/error.log");
        let log_config = crate::protocol::XrayLogConfig {
            loglevel: "warning".to_string(),
            // Stands in for the default corvex fills in for an unset
            // `log.xray.access` — a directory nothing else here names.
            access: base.join("state_default/access.log").display().to_string(),
            error: base.join("named/error.log").display().to_string(),
        };

        super::ensure_directories(&config, &log_config);

        assert!(base.join("named").exists());
        assert!(base.join("state_default").exists());
    }

    #[test]
    fn test_ensure_directories_with_log_settings() {
        let dir = crate::config::test_tempdir();
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

        super::ensure_directories(&config, &super::build_xray_log_config(&settings));

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
        let log_config = temp_log_config(std::path::Path::new("/nonexistent_root_path"));
        // Should not panic
        super::ensure_directories(&config, &log_config);
    }

    // -- log_open_error_message --

    #[test]
    fn test_log_open_error_message_permission_denied_names_uid_and_chown() {
        let path = std::path::Path::new("/var/log/xray/access.log");
        let err = std::io::Error::from(std::io::ErrorKind::PermissionDenied);

        let msg = super::log_open_error_message(path, &err, Some(501));

        assert!(msg.contains("/var/log/xray/access.log"));
        assert!(msg.contains("501"));
        assert!(msg.contains("sudo chown -- \"$(id -un)\" '/var/log/xray/access.log'"));
    }

    #[test]
    fn test_log_open_error_message_chown_quotes_path_with_space() {
        let path = std::path::Path::new("/var/log/xray dir/access.log");
        let err = std::io::Error::from(std::io::ErrorKind::PermissionDenied);

        let msg = super::log_open_error_message(path, &err, Some(501));

        assert!(msg.contains("sudo chown -- \"$(id -un)\" '/var/log/xray dir/access.log'"));
    }

    /// A log corvex's own uid owns must never earn the `sudo chown` advice:
    /// `ensure_trusted_ancestry` also fails with `PermissionDenied`, and that
    /// refusal is about a directory, not about who owns the file.
    #[test]
    #[cfg(unix)]
    fn test_log_target_foreign_owner_uid_is_none_for_a_file_this_uid_owns() {
        let dir = crate::config::test_tempdir();
        let path = dir.path().join("error.log");
        std::fs::write(&path, b"").unwrap();

        assert_eq!(super::log_target_foreign_owner_uid(&path), None);
    }

    #[test]
    fn test_log_open_error_message_other_error_has_no_chown_line() {
        let path = std::path::Path::new("/var/log/xray/access.log");
        let err = std::io::Error::other("read-only file system");

        let msg = super::log_open_error_message(path, &err, None);

        assert!(msg.contains("/var/log/xray/access.log"));
        assert!(msg.contains("read-only file system"));
        assert!(!msg.contains("chown"));
    }

    #[test]
    fn test_log_open_error_message_permission_denied_without_known_owner_has_no_chown_line() {
        // The Windows case: MetadataExt is unix-only, so owner_uid is always
        // None there even on a PermissionDenied error.
        let path = std::path::Path::new("/var/log/xray/access.log");
        let err = std::io::Error::from(std::io::ErrorKind::PermissionDenied);

        let msg = super::log_open_error_message(path, &err, None);

        assert!(!msg.contains("chown"));
    }

    // -- preflight_log_paths --

    #[test]
    #[cfg(unix)]
    fn test_preflight_log_paths_rejects_readonly_existing_file() {
        let dir = crate::config::test_tempdir();
        let path = dir.path().join("access.log");
        std::fs::write(&path, "").unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o400);
        std::fs::set_permissions(&path, perms).unwrap();

        let result = super::preflight_log_paths(std::slice::from_ref(&path));

        // Restore before the temp dir is dropped.
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o600);
        std::fs::set_permissions(&path, perms).unwrap();

        let err = result.expect_err("a 0o400 existing file must be rejected");
        assert!(err.to_string().contains(&path.display().to_string()));
    }

    #[test]
    #[cfg(unix)]
    fn test_preflight_log_paths_rejects_creation_in_readonly_directory() {
        let dir = crate::config::test_tempdir();
        let sub = dir.path().join("logs");
        std::fs::create_dir_all(&sub).unwrap();
        let path = sub.join("access.log");
        let mut perms = std::fs::metadata(&sub).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o500);
        std::fs::set_permissions(&sub, perms).unwrap();

        let result = super::preflight_log_paths(std::slice::from_ref(&path));

        // Restore before the temp dir is dropped.
        let mut perms = std::fs::metadata(&sub).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o700);
        std::fs::set_permissions(&sub, perms).unwrap();

        let err = result.expect_err("creating a new file in a 0o500 directory must be rejected");
        assert!(err.to_string().contains(&path.display().to_string()));
    }

    #[test]
    #[cfg(unix)]
    fn test_preflight_log_paths_accepts_writable_target() {
        let dir = crate::config::test_tempdir();
        let path = dir.path().join("access.log");

        super::preflight_log_paths(std::slice::from_ref(&path))
            .expect("a writable target must pass");
        assert!(
            !path.exists(),
            "a target created only to probe it must be removed afterwards"
        );
    }

    /// A dangling symlink is a pre-existing entry even though `exists()` says
    /// otherwise, because it follows the link. Probing must not delete it: the
    /// user pointed the log somewhere deliberately, and removing the link
    /// would send xray's output to a fresh regular file instead.
    #[test]
    #[cfg(unix)]
    fn test_preflight_log_paths_preserves_dangling_symlink() {
        let dir = crate::config::test_tempdir();
        let target = dir.path().join("elsewhere.log");
        let link = dir.path().join("access.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(!link.exists(), "the link must dangle for this test to bite");

        super::preflight_log_paths(std::slice::from_ref(&link))
            .expect("a writable dangling symlink must pass");

        assert!(
            std::fs::symlink_metadata(&link).is_ok(),
            "the symlink itself must survive the probe"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_preflight_log_paths_preserves_preexisting_file() {
        let dir = crate::config::test_tempdir();
        let path = dir.path().join("access.log");
        std::fs::write(&path, "existing content").unwrap();

        super::preflight_log_paths(std::slice::from_ref(&path))
            .expect("an already-writable existing file must pass");

        assert!(path.exists(), "a pre-existing target must not be removed");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "existing content",
            "a pre-existing target's content must be untouched"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_preflight_log_paths_dedupes_duplicate_path() {
        let dir = crate::config::test_tempdir();
        let path = dir.path().join("access.log");
        std::fs::write(&path, "").unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o400);
        std::fs::set_permissions(&path, perms).unwrap();

        // config.xray_log aliases to log.xray.error in real usage, so the
        // same failing path can appear twice in the input.
        let result = super::preflight_log_paths(&[path.clone(), path.clone()]);

        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o600);
        std::fs::set_permissions(&path, perms).unwrap();

        let err = result.expect_err("a 0o400 existing file must be rejected");
        // The message names the path twice on its own (once in "cannot open
        // log file X", once in the chown hint), so count failure entries via
        // a marker that appears exactly once per checked path, not raw path
        // occurrences.
        let occurrences = err.to_string().matches("cannot open log file").count();
        assert_eq!(
            occurrences, 1,
            "a duplicated path must be reported once, not once per occurrence: {err}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_preflight_log_paths_rejects_non_permission_error() {
        // A directory target fails to open as a file with ErrorKind::IsADirectory
        // or ErrorKind::Other, never PermissionDenied - every failure must still
        // be fatal, not just permission errors.
        let dir = crate::config::test_tempdir();
        let target = dir.path().join("access.log");
        std::fs::create_dir_all(&target).unwrap();

        let result = super::preflight_log_paths(std::slice::from_ref(&target));

        assert!(
            result.is_err(),
            "a non-permission open failure must still be fatal"
        );
    }

    // -- is_special_log_value / xray_log_preflight_targets --

    #[test]
    fn test_is_special_log_value_empty_and_none() {
        assert!(super::is_special_log_value(""));
        assert!(super::is_special_log_value("none"));
    }

    #[test]
    fn test_is_special_log_value_real_path_is_not_special() {
        assert!(!super::is_special_log_value("/var/log/xray/access.log"));
        assert!(!super::is_special_log_value("None")); // xray matches case-sensitively
    }

    #[test]
    fn test_xray_log_preflight_targets_skips_empty_and_none() {
        let targets = super::xray_log_preflight_targets(
            std::path::Path::new("/state/xray/xray.log"),
            "",
            "none",
        );

        assert_eq!(
            targets,
            vec![std::path::PathBuf::from("/state/xray/xray.log")]
        );
    }

    #[test]
    fn test_xray_log_preflight_targets_keeps_real_paths() {
        let targets = super::xray_log_preflight_targets(
            std::path::Path::new("/state/xray/xray.log"),
            "/state/xray/access.log",
            "/state/xray/error.log",
        );

        assert_eq!(
            targets,
            vec![
                std::path::PathBuf::from("/state/xray/xray.log"),
                std::path::PathBuf::from("/state/xray/access.log"),
                std::path::PathBuf::from("/state/xray/error.log"),
            ]
        );
    }

    // -- xray_log_dirs --

    #[test]
    fn test_xray_log_dirs_includes_default_access_dir_when_error_is_named() {
        let dirs = super::xray_log_dirs(
            // What `run()` leaves behind once `log.xray.error` is set.
            std::path::Path::new("/var/log/xray/error.log"),
            "/state/xray/access.log",
            "/var/log/xray/error.log",
        );

        assert_eq!(
            dirs,
            vec![
                std::path::PathBuf::from("/var/log/xray"),
                std::path::PathBuf::from("/state/xray"),
            ]
        );
    }

    #[test]
    fn test_xray_log_dirs_deduplicates_the_aliased_path() {
        let dirs = super::xray_log_dirs(
            std::path::Path::new("/state/xray/xray.log"),
            "/state/xray/access.log",
            "/state/xray/error.log",
        );

        assert_eq!(dirs, vec![std::path::PathBuf::from("/state/xray")]);
    }

    #[test]
    fn test_xray_log_dirs_skips_special_values_and_relative_parents() {
        let dirs = super::xray_log_dirs(
            std::path::Path::new("/state/xray/xray.log"),
            // "none" and "" name no file, and a bare relative name's parent is
            // the working directory, which needs no creating.
            "none",
            "relative.log",
        );

        assert_eq!(dirs, vec![std::path::PathBuf::from("/state/xray")]);
    }

    // -- run()'s xray_log override --

    #[test]
    fn test_special_error_log_value_does_not_become_the_capture_path() {
        // The filter `run()` applies. `"none"` used to be copied into
        // `config.xray_log` verbatim, which made corvex create a file called
        // `none` in its own working directory; `""` aborted `start` outright.
        for value in ["none", ""] {
            assert!(
                super::is_special_log_value(value),
                "{value:?} must not reach config.xray_log"
            );
        }
        assert!(!super::is_special_log_value("/var/log/xray/error.log"));
    }

    #[test]
    #[cfg(unix)]
    fn test_preflight_log_paths_accepts_empty_and_none_log_values() {
        let dir = crate::config::test_tempdir();
        let xray_log = dir.path().join("xray.log");

        // "" (stdout) and "none" (disabled) are xray's own special values,
        // never real files - the preflight must not try to open them.
        let targets = super::xray_log_preflight_targets(&xray_log, "", "none");
        super::preflight_log_paths(&targets)
            .expect("empty and \"none\" log values must not be probed as files");
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

    // --- logging ---------------------------------------------------------

    /// An `Env` that ignores the ambient environment, so `RUST_LOG` and
    /// `RUST_LOG_STYLE` in the developer's shell cannot change what these
    /// tests observe. The variable names are deliberately never set.
    fn isolated_env() -> env_logger::Env<'static> {
        env_logger::Env::new()
            .filter_or("CORVEX_TEST_FILTER_UNSET", super::default_level(false))
            .write_style_or("CORVEX_TEST_STYLE_UNSET", "never")
    }

    /// Push one `info!`-level record through a logger built exactly the way
    /// `init_logger` builds it, without installing it globally — a global
    /// logger can only be set once per process, and the test binary is one
    /// process.
    fn log_one_record(env: env_logger::Env<'_>, file: Option<std::fs::File>, message: &str) {
        use log::Log;
        let logger = super::logger_builder(env, file).build();
        logger.log(
            &log::Record::builder()
                .level(log::Level::Info)
                .target("corvex")
                .args(format_args!("{message}"))
                .build(),
        );
        logger.flush();
    }

    #[test]
    fn tee_writer_writes_to_both_sinks() {
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");
        let mut stderr = Vec::new();
        {
            let file = crate::config::open_append_restricted(&log).unwrap();
            let mut tee = super::TeeWriter::new(&mut stderr, Some(file));
            std::io::Write::write_all(&mut tee, b"a line\n").unwrap();
            std::io::Write::flush(&mut tee).unwrap();
        }

        assert_eq!(String::from_utf8(stderr).unwrap(), "a line\n");
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "a line\n");
    }

    #[test]
    fn tee_writer_survives_a_failing_file_sink() {
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");
        std::fs::write(&log, "").unwrap();
        // Opened read-only, so every write to it fails.
        let unwritable = std::fs::File::open(&log).unwrap();

        let mut stderr = Vec::new();
        {
            let mut tee = super::TeeWriter::new(&mut stderr, Some(unwritable));
            std::io::Write::write_all(&mut tee, b"first\n").unwrap();
            std::io::Write::write_all(&mut tee, b"second\n").unwrap();
        }

        let out = String::from_utf8(stderr).unwrap();
        assert!(out.contains("first\n"), "stderr was {out:?}");
        assert!(out.contains("second\n"), "stderr was {out:?}");
        assert_eq!(
            out.matches("continuing on stderr only").count(),
            1,
            "the file failure must be reported exactly once; stderr was {out:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "",
            "nothing should have reached the unwritable file"
        );
    }

    /// `corvex start | head` closes the pipe under us. The file is the durable
    /// record, so it must still get the line — which only holds because
    /// `TeeWriter::write` holds the stderr result back instead of returning it
    /// before the file is written.
    #[test]
    fn tee_writer_still_writes_the_file_when_stderr_is_a_closed_pipe() {
        struct ClosedPipe;
        impl std::io::Write for ClosedPipe {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
        }

        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");
        {
            let file = crate::config::open_append_restricted(&log).unwrap();
            let mut tee = super::TeeWriter::new(ClosedPipe, Some(file));
            let result = std::io::Write::write_all(&mut tee, b"the record\n");
            assert!(
                result.is_err(),
                "a broken stderr must still be reported to the caller"
            );
        }

        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "the record\n",
            "the durable record must survive a broken stderr"
        );
    }

    /// The only reader of `log.corvex.debug`, and the sole gate between `info`
    /// and `debug`. Reading the wrong key, or inverting the `unwrap_or`, leaves
    /// the log quiet during exactly the slow start it was written for.
    #[test]
    fn debug_requested_reads_log_corvex_debug_from_the_settings_file() {
        let dir = crate::config::test_tempdir();

        let on = dir.path().join("on.json");
        std::fs::write(
            &on,
            r#"{"uri":"vless://x@y:1","log":{"corvex":{"debug":true}}}"#,
        )
        .unwrap();
        assert!(super::debug_requested_inner(None, &on));

        let off = dir.path().join("off.json");
        std::fs::write(
            &off,
            r#"{"uri":"vless://x@y:1","log":{"corvex":{"debug":false}}}"#,
        )
        .unwrap();
        assert!(!super::debug_requested_inner(None, &off));

        // `log.xray.loglevel` is a different key and must not turn debug on.
        let xray_only = dir.path().join("xray-only.json");
        std::fs::write(
            &xray_only,
            r#"{"uri":"vless://x@y:1","log":{"xray":{"loglevel":"debug"}}}"#,
        )
        .unwrap();
        assert!(!super::debug_requested_inner(None, &xray_only));
    }

    #[test]
    fn debug_requested_defaults_to_off_when_the_settings_cannot_be_read() {
        let dir = crate::config::test_tempdir();
        let missing = dir.path().join("nope.json");

        assert!(
            !super::debug_requested_inner(None, &missing),
            "a fresh install has no settings file and must still start"
        );

        let malformed = dir.path().join("bad.json");
        std::fs::write(&malformed, "{ not json").unwrap();
        assert!(!super::debug_requested_inner(None, &malformed));
    }

    #[test]
    fn debug_requested_honours_corvex_debug_over_the_settings_file() {
        let dir = crate::config::test_tempdir();
        let off = dir.path().join("off.json");
        std::fs::write(
            &off,
            r#"{"uri":"vless://x@y:1","log":{"corvex":{"debug":false}}}"#,
        )
        .unwrap();

        assert!(
            super::debug_requested_inner(Some("1".to_string()), &off),
            "the environment variable wins over a settings file that says no"
        );
        // Only "1" counts: an exported-but-empty or "0" value is not a request.
        assert!(!super::debug_requested_inner(Some("0".to_string()), &off));
        assert!(!super::debug_requested_inner(Some(String::new()), &off));
    }

    #[test]
    fn prepare_log_file_persists_the_first_record_from_fresh_state() {
        let dir = crate::config::test_tempdir();
        // Neither the state directory nor the file exists yet.
        let log = dir.path().join("state").join("corvex").join("corvex.log");
        assert!(!log.parent().unwrap().exists());

        let file = super::prepare_log_file(&log).expect("fresh state must yield a log file");
        log_one_record(isolated_env(), Some(file), "first record after install");

        let written = std::fs::read_to_string(&log).unwrap();
        assert!(
            written.contains("first record after install"),
            "log was {written:?}"
        );
        assert!(written.contains("[INFO]"), "log was {written:?}");
    }

    #[cfg(unix)]
    #[test]
    fn prepare_log_file_creates_the_log_at_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("state").join("corvex").join("corvex.log");

        drop(super::prepare_log_file(&log).unwrap());

        let mode = std::fs::metadata(&log).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }

    #[test]
    fn log_file_has_no_escape_bytes_even_when_style_is_forced_on() {
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");
        let file = super::prepare_log_file(&log).unwrap();

        // `always` is what `RUST_LOG_STYLE=always` would ask for; the explicit
        // `WriteStyle::Never` in `logger_builder` has to win.
        let styled = env_logger::Env::new()
            .filter_or("CORVEX_TEST_FILTER_UNSET", super::default_level(false))
            .write_style_or("CORVEX_TEST_STYLE_UNSET", "always");
        log_one_record(styled, Some(file), "a styled message");

        let bytes = std::fs::read(&log).unwrap();
        assert!(
            !bytes.contains(&0x1b),
            "log file must hold no ESC byte, got {:?}",
            String::from_utf8_lossy(&bytes)
        );
    }

    #[test]
    fn prepare_log_file_degrades_to_stderr_only_when_the_directory_is_unusable() {
        let dir = crate::config::test_tempdir();
        // A plain file where a directory is needed: `create_dir_all` cannot win.
        let blocker = dir.path().join("corvex");
        std::fs::write(&blocker, "not a directory").unwrap();

        assert!(super::prepare_log_file(&blocker.join("corvex.log")).is_none());
    }

    /// The rotation wiring, not `rotate_if_oversized` itself: that an oversized
    /// log is moved aside *before* the file is opened, and that the handle
    /// handed back appends to the fresh file rather than to the unlinked inode
    /// the old name used to point at. Rotating after the open would leave the
    /// process writing to a file nobody can find.
    #[test]
    fn prepare_log_file_rotates_before_it_opens() {
        use std::io::Write;
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");
        std::fs::write(&log, "an oversized previous run\n").unwrap();

        let mut file = super::prepare_log_file_at(&log, 4).expect("the log opens");
        file.write_all(b"this run\n").unwrap();
        file.flush().unwrap();
        drop(file);

        assert_eq!(
            std::fs::read_to_string(dir.path().join("corvex.log.1")).unwrap(),
            "an oversized previous run\n",
            "the previous generation is kept under .1"
        );
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "this run\n",
            "the returned handle writes to the file that now bears the log's name"
        );
    }

    /// The threshold `prepare_log_file` actually passes is the documented 5 MB,
    /// not the one a test made up: a log under it is left where it is.
    #[test]
    fn prepare_log_file_leaves_a_log_under_the_five_megabyte_threshold_alone() {
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");
        std::fs::write(&log, "well under 5 MB\n").unwrap();

        drop(super::prepare_log_file(&log).expect("the log opens"));

        assert!(
            !dir.path().join("corvex.log.1").exists(),
            "nothing to rotate below {} bytes",
            crate::config::LOG_MAX_BYTES
        );
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "well under 5 MB\n",
            "and the existing records survive"
        );
    }

    /// "Never both" is the whole point of the fork: when the logger will carry
    /// the error, `main` must not also print it, or a terminal that is watching
    /// stderr sees the failure twice. When the filter drops it, stderr is the
    /// only sink left and must get it.
    #[test]
    fn the_terminal_error_goes_to_exactly_one_sink() {
        let mut printed = Vec::new();
        super::report_terminal_error("no route to host", true, &mut printed);
        assert!(
            printed.is_empty(),
            "the logger has it; printing again would double the line: {:?}",
            String::from_utf8_lossy(&printed)
        );

        let mut printed = Vec::new();
        super::report_terminal_error("no route to host", false, &mut printed);
        let out = String::from_utf8(printed).unwrap();
        assert!(
            out.contains("no route to host"),
            "RUST_LOG=off still owes stderr the reason: {out}"
        );
        assert_eq!(
            out.matches("no route to host").count(),
            1,
            "and owes it once: {out}"
        );
    }

    #[test]
    fn default_level_is_info_and_rises_to_debug_when_asked() {
        assert_eq!(super::default_level(false), "info");
        assert_eq!(super::default_level(true), "debug");
    }

    #[test]
    fn a_debug_record_is_dropped_at_the_default_level() {
        use log::Log;
        let dir = crate::config::test_tempdir();
        let log = dir.path().join("corvex.log");
        let file = super::prepare_log_file(&log).unwrap();

        let logger = super::logger_builder(isolated_env(), Some(file)).build();
        logger.log(
            &log::Record::builder()
                .level(log::Level::Debug)
                .target("corvex")
                .args(format_args!("noisy detail"))
                .build(),
        );
        logger.flush();

        assert_eq!(std::fs::read_to_string(&log).unwrap(), "");
    }

    /// The diagnostic half of the mock: `list_system_resolvers` hands back the
    /// resolver list a test configured, verbatim and including a domain-less
    /// global resolver, so `cmd_dns` rendering can be driven from it.
    #[test]
    fn recording_platform_returns_the_resolvers_it_was_given() {
        let plat = RecordingPlatform {
            resolvers: vec![
                ResolverEntry {
                    domain: None,
                    nameservers: vec!["10.10.20.53".to_string(), "10.10.20.54".to_string()],
                    interface: None,
                },
                ResolverEntry {
                    domain: Some("corp.example.com".to_string()),
                    nameservers: vec!["10.10.20.53".to_string()],
                    interface: Some("en0".to_string()),
                },
            ],
            ..Default::default()
        };

        let resolvers = plat.list_system_resolvers().expect("mock never fails");

        assert_eq!(resolvers.len(), 2);
        assert_eq!(resolvers[0].domain, None, "the global resolver survives");
        assert_eq!(
            resolvers[0].nameservers.len(),
            2,
            "both nameservers survive"
        );
        assert_eq!(*plat.calls.borrow(), ["list_system_resolvers"]);
    }

    /// An address with no configured hop gets the reachable default; the one a
    /// test configured as unreachable keeps its verdict. Both lookups are
    /// recorded with the address, which is how a test can later assert that a
    /// probe was skipped.
    #[test]
    fn recording_platform_answers_configured_and_default_next_hops() {
        let plat = RecordingPlatform {
            next_hops: BTreeMap::from([(
                "10.10.20.54".to_string(),
                RecordingPlatform::unreachable_next_hop(),
            )]),
            ..Default::default()
        };

        let healthy = plat
            .next_hop_status("10.10.20.53")
            .expect("mock never fails");
        assert_eq!(healthy, RecordingPlatform::default_next_hop());
        assert!(healthy.on_link);

        let stale = plat
            .next_hop_status("10.10.20.54")
            .expect("mock never fails");
        assert!(!stale.on_link, "the configured verdict must win");
        assert_eq!(stale.gateway.as_deref(), Some("10.10.99.1"));
        assert_eq!(stale.interface, "en0");

        assert_eq!(
            *plat.calls.borrow(),
            [
                "next_hop_status(10.10.20.53)",
                "next_hop_status(10.10.20.54)",
            ],
            "each lookup is recorded with the address it asked about"
        );
    }

    // -- cmd_dns --

    /// Stand-in for `netdiag::probe_udp53`: records every address it was asked
    /// to probe and answers from a canned result, so the report renders without
    /// a socket. The record is the whole point — "this nameserver was never
    /// probed" is only provable if every probe leaves a trace.
    struct ProbeRecorder {
        probed: RefCell<Vec<(String, std::time::Duration)>>,
        answer: Result<std::time::Duration, String>,
    }

    impl ProbeRecorder {
        fn answering_in(millis: u64) -> Self {
            ProbeRecorder {
                probed: RefCell::new(Vec::new()),
                answer: Ok(std::time::Duration::from_millis(millis)),
            }
        }

        fn failing(reason: &str) -> Self {
            ProbeRecorder {
                probed: RefCell::new(Vec::new()),
                answer: Err(reason.to_string()),
            }
        }

        fn probe(
            &self,
            nameserver: &str,
            timeout: std::time::Duration,
        ) -> anyhow::Result<std::time::Duration> {
            self.probed
                .borrow_mut()
                .push((nameserver.to_string(), timeout));
            match &self.answer {
                Ok(elapsed) => Ok(*elapsed),
                Err(reason) => anyhow::bail!("{reason}"),
            }
        }

        fn addresses(&self) -> Vec<String> {
            self.probed
                .borrow()
                .iter()
                .map(|(nameserver, _)| nameserver.clone())
                .collect()
        }
    }

    /// The incident this command exists for: a resolver whose route points at a
    /// gateway that is not on the interface's subnet. It must be named, and the
    /// probe must not be attempted — probing could only spend the timeout
    /// rediscovering what the route already said.
    #[test]
    fn cmd_dns_reports_an_unreachable_next_hop_and_skips_its_probe() {
        let dir = crate::config::test_tempdir();
        let config = temp_config(dir.path(), "xray");
        let plat = RecordingPlatform {
            resolvers: vec![ResolverEntry {
                domain: Some("corp.example.com".to_string()),
                nameservers: vec!["10.10.20.53".to_string(), "10.10.20.54".to_string()],
                interface: Some("en0".to_string()),
            }],
            next_hops: BTreeMap::from([(
                "10.10.20.54".to_string(),
                RecordingPlatform::unreachable_next_hop(),
            )]),
            ..Default::default()
        };
        let probe = ProbeRecorder::answering_in(12);

        let mut buf: Vec<u8> = Vec::new();
        super::cmd_dns_with(&config, &plat, &mut buf, |ns, timeout| {
            probe.probe(ns, timeout)
        })
        .expect("one unreachable resolver must not fail the whole report");

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("UNREACHABLE NEXT HOP"),
            "the off-link resolver must be called out: {output}"
        );
        assert!(
            output.contains("10.10.99.1") && output.contains("en0"),
            "the verdict must name the gateway and the interface: {output}"
        );
        assert_eq!(
            probe.addresses(),
            ["10.10.20.53"],
            "only the on-link nameserver may be probed: {output}"
        );
        assert!(
            plat.calls
                .borrow()
                .contains(&"next_hop_status(10.10.20.54)".to_string()),
            "the skipped nameserver was still looked up, so the skip is a verdict \
             and not an oversight: {:?}",
            plat.calls.borrow()
        );
    }

    /// macOS prints one `resolver #N` block per split-DNS search domain, and a
    /// corporate VPN points a dozen of them at the same failover pair. Each
    /// address is therefore diagnosed once and its line reused: without that, a
    /// silent-but-on-link pair spends the 2s probe timeout once per block and
    /// the report takes a minute to say the same thing twelve times.
    #[test]
    fn cmd_dns_diagnoses_a_repeated_nameserver_only_once() {
        let dir = crate::config::test_tempdir();
        let config = temp_config(dir.path(), "xray");
        let shared = || ResolverEntry {
            nameservers: vec!["10.10.20.53".to_string()],
            interface: Some("en0".to_string()),
            domain: None,
        };
        let plat = RecordingPlatform {
            resolvers: vec![
                ResolverEntry {
                    domain: Some("corp.example.com".to_string()),
                    ..shared()
                },
                ResolverEntry {
                    domain: Some("intranet.example.com".to_string()),
                    ..shared()
                },
            ],
            ..Default::default()
        };
        let probe = ProbeRecorder::answering_in(12);

        let mut buf: Vec<u8> = Vec::new();
        super::cmd_dns_with(&config, &plat, &mut buf, |ns, timeout| {
            probe.probe(ns, timeout)
        })
        .expect("the report renders");
        let report = String::from_utf8(buf).unwrap();

        assert_eq!(
            probe.probed.borrow().len(),
            1,
            "one probe for one address, however many resolvers name it: {:?}",
            probe.probed.borrow()
        );
        assert_eq!(
            plat.calls
                .borrow()
                .iter()
                .filter(|call| call.starts_with("next_hop_status"))
                .count(),
            1,
            "and one route lookup: {:?}",
            plat.calls.borrow()
        );
        // Memoized, not suppressed: both blocks still carry the full line.
        assert_eq!(
            report.matches("10.10.20.53").count(),
            2,
            "each resolver block still reports the nameserver: {report}"
        );
        assert!(report.contains("corp.example.com"), "{report}");
        assert!(report.contains("intranet.example.com"), "{report}");
    }

    #[test]
    fn cmd_dns_renders_the_interface_and_gateway_of_a_healthy_resolver() {
        let dir = crate::config::test_tempdir();
        let config = temp_config(dir.path(), "xray");
        let plat = RecordingPlatform {
            resolvers: vec![ResolverEntry {
                domain: Some("corp.example.com".to_string()),
                nameservers: vec!["10.10.20.53".to_string()],
                interface: Some("en0".to_string()),
            }],
            ..Default::default()
        };
        let probe = ProbeRecorder::answering_in(12);

        let mut buf: Vec<u8> = Vec::new();
        super::cmd_dns_with(&config, &plat, &mut buf, |ns, timeout| {
            probe.probe(ns, timeout)
        })
        .expect("a healthy resolver must render");

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("corp.example.com"),
            "the resolver's domain must appear: {output}"
        );
        assert!(
            output.contains("10.10.20.53"),
            "the nameserver address must appear: {output}"
        );
        assert!(
            output.contains("via 192.0.2.1") && output.contains("on en0"),
            "the gateway and interface must appear: {output}"
        );
        assert!(
            output.contains("answered in 12ms"),
            "the probe result must appear: {output}"
        );
        assert_eq!(
            probe.probed.borrow()[0].1,
            super::DNS_PROBE_TIMEOUT,
            "the probe must get the command's timeout, not one of its own"
        );
    }

    /// A resolver with no `domain` line is the system default. It has to be in
    /// the report: when it is broken, everything that is not split-DNS breaks
    /// with it.
    #[test]
    fn cmd_dns_lists_a_resolver_with_no_domain() {
        let dir = crate::config::test_tempdir();
        let config = temp_config(dir.path(), "xray");
        let plat = RecordingPlatform {
            resolvers: vec![ResolverEntry {
                domain: None,
                nameservers: vec!["192.0.2.53".to_string()],
                interface: None,
            }],
            ..Default::default()
        };
        let probe = ProbeRecorder::answering_in(8);

        let mut buf: Vec<u8> = Vec::new();
        super::cmd_dns_with(&config, &plat, &mut buf, |ns, timeout| {
            probe.probe(ns, timeout)
        })
        .expect("a global resolver must render");

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("global"),
            "a domain-less resolver must be labelled global: {output}"
        );
        assert!(
            output.contains("192.0.2.53"),
            "its nameserver must still be reported: {output}"
        );
        assert_eq!(probe.addresses(), ["192.0.2.53"], "and still probed");
    }

    #[test]
    fn cmd_dns_reports_a_probe_that_did_not_answer() {
        let dir = crate::config::test_tempdir();
        let config = temp_config(dir.path(), "xray");
        let plat = RecordingPlatform {
            resolvers: vec![ResolverEntry {
                domain: Some("corp.example.com".to_string()),
                nameservers: vec!["10.10.20.53".to_string()],
                interface: Some("en0".to_string()),
            }],
            ..Default::default()
        };
        let probe = ProbeRecorder::failing("no DNS reply within 2s");

        let mut buf: Vec<u8> = Vec::new();
        super::cmd_dns_with(&config, &plat, &mut buf, |ns, timeout| {
            probe.probe(ns, timeout)
        })
        .expect("a silent resolver is a finding, not a command failure");

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("no answer: no DNS reply within 2s"),
            "the probe's own reason must survive into the report: {output}"
        );
    }

    #[test]
    fn cmd_dns_says_so_when_there_are_no_resolvers() {
        let dir = crate::config::test_tempdir();
        let config = temp_config(dir.path(), "xray");
        let plat = RecordingPlatform::default();
        let probe = ProbeRecorder::answering_in(1);

        let mut buf: Vec<u8> = Vec::new();
        super::cmd_dns_with(&config, &plat, &mut buf, |ns, timeout| {
            probe.probe(ns, timeout)
        })
        .expect("an empty resolver list is reportable, not an error");

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("No resolvers to diagnose were reported by the system."),
            "an empty list must be stated rather than rendered as silence, and \
             stated as what corvex could list rather than what the machine has: {output}"
        );
        assert!(
            probe.addresses().is_empty(),
            "nothing to probe means nothing probed"
        );
    }

    /// The listing is the one step with nothing to fall back on — Windows takes
    /// this path unconditionally — so its failure must surface as an error with
    /// context, not as an empty report.
    #[test]
    fn cmd_dns_fails_with_context_when_the_resolvers_cannot_be_listed() {
        let dir = crate::config::test_tempdir();
        let config = temp_config(dir.path(), "xray");
        let plat = RecordingPlatform {
            fail_list_system_resolvers: true,
            ..Default::default()
        };
        let probe = ProbeRecorder::answering_in(1);

        let mut buf: Vec<u8> = Vec::new();
        let result = super::cmd_dns_with(&config, &plat, &mut buf, |ns, timeout| {
            probe.probe(ns, timeout)
        });
        let error = result.expect_err("an unlistable system is a command failure");

        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("failed to list the system resolvers"),
            "the context must say which step failed: {rendered}"
        );
        assert!(
            probe.addresses().is_empty(),
            "nothing may be probed once the listing failed"
        );
    }

    /// One nameserver whose route cannot be read must not end the walk: the
    /// other half of a failover pair is often the working one.
    #[test]
    fn cmd_dns_steps_over_a_nameserver_whose_route_cannot_be_read() {
        let dir = crate::config::test_tempdir();
        let config = temp_config(dir.path(), "xray");
        let plat = RecordingPlatform {
            resolvers: vec![ResolverEntry {
                domain: Some("corp.example.com".to_string()),
                nameservers: vec!["10.10.20.53".to_string(), "10.10.20.54".to_string()],
                interface: Some("en0".to_string()),
            }],
            fail_next_hop_status_for: BTreeSet::from(["10.10.20.53".to_string()]),
            ..Default::default()
        };
        let probe = ProbeRecorder::answering_in(9);

        let mut buf: Vec<u8> = Vec::new();
        super::cmd_dns_with(&config, &plat, &mut buf, |ns, timeout| {
            probe.probe(ns, timeout)
        })
        .expect("one unreadable route is a finding, not a command failure");

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("10.10.20.53") && output.contains("no route:"),
            "the unreadable one must be named and explained: {output}"
        );
        assert!(
            output.contains("answered in 9ms"),
            "the walk must reach the second nameserver: {output}"
        );
        assert_eq!(
            probe.addresses(),
            ["10.10.20.54"],
            "only the nameserver with a readable route is probed: {output}"
        );
    }

    /// A router advertising RDNSS puts `fe80::1%en0` in `scutil --dns`. Neither
    /// `route -n get` nor `IpAddr::from_str` accepts a zone id, so walking one
    /// would print a red failure for a healthy resolver. It is listed and
    /// stepped over instead.
    #[test]
    fn cmd_dns_lists_a_zone_scoped_nameserver_without_diagnosing_it() {
        let dir = crate::config::test_tempdir();
        let config = temp_config(dir.path(), "xray");
        let plat = RecordingPlatform {
            resolvers: vec![ResolverEntry {
                domain: None,
                nameservers: vec!["fe80::1%en0".to_string(), "192.0.2.53".to_string()],
                interface: Some("en0".to_string()),
            }],
            ..Default::default()
        };
        let probe = ProbeRecorder::answering_in(4);

        let mut buf: Vec<u8> = Vec::new();
        super::cmd_dns_with(&config, &plat, &mut buf, |ns, timeout| {
            probe.probe(ns, timeout)
        })
        .expect("an IPv6 nameserver must not fail the report");

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("fe80::1%en0") && output.contains("not diagnosed"),
            "it must be listed, and said to be undiagnosed: {output}"
        );
        assert!(
            !output.contains("no answer") && !output.contains("no route"),
            "a limit of the tool must not be rendered as a resolver fault: {output}"
        );
        assert_eq!(
            probe.addresses(),
            ["192.0.2.53"],
            "only the IPv4 nameserver is probed: {output}"
        );
        assert_eq!(
            *plat.calls.borrow(),
            ["list_system_resolvers", "next_hop_status(192.0.2.53)"],
            "no route lookup is attempted for the zone-scoped literal"
        );
    }

    #[test]
    fn resolver_heading_names_the_domain_and_interface() {
        let entry = ResolverEntry {
            domain: Some("corp.example.com".to_string()),
            nameservers: vec!["10.10.20.53".to_string()],
            interface: Some("en0".to_string()),
        };
        assert_eq!(
            super::resolver_heading(&entry),
            "Resolver: domain corp.example.com on en0"
        );
    }

    #[test]
    fn resolver_heading_marks_a_domainless_resolver_global() {
        let entry = ResolverEntry {
            domain: None,
            nameservers: vec!["192.0.2.53".to_string()],
            interface: None,
        };
        assert_eq!(
            super::resolver_heading(&entry),
            "Resolver: global (no domain scope)"
        );
    }

    #[test]
    fn nameserver_line_renders_a_directly_connected_resolver() {
        let hop = NextHop {
            gateway: None,
            interface: "en0".to_string(),
            on_link: true,
        };
        let line = super::nameserver_line(
            "192.0.2.53",
            &hop,
            &super::NameserverVerdict::Answered(std::time::Duration::from_millis(3)),
        );
        assert!(
            line.contains("directly connected on en0"),
            "a gateway-less route is not a fault and must not read like one: {line}"
        );
        assert!(line.contains("answered in 3ms"), "{line}");
    }

    /// Latency shares `format_elapsed` with the start-path progress lines, so a
    /// pathologically slow resolver reads in seconds rather than four digits of
    /// milliseconds.
    #[test]
    fn nameserver_line_renders_a_slow_answer_in_seconds() {
        let hop = RecordingPlatform::default_next_hop();
        let line = super::nameserver_line(
            "10.10.20.53",
            &hop,
            &super::NameserverVerdict::Answered(std::time::Duration::from_millis(1500)),
        );
        assert!(line.contains("answered in 1.50s"), "{line}");
    }

    #[test]
    fn test_dns_command_parses() {
        let cli = Cli::try_parse_from(["corvex", "dns"]).unwrap();
        assert!(matches!(cli.command, super::Commands::Dns));
    }
}
