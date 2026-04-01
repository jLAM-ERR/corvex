mod config;
mod dns;
mod domain;
mod network;
mod proxy;
mod vless;
mod xray;

use clap::{Parser, Subcommand};
use colored::Colorize;
use config::Config;
use domain::RouteTarget;
use std::process::{self, Command};

#[derive(Parser)]
#[command(
    name = "xray-proxy",
    about = "Manage Xray proxy and macOS system proxy"
)]
struct Cli {
    /// Path to xray config file (overrides default)
    #[arg(long = "config", global = true)]
    config_path: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start xray and enable system proxy
    Start,
    /// Disable system proxy and stop xray
    Stop,
    /// Restart xray (stop + start)
    Restart,
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
    /// Parse VLESS URI and update xray config
    Load {
        /// VLESS URI (vless://...)
        uri: String,
    },
    /// Manage domain routing rules
    Domain {
        #[command(subcommand)]
        subcommand: DomainCommands,
    },
    /// Manage corporate DNS mappings
    Dns {
        #[command(subcommand)]
        subcommand: DnsCommands,
    },
}

#[derive(Subcommand)]
enum DomainCommands {
    /// List all domain entries
    List {
        /// Route target (direct or proxy)
        target: RouteTarget,
    },
    /// Add a domain entry
    Add {
        /// Route target (direct or proxy)
        target: RouteTarget,
        /// Entry (e.g. "domain:example.com" or "regex:.*\\.corp$")
        entry: String,
    },
    /// Remove a domain entry
    Remove {
        /// Route target (direct or proxy)
        target: RouteTarget,
        /// Entry to remove (exact match)
        entry: String,
    },
    /// Search domain entries
    Find {
        /// Route target (direct or proxy)
        target: RouteTarget,
        /// Search pattern (substring match)
        pattern: String,
    },
}

#[derive(Subcommand)]
enum DnsCommands {
    /// List all DNS mappings
    List,
    /// Add or update a DNS mapping
    Add {
        /// Domain name
        domain: String,
        /// DNS server IP address
        server: String,
    },
    /// Remove a DNS mapping
    Remove {
        /// Domain name to remove
        domain: String,
    },
    /// Discover corp DNS from system (scutil --dns) and populate corp-dns.json
    Init,
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::new(cli.config_path.as_deref());

    match cli.command {
        Commands::Start => cmd_start(&config),
        Commands::Stop => cmd_stop(&config),
        Commands::Restart => cmd_restart(&config),
        Commands::Reload => cmd_reload(&config),
        Commands::Status => cmd_status(&config),
        Commands::Logs { follow } => cmd_logs(&config, follow),
        Commands::Load { uri } => cmd_load(&config, &uri),
        Commands::Domain { subcommand } => cmd_domain(&config, subcommand),
        Commands::Dns { subcommand } => cmd_dns(&config, subcommand),
    }
}

fn cmd_start(config: &Config) -> anyhow::Result<()> {
    // Sync corp DNS into xray config before starting
    if config.corp_dns.exists() && config.xray_config.exists() {
        let count = dns::sync_to_config(config)?;
        if count > 0 {
            println!(
                "{}",
                format!("Synced {count} corp DNS mappings to config").green()
            );
        }
    }

    println!("{}", "Starting xray...".yellow());
    println!("  Config: {}", config.xray_config.display());
    println!("  Log:    {}", config.xray_log.display());

    let pid = xray::start(config)?;
    println!("{}", format!("xray started (PID: {pid})").green());

    println!();
    let service = network::detect_active_service()?;
    println!("Network service: {}", service.yellow());
    println!("{}", "Enabling system proxy...".yellow());

    proxy::enable(&service, config)?;

    println!("{}", "System proxy enabled".green());
    println!("  Proxy: {}:{}", config.socks_host, config.socks_port);

    Ok(())
}

fn cmd_stop(config: &Config) -> anyhow::Result<()> {
    let service = network::detect_active_service()?;
    println!("Network service: {}", service.yellow());

    println!("{}", "Disabling system proxy...".yellow());
    proxy::disable(&service)?;
    println!("{}", "System proxy disabled".green());

    println!();
    println!("{}", "Stopping xray...".yellow());
    xray::stop(config)?;
    println!("{}", "xray stopped".green());

    Ok(())
}

fn cmd_restart(config: &Config) -> anyhow::Result<()> {
    let service = network::detect_active_service()?;
    println!("Network service: {}", service.yellow());

    // Stop proxy + xray, ignoring "not running"
    let _ = proxy::disable(&service);
    match xray::stop(config) {
        Ok(()) => println!("{}", "xray stopped".green()),
        Err(e) => {
            if e.downcast_ref::<xray::XrayError>()
                .is_some_and(|xe| matches!(xe, xray::XrayError::NotRunning))
            {
                println!("{}", "xray was not running".yellow());
            } else {
                return Err(e);
            }
        }
    }

    println!();

    // Start xray + proxy
    println!("{}", "Starting xray...".yellow());
    let pid = xray::start(config)?;
    println!("{}", format!("xray started (PID: {pid})").green());

    println!("{}", "Enabling system proxy...".yellow());
    proxy::enable(&service, config)?;
    println!("{}", "System proxy enabled".green());
    println!("  Proxy: {}:{}", config.socks_host, config.socks_port);

    Ok(())
}

fn cmd_reload(config: &Config) -> anyhow::Result<()> {
    println!("{}", "Validating config...".yellow());
    xray::reload(config)?;
    println!("{}", "Config reloaded (SIGHUP sent)".green());
    Ok(())
}

fn cmd_status(config: &Config) -> anyhow::Result<()> {
    let service = network::detect_active_service()?;
    println!("Network service: {}", service.yellow());
    println!();

    // Xray process
    println!("=== Xray process ===");
    match xray::is_running(config) {
        Some(pid) => println!("{}", format!("Running (PID: {pid})").green()),
        None => println!("{}", "Not running".red()),
    }

    // Ports
    println!();
    println!("=== Ports ===");
    for port in &[config.socks_port, config.http_port] {
        let listening = Command::new("lsof")
            .args(["-i", &format!(":{port}")])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if listening {
            println!("{}", format!("Port {port} listening").green());
        } else {
            println!("{}", format!("Port {port} not listening").red());
        }
    }

    // Proxy status
    println!();
    println!("=== Proxy settings ===");
    match proxy::status(&service) {
        Ok((socks, http, https)) => {
            print_proxy_line("SOCKS5", &socks);
            print_proxy_line("HTTP", &http);
            print_proxy_line("HTTPS", &https);
        }
        Err(e) => println!("{}", format!("Failed to query proxy: {e}").red()),
    }

    // Last log lines
    if config.xray_log.exists() {
        println!();
        println!("=== Last 5 log lines ===");
        let _ = Command::new("tail")
            .args(["-5"])
            .arg(&config.xray_log)
            .status();
    }

    Ok(())
}

fn print_proxy_line(label: &str, info: &proxy::ProxyInfo) {
    if info.enabled {
        println!(
            "  {label}: {} ({}:{})",
            "ON".green(),
            info.server,
            info.port
        );
    } else {
        println!("  {label}: {}", "OFF".red());
    }
}

fn cmd_logs(config: &Config, follow: bool) -> anyhow::Result<()> {
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

fn cmd_load(config: &Config, uri: &str) -> anyhow::Result<()> {
    println!("{}", "Parsing VLESS URI...".yellow());
    let params = vless::parse_vless_uri(uri)?;

    println!("  UUID:        {}", params.uuid);
    println!("  Host:        {}", params.host);
    println!("  Port:        {}", params.port);
    println!("  Name:        {}", params.name);
    println!("  Network:     {}", params.network);
    println!("  Security:    {}", params.security);
    println!("  SNI:         {}", params.sni);
    println!("  Fingerprint: {}", params.fingerprint);
    if !params.alpn.is_empty() {
        println!("  ALPN:        {}", params.alpn.join(", "));
    }

    println!();

    if config.xray_config.exists() {
        println!("{}", "Updating xray config...".yellow());
        vless::apply_to_config(&params, &config.xray_config)?;
        println!(
            "{}",
            format!("Config updated: {}", config.xray_config.display()).green()
        );
    } else {
        println!("{}", "Creating xray config...".yellow());
        if let Some(parent) = config.xray_config.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let new_config = vless::create_config(&params, config.socks_port, config.http_port);
        let pretty = serde_json::to_string_pretty(&new_config)?;
        std::fs::write(&config.xray_config, pretty)?;
        println!(
            "{}",
            format!("Config created: {}", config.xray_config.display()).green()
        );
    }

    Ok(())
}

fn cmd_domain(config: &Config, subcommand: DomainCommands) -> anyhow::Result<()> {
    match subcommand {
        DomainCommands::List { target } => {
            let entries = domain::list(target, config)?;
            if entries.is_empty() {
                println!("No {} domain entries", target);
            } else {
                for entry in &entries {
                    println!("  {entry}");
                }
                println!();
                println!("{} entries", entries.len());
            }
        }
        DomainCommands::Add { target, entry } => {
            domain::add(target, &entry, config)?;
            println!("{}", format!("Added to {target}: {entry}").green());
        }
        DomainCommands::Remove { target, entry } => {
            domain::remove(target, &entry, config)?;
            println!("{}", format!("Removed from {target}: {entry}").green());
        }
        DomainCommands::Find { target, pattern } => {
            let results = domain::find(target, &pattern, config)?;
            if results.is_empty() {
                println!("No matches for '{pattern}' in {target}");
            } else {
                for entry in &results {
                    println!("  {entry}");
                }
                println!();
                println!("{} matches", results.len());
            }
        }
    }
    Ok(())
}

fn cmd_dns(config: &Config, subcommand: DnsCommands) -> anyhow::Result<()> {
    match subcommand {
        DnsCommands::List => {
            let map = dns::list(config)?;
            if map.is_empty() {
                println!("No DNS mappings");
            } else {
                for (domain, server) in &map {
                    println!("  {domain} -> {server}");
                }
                println!();
                println!("{} mappings", map.len());
            }
        }
        DnsCommands::Add { domain, server } => {
            let was_update = dns::add(&domain, &server, config)?;
            if was_update {
                println!("{}", format!("Updated: {domain} -> {server}").green());
            } else {
                println!("{}", format!("Added: {domain} -> {server}").green());
            }
        }
        DnsCommands::Remove { domain } => {
            dns::remove(&domain, config)?;
            println!("{}", format!("Removed: {domain}").green());
        }
        DnsCommands::Init => {
            if config.corp_dns.exists() {
                println!(
                    "{}",
                    format!(
                        "{} already exists, use 'dns list' to view",
                        config.corp_dns.display()
                    )
                    .yellow()
                );
                return Ok(());
            }
            println!("{}", "Discovering corp DNS from scutil --dns...".yellow());
            let map = dns::init(config)?;
            for (domain, server) in &map {
                println!("  {domain} -> {server}");
            }
            println!();
            println!(
                "{}",
                format!(
                    "{} mappings saved to {}",
                    map.len(),
                    config.corp_dns.display()
                )
                .green()
            );
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{}: {e:#}", "Error".red());
        process::exit(1);
    }
}
