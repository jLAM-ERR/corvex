use super::{Platform, ProxyInfo, ProxyStatus};
use anyhow::{Context, Result};
use log::debug;
use std::collections::BTreeMap;
use std::process::Command;

pub struct MacOsPlatform;

impl MacOsPlatform {
    pub fn new() -> Self {
        MacOsPlatform
    }
}

/// Outcome of one `networksetup` invocation, with "needs admin" kept apart
/// from a real failure so the caller decides when (and how widely) to escalate.
#[derive(Debug, PartialEq)]
enum NsOutcome {
    Ok(String),
    NeedsAdmin,
    Failed(String),
}

/// Decide the outcome from already-captured process output, without spawning
/// anything, so the decision itself is unit testable.
fn classify_networksetup_output(exit_ok: bool, stdout: &str, stderr: &str) -> NsOutcome {
    // networksetup reports errors inconsistently across macOS versions:
    // sometimes on stderr, sometimes on stdout (e.g. "** Error: Command
    // requires admin privileges."), and not always with a failing exit code.
    // Classify on the combined output so an error written to either stream
    // is caught, even when the exit code is 0.
    let detail = join_output(stdout, stderr);
    if !exit_ok || detail.contains("** Error") {
        if is_admin_required_error(&detail) {
            return NsOutcome::NeedsAdmin;
        }
        return NsOutcome::Failed(detail);
    }
    NsOutcome::Ok(stdout.to_string())
}

/// Runs one `networksetup` invocation and classifies the result. Returns
/// `Err` only when the process itself could not be spawned.
fn try_networksetup(args: &[&str]) -> Result<NsOutcome> {
    let output = Command::new("networksetup")
        .args(args)
        .output()
        .with_context(|| format!("Failed to run: networksetup {}", args.join(" ")))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Ok(classify_networksetup_output(
        output.status.success(),
        &stdout,
        &stderr,
    ))
}

fn run_networksetup(args: &[&str]) -> Result<String> {
    match try_networksetup(args)? {
        NsOutcome::Ok(stdout) => Ok(stdout),
        NsOutcome::NeedsAdmin => {
            debug!(
                "admin required for networksetup {}, escalating via osascript",
                args.join(" ")
            );
            // Nothing has been applied yet: this is the only command, and it just reported NeedsAdmin.
            run_networksetup_elevated(&[args.to_vec()], false)
        }
        NsOutcome::Failed(detail) => {
            anyhow::bail!("networksetup {} failed: {}", args.join(" "), detail)
        }
    }
}

/// Runs a sequence of `networksetup` commands unelevated, in order. The
/// moment one needs admin, the whole sequence is re-run through a single
/// osascript prompt instead of escalating per command.
fn run_networksetup_all(commands: &[Vec<&str>]) -> Result<()> {
    if commands.is_empty() {
        return Ok(());
    }

    for (i, args) in commands.iter().enumerate() {
        match try_networksetup(args)? {
            NsOutcome::Ok(_) => continue,
            NsOutcome::NeedsAdmin => {
                debug!(
                    "admin required for networksetup {}, escalating {} commands into one osascript prompt",
                    args.join(" "),
                    commands.len()
                );
                // If an earlier command in this batch already ran unelevated, its
                // effect already happened, regardless of what the user does next.
                let already_applied = i > 0;
                run_networksetup_elevated(commands, already_applied)?;
                return Ok(());
            }
            NsOutcome::Failed(detail) => {
                anyhow::bail!("networksetup {} failed: {}", args.join(" "), detail);
            }
        }
    }

    Ok(())
}

/// Combine stdout and stderr into one error detail string.
fn join_output(stdout: &str, stderr: &str) -> String {
    [stdout.trim(), stderr.trim()]
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Message for when the elevation prompt was denied or canceled.
/// `already_applied` distinguishes a cancel on the very first command
/// (nothing changed yet) from a cancel mid-batch (some earlier commands
/// already ran unelevated and cannot be undone by canceling this one).
fn authorization_denied_message(already_applied: bool) -> String {
    if already_applied {
        "Authorization denied — some proxy settings from earlier in this batch may already have been applied before you canceled"
            .to_string()
    } else {
        "Authorization denied — proxy settings were not changed".to_string()
    }
}

/// Message for a networksetup batch that failed while running elevated,
/// once `detail` (the combined stdout/stderr of the failed run) is known.
fn batch_failure_message(commands: &[Vec<&str>], detail: &str) -> String {
    let commands_str = commands
        .iter()
        .map(|args| args.join(" "))
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "networksetup batch failed (elevated): {}\ncommands run in order, stopped at the first failure above — earlier ones in this list may already be applied: {}",
        detail, commands_str
    )
}

/// Outcome of one elevated osascript run, decided from already-captured
/// output so the decision itself is unit testable without spawning anything.
#[derive(Debug, PartialEq)]
enum ElevatedOutcome {
    Ok(String),
    Cancelled,
    NoGui,
    Failed(String),
}

/// Decides the outcome of an elevated osascript run. A nonzero exit is
/// classified the same way it always was (cancel, no-GUI, or a generic
/// failure). But a zero exit is not trusted on its own: `networksetup` can
/// print "** Error: ..." to either stream while still exiting 0, even inside
/// the `&&`-chained elevated shell, so the remaining commands run anyway and
/// look like success. Combined output is checked for that marker regardless
/// of exit status.
fn classify_elevated_output(exit_ok: bool, stdout: &str, stderr: &str) -> ElevatedOutcome {
    if !exit_ok {
        if is_user_cancel_error(stderr) {
            return ElevatedOutcome::Cancelled;
        }
        if is_no_gui_error(stderr) {
            return ElevatedOutcome::NoGui;
        }
        return ElevatedOutcome::Failed(join_output(stdout, stderr));
    }
    let detail = join_output(stdout, stderr);
    if detail.contains("** Error") {
        return ElevatedOutcome::Failed(detail);
    }
    ElevatedOutcome::Ok(stdout.to_string())
}

/// Runs `commands` through a single osascript elevation prompt.
/// `already_applied` must be true if any of `commands` already ran
/// unelevated and succeeded before this call, so a cancel here does not
/// undo that: the caller knows this, `run_networksetup_elevated` does not.
fn run_networksetup_elevated(commands: &[Vec<&str>], already_applied: bool) -> Result<String> {
    if commands.is_empty() {
        anyhow::bail!("run_networksetup_elevated called with no commands to run");
    }
    let script = build_osascript_command(commands);
    let output = Command::new("osascript")
        .args(["-e", &script])
        .output()
        .context("Failed to run osascript for privilege escalation")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    match classify_elevated_output(output.status.success(), &stdout, &stderr) {
        ElevatedOutcome::Ok(stdout) => Ok(stdout),
        ElevatedOutcome::Cancelled => {
            anyhow::bail!("{}", authorization_denied_message(already_applied))
        }
        ElevatedOutcome::NoGui => {
            anyhow::bail!("No GUI session available — run with sudo instead")
        }
        ElevatedOutcome::Failed(detail) => {
            anyhow::bail!("{}", batch_failure_message(commands, &detail))
        }
    }
}

/// Ordered `networksetup` setters that enable socks, web, and secure web
/// proxies for a service. Each host/port setter must precede its matching
/// state-on command, or the proxy would flip on pointing at a stale address.
fn enable_proxy_commands<'a>(service: &'a str, host: &'a str, port: &'a str) -> Vec<Vec<&'a str>> {
    vec![
        vec!["-setsocksfirewallproxy", service, host, port],
        vec!["-setsocksfirewallproxystate", service, "on"],
        vec!["-setwebproxy", service, host, port],
        vec!["-setwebproxystate", service, "on"],
        vec!["-setsecurewebproxy", service, host, port],
        vec!["-setsecurewebproxystate", service, "on"],
    ]
}

/// Ordered `networksetup` setters that turn off socks, web, and secure web
/// proxies for a service.
fn disable_proxy_commands(service: &str) -> Vec<Vec<&str>> {
    vec![
        vec!["-setsocksfirewallproxystate", service, "off"],
        vec!["-setwebproxystate", service, "off"],
        vec!["-setsecurewebproxystate", service, "off"],
    ]
}

impl Platform for MacOsPlatform {
    fn detect_active_service(&self) -> Result<String> {
        let route_output = Command::new("route")
            .args(["get", "default"])
            .output()
            .context("Failed to run 'route get default'")?;
        let route_str = String::from_utf8_lossy(&route_output.stdout);

        let iface = match parse_default_interface(&route_str) {
            Some(iface) => {
                debug!("default interface: {}", iface);
                iface
            }
            None => {
                debug!("no default interface found, falling back to Wi-Fi");
                return Ok("Wi-Fi".to_string());
            }
        };

        let ports_output = Command::new("networksetup")
            .arg("-listallhardwareports")
            .output()
            .context("Failed to run 'networksetup -listallhardwareports'")?;
        let ports_str = String::from_utf8_lossy(&ports_output.stdout);

        let service =
            parse_service_for_interface(&ports_str, &iface).unwrap_or_else(|| "Wi-Fi".to_string());
        debug!("detected network service: '{}'", service);
        Ok(service)
    }

    fn enable_proxy(&self, service: &str, host: &str, port: u16) -> Result<()> {
        debug!("enabling proxies on '{}' -> {}:{}", service, host, port);
        let port_str = port.to_string();
        let commands = enable_proxy_commands(service, host, &port_str);
        run_networksetup_all(&commands)
    }

    fn disable_proxy(&self, service: &str) -> Result<()> {
        debug!("disabling proxies on '{}'", service);
        let commands = disable_proxy_commands(service);
        run_networksetup_all(&commands)
    }

    fn proxy_status(&self, service: &str) -> Result<ProxyStatus> {
        let socks = run_networksetup(&["-getsocksfirewallproxy", service])?;
        let http = run_networksetup(&["-getwebproxy", service])?;
        let https = run_networksetup(&["-getsecurewebproxy", service])?;

        Ok(ProxyStatus {
            socks: parse_proxy_info(&socks),
            http: parse_proxy_info(&http),
            https: parse_proxy_info(&https),
        })
    }

    fn discover_corporate_dns(&self) -> Result<BTreeMap<String, String>> {
        debug!("running scutil --dns to discover corp DNS");
        let output = Command::new("scutil")
            .arg("--dns")
            .output()
            .context("Failed to run scutil --dns")?;

        if !output.status.success() {
            anyhow::bail!("scutil --dns exited with status {}", output.status);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let discovered = crate::dns::parse_scutil_dns(&stdout);
        debug!("discovered {} split-DNS resolvers", discovered.len());

        if discovered.is_empty() {
            anyhow::bail!("No split-DNS resolvers found in scutil --dns output");
        }

        Ok(discovered)
    }
}

/// Extracts the interface name (e.g. "en0") from `route get default` output.
pub fn parse_default_interface(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("interface:") {
            return trimmed
                .strip_prefix("interface:")
                .map(|s| s.trim().to_string());
        }
    }
    None
}

/// Maps an interface name to its network service name from `networksetup -listallhardwareports` output.
pub fn parse_service_for_interface(output: &str, iface: &str) -> Option<String> {
    let mut current_service: Option<String> = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("Hardware Port:") {
            current_service = Some(name.trim().to_string());
        } else if let Some(device) = trimmed.strip_prefix("Device:") {
            if device.trim() == iface {
                return current_service;
            }
        }
    }
    None
}

/// Parse output from networksetup -getwebproxy / -getsocksfirewallproxy / etc.
pub fn parse_proxy_info(output: &str) -> ProxyInfo {
    let mut enabled = false;
    let mut server = String::new();
    let mut port = String::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("Enabled:") {
            enabled = val.trim().eq_ignore_ascii_case("yes");
        } else if let Some(val) = trimmed.strip_prefix("Server:") {
            server = val.trim().to_string();
        } else if let Some(val) = trimmed.strip_prefix("Port:") {
            port = val.trim().to_string();
        }
    }

    ProxyInfo {
        enabled,
        server,
        port,
    }
}

fn shell_escape(arg: &str) -> String {
    let mut escaped = String::new();
    escaped.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            escaped.push_str("'\\''");
        } else {
            escaped.push(ch);
        }
    }
    escaped.push('\'');
    escaped
}

fn applescript_escape(s: &str) -> String {
    let mut escaped = String::new();
    for ch in s.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn is_admin_required_error(stderr: &str) -> bool {
    stderr.contains("requires admin privileges")
}

fn is_user_cancel_error(stderr: &str) -> bool {
    stderr.contains("User canceled")
}

fn is_no_gui_error(stderr: &str) -> bool {
    stderr.contains("connection is invalid")
}

// networksetup can print "** Error: ..." while exiting 0, so a plain `&&`
// chain would not stop there. This shell function captures each command's
// combined output, echoes it (so the caller still sees it), and turns the
// marker into a nonzero exit so `&&` stops the chain at that command.
const GUARD_HELPER: &str =
    "c() { o=$(\"$@\" 2>&1); printf %s \"$o\"; case $o in *'** Error'*) exit 1;; esac; }; ";

/// Builds the guarded `&&` chain (helper definition + one guarded invocation
/// per command) for `bin`, without any AppleScript wrapping. Kept separate
/// from `build_osascript_command` so the guard's stop-on-error behaviour can
/// be exercised directly against a stub binary in tests.
fn build_guarded_chain(bin: &str, commands: &[Vec<&str>]) -> String {
    let rendered: Vec<String> = commands
        .iter()
        .map(|args| {
            let escaped_args: Vec<String> = args.iter().map(|a| shell_escape(a)).collect();
            format!("c {} {}", bin, escaped_args.join(" "))
        })
        .collect();
    format!("{}{}", GUARD_HELPER, rendered.join(" && "))
}

fn build_osascript_command(commands: &[Vec<&str>]) -> String {
    let shell_cmd = build_guarded_chain("/usr/sbin/networksetup", commands);
    let as_escaped = applescript_escape(&shell_cmd);
    format!(
        "do shell script \"{}\" with administrator privileges",
        as_escaped
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proxy_info_enabled() {
        let output =
            "Enabled: Yes\nServer: 127.0.0.1\nPort: 1080\nAuthenticated Proxy Enabled: 0\n";
        let info = parse_proxy_info(output);
        assert!(info.enabled);
        assert_eq!(info.server, "127.0.0.1");
        assert_eq!(info.port, "1080");
    }

    #[test]
    fn parse_proxy_info_disabled() {
        let output = "Enabled: No\nServer: \nPort: 0\n";
        let info = parse_proxy_info(output);
        assert!(!info.enabled);
        assert_eq!(info.server, "");
        assert_eq!(info.port, "0");
    }

    #[test]
    fn parse_interface_from_route_output() {
        let output = "   route to: default\n\
                       destination: default\n\
                              mask: default\n\
                           gateway: 192.168.1.1\n\
                         interface: en0\n\
                             flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n";
        assert_eq!(parse_default_interface(output), Some("en0".to_string()));
    }

    #[test]
    fn parse_interface_missing() {
        let output = "destination: default\ngateway: 192.168.1.1\n";
        assert_eq!(parse_default_interface(output), None);
    }

    #[test]
    fn parse_service_for_en0() {
        let output = "Hardware Port: Ethernet\n\
                      Device: en6\n\
                      Ethernet Address: aa:bb:cc:dd:ee:ff\n\
                      \n\
                      Hardware Port: Wi-Fi\n\
                      Device: en0\n\
                      Ethernet Address: 11:22:33:44:55:66\n";
        assert_eq!(
            parse_service_for_interface(output, "en0"),
            Some("Wi-Fi".to_string())
        );
    }

    #[test]
    fn parse_service_not_found() {
        let output = "Hardware Port: Wi-Fi\nDevice: en0\n";
        assert_eq!(parse_service_for_interface(output, "en7"), None);
    }

    // shell_escape tests
    #[test]
    fn shell_escape_plain() {
        assert_eq!(shell_escape("hello"), "'hello'");
    }

    #[test]
    fn shell_escape_with_spaces() {
        assert_eq!(shell_escape("Wi-Fi Network"), "'Wi-Fi Network'");
    }

    #[test]
    fn shell_escape_with_single_quotes() {
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn shell_escape_with_double_quotes() {
        assert_eq!(shell_escape("say \"hi\""), "'say \"hi\"'");
    }

    // applescript_escape tests
    #[test]
    fn applescript_escape_plain() {
        assert_eq!(applescript_escape("hello"), "hello");
    }

    #[test]
    fn applescript_escape_double_quotes() {
        assert_eq!(applescript_escape("say \"hi\""), "say \\\"hi\\\"");
    }

    #[test]
    fn applescript_escape_backslashes() {
        assert_eq!(applescript_escape("path\\to\\file"), "path\\\\to\\\\file");
    }

    // error detection tests
    #[test]
    fn admin_required_positive() {
        assert!(is_admin_required_error(
            "** Error: requires admin privileges."
        ));
    }

    #[test]
    fn admin_required_negative() {
        assert!(!is_admin_required_error("some other error"));
    }

    /// networksetup on newer macOS prints the admin error to stdout with the
    /// exact text below; detection must work on the combined output.
    #[test]
    fn admin_required_stdout_variant() {
        let detail = join_output("** Error: Command requires admin privileges.\n", "");
        assert!(is_admin_required_error(&detail));
    }

    #[test]
    fn join_output_both_streams() {
        assert_eq!(join_output("out\n", "err\n"), "out err");
        assert_eq!(join_output("", "err"), "err");
        assert_eq!(join_output("out", ""), "out");
        assert_eq!(join_output("", ""), "");
    }

    #[test]
    fn user_cancel_positive() {
        assert!(is_user_cancel_error(
            "execution error: User canceled. (-128)"
        ));
    }

    #[test]
    fn user_cancel_negative() {
        assert!(!is_user_cancel_error("some other error"));
    }

    #[test]
    fn no_gui_positive() {
        assert!(is_no_gui_error(
            "execution error: connection is invalid (-609)"
        ));
    }

    #[test]
    fn no_gui_negative() {
        assert!(!is_no_gui_error("some other error"));
    }

    // build_osascript_command tests
    #[test]
    fn osascript_single_arg() {
        let cmd = build_osascript_command(&[vec!["-getwebproxy"]]);
        assert_eq!(
            cmd,
            "do shell script \"c() { o=$(\\\"$@\\\" 2>&1); printf %s \\\"$o\\\"; case $o in *'** Error'*) exit 1;; esac; }; c /usr/sbin/networksetup '-getwebproxy'\" with administrator privileges"
        );
    }

    #[test]
    fn osascript_multiple_args() {
        let cmd = build_osascript_command(&[vec![
            "-setsocksfirewallproxy",
            "Wi-Fi",
            "127.0.0.1",
            "1080",
        ]]);
        assert_eq!(
            cmd,
            "do shell script \"c() { o=$(\\\"$@\\\" 2>&1); printf %s \\\"$o\\\"; case $o in *'** Error'*) exit 1;; esac; }; c /usr/sbin/networksetup '-setsocksfirewallproxy' 'Wi-Fi' '127.0.0.1' '1080'\" with administrator privileges"
        );
    }

    #[test]
    fn osascript_args_with_special_chars() {
        let cmd = build_osascript_command(&[vec![
            "-setsocksfirewallproxy",
            "Thunderbolt \"Pro\" Bridge",
            "127.0.0.1",
            "1080",
        ]]);
        assert_eq!(
            cmd,
            "do shell script \"c() { o=$(\\\"$@\\\" 2>&1); printf %s \\\"$o\\\"; case $o in *'** Error'*) exit 1;; esac; }; c /usr/sbin/networksetup '-setsocksfirewallproxy' 'Thunderbolt \\\"Pro\\\" Bridge' '127.0.0.1' '1080'\" with administrator privileges"
        );
    }

    #[test]
    fn osascript_batch_of_six_joined_with_and() {
        let commands: Vec<Vec<&str>> = vec![
            vec!["-setsocksfirewallproxy", "Wi-Fi", "127.0.0.1", "21080"],
            vec!["-setsocksfirewallproxystate", "Wi-Fi", "on"],
            vec!["-setwebproxy", "Wi-Fi", "127.0.0.1", "21080"],
            vec!["-setwebproxystate", "Wi-Fi", "on"],
            vec!["-setsecurewebproxy", "Wi-Fi", "127.0.0.1", "21080"],
            vec!["-setsecurewebproxystate", "Wi-Fi", "on"],
        ];
        let cmd = build_osascript_command(&commands);
        assert_eq!(
            cmd,
            "do shell script \"c() { o=$(\\\"$@\\\" 2>&1); printf %s \\\"$o\\\"; case $o in *'** Error'*) exit 1;; esac; }; \
c /usr/sbin/networksetup '-setsocksfirewallproxy' 'Wi-Fi' '127.0.0.1' '21080' && \
c /usr/sbin/networksetup '-setsocksfirewallproxystate' 'Wi-Fi' 'on' && \
c /usr/sbin/networksetup '-setwebproxy' 'Wi-Fi' '127.0.0.1' '21080' && \
c /usr/sbin/networksetup '-setwebproxystate' 'Wi-Fi' 'on' && \
c /usr/sbin/networksetup '-setsecurewebproxy' 'Wi-Fi' '127.0.0.1' '21080' && \
c /usr/sbin/networksetup '-setsecurewebproxystate' 'Wi-Fi' 'on'\" with administrator privileges"
        );
    }

    // Proves the chain is actually guarded: every command after the helper
    // definition is invoked through `c`, so a "** Error" with exit 0 turns
    // into a nonzero status and the `&&` chain stops there.
    #[test]
    fn osascript_batch_each_command_is_guarded_by_c() {
        let commands: Vec<Vec<&str>> = vec![
            vec!["-setsocksfirewallproxy", "Wi-Fi", "127.0.0.1", "21080"],
            vec!["-setsocksfirewallproxystate", "Wi-Fi", "on"],
        ];
        let cmd = build_osascript_command(&commands);
        assert!(cmd.contains("c() { o=$(\\\"$@\\\" 2>&1); printf %s \\\"$o\\\"; case $o in *'** Error'*) exit 1;; esac; }"));
        assert!(cmd.contains("c /usr/sbin/networksetup '-setsocksfirewallproxy'"));
        assert!(cmd.contains("c /usr/sbin/networksetup '-setsocksfirewallproxystate'"));
    }

    // This only checks the generated script text has one elevation phrase.
    // It does not prove osascript is spawned only once; that would need a
    // process-runner seam, which this change does not add.
    #[test]
    fn osascript_batch_script_text_has_one_elevation_phrase() {
        let commands: Vec<Vec<&str>> = vec![
            vec!["-setsocksfirewallproxystate", "Wi-Fi", "off"],
            vec!["-setwebproxystate", "Wi-Fi", "off"],
            vec!["-setsecurewebproxystate", "Wi-Fi", "off"],
        ];
        let cmd = build_osascript_command(&commands);
        assert_eq!(cmd.matches("with administrator privileges").count(), 1);
    }

    #[test]
    fn osascript_batch_escapes_special_service_name_in_every_position() {
        let service = "Thunderbolt \"Pro\" Bridge";
        let commands: Vec<Vec<&str>> = vec![
            vec!["-setsocksfirewallproxystate", service, "off"],
            vec!["-setwebproxystate", service, "off"],
            vec!["-setsecurewebproxystate", service, "off"],
        ];
        let cmd = build_osascript_command(&commands);
        let escaped_service = "'Thunderbolt \\\"Pro\\\" Bridge'";
        assert_eq!(cmd.matches(escaped_service).count(), 3);
    }

    // Behavioural proof of the guard, run through /bin/sh with a stub in
    // place of networksetup. Never touches osascript or the real
    // networksetup, so it is safe to run here.
    #[test]
    fn guarded_chain_stops_after_a_command_reports_error_with_zero_exit() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("corvex_guard_test_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp dir");
        let stub = dir.join("fake_networksetup.sh");
        fs::write(
            &stub,
            "#!/bin/sh\n\
case \"$1\" in\n\
  -first) echo '** Error: fake'; touch \"$MARKER_DIR/first_ran\"; exit 0 ;;\n\
  -second) touch \"$MARKER_DIR/second_ran\"; exit 0 ;;\n\
esac\n",
        )
        .expect("write stub script");
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).expect("chmod stub script");

        let commands: Vec<Vec<&str>> = vec![vec!["-first"], vec!["-second"]];
        let chain = build_guarded_chain(stub.to_str().unwrap(), &commands);

        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(&chain)
            .env("MARKER_DIR", &dir)
            .output()
            .expect("run guarded chain via /bin/sh");

        assert!(
            dir.join("first_ran").exists(),
            "the first command should have run"
        );
        assert!(
            !dir.join("second_ran").exists(),
            "the second command must not run once the first reports ** Error"
        );
        assert!(
            !output.status.success(),
            "the guarded chain must exit nonzero"
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("** Error"));

        let _ = fs::remove_dir_all(&dir);
    }

    // The service name comes from parsing `networksetup -listallhardwareports`
    // output and ends up inside a shell string that runs with administrator
    // privileges, so shell metacharacters in it must stay inert data: they
    // must stay inside the single-quoted argument and never start a command
    // substitution. Each case below asserts on the exact generated string.

    #[test]
    fn build_osascript_command_service_name_with_single_quote_stays_inert() {
        let cmd = build_osascript_command(&[vec!["-setsocksfirewallproxystate", "O'Brien", "off"]]);
        assert_eq!(
            cmd,
            "do shell script \"c() { o=$(\\\"$@\\\" 2>&1); printf %s \\\"$o\\\"; case $o in *'** Error'*) exit 1;; esac; }; c /usr/sbin/networksetup '-setsocksfirewallproxystate' 'O'\\\\''Brien' 'off'\" with administrator privileges"
        );
    }

    #[test]
    fn build_osascript_command_service_name_with_backslash_stays_inert() {
        let cmd = build_osascript_command(&[vec![
            "-setsocksfirewallproxystate",
            "Path\\to\\Bridge",
            "off",
        ]]);
        assert_eq!(
            cmd,
            "do shell script \"c() { o=$(\\\"$@\\\" 2>&1); printf %s \\\"$o\\\"; case $o in *'** Error'*) exit 1;; esac; }; c /usr/sbin/networksetup '-setsocksfirewallproxystate' 'Path\\\\to\\\\Bridge' 'off'\" with administrator privileges"
        );
    }

    #[test]
    fn build_osascript_command_service_name_with_command_substitution_stays_inert() {
        let cmd = build_osascript_command(&[vec!["-setsocksfirewallproxystate", "$(id)", "off"]]);
        assert_eq!(
            cmd,
            "do shell script \"c() { o=$(\\\"$@\\\" 2>&1); printf %s \\\"$o\\\"; case $o in *'** Error'*) exit 1;; esac; }; c /usr/sbin/networksetup '-setsocksfirewallproxystate' '$(id)' 'off'\" with administrator privileges"
        );
    }

    #[test]
    fn build_osascript_command_service_name_with_backtick_stays_inert() {
        let cmd = build_osascript_command(&[vec!["-setsocksfirewallproxystate", "`id`", "off"]]);
        assert_eq!(
            cmd,
            "do shell script \"c() { o=$(\\\"$@\\\" 2>&1); printf %s \\\"$o\\\"; case $o in *'** Error'*) exit 1;; esac; }; c /usr/sbin/networksetup '-setsocksfirewallproxystate' '`id`' 'off'\" with administrator privileges"
        );
    }

    #[test]
    fn build_osascript_command_service_name_with_combined_metacharacters_stays_inert() {
        let service = "'\\\"$(id)`whoami`";
        let cmd = build_osascript_command(&[vec!["-setsocksfirewallproxystate", service, "off"]]);
        assert_eq!(
            cmd,
            "do shell script \"c() { o=$(\\\"$@\\\" 2>&1); printf %s \\\"$o\\\"; case $o in *'** Error'*) exit 1;; esac; }; c /usr/sbin/networksetup '-setsocksfirewallproxystate' ''\\\\''\\\\\\\"$(id)`whoami`' 'off'\" with administrator privileges"
        );
    }

    // classify_networksetup_output tests
    #[test]
    fn classify_success() {
        let outcome = classify_networksetup_output(true, "Enabled: Yes\n", "");
        assert_eq!(outcome, NsOutcome::Ok("Enabled: Yes\n".to_string()));
    }

    #[test]
    fn classify_admin_required_on_stdout_with_zero_exit() {
        let outcome = classify_networksetup_output(
            true,
            "** Error: Command requires admin privileges.\n",
            "",
        );
        assert_eq!(outcome, NsOutcome::NeedsAdmin);
    }

    #[test]
    fn classify_admin_required_on_stderr_with_nonzero_exit() {
        let outcome = classify_networksetup_output(
            false,
            "",
            "** Error: Command requires admin privileges.\n",
        );
        assert_eq!(outcome, NsOutcome::NeedsAdmin);
    }

    #[test]
    fn classify_unrelated_failure() {
        let outcome = classify_networksetup_output(false, "", "** Error: Invalid arguments.\n");
        assert_eq!(
            outcome,
            NsOutcome::Failed("** Error: Invalid arguments.".to_string())
        );
    }

    /// Exit code 0, empty stdout, admin error only on stderr: this is the
    /// hole the combined-output classification closes.
    #[test]
    fn classify_admin_required_on_stderr_with_zero_exit() {
        let outcome = classify_networksetup_output(
            true,
            "",
            "** Error: Command requires admin privileges.\n",
        );
        assert_eq!(outcome, NsOutcome::NeedsAdmin);
    }

    #[test]
    fn classify_unrelated_failure_on_stderr_with_zero_exit() {
        let outcome = classify_networksetup_output(true, "", "** Error: Invalid arguments.\n");
        assert_eq!(
            outcome,
            NsOutcome::Failed("** Error: Invalid arguments.".to_string())
        );
    }

    // authorization_denied_message / batch_failure_message tests
    #[test]
    fn authorization_denied_message_nothing_applied_yet() {
        assert_eq!(
            authorization_denied_message(false),
            "Authorization denied — proxy settings were not changed"
        );
    }

    #[test]
    fn authorization_denied_message_partial_batch_already_applied() {
        assert_eq!(
            authorization_denied_message(true),
            "Authorization denied — some proxy settings from earlier in this batch may already have been applied before you canceled"
        );
    }

    #[test]
    fn authorization_denied_message_differs_by_already_applied() {
        // Would fail if `already_applied` were collapsed to a constant.
        assert_ne!(
            authorization_denied_message(false),
            authorization_denied_message(true)
        );
    }

    #[test]
    fn batch_failure_message_includes_detail_and_commands_in_order() {
        let commands: Vec<Vec<&str>> = vec![
            vec!["-setsocksfirewallproxy", "Wi-Fi", "127.0.0.1", "21080"],
            vec!["-setsocksfirewallproxystate", "Wi-Fi", "on"],
        ];
        let msg = batch_failure_message(&commands, "** Error: Invalid arguments.");
        assert_eq!(
            msg,
            "networksetup batch failed (elevated): ** Error: Invalid arguments.\n\
             commands run in order, stopped at the first failure above — earlier ones in this list may already be applied: \
             -setsocksfirewallproxy Wi-Fi 127.0.0.1 21080; -setsocksfirewallproxystate Wi-Fi on"
        );
    }

    // classify_elevated_output tests
    #[test]
    fn classify_elevated_output_clean_success_returns_stdout() {
        let outcome = classify_elevated_output(true, "Enabled: Yes\n", "");
        assert_eq!(outcome, ElevatedOutcome::Ok("Enabled: Yes\n".to_string()));
    }

    /// The exact bug this fix closes: exit status 0, but one command in the
    /// elevated `&&` chain printed an error to stdout. Trusting the exit
    /// code alone would report success while the proxy was never set.
    #[test]
    fn classify_elevated_output_zero_exit_with_error_on_stdout_is_failure() {
        let outcome = classify_elevated_output(true, "** Error: Invalid arguments.\n", "");
        assert_eq!(
            outcome,
            ElevatedOutcome::Failed("** Error: Invalid arguments.".to_string())
        );
    }

    #[test]
    fn classify_elevated_output_zero_exit_with_error_on_stderr_is_failure() {
        let outcome = classify_elevated_output(true, "", "** Error: Invalid arguments.\n");
        assert_eq!(
            outcome,
            ElevatedOutcome::Failed("** Error: Invalid arguments.".to_string())
        );
    }

    #[test]
    fn classify_elevated_output_nonzero_exit_user_cancel() {
        let outcome = classify_elevated_output(false, "", "execution error: User canceled. (-128)");
        assert_eq!(outcome, ElevatedOutcome::Cancelled);
    }

    #[test]
    fn classify_elevated_output_nonzero_exit_no_gui() {
        let outcome =
            classify_elevated_output(false, "", "execution error: connection is invalid (-609)");
        assert_eq!(outcome, ElevatedOutcome::NoGui);
    }

    #[test]
    fn classify_elevated_output_nonzero_exit_generic_failure() {
        let outcome = classify_elevated_output(false, "", "some other error");
        assert_eq!(
            outcome,
            ElevatedOutcome::Failed("some other error".to_string())
        );
    }

    // run_networksetup_elevated tests
    #[test]
    fn run_networksetup_elevated_rejects_empty_batch() {
        // The real guard against an empty batch: build_osascript_command(&[])
        // would render `do shell script "" with administrator privileges`,
        // popping a password dialog that runs nothing. This must be refused
        // before osascript is ever spawned.
        let result = run_networksetup_elevated(&[], false);
        assert_eq!(
            result.unwrap_err().to_string(),
            "run_networksetup_elevated called with no commands to run"
        );
    }

    // enable_proxy_commands / disable_proxy_commands tests
    #[test]
    fn enable_proxy_commands_order_and_substitution() {
        let commands = enable_proxy_commands("Wi-Fi", "127.0.0.1", "21080");
        assert_eq!(
            commands,
            vec![
                vec!["-setsocksfirewallproxy", "Wi-Fi", "127.0.0.1", "21080"],
                vec!["-setsocksfirewallproxystate", "Wi-Fi", "on"],
                vec!["-setwebproxy", "Wi-Fi", "127.0.0.1", "21080"],
                vec!["-setwebproxystate", "Wi-Fi", "on"],
                vec!["-setsecurewebproxy", "Wi-Fi", "127.0.0.1", "21080"],
                vec!["-setsecurewebproxystate", "Wi-Fi", "on"],
            ]
        );
    }

    #[test]
    fn enable_proxy_commands_sets_host_before_state() {
        let commands = enable_proxy_commands("Wi-Fi", "127.0.0.1", "21080");
        let index_of = |setter: &str| commands.iter().position(|c| c[0] == setter).unwrap();

        assert!(index_of("-setsocksfirewallproxy") < index_of("-setsocksfirewallproxystate"));
        assert!(index_of("-setwebproxy") < index_of("-setwebproxystate"));
        assert!(index_of("-setsecurewebproxy") < index_of("-setsecurewebproxystate"));
    }

    #[test]
    fn disable_proxy_commands_order() {
        let commands = disable_proxy_commands("Wi-Fi");
        assert_eq!(
            commands,
            vec![
                vec!["-setsocksfirewallproxystate", "Wi-Fi", "off"],
                vec!["-setwebproxystate", "Wi-Fi", "off"],
                vec!["-setsecurewebproxystate", "Wi-Fi", "off"],
            ]
        );
    }

    // Same caveat as osascript_batch_script_text_has_one_elevation_phrase: this
    // checks script text, not how many osascript processes actually run.
    #[test]
    fn enable_proxy_commands_script_text_has_one_elevation_phrase() {
        let commands = enable_proxy_commands("Wi-Fi", "127.0.0.1", "21080");
        let script = build_osascript_command(&commands);
        assert_eq!(script.matches("with administrator privileges").count(), 1);
    }
}
