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

fn run_networksetup(args: &[&str]) -> Result<String> {
    let output = Command::new("networksetup")
        .args(args)
        .output()
        .with_context(|| format!("Failed to run: networksetup {}", args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_admin_required_error(&stderr) {
            debug!(
                "admin required for networksetup {}, escalating via osascript",
                args.join(" ")
            );
            return run_networksetup_elevated(args);
        }
        anyhow::bail!("networksetup {} failed: {}", args.join(" "), stderr);
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_networksetup_elevated(args: &[&str]) -> Result<String> {
    let script = build_osascript_command(args);
    let output = Command::new("osascript")
        .args(["-e", &script])
        .output()
        .context("Failed to run osascript for privilege escalation")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_user_cancel_error(&stderr) {
            anyhow::bail!("Authorization denied — proxy settings were not changed");
        }
        if is_no_gui_error(&stderr) {
            anyhow::bail!("No GUI session available — run with sudo instead");
        }
        anyhow::bail!(
            "networksetup {} failed (elevated): {}",
            args.join(" "),
            stderr
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
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

        run_networksetup(&["-setsocksfirewallproxy", service, host, &port_str])?;
        run_networksetup(&["-setsocksfirewallproxystate", service, "on"])?;

        run_networksetup(&["-setwebproxy", service, host, &port_str])?;
        run_networksetup(&["-setwebproxystate", service, "on"])?;

        run_networksetup(&["-setsecurewebproxy", service, host, &port_str])?;
        run_networksetup(&["-setsecurewebproxystate", service, "on"])?;

        Ok(())
    }

    fn disable_proxy(&self, service: &str) -> Result<()> {
        debug!("disabling proxies on '{}'", service);
        run_networksetup(&["-setsocksfirewallproxystate", service, "off"])?;
        run_networksetup(&["-setwebproxystate", service, "off"])?;
        run_networksetup(&["-setsecurewebproxystate", service, "off"])?;
        Ok(())
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

fn build_osascript_command(args: &[&str]) -> String {
    let escaped_args: Vec<String> = args.iter().map(|a| shell_escape(a)).collect();
    let shell_cmd = format!("/usr/sbin/networksetup {}", escaped_args.join(" "));
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
        let cmd = build_osascript_command(&["-getwebproxy"]);
        assert_eq!(
            cmd,
            "do shell script \"/usr/sbin/networksetup '-getwebproxy'\" with administrator privileges"
        );
    }

    #[test]
    fn osascript_multiple_args() {
        let cmd =
            build_osascript_command(&["-setsocksfirewallproxy", "Wi-Fi", "127.0.0.1", "1080"]);
        assert_eq!(
            cmd,
            "do shell script \"/usr/sbin/networksetup '-setsocksfirewallproxy' 'Wi-Fi' '127.0.0.1' '1080'\" with administrator privileges"
        );
    }

    #[test]
    fn osascript_args_with_special_chars() {
        let cmd = build_osascript_command(&[
            "-setsocksfirewallproxy",
            "Thunderbolt \"Pro\" Bridge",
            "127.0.0.1",
            "1080",
        ]);
        assert_eq!(
            cmd,
            "do shell script \"/usr/sbin/networksetup '-setsocksfirewallproxy' 'Thunderbolt \\\"Pro\\\" Bridge' '127.0.0.1' '1080'\" with administrator privileges"
        );
    }
}
