use anyhow::{Context, Result};
use log::debug;
use std::process::Command;

/// Detects the active macOS network service by finding the default route interface
/// and mapping it to a service name.
pub fn detect_active_service() -> Result<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
