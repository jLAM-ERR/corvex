#[cfg(windows)]
use super::Platform;
use super::{ProxyInfo, ProxyStatus};
#[allow(unused_imports)]
use anyhow::{Context, Result};
#[cfg(windows)]
use log::debug;
use std::collections::BTreeMap;
use std::net::IpAddr;

pub struct WindowsPlatform;

impl WindowsPlatform {
    pub fn new() -> Self {
        WindowsPlatform
    }
}

// ---------------------------------------------------------------------------
// Pure parsing helpers — testable on any platform
// ---------------------------------------------------------------------------

/// Check if an IP address is private (RFC 1918 / RFC 4193 / link-local).
pub fn is_private_ip(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        Ok(IpAddr::V6(v6)) => v6.is_loopback(),
        Err(_) => false,
    }
}

/// Parse Windows `ProxyServer` registry value into proxy info.
///
/// Formats:
///   "socks=127.0.0.1:1080"
///   "http=127.0.0.1:8080;https=127.0.0.1:8080;socks=127.0.0.1:1080"
///   "127.0.0.1:8080"  (applies to all)
pub fn parse_proxy_server(value: &str, enabled: bool) -> ProxyStatus {
    let mut socks = ProxyInfo {
        enabled: false,
        server: String::new(),
        port: "0".to_string(),
    };
    let mut http = ProxyInfo {
        enabled: false,
        server: String::new(),
        port: "0".to_string(),
    };
    let mut https = ProxyInfo {
        enabled: false,
        server: String::new(),
        port: "0".to_string(),
    };

    if !enabled || value.is_empty() {
        return ProxyStatus { socks, http, https };
    }

    // Split by ; for multiple proxy types
    for part in value.split(';') {
        let part = part.trim();
        if let Some(addr) = part.strip_prefix("socks=") {
            if let Some((host, port)) = split_host_port(addr) {
                socks = ProxyInfo {
                    enabled: true,
                    server: host.to_string(),
                    port: port.to_string(),
                };
            }
        } else if let Some(addr) = part.strip_prefix("http=") {
            if let Some((host, port)) = split_host_port(addr) {
                http = ProxyInfo {
                    enabled: true,
                    server: host.to_string(),
                    port: port.to_string(),
                };
            }
        } else if let Some(addr) = part.strip_prefix("https=") {
            if let Some((host, port)) = split_host_port(addr) {
                https = ProxyInfo {
                    enabled: true,
                    server: host.to_string(),
                    port: port.to_string(),
                };
            }
        } else if !part.contains('=') {
            // Bare "host:port" — applies to all types
            if let Some((host, port)) = split_host_port(part) {
                let info = || ProxyInfo {
                    enabled: true,
                    server: host.to_string(),
                    port: port.to_string(),
                };
                socks = info();
                http = info();
                https = info();
            }
        }
    }

    ProxyStatus { socks, http, https }
}

fn split_host_port(addr: &str) -> Option<(&str, &str)> {
    let colon = addr.rfind(':')?;
    let host = &addr[..colon];
    let port = &addr[colon + 1..];
    if port.is_empty() || host.is_empty() {
        return None;
    }
    Some((host, port))
}

/// Strip leading dot from NRPT namespace (e.g., ".corp.com" → "corp.com").
pub fn normalize_nrpt_namespace(ns: &str) -> String {
    ns.strip_prefix('.').unwrap_or(ns).to_string()
}

/// Merge two DNS maps. `primary` entries take priority over `secondary`.
pub fn merge_dns_maps(
    primary: &BTreeMap<String, String>,
    secondary: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut merged = primary.clone();
    for (domain, ns) in secondary {
        merged.entry(domain.clone()).or_insert_with(|| ns.clone());
    }
    merged
}

// ---------------------------------------------------------------------------
// Windows-only WinAPI implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod winapi {
    use super::*;
    use anyhow::bail;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER,
        HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_SZ,
    };

    const INTERNET_SETTINGS_KEY: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const NRPT_KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn from_wide(buf: &[u16]) -> String {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        OsString::from_wide(&buf[..len])
            .to_string_lossy()
            .into_owned()
    }

    fn reg_get_string(hkey: HKEY, value_name: &str) -> Result<String> {
        let name_wide = to_wide(value_name);
        let mut data_type: u32 = 0;
        let mut data_size: u32 = 0;

        unsafe {
            let ret = RegQueryValueExW(
                hkey,
                name_wide.as_ptr(),
                std::ptr::null(),
                &mut data_type,
                std::ptr::null_mut(),
                &mut data_size,
            );
            if ret != ERROR_SUCCESS as WIN32_ERROR {
                bail!("RegQueryValueExW size query failed: {}", ret);
            }
            if data_type != REG_SZ {
                bail!("expected REG_SZ, got type {}", data_type);
            }

            let mut buffer = vec![0u16; (data_size as usize) / 2];
            let ret = RegQueryValueExW(
                hkey,
                name_wide.as_ptr(),
                std::ptr::null(),
                &mut data_type,
                buffer.as_mut_ptr() as *mut u8,
                &mut data_size,
            );
            if ret != ERROR_SUCCESS as WIN32_ERROR {
                bail!("RegQueryValueExW read failed: {}", ret);
            }

            Ok(from_wide(&buffer))
        }
    }

    fn reg_get_dword(hkey: HKEY, value_name: &str) -> Result<u32> {
        let name_wide = to_wide(value_name);
        let mut data_type: u32 = 0;
        let mut data: u32 = 0;
        let mut data_size: u32 = std::mem::size_of::<u32>() as u32;

        unsafe {
            let ret = RegQueryValueExW(
                hkey,
                name_wide.as_ptr(),
                std::ptr::null(),
                &mut data_type,
                &mut data as *mut u32 as *mut u8,
                &mut data_size,
            );
            if ret != ERROR_SUCCESS as WIN32_ERROR {
                bail!("RegQueryValueExW DWORD failed: {}", ret);
            }
            Ok(data)
        }
    }

    fn reg_set_dword(hkey: HKEY, value_name: &str, value: u32) -> Result<()> {
        use windows_sys::Win32::System::Registry::RegSetValueExW;
        let name_wide = to_wide(value_name);
        unsafe {
            let ret = RegSetValueExW(
                hkey,
                name_wide.as_ptr(),
                0,
                REG_DWORD,
                &value as *const u32 as *const u8,
                std::mem::size_of::<u32>() as u32,
            );
            if ret != ERROR_SUCCESS as WIN32_ERROR {
                bail!("RegSetValueExW DWORD failed: {}", ret);
            }
        }
        Ok(())
    }

    fn reg_set_string(hkey: HKEY, value_name: &str, value: &str) -> Result<()> {
        use windows_sys::Win32::System::Registry::RegSetValueExW;
        let name_wide = to_wide(value_name);
        let value_wide = to_wide(value);
        unsafe {
            let ret = RegSetValueExW(
                hkey,
                name_wide.as_ptr(),
                0,
                REG_SZ,
                value_wide.as_ptr() as *const u8,
                (value_wide.len() * 2) as u32,
            );
            if ret != ERROR_SUCCESS as WIN32_ERROR {
                bail!("RegSetValueExW string failed: {}", ret);
            }
        }
        Ok(())
    }

    /// Read ProxyEnable and ProxyServer from Internet Settings registry.
    pub fn read_proxy_settings() -> Result<(bool, String)> {
        let key_path = to_wide(INTERNET_SETTINGS_KEY);
        let mut hkey: HKEY = 0;

        unsafe {
            let ret = RegOpenKeyExW(HKEY_CURRENT_USER, key_path.as_ptr(), 0, KEY_READ, &mut hkey);
            if ret != ERROR_SUCCESS as WIN32_ERROR {
                bail!("Failed to open Internet Settings registry key: {}", ret);
            }
        }

        let enabled = reg_get_dword(hkey, "ProxyEnable").unwrap_or(0) != 0;
        let server = reg_get_string(hkey, "ProxyServer").unwrap_or_default();

        unsafe { RegCloseKey(hkey) };
        Ok((enabled, server))
    }

    /// Write proxy settings to Internet Settings registry.
    pub fn write_proxy_settings(enabled: bool, server: &str) -> Result<()> {
        use windows_sys::Win32::System::Registry::KEY_WRITE;
        let key_path = to_wide(INTERNET_SETTINGS_KEY);
        let mut hkey: HKEY = 0;

        unsafe {
            let ret = RegOpenKeyExW(
                HKEY_CURRENT_USER,
                key_path.as_ptr(),
                0,
                KEY_WRITE,
                &mut hkey,
            );
            if ret != ERROR_SUCCESS as WIN32_ERROR {
                bail!("Failed to open Internet Settings for writing: {}", ret);
            }
        }

        let result = (|| -> Result<()> {
            reg_set_dword(hkey, "ProxyEnable", if enabled { 1 } else { 0 })?;
            reg_set_string(hkey, "ProxyServer", server)?;
            Ok(())
        })();

        unsafe { RegCloseKey(hkey) };
        result
    }

    /// Get adapter DNS suffix → first DNS server mappings via GetAdaptersAddresses.
    pub fn get_adapter_dns_mappings() -> Result<BTreeMap<String, String>> {
        let mut result = BTreeMap::new();
        let mut buf_size: u32 = 15000;
        let mut buffer: Vec<u8>;

        loop {
            buffer = vec![0u8; buf_size as usize];
            let ret = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    GAA_FLAG_INCLUDE_PREFIX,
                    std::ptr::null_mut(),
                    buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                    &mut buf_size,
                )
            };

            if ret == ERROR_SUCCESS {
                break;
            }
            if ret == 111 {
                // ERROR_BUFFER_OVERFLOW
                continue;
            }
            bail!("GetAdaptersAddresses failed: {}", ret);
        }

        let mut adapter = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !adapter.is_null() {
            let a = unsafe { &*adapter };

            // Read DNS suffix
            let dns_suffix = if !a.DnsSuffix.is_null() {
                let suffix_slice = unsafe {
                    let mut len = 0;
                    let ptr = a.DnsSuffix;
                    while *ptr.add(len) != 0 {
                        len += 1;
                    }
                    std::slice::from_raw_parts(ptr, len)
                };
                from_wide(suffix_slice)
            } else {
                String::new()
            };

            if !dns_suffix.is_empty() {
                // Read first DNS server address
                let mut dns_addr = a.FirstDnsServerAddress;
                while !dns_addr.is_null() {
                    let dns = unsafe { &*dns_addr };
                    if let Some(ip_str) =
                        sockaddr_to_string(dns.Address.lpSockaddr, dns.Address.iSockaddrLength)
                    {
                        if is_private_ip(&ip_str) {
                            debug!("adapter DNS: {} -> {}", dns_suffix, ip_str);
                            result.entry(dns_suffix.clone()).or_insert(ip_str);
                            break;
                        }
                    }
                    dns_addr = unsafe { (*dns_addr).Next };
                }
            }

            adapter = a.Next;
        }

        Ok(result)
    }

    fn sockaddr_to_string(
        addr: *const windows_sys::Win32::Networking::WinSock::SOCKADDR,
        len: i32,
    ) -> Option<String> {
        if addr.is_null() || len == 0 {
            return None;
        }
        unsafe {
            let family = (*addr).sa_family;
            if family == windows_sys::Win32::Networking::WinSock::AF_INET as u16 {
                if (len as usize) < std::mem::size_of::<SOCKADDR_IN>() {
                    return None;
                }
                let sin = &*(addr as *const SOCKADDR_IN);
                let bytes = sin.sin_addr.S_un.S_addr.to_ne_bytes();
                Some(format!(
                    "{}.{}.{}.{}",
                    bytes[0], bytes[1], bytes[2], bytes[3]
                ))
            } else if family == windows_sys::Win32::Networking::WinSock::AF_INET6 as u16 {
                if (len as usize) < std::mem::size_of::<SOCKADDR_IN6>() {
                    return None;
                }
                let sin6 = &*(addr as *const SOCKADDR_IN6);
                let bytes = sin6.sin6_addr.u.Byte;
                let addr = std::net::Ipv6Addr::from(bytes);
                Some(addr.to_string())
            } else {
                None
            }
        }
    }

    /// Read NRPT DNS policy rules from registry.
    pub fn get_nrpt_dns_mappings() -> Result<BTreeMap<String, String>> {
        let mut result = BTreeMap::new();
        let key_path = to_wide(NRPT_KEY);
        let mut hkey: HKEY = 0;

        let ret = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                key_path.as_ptr(),
                0,
                KEY_READ,
                &mut hkey,
            )
        };
        if ret != ERROR_SUCCESS as WIN32_ERROR {
            // NRPT key may not exist — not an error
            debug!("NRPT registry key not found (ret={}), skipping", ret);
            return Ok(result);
        }

        // Enumerate subkeys
        let mut index: u32 = 0;
        loop {
            let mut name_buf = [0u16; 256];
            let mut name_len = name_buf.len() as u32;

            let ret = unsafe {
                RegEnumKeyExW(
                    hkey,
                    index,
                    name_buf.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ret != ERROR_SUCCESS as WIN32_ERROR {
                break;
            }

            let subkey_name = from_wide(&name_buf[..name_len as usize]);
            let subkey_path = to_wide(&format!("{}\\{}", NRPT_KEY, subkey_name));
            let mut sub_hkey: HKEY = 0;

            let ret = unsafe {
                RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    subkey_path.as_ptr(),
                    0,
                    KEY_READ,
                    &mut sub_hkey,
                )
            };
            if ret == ERROR_SUCCESS as WIN32_ERROR {
                // Read Name (namespace / domain pattern)
                if let Ok(namespace) = reg_get_string(sub_hkey, "Name") {
                    // Read GenericDNSServers (nameserver IP)
                    if let Ok(dns_server) = reg_get_string(sub_hkey, "GenericDNSServers") {
                        let domain = normalize_nrpt_namespace(&namespace);
                        if !domain.is_empty() && !dns_server.is_empty() {
                            debug!("NRPT rule: {} -> {}", domain, dns_server);
                            result.entry(domain).or_insert(dns_server);
                        }
                    }
                }
                unsafe { RegCloseKey(sub_hkey) };
            }

            index += 1;
        }

        unsafe { RegCloseKey(hkey) };
        Ok(result)
    }

    /// Detect active network adapter via default route.
    pub fn detect_active_adapter() -> Result<String> {
        // Use `route print 0.0.0.0` and parse the output for the active interface
        let output = std::process::Command::new("route")
            .args(["print", "0.0.0.0"])
            .output()
            .context("failed to run 'route print'")?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse the active routes table — first line with 0.0.0.0 destination
        // Format: "Network Destination    Netmask    Gateway    Interface    Metric"
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
                let iface_ip = parts[3];
                debug!("default route interface IP: {}", iface_ip);
                // Map interface IP to adapter friendly name via GetAdaptersAddresses
                return adapter_name_for_ip(iface_ip);
            }
        }

        // Fallback
        Ok("Ethernet".to_string())
    }

    fn adapter_name_for_ip(target_ip: &str) -> Result<String> {
        let mut buf_size: u32 = 15000;
        let mut buffer: Vec<u8>;

        loop {
            buffer = vec![0u8; buf_size as usize];
            let ret = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    GAA_FLAG_INCLUDE_PREFIX,
                    std::ptr::null_mut(),
                    buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                    &mut buf_size,
                )
            };
            if ret == ERROR_SUCCESS {
                break;
            }
            if ret == 111 {
                continue;
            }
            bail!("GetAdaptersAddresses failed: {}", ret);
        }

        let mut adapter = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !adapter.is_null() {
            let a = unsafe { &*adapter };

            // Check unicast addresses
            let mut unicast = a.FirstUnicastAddress;
            while !unicast.is_null() {
                let ua = unsafe { &*unicast };
                if let Some(ip_str) =
                    sockaddr_to_string(ua.Address.lpSockaddr, ua.Address.iSockaddrLength)
                {
                    if ip_str == target_ip {
                        // Found — return friendly name
                        let name = if !a.FriendlyName.is_null() {
                            let mut len = 0;
                            unsafe {
                                while *a.FriendlyName.add(len) != 0 {
                                    len += 1;
                                }
                            }
                            let slice = unsafe { std::slice::from_raw_parts(a.FriendlyName, len) };
                            from_wide(slice)
                        } else {
                            "Unknown".to_string()
                        };
                        return Ok(name);
                    }
                }
                unicast = unsafe { (*unicast).Next };
            }

            adapter = a.Next;
        }

        Ok(format!("adapter({})", target_ip))
    }
}

// ---------------------------------------------------------------------------
// Platform trait implementation (Windows only)
// ---------------------------------------------------------------------------

#[cfg(windows)]
impl Platform for WindowsPlatform {
    fn detect_active_service(&self) -> Result<String> {
        winapi::detect_active_adapter()
    }

    fn enable_proxy(&self, _service: &str, host: &str, port: u16) -> Result<()> {
        debug!("enabling Windows system proxy -> {}:{}", host, port);
        let proxy_server = format!("socks={}:{}", host, port);
        winapi::write_proxy_settings(true, &proxy_server)?;

        // Also set WinHTTP proxy for apps that use it
        let _ = std::process::Command::new("netsh")
            .args([
                "winhttp",
                "set",
                "proxy",
                &format!("proxy-server=\"socks={}:{}\"", host, port),
            ])
            .output();

        Ok(())
    }

    fn disable_proxy(&self, _service: &str) -> Result<()> {
        debug!("disabling Windows system proxy");
        winapi::write_proxy_settings(false, "")?;

        let _ = std::process::Command::new("netsh")
            .args(["winhttp", "reset", "proxy"])
            .output();

        Ok(())
    }

    fn proxy_status(&self, _service: &str) -> Result<ProxyStatus> {
        let (enabled, server) = winapi::read_proxy_settings()?;
        Ok(parse_proxy_server(&server, enabled))
    }

    fn discover_corporate_dns(&self) -> Result<BTreeMap<String, String>> {
        debug!("discovering corporate DNS on Windows");
        let adapter_dns = winapi::get_adapter_dns_mappings().unwrap_or_default();
        debug!("adapter DNS: {} entries", adapter_dns.len());

        let nrpt_dns = winapi::get_nrpt_dns_mappings().unwrap_or_default();
        debug!("NRPT DNS: {} entries", nrpt_dns.len());

        let merged = merge_dns_maps(&adapter_dns, &nrpt_dns);

        if merged.is_empty() {
            anyhow::bail!("no corporate DNS mappings found on Windows");
        }

        Ok(merged)
    }
}

// ---------------------------------------------------------------------------
// Tests — pure parsing functions work on any platform
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_private_ip ---

    #[test]
    fn private_ip_rfc1918_10() {
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("10.255.255.255"));
    }

    #[test]
    fn private_ip_rfc1918_172() {
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("172.31.255.255"));
    }

    #[test]
    fn private_ip_rfc1918_192() {
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("192.168.0.1"));
    }

    #[test]
    fn public_ip_not_private() {
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("1.1.1.1"));
        assert!(!is_private_ip("203.0.113.1"));
    }

    #[test]
    fn loopback_is_private() {
        assert!(is_private_ip("127.0.0.1"));
    }

    #[test]
    fn invalid_ip_not_private() {
        assert!(!is_private_ip("not-an-ip"));
        assert!(!is_private_ip(""));
    }

    // --- parse_proxy_server ---

    #[test]
    fn parse_socks_only() {
        let status = parse_proxy_server("socks=127.0.0.1:1080", true);
        assert!(status.socks.enabled);
        assert_eq!(status.socks.server, "127.0.0.1");
        assert_eq!(status.socks.port, "1080");
        assert!(!status.http.enabled);
        assert!(!status.https.enabled);
    }

    #[test]
    fn parse_multiple_types() {
        let status = parse_proxy_server(
            "http=127.0.0.1:8080;https=127.0.0.1:8443;socks=127.0.0.1:1080",
            true,
        );
        assert!(status.socks.enabled);
        assert_eq!(status.socks.port, "1080");
        assert!(status.http.enabled);
        assert_eq!(status.http.port, "8080");
        assert!(status.https.enabled);
        assert_eq!(status.https.port, "8443");
    }

    #[test]
    fn parse_bare_host_port() {
        let status = parse_proxy_server("127.0.0.1:8080", true);
        assert!(status.socks.enabled);
        assert!(status.http.enabled);
        assert!(status.https.enabled);
        assert_eq!(status.socks.port, "8080");
        assert_eq!(status.http.port, "8080");
    }

    #[test]
    fn parse_disabled_proxy() {
        let status = parse_proxy_server("socks=127.0.0.1:1080", false);
        assert!(!status.socks.enabled);
        assert!(!status.http.enabled);
        assert!(!status.https.enabled);
    }

    #[test]
    fn parse_empty_value() {
        let status = parse_proxy_server("", true);
        assert!(!status.socks.enabled);
    }

    // --- normalize_nrpt_namespace ---

    #[test]
    fn nrpt_strip_leading_dot() {
        assert_eq!(normalize_nrpt_namespace(".corp.com"), "corp.com");
    }

    #[test]
    fn nrpt_no_leading_dot() {
        assert_eq!(normalize_nrpt_namespace("corp.com"), "corp.com");
    }

    #[test]
    fn nrpt_empty() {
        assert_eq!(normalize_nrpt_namespace(""), "");
    }

    // --- merge_dns_maps ---

    #[test]
    fn merge_primary_wins() {
        let mut primary = BTreeMap::new();
        primary.insert("corp.com".to_string(), "10.0.0.1".to_string());

        let mut secondary = BTreeMap::new();
        secondary.insert("corp.com".to_string(), "10.0.0.99".to_string());
        secondary.insert("other.com".to_string(), "10.0.0.2".to_string());

        let merged = merge_dns_maps(&primary, &secondary);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged["corp.com"], "10.0.0.1"); // primary wins
        assert_eq!(merged["other.com"], "10.0.0.2"); // secondary added
    }

    #[test]
    fn merge_empty_primary() {
        let primary = BTreeMap::new();
        let mut secondary = BTreeMap::new();
        secondary.insert("corp.com".to_string(), "10.0.0.1".to_string());

        let merged = merge_dns_maps(&primary, &secondary);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged["corp.com"], "10.0.0.1");
    }

    #[test]
    fn merge_both_empty() {
        let merged = merge_dns_maps(&BTreeMap::new(), &BTreeMap::new());
        assert!(merged.is_empty());
    }
}
