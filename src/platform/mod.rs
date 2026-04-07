use anyhow::Result;
use std::collections::BTreeMap;

#[cfg(target_os = "macos")]
pub mod macos;
#[allow(dead_code)]
pub mod windows;

/// Proxy info for a single proxy type.
#[derive(Debug)]
pub struct ProxyInfo {
    pub enabled: bool,
    pub server: String,
    pub port: String,
}

/// Status of all three proxy types (SOCKS, HTTP, HTTPS).
#[derive(Debug)]
pub struct ProxyStatus {
    pub socks: ProxyInfo,
    pub http: ProxyInfo,
    pub https: ProxyInfo,
}

/// Platform abstraction for proxy, network, and DNS operations.
pub trait Platform {
    fn detect_active_service(&self) -> Result<String>;
    fn enable_proxy(&self, service: &str, host: &str, port: u16) -> Result<()>;
    fn disable_proxy(&self, service: &str) -> Result<()>;
    fn proxy_status(&self, service: &str) -> Result<ProxyStatus>;
    fn discover_corporate_dns(&self) -> Result<BTreeMap<String, String>>;
}

#[cfg(target_os = "macos")]
pub type PlatformImpl = macos::MacOsPlatform;

#[cfg(target_os = "windows")]
pub type PlatformImpl = windows::WindowsPlatform;

#[cfg(all(unix, not(target_os = "macos")))]
compile_error!("Only macOS and Windows are currently supported");

/// Create the platform-specific implementation.
pub fn create_platform() -> PlatformImpl {
    PlatformImpl::new()
}
