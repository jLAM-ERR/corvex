use crate::dns::ResolverEntry;
use anyhow::Result;
use std::collections::BTreeMap;

#[cfg(target_os = "linux")]
pub mod linux;
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

/// How the host would reach one address: the router it would hand the packet
/// to, the interface it would leave by, and whether that router is actually
/// on the wire.
///
/// `on_link` is computed from the interface's own subnet rather than probed —
/// see [`crate::netdiag`] for why — and errs towards `true` whenever the
/// arithmetic cannot be done, so the diagnostic never invents a fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextHop {
    /// `None` when the destination is directly connected, reached over the
    /// link itself rather than through a router.
    pub gateway: Option<String>,
    /// The interface the route names, e.g. `en0`.
    pub interface: String,
    /// False only when the gateway provably sits outside the interface's
    /// subnet — the stale-gateway shape `corvex dns` exists to catch.
    pub on_link: bool,
}

impl NextHop {
    /// Assemble a verdict from a parsed route and the addresses of the
    /// interface it named.
    ///
    /// Shared by every `Platform::next_hop_status`: the commands differ per
    /// platform, but this last step — run `route_is_on_link` and carry the
    /// route's own fields across — was byte-identical in each, and it is the
    /// step a test can reach without running a command.
    pub fn from_route(route: crate::netdiag::RouteGet, inets: &[crate::netdiag::InetAddr]) -> Self {
        let on_link = crate::netdiag::route_is_on_link(&route, inets);
        log::debug!(
            "next hop via {}: gateway {:?} (on-link: {on_link})",
            route.interface,
            route.gateway
        );
        NextHop {
            gateway: route.gateway,
            interface: route.interface,
            on_link,
        }
    }
}

/// Platform abstraction for proxy, network, and DNS operations.
pub trait Platform {
    fn detect_active_service(&self) -> Result<String>;
    fn enable_proxy(&self, service: &str, host: &str, port: u16) -> Result<()>;
    fn disable_proxy(&self, service: &str) -> Result<()>;
    fn proxy_status(&self, service: &str) -> Result<ProxyStatus>;
    fn discover_corporate_dns(&self) -> Result<BTreeMap<String, String>>;
    /// Every resolver the system knows about, global ones included.
    ///
    /// The diagnostic's view: unlike [`Platform::discover_corporate_dns`], which
    /// projects down to one nameserver per domain for the xray DNS block, this
    /// keeps the resolver list whole.
    fn list_system_resolvers(&self) -> Result<Vec<ResolverEntry>>;
    /// The route to `ip`, with a verdict on whether its gateway is reachable.
    fn next_hop_status(&self, ip: &str) -> Result<NextHop>;
}

#[cfg(target_os = "macos")]
pub type PlatformImpl = macos::MacOsPlatform;

#[cfg(target_os = "windows")]
pub type PlatformImpl = windows::WindowsPlatform;

#[cfg(target_os = "linux")]
pub type PlatformImpl = linux::LinuxPlatform;

/// Create the platform-specific implementation.
pub fn create_platform() -> PlatformImpl {
    PlatformImpl::new()
}
