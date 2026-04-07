pub mod awg;

/// Engine mode: how the proxy tunnel is established.
///
/// - `Xray`: Full xray handles both the tunnel and routing.
/// - `Awg`: AmneziaWG creates the tunnel; xray runs as a local routing layer
///   with a `freedom` outbound (traffic exits through the OS network stack,
///   where AWG's routing table sends it through the tunnel).
#[derive(Debug, PartialEq)]
pub enum EngineMode {
    Xray,
    Awg,
}
