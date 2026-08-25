//! Pure network-path helpers behind the `corvex dns` diagnostic.
//!
//! Everything here is a `&str -> value` function so the reachability verdict can
//! be unit-tested without a routing socket. The system calls that feed them
//! (`route -n get` and `ifconfig` on macOS, `ip route get` and `ip addr show` on
//! Linux) live in the platform modules. Each platform's parsers are cfg-gated to
//! the platform that runs those commands, plus `test` so every shape stays
//! covered wherever the suite runs; the verdict itself is shared.
//!
//! The verdict is *computed*, not ARP-probed: a gateway is reachable only if it
//! shares a subnet with the address of the interface the route names. ARP state
//! is racy and needs privileges to read meaningfully, whereas subnet arithmetic
//! over three values is exact and testable — and an off-subnet gateway is
//! precisely the failure this diagnostic exists to catch.

use anyhow::{bail, Context, Result};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// The route to one destination, as `route -n get <ip>` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteGet {
    /// `None` for a directly-connected destination — one with no `gateway:`
    /// line, reached over the link itself rather than through a router.
    pub gateway: Option<String>,
    /// The interface the kernel would send over, e.g. `en0`.
    pub interface: String,
}

/// The IPv4 address configured on an interface, with its netmask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InetAddr {
    pub address: String,
    /// Netmask as a 32-bit mask, e.g. `0xffffff00` for a /24.
    pub netmask: u32,
}

/// Parse `route -n get <ip>` into the interface and its gateway.
///
/// Returns `None` when the output names no interface — the shape `route` prints
/// when the destination is not in the table at all.
#[cfg(any(test, target_os = "macos"))]
pub fn parse_route_get(output: &str) -> Option<RouteGet> {
    let mut gateway = None;
    let mut interface = None;

    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.trim() {
            "gateway" => gateway = Some(value.to_string()),
            "interface" => interface = Some(value.to_string()),
            _ => {}
        }
    }

    interface.map(|interface| RouteGet { gateway, interface })
}

/// Parse every IPv4 `inet` line out of `ifconfig <iface>`.
///
/// macOS prints the mask in hex — `inet 192.0.2.10 netmask 0xffffff00` — so it
/// is decoded as hex; a dotted-quad mask is accepted too, since that is what
/// some ifconfig builds print. `inet6` lines are ignored: the whole reachability
/// calculation is IPv4-only.
///
/// *Every* address, not just the first: an interface carrying aliases is on
/// several subnets at once, and a gateway on the second one is still on-link.
/// Reading only the first address turns that into a reported fault.
#[cfg(any(test, target_os = "macos"))]
pub fn parse_ifconfig_inets(output: &str) -> Vec<InetAddr> {
    let mut addresses = Vec::new();
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        // `inet` exactly — `inet6` is a different address family.
        if tokens.first() != Some(&"inet") {
            continue;
        }
        let Some(address) = tokens
            .get(1)
            .copied()
            .filter(|a| a.parse::<Ipv4Addr>().is_ok())
        else {
            continue;
        };
        // The mask does not always follow the address immediately.
        let netmask = tokens
            .iter()
            .position(|token| *token == "netmask")
            .and_then(|index| tokens.get(index + 1).copied())
            .and_then(parse_netmask);
        if let Some(netmask) = netmask {
            addresses.push(InetAddr {
                address: address.to_string(),
                netmask,
            });
        }
    }
    addresses
}

/// Decode a netmask written either as hex (`0xffffff00`) or dotted
/// (`255.255.255.0`).
#[cfg(any(test, target_os = "macos"))]
fn parse_netmask(token: &str) -> Option<u32> {
    if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        return u32::from_str_radix(hex, 16).ok();
    }
    token.parse::<Ipv4Addr>().ok().map(u32::from)
}

/// Parse `ip route get <ip>` into the interface and its gateway.
///
/// iproute2 answers on one line — `10.10.20.53 via 192.0.2.1 dev eth0 src
/// 192.0.2.10 uid 1000` — with `via` absent when the destination is on the link
/// itself. Returns `None` when no `dev` is named, which is what the output
/// degrades to when there is no route at all.
#[cfg(any(test, target_os = "linux"))]
pub fn parse_ip_route_get(output: &str) -> Option<RouteGet> {
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let after = |keyword: &str| {
            tokens
                .iter()
                .position(|token| *token == keyword)
                .and_then(|index| tokens.get(index + 1).copied())
        };
        let Some(interface) = after("dev") else {
            continue;
        };
        return Some(RouteGet {
            // No `via` means directly connected, the same shape macOS prints
            // without a `gateway:` line. iproute2 names the family first when
            // the next hop is not the route's own — `via inet6 fe80::1 dev
            // eth0`, an RFC 5549 IPv4-over-IPv6 next hop — so the token after
            // `via` is not always the address; step over the family keyword.
            gateway: after("via")
                .map(|token| match token {
                    "inet" | "inet6" => after(token).unwrap_or(token),
                    _ => token,
                })
                .map(str::to_string),
            interface: interface.to_string(),
        });
    }
    None
}

/// Parse every IPv4 `inet` line out of `ip addr show dev <iface>`.
///
/// iproute2 writes the mask as a prefix length — `inet 192.0.2.10/24 brd
/// 192.0.2.255 scope global eth0` — rather than the netmask ifconfig prints, so
/// the prefix is widened back into a 32-bit mask. `inet6` lines are ignored: the
/// whole reachability calculation is IPv4-only.
///
/// *Every* address, for the same reason [`parse_ifconfig_inets`] keeps them all.
#[cfg(any(test, target_os = "linux"))]
pub fn parse_ip_addr_inets(output: &str) -> Vec<InetAddr> {
    let mut addresses = Vec::new();
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        // `inet` exactly — `inet6` is a different address family.
        if tokens.first() != Some(&"inet") {
            continue;
        }
        let Some((address, prefix)) = tokens.get(1).and_then(|token| token.split_once('/')) else {
            continue;
        };
        if address.parse::<Ipv4Addr>().is_err() {
            continue;
        }
        let Some(netmask) = prefix.parse::<u32>().ok().and_then(netmask_from_prefix) else {
            continue;
        };
        addresses.push(InetAddr {
            address: address.to_string(),
            netmask,
        });
    }
    addresses
}

/// Widen a prefix length into a 32-bit netmask, rejecting anything over /32.
///
/// `/0` is spelled out rather than shifted: `u32::MAX << 32` overflows.
#[cfg(any(test, target_os = "linux"))]
fn netmask_from_prefix(prefix: u32) -> Option<u32> {
    match prefix {
        0 => Some(0),
        1..=32 => Some(u32::MAX << (32 - prefix)),
        _ => None,
    }
}

/// True if `gateway` sits in the same subnet as `address`/`netmask`, i.e. the
/// host can actually put a packet on the wire for it.
///
/// Anything that is not an IPv4 literal on both sides returns `true`: the
/// diagnostic must not cry wolf over an address family this arithmetic does not
/// cover.
pub fn next_hop_on_link(gateway: &str, address: &str, netmask: u32) -> bool {
    let (Ok(gateway), Ok(address)) = (gateway.parse::<Ipv4Addr>(), address.parse::<Ipv4Addr>())
    else {
        return true;
    };
    (u32::from(gateway) & netmask) == (u32::from(address) & netmask)
}

/// A host mask: the interface is point-to-point, so it has no subnet to reason
/// about. macOS prints a `utun` as `inet A --> B netmask 0xffffffff` and Linux
/// as `inet A/32`, and the peer at the other end of such a link is reachable
/// without sharing a subnet with it.
const HOST_NETMASK: u32 = u32::MAX;

/// The reachability verdict for a parsed route, given the addresses configured
/// on the interface it names.
///
/// Three ways to come out on-link without doing the arithmetic, all of them
/// deliberate — the verdict must never invent a fault:
///
/// * a route with no gateway is directly connected;
/// * an interface whose addresses could not be read proves nothing (failing to
///   *read* the interface is not evidence the gateway is unreachable);
/// * a point-to-point interface (`/32`) has no subnet, so its peer gateway is
///   legitimately outside it — the shape of every VPN `utun`/`wg` link.
///
/// Otherwise the gateway need only share a subnet with *one* configured
/// address: an interface carrying aliases is on several subnets at once.
///
/// The `/32` exemption is a property of the *interface*, not of an individual
/// address, and the two differ on an interface carrying both. A host mask
/// contributes no subnet, so it is skipped rather than counted as a match:
/// folding it into the search below let a single `/32` service alias on an
/// ordinary `en0` — a keepalived VIP, an anycast address, a container bridge
/// helper — report every gateway as on-link, silently disabling the check on
/// exactly the kind of host it exists for. Only when *nothing* is left to
/// judge against does the exemption apply.
pub fn route_is_on_link(route: &RouteGet, inets: &[InetAddr]) -> bool {
    let Some(gateway) = route.gateway.as_deref() else {
        return true;
    };
    let mut judgeable = false;
    for inet in inets {
        if inet.netmask == HOST_NETMASK {
            continue;
        }
        judgeable = true;
        if next_hop_on_link(gateway, &inet.address, inet.netmask) {
            return true;
        }
    }
    // No address, or only host masks: nothing to disprove the gateway with.
    !judgeable
}

/// Length of a DNS message header: id, flags and four section counts.
const DNS_HEADER_LEN: usize = 12;
/// `QTYPE` for a host address record.
const QTYPE_A: u16 = 1;
/// `QCLASS` for the internet class.
const QCLASS_IN: u16 = 1;
/// Longest a single label may be (RFC 1035 s2.3.4).
const MAX_LABEL_LEN: usize = 63;
/// Longest an encoded name may be, its terminating root label included.
const MAX_NAME_LEN: usize = 255;
/// Largest reply a resolver may send over UDP without EDNS(0) (RFC 1035 s4.2.1).
const MAX_UDP_REPLY: usize = 512;

/// The name every probe asks for. Reserved for documentation by RFC 2606, so a
/// probe never leaks the operator's own zone onto the wire, and every working
/// resolver has an answer for it.
pub const PROBE_NAME: &str = "example.com";

/// Encode a standard recursive A query for `name` as a wire-format DNS message.
///
/// Hand-rolled rather than taken from a crate: a query is a 12-byte header, a
/// length-prefixed name and four bytes of type and class, and the diagnostic
/// wants nothing else from DNS.
pub fn build_dns_query(transaction_id: u16, name: &str) -> Result<Vec<u8>> {
    let mut message = Vec::with_capacity(DNS_HEADER_LEN + name.len() + 6);
    message.extend_from_slice(&transaction_id.to_be_bytes());
    // Recursion desired, every other flag clear: an ordinary standard query.
    message.extend_from_slice(&0x0100u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT: one question
    message.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    message.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    message.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    let qname_start = message.len();
    // A trailing dot is the root label, which the terminator below already is.
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            bail!("cannot query {name:?}: it has an empty label");
        }
        if !label.is_ascii() {
            bail!("cannot query {name:?}: labels must be ASCII, already punycoded");
        }
        if label.len() > MAX_LABEL_LEN {
            bail!("cannot query {name:?}: label {label:?} is over {MAX_LABEL_LEN} bytes");
        }
        // Checked directly above, so the cast cannot truncate.
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0); // the root label, terminating the name
    if message.len() - qname_start > MAX_NAME_LEN {
        bail!("cannot query {name:?}: the encoded name is over {MAX_NAME_LEN} bytes");
    }

    message.extend_from_slice(&QTYPE_A.to_be_bytes());
    message.extend_from_slice(&QCLASS_IN.to_be_bytes());
    Ok(message)
}

/// Check that `message` is a reply to the query that carried `transaction_id`.
///
/// Only the header is read. A reply whose id matches, with the QR bit set,
/// proves the resolver took the query and answered it — which is the entire
/// question this diagnostic asks. The RCODE is deliberately not interpreted: a
/// SERVFAIL from a resolver that replies is still a resolver that is reachable,
/// and reading it as a failure would blame the network for the zone.
pub fn parse_dns_response(message: &[u8], transaction_id: u16) -> Result<()> {
    if message.len() < DNS_HEADER_LEN {
        bail!(
            "DNS reply is {} bytes, short of the {DNS_HEADER_LEN}-byte header",
            message.len()
        );
    }
    let replied = u16::from_be_bytes([message[0], message[1]]);
    if replied != transaction_id {
        bail!("DNS reply carries transaction id {replied:#06x}, expected {transaction_id:#06x}");
    }
    // Top bit of the flags word: 0 is a query, 1 is a response.
    if message[2] & 0x80 == 0 {
        bail!("DNS reply has the QR bit clear, so it is a query and not an answer");
    }
    Ok(())
}

/// The well-known DNS port. Only `probe_udp53` hardcodes it, so
/// `probe_udp53_at` can be pointed at a loopback responder by the tests.
const DNS_PORT: u16 = 53;

/// Send one A query to `nameserver` over UDP/53 and time the round trip.
///
/// A thin wrapper that pins the port: everything else lives in
/// `probe_udp53_at`, which the tests drive against a responder bound to
/// `127.0.0.1:0`. `cmd_dns` is this function's caller, and takes it as a
/// parameter so the report around it stays testable too.
pub fn probe_udp53(nameserver: &str, timeout: Duration) -> Result<Duration> {
    let address: IpAddr = nameserver
        .parse()
        .with_context(|| format!("{nameserver} is not an IP address"))?;
    probe_udp53_at(SocketAddr::new(address, DNS_PORT), timeout)
}

/// Whether a `recv` failure is the read timeout expiring rather than a real
/// I/O error.
///
/// A blocking socket carrying `SO_RCVTIMEO` reports the expiry as `EAGAIN` on
/// unix and `WSAETIMEDOUT` on Windows, which std maps to `WouldBlock` and
/// `TimedOut` respectively. Both spellings have to count, or the platform
/// decides which message the user gets.
fn is_receive_timeout(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Send one A query to `target` over UDP and time the round trip.
///
/// The socket layer over `build_dns_query` and `parse_dns_response`. Takes a
/// full `SocketAddr` rather than an address and a fixed 53 so a test can point
/// it at a loopback responder — no real DNS query is ever made by the suite.
pub fn probe_udp53_at(target: SocketAddr, timeout: Duration) -> Result<Duration> {
    // Bind in the target's own address family, or `connect` refuses the peer.
    let bind: SocketAddr = match target.ip() {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(bind)
        .with_context(|| format!("failed to open a UDP socket for {target}"))?;
    // `connect` on a datagram socket also filters what arrives, so a reply from
    // any other host never reaches the parser.
    socket
        .connect(target)
        .with_context(|| format!("failed to point a UDP socket at {target}"))?;
    socket
        .set_read_timeout(Some(timeout))
        .and_then(|()| socket.set_write_timeout(Some(timeout)))
        .with_context(|| format!("failed to set a {timeout:?} timeout on the UDP socket"))?;

    let transaction_id: u16 = rand::rng().random();
    let query = build_dns_query(transaction_id, PROBE_NAME)?;

    let started = Instant::now();
    socket
        .send(&query)
        .with_context(|| format!("failed to send a DNS query to {target}"))?;
    let mut buffer = [0u8; MAX_UDP_REPLY];
    let read = match socket.recv(&mut buffer) {
        Ok(read) => read,
        // The two failures read very differently to whoever is holding the
        // incident. A timeout means the query left and nothing came back —
        // firewall, blackhole, wedged resolver. `ECONNREFUSED`, which a
        // *connected* UDP socket surfaces when the peer answers the datagram
        // with an ICMP port-unreachable, means the host is up and reachable and
        // simply has nothing listening on 53. Reporting the second as "no reply
        // within 2s" points the reader at the network when the answer is the
        // resolver address.
        Err(e) if is_receive_timeout(&e) => {
            return Err(anyhow::Error::new(e))
                .with_context(|| format!("no DNS reply from {target} within {timeout:?}"));
        }
        Err(e) => {
            return Err(anyhow::Error::new(e))
                .with_context(|| format!("failed to read a DNS reply from {target}"));
        }
    };
    let elapsed = started.elapsed();

    parse_dns_response(&buffer[..read], transaction_id)
        .with_context(|| format!("malformed DNS reply from {target}"))?;
    Ok(elapsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sanitized shape of macOS `route -n get`: a gateway one hop away on en0.
    // Values are fixtures only — see the plan's sanitization table.
    const ROUTE_GET_FIXTURE: &str = "\
   route to: 10.10.20.53
destination: 10.10.20.0
       mask: 255.255.255.0
    gateway: 10.10.20.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
";

    // A destination on the local link: no `gateway:` line at all.
    const ROUTE_GET_DIRECT_FIXTURE: &str = "\
   route to: 192.0.2.20
destination: 192.0.2.0
       mask: 255.255.255.0
  interface: en0
      flags: <UP,DONE,CLONING>
";

    const IFCONFIG_FIXTURE: &str = "\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\toptions=400<CHANNEL_IO>
\tether 02:00:5e:10:00:00
\tinet6 fe80::1%en0 prefixlen 64 secured scopeid 0xc
\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255
\tnd6 options=201<PERFORMNUD,DAD>
\tmedia: autoselect
\tstatus: active
";

    // The same interface carrying a second address on another subnet, which is
    // what an alias, a second lease or a container bridge looks like.
    const IFCONFIG_ALIAS_FIXTURE: &str = "\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255
\tinet 10.10.20.10 netmask 0xffffff00 broadcast 10.10.20.255
\tstatus: active
";

    // A macOS VPN tunnel: point-to-point, so the mask is a host mask and the
    // peer gateway is legitimately outside the "subnet".
    const IFCONFIG_UTUN_FIXTURE: &str = "\
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400
\tinet 10.10.20.9 --> 10.10.20.9 netmask 0xffffffff
";

    // An ordinary interface carrying a /32 service alias next to its real
    // subnet: a keepalived VIP, an anycast address, a container bridge helper.
    // The host mask is not a point-to-point link and must not exempt en0 from
    // the arithmetic the /24 supports.
    const IFCONFIG_HOST_ALIAS_FIXTURE: &str = "\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255
\tinet 198.51.100.7 netmask 0xffffffff
\tstatus: active
";

    // Sanitized shape of `ip route get`: iproute2 answers on one line.
    const IP_ROUTE_GET_FIXTURE: &str = "\
10.10.20.53 via 10.10.20.1 dev eth0 src 192.0.2.10 uid 1000
    cache
";

    // On-link destination: iproute2 simply omits `via`.
    const IP_ROUTE_GET_DIRECT_FIXTURE: &str = "\
192.0.2.20 dev eth0 src 192.0.2.10 uid 1000
    cache
";

    const IP_ADDR_SHOW_FIXTURE: &str = "\
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:00:5e:10:00:00 brd ff:ff:ff:ff:ff:ff
    inet 192.0.2.10/24 brd 192.0.2.255 scope global dynamic eth0
       valid_lft 84611sec preferred_lft 84611sec
    inet6 fe80::1/64 scope link
       valid_lft forever preferred_lft forever
";

    // The same device with a second address, iproute2's spelling of an alias.
    const IP_ADDR_SHOW_ALIAS_FIXTURE: &str = "\
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    inet 192.0.2.10/24 brd 192.0.2.255 scope global dynamic eth0
    inet 10.10.20.10/24 brd 10.10.20.255 scope global secondary eth0
";

    #[test]
    fn parse_route_get_extracts_gateway_and_interface() {
        let route = parse_route_get(ROUTE_GET_FIXTURE).expect("route parses");
        assert_eq!(route.gateway.as_deref(), Some("10.10.20.1"));
        assert_eq!(route.interface, "en0");
    }

    #[test]
    fn parse_route_get_treats_missing_gateway_as_directly_connected() {
        let route = parse_route_get(ROUTE_GET_DIRECT_FIXTURE).expect("route parses");
        assert_eq!(route.gateway, None);
        assert_eq!(route.interface, "en0");
        // No gateway means the destination is on the link itself.
        assert!(route_is_on_link(&route, &[]));
        assert!(route_is_on_link(
            &route,
            &[InetAddr {
                address: "192.0.2.10".to_string(),
                netmask: 0xffff_ff00,
            }]
        ));
    }

    #[test]
    fn parse_route_get_returns_none_without_an_interface() {
        // What `route` prints for a destination that is not in the table.
        assert_eq!(
            parse_route_get("route: writing to routing socket: not in table"),
            None
        );
        assert_eq!(parse_route_get(""), None);
    }

    #[test]
    fn parse_ifconfig_inets_decodes_hex_netmask() {
        let inets = parse_ifconfig_inets(IFCONFIG_FIXTURE);
        assert_eq!(inets.len(), 1);
        assert_eq!(inets[0].address, "192.0.2.10");
        assert_eq!(inets[0].netmask, 0xffff_ff00);
    }

    #[test]
    fn parse_ifconfig_inets_accepts_dotted_netmask() {
        let inets = parse_ifconfig_inets("\tinet 192.0.2.10 netmask 255.255.0.0");
        assert_eq!(inets[0].netmask, 0xffff_0000);
    }

    #[test]
    fn parse_ifconfig_inets_keeps_every_alias() {
        let inets = parse_ifconfig_inets(IFCONFIG_ALIAS_FIXTURE);
        assert_eq!(
            inets,
            vec![
                InetAddr {
                    address: "192.0.2.10".to_string(),
                    netmask: 0xffff_ff00,
                },
                InetAddr {
                    address: "10.10.20.10".to_string(),
                    netmask: 0xffff_ff00,
                },
            ],
            "an aliased interface is on both subnets, not just the first"
        );
    }

    #[test]
    fn parse_ifconfig_inets_ignores_ipv6_and_empty_output() {
        assert!(
            parse_ifconfig_inets("\tinet6 fe80::1%en0 prefixlen 64 secured scopeid 0xc").is_empty()
        );
        assert!(parse_ifconfig_inets("").is_empty());
    }

    #[test]
    fn parse_ifconfig_inets_reads_a_point_to_point_tunnel() {
        let inets = parse_ifconfig_inets(IFCONFIG_UTUN_FIXTURE);
        assert_eq!(inets.len(), 1);
        assert_eq!(inets[0].address, "10.10.20.9");
        assert_eq!(inets[0].netmask, u32::MAX, "a utun is a /32");
    }

    #[test]
    fn next_hop_on_link_rejects_a_gateway_outside_the_subnet() {
        // The incident shape: a stale gateway left over from another network.
        assert!(!next_hop_on_link("10.10.99.1", "192.0.2.10", 0xffff_ff00));
    }

    #[test]
    fn next_hop_on_link_accepts_a_gateway_inside_the_subnet() {
        assert!(next_hop_on_link("192.0.2.1", "192.0.2.10", 0xffff_ff00));
        // Same pair, widened mask: still on-link.
        assert!(next_hop_on_link("192.0.2.1", "192.0.2.10", 0xffff_0000));
    }

    #[test]
    fn next_hop_on_link_does_not_cry_wolf_over_non_ipv4() {
        assert!(next_hop_on_link("fe80::1", "192.0.2.10", 0xffff_ff00));
        assert!(next_hop_on_link("192.0.2.1", "not-an-address", 0xffff_ff00));
    }

    #[test]
    fn route_is_on_link_composes_the_parsers() {
        let route = parse_route_get(ROUTE_GET_FIXTURE).expect("route parses");
        let inets = parse_ifconfig_inets(IFCONFIG_FIXTURE);
        // 10.10.20.1 through an interface addressed 192.0.2.10/24: unreachable.
        assert!(!route_is_on_link(&route, &inets));
        // Without any interface address there is nothing to disprove.
        assert!(route_is_on_link(&route, &[]));
    }

    /// The last step of every `Platform::next_hop_status`, which was inlined
    /// and duplicated in each platform impl until `NextHop::from_route` pulled
    /// it out: the route's gateway and interface are carried across unchanged
    /// and `on_link` is the computed verdict. No test could reach this while it
    /// sat behind a `Command`.
    #[test]
    fn next_hop_from_route_carries_the_route_across_and_flags_an_off_subnet_gateway() {
        let route = parse_route_get(ROUTE_GET_FIXTURE).expect("route parses");
        let inets = parse_ifconfig_inets(IFCONFIG_FIXTURE);

        let hop = crate::platform::NextHop::from_route(route, &inets);

        assert_eq!(hop.gateway.as_deref(), Some("10.10.20.1"));
        assert_eq!(hop.interface, "en0");
        assert!(
            !hop.on_link,
            "10.10.20.1 is outside the interface's 192.0.2.10/24"
        );
    }

    /// The Linux half of the same assembly, over `ip route get` output.
    #[test]
    fn next_hop_from_route_reads_a_directly_connected_linux_route() {
        let route = parse_ip_route_get(IP_ROUTE_GET_DIRECT_FIXTURE).expect("route parses");
        let inets = parse_ip_addr_inets(IP_ADDR_SHOW_FIXTURE);

        let hop = crate::platform::NextHop::from_route(route, &inets);

        assert_eq!(
            hop.gateway, None,
            "a directly connected route has no gateway"
        );
        assert!(hop.on_link, "there is no gateway to be off the subnet");
    }

    /// An interface whose addresses could not be read must not be reported as a
    /// fault: failing to read it is not evidence the gateway is unreachable.
    #[test]
    fn next_hop_from_route_fails_open_on_an_unreadable_interface() {
        let route = parse_route_get(ROUTE_GET_FIXTURE).expect("route parses");

        let hop = crate::platform::NextHop::from_route(route, &[]);

        assert!(hop.on_link);
    }

    #[test]
    fn route_is_on_link_accepts_a_gateway_on_a_second_address() {
        let route = parse_route_get(ROUTE_GET_FIXTURE).expect("route parses");
        let inets = parse_ifconfig_inets(IFCONFIG_ALIAS_FIXTURE);
        // The gateway 10.10.20.1 is off the first address's subnet but on the
        // alias's, so the interface can put a packet on the wire for it.
        assert!(
            route_is_on_link(&route, &inets),
            "one matching alias is enough"
        );
    }

    #[test]
    fn route_is_on_link_does_not_cry_wolf_over_a_point_to_point_link() {
        let route = parse_route_get(ROUTE_GET_FIXTURE).expect("route parses");
        let inets = parse_ifconfig_inets(IFCONFIG_UTUN_FIXTURE);
        // 10.10.20.1 over a /32 utun: no subnet to be outside of, so the
        // arithmetic cannot judge it and the probe must still run.
        assert!(
            route_is_on_link(&route, &inets),
            "a VPN tunnel's peer gateway is not a fault"
        );
    }

    /// The other half of the same rule: a `/32` sitting *beside* a real subnet
    /// is an alias, not a point-to-point link, and must not carry the
    /// exemption. Evaluating the host mask inside the search made one such
    /// alias answer for the whole interface, so the stale-gateway incident this
    /// command was written for went unreported on any host with a VIP.
    #[test]
    fn route_is_on_link_still_judges_an_interface_with_a_host_alias() {
        let route = parse_route_get(ROUTE_GET_FIXTURE).expect("route parses");
        let inets = parse_ifconfig_inets(IFCONFIG_HOST_ALIAS_FIXTURE);
        assert_eq!(inets.len(), 2, "both addresses parse");
        // 10.10.20.1 is off the /24 and the /32 proves nothing either way.
        assert!(
            !route_is_on_link(&route, &inets),
            "a host alias must not exempt an interface that has a subnet"
        );
    }

    #[test]
    fn parse_ip_route_get_extracts_gateway_and_interface() {
        let route = parse_ip_route_get(IP_ROUTE_GET_FIXTURE).expect("route parses");
        assert_eq!(route.gateway.as_deref(), Some("10.10.20.1"));
        assert_eq!(route.interface, "eth0");
    }

    #[test]
    fn parse_ip_route_get_treats_a_missing_via_as_directly_connected() {
        let route = parse_ip_route_get(IP_ROUTE_GET_DIRECT_FIXTURE).expect("route parses");
        assert_eq!(route.gateway, None);
        assert_eq!(route.interface, "eth0");
        assert!(route_is_on_link(&route, &[]));
    }

    /// An IPv4 destination reached over an IPv6 next hop (RFC 5549): iproute2
    /// writes the family before the address, and taking the token straight
    /// after `via` rendered the literal `inet6` as the gateway.
    #[test]
    fn parse_ip_route_get_steps_over_the_next_hop_family() {
        let route = parse_ip_route_get(
            "10.10.20.53 via inet6 fe80::1 dev eth0 src 192.0.2.10 uid 1000 \n    cache",
        )
        .expect("route parses");
        assert_eq!(route.gateway.as_deref(), Some("fe80::1"));
        assert_eq!(route.interface, "eth0");
    }

    #[test]
    fn parse_ip_route_get_returns_none_without_a_dev() {
        // What iproute2 prints when the destination has no route.
        assert_eq!(
            parse_ip_route_get("RTNETLINK answers: Network is unreachable"),
            None
        );
        assert_eq!(parse_ip_route_get(""), None);
    }

    #[test]
    fn parse_ip_addr_inets_widens_the_prefix_length() {
        let inets = parse_ip_addr_inets(IP_ADDR_SHOW_FIXTURE);
        assert_eq!(inets.len(), 1);
        assert_eq!(inets[0].address, "192.0.2.10");
        assert_eq!(inets[0].netmask, 0xffff_ff00, "/24 is 255.255.255.0");
    }

    #[test]
    fn parse_ip_addr_inets_handles_the_edges_of_the_prefix_range() {
        let host = parse_ip_addr_inets("    inet 192.0.2.10/32 scope host lo");
        assert_eq!(host[0].netmask, u32::MAX);

        let any = parse_ip_addr_inets("    inet 192.0.2.10/0 scope global eth0");
        // `/0` must be spelled out: shifting a u32 by 32 overflows.
        assert_eq!(any[0].netmask, 0);

        // A prefix that cannot be a v4 mask is not an address to reason from.
        assert!(parse_ip_addr_inets("    inet 192.0.2.10/64 scope global").is_empty());
    }

    #[test]
    fn parse_ip_addr_inets_keeps_every_alias() {
        let inets = parse_ip_addr_inets(IP_ADDR_SHOW_ALIAS_FIXTURE);
        assert_eq!(inets.len(), 2, "both addresses survive");
        assert_eq!(inets[1].address, "10.10.20.10");
    }

    #[test]
    fn parse_ip_addr_inets_ignores_ipv6_and_maskless_output() {
        assert!(parse_ip_addr_inets("    inet6 fe80::1/64 scope link").is_empty());
        // ifconfig's shape has no prefix, so this parser must decline it.
        assert!(parse_ip_addr_inets("\tinet 192.0.2.10 netmask 0xffff0000").is_empty());
        assert!(parse_ip_addr_inets("").is_empty());
    }

    #[test]
    fn route_is_on_link_composes_the_linux_parsers_too() {
        let route = parse_ip_route_get(IP_ROUTE_GET_FIXTURE).expect("route parses");
        let inets = parse_ip_addr_inets(IP_ADDR_SHOW_FIXTURE);
        // 10.10.20.1 through an interface addressed 192.0.2.10/24: unreachable.
        assert!(!route_is_on_link(&route, &inets));
    }

    #[test]
    fn route_is_on_link_spares_a_linux_point_to_point_link() {
        let route = parse_ip_route_get(IP_ROUTE_GET_FIXTURE).expect("route parses");
        let inets = parse_ip_addr_inets("    inet 10.10.20.9/32 scope global wg0");
        assert!(
            route_is_on_link(&route, &inets),
            "a wireguard /32 has no subnet to be outside of"
        );
    }

    /// A reply header for `transaction_id`: our own query bytes, optionally with
    /// the QR bit set — the shape a resolver echoes back.
    fn reply(transaction_id: u16, is_answer: bool) -> Vec<u8> {
        let mut message = build_dns_query(transaction_id, PROBE_NAME).expect("query builds");
        if is_answer {
            message[2] |= 0x80;
        }
        message
    }

    #[test]
    fn build_dns_query_encodes_a_standard_a_question() {
        let query = build_dns_query(0x1234, "example.com").expect("query builds");

        // 12-byte header, then `7example3com0`, then QTYPE and QCLASS.
        assert_eq!(query.len(), DNS_HEADER_LEN + 13 + 4);
        assert_eq!(&query[0..2], &[0x12u8, 0x34], "transaction id");
        assert_eq!(
            &query[2..4],
            &[0x01u8, 0x00],
            "recursion desired, nothing else"
        );
        assert_eq!(&query[4..6], &[0x00u8, 0x01], "QDCOUNT is one question");
        assert_eq!(
            &query[6..12],
            &[0u8; 6],
            "no answer, authority or additional records"
        );
        assert_eq!(&query[12..25], b"\x07example\x03com\x00", "QNAME labels");
        assert_eq!(&query[25..27], &QTYPE_A.to_be_bytes(), "QTYPE A");
        assert_eq!(&query[27..29], &QCLASS_IN.to_be_bytes(), "QCLASS IN");
    }

    #[test]
    fn build_dns_query_treats_a_trailing_dot_as_the_root_label() {
        assert_eq!(
            build_dns_query(0x1234, "example.com.").expect("query builds"),
            build_dns_query(0x1234, "example.com").expect("query builds"),
        );
    }

    #[test]
    fn build_dns_query_rejects_names_it_cannot_encode() {
        assert!(build_dns_query(1, "").is_err(), "empty name");
        assert!(build_dns_query(1, "example..com").is_err(), "empty label");
        assert!(
            build_dns_query(1, &"a".repeat(MAX_LABEL_LEN + 1)).is_err(),
            "label over 63 bytes"
        );
        assert!(
            build_dns_query(1, "\u{f6}sterreich.test").is_err(),
            "a unicode name that was never punycoded"
        );
        // Four legal labels that together overrun the 255-byte encoded name.
        let long_name = vec!["a".repeat(MAX_LABEL_LEN); 4].join(".");
        assert!(
            build_dns_query(1, &long_name).is_err(),
            "encoded name over {MAX_NAME_LEN} bytes"
        );
    }

    #[test]
    fn parse_dns_response_accepts_the_matching_reply() {
        assert!(parse_dns_response(&reply(0x1234, true), 0x1234).is_ok());
    }

    #[test]
    fn parse_dns_response_rejects_another_querys_transaction_id() {
        // A late reply to a query we are no longer waiting on.
        assert!(parse_dns_response(&reply(0x1234, true), 0x4321).is_err());
    }

    #[test]
    fn parse_dns_response_rejects_a_message_with_the_qr_bit_clear() {
        // Our own query reflected back: right id, but it is not an answer.
        assert!(parse_dns_response(&reply(0x1234, false), 0x1234).is_err());
    }

    #[test]
    fn parse_dns_response_rejects_short_input_instead_of_panicking() {
        let answer = reply(0x1234, true);
        for length in 0..DNS_HEADER_LEN {
            assert!(
                parse_dns_response(&answer[..length], 0x1234).is_err(),
                "{length} bytes must be rejected, never indexed into"
            );
        }
        // The header alone suffices — the question section is not inspected.
        assert!(parse_dns_response(&answer[..DNS_HEADER_LEN], 0x1234).is_ok());
    }

    /// Bind a UDP responder on loopback and answer `answers` datagrams by
    /// echoing each query back with the QR bit set — the smallest thing that
    /// looks like a resolver. Returns the address to probe and the thread, so
    /// the caller can join it and let the socket close.
    ///
    /// `mangle` gets the echoed reply before it goes out, which is how the
    /// wrong-transaction-id case is built without a second responder.
    fn loopback_responder(
        answers: usize,
        mangle: fn(&mut Vec<u8>),
    ) -> (SocketAddr, std::thread::JoinHandle<()>) {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("loopback bind");
        let address = socket.local_addr().expect("bound address");
        // Without this a wedged test would hang the suite rather than fail it.
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let handle = std::thread::spawn(move || {
            for _ in 0..answers {
                let mut buffer = [0u8; MAX_UDP_REPLY];
                let Ok((read, from)) = socket.recv_from(&mut buffer) else {
                    return;
                };
                let mut reply = buffer[..read].to_vec();
                reply[2] |= 0x80; // QR: this is an answer
                mangle(&mut reply);
                let _ = socket.send_to(&reply, from);
            }
        });
        (address, handle)
    }

    #[test]
    fn probe_udp53_at_times_a_reply_from_a_responder() {
        let (address, responder) = loopback_responder(1, |_| {});

        let elapsed = probe_udp53_at(address, Duration::from_secs(5))
            .expect("a responder that answers is a resolver that works");

        // The clock starts after the socket is set up, so the round trip is
        // real but bounded — asserting a floor of zero would test nothing.
        assert!(
            elapsed < Duration::from_secs(5),
            "a loopback round trip cannot take the whole timeout: {elapsed:?}"
        );
        responder.join().expect("responder thread");
    }

    #[test]
    fn probe_udp53_at_rejects_a_reply_carrying_another_transaction_id() {
        let (address, responder) = loopback_responder(1, |reply| {
            reply[0] ^= 0xff;
            reply[1] ^= 0xff;
        });

        let error = probe_udp53_at(address, Duration::from_secs(5))
            .expect_err("a reply to somebody else's query is not an answer");

        assert!(
            format!("{error:#}").contains("transaction id"),
            "the mismatch must be named: {error:#}"
        );
        responder.join().expect("responder thread");
    }

    /// How far under its requested timeout a `recv` is allowed to come back
    /// and still count as having waited. Generous next to the rounding it
    /// absorbs and still two orders of magnitude under the "returned
    /// immediately" failure the assertion exists to catch.
    const RECEIVE_TIMEOUT_SLACK: Duration = Duration::from_millis(20);

    #[test]
    fn probe_udp53_at_reports_a_silent_resolver_as_a_timeout() {
        // Bound but never answering: the shape of a firewalled resolver.
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("loopback bind");
        let address = socket.local_addr().expect("bound address");

        let timeout = Duration::from_millis(150);
        let started = Instant::now();
        let error = probe_udp53_at(address, timeout).expect_err("nothing ever answers");

        // What is being tested is that the probe *waits* rather than falling
        // through, so the floor carries a tolerance: `SO_RCVTIMEO` is a
        // kernel timer rounded to its own granularity and compared here
        // against `Instant`'s clock, and it may return a hair early without
        // anything being wrong. An exact floor made this assertion a
        // load-sensitive flake; the failure it is meant to catch - a probe
        // that gives up immediately - is nowhere near this margin.
        let floor = timeout - RECEIVE_TIMEOUT_SLACK;
        let elapsed = started.elapsed();
        assert!(
            elapsed >= floor,
            "the probe must wait out its timeout, not return early: {elapsed:?} < {floor:?}"
        );
        assert!(
            format!("{error:#}").contains("no DNS reply"),
            "the timeout must be named: {error:#}"
        );
    }

    #[test]
    fn is_receive_timeout_covers_both_platform_spellings() {
        use std::io::{Error, ErrorKind};
        assert!(is_receive_timeout(&Error::from(ErrorKind::WouldBlock)));
        assert!(is_receive_timeout(&Error::from(ErrorKind::TimedOut)));
        assert!(!is_receive_timeout(&Error::from(
            ErrorKind::ConnectionRefused
        )));
        assert!(!is_receive_timeout(&Error::from(
            ErrorKind::PermissionDenied
        )));
    }

    /// A resolver address with nothing listening on 53 is a different incident
    /// from a silent one: the host is up, the route works, and the port is
    /// closed. Reporting it as "no DNS reply within 2s" sends the reader after
    /// the network instead of after the address.
    ///
    /// The refusal depends on the host looping an ICMP port-unreachable back to
    /// the connected socket. Where it does — Linux and macOS loopback both do —
    /// this pins the wording; where it does not, the probe legitimately times
    /// out and there is nothing to assert, which is why the check is guarded
    /// rather than unconditional.
    #[test]
    fn probe_udp53_at_does_not_report_a_closed_port_as_silence() {
        // Bound and immediately released: an address with no listener.
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("loopback bind");
        let address = socket.local_addr().expect("bound address");
        drop(socket);

        let error = probe_udp53_at(address, Duration::from_millis(250))
            .expect_err("nothing is listening on a released port");
        let rendered = format!("{error:#}");

        let refused = error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::ConnectionRefused);
        if refused {
            assert!(
                !rendered.contains("no DNS reply"),
                "a refused port must not be rendered as silence: {rendered}"
            );
        }
    }
}
