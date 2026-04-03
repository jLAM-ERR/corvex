use anyhow::{bail, Result};
use log::debug;
use rand::Rng;
use std::net::TcpListener;

const PORT_MIN: u16 = 20000;
const PORT_MAX: u16 = 60000;
const MAX_ATTEMPTS: u32 = 100;

/// Find a free port by randomly picking in the range 20000-60000 and attempting to bind.
/// Retries up to 100 times before giving up.
///
/// Note: there is a small TOCTOU window between port validation and xray binding.
/// The 40K port range makes collisions unlikely.
pub fn find_free_port() -> Result<u16> {
    let mut rng = rand::rng();
    for attempt in 1..=MAX_ATTEMPTS {
        let port = rng.random_range(PORT_MIN..=PORT_MAX);
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            if attempt > 1 {
                debug!("found free port {} after {} attempts", port, attempt);
            } else {
                debug!("found free port {}", port);
            }
            return Ok(port);
        }
    }
    bail!("failed to find a free port after {MAX_ATTEMPTS} attempts")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_free_port_in_range() {
        let port = find_free_port().expect("should find a free port");
        assert!(
            (PORT_MIN..=PORT_MAX).contains(&port),
            "port {port} is outside range {PORT_MIN}-{PORT_MAX}"
        );
    }

    #[test]
    fn test_find_free_port_is_bindable() {
        let port = find_free_port().expect("should find a free port");
        let listener = TcpListener::bind(("127.0.0.1", port));
        assert!(
            listener.is_ok(),
            "port {port} should be bindable but got: {:?}",
            listener.err()
        );
    }
}
