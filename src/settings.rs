//! The settings the caller injects.
//!
//! The crate reads no configuration file and consults no environment
//! variable: everything the client needs arrives through
//! [`TunSettings`]. The caller decides where the values come from.

use std::path::PathBuf;

/// Which transport the client uses to reach the gateway.
///
/// `Auto` is the default: the client attempts QUIC with a bounded
/// handshake timeout and falls back to the WebSocket/TCP transport
/// when the attempt fails. `Quic` and `Tcp` pin the client to one
/// transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportSelector {
    /// Prefer QUIC, fall back to the WebSocket/TCP transport.
    #[default]
    Auto,
    /// QUIC only — no fallback. The tunnel fails when the network
    /// blocks UDP.
    Quic,
    /// WebSocket/TCP only — the transport used before QUIC existed.
    Tcp,
}

impl TransportSelector {
    /// The stable, lower-case name of the selector — the spelling the
    /// log lines and the caller's configuration use.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportSelector::Auto => "auto",
            TransportSelector::Quic => "quic",
            TransportSelector::Tcp => "tcp",
        }
    }
}

impl std::fmt::Display for TransportSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Everything the tunnel client needs, supplied by the caller.
///
/// The crate has no opinion about where the values came from: a
/// configuration file, an environment variable, a command-line flag
/// or a test fixture are all the caller's business.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunSettings {
    /// The gateway's tunnel endpoint, `host:port`.
    pub server: String,
    /// The bearer token the gateway validates against the `tun` table.
    pub token: String,
    /// This tun's name, as registered on the gateway.
    pub name: String,
    /// Which transport to use: `auto` prefers QUIC and falls back.
    pub transport: TransportSelector,
    /// Where the trusted gateway-certificate fingerprints are kept.
    pub pin_path: PathBuf,
    /// Where the time of the last failed QUIC attempt is kept.
    pub quic_failure_path: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names are the crate's output vocabulary — the log lines and
    /// the caller's configuration use the same spelling.
    #[test]
    fn the_selector_names_are_stable() {
        assert_eq!(TransportSelector::Auto.as_str(), "auto");
        assert_eq!(TransportSelector::Quic.as_str(), "quic");
        assert_eq!(TransportSelector::Tcp.as_str(), "tcp");
        assert_eq!(TransportSelector::Auto.to_string(), "auto");
        assert_eq!(TransportSelector::Quic.to_string(), "quic");
        assert_eq!(TransportSelector::Tcp.to_string(), "tcp");
    }

    /// The default is `auto`: prefer QUIC, fall back.
    #[test]
    fn the_default_is_auto() {
        assert_eq!(TransportSelector::default(), TransportSelector::Auto);
    }
}
