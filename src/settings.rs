//! The settings the caller injects.
//!
//! The crate reads no configuration file and consults no environment
//! variable: everything the client needs arrives through
//! [`TunSettings`]. The caller decides where the values come from.

use std::path::PathBuf;

use crate::error::{Error, Result};

/// Which transport the client uses to reach the gateway.
///
/// `Auto` is the default and reproduces the pre-QUIC behaviour of
/// trying QUIC first: the client attempts QUIC with a bounded
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
    /// The stable, lower-case name used in the configuration file and
    /// in the log lines.
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

impl std::str::FromStr for TransportSelector {
    type Err = Error;

    /// Parse the selector's name.
    ///
    /// The names are the ones the tun's configuration file uses:
    /// `auto`, `quic` and `tcp`. The fallback transport is also
    /// accepted under the names its transport is known by.
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(TransportSelector::Auto),
            "quic" => Ok(TransportSelector::Quic),
            "tcp" | "websocket" | "ws" => Ok(TransportSelector::Tcp),
            other => Err(Error::Invalid(format!(
                "unknown transport {other:?} — expected auto, quic or tcp"
            ))),
        }
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
    use std::str::FromStr;

    /// The selector accepts the three documented names.
    #[test]
    fn the_selector_accepts_the_three_documented_names() {
        assert_eq!(
            TransportSelector::from_str("auto").unwrap(),
            TransportSelector::Auto
        );
        assert_eq!(
            TransportSelector::from_str("quic").unwrap(),
            TransportSelector::Quic
        );
        assert_eq!(
            TransportSelector::from_str("tcp").unwrap(),
            TransportSelector::Tcp
        );
    }

    /// The names round-trip through the parser — the configuration
    /// file and the log lines use the same spelling.
    #[test]
    fn the_names_roundtrip() {
        for selector in [
            TransportSelector::Auto,
            TransportSelector::Quic,
            TransportSelector::Tcp,
        ] {
            assert_eq!(
                TransportSelector::from_str(selector.as_str()).unwrap(),
                selector
            );
        }
    }

    /// The parser is forgiving about case and surrounding whitespace,
    /// so a value that reached the crate from a text file still
    /// works.
    #[test]
    fn the_parser_ignores_case_and_whitespace() {
        assert_eq!(
            TransportSelector::from_str(" QUIC ").unwrap(),
            TransportSelector::Quic
        );
    }

    /// The fallback transport is also known under the names its
    /// transport is known by.
    #[test]
    fn the_fallback_transport_is_known_under_its_other_names() {
        for name in ["websocket", "ws"] {
            assert_eq!(
                TransportSelector::from_str(name).unwrap(),
                TransportSelector::Tcp
            );
        }
    }

    /// An unknown name is refused rather than silently defaulting to
    /// `auto` — a typo must not change the transport.
    #[test]
    fn an_unknown_name_is_refused() {
        let err = TransportSelector::from_str("carrier-pigeon").unwrap_err();
        assert!(matches!(err, Error::Invalid(_)), "{err}");
    }

    /// The default is `auto`: prefer QUIC, fall back.
    #[test]
    fn the_default_is_auto() {
        assert_eq!(TransportSelector::default(), TransportSelector::Auto);
    }
}
