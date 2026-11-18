//! The crate's error type.

/// A failure of the tunnel.
///
/// The variants are what a caller acts on. `Unreachable`, `Untrusted`
/// and `Refused` are the three outcomes a caller has to tell apart
/// before it decides what to do next — in particular, only
/// `Unreachable` allows a fallback to the unencrypted WebSocket/TCP
/// transport.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The operation failed at the I/O level.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The input or the state is not usable.
    #[error("invalid: {0}")]
    Invalid(String),
    /// The peer sent something the protocol does not define.
    #[error("protocol: {0}")]
    Protocol(String),
    /// The gateway could not be reached: UDP blocked, the address is
    /// wrong, the handshake timed out. Falling back to the
    /// WebSocket/TCP transport is allowed.
    #[error("unreachable: {0}")]
    Unreachable(String),
    /// The gateway's certificate is not the one this tun pinned.
    /// Falling back is not allowed: the fallback is unencrypted, so it
    /// would hand the bearer token to whoever is presenting the wrong
    /// certificate.
    #[error("untrusted: {0}")]
    Untrusted(String),
    /// The gateway refused the session — a bad token, a protocol
    /// version mismatch, a peer that answered QUIC but refused our
    /// protocol — or the session did not come up after the handshake.
    /// The gateway was reached, so a fallback to the unencrypted
    /// transport is not allowed.
    #[error("refused: {0}")]
    Refused(String),
}

/// The result of an operation that can fail inside the crate.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// The error with a context prefix, keeping its variant.
    ///
    /// The variant is what a caller acts on, so adding context must
    /// not turn an I/O failure into a protocol violation.
    pub(crate) fn with_context(self, context: &str) -> Error {
        match self {
            Error::Io(e) => Error::Io(std::io::Error::new(e.kind(), format!("{context}: {e}"))),
            Error::Invalid(m) => Error::Invalid(format!("{context}: {m}")),
            Error::Protocol(m) => Error::Protocol(format!("{context}: {m}")),
            Error::Unreachable(m) => Error::Unreachable(format!("{context}: {m}")),
            Error::Untrusted(m) => Error::Untrusted(format!("{context}: {m}")),
            Error::Refused(m) => Error::Refused(format!("{context}: {m}")),
        }
    }

    /// The reason without the variant's prefix, on a single line.
    ///
    /// The `ERR <reason>` reply of the CONNECT exchange is one line,
    /// so a reason carrying a line break would smuggle a second line
    /// into the gateway's stream.
    pub(crate) fn reason(&self) -> String {
        let text = match self {
            Error::Io(e) => e.to_string(),
            Error::Invalid(m)
            | Error::Protocol(m)
            | Error::Unreachable(m)
            | Error::Untrusted(m)
            | Error::Refused(m) => m.clone(),
        };
        text.replace(['\r', '\n'], " ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reason carries the message without the variant's prefix,
    /// so the wire reply reads like a sentence.
    #[test]
    fn the_reason_drops_the_variant_prefix() {
        let err = Error::Unreachable("the gateway did not answer".into());
        assert_eq!(err.reason(), "the gateway did not answer");
    }

    /// The reason is one line: a message that carried a line break
    /// would smuggle a second line into the gateway's stream.
    #[test]
    fn the_reason_is_one_line() {
        let err = Error::Protocol("first line\nsecond line".into());
        assert_eq!(err.reason(), "first line second line");
    }

    /// An I/O error's reason is the I/O error's own message.
    #[test]
    fn the_reason_of_an_io_error_is_the_io_message() {
        let err = Error::Io(std::io::Error::other("connection refused"));
        assert_eq!(err.reason(), "connection refused");
    }
}
