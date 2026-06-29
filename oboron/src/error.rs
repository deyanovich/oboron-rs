use thiserror::Error;

/// All errors that can occur in oboron operations.
///
/// The variants are deliberately granular at the library layer so
/// callers can diagnose failures precisely. Across a trust boundary,
/// however, distinguishing *why* a decode/decrypt failed can leak an
/// oracle: code exposing oboron to untrusted input should collapse
/// every decode/decrypt failure into one uniform error before
/// surfacing it. The oboron CLI performs exactly this collapse
/// (spec §5).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    // Key errors
    // ----------
    #[error("key must be 64 bytes")]
    InvalidKeyLength,

    // Encoding errors
    // ---------------
    #[error("invalid hex encoding")]
    InvalidHex,
    #[error("invalid base64 encoding")]
    InvalidB64,
    #[error("invalid base32rfc encoding")]
    InvalidB32,
    #[error("invalid base32crockford encoding")]
    InvalidC32,
    #[error("invalid UTF-8")]
    InvalidUtf8,

    // Format/scheme errors
    // --------------------
    #[error("invalid format string")]
    InvalidFormat,
    #[error("invalid scheme")]
    InvalidScheme,
    #[error("unknown scheme")]
    UnknownScheme,
    #[error("unknown encoding")]
    UnknownEncoding,

    // Encryption errors
    // -----------------
    #[error("enc failed")]
    EncryptionFailed,
    #[error("enc failed: empty plaintext")]
    EmptyPlaintext,
    #[error("dec failed: empty payload")]
    EmptyPayload,
    #[error("dec failed: payload too short")]
    PayloadTooShort,

    // Decryption errors
    // -----------------
    #[error("decryption failed")]
    DecryptionFailed,
}

impl From<hex::FromHexError> for Error {
    fn from(_: hex::FromHexError) -> Self {
        Error::InvalidHex
    }
}

impl From<obcrypt::Error> for Error {
    fn from(e: obcrypt::Error) -> Self {
        match e {
            obcrypt::Error::InvalidKeyLength => Error::InvalidKeyLength,
            obcrypt::Error::InvalidHex => Error::InvalidHex,
            obcrypt::Error::UnknownScheme => Error::UnknownScheme,
            obcrypt::Error::EncryptionFailed => Error::EncryptionFailed,
            obcrypt::Error::EmptyPlaintext => Error::EmptyPlaintext,
            obcrypt::Error::DecryptionFailed => Error::DecryptionFailed,
            obcrypt::Error::EmptyPayload => Error::EmptyPayload,
            obcrypt::Error::PayloadTooShort => Error::PayloadTooShort,
            // obcrypt::Error is #[non_exhaustive]; route unknown variants to a generic decrypt failure.
            _ => Error::DecryptionFailed,
        }
    }
}
