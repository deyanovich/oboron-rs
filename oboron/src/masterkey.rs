use crate::Error;
#[cfg(feature = "base64-keys")]
use data_encoding::BASE64URL_NOPAD;

/// Wraps the bytes-in/bytes-out [`obcrypt::Key`] with oboron's
/// string-keyed constructors (hex; base64 deprecated) and string
/// accessors.
///
/// Stays an oboron-internal type — encoding parsing belongs at this
/// layer, not in `obcrypt`.
pub struct MasterKey {
    key: obcrypt::Key,
}

impl MasterKey {
    /// Create a MasterKey from 64 raw bytes.
    #[inline]
    pub fn from_bytes(key_bytes: &[u8; 64]) -> Result<Self, Error> {
        Ok(MasterKey {
            key: obcrypt::Key::from_bytes(*key_bytes),
        })
    }

    /// Create a MasterKey from a 128-character hex string.
    ///
    /// This is the canonical text encoding for oboron keys.
    #[inline]
    pub fn from_hex(key_hex: &str) -> Result<Self, Error> {
        let key_bytes: [u8; 64] = hex::decode(key_hex)?
            .try_into()
            .map_err(|_| Error::InvalidKeyLength)?;
        Self::from_bytes(&key_bytes)
    }

    /// Create a MasterKey from a string, auto-detecting hex or base64
    /// by length.
    ///
    /// - 128 chars → parsed as hex (the canonical format).
    /// - 86 chars → parsed as base64 (deprecated; only when the
    ///   `base64-keys` feature is on).
    /// - any other length → [`Error::InvalidKeyLength`].
    ///
    /// This auto-detect is a **transitional** convenience for the
    /// base64 → hex migration: it lets callers' code keep compiling
    /// (and running) against existing base64 keys while they migrate
    /// to hex. Auto-detect of the base64 form will be removed when
    /// the `base64-keys` feature is removed before oboron 1.0.
    ///
    /// For new code, prefer the explicit [`Self::from_hex`].
    #[inline]
    pub fn from_string(s: &str) -> Result<Self, Error> {
        match s.len() {
            128 => Self::from_hex(s),
            #[cfg(feature = "base64-keys")]
            86 => {
                #[allow(deprecated)]
                Self::from_base64(s)
            }
            _ => Err(Error::InvalidKeyLength),
        }
    }

    /// Create a MasterKey from an 86-character base64 string.
    ///
    /// Deprecated: oboron is moving to hex-only keys before v1.0.
    /// Use [`Self::from_hex`] instead.
    #[cfg(feature = "base64-keys")]
    #[deprecated(
        since = "0.7.1",
        note = "use MasterKey::from_hex instead; base64 key support will be removed before oboron 1.0"
    )]
    #[inline]
    pub fn from_base64(key_base64: &str) -> Result<Self, Error> {
        let key: [u8; 64] = BASE64URL_NOPAD
            .decode(key_base64.as_bytes())
            .map_err(|_| Error::InvalidB64)?
            .try_into()
            .map_err(|_| Error::InvalidKeyLength)?;
        Self::from_bytes(&key)
    }

    /// Encode the key as a 128-character hex string.
    ///
    /// This is the canonical text encoding for oboron keys.
    #[inline]
    pub fn key_hex(&self) -> String {
        hex::encode(self.key.as_bytes())
    }

    /// Encode the key as an 86-character base64 string.
    ///
    /// Deprecated: oboron is moving to hex-only keys before v1.0.
    /// Use [`Self::key_hex`] instead.
    #[cfg(feature = "base64-keys")]
    #[deprecated(
        since = "0.7.1",
        note = "use MasterKey::key_hex instead; base64 key support will be removed before oboron 1.0"
    )]
    #[inline]
    pub fn key_base64(&self) -> String {
        BASE64URL_NOPAD.encode(self.key.as_bytes())
    }

    #[inline]
    pub(crate) fn key_bytes(&self) -> &[u8; 64] {
        self.key.as_bytes()
    }

    /// Borrow the underlying `obcrypt::Key` for direct handoff to obcrypt
    /// without a 64-byte copy.
    #[inline(always)]
    pub(crate) fn obcrypt_key(&self) -> &obcrypt::Key {
        &self.key
    }
}
