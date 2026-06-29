use crate::Error;

/// Wraps the bytes-in/bytes-out [`obcrypt::Key`] with oboron's
/// hex-string constructors and accessors.
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
        // Spec §3.3: keys MUST be lowercase hex. The `hex` crate decodes
        // case-insensitively, so reject any uppercase explicitly.
        if key_hex.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(Error::InvalidHex);
        }
        let key_bytes: [u8; 64] = hex::decode(key_hex)?
            .try_into()
            .map_err(|_| Error::InvalidKeyLength)?;
        Self::from_bytes(&key_bytes)
    }

    /// Create a MasterKey from a key string.
    ///
    /// The canonical — and only — key text encoding is 128-character
    /// hex; any other length is rejected with [`Error::InvalidKeyLength`].
    /// Equivalent to [`Self::from_hex`]; kept as the length-routing
    /// entry point the `new` constructors delegate to.
    #[inline]
    pub fn from_string(s: &str) -> Result<Self, Error> {
        match s.len() {
            128 => Self::from_hex(s),
            _ => Err(Error::InvalidKeyLength),
        }
    }

    /// Encode the key as a 128-character hex string.
    ///
    /// This is the canonical text encoding for oboron keys.
    #[inline]
    pub fn key_hex(&self) -> String {
        hex::encode(self.key.as_bytes())
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
