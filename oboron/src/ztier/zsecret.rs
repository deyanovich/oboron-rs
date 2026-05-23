//!  MasterKey for z-tier schemes (32-byte secrets, obfuscation-only)

use crate::Error;
#[cfg(feature = "base64-keys")]
use data_encoding::BASE64URL_NOPAD;

/// MasterKey for z-tier schemes (obfuscation-only, 32-byte secrets)
///
/// **WARNING**: Z-tier schemes provide NO cryptographic security.
/// Use only for obfuscation, never for actual encryption.
pub(crate) struct ZSecret {
    secret: [u8; 32],
}

impl ZSecret {
    /// Create a new ZSecret from a 32-byte secret.
    #[inline]
    pub(crate) fn from_bytes(secret_bytes: &[u8; 32]) -> Result<Self, Error> {
        Ok(ZSecret {
            secret: *secret_bytes,
        })
    }

    /// Length-routed entry point used by every z-tier `new()`
    /// constructor. Hex (64 chars) is the canonical form; the
    /// 43-character base64 form is still accepted while the
    /// `base64-keys` gate is on (transitional). Mirrors
    /// `MasterKey::from_string` in the a/u-tier.
    #[inline]
    pub(crate) fn from_string(s: &str) -> Result<Self, Error> {
        match s.len() {
            64 => Self::from_hex(s),
            #[cfg(feature = "base64-keys")]
            43 => Self::from_base64(s),
            _ => Err(Error::InvalidKeyLength),
        }
    }

    /// Create a new ZSecret from a 64-character hex string. Strict:
    /// rejects base64 even if it would otherwise parse.
    #[inline]
    pub(crate) fn from_hex(secret_hex: &str) -> Result<Self, Error> {
        let secret_bytes: [u8; 32] = hex::decode(secret_hex)?
            .try_into()
            .map_err(|_| Error::InvalidKeyLength)?;
        Self::from_bytes(&secret_bytes)
    }

    /// Create a new ZSecret from a 43-character base64 string secret.
    /// Strict: rejects hex.
    ///
    /// Deprecated: oboron is moving to hex-only secrets before v1.0.
    /// Use [`Self::from_hex`] instead.
    #[inline]
    #[cfg(feature = "base64-keys")]
    pub(crate) fn from_base64(secret_base64: &str) -> Result<Self, Error> {
        let secret: [u8; 32] = BASE64URL_NOPAD
            .decode(secret_base64.as_bytes())
            .map_err(|_| Error::InvalidB64)?
            .try_into()
            .map_err(|_| Error::InvalidKeyLength)?;

        Self::from_bytes(&secret)
    }

    /// Get the secret as base64 string.
    ///
    /// Deprecated: oboron is moving to hex-only secrets before v1.0.
    /// Use [`Self::secret_hex`] instead.
    #[inline]
    #[cfg(feature = "base64-keys")]
    pub(crate) fn secret_base64(&self) -> String {
        BASE64URL_NOPAD.encode(&self.secret)
    }

    /// Get the secret as raw bytes.
    #[inline]
    #[allow(dead_code)] // Used by Obz.key_bytes()
    pub(crate) fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Get the secret as hex string.
    #[inline]
    #[allow(dead_code)] // Used by Obz.key_hex()
    pub(crate) fn secret_hex(&self) -> String {
        hex::encode(&self.secret)
    }

    /// Get the secret as raw bytes. (internal)
    #[inline(always)]
    pub(crate) fn master_secret(&self) -> &[u8; 32] {
        &self.secret
    }

    // Direct secret accessors for z-tier schemes
    // ===========================================

    /// Get secret for zrbcx scheme (returns full 32-byte secret)
    #[inline(always)]
    #[cfg(feature = "zrbcx")]
    pub(crate) fn zrbcx(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Get secret for zmock1 scheme (returns full 32-byte secret)
    #[inline(always)]
    #[cfg(feature = "mock")]
    pub(crate) fn zmock1(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Get secret for legacy scheme (returns full 32-byte secret)
    #[inline(always)]
    #[cfg(feature = "legacy")]
    #[allow(dead_code)] // Used by zdec_auto fallback
    pub(crate) fn legacy(&self) -> &[u8; 32] {
        &self.secret
    }
}
