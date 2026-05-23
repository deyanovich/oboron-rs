//! Omnibz - Multi-format z-tier codec with runtime format selection
//!
//! ⚠️ **WARNING**: Z-tier schemes provide NO cryptographic security.
//! Use only for obfuscation, never for actual encryption.

#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_SECRET_BYTES;
use crate::{format::IntoFormat, Error};

use super::zdec_auto;
use super::zsecret::ZSecret;

/// A z-tier codec implementation that takes format on enc operation and autodetects on dec operation.
///
/// This is the z-tier equivalent of `Omnib`, working with 32-byte secrets instead of 64-byte keys.
/// Unlike other implementations (Obz, ZrbcxC32, etc.) it does not have a format stored internally.
///
/// This struct allows specifying the format (scheme + encoding) at enc call time,
/// and automatically detects both scheme and encoding on dec calls.
/// It is the only z-tier codec implementation that does full format autodetection.
///
/// **WARNING**: Z-tier schemes provide NO cryptographic security.
/// Use only for obfuscation, never for actual encryption.
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(all(feature = "zrbcx", feature = "mock"))]
/// # {
/// # use oboron::ztier::Omnibz;
/// let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"; // 64 hex chars
/// let omz = Omnibz::new(secret)?;
///
/// // Encode with explicit format
/// let ot1 = omz.enc("hello", "zrbcx.c32")?;
/// let ot2 = omz.enc("world", "zmock1.b64")?;
///
/// // autodec detects both scheme and encoding
/// let pt1 = omz.autodec(&ot1)?;
/// let pt2 = omz.autodec(&ot2)?;
/// assert_eq!(pt1, "hello");
/// assert_eq!(pt2, "world");
/// # }
/// # Ok(())
/// # }
/// ```
pub struct Omnibz {
    zsecret: ZSecret,
}

impl Omnibz {
    /// Create a new Omnibz instance with a base64 secret.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "zrbcx")]
    /// # {
    /// # use oboron::ztier::Omnibz;
    /// let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"; // 64 hex chars
    /// let omz = Omnibz::new(secret)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(secret: &str) -> Result<Self, Error> {
        Ok(Self {
            zsecret: ZSecret::from_string(secret)?,
        })
    }

    /// Create a new Omnibz instance with hardcoded secret (testing only).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "zrbcx", feature = "keyless"))]
    /// # {
    /// # use oboron::ztier::Omnibz;
    /// let omz = Omnibz::new_keyless()?;
    /// let ot = omz.enc("test", "zrbcx.b64")?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "keyless")]
    pub fn new_keyless() -> Result<Self, Error> {
        Ok(Self {
            zsecret: ZSecret::from_bytes(&HARDCODED_SECRET_BYTES)?,
        })
    }

    /// Encrypt and encode plaintext with the specified format.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "zrbcx")]
    /// # {
    /// # use oboron::ztier::Omnibz;
    /// # use oboron::{Format, Scheme, Encoding};
    /// let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    /// let omz = Omnibz::new(secret)?;
    ///
    /// // Using format string
    /// let ot1 = omz.enc("hello", "zrbcx.b64")?;
    ///
    /// // Using Format instance
    /// let ot2 = omz.enc("hello", Format::new(Scheme::Zrbcx, Encoding::B64))?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn enc(&self, plaintext: &str, format: impl IntoFormat) -> Result<String, Error> {
        let format = format.into_format()?;
        validate_ztier_scheme(format.scheme())?;
        // Pass full 32-byte secret - z-tier enc function uses it directly
        crate::ztier::enc_to_format_ztier(plaintext, format, self.zsecret.master_secret())
    }

    /// Decode and decrypt obtext with the specified format.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "zrbcx")]
    /// # {
    /// # use oboron::ztier::Omnibz;
    /// # use oboron::{Format, Scheme, Encoding};
    /// let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    /// let omz = Omnibz::new(secret)?;
    /// let ot = omz.enc("test", "zrbcx.b64")?;
    ///
    /// // Using format string
    /// let pt1 = omz.dec(&ot, "zrbcx.b64")?;
    ///
    /// // Using Format instance
    /// let pt2 = omz.dec(&ot, Format::new(Scheme::Zrbcx, Encoding::B64))?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn dec(&self, obtext: &str, format: impl IntoFormat) -> Result<String, Error> {
        let format = format.into_format()?;
        validate_ztier_scheme(format.scheme())?;
        // Pass full 32-byte secret - z-tier dec function uses it directly
        crate::ztier::dec_from_format_ztier(obtext, format, self.zsecret.master_secret())
    }

    /// Decode+decrypt with automatic scheme and encoding detection.
    ///
    /// Automatically detects both the z-tier scheme and encoding used.
    /// Falls back to legacy decoding if scheme detection fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "zrbcx")]
    /// # {
    /// # use oboron::ztier::Omnibz;
    /// let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    /// let omz = Omnibz::new(secret)?;
    /// let ot = omz.enc("hello", "zrbcx.b64")?;
    /// let pt2 = omz.autodec(&ot)?;  // Autodetects zrbcx.b64
    /// assert_eq!(pt2, "hello");
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn autodec(&self, obtext: &str) -> Result<String, Error> {
        zdec_auto::dec_any_format_ztier(&self.zsecret, obtext)
    }

    /// The 64-character hex secret bound to this Omnibz (canonical
    /// oboron form).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "zrbcx")]
    /// # {
    /// # use oboron::ztier::Omnibz;
    /// let secret = oboron::generate_secret(); // 64-char hex
    /// let omz = Omnibz::new(&secret)?;
    /// let retrieved = omz.secret();
    /// assert_eq!(retrieved, secret);
    /// assert_eq!(retrieved.len(), 64);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn secret(&self) -> String {
        self.zsecret.secret_hex()
    }

    /// The secret as a 64-character hex string (alias for `secret`).
    pub fn secret_hex(&self) -> String {
        self.zsecret.secret_hex()
    }

    /// The secret as a 43-character base64 string.
    ///
    /// Deprecated: hex is canonical; this getter will be removed
    /// when the `base64-keys` gate goes away before oboron 1.0.
    #[cfg(feature = "base64-keys")]
    pub fn secret_base64(&self) -> String {
        self.zsecret.secret_base64()
    }

    /// The raw 32-byte secret material.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.zsecret.secret_bytes()
    }

    // Alt input constructors ==========================================

    /// Create a new Omnibz instance from a 64-character hex secret.
    /// Strict hex — rejects base64. Use [`Self::new`] for the
    /// length-routing entry point that accepts both.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "zrbcx")]
    /// # {
    /// # use oboron::ztier::Omnibz;
    /// let secret_hex = "0".repeat(64); // 32 bytes as hex
    /// let omz = Omnibz::from_hex_secret(&secret_hex)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_hex_secret(secret_hex: &str) -> Result<Self, Error> {
        Ok(Self {
            zsecret: ZSecret::from_hex(secret_hex)?,
        })
    }

    /// Deprecated alias for [`Self::from_hex_secret`].
    ///
    /// The 0.8.x name had the target/format order flipped relative
    /// to the standard `from_<format>_<target>` pattern (e.g.
    /// `from_hex_key`, `from_base64_secret`); renamed in 0.9.0
    /// for consistency.
    #[deprecated(
        since = "0.9.0",
        note = "use Omnibz::from_hex_secret instead — standard from_<format>_<target> pattern"
    )]
    pub fn from_secret_hex(secret_hex: &str) -> Result<Self, Error> {
        Self::from_hex_secret(secret_hex)
    }

    /// Create a new Omnibz instance from raw secret bytes (32 bytes).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "zrbcx")]
    /// # {
    /// # use oboron::ztier::Omnibz;
    /// let secret_bytes = [0u8; 32];
    /// let omz = Omnibz::from_bytes(&secret_bytes)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_bytes(secret_bytes: &[u8; 32]) -> Result<Self, Error> {
        Ok(Self {
            zsecret: ZSecret::from_bytes(secret_bytes)?,
        })
    }

    /// Create a new Omnibz instance from a 43-character base64
    /// secret string.
    ///
    /// Deprecated: hex is canonical; this constructor will be
    /// removed when the `base64-keys` gate goes away before
    /// oboron 1.0.
    #[cfg(feature = "base64-keys")]
    #[deprecated(
        since = "0.9.0",
        note = "use Omnibz::from_hex_secret() / new() (hex) instead; base64 support will be removed before oboron 1.0"
    )]
    pub fn from_base64_secret(secret_base64: &str) -> Result<Self, Error> {
        Ok(Self {
            zsecret: ZSecret::from_base64(secret_base64)?,
        })
    }

    /// Deprecated alias for [`Self::from_base64_secret`].
    ///
    /// The in-development 0.9.x preview used the target/format
    /// order; canonical is `from_<format>_<target>`. Doubly
    /// deprecated: base64 support itself is on the way out.
    #[cfg(feature = "base64-keys")]
    #[deprecated(
        since = "0.9.0",
        note = "use Omnibz::from_base64_secret (or from_hex_secret — base64 is going away)"
    )]
    pub fn from_secret_base64(secret_base64: &str) -> Result<Self, Error> {
        #[allow(deprecated)]
        Self::from_base64_secret(secret_base64)
    }
}

/// Helper function to validate that a scheme is a z-tier scheme
fn validate_ztier_scheme(scheme: crate::Scheme) -> Result<(), Error> {
    match scheme {
        #[cfg(feature = "zrbcx")]
        crate::Scheme::Zrbcx => Ok(()),
        #[cfg(feature = "mock")]
        crate::Scheme::Zmock1 => Ok(()),
        #[cfg(feature = "legacy")]
        crate::Scheme::Legacy => Ok(()),
        _ => Err(Error::InvalidScheme),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "zrbcx")]
    fn test_omnibz_basic() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"; // 64 hex chars
        let omz = Omnibz::new(secret).unwrap();

        let plaintext = "hello world";
        let ot = omz.enc(plaintext, "zrbcx.b64").unwrap();
        let pt2 = omz.dec(&ot, "zrbcx.b64").unwrap();

        assert_eq!(pt2, plaintext);
    }

    #[test]
    #[cfg(feature = "zrbcx")]
    fn test_omnibz_autodec() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let omz = Omnibz::new(secret).unwrap();

        let plaintext = "test data";
        let ot = omz.enc(plaintext, "zrbcx.c32").unwrap();
        let pt2 = omz.autodec(&ot).unwrap();

        assert_eq!(pt2, plaintext);
    }

    #[test]
    #[cfg(all(feature = "zrbcx", feature = "mock"))]
    fn test_omnibz_multiple_formats() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let omz = Omnibz::new(secret).unwrap();

        let plaintext = "multi format test";

        let ot1 = omz.enc(plaintext, "zrbcx.b64").unwrap();
        let ot2 = omz.enc(plaintext, "zmock1.c32").unwrap();

        let pt1 = omz.autodec(&ot1).unwrap();
        let pt2 = omz.autodec(&ot2).unwrap();

        assert_eq!(pt1, plaintext);
        assert_eq!(pt2, plaintext);
    }

    #[test]
    #[cfg(feature = "zrbcx")]
    fn test_omnibz_secret_methods() {
        let secret_hex = "0".repeat(64);
        let omz = Omnibz::new(&secret_hex).unwrap();

        // `secret()` is canonical hex in 0.9.0.
        let retrieved = omz.secret();
        assert_eq!(retrieved, secret_hex);
        assert_eq!(retrieved.len(), 64);

        // `secret_hex()` is the alias.
        assert_eq!(omz.secret_hex().len(), 64);

        let secret_bytes = omz.secret_bytes();
        assert_eq!(secret_bytes.len(), 32);
    }

    #[test]
    #[cfg(all(feature = "zrbcx", feature = "base64-keys"))]
    fn test_omnibz_secret_base64_passthrough() {
        // `new()` length-routes — 43-char base64 still works as a
        // transitional input. `secret_base64()` round-trips it.
        let secret_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 chars
        let omz = Omnibz::new(secret_b64).unwrap();

        assert_eq!(omz.secret_base64(), secret_b64);
        assert_eq!(omz.secret().len(), 64); // hex
    }

    #[test]
    #[cfg(all(feature = "zrbcx", feature = "keyless"))]
    fn test_omnibz_keyless() {
        let omz = Omnibz::new_keyless().unwrap();

        let plaintext = "keyless test";
        let ot = omz.enc(plaintext, "zrbcx.b64").unwrap();
        let pt2 = omz.autodec(&ot).unwrap();

        assert_eq!(pt2, plaintext);
    }

    #[test]
    #[cfg(feature = "zrbcx")]
    fn test_omnibz_from_hex_secret() {
        let secret_hex = "0".repeat(64);
        let omz = Omnibz::from_hex_secret(&secret_hex).unwrap();

        let plaintext = "hex secret test";
        let ot = omz.enc(plaintext, "zrbcx.b64").unwrap();
        let pt2 = omz.autodec(&ot).unwrap();

        assert_eq!(pt2, plaintext);
    }

    #[test]
    #[cfg(feature = "zrbcx")]
    fn test_omnibz_from_bytes() {
        let secret_bytes = [0u8; 32];
        let omz = Omnibz::from_bytes(&secret_bytes).unwrap();

        let plaintext = "bytes secret test";
        let ot = omz.enc(plaintext, "zrbcx.b64").unwrap();
        let pt2 = omz.autodec(&ot).unwrap();

        assert_eq!(pt2, plaintext);
    }

    #[test]
    #[cfg(feature = "zrbcx")]
    fn test_omnibz_rejects_non_ztier_scheme() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let omz = Omnibz::new(secret).unwrap();

        #[cfg(feature = "aasv")]
        {
            let result = omz.enc("test", "aasv.b64");
            assert!(result.is_err());
        }
    }
}
