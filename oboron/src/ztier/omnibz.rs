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
/// let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 chars
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
    /// let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 chars
    /// let omz = Omnibz::new(secret)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(secret_b64: &str) -> Result<Self, Error> {
        Ok(Self {
            zsecret: ZSecret::from_base64(secret_b64)?,
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
    /// let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
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
    /// let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
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
    /// let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
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

    /// Get the secret used by this instance (base64 format, 43 chars).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "zrbcx")]
    /// # {
    /// # use oboron::ztier::Omnibz;
    /// let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    /// let omz = Omnibz::new(secret)?;
    /// let retrieved = omz.secret();
    /// assert_eq!(retrieved, secret);
    /// assert_eq!(retrieved.len(), 43);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn secret(&self) -> String {
        self.zsecret.secret_base64()
    }

    /// Get the secret as hex (64 chars).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "zrbcx")]
    /// # {
    /// # use oboron::ztier::Omnibz;
    /// let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    /// let omz = Omnibz::new(secret)?;
    /// let secret_hex = omz.secret_hex();
    /// assert_eq!(secret_hex.len(), 64); // 32 bytes = 64 hex chars
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn secret_hex(&self) -> String {
        self.zsecret.secret_hex()
    }

    /// Get the secret as raw bytes (32 bytes).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "zrbcx")]
    /// # {
    /// # use oboron::ztier::Omnibz;
    /// let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    /// let omz = Omnibz::new(secret)?;
    /// let secret_bytes = omz.secret_bytes();
    /// assert_eq!(secret_bytes.len(), 32);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.zsecret.secret_bytes()
    }

    // Alt input constructors ==========================================

    /// Create a new Omnibz instance with a hex secret (64 chars).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "zrbcx")]
    /// # {
    /// # use oboron::ztier::Omnibz;
    /// let secret_hex = "0".repeat(64); // 32 bytes as hex
    /// let omz = Omnibz::from_secret_hex(&secret_hex)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_secret_hex(secret_hex: &str) -> Result<Self, Error> {
        Ok(Self {
            zsecret: ZSecret::from_hex(secret_hex)?,
        })
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
        let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 chars
        let omz = Omnibz::new(secret).unwrap();

        let plaintext = "hello world";
        let ot = omz.enc(plaintext, "zrbcx.b64").unwrap();
        let pt2 = omz.dec(&ot, "zrbcx.b64").unwrap();

        assert_eq!(pt2, plaintext);
    }

    #[test]
    #[cfg(feature = "zrbcx")]
    fn test_omnibz_autodec() {
        let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let omz = Omnibz::new(secret).unwrap();

        let plaintext = "test data";
        let ot = omz.enc(plaintext, "zrbcx.c32").unwrap();
        let pt2 = omz.autodec(&ot).unwrap();

        assert_eq!(pt2, plaintext);
    }

    #[test]
    #[cfg(all(feature = "zrbcx", feature = "mock"))]
    fn test_omnibz_multiple_formats() {
        let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
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
        let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let omz = Omnibz::new(secret).unwrap();

        let retrieved = omz.secret();
        assert_eq!(retrieved, secret);
        assert_eq!(retrieved.len(), 43);

        let secret_hex = omz.secret_hex();
        assert_eq!(secret_hex.len(), 64);

        let secret_bytes = omz.secret_bytes();
        assert_eq!(secret_bytes.len(), 32);
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
    fn test_omnibz_from_hex() {
        let secret_hex = "0".repeat(64);
        let omz = Omnibz::from_secret_hex(&secret_hex).unwrap();

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
        let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let omz = Omnibz::new(secret).unwrap();

        #[cfg(feature = "aasv")]
        {
            let result = omz.enc("test", "aasv.b64");
            assert!(result.is_err());
        }
    }
}
