//! Obz - Flexible z-tier codec with runtime format selection
//!
//! ⚠️ **WARNING**: Z-tier schemes provide NO cryptographic security.
//! Use only for obfuscation, never for actual encryption.

#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_SECRET_BYTES;
use crate::{format::IntoFormat, Encoding, Error, Format, ObtextCodec, Scheme};

use super::zdec_auto;
use super::zsecret::ZSecret;

/// A flexible z-tier codec with runtime format selection.
///
/// `Obz` is the z-tier equivalent of `Ob`, allowing runtime format selection
/// for obfuscation-only schemes (zrbcx, legacy).
///
/// **WARNING**: Z-tier schemes provide NO cryptographic security.
/// Use only for obfuscation, never for actual encryption.
///
/// # Examples
///
/// ## Basic usage with immutable format
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(feature = "zrbcx")]
/// # {
/// # use oboron::ztier::Obz;
/// # let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"; // 64 hex chars
/// let obz = Obz::new("zrbcx.b64", secret)?;
/// let ot = obz.enc("hello")?;
/// let pt2 = obz.dec(&ot)?;
/// assert_eq!(pt2, "hello");
/// # }
/// # Ok(())
/// # }
/// ```
///
/// ## Dynamic format switching
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(all(feature = "zrbcx", feature = "mock"))]
/// # {
/// # use oboron::ztier::Obz;
/// # use oboron::{Scheme, Encoding, Format};
/// # let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
/// let mut obz = Obz::new("zrbcx.c32", secret)?;
/// let ot1 = obz.enc("hello")?;
///
/// // Change format at runtime
/// obz.set_scheme(Scheme::Zmock1)?;
/// let ot2 = obz.enc("hello")?; // now zmock1.c32
///
/// // Change encoding
/// obz.set_encoding(Encoding::B64)?; // now zmock1.b64
///
/// // Set entire format at once
/// obz.set_format("zrbcx.hex")?; // now zrbcx.hex
/// # }
/// # Ok(())
/// # }
/// ```
pub struct Obz {
    zsecret: ZSecret,
    format: Format,
}

impl Obz {
    /// Create a new Obz with the specified format and secret.
    /// Length-routed: accepts either a 64-character hex secret
    /// (canonical) or a 43-character base64 secret (transitional,
    /// gated by the `base64-keys` feature). The `format` argument
    /// accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "zrbcx")]
    /// # {
    /// # use oboron::ztier::Obz;
    /// # use oboron::{Format, Scheme, Encoding};
    /// let secret = oboron::generate_secret(); // 64-char hex
    /// let obz1 = Obz::new("zrbcx.b64", &secret)?;
    ///
    /// // Using Format instance
    /// let format = Format::new(Scheme::Zrbcx, Encoding::B64);
    /// let obz2 = Obz::new(format, &secret)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(format: impl IntoFormat, secret: &str) -> Result<Self, Error> {
        let format = format.into_format()?;
        validate_ztier_scheme(format.scheme())?;
        Ok(Self {
            zsecret: ZSecret::from_string(secret)?,
            format,
        })
    }

    /// Get the current format.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "zrbcx")]
    /// # {
    /// # use oboron::ztier::Obz;
    /// # use oboron::{Scheme, Encoding};
    /// # let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    /// let obz = Obz::new("zrbcx.b64", secret)?;
    /// let format = obz.format();
    /// assert_eq!(format.scheme(), Scheme::Zrbcx);
    /// assert_eq!(format.encoding(), Encoding::B64);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn format(&self) -> Format {
        self.format
    }

    /// Set the format to a new value.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "zrbcx", feature = "legacy"))]
    /// # {
    /// # use oboron::ztier::Obz;
    /// # use oboron::{Format, Scheme, Encoding};
    /// # let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    /// let mut obz = Obz::new("zrbcx.c32", secret)?;
    /// obz.set_format("legacy")?; // switch using string
    /// obz.set_format(Format::new(Scheme::Zrbcx, Encoding::Hex))?; // switch using Format
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_format(&mut self, format: impl IntoFormat) -> Result<(), Error> {
        let format = format.into_format()?;
        validate_ztier_scheme(format.scheme())?;
        self.format = format;
        Ok(())
    }

    /// Set the scheme while keeping the current encoding.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "zrbcx", feature = "legacy"))]
    /// # {
    /// # use oboron::ztier::Obz;
    /// # use oboron::Scheme;
    /// # let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    /// let mut obz = Obz::new("zrbcx.c32", secret)?;
    /// obz.set_scheme(Scheme::Legacy)?; // switch to legacy, keeping c32 encoding
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_scheme(&mut self, scheme: Scheme) -> Result<(), Error> {
        validate_ztier_scheme(scheme)?;
        self.format = Format::new(scheme, self.format.encoding());
        Ok(())
    }

    /// Set the encoding while keeping the current scheme.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "zrbcx")]
    /// # {
    /// # use oboron::ztier::Obz;
    /// # use oboron::Encoding;
    /// # let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    /// let mut obz = Obz::new("zrbcx.c32", secret)?;
    /// obz.set_encoding(Encoding::B64)?; // switch to b64, keeping zrbcx scheme
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_encoding(&mut self, encoding: Encoding) -> Result<(), Error> {
        self.format = Format::new(self.format.scheme(), encoding);
        Ok(())
    }

    /// Decode and decrypt obtext with scheme autodetection.
    ///
    /// Uses the current encoding but automatically detects the scheme from the payload.
    /// Falls back to legacy decoding if scheme detection fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "zrbcx"))]
    /// # {
    /// # use oboron::ztier::Obz;
    /// # let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    /// let mut obz = Obz::new("zrbcx.b64", secret)?;
    /// let ot = obz.enc("test")?;
    /// let pt2 = obz.autodec(&ot)?;
    /// assert_eq!(pt2, "test");
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn autodec(&self, obtext: &str) -> Result<String, Error> {
        // Fast path: try current encoding first
        if let Ok(result) =
            zdec_auto::dec_any_scheme_ztier(&self.zsecret, self.format.encoding(), obtext)
        {
            return Ok(result);
        }
        zdec_auto::dec_any_format_ztier(&self.zsecret, obtext)
    }

    // Alt constructors ================================================

    /// Create a new Obz with hardcoded secret (testing only).
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "zrbcx", feature = "keyless"))]
    /// # {
    /// # use oboron::ztier::Obz;
    /// # use oboron::{Format, Scheme, Encoding};
    /// // Using format string
    /// let obz1 = Obz::new_keyless("zrbcx.c32")?;
    ///
    /// // Using Format instance
    /// let format = Format::new(Scheme::Zrbcx, Encoding::C32);
    /// let obz2 = Obz::new_keyless(format)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "keyless")]
    pub fn new_keyless(format: impl IntoFormat) -> Result<Self, Error> {
        let format = format.into_format()?;
        validate_ztier_scheme(format.scheme())?;
        Ok(Self {
            zsecret: ZSecret::from_bytes(&HARDCODED_SECRET_BYTES)?,
            format,
        })
    }

    /// Create a new Obz with the specified format and a 64-character
    /// hex secret. Strict hex — rejects base64. Use [`Self::new`]
    /// for the length-routing entry point that accepts both.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "zrbcx")]
    /// # {
    /// # use oboron::ztier::Obz;
    /// # use oboron::{Format, Scheme, Encoding};
    /// let secret_hex = "0".repeat(64); // 32 bytes as hex
    /// let obz1 = Obz::from_hex_secret("zrbcx.b64", &secret_hex)?;
    ///
    /// let format = Format::new(Scheme::Zrbcx, Encoding::B64);
    /// let obz2 = Obz::from_hex_secret(format, &secret_hex)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_hex_secret(format: impl IntoFormat, secret_hex: &str) -> Result<Self, Error> {
        let format = format.into_format()?;
        validate_ztier_scheme(format.scheme())?;
        Ok(Self {
            zsecret: ZSecret::from_hex(secret_hex)?,
            format,
        })
    }

    /// Deprecated alias for [`Self::from_hex_secret`].
    ///
    /// Kept for migration from any in-development 0.9.x preview;
    /// canonical pattern is `from_<format>_<target>`.
    #[deprecated(
        since = "0.9.0",
        note = "use Obz::from_hex_secret instead — standard from_<format>_<target> pattern"
    )]
    pub fn from_secret_hex(format: impl IntoFormat, secret_hex: &str) -> Result<Self, Error> {
        Self::from_hex_secret(format, secret_hex)
    }

    /// Deprecated alias for [`Self::from_hex_secret`].
    ///
    /// The 0.8.x name leaked the a/u-tier "key" terminology into the
    /// z-tier API where the field is named "secret"; renamed in
    /// 0.9.0 for consistency.
    #[deprecated(
        since = "0.9.0",
        note = "use Obz::from_hex_secret instead — the z-tier field is `secret`, not `key`"
    )]
    pub fn from_hex_key(format: impl IntoFormat, secret_hex: &str) -> Result<Self, Error> {
        Self::from_hex_secret(format, secret_hex)
    }

    /// Deprecated alias for [`Self::from_hex_secret`].
    ///
    /// The 0.8.x name leaked the a/u-tier "key" terminology into the
    /// z-tier API where the field is named "secret". This particular
    /// spelling never shipped as canonical but is provided for any
    /// migrating caller who reached for the a/u-tier word order.
    #[deprecated(
        since = "0.9.0",
        note = "use Obz::from_hex_secret instead — the z-tier field is `secret`, not `key`"
    )]
    pub fn from_key_hex(format: impl IntoFormat, secret_hex: &str) -> Result<Self, Error> {
        Self::from_hex_secret(format, secret_hex)
    }

    /// Create a new Obz from a 43-character base64 secret string.
    ///
    /// Deprecated: hex is canonical; this constructor will be removed
    /// when the `base64-keys` gate goes away before oboron 1.0.
    #[cfg(feature = "base64-keys")]
    #[deprecated(
        since = "0.9.0",
        note = "use Obz::from_hex_secret() / new() (hex) instead; base64 support will be removed before oboron 1.0"
    )]
    pub fn from_base64_secret(
        format: impl IntoFormat,
        secret_base64: &str,
    ) -> Result<Self, Error> {
        let format = format.into_format()?;
        validate_ztier_scheme(format.scheme())?;
        Ok(Self {
            zsecret: ZSecret::from_base64(secret_base64)?,
            format,
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
        note = "use Obz::from_base64_secret (or from_hex_secret — base64 is going away)"
    )]
    pub fn from_secret_base64(
        format: impl IntoFormat,
        secret_base64: &str,
    ) -> Result<Self, Error> {
        #[allow(deprecated)]
        Self::from_base64_secret(format, secret_base64)
    }

    /// Deprecated alias for [`Self::from_base64_secret`].
    ///
    /// The 0.8.x convention leaked the a/u-tier "key" word into a
    /// z-tier method. Provided for any caller who reached for it.
    #[cfg(feature = "base64-keys")]
    #[deprecated(
        since = "0.9.0",
        note = "use Obz::from_base64_secret instead — the z-tier field is `secret`, not `key`"
    )]
    pub fn from_base64_key(
        format: impl IntoFormat,
        secret_base64: &str,
    ) -> Result<Self, Error> {
        #[allow(deprecated)]
        Self::from_base64_secret(format, secret_base64)
    }

    /// Deprecated alias for [`Self::from_base64_secret`].
    ///
    /// The 0.8.x convention leaked the a/u-tier "key" word into a
    /// z-tier method. Provided for any caller who reached for it.
    #[cfg(feature = "base64-keys")]
    #[deprecated(
        since = "0.9.0",
        note = "use Obz::from_base64_secret instead — the z-tier field is `secret`, not `key`"
    )]
    pub fn from_key_base64(
        format: impl IntoFormat,
        secret_base64: &str,
    ) -> Result<Self, Error> {
        #[allow(deprecated)]
        Self::from_base64_secret(format, secret_base64)
    }

    /// Create a new Obz from the specified format and raw secret bytes.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "zrbcx")]
    /// # {
    /// # use oboron::ztier::Obz;
    /// # use oboron::{Format, Scheme, Encoding};
    /// let secret_bytes = [0u8; 32];
    /// let obz1 = Obz::from_bytes("zrbcx.b64", &secret_bytes)?; // using format string
    /// let format = Format::new(Scheme::Zrbcx, Encoding::B64); // using Format
    /// let obz2 = Obz::from_bytes(format, &secret_bytes)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_bytes(format: impl IntoFormat, secret: &[u8; 32]) -> Result<Self, Error> {
        let format = format.into_format()?;
        validate_ztier_scheme(format.scheme())?;
        Ok(Self {
            zsecret: ZSecret::from_bytes(secret)?,
            format,
        })
    }

    /// The 64-character hex secret bound to this codec (canonical
    /// oboron form).
    #[inline]
    pub fn secret(&self) -> String {
        self.zsecret.secret_hex()
    }

    /// The secret as a 64-character hex string (alias for `secret`).
    #[inline]
    pub fn secret_hex(&self) -> String {
        self.zsecret.secret_hex()
    }

    /// The secret as a 43-character base64 string.
    ///
    /// Deprecated: hex is canonical; this getter will be removed
    /// when the `base64-keys` gate goes away before oboron 1.0.
    #[cfg(feature = "base64-keys")]
    #[inline]
    pub fn secret_base64(&self) -> String {
        self.zsecret.secret_base64()
    }

    /// The raw 32-byte secret material.
    #[inline]
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.zsecret.secret_bytes()
    }
}

impl ObtextCodec for Obz {
    fn enc(&self, plaintext: &str) -> Result<String, Error> {
        #[cfg(feature = "legacy")]
        if self.format.scheme() == Scheme::Legacy {
            let legacy = super::legacy::Legacy::from_master_secret(self.zsecret.master_secret())?;
            return <super::legacy::Legacy as ObtextCodec>::enc(&legacy, plaintext);
        }
        // Pass full 32-byte secret - z-tier enc function uses it directly
        crate::ztier::enc_to_format_ztier(plaintext, self.format, self.zsecret.master_secret())
    }

    fn dec(&self, obtext: &str) -> Result<String, Error> {
        #[cfg(feature = "legacy")]
        if self.format.scheme() == Scheme::Legacy {
            let legacy = super::legacy::Legacy::from_master_secret(self.zsecret.master_secret())?;
            return <super::legacy::Legacy as ObtextCodec>::dec(&legacy, obtext);
        }
        // Pass full 32-byte secret - z-tier dec function uses it directly
        crate::ztier::dec_from_format_ztier(obtext, self.format, self.zsecret.master_secret())
    }

    fn format(&self) -> Format {
        self.format
    }

    fn scheme(&self) -> Scheme {
        self.format.scheme()
    }

    fn encoding(&self) -> Encoding {
        self.format.encoding()
    }
}

// Add inherent methods that delegate to trait methods
impl Obz {
    /// Encrypt and encode plaintext
    #[inline]
    pub fn enc(&self, plaintext: &str) -> Result<String, Error> {
        <Self as ObtextCodec>::enc(self, plaintext)
    }

    /// Decode and decrypt obtext (no scheme autodetection)
    #[inline]
    pub fn dec(&self, obtext: &str) -> Result<String, Error> {
        <Self as ObtextCodec>::dec(self, obtext)
    }

    /// Get the scheme
    #[inline]
    pub fn scheme(&self) -> Scheme {
        <Self as ObtextCodec>::scheme(self)
    }

    /// Get the encoding
    #[inline]
    pub fn encoding(&self) -> Encoding {
        <Self as ObtextCodec>::encoding(self)
    }
}

/// Helper function to validate that a scheme is a z-tier scheme
fn validate_ztier_scheme(scheme: Scheme) -> Result<(), Error> {
    match scheme {
        #[cfg(feature = "zrbcx")]
        Scheme::Zrbcx => Ok(()),
        #[cfg(feature = "mock")]
        Scheme::Zmock1 => Ok(()),
        #[cfg(feature = "legacy")]
        Scheme::Legacy => Ok(()),
        _ => Err(Error::InvalidScheme),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "zrbcx")]
    fn test_obz_basic() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"; // 64 hex chars
        let obz = Obz::new("zrbcx.b64", secret).unwrap();

        let plaintext = "hello world";
        let ot = obz.enc(plaintext).unwrap();
        let pt2 = obz.dec(&ot).unwrap();

        assert_eq!(pt2, plaintext);
    }

    #[test]
    #[cfg(feature = "zrbcx")]
    fn test_obz_format_switching() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let mut obz = Obz::new("zrbcx.c32", secret).unwrap();

        assert_eq!(obz.encoding(), Encoding::C32);

        obz.set_encoding(Encoding::B64).unwrap();
        assert_eq!(obz.encoding(), Encoding::B64);
    }

    #[test]
    #[cfg(all(feature = "zrbcx", feature = "legacy"))]
    fn test_obz_scheme_switching() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let mut obz = Obz::new("zrbcx.b64", secret).unwrap();

        assert_eq!(obz.scheme(), Scheme::Zrbcx);

        obz.set_scheme(Scheme::Legacy).unwrap();
        assert_eq!(obz.scheme(), Scheme::Legacy);
    }

    #[test]
    #[cfg(feature = "zrbcx")]
    fn test_obz_rejects_non_ztier_scheme() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

        #[cfg(feature = "aasv")]
        {
            let result = Obz::new("aasv.b64", secret);
            assert!(result.is_err());
        }
    }
}
