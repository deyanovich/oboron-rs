#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_KEY_BYTES;
use crate::{format::IntoFormat, Encoding, Error, Format, MasterKey, ObtextCodec, Scheme};

/// A flexible ObtextCodec implementation with runtime format selection.
///
/// `Ob` allows you to specify any format at runtime via constructor parameters,
/// and provides methods to change the format after construction if needed.
///
/// This provides a unified interface for all runtime format needs, from
/// immutable configurations to dynamic format switching.
///
/// # Examples
///
/// ## Basic usage with immutable format
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(feature = "aasv")]
/// # {
/// # use oboron::{Ob, generate_key};
/// # let key = generate_key();
/// let ob = Ob::new("aasv.b64", &key)?;
/// let ot = ob.enc("hello")?; // obtext
/// let pt2 = ob.dec(&ot)?; // recovered plaintext
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
/// # #[cfg(all(feature = "aasv", feature = "mock"))]
/// # {
/// # use oboron::{Ob, Scheme, Encoding, Format, AASV_B64};
/// # let key = oboron::generate_key();
/// let mut ob = Ob::new("aasv.c32", &key)?;
/// let ot1 = ob.enc("hello")?; // aasv.c32 format
///
/// // Change format at runtime
/// ob.set_scheme(Scheme::Mock1)?;
/// let ot2 = ob.enc("hello")?; // mock1.c32 format
///
/// // Change encoding
/// ob.set_encoding(Encoding::B64)?; // now mock1.b64
///
/// // Set entire format at once
/// ob.set_format("aasv.hex")?; // now aasv.hex
/// ob.set_format(AASV_B64)?;   // now aasv.b64 (using constant)
/// # }
/// # Ok(())
/// # }
/// ```
pub struct Ob {
    masterkey: MasterKey,
    format: Format,
}

impl Ob {
    /// Create a new Ob with the specified format and base64 key.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::{Ob, Format, Scheme, Encoding};
    /// # let key = oboron::generate_key();
    /// // Using format string
    /// let ob1 = Ob::new("aasv.b64", &key)?;
    ///
    /// // Using Format instance
    /// let format = Format::new(Scheme::Aasv, Encoding::B64);
    /// let ob2 = Ob::new(format, &key)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    /// Create a new `Ob` instance from a format and a key string.
    ///
    /// The key format is auto-detected by length: 128 chars → hex
    /// (canonical), 86 chars → base64 (deprecated; behind the
    /// `base64-keys` feature). For format-explicit constructors see
    /// [`Self::from_hex_key`] / [`Self::from_base64_key`].
    ///
    /// The base64 path is transitional and will be removed before
    /// oboron 1.0 — migrate keys to hex.
    pub fn new(format: impl IntoFormat, key: &str) -> Result<Self, Error> {
        let format = format.into_format()?;
        Ok(Self {
            masterkey: MasterKey::from_string(key)?,
            format,
        })
    }

    /// Create a new `Ob` instance from a base64 key.
    ///
    /// Deprecated: oboron is moving to hex-only keys before v1.0.
    /// Use [`Self::new`] (hex) or [`Self::from_hex_key`] instead.
    #[cfg(feature = "base64-keys")]
    #[deprecated(
        since = "0.7.1",
        note = "use Ob::new() / Ob::from_hex_key() (hex) instead; base64 key support will be removed before oboron 1.0"
    )]
    pub fn from_base64_key(format: impl IntoFormat, key_b64: &str) -> Result<Self, Error> {
        let format = format.into_format()?;
        Ok(Self {
            #[allow(deprecated)]
            masterkey: MasterKey::from_base64(key_b64)?,
            format,
        })
    }

    /// Deprecated alias for [`Self::from_base64_key`].
    ///
    /// The 0.8.x name had the target/format order flipped relative
    /// to the standard `from_<format>_<target>` pattern. Doubly
    /// deprecated: base64 support itself is on the way out before
    /// oboron 1.0.
    #[cfg(feature = "base64-keys")]
    #[deprecated(
        since = "0.9.0",
        note = "use Ob::from_base64_key (or Ob::from_hex_key — base64 is going away)"
    )]
    pub fn from_key_base64(format: impl IntoFormat, key_b64: &str) -> Result<Self, Error> {
        #[allow(deprecated)]
        Self::from_base64_key(format, key_b64)
    }

    /// Set the format to a new value.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "aasv", feature = "mock"))]
    /// # {
    /// # use oboron::{Ob, Format, Scheme, Encoding};
    /// # let key = oboron::generate_key();
    /// let mut ob = Ob::new("aasv.c32", &key)?;
    /// ob.set_format("mock1.b64")?; // switch using string
    /// ob.set_format(Format::new(Scheme::Mock2, Encoding:: Hex))?; // switch using Format
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_format(&mut self, format: impl IntoFormat) -> Result<(), Error> {
        self.format = format.into_format()?;
        Ok(())
    }

    /// Set the scheme while keeping the current encoding.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "aasv", feature = "mock"))]
    /// # {
    /// # use oboron::{Ob, Scheme};
    /// # let key = oboron::generate_key();
    /// let mut ob = Ob::new("aasv.c32", &key)?;
    /// ob.set_scheme(Scheme::Mock1)?; // switch to mock1, keeping c32 encoding
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_scheme(&mut self, scheme: Scheme) -> Result<(), Error> {
        self.format = Format::new(scheme, self.format.encoding());
        Ok(())
    }

    /// Set the encoding while keeping the current scheme.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::{Ob, Encoding};
    /// # let key = oboron::generate_key();
    /// let mut ob = Ob::new("aasv.c32", &key)?;
    /// ob.set_encoding(Encoding::B64)?; // switch to b64, keeping aasv scheme
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_encoding(&mut self, encoding: Encoding) -> Result<(), Error> {
        self.format = Format::new(self.format.scheme(), encoding);
        Ok(())
    }

    /// Decode and decrypt obtext with automatic format detection.
    ///
    /// Tries to decode using the instance's current encoding first (fast path),
    /// then falls back to full format autodetection if that fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "aasv", feature = "mock"))]
    /// # {
    /// # use oboron:: Ob;
    /// # let key = oboron::generate_key();
    /// let mut ob = Ob::new("aasv.b64", &key)?;
    /// let ot = ob.enc("test")?;
    ///
    /// // Change scheme - autodec will still work
    /// ob.set_scheme(oboron::Scheme::Mock1)?;
    /// let pt2 = ob.autodec(&ot)?;
    /// assert_eq!(pt2, "test");
    ///
    /// // Works even with different encoding (slower fallback path)
    /// ob.set_encoding(oboron::Encoding:: Hex)?;
    /// let pt3 = ob.autodec(&ot)?; // Falls back to full autodetection
    /// assert_eq!(pt3, "test");
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn autodec(&self, obtext: &str) -> Result<String, Error> {
        // Fast path: try current encoding first
        if let Ok(result) =
            crate::dec_auto::dec_any_scheme(&self.masterkey, self.format.encoding(), obtext)
        {
            return Ok(result);
        }

        // Fallback:  full format autodetection (encoding + scheme)
        crate::dec_auto::dec_any_format(&self.masterkey, obtext)
    }

    // Alt constructors ================================================

    /// Create a new Ob with hardcoded key (testing only).
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(all(feature = "aasv", feature="keyless"))]
    /// # {
    /// # use oboron::{Ob, Format, Scheme, Encoding};
    /// // Using format string
    /// let ob1 = Ob::new_keyless("aasv.c32")?;
    ///
    /// // Using Format instance
    /// let format = Format::new(Scheme::Aasv, Encoding::C32);
    /// let ob2 = Ob:: new_keyless(format)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "keyless")]
    pub fn new_keyless(format: impl IntoFormat) -> Result<Self, Error> {
        let format = format.into_format()?;
        Ok(Self {
            masterkey: MasterKey::from_bytes(&HARDCODED_KEY_BYTES)?,
            format,
        })
    }

    /// Create a new Ob from a format and a 128-character hex key.
    /// Strict hex — rejects base64. Use [`Self::new`] for the
    /// length-routing entry point that accepts both.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::{Ob, Format, Scheme, Encoding};
    /// let key_hex = oboron::generate_key();
    /// let ob1 = Ob::from_hex_key("aasv.b64", &key_hex)?;
    /// let ob2 = Ob::from_hex_key(Format::new(Scheme::Aasv, Encoding::B64), &key_hex)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_hex_key(format: impl IntoFormat, key_hex: &str) -> Result<Self, Error> {
        let format = format.into_format()?;
        Ok(Self {
            masterkey: MasterKey::from_hex(key_hex)?,
            format,
        })
    }

    /// Deprecated alias for [`Self::from_hex_key`].
    ///
    /// Kept for migration from any in-development 0.9.x preview;
    /// canonical pattern is `from_<format>_<target>`.
    #[deprecated(
        since = "0.9.0",
        note = "use Ob::from_hex_key instead — standard from_<format>_<target> pattern"
    )]
    pub fn from_key_hex(format: impl IntoFormat, key_hex: &str) -> Result<Self, Error> {
        Self::from_hex_key(format, key_hex)
    }

    /// Create a new Ob from the specified format and raw key bytes.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::{Ob, Format, Scheme, Encoding};
    /// let key_bytes = oboron::generate_key_bytes();
    /// let ob1 = Ob::from_bytes("aasv.b64", &key_bytes)?; // using format string
    /// let format = Format::new(Scheme:: Aasv, Encoding:: B64); // using Format
    /// let ob2 = Ob::from_bytes(format, &key_bytes)?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_bytes(format: impl IntoFormat, key: &[u8; 64]) -> Result<Self, Error> {
        let format = format.into_format()?;
        Ok(Self {
            masterkey: MasterKey::from_bytes(key)?,
            format,
        })
    }

    /// Get the key as a 128-character hex string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::Ob;
    /// # let key = oboron::generate_key();
    /// let ob = Ob::new("aasv.b64", &key)?;
    /// let key_retrieved = ob.key();
    /// assert_eq!(key_retrieved, key);
    /// assert_eq!(key_retrieved.len(), 128); // 64 bytes = 128 hex chars
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn key(&self) -> String {
        self.masterkey.key_hex()
    }

    /// Get the key as a base64 string.
    ///
    /// Deprecated: oboron is moving to hex-only keys before v1.0.
    /// Use [`Self::key`] (hex) instead.
    #[cfg(feature = "base64-keys")]
    #[deprecated(
        since = "0.7.1",
        note = "use Ob::key() (hex) instead; base64 key support will be removed before oboron 1.0"
    )]
    #[inline]
    pub fn key_base64(&self) -> String {
        #[allow(deprecated)]
        self.masterkey.key_base64()
    }

    /// Get the key as a 128-character hex string. Equivalent to [`Self::key`].
    #[inline]
    pub fn key_hex(&self) -> String {
        self.masterkey.key_hex()
    }

    /// Get the key as raw bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::Ob;
    /// let key_bytes = oboron::generate_key_bytes();
    /// let ob = Ob::from_bytes("aasv.b64", &key_bytes)?;
    /// let retrieved = ob.key_bytes();
    /// assert_eq!(retrieved, &key_bytes);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn key_bytes(&self) -> &[u8; 64] {
        self.masterkey.key_bytes()
    }
}

impl ObtextCodec for Ob {
    fn enc(&self, plaintext: &str) -> Result<String, Error> {
        crate::enc::enc_to_format(plaintext, self.format, self.masterkey.obcrypt_key())
    }

    fn dec(&self, obtext: &str) -> Result<String, Error> {
        crate::dec::dec_from_format(obtext, self.format, self.masterkey.obcrypt_key())
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
impl Ob {
    /// Encrypt and encode plaintext to obtext.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron:: Ob;
    /// # let key = oboron::generate_key();
    /// let ob = Ob::new("aasv.b64", &key)?;
    /// let ot = ob.enc("secret data")?;
    /// assert! (!ot.is_empty());
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn enc(&self, plaintext: &str) -> Result<String, Error> {
        <Self as ObtextCodec>::enc(self, plaintext)
    }

    /// Decode and decrypt obtext to plaintext.
    ///
    /// Uses the instance's configured format for decoding.  Does not perform
    /// scheme autodetection - use [`autodec`](Self::autodec) for that.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::Ob;
    /// # let key = oboron::generate_key();
    /// let ob = Ob::new("aasv.b64", &key)?;
    /// let ot = ob.enc("secret data")?;
    /// let pt2 = ob.dec(&ot)?;
    /// assert_eq!(pt2, "secret data");
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn dec(&self, obtext: &str) -> Result<String, Error> {
        <Self as ObtextCodec>::dec(self, obtext)
    }

    /// Get the current format (scheme + encoding).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::{Ob, Scheme, Encoding};
    /// # let key = oboron::generate_key();
    /// let ob = Ob::new("aasv.b64", &key)?;
    /// let format = ob.format();
    /// assert_eq!(format.scheme(), Scheme::Aasv);
    /// assert_eq!(format.encoding(), Encoding::B64);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn format(&self) -> Format {
        <Self as ObtextCodec>::format(self)
    }

    /// Get the current scheme.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::{Ob, Scheme};
    /// # let key = oboron::generate_key();
    /// let ob = Ob:: new("aasv.b64", &key)?;
    /// assert_eq!(ob.scheme(), Scheme::Aasv);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn scheme(&self) -> Scheme {
        <Self as ObtextCodec>::scheme(self)
    }

    /// Get the current encoding.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::{Ob, Encoding};
    /// # let key = oboron::generate_key();
    /// let ob = Ob:: new("aasv.b64", &key)?;
    /// assert_eq!(ob.encoding(), Encoding::B64);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn encoding(&self) -> Encoding {
        <Self as ObtextCodec>::encoding(self)
    }
}
