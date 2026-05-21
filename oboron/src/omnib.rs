#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_KEY_BYTES;
use crate::{format::IntoFormat, Error, MasterKey};

/// An ObtextCodec implementation that takes format on enc operation
/// and autodetects on dec operation.
///
/// Unlike all other implementations (`Ob`, `ZrbcxC32`, …) it does not
/// have a format stored internally. This struct allows specifying the
/// format (scheme + encoding) at enc call time, and automatically
/// detects both scheme and encoding on dec calls. It is the only
/// `ObtextCodec` implementation that does full format autodetection;
/// all others can autodetect the scheme only (e.g. `upbc`), not the
/// encoding (base32 / base64 / etc.).
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(all(feature = "aasv", feature = "mock"))]
/// # {
/// # use oboron::{Omnib, MOCK1_B64};
/// # let key = oboron::generate_key();
/// let omb = Omnib::new(&key)?;
///
/// // Encode with explicit format
/// let ot1 = omb.enc("hello", "aasv.c32")?;
/// let ot2 = omb.enc("world", MOCK1_B64)?;
///
/// // autodec detects both scheme and encoding
/// let pt1 = omb.autodec(&ot1)?;
/// let pt2 = omb.autodec(&ot2)?;
/// # }
/// # Ok(())
/// # }
/// ```
pub struct Omnib {
    masterkey: MasterKey,
}

impl Omnib {
    /// Create a new `Omnib` instance from a key string.
    ///
    /// The key format is auto-detected by length: 128 chars → hex
    /// (canonical), 86 chars → base64 (deprecated; behind the
    /// `base64-keys` feature). For raw bytes use [`Self::from_bytes`].
    /// For format-explicit constructors see [`Self::from_key_hex`] /
    /// [`Self::from_key_base64`].
    ///
    /// The base64 path is transitional and will be removed before
    /// oboron 1.0 — migrate keys to hex.
    pub fn new(key: &str) -> Result<Self, Error> {
        Ok(Self {
            masterkey: MasterKey::from_string(key)?,
        })
    }

    /// Create a new `Omnib` instance with the hardcoded key (testing only).
    #[cfg(feature = "keyless")]
    pub fn new_keyless() -> Result<Self, Error> {
        Self::from_bytes(&HARDCODED_KEY_BYTES)
    }

    /// Encrypt and encode plaintext with the specified format.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::{Omnib, Format, Scheme, Encoding, AASV_B64};
    /// # let key = oboron::generate_key();
    /// let omb = Omnib::new(&key)?;
    ///
    /// let ot1 = omb.enc("hello", "aasv.b64")?;                          // format string
    /// let ot2 = omb.enc("hello", Format::new(Scheme::Aasv, Encoding::B64))?; // Format instance
    /// let ot3 = omb.enc("hello", AASV_B64)?;                            // format constant
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn enc(&self, plaintext: &str, format: impl IntoFormat) -> Result<String, Error> {
        let format = format.into_format()?;
        crate::enc::enc_to_format(plaintext, format, self.masterkey.obcrypt_key())
    }

    /// Decode and decrypt obtext with the specified format.
    ///
    /// Accepts either a format string (`&str`) or a `Format` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::{Omnib, Format, Scheme, Encoding};
    /// # let key = oboron::generate_key();
    /// # let omb = Omnib::new(&key)?;
    /// # let ot = omb.enc("test", "aasv.b64")?;
    /// let pt1 = omb.dec(&ot, "aasv.b64")?;
    /// let pt2 = omb.dec(&ot, Format::new(Scheme::Aasv, Encoding::B64))?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn dec(&self, obtext: &str, format: impl IntoFormat) -> Result<String, Error> {
        let format = format.into_format()?;
        crate::dec::dec_from_format(obtext, format, self.masterkey.obcrypt_key())
    }

    /// Decode+decrypt with automatic scheme and encoding detection.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), oboron::Error> {
    /// # #[cfg(feature = "aasv")]
    /// # {
    /// # use oboron::Omnib;
    /// # let key = oboron::generate_key();
    /// # let omb = Omnib::new(&key)?;
    /// let ot = omb.enc("hello", "aasv.b64")?;
    /// let pt2 = omb.autodec(&ot)?;
    /// assert_eq!(pt2, "hello");
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn autodec(&self, obtext: &str) -> Result<String, Error> {
        crate::dec_auto::dec_any_format(&self.masterkey, obtext)
    }

    /// Get the key used by this instance, encoded as 128-char hex.
    pub fn key(&self) -> String {
        self.masterkey.key_hex()
    }

    /// Get the key used by this instance, encoded as base64.
    ///
    /// Deprecated: oboron is moving to hex-only keys before v1.0.
    /// Use [`Self::key`] (or [`Self::key_hex`]) instead.
    #[cfg(feature = "base64-keys")]
    #[deprecated(
        since = "0.7.1",
        note = "use Omnib::key() (hex) instead; base64 key support will be removed before oboron 1.0"
    )]
    pub fn key_base64(&self) -> String {
        #[allow(deprecated)]
        self.masterkey.key_base64()
    }

    /// Get the key used by this instance, encoded as 128-char hex.
    /// Equivalent to [`Self::key`].
    pub fn key_hex(&self) -> String {
        self.masterkey.key_hex()
    }

    pub fn key_bytes(&self) -> &[u8; 64] {
        self.masterkey.key_bytes()
    }

    // Alt input constructors ==========================================

    /// Create a new `Omnib` instance from a hex key. Equivalent to [`Self::new`].
    pub fn from_key_hex(key_hex: &str) -> Result<Self, Error> {
        Self::new(key_hex)
    }

    /// Create a new `Omnib` instance from a base64 key.
    ///
    /// Deprecated: oboron is moving to hex-only keys before v1.0.
    /// Use [`Self::new`] (or [`Self::from_key_hex`]) instead.
    #[cfg(feature = "base64-keys")]
    #[deprecated(
        since = "0.7.1",
        note = "use Omnib::new() (hex) instead; base64 key support will be removed before oboron 1.0"
    )]
    pub fn from_key_base64(key_b64: &str) -> Result<Self, Error> {
        Ok(Self {
            #[allow(deprecated)]
            masterkey: MasterKey::from_base64(key_b64)?,
        })
    }

    /// Create a new `Omnib` instance from raw bytes.
    pub fn from_bytes(key_bytes: &[u8; 64]) -> Result<Self, Error> {
        Ok(Self {
            masterkey: MasterKey::from_bytes(key_bytes)?,
        })
    }
}
