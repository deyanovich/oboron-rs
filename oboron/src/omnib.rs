#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_KEY_BYTES;
use crate::{format::IntoFormat, Error, MasterKey};

/// An ObtextCodec that takes the format per operation.
///
/// Unlike the other implementations (`Ob`, `DsivC32`, …) it stores no
/// format internally: the format (scheme + encoding) is supplied at
/// each `enc` / `dec` call. The scheme is never detected — oboron
/// obtext carries no scheme marker, so the caller supplies the format,
/// exactly like the key.
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(all(feature = "dsiv", feature = "mock"))]
/// # {
/// # use oboron::{Omnib, MOCK1_B64};
/// # let key = oboron::generate_key();
/// let omb = Omnib::new(&key)?;
///
/// // Encode with an explicit format
/// let ot1 = omb.enc("hello", "dsiv.c32")?;
/// let ot2 = omb.enc("world", MOCK1_B64)?;
///
/// // Decode with the same format
/// let pt1 = omb.dec(&ot1, "dsiv.c32")?;
/// let pt2 = omb.dec(&ot2, MOCK1_B64)?;
/// # }
/// # Ok(())
/// # }
/// ```
pub struct Omnib {
    masterkey: MasterKey,
}

impl Omnib {
    /// Create a new `Omnib` instance from a 128-character hex key
    /// string (the canonical key form). For raw bytes use
    /// [`Self::from_bytes`]; [`Self::from_hex_key`] is the
    /// explicit-hex equivalent.
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
    /// # #[cfg(feature = "dsiv")]
    /// # {
    /// # use oboron::{Omnib, Format, Scheme, Encoding, DSIV_B64};
    /// # let key = oboron::generate_key();
    /// let omb = Omnib::new(&key)?;
    ///
    /// let ot1 = omb.enc("hello", "dsiv.b64")?;                          // format string
    /// let ot2 = omb.enc("hello", Format::new(Scheme::Dsiv, Encoding::B64))?; // Format instance
    /// let ot3 = omb.enc("hello", DSIV_B64)?;                            // format constant
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
    /// # #[cfg(feature = "dsiv")]
    /// # {
    /// # use oboron::{Omnib, Format, Scheme, Encoding};
    /// # let key = oboron::generate_key();
    /// # let omb = Omnib::new(&key)?;
    /// # let ot = omb.enc("test", "dsiv.b64")?;
    /// let pt1 = omb.dec(&ot, "dsiv.b64")?;
    /// let pt2 = omb.dec(&ot, Format::new(Scheme::Dsiv, Encoding::B64))?;
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn dec(&self, obtext: &str, format: impl IntoFormat) -> Result<String, Error> {
        let format = format.into_format()?;
        crate::dec::dec_from_format(obtext, format, self.masterkey.obcrypt_key())
    }

    /// Get the key used by this instance, encoded as 128-char hex.
    pub fn key(&self) -> String {
        self.masterkey.key_hex()
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

    /// Create a new `Omnib` instance from a 128-character hex key.
    /// Strict hex — rejects base64. Use [`Self::new`] for the
    /// length-routing entry point that accepts both.
    pub fn from_hex_key(key_hex: &str) -> Result<Self, Error> {
        Ok(Self {
            masterkey: MasterKey::from_hex(key_hex)?,
        })
    }

    /// Deprecated alias for [`Self::from_hex_key`].
    ///
    /// The 0.8.x name had the target/format order flipped relative
    /// to the standard `from_<format>_<target>` pattern (e.g.
    /// `from_hex_key`, `from_base64_secret`); renamed in 0.9.0 for
    /// consistency.
    #[deprecated(
        since = "0.9.0",
        note = "use Omnib::from_hex_key instead — standard from_<format>_<target> pattern"
    )]
    pub fn from_key_hex(key_hex: &str) -> Result<Self, Error> {
        Self::from_hex_key(key_hex)
    }

    /// Create a new `Omnib` instance from raw bytes.
    pub fn from_bytes(key_bytes: &[u8; 64]) -> Result<Self, Error> {
        Ok(Self {
            masterkey: MasterKey::from_bytes(key_bytes)?,
        })
    }
}
