//! Trait-based interface for scheme-specific ObtextCodec implementations.
#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_KEY_BYTES;
use crate::{error::Error, Encoding, Format, MasterKey, Scheme};

/// Core trait for ObtextCodec encryption+encoding/decoding+decryption implementations.
///
/// Each scheme+encoding combination (DsivC32, DsivB64, etc.) implements this trait
/// to provide a consistent interface for encoding and decoding operations.
///
/// Note: Construction methods (`new`, `from_bytes`, `new_keyless`) are not part of
/// this trait.     Each type provides its own constructor with an appropriate signature.
pub trait ObtextCodec {
    /// Encode a plaintext string.
    fn enc(&self, plaintext: &str) -> Result<String, Error>;

    /// Decode an encoded string back to plaintext
    fn dec(&self, obtext: &str) -> Result<String, Error>;

    /// Get the full format (encapsulating scheme + encoding) used by this instance
    fn format(&self) -> Format;

    /// Get the scheme identifier.
    fn scheme(&self) -> Scheme;

    /// Get the encoding used by this instance.
    fn encoding(&self) -> Encoding;
}

/// Macro for the GCM-SIV and mock schemes (dgcmsiv, pgcmsiv, mock1,
/// mock2). Every codec stores the full 64-byte master key; obcrypt
/// derives the 32-byte AES-GCM-SIV key internally via HKDF-Expand.
///
/// This macro generates a complete ObtextCodec implementation with all overhead eliminated:
/// - No runtime scheme matching
/// - No method call overhead for byte()
/// - Direct function calls to encrypt/decrypt
/// - Encoding functions called directly (no dispatch)
/// - All constants baked in at compile time
macro_rules! impl_codec_32 {
    (
        $name: ident,
        $scheme: expr,
        $encoding:expr,
        $format_str:expr,
        $encrypt_fn:path,
        $decrypt_fn: path,
        $key_extract: ident
    ) => {
        #[doc = concat!("ObtextCodec implementation for ", $format_str, " format.\n\n")]
        #[doc = concat!("Corresponds to format string: `\"", $format_str, "\"`")]
        #[allow(non_camel_case_types)]
        pub struct $name {
            masterkey: MasterKey,
        }

        impl $name {
            /// Create a new instance from a 128-character hex key
            /// string (the canonical key form). For raw bytes use
            /// [`Self::from_bytes`]; [`Self::from_hex_key`] is the
            /// explicit-hex equivalent of this constructor.
            #[inline]
            pub fn new(key: &str) -> Result<Self, Error> {
                Ok(Self {
                    masterkey: MasterKey::from_string(key)?,
                })
            }

            /// Internal: build from raw bytes. Used by `ObAny`
            /// constructors that route to per-format codecs.
            #[inline]
            fn from_bytes_internal(key_bytes: &[u8; 64]) -> Result<Self, Error> {
                Ok(Self {
                    masterkey: MasterKey::from_bytes(key_bytes)?,
                })
            }

            /// Create a new instance with hardcoded key (testing only).
            #[inline]
            #[cfg(feature = "keyless")]
            pub fn new_keyless() -> Result<Self, Error> {
                Ok(Self {
                    masterkey: MasterKey::from_bytes(&HARDCODED_KEY_BYTES)?,
                })
            }

            /// Create a new instance from a 128-character hex key.
            /// Strict hex — rejects base64. Use [`Self::new`] for the
            /// length-routing entry point that accepts both.
            #[inline]
            pub fn from_hex_key(key_hex: &str) -> Result<Self, Error> {
                Ok(Self {
                    masterkey: MasterKey::from_hex(key_hex)?,
                })
            }

            /// Create a new instance from a 64-byte key.
            #[inline]
            pub fn from_bytes(key_bytes: &[u8; 64]) -> Result<Self, Error> {
                Ok(Self {
                    masterkey: MasterKey::from_bytes(key_bytes)?,
                })
            }

            /// Get the key as a 128-character hex string.
            #[inline]
            pub fn key(&self) -> String {
                self.masterkey.key_hex()
            }

            /// Get the key as a hex string. Equivalent to [`Self::key`].
            #[inline]
            pub fn key_hex(&self) -> String {
                self.masterkey.key_hex()
            }

            /// Get the key in raw bytes format
            #[inline]
            pub fn key_bytes(&self) -> &[u8; 64] {
                self.masterkey.key_bytes()
            }
        }

        impl ObtextCodec for $name {
            #[inline(always)]
            fn enc(&self, plaintext: &str) -> Result<String, Error> {
                if plaintext.is_empty() {
                    return Err(Error::EmptyPlaintext);
                }

                // obcrypt produces the raw AEAD scheme output; the
                // obtext is its text encoding, no scheme marker on the
                // wire (the scheme is fixed by this codec type).
                let scheme_output =
                    $encrypt_fn(plaintext.as_bytes(), self.masterkey.obcrypt_key())?;

                // Encode - compile-time dispatch
                Ok(encode_bytes(&scheme_output, $encoding))
            }

            #[inline(always)]
            fn dec(&self, obtext: &str) -> Result<String, Error> {
                // Decode to the scheme output bytes
                let buffer = decode_bytes(obtext, $encoding)?;

                // Decrypt directly. The scheme is fixed by this codec
                // type; a wrong scheme fails the AEAD tag check.
                let plaintext_bytes = $decrypt_fn(&buffer, self.masterkey.obcrypt_key())?;

                // Convert to string. The core dec path always validates
                // UTF-8 (spec §4.1) — a decrypt must never return an
                // unchecked `String`.
                String::from_utf8(plaintext_bytes).map_err(|_| Error::InvalidUtf8)
            }

            #[inline(always)]
            fn format(&self) -> Format {
                Format::new($scheme, $encoding)
            }

            #[inline(always)]
            fn scheme(&self) -> Scheme {
                $scheme
            }

            #[inline(always)]
            fn encoding(&self) -> Encoding {
                $encoding
            }
        }

        // Add inherent methods that delegate to trait methods
        impl $name {
            /// Encrypt and encode plaintext
            #[inline(always)]
            pub fn enc(&self, plaintext: &str) -> Result<String, Error> {
                <Self as ObtextCodec>::enc(self, plaintext)
            }

            /// Decode and decrypt obtext (no scheme autodetection)
            #[inline(always)]
            pub fn dec(&self, obtext: &str) -> Result<String, Error> {
                <Self as ObtextCodec>::dec(self, obtext)
            }

            /// Get the format
            #[inline(always)]
            pub fn format(&self) -> Format {
                <Self as ObtextCodec>::format(self)
            }

            /// Get the scheme
            #[inline(always)]
            pub fn scheme(&self) -> Scheme {
                <Self as ObtextCodec>::scheme(self)
            }

            /// Get the encoding
            #[inline(always)]
            pub fn encoding(&self) -> Encoding {
                <Self as ObtextCodec>::encoding(self)
            }
        }
    };
}

/// Macro for the AES-SIV schemes (dsiv, psiv). The full 64-byte master
/// key is used directly as the AES-SIV key (no derivation).
macro_rules! impl_codec_64 {
    (
        $name:ident,
        $scheme:expr,
        $encoding:expr,
        $format_str:expr,
        $encrypt_fn:path,
        $decrypt_fn:path,
        $key_extract: ident
    ) => {
        #[doc = concat!("ObtextCodec implementation for ", $format_str, " format.\n\n")]
        #[doc = concat!("Corresponds to format string: `\"", $format_str, "\"`")]
        #[allow(non_camel_case_types)]
        pub struct $name {
            masterkey: MasterKey,
        }

        impl $name {
            /// Create a new instance from a 128-character hex key
            /// string (the canonical key form). For raw bytes use
            /// [`Self::from_bytes`]; [`Self::from_hex_key`] is the
            /// explicit-hex equivalent of this constructor.
            #[inline]
            pub fn new(key: &str) -> Result<Self, Error> {
                Ok(Self {
                    masterkey: MasterKey::from_string(key)?,
                })
            }

            /// Internal: build from raw bytes. Used by `ObAny`
            /// constructors that route to per-format codecs.
            #[inline]
            fn from_bytes_internal(key_bytes: &[u8; 64]) -> Result<Self, Error> {
                Ok(Self {
                    masterkey: MasterKey::from_bytes(key_bytes)?,
                })
            }

            /// Create a new instance with hardcoded key (testing only).
            #[inline]
            #[cfg(feature = "keyless")]
            pub fn new_keyless() -> Result<Self, Error> {
                Ok(Self {
                    masterkey: MasterKey::from_bytes(&HARDCODED_KEY_BYTES)?,
                })
            }

            /// Create a new instance from a 128-character hex key.
            /// Strict hex — rejects base64. Use [`Self::new`] for the
            /// length-routing entry point that accepts both.
            #[inline]
            pub fn from_hex_key(key_hex: &str) -> Result<Self, Error> {
                Ok(Self {
                    masterkey: MasterKey::from_hex(key_hex)?,
                })
            }

            /// Create a new instance from a 64-byte key.
            #[inline]
            pub fn from_bytes(key_bytes: &[u8; 64]) -> Result<Self, Error> {
                Ok(Self {
                    masterkey: MasterKey::from_bytes(key_bytes)?,
                })
            }

            /// Get the key as a 128-character hex string.
            #[inline]
            pub fn key(&self) -> String {
                self.masterkey.key_hex()
            }

            /// Get the key as a hex string. Equivalent to [`Self::key`].
            #[inline]
            pub fn key_hex(&self) -> String {
                self.masterkey.key_hex()
            }

            /// Get the key in raw bytes format
            #[inline]
            pub fn key_bytes(&self) -> &[u8; 64] {
                self.masterkey.key_bytes()
            }
        }

        impl ObtextCodec for $name {
            #[inline(always)]
            fn enc(&self, plaintext: &str) -> Result<String, Error> {
                if plaintext.is_empty() {
                    return Err(Error::EmptyPlaintext);
                }

                // obcrypt produces the raw AEAD scheme output; the
                // obtext is its text encoding, no scheme marker on the
                // wire (the scheme is fixed by this codec type).
                let scheme_output =
                    $encrypt_fn(plaintext.as_bytes(), self.masterkey.obcrypt_key())?;

                // Encode - compile-time dispatch
                Ok(encode_bytes(&scheme_output, $encoding))
            }

            #[inline(always)]
            fn dec(&self, obtext: &str) -> Result<String, Error> {
                // Decode to the scheme output bytes
                let buffer = decode_bytes(obtext, $encoding)?;

                // Decrypt directly. The scheme is fixed by this codec
                // type; a wrong scheme fails the AEAD tag check.
                let plaintext_bytes = $decrypt_fn(&buffer, self.masterkey.obcrypt_key())?;

                // Convert to string. The core dec path always validates
                // UTF-8 (spec §4.1) — a decrypt must never return an
                // unchecked `String`.
                String::from_utf8(plaintext_bytes).map_err(|_| Error::InvalidUtf8)
            }

            #[inline(always)]
            fn format(&self) -> Format {
                Format::new($scheme, $encoding)
            }

            #[inline(always)]
            fn scheme(&self) -> Scheme {
                $scheme
            }

            #[inline(always)]
            fn encoding(&self) -> Encoding {
                $encoding
            }
        }

        impl $name {
            /// Encrypt and encode plaintext
            #[inline(always)]
            pub fn enc(&self, plaintext: &str) -> Result<String, Error> {
                <Self as ObtextCodec>::enc(self, plaintext)
            }

            /// Decode and decrypt obtext (no scheme autodetection)
            #[inline(always)]
            pub fn dec(&self, obtext: &str) -> Result<String, Error> {
                <Self as ObtextCodec>::dec(self, obtext)
            }

            /// Get the format
            #[inline(always)]
            pub fn format(&self) -> Format {
                <Self as ObtextCodec>::format(self)
            }

            /// Get the scheme
            #[inline(always)]
            pub fn scheme(&self) -> Scheme {
                <Self as ObtextCodec>::scheme(self)
            }

            /// Get the encoding
            #[inline(always)]
            pub fn encoding(&self) -> Encoding {
                <Self as ObtextCodec>::encoding(self)
            }
        }
    };
}

// Helper functions for encoding/decoding with compile-time dispatch
#[inline(always)]
fn encode_bytes(bytes: &[u8], encoding: Encoding) -> String {
    match encoding {
        Encoding::C32 => crate::base32::BASE32_CROCKFORD.encode(bytes),
        Encoding::B32 => crate::base32::BASE32_RFC.encode(bytes),
        Encoding::B64 => data_encoding::BASE64URL_NOPAD.encode(bytes),
        Encoding::Hex => data_encoding::HEXLOWER.encode(bytes),
    }
}

#[inline(always)]
fn decode_bytes(text: &str, encoding: Encoding) -> Result<Vec<u8>, Error> {
    match encoding {
        Encoding::C32 => crate::base32::BASE32_CROCKFORD
            .decode(text.as_bytes())
            .map_err(|_| Error::InvalidC32),
        Encoding::B32 => crate::base32::BASE32_RFC
            .decode(text.as_bytes())
            .map_err(|_| Error::InvalidB32),
        Encoding::B64 => data_encoding::BASE64URL_NOPAD
            .decode(text.as_bytes())
            .map_err(|_| Error::InvalidB64),
        Encoding::Hex => data_encoding::HEXLOWER
            .decode(text.as_bytes())
            .map_err(|_| Error::InvalidHex),
    }
}

// Generate all scheme+encoding combinations

// dgcmsiv variants (32-byte key)
#[cfg(feature = "dgcmsiv")]
impl_codec_32!(
    DgcmsivC32,
    Scheme::Dgcmsiv,
    Encoding::C32,
    "dgcmsiv. c32",
    obcrypt::schemes::dgcmsiv::encrypt,
    obcrypt::schemes::dgcmsiv::decrypt,
    dgcmsiv
);
#[cfg(feature = "dgcmsiv")]
impl_codec_32!(
    DgcmsivB32,
    Scheme::Dgcmsiv,
    Encoding::B32,
    "dgcmsiv. b32",
    obcrypt::schemes::dgcmsiv::encrypt,
    obcrypt::schemes::dgcmsiv::decrypt,
    dgcmsiv
);
#[cfg(feature = "dgcmsiv")]
impl_codec_32!(
    DgcmsivB64,
    Scheme::Dgcmsiv,
    Encoding::B64,
    "dgcmsiv.b64",
    obcrypt::schemes::dgcmsiv::encrypt,
    obcrypt::schemes::dgcmsiv::decrypt,
    dgcmsiv
);
#[cfg(feature = "dgcmsiv")]
impl_codec_32!(
    DgcmsivHex,
    Scheme::Dgcmsiv,
    Encoding::Hex,
    "dgcmsiv.hex",
    obcrypt::schemes::dgcmsiv::encrypt,
    obcrypt::schemes::dgcmsiv::decrypt,
    dgcmsiv
);

// dsiv variants (64-byte key)
#[cfg(feature = "dsiv")]
impl_codec_64!(
    DsivC32,
    Scheme::Dsiv,
    Encoding::C32,
    "dsiv.c32",
    obcrypt::schemes::dsiv::encrypt,
    obcrypt::schemes::dsiv::decrypt,
    dsiv
);
#[cfg(feature = "dsiv")]
impl_codec_64!(
    DsivB32,
    Scheme::Dsiv,
    Encoding::B32,
    "dsiv.b32",
    obcrypt::schemes::dsiv::encrypt,
    obcrypt::schemes::dsiv::decrypt,
    dsiv
);
#[cfg(feature = "dsiv")]
impl_codec_64!(
    DsivB64,
    Scheme::Dsiv,
    Encoding::B64,
    "dsiv.b64",
    obcrypt::schemes::dsiv::encrypt,
    obcrypt::schemes::dsiv::decrypt,
    dsiv
);
#[cfg(feature = "dsiv")]
impl_codec_64!(
    DsivHex,
    Scheme::Dsiv,
    Encoding::Hex,
    "dsiv.hex",
    obcrypt::schemes::dsiv::encrypt,
    obcrypt::schemes::dsiv::decrypt,
    dsiv
);

// pgcmsiv variants (32-byte key)
#[cfg(feature = "pgcmsiv")]
impl_codec_32!(
    PgcmsivC32,
    Scheme::Pgcmsiv,
    Encoding::C32,
    "pgcmsiv.c32",
    obcrypt::schemes::pgcmsiv::encrypt,
    obcrypt::schemes::pgcmsiv::decrypt,
    pgcmsiv
);
#[cfg(feature = "pgcmsiv")]
impl_codec_32!(
    PgcmsivB32,
    Scheme::Pgcmsiv,
    Encoding::B32,
    "pgcmsiv.b32",
    obcrypt::schemes::pgcmsiv::encrypt,
    obcrypt::schemes::pgcmsiv::decrypt,
    pgcmsiv
);
#[cfg(feature = "pgcmsiv")]
impl_codec_32!(
    PgcmsivB64,
    Scheme::Pgcmsiv,
    Encoding::B64,
    "pgcmsiv.b64",
    obcrypt::schemes::pgcmsiv::encrypt,
    obcrypt::schemes::pgcmsiv::decrypt,
    pgcmsiv
);
#[cfg(feature = "pgcmsiv")]
impl_codec_32!(
    PgcmsivHex,
    Scheme::Pgcmsiv,
    Encoding::Hex,
    "pgcmsiv.hex",
    obcrypt::schemes::pgcmsiv::encrypt,
    obcrypt::schemes::pgcmsiv::decrypt,
    pgcmsiv
);

// psiv variants (64-byte key)
#[cfg(feature = "psiv")]
impl_codec_64!(
    PsivC32,
    Scheme::Psiv,
    Encoding::C32,
    "psiv.c32",
    obcrypt::schemes::psiv::encrypt,
    obcrypt::schemes::psiv::decrypt,
    psiv
);
#[cfg(feature = "psiv")]
impl_codec_64!(
    PsivB32,
    Scheme::Psiv,
    Encoding::B32,
    "psiv.b32",
    obcrypt::schemes::psiv::encrypt,
    obcrypt::schemes::psiv::decrypt,
    psiv
);
#[cfg(feature = "psiv")]
impl_codec_64!(
    PsivB64,
    Scheme::Psiv,
    Encoding::B64,
    "psiv.b64",
    obcrypt::schemes::psiv::encrypt,
    obcrypt::schemes::psiv::decrypt,
    psiv
);
#[cfg(feature = "psiv")]
impl_codec_64!(
    PsivHex,
    Scheme::Psiv,
    Encoding::Hex,
    "psiv.hex",
    obcrypt::schemes::psiv::encrypt,
    obcrypt::schemes::psiv::decrypt,
    psiv
);


// mock1 variants (32-byte key)
#[cfg(feature = "mock")]
impl_codec_32!(
    Mock1C32,
    Scheme::Mock1,
    Encoding::C32,
    "mock1.c32",
    obcrypt::schemes::mock1::encrypt,
    obcrypt::schemes::mock1::decrypt,
    mock1
);
#[cfg(feature = "mock")]
impl_codec_32!(
    Mock1B32,
    Scheme::Mock1,
    Encoding::B32,
    "mock1.b32",
    obcrypt::schemes::mock1::encrypt,
    obcrypt::schemes::mock1::decrypt,
    mock1
);
#[cfg(feature = "mock")]
impl_codec_32!(
    Mock1B64,
    Scheme::Mock1,
    Encoding::B64,
    "mock1.b64",
    obcrypt::schemes::mock1::encrypt,
    obcrypt::schemes::mock1::decrypt,
    mock1
);
#[cfg(feature = "mock")]
impl_codec_32!(
    Mock1Hex,
    Scheme::Mock1,
    Encoding::Hex,
    "mock1.hex",
    obcrypt::schemes::mock1::encrypt,
    obcrypt::schemes::mock1::decrypt,
    mock1
);

// mock2 variants (32-byte key)
#[cfg(feature = "mock")]
impl_codec_32!(
    Mock2C32,
    Scheme::Mock2,
    Encoding::C32,
    "mock2.c32",
    obcrypt::schemes::mock2::encrypt,
    obcrypt::schemes::mock2::decrypt,
    mock2
);
#[cfg(feature = "mock")]
impl_codec_32!(
    Mock2B32,
    Scheme::Mock2,
    Encoding::B32,
    "mock2.b32",
    obcrypt::schemes::mock2::encrypt,
    obcrypt::schemes::mock2::decrypt,
    mock2
);
#[cfg(feature = "mock")]
impl_codec_32!(
    Mock2B64,
    Scheme::Mock2,
    Encoding::B64,
    "mock2.b64",
    obcrypt::schemes::mock2::encrypt,
    obcrypt::schemes::mock2::decrypt,
    mock2
);
#[cfg(feature = "mock")]
impl_codec_32!(
    Mock2Hex,
    Scheme::Mock2,
    Encoding::Hex,
    "mock2.hex",
    obcrypt::schemes::mock2::encrypt,
    obcrypt::schemes::mock2::decrypt,
    mock2
);

/// Type-erased ObtextCodec encoder that can hold any scheme+encoding combination.
///
/// This enum allows for runtime scheme selection without heap allocation.
/// It's returned by the `oboron::new()` factory function.
#[allow(non_camel_case_types)]
pub enum ObAny {
    #[cfg(feature = "dgcmsiv")]
    DgcmsivC32(DgcmsivC32),
    #[cfg(feature = "dgcmsiv")]
    DgcmsivB32(DgcmsivB32),
    #[cfg(feature = "dgcmsiv")]
    DgcmsivB64(DgcmsivB64),
    #[cfg(feature = "dgcmsiv")]
    DgcmsivHex(DgcmsivHex),
    #[cfg(feature = "pgcmsiv")]
    PgcmsivC32(PgcmsivC32),
    #[cfg(feature = "pgcmsiv")]
    PgcmsivB32(PgcmsivB32),
    #[cfg(feature = "pgcmsiv")]
    PgcmsivB64(PgcmsivB64),
    #[cfg(feature = "pgcmsiv")]
    PgcmsivHex(PgcmsivHex),
    #[cfg(feature = "dsiv")]
    DsivC32(DsivC32),
    #[cfg(feature = "dsiv")]
    DsivB32(DsivB32),
    #[cfg(feature = "dsiv")]
    DsivB64(DsivB64),
    #[cfg(feature = "dsiv")]
    DsivHex(DsivHex),
    #[cfg(feature = "psiv")]
    PsivC32(PsivC32),
    #[cfg(feature = "psiv")]
    PsivB32(PsivB32),
    #[cfg(feature = "psiv")]
    PsivB64(PsivB64),
    #[cfg(feature = "psiv")]
    PsivHex(PsivHex),
    // Testing
    #[cfg(feature = "mock")]
    Mock1C32(Mock1C32),
    #[cfg(feature = "mock")]
    Mock1B32(Mock1B32),
    #[cfg(feature = "mock")]
    Mock1Hex(Mock1Hex),
    #[cfg(feature = "mock")]
    Mock1B64(Mock1B64),
    #[cfg(feature = "mock")]
    Mock2C32(Mock2C32),
    #[cfg(feature = "mock")]
    Mock2B32(Mock2B32),
    #[cfg(feature = "mock")]
    Mock2Hex(Mock2Hex),
    #[cfg(feature = "mock")]
    Mock2B64(Mock2B64),
}

// Macro to delegate ObtextCodec methods to the inner type
macro_rules! delegate_to_inner {
    (fn $method:ident(&self $(, $arg:ident: $argty:ty)*) -> $ret:ty) => {
        fn $method(&self $(, $arg: $argty)*) -> $ret {
            match self {
                #[cfg(feature = "dgcmsiv")]
                ObAny::DgcmsivC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "dgcmsiv")]
                ObAny::DgcmsivB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "dgcmsiv")]
                ObAny::DgcmsivB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "dgcmsiv")]
                ObAny::DgcmsivHex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "pgcmsiv")]
                ObAny::PgcmsivC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "pgcmsiv")]
                ObAny::PgcmsivB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "pgcmsiv")]
                ObAny::PgcmsivB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "pgcmsiv")]
                ObAny::PgcmsivHex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "dsiv")]
                ObAny::DsivC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "dsiv")]
                ObAny::DsivB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "dsiv")]
                ObAny::DsivB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "dsiv")]
                ObAny::DsivHex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "psiv")]
                ObAny::PsivC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "psiv")]
                ObAny::PsivB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "psiv")]
                ObAny::PsivB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "psiv")]
                ObAny::PsivHex(ob) => ob.$method($($arg),*),
                // Testing
                #[cfg(feature = "mock")]
                ObAny::Mock1C32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "mock")]
                ObAny::Mock1B32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "mock")]
                ObAny::Mock1B64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "mock")]
                ObAny::Mock1Hex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "mock")]
                ObAny::Mock2C32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "mock")]
                ObAny::Mock2B32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "mock")]
                ObAny::Mock2B64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "mock")]
                ObAny::Mock2Hex(ob) => ob.$method($($arg),*),
            }
        }
    };
}

impl ObtextCodec for ObAny {
    delegate_to_inner!(fn enc(&self, plaintext: &str) -> Result<String, Error>);
    delegate_to_inner!(fn dec(&self, obtext: &str) -> Result<String, Error>);
    delegate_to_inner!(fn format(&self) -> Format);
    delegate_to_inner!(fn scheme(&self) -> Scheme);
    delegate_to_inner!(fn encoding(&self) -> Encoding);
}

// Inherent constructors for ObAny
impl ObAny {
    /// Create a new instance with a 128-character hex string key.
    ///
    /// Defaults to dgcmsiv.c32 format.
    pub fn new(key: &str) -> Result<Self, Error> {
        #[cfg(feature = "dgcmsiv")]
        return Ok(ObAny::DgcmsivC32(DgcmsivC32::new(key)?));
        #[cfg(feature = "pgcmsiv")]
        #[cfg(not(any(feature = "dgcmsiv")))]
        return Ok(ObAny::PgcmsivC32(PgcmsivC32::new(key)?));
        #[cfg(feature = "dsiv")]
        #[cfg(not(any(feature = "dgcmsiv", feature = "pgcmsiv")))]
        return Ok(ObAny::DsivC32(DsivC32::new(key)?));
        #[cfg(feature = "psiv")]
        #[cfg(not(any(feature = "dgcmsiv", feature = "pgcmsiv", feature = "dsiv")))]
        return Ok(ObAny::PsivC32(PsivC32::new(key)?));
        #[cfg(not(any(
            feature = "dgcmsiv",
            feature = "pgcmsiv",
            feature = "dsiv",
            feature = "psiv",
        )))]
        compile_error!("At least one oboron scheme must be enabled");
    }

    /// Create a new instance from a 64-byte key.
    ///
    /// Defaults to dgcmsiv.c32 format.
    #[inline]
    pub fn from_bytes(key_bytes: &[u8; 64]) -> Result<Self, Error> {
        #[cfg(feature = "dgcmsiv")]
        return Ok(ObAny::DgcmsivC32(DgcmsivC32 {
            masterkey: MasterKey::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "pgcmsiv")]
        #[cfg(not(any(feature = "dgcmsiv")))]
        return Ok(ObAny::PgcmsivC32(PgcmsivC32 {
            masterkey: MasterKey::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "dsiv")]
        #[cfg(not(any(feature = "dgcmsiv", feature = "pgcmsiv")))]
        return Ok(ObAny::DsivC32(DsivC32 {
            masterkey: MasterKey::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "psiv")]
        #[cfg(not(any(feature = "dgcmsiv", feature = "dsiv", feature = "pgcmsiv")))]
        return Ok(ObAny::PsivC32(PsivC32 {
            masterkey: MasterKey::from_bytes(key_bytes)?,
        }));
        #[cfg(not(any(
            feature = "dgcmsiv",
            feature = "dsiv",
            feature = "pgcmsiv",
            feature = "psiv",
        )))]
        compile_error!("At least one oboron scheme must be enabled");
    }

    pub fn from_hex_key(key_hex: &str) -> Result<Self, Error> {
        #[cfg(feature = "dgcmsiv")]
        return Ok(ObAny::DgcmsivC32(DgcmsivC32::from_hex_key(key_hex)?));
        #[cfg(feature = "pgcmsiv")]
        #[cfg(not(any(feature = "dgcmsiv")))]
        return Ok(ObAny::PgcmsivC32(PgcmsivC32::from_hex_key(key_hex)?));
        #[cfg(feature = "dsiv")]
        #[cfg(not(any(feature = "dgcmsiv", feature = "pgcmsiv")))]
        return Ok(ObAny::DsivC32(DsivC32::from_hex_key(key_hex)?));
        #[cfg(feature = "psiv")]
        #[cfg(not(any(feature = "dgcmsiv", feature = "pgcmsiv", feature = "dsiv")))]
        return Ok(ObAny::PsivC32(PsivC32::from_hex_key(key_hex)?));
        #[cfg(not(any(
            feature = "dgcmsiv",
            feature = "pgcmsiv",
            feature = "dsiv",
            feature = "psiv",
        )))]
        compile_error!("At least one oboron scheme must be enabled");
    }

    /// Create a new instance with hardcoded key (testing only).
    ///
    /// Defaults to dgcmsiv.c32 format.
    #[cfg(feature = "keyless")]
    pub fn new_keyless() -> Result<Self, Error> {
        #[cfg(feature = "dgcmsiv")]
        return Ok(ObAny::DgcmsivC32(DgcmsivC32 {
            masterkey: MasterKey::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "pgcmsiv")]
        #[cfg(not(any(feature = "dgcmsiv")))]
        return Ok(ObAny::PgcmsivC32(PgcmsivC32 {
            masterkey: MasterKey::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "dsiv")]
        #[cfg(not(any(feature = "dgcmsiv", feature = "pgcmsiv")))]
        return Ok(ObAny::DsivC32(DsivC32 {
            masterkey: MasterKey::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "psiv")]
        #[cfg(not(any(feature = "dgcmsiv", feature = "pgcmsiv", feature = "dsiv")))]
        return Ok(ObAny::PsivC32(PsivC32 {
            masterkey: MasterKey::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(not(any(
            feature = "dgcmsiv",
            feature = "pgcmsiv",
            feature = "dsiv",
            feature = "psiv",
        )))]
        compile_error!("At least one oboron scheme must be enabled");
    }
}

// Delegate to ObtextCodec methods
impl ObAny {
    /// Encrypt and encode plaintext
    #[inline]
    pub fn enc(&self, plaintext: &str) -> Result<String, Error> {
        <Self as ObtextCodec>::enc(self, plaintext)
    }

    /// Decode and decrypt obtext
    #[inline]
    pub fn dec(&self, obtext: &str) -> Result<String, Error> {
        <Self as ObtextCodec>::dec(self, obtext)
    }

    /// Get the format
    #[inline]
    pub fn format(&self) -> Format {
        <Self as ObtextCodec>::format(self)
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

/// Create an encoder from a format string and base64 key.
pub fn new(fmt: &str, key: &str) -> Result<ObAny, Error> {
    let format = Format::from_str(fmt)?;
    new_with_format(format, key)
}

/// Create an encoder from a pre-parsed Format and base64 key.
pub fn new_with_format(format: Format, key: &str) -> Result<ObAny, Error> {
    match (format.scheme(), format.encoding()) {
        #[cfg(feature = "dgcmsiv")]
        (Scheme::Dgcmsiv, Encoding::C32) => Ok(ObAny::DgcmsivC32(DgcmsivC32::new(key)?)),
        #[cfg(feature = "dgcmsiv")]
        (Scheme::Dgcmsiv, Encoding::B32) => Ok(ObAny::DgcmsivB32(DgcmsivB32::new(key)?)),
        #[cfg(feature = "dgcmsiv")]
        (Scheme::Dgcmsiv, Encoding::B64) => Ok(ObAny::DgcmsivB64(DgcmsivB64::new(key)?)),
        #[cfg(feature = "dgcmsiv")]
        (Scheme::Dgcmsiv, Encoding::Hex) => Ok(ObAny::DgcmsivHex(DgcmsivHex::new(key)?)),
        #[cfg(feature = "pgcmsiv")]
        (Scheme::Pgcmsiv, Encoding::C32) => Ok(ObAny::PgcmsivC32(PgcmsivC32::new(key)?)),
        #[cfg(feature = "pgcmsiv")]
        (Scheme::Pgcmsiv, Encoding::B32) => Ok(ObAny::PgcmsivB32(PgcmsivB32::new(key)?)),
        #[cfg(feature = "pgcmsiv")]
        (Scheme::Pgcmsiv, Encoding::B64) => Ok(ObAny::PgcmsivB64(PgcmsivB64::new(key)?)),
        #[cfg(feature = "pgcmsiv")]
        (Scheme::Pgcmsiv, Encoding::Hex) => Ok(ObAny::PgcmsivHex(PgcmsivHex::new(key)?)),
        #[cfg(feature = "dsiv")]
        (Scheme::Dsiv, Encoding::C32) => Ok(ObAny::DsivC32(DsivC32::new(key)?)),
        #[cfg(feature = "dsiv")]
        (Scheme::Dsiv, Encoding::B32) => Ok(ObAny::DsivB32(DsivB32::new(key)?)),
        #[cfg(feature = "dsiv")]
        (Scheme::Dsiv, Encoding::B64) => Ok(ObAny::DsivB64(DsivB64::new(key)?)),
        #[cfg(feature = "dsiv")]
        (Scheme::Dsiv, Encoding::Hex) => Ok(ObAny::DsivHex(DsivHex::new(key)?)),
        #[cfg(feature = "psiv")]
        (Scheme::Psiv, Encoding::C32) => Ok(ObAny::PsivC32(PsivC32::new(key)?)),
        #[cfg(feature = "psiv")]
        (Scheme::Psiv, Encoding::B32) => Ok(ObAny::PsivB32(PsivB32::new(key)?)),
        #[cfg(feature = "psiv")]
        (Scheme::Psiv, Encoding::B64) => Ok(ObAny::PsivB64(PsivB64::new(key)?)),
        #[cfg(feature = "psiv")]
        (Scheme::Psiv, Encoding::Hex) => Ok(ObAny::PsivHex(PsivHex::new(key)?)),
        // Testing
        #[cfg(feature = "mock")]
        (Scheme::Mock1, Encoding::C32) => Ok(ObAny::Mock1C32(Mock1C32::new(key)?)),
        #[cfg(feature = "mock")]
        (Scheme::Mock1, Encoding::B32) => Ok(ObAny::Mock1B32(Mock1B32::new(key)?)),
        #[cfg(feature = "mock")]
        (Scheme::Mock1, Encoding::B64) => Ok(ObAny::Mock1B64(Mock1B64::new(key)?)),
        #[cfg(feature = "mock")]
        (Scheme::Mock1, Encoding::Hex) => Ok(ObAny::Mock1Hex(Mock1Hex::new(key)?)),
        #[cfg(feature = "mock")]
        (Scheme::Mock2, Encoding::C32) => Ok(ObAny::Mock2C32(Mock2C32::new(key)?)),
        #[cfg(feature = "mock")]
        (Scheme::Mock2, Encoding::B32) => Ok(ObAny::Mock2B32(Mock2B32::new(key)?)),
        #[cfg(feature = "mock")]
        (Scheme::Mock2, Encoding::B64) => Ok(ObAny::Mock2B64(Mock2B64::new(key)?)),
        #[cfg(feature = "mock")]
        (Scheme::Mock2, Encoding::Hex) => Ok(ObAny::Mock2Hex(Mock2Hex::new(key)?)),
        #[allow(unreachable_patterns)]
        _ => Err(Error::UnknownScheme),
    }
}

fn from_bytes_with_format_internal(format: Format, key_bytes: &[u8; 64]) -> Result<ObAny, Error> {
    match (format.scheme(), format.encoding()) {
        #[cfg(feature = "dgcmsiv")]
        (Scheme::Dgcmsiv, Encoding::C32) => {
            Ok(ObAny::DgcmsivC32(DgcmsivC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "dgcmsiv")]
        (Scheme::Dgcmsiv, Encoding::B32) => {
            Ok(ObAny::DgcmsivB32(DgcmsivB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "dgcmsiv")]
        (Scheme::Dgcmsiv, Encoding::B64) => {
            Ok(ObAny::DgcmsivB64(DgcmsivB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "dgcmsiv")]
        (Scheme::Dgcmsiv, Encoding::Hex) => {
            Ok(ObAny::DgcmsivHex(DgcmsivHex::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "pgcmsiv")]
        (Scheme::Pgcmsiv, Encoding::C32) => {
            Ok(ObAny::PgcmsivC32(PgcmsivC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "pgcmsiv")]
        (Scheme::Pgcmsiv, Encoding::B32) => {
            Ok(ObAny::PgcmsivB32(PgcmsivB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "pgcmsiv")]
        (Scheme::Pgcmsiv, Encoding::B64) => {
            Ok(ObAny::PgcmsivB64(PgcmsivB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "pgcmsiv")]
        (Scheme::Pgcmsiv, Encoding::Hex) => {
            Ok(ObAny::PgcmsivHex(PgcmsivHex::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "dsiv")]
        (Scheme::Dsiv, Encoding::C32) => {
            Ok(ObAny::DsivC32(DsivC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "dsiv")]
        (Scheme::Dsiv, Encoding::B32) => {
            Ok(ObAny::DsivB32(DsivB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "dsiv")]
        (Scheme::Dsiv, Encoding::B64) => {
            Ok(ObAny::DsivB64(DsivB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "dsiv")]
        (Scheme::Dsiv, Encoding::Hex) => {
            Ok(ObAny::DsivHex(DsivHex::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "psiv")]
        (Scheme::Psiv, Encoding::C32) => {
            Ok(ObAny::PsivC32(PsivC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "psiv")]
        (Scheme::Psiv, Encoding::B32) => {
            Ok(ObAny::PsivB32(PsivB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "psiv")]
        (Scheme::Psiv, Encoding::B64) => {
            Ok(ObAny::PsivB64(PsivB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "psiv")]
        (Scheme::Psiv, Encoding::Hex) => {
            Ok(ObAny::PsivHex(PsivHex::from_bytes_internal(key_bytes)?))
        }
        // Testing
        #[cfg(feature = "mock")]
        (Scheme::Mock1, Encoding::C32) => {
            Ok(ObAny::Mock1C32(Mock1C32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "mock")]
        (Scheme::Mock1, Encoding::B32) => {
            Ok(ObAny::Mock1B32(Mock1B32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "mock")]
        (Scheme::Mock1, Encoding::B64) => {
            Ok(ObAny::Mock1B64(Mock1B64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "mock")]
        (Scheme::Mock1, Encoding::Hex) => {
            Ok(ObAny::Mock1Hex(Mock1Hex::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "mock")]
        (Scheme::Mock2, Encoding::C32) => {
            Ok(ObAny::Mock2C32(Mock2C32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "mock")]
        (Scheme::Mock2, Encoding::B32) => {
            Ok(ObAny::Mock2B32(Mock2B32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "mock")]
        (Scheme::Mock2, Encoding::B64) => {
            Ok(ObAny::Mock2B64(Mock2B64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "mock")]
        (Scheme::Mock2, Encoding::Hex) => {
            Ok(ObAny::Mock2Hex(Mock2Hex::from_bytes_internal(key_bytes)?))
        }
        #[allow(unreachable_patterns)]
        _ => Err(Error::UnknownScheme),
    }
}

fn from_hex_key_with_format_internal(format: Format, key_hex: &str) -> Result<ObAny, Error> {
    // Spec §3.3: keys MUST be lowercase hex (the `hex` crate is
    // case-insensitive, so reject uppercase explicitly).
    if key_hex.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(Error::InvalidHex);
    }
    let key_vec = hex::decode(key_hex)?;
    let key_arr: [u8; 64] = key_vec.try_into().map_err(|_| Error::InvalidKeyLength)?;
    from_bytes_with_format_internal(format, &key_arr)
}

/// Create an encoder from a format string and a 128-character hex key.
pub fn from_hex_key(fmt: &str, key_hex: &str) -> Result<ObAny, Error> {
    let format = Format::from_str(fmt)?;
    from_hex_key_with_format_internal(format, key_hex)
}

/// Create an encoder from a pre-parsed Format and a 128-character hex key.
pub fn from_hex_key_with_format(format: Format, key_hex: &str) -> Result<ObAny, Error> {
    from_hex_key_with_format_internal(format, key_hex)
}

/// Create an encoder from a format string and raw bytes.
pub fn from_bytes(fmt: &str, key_bytes: &[u8; 64]) -> Result<ObAny, Error> {
    let format = Format::from_str(fmt)?;
    from_bytes_with_format_internal(format, key_bytes)
}

/// Create an encoder from a pre-parsed Format and raw bytes.
pub fn from_bytes_with_format(format: Format, key_bytes: &[u8; 64]) -> Result<ObAny, Error> {
    from_bytes_with_format_internal(format, key_bytes)
}

/// Create an encoder from a format string using the hardcoded key (testing only).
#[cfg(feature = "keyless")]
pub fn new_keyless(fmt: &str) -> Result<ObAny, Error> {
    let format = Format::from_str(fmt)?;
    from_bytes_with_format_internal(format, &HARDCODED_KEY_BYTES)
}

/// Create an encoder from a pre-parsed Format using the hardcoded key (testing only).
#[cfg(feature = "keyless")]
pub fn new_keyless_with_format(format: Format) -> Result<ObAny, Error> {
    from_bytes_with_format_internal(format, &HARDCODED_KEY_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_with_format_all_combinations() {
        // let key = "0".repeat(86);
        let key = crate::generate_key();

        // Define all schemes
        let schemes = vec![
            #[cfg(feature = "dgcmsiv")]
            Scheme::Dgcmsiv,
            #[cfg(feature = "pgcmsiv")]
            Scheme::Pgcmsiv,
            #[cfg(feature = "dsiv")]
            Scheme::Dsiv,
            #[cfg(feature = "psiv")]
            Scheme::Psiv,
            // Testing
            #[cfg(feature = "mock")]
            Scheme::Mock1,
            #[cfg(feature = "mock")]
            Scheme::Mock2,
        ];

        // Define all encodings
        let encodings = vec![Encoding::C32, Encoding::B32, Encoding::B64, Encoding::Hex];

        for scheme in &schemes {
            for encoding in &encodings {
                let format = Format::new(*scheme, *encoding);
                let result = new_with_format(format, &key);

                assert!(
                    result.is_ok(),
                    "Failed to create ObtextCodec implementation for {:?}:{:?}",
                    scheme,
                    encoding
                );

                let ob = result.unwrap();
                assert_eq!(
                    ob.scheme(),
                    *scheme,
                    "Scheme mismatch for {:?}:{:?}",
                    scheme,
                    encoding
                );
                assert_eq!(
                    ob.encoding(),
                    *encoding,
                    "Encoding mismatch for {:?}:{:?}",
                    scheme,
                    encoding
                );
            }
        }
    }

    #[test]
    fn test_new_from_format_string_all_combinations() {
        let key = crate::generate_key();

        // Only the authenticated core schemes are string-parseable; the
        // mock schemes are deliberately fenced out of the string factory.
        let schemes = vec![
            #[cfg(feature = "dgcmsiv")]
            Scheme::Dgcmsiv,
            #[cfg(feature = "pgcmsiv")]
            Scheme::Pgcmsiv,
            #[cfg(feature = "dsiv")]
            Scheme::Dsiv,
            #[cfg(feature = "psiv")]
            Scheme::Psiv,
        ];

        // Define all encodings
        let encodings = vec![Encoding::C32, Encoding::B32, Encoding::B64, Encoding::Hex];

        for scheme in schemes {
            for encoding in &encodings {
                let format_str = format!("{}.{}", scheme.as_str(), encoding.as_str());
                let result = new(format_str.as_str(), &key);

                assert!(
                    result.is_ok(),
                    "Failed to create ObtextCodec implementation from format string: {}",
                    format_str
                );

                let ob = result.unwrap();
                assert_eq!(
                    ob.scheme(),
                    scheme,
                    "Scheme mismatch for format string: {}",
                    format_str
                );
                assert_eq!(
                    ob.encoding(),
                    *encoding,
                    "Encoding mismatch for format string: {}",
                    format_str
                );
            }
        }
    }

    #[test]
    fn test_roundtrip_all_combinations() {
        let key = crate::generate_key();
        let plaintext = "hello world";

        // mock is reachable by value (not by string), so new_with_format
        // still accepts it here.
        let schemes = vec![
            #[cfg(feature = "mock")]
            Scheme::Mock2,
            #[cfg(feature = "mock")]
            Scheme::Mock1,
            #[cfg(feature = "dgcmsiv")]
            Scheme::Dgcmsiv,
            #[cfg(feature = "dsiv")]
            Scheme::Dsiv,
        ];

        // Define all encodings
        let encodings = vec![Encoding::C32, Encoding::B32, Encoding::B64, Encoding::Hex];

        for scheme in &schemes {
            // Skip probabilistic schemes for this test (they can't roundtrip with the same output)
            if scheme.is_probabilistic() {
                continue;
            }

            for encoding in &encodings {
                let format = Format::new(*scheme, *encoding);
                let ob = new_with_format(format, &key).unwrap();

                let ot = ob.enc(&plaintext).unwrap();
                let pt2 = ob.dec(&ot).unwrap();

                assert_eq!(
                    pt2, plaintext,
                    "Roundtrip failed for {:?}:{:?}",
                    scheme, encoding
                );
            }
        }
    }

    #[test]
    fn test_key_methods() {
        let key = crate::generate_key();
        let dsiv = DsivC32::new(&key).unwrap();

        // generate_key() returns 128-char hex; dsiv.key() returns hex.
        let retrieved_key = dsiv.key();
        assert_eq!(retrieved_key, key);
        assert_eq!(retrieved_key.len(), 128);

        // key_hex() is the canonical accessor.
        let key_hex = dsiv.key_hex();
        assert_eq!(key_hex.len(), 128);

        let key_bytes = dsiv.key_bytes();
        assert_eq!(key_bytes.len(), 64);
    }
}
