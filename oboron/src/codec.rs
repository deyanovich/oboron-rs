//! Trait-based interface for scheme-specific ObtextCodec implementations.
#[cfg(feature = "keyless")]
use crate::constants::HARDCODED_KEY_BYTES;
use crate::{error::Error, Encoding, Format, MasterKey, Scheme};

/// Core trait for ObtextCodec encryption+encoding/decoding+decryption implementations.
///
/// Each scheme+encoding combination (AasvC32, AasvB64, etc.) implements this trait
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

/// Macro for 32-byte key schemes (aags, apgs, upbc, mock1, mock2)
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
            /// Create a new instance from a key string.
            ///
            /// The key format is auto-detected by length: 128 chars →
            /// hex (canonical), 86 chars → base64 (deprecated; behind
            /// the `base64-keys` feature). For format-explicit
            /// constructors see `from_hex_key` / `from_base64_key`;
            /// for raw bytes use `from_bytes`.
            ///
            /// The base64 path is transitional and will be removed
            /// before oboron 1.0 — migrate keys to hex.
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

            /// Deprecated alias for [`Self::from_hex_key`].
            ///
            /// The 0.8.x `Omnib` used `from_key_hex`; this alias is
            /// kept for migration. Canonical form is
            /// `from_<format>_<target>` (e.g. `from_hex_key`,
            /// `from_base64_secret`).
            #[inline]
            #[deprecated(
                since = "0.9.0",
                note = "use from_hex_key instead — standard from_<format>_<target> pattern"
            )]
            pub fn from_key_hex(key_hex: &str) -> Result<Self, Error> {
                Self::from_hex_key(key_hex)
            }

            /// Create a new instance from a 86-character base64 key.
            /// Strict base64 — rejects hex.
            ///
            /// Deprecated: oboron is moving to hex-only keys before
            /// v1.0. Use [`Self::from_hex_key`] (hex) instead.
            #[inline]
            #[cfg(feature = "base64-keys")]
            #[deprecated(
                since = "0.7.1",
                note = "use from_hex_key() / new() (hex) instead; base64 key support will be removed before oboron 1.0"
            )]
            pub fn from_base64_key(key_b64: &str) -> Result<Self, Error> {
                Ok(Self {
                    #[allow(deprecated)]
                    masterkey: MasterKey::from_base64(key_b64)?,
                })
            }

            /// Deprecated alias for [`Self::from_base64_key`].
            ///
            /// The 0.8.x name had the target/format order flipped
            /// relative to the standard `from_<format>_<target>`
            /// pattern; renamed in 0.9.0 for consistency. Doubly
            /// deprecated: base64 support itself is on the way out
            /// before oboron 1.0.
            #[inline]
            #[cfg(feature = "base64-keys")]
            #[deprecated(
                since = "0.9.0",
                note = "use from_base64_key (or from_hex_key — base64 is going away)"
            )]
            pub fn from_key_base64(key_b64: &str) -> Result<Self, Error> {
                #[allow(deprecated)]
                Self::from_base64_key(key_b64)
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

            /// Get the key as a base64 string.
            ///
            /// Deprecated: oboron is moving to hex-only keys before
            /// v1.0. Use [`Self::key`] (hex) instead.
            #[inline]
            #[cfg(feature = "base64-keys")]
            #[deprecated(
                since = "0.7.1",
                note = "use key() (hex) instead; base64 key support will be removed before oboron 1.0"
            )]
            pub fn key_base64(&self) -> String {
                #[allow(deprecated)]
                self.masterkey.key_base64()
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

                // obcrypt does crypto + scheme-marker framing in one call.
                let mut ciphertext = $encrypt_fn(plaintext.as_bytes(), self.masterkey.obcrypt_key())?;

                // Append the XOR'd marker (oboron protocol framing).
                let marker = $scheme.marker();
                let first_byte = ciphertext[0];
                ciphertext.push(marker[0] ^ first_byte);
                ciphertext.push(marker[1] ^ first_byte);

                // Encode - compile-time dispatch
                Ok(encode_bytes(&ciphertext, $encoding))
            }

            #[inline(always)]
            fn dec(&self, obtext: &str) -> Result<String, Error> {
                // Decode
                let mut buffer = decode_bytes(obtext, $encoding)?;

                if buffer.len() < 2 {
                    return Err(Error::PayloadTooShort);
                }

                // XOR and extract marker
                let len = buffer.len();
                let first_byte = buffer[0];
                let scheme_marker = [buffer[len - 2] ^ first_byte, buffer[len - 1] ^ first_byte];

                // Validate marker
                if scheme_marker != $scheme.marker() {
                    return Err(Error::SchemeMarkerMismatch);
                }

                buffer.truncate(len - 2);

                // Decrypt directly (obcrypt scheme module, no marker framing here).
                let plaintext_bytes = $decrypt_fn(&buffer, self.masterkey.obcrypt_key())?;

                // Convert to string
                #[cfg(feature = "unchecked-utf8")]
                {
                    Ok(unsafe { String::from_utf8_unchecked(plaintext_bytes) })
                }
                #[cfg(not(feature = "unchecked-utf8"))]
                {
                    String::from_utf8(plaintext_bytes).map_err(|_| Error::InvalidUtf8)
                }
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

/// Macro for 64-byte key schemes (aasv, apsv)
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
            /// Create a new instance from a key string.
            ///
            /// The key format is auto-detected by length: 128 chars →
            /// hex (canonical), 86 chars → base64 (deprecated; behind
            /// the `base64-keys` feature). For format-explicit
            /// constructors see `from_hex_key` / `from_base64_key`;
            /// for raw bytes use `from_bytes`.
            ///
            /// The base64 path is transitional and will be removed
            /// before oboron 1.0 — migrate keys to hex.
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

            /// Deprecated alias for [`Self::from_hex_key`].
            ///
            /// The 0.8.x `Omnib` used `from_key_hex`; this alias is
            /// kept for migration. Canonical form is
            /// `from_<format>_<target>` (e.g. `from_hex_key`,
            /// `from_base64_secret`).
            #[inline]
            #[deprecated(
                since = "0.9.0",
                note = "use from_hex_key instead — standard from_<format>_<target> pattern"
            )]
            pub fn from_key_hex(key_hex: &str) -> Result<Self, Error> {
                Self::from_hex_key(key_hex)
            }

            /// Create a new instance from a 86-character base64 key.
            /// Strict base64 — rejects hex.
            ///
            /// Deprecated: oboron is moving to hex-only keys before
            /// v1.0. Use [`Self::from_hex_key`] (hex) instead.
            #[inline]
            #[cfg(feature = "base64-keys")]
            #[deprecated(
                since = "0.7.1",
                note = "use from_hex_key() / new() (hex) instead; base64 key support will be removed before oboron 1.0"
            )]
            pub fn from_base64_key(key_b64: &str) -> Result<Self, Error> {
                Ok(Self {
                    #[allow(deprecated)]
                    masterkey: MasterKey::from_base64(key_b64)?,
                })
            }

            /// Deprecated alias for [`Self::from_base64_key`].
            ///
            /// The 0.8.x name had the target/format order flipped
            /// relative to the standard `from_<format>_<target>`
            /// pattern; renamed in 0.9.0 for consistency. Doubly
            /// deprecated: base64 support itself is on the way out
            /// before oboron 1.0.
            #[inline]
            #[cfg(feature = "base64-keys")]
            #[deprecated(
                since = "0.9.0",
                note = "use from_base64_key (or from_hex_key — base64 is going away)"
            )]
            pub fn from_key_base64(key_b64: &str) -> Result<Self, Error> {
                #[allow(deprecated)]
                Self::from_base64_key(key_b64)
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

            /// Get the key as a base64 string.
            ///
            /// Deprecated: oboron is moving to hex-only keys before
            /// v1.0. Use [`Self::key`] (hex) instead.
            #[inline]
            #[cfg(feature = "base64-keys")]
            #[deprecated(
                since = "0.7.1",
                note = "use key() (hex) instead; base64 key support will be removed before oboron 1.0"
            )]
            pub fn key_base64(&self) -> String {
                #[allow(deprecated)]
                self.masterkey.key_base64()
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

                // obcrypt does crypto + scheme-marker framing in one call.
                let mut ciphertext = $encrypt_fn(plaintext.as_bytes(), self.masterkey.obcrypt_key())?;

                // Append the XOR'd marker (oboron protocol framing).
                let marker = $scheme.marker();
                let first_byte = ciphertext[0];
                ciphertext.push(marker[0] ^ first_byte);
                ciphertext.push(marker[1] ^ first_byte);

                // Encode - compile-time dispatch
                Ok(encode_bytes(&ciphertext, $encoding))
            }

            #[inline(always)]
            fn dec(&self, obtext: &str) -> Result<String, Error> {
                // Decode
                let mut buffer = decode_bytes(obtext, $encoding)?;

                if buffer.len() < 2 {
                    return Err(Error::PayloadTooShort);
                }

                // XOR and extract marker
                let len = buffer.len();
                let first_byte = buffer[0];
                let scheme_marker = [buffer[len - 2] ^ first_byte, buffer[len - 1] ^ first_byte];

                // Validate marker
                if scheme_marker != $scheme.marker() {
                    return Err(Error::SchemeMarkerMismatch);
                }

                buffer.truncate(len - 2);

                // Decrypt directly (obcrypt scheme module, no marker framing here).
                let plaintext_bytes = $decrypt_fn(&buffer, self.masterkey.obcrypt_key())?;

                // Convert to string
                #[cfg(feature = "unchecked-utf8")]
                {
                    Ok(unsafe { String::from_utf8_unchecked(plaintext_bytes) })
                }
                #[cfg(not(feature = "unchecked-utf8"))]
                {
                    String::from_utf8(plaintext_bytes).map_err(|_| Error::InvalidUtf8)
                }
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

// aags variants (32-byte key)
#[cfg(feature = "aags")]
impl_codec_32!(
    AagsC32,
    Scheme::Aags,
    Encoding::C32,
    "aags. c32",
    obcrypt::schemes::aags::encrypt,
    obcrypt::schemes::aags::decrypt,
    aags
);
#[cfg(feature = "aags")]
impl_codec_32!(
    AagsB32,
    Scheme::Aags,
    Encoding::B32,
    "aags. b32",
    obcrypt::schemes::aags::encrypt,
    obcrypt::schemes::aags::decrypt,
    aags
);
#[cfg(feature = "aags")]
impl_codec_32!(
    AagsB64,
    Scheme::Aags,
    Encoding::B64,
    "aags.b64",
    obcrypt::schemes::aags::encrypt,
    obcrypt::schemes::aags::decrypt,
    aags
);
#[cfg(feature = "aags")]
impl_codec_32!(
    AagsHex,
    Scheme::Aags,
    Encoding::Hex,
    "aags.hex",
    obcrypt::schemes::aags::encrypt,
    obcrypt::schemes::aags::decrypt,
    aags
);

// aasv variants (64-byte key)
#[cfg(feature = "aasv")]
impl_codec_64!(
    AasvC32,
    Scheme::Aasv,
    Encoding::C32,
    "aasv.c32",
    obcrypt::schemes::aasv::encrypt,
    obcrypt::schemes::aasv::decrypt,
    aasv
);
#[cfg(feature = "aasv")]
impl_codec_64!(
    AasvB32,
    Scheme::Aasv,
    Encoding::B32,
    "aasv.b32",
    obcrypt::schemes::aasv::encrypt,
    obcrypt::schemes::aasv::decrypt,
    aasv
);
#[cfg(feature = "aasv")]
impl_codec_64!(
    AasvB64,
    Scheme::Aasv,
    Encoding::B64,
    "aasv.b64",
    obcrypt::schemes::aasv::encrypt,
    obcrypt::schemes::aasv::decrypt,
    aasv
);
#[cfg(feature = "aasv")]
impl_codec_64!(
    AasvHex,
    Scheme::Aasv,
    Encoding::Hex,
    "aasv.hex",
    obcrypt::schemes::aasv::encrypt,
    obcrypt::schemes::aasv::decrypt,
    aasv
);

// apgs variants (32-byte key)
#[cfg(feature = "apgs")]
impl_codec_32!(
    ApgsC32,
    Scheme::Apgs,
    Encoding::C32,
    "apgs.c32",
    obcrypt::schemes::apgs::encrypt,
    obcrypt::schemes::apgs::decrypt,
    apgs
);
#[cfg(feature = "apgs")]
impl_codec_32!(
    ApgsB32,
    Scheme::Apgs,
    Encoding::B32,
    "apgs.b32",
    obcrypt::schemes::apgs::encrypt,
    obcrypt::schemes::apgs::decrypt,
    apgs
);
#[cfg(feature = "apgs")]
impl_codec_32!(
    ApgsB64,
    Scheme::Apgs,
    Encoding::B64,
    "apgs.b64",
    obcrypt::schemes::apgs::encrypt,
    obcrypt::schemes::apgs::decrypt,
    apgs
);
#[cfg(feature = "apgs")]
impl_codec_32!(
    ApgsHex,
    Scheme::Apgs,
    Encoding::Hex,
    "apgs.hex",
    obcrypt::schemes::apgs::encrypt,
    obcrypt::schemes::apgs::decrypt,
    apgs
);

// apsv variants (64-byte key)
#[cfg(feature = "apsv")]
impl_codec_64!(
    ApsvC32,
    Scheme::Apsv,
    Encoding::C32,
    "apsv.c32",
    obcrypt::schemes::apsv::encrypt,
    obcrypt::schemes::apsv::decrypt,
    apsv
);
#[cfg(feature = "apsv")]
impl_codec_64!(
    ApsvB32,
    Scheme::Apsv,
    Encoding::B32,
    "apsv.b32",
    obcrypt::schemes::apsv::encrypt,
    obcrypt::schemes::apsv::decrypt,
    apsv
);
#[cfg(feature = "apsv")]
impl_codec_64!(
    ApsvB64,
    Scheme::Apsv,
    Encoding::B64,
    "apsv.b64",
    obcrypt::schemes::apsv::encrypt,
    obcrypt::schemes::apsv::decrypt,
    apsv
);
#[cfg(feature = "apsv")]
impl_codec_64!(
    ApsvHex,
    Scheme::Apsv,
    Encoding::Hex,
    "apsv.hex",
    obcrypt::schemes::apsv::encrypt,
    obcrypt::schemes::apsv::decrypt,
    apsv
);

// upbc variants (32-byte key)
#[cfg(feature = "upbc")]
impl_codec_32!(
    UpbcC32,
    Scheme::Upbc,
    Encoding::C32,
    "upbc.c32",
    obcrypt::schemes::upbc::encrypt,
    obcrypt::schemes::upbc::decrypt,
    upbc
);
#[cfg(feature = "upbc")]
impl_codec_32!(
    UpbcB32,
    Scheme::Upbc,
    Encoding::B32,
    "upbc.b32",
    obcrypt::schemes::upbc::encrypt,
    obcrypt::schemes::upbc::decrypt,
    upbc
);
#[cfg(feature = "upbc")]
impl_codec_32!(
    UpbcB64,
    Scheme::Upbc,
    Encoding::B64,
    "upbc.b64",
    obcrypt::schemes::upbc::encrypt,
    obcrypt::schemes::upbc::decrypt,
    upbc
);
#[cfg(feature = "upbc")]
impl_codec_32!(
    UpbcHex,
    Scheme::Upbc,
    Encoding::Hex,
    "upbc.hex",
    obcrypt::schemes::upbc::encrypt,
    obcrypt::schemes::upbc::decrypt,
    upbc
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
    #[cfg(feature = "aags")]
    AagsC32(AagsC32),
    #[cfg(feature = "aags")]
    AagsB32(AagsB32),
    #[cfg(feature = "aags")]
    AagsB64(AagsB64),
    #[cfg(feature = "aags")]
    AagsHex(AagsHex),
    #[cfg(feature = "apgs")]
    ApgsC32(ApgsC32),
    #[cfg(feature = "apgs")]
    ApgsB32(ApgsB32),
    #[cfg(feature = "apgs")]
    ApgsB64(ApgsB64),
    #[cfg(feature = "apgs")]
    ApgsHex(ApgsHex),
    #[cfg(feature = "aasv")]
    AasvC32(AasvC32),
    #[cfg(feature = "aasv")]
    AasvB32(AasvB32),
    #[cfg(feature = "aasv")]
    AasvB64(AasvB64),
    #[cfg(feature = "aasv")]
    AasvHex(AasvHex),
    #[cfg(feature = "apsv")]
    ApsvC32(ApsvC32),
    #[cfg(feature = "apsv")]
    ApsvB32(ApsvB32),
    #[cfg(feature = "apsv")]
    ApsvB64(ApsvB64),
    #[cfg(feature = "apsv")]
    ApsvHex(ApsvHex),
    #[cfg(feature = "upbc")]
    UpbcC32(UpbcC32),
    #[cfg(feature = "upbc")]
    UpbcB32(UpbcB32),
    #[cfg(feature = "upbc")]
    UpbcB64(UpbcB64),
    #[cfg(feature = "upbc")]
    UpbcHex(UpbcHex),
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
                #[cfg(feature = "aags")]
                ObAny::AagsC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "aags")]
                ObAny::AagsB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "aags")]
                ObAny::AagsB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "aags")]
                ObAny::AagsHex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apgs")]
                ObAny::ApgsC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apgs")]
                ObAny::ApgsB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apgs")]
                ObAny::ApgsB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apgs")]
                ObAny::ApgsHex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "aasv")]
                ObAny::AasvC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "aasv")]
                ObAny::AasvB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "aasv")]
                ObAny::AasvB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "aasv")]
                ObAny::AasvHex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apsv")]
                ObAny::ApsvC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apsv")]
                ObAny::ApsvB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apsv")]
                ObAny::ApsvB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "apsv")]
                ObAny::ApsvHex(ob) => ob.$method($($arg),*),
                #[cfg(feature = "upbc")]
                ObAny::UpbcC32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "upbc")]
                ObAny::UpbcB32(ob) => ob.$method($($arg),*),
                #[cfg(feature = "upbc")]
                ObAny::UpbcB64(ob) => ob.$method($($arg),*),
                #[cfg(feature = "upbc")]
                ObAny::UpbcHex(ob) => ob.$method($($arg),*),
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
    /// Defaults to mock1.c32 format.
    pub fn new(key: &str) -> Result<Self, Error> {
        #[cfg(feature = "mock")]
        return Ok(ObAny::Mock1C32(Mock1C32::new(key)?));
        #[cfg(feature = "upbc")]
        #[cfg(not(any(feature = "mock")))]
        return Ok(ObAny::UpbcC32(UpbcC32::new(key)?));
        #[cfg(feature = "aags")]
        #[cfg(not(any(feature = "mock", feature = "upbc")))]
        return Ok(ObAny::AagsC32(AagsC32::new(key)?));
        #[cfg(feature = "apgs")]
        #[cfg(not(any(feature = "mock", feature = "upbc", feature = "aags")))]
        return Ok(ObAny::ApgsC32(ApgsC32::new(key)?));
        #[cfg(feature = "aasv")]
        #[cfg(not(any(feature = "mock", feature = "upbc", feature = "aags", feature = "apgs")))]
        return Ok(ObAny::AasvC32(AasvC32::new(key)?));
        #[cfg(feature = "apsv")]
        #[cfg(not(any(
            feature = "mock",
            feature = "upbc",
            feature = "aags",
            feature = "apgs",
            feature = "aasv"
        )))]
        return Ok(ObAny::ApsvC32(ApsvC32::new(key)?));
        #[cfg(not(any(
            feature = "mock",
            feature = "upbc",
            feature = "aags",
            feature = "apgs",
            feature = "aasv",
            feature = "apsv",
        )))]
        compile_error!("At least one oboron scheme must be enabled");
    }

    /// Create a new instance from a 64-byte key.
    ///
    /// Defaults to mock1.c32 format.
    #[inline]
    pub fn from_bytes(key_bytes: &[u8; 64]) -> Result<Self, Error> {
        #[cfg(feature = "mock")]
        return Ok(ObAny::Mock1C32(Mock1C32 {
            masterkey: MasterKey::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "upbc")]
        #[cfg(not(any(feature = "mock")))]
        return Ok(ObAny::UpbcC32(UpbcC32 {
            masterkey: MasterKey::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "aags")]
        #[cfg(not(any(feature = "mock", feature = "upbc")))]
        return Ok(ObAny::AagsC32(AagsC32 {
            masterkey: MasterKey::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "apgs")]
        #[cfg(not(any(feature = "mock", feature = "upbc", feature = "aags")))]
        return Ok(ObAny::ApgsC32(ApgsC32 {
            masterkey: MasterKey::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "aasv")]
        #[cfg(not(any(feature = "mock", feature = "upbc", feature = "aags", feature = "apgs")))]
        return Ok(ObAny::AasvC32(AasvC32 {
            masterkey: MasterKey::from_bytes(key_bytes)?,
        }));
        #[cfg(feature = "apsv")]
        #[cfg(not(any(
            feature = "aags",
            feature = "aasv",
            feature = "apgs",
            feature = "mock",
            feature = "upbc",
        )))]
        return Ok(ObAny::ApsvC32(ApsvC32 {
            masterkey: MasterKey::from_bytes(key_bytes)?,
        }));
        #[cfg(not(any(
            feature = "aags",
            feature = "aasv",
            feature = "apgs",
            feature = "apsv",
            feature = "mock",
            feature = "upbc",
        )))]
        compile_error!("At least one oboron scheme must be enabled");
    }

    pub fn from_hex_key(key_hex: &str) -> Result<Self, Error> {
        #[cfg(feature = "mock")]
        return Ok(ObAny::Mock1C32(Mock1C32::from_hex_key(key_hex)?));
        #[cfg(feature = "upbc")]
        #[cfg(not(any(feature = "mock")))]
        return Ok(ObAny::UpbcC32(UpbcC32::from_hex_key(key_hex)?));
        #[cfg(feature = "aags")]
        #[cfg(not(any(feature = "mock", feature = "upbc")))]
        return Ok(ObAny::AagsC32(AagsC32::from_hex_key(key_hex)?));
        #[cfg(feature = "apgs")]
        #[cfg(not(any(feature = "mock", feature = "upbc", feature = "aags")))]
        return Ok(ObAny::ApgsC32(ApgsC32::from_hex_key(key_hex)?));
        #[cfg(feature = "aasv")]
        #[cfg(not(any(feature = "mock", feature = "upbc", feature = "aags", feature = "apgs")))]
        return Ok(ObAny::AasvC32(AasvC32::from_hex_key(key_hex)?));
        #[cfg(feature = "apsv")]
        #[cfg(not(any(
            feature = "mock",
            feature = "upbc",
            feature = "aags",
            feature = "apgs",
            feature = "aasv"
        )))]
        return Ok(ObAny::ApsvC32(ApsvC32::from_hex_key(key_hex)?));
        #[cfg(not(any(
            feature = "mock",
            feature = "upbc",
            feature = "aags",
            feature = "apgs",
            feature = "aasv",
            feature = "apsv",
        )))]
        compile_error!("At least one oboron scheme must be enabled");
    }

    /// Create a new instance with hardcoded key (testing only).
    ///
    /// Defaults to mock1.c32 format.
    #[cfg(feature = "keyless")]
    pub fn new_keyless() -> Result<Self, Error> {
        #[cfg(feature = "mock")]
        return Ok(ObAny::Mock1C32(Mock1C32 {
            masterkey: MasterKey::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "upbc")]
        #[cfg(not(any(feature = "mock")))]
        return Ok(ObAny::UpbcC32(UpbcC32 {
            masterkey: MasterKey::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "aags")]
        #[cfg(not(any(feature = "mock", feature = "upbc")))]
        return Ok(ObAny::AagsC32(AagsC32 {
            masterkey: MasterKey::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "apgs")]
        #[cfg(not(any(feature = "mock", feature = "upbc", feature = "aags")))]
        return Ok(ObAny::ApgsC32(ApgsC32 {
            masterkey: MasterKey::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "aasv")]
        #[cfg(not(any(feature = "mock", feature = "upbc", feature = "aags", feature = "apgs")))]
        return Ok(ObAny::AasvC32(AasvC32 {
            masterkey: MasterKey::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(feature = "apsv")]
        #[cfg(not(any(
            feature = "mock",
            feature = "upbc",
            feature = "aags",
            feature = "apgs",
            feature = "aasv"
        )))]
        return Ok(ObAny::ApsvC32(ApsvC32 {
            masterkey: MasterKey::from_bytes(&HARDCODED_KEY_BYTES)?,
        }));
        #[cfg(not(any(
            feature = "mock",
            feature = "upbc",
            feature = "aags",
            feature = "apgs",
            feature = "aasv",
            feature = "apsv",
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
        #[cfg(feature = "upbc")]
        (Scheme::Upbc, Encoding::C32) => Ok(ObAny::UpbcC32(UpbcC32::new(key)?)),
        #[cfg(feature = "upbc")]
        (Scheme::Upbc, Encoding::B32) => Ok(ObAny::UpbcB32(UpbcB32::new(key)?)),
        #[cfg(feature = "upbc")]
        (Scheme::Upbc, Encoding::B64) => Ok(ObAny::UpbcB64(UpbcB64::new(key)?)),
        #[cfg(feature = "upbc")]
        (Scheme::Upbc, Encoding::Hex) => Ok(ObAny::UpbcHex(UpbcHex::new(key)?)),
        #[cfg(feature = "aags")]
        (Scheme::Aags, Encoding::C32) => Ok(ObAny::AagsC32(AagsC32::new(key)?)),
        #[cfg(feature = "aags")]
        (Scheme::Aags, Encoding::B32) => Ok(ObAny::AagsB32(AagsB32::new(key)?)),
        #[cfg(feature = "aags")]
        (Scheme::Aags, Encoding::B64) => Ok(ObAny::AagsB64(AagsB64::new(key)?)),
        #[cfg(feature = "aags")]
        (Scheme::Aags, Encoding::Hex) => Ok(ObAny::AagsHex(AagsHex::new(key)?)),
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::C32) => Ok(ObAny::ApgsC32(ApgsC32::new(key)?)),
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::B32) => Ok(ObAny::ApgsB32(ApgsB32::new(key)?)),
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::B64) => Ok(ObAny::ApgsB64(ApgsB64::new(key)?)),
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::Hex) => Ok(ObAny::ApgsHex(ApgsHex::new(key)?)),
        #[cfg(feature = "aasv")]
        (Scheme::Aasv, Encoding::C32) => Ok(ObAny::AasvC32(AasvC32::new(key)?)),
        #[cfg(feature = "aasv")]
        (Scheme::Aasv, Encoding::B32) => Ok(ObAny::AasvB32(AasvB32::new(key)?)),
        #[cfg(feature = "aasv")]
        (Scheme::Aasv, Encoding::B64) => Ok(ObAny::AasvB64(AasvB64::new(key)?)),
        #[cfg(feature = "aasv")]
        (Scheme::Aasv, Encoding::Hex) => Ok(ObAny::AasvHex(AasvHex::new(key)?)),
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::C32) => Ok(ObAny::ApsvC32(ApsvC32::new(key)?)),
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::B32) => Ok(ObAny::ApsvB32(ApsvB32::new(key)?)),
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::B64) => Ok(ObAny::ApsvB64(ApsvB64::new(key)?)),
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::Hex) => Ok(ObAny::ApsvHex(ApsvHex::new(key)?)),
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
        #[cfg(feature = "upbc")]
        (Scheme::Upbc, Encoding::C32) => {
            Ok(ObAny::UpbcC32(UpbcC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "upbc")]
        (Scheme::Upbc, Encoding::B32) => {
            Ok(ObAny::UpbcB32(UpbcB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "upbc")]
        (Scheme::Upbc, Encoding::B64) => {
            Ok(ObAny::UpbcB64(UpbcB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "upbc")]
        (Scheme::Upbc, Encoding::Hex) => {
            Ok(ObAny::UpbcHex(UpbcHex::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "aags")]
        (Scheme::Aags, Encoding::C32) => {
            Ok(ObAny::AagsC32(AagsC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "aags")]
        (Scheme::Aags, Encoding::B32) => {
            Ok(ObAny::AagsB32(AagsB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "aags")]
        (Scheme::Aags, Encoding::B64) => {
            Ok(ObAny::AagsB64(AagsB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "aags")]
        (Scheme::Aags, Encoding::Hex) => {
            Ok(ObAny::AagsHex(AagsHex::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::C32) => {
            Ok(ObAny::ApgsC32(ApgsC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::B32) => {
            Ok(ObAny::ApgsB32(ApgsB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::B64) => {
            Ok(ObAny::ApgsB64(ApgsB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apgs")]
        (Scheme::Apgs, Encoding::Hex) => {
            Ok(ObAny::ApgsHex(ApgsHex::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "aasv")]
        (Scheme::Aasv, Encoding::C32) => {
            Ok(ObAny::AasvC32(AasvC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "aasv")]
        (Scheme::Aasv, Encoding::B32) => {
            Ok(ObAny::AasvB32(AasvB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "aasv")]
        (Scheme::Aasv, Encoding::B64) => {
            Ok(ObAny::AasvB64(AasvB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "aasv")]
        (Scheme::Aasv, Encoding::Hex) => {
            Ok(ObAny::AasvHex(AasvHex::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::C32) => {
            Ok(ObAny::ApsvC32(ApsvC32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::B32) => {
            Ok(ObAny::ApsvB32(ApsvB32::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::B64) => {
            Ok(ObAny::ApsvB64(ApsvB64::from_bytes_internal(key_bytes)?))
        }
        #[cfg(feature = "apsv")]
        (Scheme::Apsv, Encoding::Hex) => {
            Ok(ObAny::ApsvHex(ApsvHex::from_bytes_internal(key_bytes)?))
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

/// Deprecated alias for [`from_hex_key`].
///
/// Kept for migration from any in-development 0.9.x preview;
/// canonical pattern is `from_<format>_<target>`.
#[deprecated(
    since = "0.9.0",
    note = "use from_hex_key instead — standard from_<format>_<target> pattern"
)]
pub fn from_key_hex(fmt: &str, key_hex: &str) -> Result<ObAny, Error> {
    from_hex_key(fmt, key_hex)
}

/// Deprecated alias for [`from_hex_key_with_format`].
#[deprecated(
    since = "0.9.0",
    note = "use from_hex_key_with_format instead — standard from_<format>_<target> pattern"
)]
pub fn from_key_hex_with_format(format: Format, key_hex: &str) -> Result<ObAny, Error> {
    from_hex_key_with_format(format, key_hex)
}

/// Create an encoder from a format string and raw bytes.
pub fn from_bytes(fmt: &str, key_bytes: &[u8; 64]) -> Result<ObAny, Error> {
    let format = Format::from_str(fmt)?;
    from_bytes_with_format_internal(format, &key_bytes)
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
            #[cfg(feature = "upbc")]
            Scheme::Upbc,
            #[cfg(feature = "aags")]
            Scheme::Aags,
            #[cfg(feature = "apgs")]
            Scheme::Apgs,
            #[cfg(feature = "aasv")]
            Scheme::Aasv,
            #[cfg(feature = "apsv")]
            Scheme::Apsv,
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

        // Define all schemes
        let schemes = vec![
            Scheme::Mock2,
            Scheme::Mock1,
            #[cfg(feature = "upbc")]
            Scheme::Upbc,
            #[cfg(feature = "aags")]
            Scheme::Aags,
            #[cfg(feature = "apgs")]
            Scheme::Apgs,
            #[cfg(feature = "aasv")]
            Scheme::Aasv,
            #[cfg(feature = "apsv")]
            Scheme::Apsv,
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

        // Define all schemes
        let schemes = vec![
            Scheme::Mock2,
            Scheme::Mock1,
            #[cfg(feature = "aags")]
            Scheme::Aags,
            #[cfg(feature = "aasv")]
            Scheme::Aasv,
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
        let aasv = AasvC32::new(&key).unwrap();

        // generate_key() returns 128-char hex; aasv.key() returns hex.
        let retrieved_key = aasv.key();
        assert_eq!(retrieved_key, key);
        assert_eq!(retrieved_key.len(), 128);

        // key_hex() is the canonical accessor.
        let key_hex = aasv.key_hex();
        assert_eq!(key_hex.len(), 128);

        #[cfg(feature = "base64-keys")]
        {
            #[allow(deprecated)]
            let key_b64 = aasv.key_base64();
            assert_eq!(key_b64.len(), 86);
        }

        let key_bytes = aasv.key_bytes();
        assert_eq!(key_bytes.len(), 64);
    }
}
