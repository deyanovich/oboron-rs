//! Zrbcx codec implementations (z-tier, obfuscation-only)

#![cfg(any(feature = "zrbcx", feature = "mock"))]

use super::zsecret::ZSecret;
use crate::{
    constants::HARDCODED_SECRET_BYTES, error::Error, Encoding, Format, ObtextCodec, Scheme,
};

/// Macro to implement z-tier codec types (32-byte secrets, obfuscation-only)
macro_rules! impl_zcodec {
    ($name:ident, $scheme:expr, $encoding:expr, $format_str:expr) => {
        #[doc = concat!("**INSECURE OBFUSCATION-ONLY** Codec for ", $format_str, ".\n\n")]
        #[doc = "⚠️ This scheme provides no cryptographic security.\n"]
        #[doc = "Use only for obfuscation, never for actual encryption.\n\n"]
        #[doc = concat!("Format:   `\"", $format_str, "\"`")]
        #[allow(non_camel_case_types)]
        pub struct $name {
            zsecret: ZSecret,
        }

        impl $name {
            /// Create from a secret string. Length-routed: accepts
            /// either a 64-character hex secret (canonical) or a
            /// 43-character base64 secret (transitional, gated by
            /// the `base64-keys` feature).
            pub fn new(secret: &str) -> Result<Self, Error> {
                Ok(Self {
                    zsecret: ZSecret::from_string(secret)?,
                })
            }

            /// Create with hardcoded secret (testing/obfuscation only)
            #[cfg(feature = "keyless")]
            pub fn new_keyless() -> Result<Self, Error> {
                Ok(Self {
                    zsecret: ZSecret::from_bytes(&HARDCODED_SECRET_BYTES)?,
                })
            }

            /// Create from a 64-character hex secret string. Strict
            /// hex — rejects base64. Use [`Self::new`] for the
            /// length-routing entry point that accepts both.
            pub fn from_hex_secret(secret_hex: &str) -> Result<Self, Error> {
                Ok(Self {
                    zsecret: ZSecret::from_hex(secret_hex)?,
                })
            }

            /// Deprecated alias for [`Self::from_hex_secret`].
            ///
            /// Kept for migration from any in-development 0.9.x
            /// preview; canonical pattern is
            /// `from_<format>_<target>` (e.g. `from_hex_key`,
            /// `from_base64_secret`).
            #[deprecated(
                since = "0.9.0",
                note = "use from_hex_secret instead — standard from_<format>_<target> pattern"
            )]
            pub fn from_secret_hex(secret_hex: &str) -> Result<Self, Error> {
                Self::from_hex_secret(secret_hex)
            }

            /// Create from a 43-character base64 secret string.
            ///
            /// Deprecated: oboron is moving to hex-only secrets before
            /// v1.0. Use [`Self::from_hex_secret`] or [`Self::new`]
            /// (with a hex secret) instead.
            #[cfg(feature = "base64-keys")]
            #[deprecated(
                since = "0.9.0",
                note = "use from_hex_secret() / new() (hex) instead; base64 support will be removed before oboron 1.0"
            )]
            pub fn from_base64_secret(secret_base64: &str) -> Result<Self, Error> {
                Ok(Self {
                    zsecret: ZSecret::from_base64(secret_base64)?,
                })
            }

            /// Deprecated alias for [`Self::from_base64_secret`].
            ///
            /// The in-development 0.9.x preview used the
            /// target/format order; canonical pattern is
            /// `from_<format>_<target>`. Doubly deprecated: base64
            /// support itself is on the way out before oboron 1.0.
            #[cfg(feature = "base64-keys")]
            #[deprecated(
                since = "0.9.0",
                note = "use from_base64_secret (or from_hex_secret — base64 is going away)"
            )]
            pub fn from_secret_base64(secret_base64: &str) -> Result<Self, Error> {
                #[allow(deprecated)]
                Self::from_base64_secret(secret_base64)
            }

            /// Create from a 32-byte secret.
            pub fn from_bytes(secret_bytes: &[u8; 32]) -> Result<Self, Error> {
                Ok(Self {
                    zsecret: ZSecret::from_bytes(secret_bytes)?,
                })
            }

            /// The 64-character hex secret bound to this codec
            /// (canonical oboron form).
            #[inline]
            pub fn secret(&self) -> String {
                self.zsecret.secret_hex()
            }

            /// The secret as a 64-character hex string (alias for
            /// [`Self::secret`]).
            #[inline]
            pub fn secret_hex(&self) -> String {
                self.zsecret.secret_hex()
            }

            /// The secret as a 43-character base64 string.
            ///
            /// Deprecated: hex is canonical; this getter will be
            /// removed when the `base64-keys` gate goes away before
            /// oboron 1.0.
            #[cfg(feature = "base64-keys")]
            #[inline]
            pub fn secret_base64(&self) -> String {
                self.zsecret.secret_base64()
            }

            #[inline]
            pub fn secret_bytes(&self) -> &[u8; 32] {
                self.zsecret.secret_bytes()
            }

            /// Internal constructor from 64-byte key (uses first 32 bytes as secret)
            #[allow(dead_code)]
            pub(crate) fn from_bytes_internal(key_bytes: &[u8; 64]) -> Result<Self, Error> {
                let secret: [u8; 32] = key_bytes[0..32].try_into().unwrap();
                Ok(Self {
                    zsecret: ZSecret::from_bytes(&secret)?,
                })
            }
        }

        impl ObtextCodec for $name {
            fn enc(&self, plaintext: &str) -> Result<String, Error> {
                let format = Format::new($scheme, $encoding);
                crate::ztier::enc_to_format_ztier(plaintext, format, self.zsecret.master_secret())
            }

            fn dec(&self, obtext: &str) -> Result<String, Error> {
                let format = Format::new($scheme, $encoding);
                crate::ztier::dec_from_format_ztier(obtext, format, self.zsecret.master_secret())
            }

            fn format(&self) -> Format {
                Format::new($scheme, $encoding)
            }

            fn scheme(&self) -> Scheme {
                $scheme
            }

            fn encoding(&self) -> Encoding {
                $encoding
            }
        }

        // Inherent methods (same as before)
        impl $name {
            #[inline]
            pub fn enc(&self, plaintext: &str) -> Result<String, Error> {
                <Self as ObtextCodec>::enc(self, plaintext)
            }

            #[inline]
            pub fn dec(&self, obtext: &str) -> Result<String, Error> {
                <Self as ObtextCodec>::dec(self, obtext)
            }

            #[inline]
            pub fn format(&self) -> Format {
                <Self as ObtextCodec>::format(self)
            }

            #[inline]
            pub fn scheme(&self) -> Scheme {
                <Self as ObtextCodec>::scheme(self)
            }

            #[inline]
            pub fn encoding(&self) -> Encoding {
                <Self as ObtextCodec>::encoding(self)
            }
        }
    };
}

// Generate all zrbcx variants
#[cfg(feature = "zrbcx")]
impl_zcodec!(ZrbcxC32, Scheme::Zrbcx, Encoding::C32, "zrbcx.c32");
#[cfg(feature = "zrbcx")]
impl_zcodec!(ZrbcxB32, Scheme::Zrbcx, Encoding::B32, "zrbcx.b32");
#[cfg(feature = "zrbcx")]
impl_zcodec!(ZrbcxB64, Scheme::Zrbcx, Encoding::B64, "zrbcx.b64");
#[cfg(feature = "zrbcx")]
impl_zcodec!(ZrbcxHex, Scheme::Zrbcx, Encoding::Hex, "zrbcx.hex");

// Zmock1 variants (z-tier testing scheme)
#[cfg(feature = "mock")]
impl_zcodec!(Zmock1C32, Scheme::Zmock1, Encoding::C32, "zmock1.c32");
#[cfg(feature = "mock")]
impl_zcodec!(Zmock1B32, Scheme::Zmock1, Encoding::B32, "zmock1.b32");
#[cfg(feature = "mock")]
impl_zcodec!(Zmock1B64, Scheme::Zmock1, Encoding::B64, "zmock1.b64");
#[cfg(feature = "mock")]
impl_zcodec!(Zmock1Hex, Scheme::Zmock1, Encoding::Hex, "zmock1.hex");
