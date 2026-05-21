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
            /// Create with a 43-character base64 secret string
            pub fn new(secret: &str) -> Result<Self, Error> {
                Ok(Self {
                    zsecret: ZSecret::from_base64(secret)?,
                })
            }

            /// Create with hardcoded secret (testing/obfuscation only)
            #[cfg(feature = "keyless")]
            pub fn new_keyless() -> Result<Self, Error> {
                Ok(Self {
                    zsecret: ZSecret::from_bytes(&HARDCODED_SECRET_BYTES)?,
                })
            }

            /// Create from a 64-character hex secret string
            pub fn from_hex_secret(secret_hex: &str) -> Result<Self, Error> {
                Ok(Self {
                    zsecret: ZSecret::from_hex(secret_hex)?,
                })
            }

            /// Create from a 32-byte secret
            pub fn from_bytes(secret_bytes: &[u8; 32]) -> Result<Self, Error> {
                Ok(Self {
                    zsecret: ZSecret::from_bytes(secret_bytes)?,
                })
            }

            #[inline]
            pub fn secret(&self) -> String {
                self.zsecret.secret_base64()
            }

            #[inline]
            pub fn secret_hex(&self) -> String {
                self.zsecret.secret_hex()
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
