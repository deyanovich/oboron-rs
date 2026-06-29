//! WebAssembly / JavaScript bindings for `oboron` via wasm-bindgen.
//!
//! Compiled to wasm and packaged for npm with `wasm-pack`, this crate
//! exposes oboron's string-in / string-out symmetric encryption +
//! encoding to JS. It mirrors the `oboron-py` surface: free functions,
//! one codec class per scheme+encoding, and the runtime-flexible `Ob` /
//! `Omnib`.
//!
//! JS-facing names are camelCase (`generateKey`, `keyBytes`,
//! `setFormat`); the Rust identifiers stay snake_case. Plaintext and
//! obtext are JS strings; raw key material maps to `Uint8Array`. Keys
//! are 128-character hex strings — the canonical oboron form. See the
//! project README for usage.
//!
//! Errors are thrown as JS `Error`s whose message is the underlying
//! `oboron::Error` description (e.g. `"invalid key length"`,
//! `"unknown scheme"`, `"decryption failed"`).

use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Module-level functions
// ---------------------------------------------------------------------------

/// The oboron-wasm package version (matches `package.json`).
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Generate a fresh random 64-byte key, returned as a 128-character
/// lowercase hex string — the canonical oboron key form, suitable for
/// env vars, config files, and codec / function `key` arguments.
///
/// For the raw 64-byte form (byte-native crypto interop, custom
/// storage), use `generateKeyBytes()`.
#[wasm_bindgen(js_name = generateKey)]
pub fn generate_key() -> String {
    oboron::generate_key()
}

/// Generate a fresh random 64-byte key, returned as a `Uint8Array`.
///
/// Provided for interop with byte-native APIs and custom storage
/// formats. For the canonical hex form used everywhere else, use
/// `generateKey()`.
#[wasm_bindgen(js_name = generateKeyBytes)]
pub fn generate_key_bytes() -> Vec<u8> {
    oboron::generate_key_bytes().to_vec()
}

/// Encrypt + encode `plaintext` under `format` (e.g. `"dsiv.b64"`)
/// using `key` (128-character hex). Convenience wrapper around
/// `Omnib`; for repeated calls, construct an `Omnib` once and reuse it.
#[wasm_bindgen]
pub fn enc(plaintext: &str, format: &str, key: &str) -> Result<String, JsError> {
    oboron::enc(plaintext, format, key).map_err(JsError::from)
}

/// Decode + decrypt `obtext` under `format` using `key`.
#[wasm_bindgen]
pub fn dec(obtext: &str, format: &str, key: &str) -> Result<String, JsError> {
    oboron::dec(obtext, format, key).map_err(JsError::from)
}

/// Encrypt + encode `plaintext` under `format` with the publicly
/// hardcoded key (testing / obfuscation only — provides no security).
#[cfg(feature = "keyless")]
#[wasm_bindgen(js_name = encKeyless)]
pub fn enc_keyless(plaintext: &str, format: &str) -> Result<String, JsError> {
    oboron::enc_keyless(plaintext, format).map_err(JsError::from)
}

/// Decode + decrypt `obtext` under `format` with the publicly
/// hardcoded key.
#[cfg(feature = "keyless")]
#[wasm_bindgen(js_name = decKeyless)]
pub fn dec_keyless(obtext: &str, format: &str) -> Result<String, JsError> {
    oboron::dec_keyless(obtext, format).map_err(JsError::from)
}

// ---------------------------------------------------------------------------
// Fixed-format codec classes (64-byte key)
// ---------------------------------------------------------------------------

/// Generate a JS codec class wrapping a fixed-format codec from the
/// oboron core. Each instance binds a key + scheme + encoding; the
/// constructor takes the canonical 128-character hex key. The `keyless`
/// static factory mirrors the core's `new_keyless` constructor.
macro_rules! impl_codec_class {
    ($name:ident, $rust_type:ty, $feature:literal, $doc:literal) => {
        #[cfg(feature = $feature)]
        #[doc = $doc]
        #[wasm_bindgen]
        pub struct $name {
            inner: $rust_type,
        }

        #[cfg(feature = $feature)]
        #[wasm_bindgen]
        impl $name {
            /// Construct from a 128-character hex key (canonical oboron
            /// form).
            #[wasm_bindgen(constructor)]
            pub fn new(key: &str) -> Result<$name, JsError> {
                Ok(Self {
                    inner: <$rust_type>::new(key).map_err(JsError::from)?,
                })
            }

            /// Construct with the publicly hardcoded key (testing /
            /// obfuscation only — provides no security).
            #[cfg(feature = "keyless")]
            pub fn keyless() -> Result<$name, JsError> {
                Ok(Self {
                    inner: <$rust_type>::new_keyless().map_err(JsError::from)?,
                })
            }

            /// Encrypt + encode `plaintext` to an obtext string.
            pub fn enc(&self, plaintext: &str) -> Result<String, JsError> {
                self.inner.enc(plaintext).map_err(JsError::from)
            }

            /// Decode + decrypt an obtext string back to plaintext.
            pub fn dec(&self, obtext: &str) -> Result<String, JsError> {
                self.inner.dec(obtext).map_err(JsError::from)
            }

            /// The format string bound to this codec, e.g. `"dsiv.c32"`.
            #[wasm_bindgen(getter)]
            pub fn format(&self) -> String {
                self.inner.format().to_string()
            }

            /// The scheme name bound to this codec, e.g. `"dsiv"`.
            #[wasm_bindgen(getter)]
            pub fn scheme(&self) -> String {
                self.inner.scheme().to_string()
            }

            /// The encoding name bound to this codec, e.g. `"c32"`.
            #[wasm_bindgen(getter)]
            pub fn encoding(&self) -> String {
                self.inner.encoding().to_string()
            }

            /// The 128-character hex key (canonical oboron form).
            #[wasm_bindgen(getter)]
            pub fn key(&self) -> String {
                self.inner.key()
            }

            /// The key as a 128-character hex string (alias for `key`).
            #[wasm_bindgen(getter, js_name = keyHex)]
            pub fn key_hex(&self) -> String {
                self.inner.key_hex()
            }

            /// The raw 64-byte key material as a `Uint8Array`. Provided
            /// for byte-native interop; the canonical form everywhere
            /// else is `key` (hex).
            #[wasm_bindgen(getter, js_name = keyBytes)]
            pub fn key_bytes(&self) -> Vec<u8> {
                self.inner.key_bytes().to_vec()
            }
        }
    };
}

// Dgcmsiv variants (deterministic AES-GCM-SIV)
impl_codec_class!(
    DgcmsivB32,
    ::oboron::DgcmsivB32,
    "dgcmsiv",
    "Dgcmsiv codec (deterministic AES-GCM-SIV) with B32 encoding."
);
impl_codec_class!(
    DgcmsivB64,
    ::oboron::DgcmsivB64,
    "dgcmsiv",
    "Dgcmsiv codec (deterministic AES-GCM-SIV) with B64 encoding."
);
impl_codec_class!(
    DgcmsivC32,
    ::oboron::DgcmsivC32,
    "dgcmsiv",
    "Dgcmsiv codec (deterministic AES-GCM-SIV) with C32 encoding."
);
impl_codec_class!(
    DgcmsivHex,
    ::oboron::DgcmsivHex,
    "dgcmsiv",
    "Dgcmsiv codec (deterministic AES-GCM-SIV) with Hex encoding."
);

// Dsiv variants (deterministic AES-SIV, nonce-misuse resistant)
impl_codec_class!(
    DsivB32,
    ::oboron::DsivB32,
    "dsiv",
    "Dsiv codec (deterministic AES-SIV, nonce-misuse resistant) with B32 encoding."
);
impl_codec_class!(
    DsivB64,
    ::oboron::DsivB64,
    "dsiv",
    "Dsiv codec (deterministic AES-SIV, nonce-misuse resistant) with B64 encoding."
);
impl_codec_class!(
    DsivC32,
    ::oboron::DsivC32,
    "dsiv",
    "Dsiv codec (deterministic AES-SIV, nonce-misuse resistant) with C32 encoding."
);
impl_codec_class!(
    DsivHex,
    ::oboron::DsivHex,
    "dsiv",
    "Dsiv codec (deterministic AES-SIV, nonce-misuse resistant) with Hex encoding."
);

// Pgcmsiv variants (probabilistic AES-GCM-SIV)
impl_codec_class!(
    PgcmsivB32,
    ::oboron::PgcmsivB32,
    "pgcmsiv",
    "Pgcmsiv codec (probabilistic AES-GCM-SIV) with B32 encoding."
);
impl_codec_class!(
    PgcmsivB64,
    ::oboron::PgcmsivB64,
    "pgcmsiv",
    "Pgcmsiv codec (probabilistic AES-GCM-SIV) with B64 encoding."
);
impl_codec_class!(
    PgcmsivC32,
    ::oboron::PgcmsivC32,
    "pgcmsiv",
    "Pgcmsiv codec (probabilistic AES-GCM-SIV) with C32 encoding."
);
impl_codec_class!(
    PgcmsivHex,
    ::oboron::PgcmsivHex,
    "pgcmsiv",
    "Pgcmsiv codec (probabilistic AES-GCM-SIV) with Hex encoding."
);

// Psiv variants (probabilistic AES-SIV)
impl_codec_class!(
    PsivB32,
    ::oboron::PsivB32,
    "psiv",
    "Psiv codec (probabilistic AES-SIV) with B32 encoding."
);
impl_codec_class!(
    PsivB64,
    ::oboron::PsivB64,
    "psiv",
    "Psiv codec (probabilistic AES-SIV) with B64 encoding."
);
impl_codec_class!(
    PsivC32,
    ::oboron::PsivC32,
    "psiv",
    "Psiv codec (probabilistic AES-SIV) with C32 encoding."
);
impl_codec_class!(
    PsivHex,
    ::oboron::PsivHex,
    "psiv",
    "Psiv codec (probabilistic AES-SIV) with Hex encoding."
);

// Mock1 variants (testing — identity scheme, no encryption)
impl_codec_class!(
    Mock1B32,
    ::oboron::Mock1B32,
    "mock",
    "Mock1 codec (identity scheme, for testing) with B32 encoding."
);
impl_codec_class!(
    Mock1B64,
    ::oboron::Mock1B64,
    "mock",
    "Mock1 codec (identity scheme, for testing) with B64 encoding."
);
impl_codec_class!(
    Mock1C32,
    ::oboron::Mock1C32,
    "mock",
    "Mock1 codec (identity scheme, for testing) with C32 encoding."
);
impl_codec_class!(
    Mock1Hex,
    ::oboron::Mock1Hex,
    "mock",
    "Mock1 codec (identity scheme, for testing) with Hex encoding."
);

// Mock2 variants (testing — reverse-plaintext scheme, no encryption)
impl_codec_class!(
    Mock2B32,
    ::oboron::Mock2B32,
    "mock",
    "Mock2 codec (reverse-plaintext scheme, for testing) with B32 encoding."
);
impl_codec_class!(
    Mock2B64,
    ::oboron::Mock2B64,
    "mock",
    "Mock2 codec (reverse-plaintext scheme, for testing) with B64 encoding."
);
impl_codec_class!(
    Mock2C32,
    ::oboron::Mock2C32,
    "mock",
    "Mock2 codec (reverse-plaintext scheme, for testing) with C32 encoding."
);
impl_codec_class!(
    Mock2Hex,
    ::oboron::Mock2Hex,
    "mock",
    "Mock2 codec (reverse-plaintext scheme, for testing) with Hex encoding."
);

// ---------------------------------------------------------------------------
// Ob — runtime-mutable format selection
// ---------------------------------------------------------------------------

/// Flexible codec with runtime format selection. Wraps `oboron::Ob`
/// and lets you change the scheme / encoding after construction.
#[wasm_bindgen]
pub struct Ob {
    inner: ::oboron::Ob,
}

#[wasm_bindgen]
impl Ob {
    /// Construct with `format` (e.g. `"dsiv.c32"`) and a 128-character
    /// hex `key`.
    #[wasm_bindgen(constructor)]
    pub fn new(format: &str, key: &str) -> Result<Ob, JsError> {
        Ok(Self {
            inner: ::oboron::Ob::new(format, key).map_err(JsError::from)?,
        })
    }

    /// Construct with `format` and the publicly hardcoded key (testing
    /// / obfuscation only).
    #[cfg(feature = "keyless")]
    pub fn keyless(format: &str) -> Result<Ob, JsError> {
        Ok(Self {
            inner: ::oboron::Ob::new_keyless(format).map_err(JsError::from)?,
        })
    }

    /// Encrypt + encode `plaintext` to an obtext string.
    pub fn enc(&self, plaintext: &str) -> Result<String, JsError> {
        self.inner.enc(plaintext).map_err(JsError::from)
    }

    /// Decode + decrypt an obtext string back to plaintext.
    pub fn dec(&self, obtext: &str) -> Result<String, JsError> {
        self.inner.dec(obtext).map_err(JsError::from)
    }

    #[wasm_bindgen(getter)]
    pub fn format(&self) -> String {
        self.inner.format().to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn scheme(&self) -> String {
        self.inner.scheme().to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn encoding(&self) -> String {
        self.inner.encoding().to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn key(&self) -> String {
        self.inner.key()
    }

    #[wasm_bindgen(getter, js_name = keyHex)]
    pub fn key_hex(&self) -> String {
        self.inner.key_hex()
    }

    #[wasm_bindgen(getter, js_name = keyBytes)]
    pub fn key_bytes(&self) -> Vec<u8> {
        self.inner.key_bytes().to_vec()
    }

    /// Switch to a new format (scheme + encoding), e.g. `"psiv.hex"`.
    #[wasm_bindgen(js_name = setFormat)]
    pub fn set_format(&mut self, format: &str) -> Result<(), JsError> {
        self.inner.set_format(format).map_err(JsError::from)
    }

    /// Switch the scheme, keeping the current encoding.
    #[wasm_bindgen(js_name = setScheme)]
    pub fn set_scheme(&mut self, scheme: &str) -> Result<(), JsError> {
        let s = ::oboron::Scheme::from_str(scheme).map_err(JsError::from)?;
        self.inner.set_scheme(s).map_err(JsError::from)
    }

    /// Switch the encoding, keeping the current scheme.
    #[wasm_bindgen(js_name = setEncoding)]
    pub fn set_encoding(&mut self, encoding: &str) -> Result<(), JsError> {
        let e = ::oboron::Encoding::from_str(encoding).map_err(JsError::from)?;
        self.inner.set_encoding(e).map_err(JsError::from)
    }
}

// ---------------------------------------------------------------------------
// Omnib — multi-format codec
// ---------------------------------------------------------------------------

/// Multi-format codec — the format is supplied per `enc` / `dec` call.
#[wasm_bindgen]
pub struct Omnib {
    inner: ::oboron::Omnib,
}

#[wasm_bindgen]
impl Omnib {
    /// Construct from a 128-character hex `key`.
    #[wasm_bindgen(constructor)]
    pub fn new(key: &str) -> Result<Omnib, JsError> {
        Ok(Self {
            inner: ::oboron::Omnib::new(key).map_err(JsError::from)?,
        })
    }

    /// Construct with the publicly hardcoded key (testing /
    /// obfuscation only).
    #[cfg(feature = "keyless")]
    pub fn keyless() -> Result<Omnib, JsError> {
        Ok(Self {
            inner: ::oboron::Omnib::new_keyless().map_err(JsError::from)?,
        })
    }

    /// Encrypt + encode `plaintext` under `format` (e.g. `"dsiv.b64"`).
    pub fn enc(&self, plaintext: &str, format: &str) -> Result<String, JsError> {
        self.inner.enc(plaintext, format).map_err(JsError::from)
    }

    /// Decode + decrypt `obtext` under `format`.
    pub fn dec(&self, obtext: &str, format: &str) -> Result<String, JsError> {
        self.inner.dec(obtext, format).map_err(JsError::from)
    }

    #[wasm_bindgen(getter)]
    pub fn key(&self) -> String {
        self.inner.key()
    }

    #[wasm_bindgen(getter, js_name = keyHex)]
    pub fn key_hex(&self) -> String {
        self.inner.key_hex()
    }

    #[wasm_bindgen(getter, js_name = keyBytes)]
    pub fn key_bytes(&self) -> Vec<u8> {
        self.inner.key_bytes().to_vec()
    }
}
