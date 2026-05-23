//! Python bindings for `oboron` via PyO3 / maturin.
//!
//! The Rust extension module `oboron._oboron`. The user-facing API
//! is the `oboron` Python package; `python/oboron/__init__.py`
//! re-exports from this module. See the project README for usage.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

// ---------------------------------------------------------------------------
// Exceptions
// ---------------------------------------------------------------------------

create_exception!(_oboron, OboronError, PyException);
create_exception!(_oboron, InvalidKey, OboronError);
create_exception!(_oboron, InvalidFormat, OboronError);
create_exception!(_oboron, EncryptionFailed, OboronError);
create_exception!(_oboron, DecryptionFailed, OboronError);

/// Map an `oboron::Error` to the closest custom Python exception.
fn map_error(e: oboron::Error) -> PyErr {
    let msg = e.to_string();
    match e {
        // Key parsing / length problems all surface as InvalidKey. The
        // hex-decode error case is the most common cause when a caller
        // passes a malformed hex key.
        oboron::Error::InvalidKeyLength | oboron::Error::InvalidHex => InvalidKey::new_err(msg),

        // Format-string / scheme-name / encoding-name problems.
        oboron::Error::InvalidFormat
        | oboron::Error::InvalidScheme
        | oboron::Error::UnknownScheme
        | oboron::Error::UnknownEncoding => InvalidFormat::new_err(msg),

        // Encrypt-path failures.
        oboron::Error::EncryptionFailed | oboron::Error::EmptyPlaintext => {
            EncryptionFailed::new_err(msg)
        }

        // Decrypt-path failures — including obtext-decoding failures
        // (bad base32/64) and post-decrypt UTF-8 validation, which
        // happen on the dec side.
        oboron::Error::DecryptionFailed
        | oboron::Error::EmptyPayload
        | oboron::Error::PayloadTooShort
        | oboron::Error::InvalidBlockLength
        | oboron::Error::SchemeMarkerMismatch
        | oboron::Error::InvalidB64
        | oboron::Error::InvalidB32
        | oboron::Error::InvalidC32
        | oboron::Error::InvalidUtf8 => DecryptionFailed::new_err(msg),

        // `oboron::Error` is `#[non_exhaustive]` — future variants and
        // the `legacy`-gated `InvalidLegacyOutput` fall through here.
        _ => OboronError::new_err(msg),
    }
}

// ---------------------------------------------------------------------------
// Per-scheme codec classes (fixed format)
// ---------------------------------------------------------------------------

/// Generate a Python wrapper class for a fixed-format ObtextCodec
/// type from the oboron core. Each instance binds a key + scheme +
/// encoding; constructors accept the canonical 128-character hex key
/// (and, while `base64-keys` is on in the oboron core, the legacy
/// 86-character base64 form).
macro_rules! impl_codec_class {
    ($py_name:ident, $rust_type:ty, $doc:expr) => {
        #[doc = $doc]
        #[pyclass(module = "oboron._oboron")]
        #[allow(non_camel_case_types)]
        struct $py_name {
            inner: $rust_type,
        }

        #[pymethods]
        impl $py_name {
            /// Create a new codec instance.
            ///
            /// Args:
            ///     key:     128-character hex key (canonical), or the
            ///              transitional 86-character base64 form.
            ///              Required if keyless=False.
            ///     keyless: If True, uses the publicly hardcoded key
            ///              (testing / obfuscation only — provides no
            ///              security).
            ///
            /// Raises:
            ///     InvalidKey:    Bad hex / base64 / wrong length.
            ///     ValueError:    Both `key` and `keyless=True` given,
            ///                    or neither.
            #[new]
            #[pyo3(signature = (key=None, keyless=false))]
            fn new(key: Option<&str>, keyless: bool) -> PyResult<Self> {
                let inner = match (key, keyless) {
                    (Some(k), false) => <$rust_type>::new(k).map_err(map_error)?,
                    #[cfg(feature = "keyless")]
                    (None, true) => <$rust_type>::new_keyless().map_err(map_error)?,
                    #[cfg(not(feature = "keyless"))]
                    (None, true) => {
                        return Err(pyo3::exceptions::PyValueError::new_err(
                            "keyless support not compiled in",
                        ));
                    }
                    (Some(_), true) => {
                        return Err(pyo3::exceptions::PyValueError::new_err(
                            "specify either key or keyless=True, not both",
                        ));
                    }
                    (None, false) => {
                        return Err(pyo3::exceptions::PyValueError::new_err(
                            "must provide either key or keyless=True",
                        ));
                    }
                };
                Ok(Self { inner })
            }

            /// Encrypt + encode `plaintext` to an obtext string.
            fn enc(&self, plaintext: &str) -> PyResult<String> {
                self.inner.enc(plaintext).map_err(map_error)
            }

            /// Decode + decrypt an obtext string back to plaintext.
            fn dec(&self, obtext: &str) -> PyResult<String> {
                self.inner.dec(obtext).map_err(map_error)
            }

            /// The format string bound to this codec, e.g. `"aasv.c32"`.
            #[getter]
            fn format(&self) -> String {
                self.inner.format().to_string()
            }

            /// The scheme name bound to this codec, e.g. `"aasv"`.
            #[getter]
            fn scheme(&self) -> String {
                self.inner.scheme().to_string()
            }

            /// The encoding name bound to this codec, e.g. `"c32"`.
            #[getter]
            fn encoding(&self) -> String {
                self.inner.encoding().to_string()
            }

            /// The 128-character hex key (canonical oboron form).
            #[getter]
            fn key(&self) -> String {
                self.inner.key()
            }

            /// The key as a 128-character hex string (alias for
            /// `.key`).
            #[getter]
            fn key_hex(&self) -> String {
                self.inner.key_hex()
            }

            /// The raw 64-byte key material. Provided for interop
            /// with byte-native APIs; the canonical form everywhere
            /// else is `.key` (hex).
            #[getter]
            fn key_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
                PyBytes::new(py, self.inner.key_bytes())
            }

            fn __repr__(&self) -> String {
                format!("{}(format='{}')", stringify!($py_name), self.inner.format())
            }
        }
    };
}

/// Generate a Python wrapper class for a fixed-format z-tier codec
/// (32-byte secret instead of 64-byte master key). Same shape as
/// `impl_codec_class!` but with `secret` instead of `key`.
macro_rules! impl_zcodec_class {
    ($py_name:ident, $rust_type:ty, $doc:expr) => {
        #[doc = $doc]
        #[pyclass(module = "oboron._oboron")]
        #[allow(non_camel_case_types)]
        struct $py_name {
            inner: $rust_type,
        }

        #[pymethods]
        impl $py_name {
            /// Create a new z-tier codec instance.
            ///
            /// Args:
            ///     secret:  64-character hex secret (canonical), or
            ///              43-character base64 secret (transitional).
            ///              Length-routed by the oboron core.
            ///              Required if keyless=False.
            ///     keyless: If True, uses the publicly hardcoded
            ///              secret (testing / obfuscation only).
            ///
            /// Raises:
            ///     InvalidKey:  Bad secret / wrong length.
            #[new]
            #[pyo3(signature = (secret=None, keyless=false))]
            fn new(secret: Option<&str>, keyless: bool) -> PyResult<Self> {
                let inner = match (secret, keyless) {
                    (Some(s), false) => <$rust_type>::new(s).map_err(map_error)?,
                    #[cfg(feature = "keyless")]
                    (None, true) => <$rust_type>::new_keyless().map_err(map_error)?,
                    #[cfg(not(feature = "keyless"))]
                    (None, true) => {
                        return Err(pyo3::exceptions::PyValueError::new_err(
                            "keyless support not compiled in",
                        ));
                    }
                    (Some(_), true) => {
                        return Err(pyo3::exceptions::PyValueError::new_err(
                            "specify either secret or keyless=True, not both",
                        ));
                    }
                    (None, false) => {
                        return Err(pyo3::exceptions::PyValueError::new_err(
                            "must provide either secret or keyless=True",
                        ));
                    }
                };
                Ok(Self { inner })
            }

            fn enc(&self, plaintext: &str) -> PyResult<String> {
                self.inner.enc(plaintext).map_err(map_error)
            }

            fn dec(&self, obtext: &str) -> PyResult<String> {
                self.inner.dec(obtext).map_err(map_error)
            }

            #[getter]
            fn format(&self) -> String {
                self.inner.format().to_string()
            }

            #[getter]
            fn scheme(&self) -> String {
                self.inner.scheme().to_string()
            }

            #[getter]
            fn encoding(&self) -> String {
                self.inner.encoding().to_string()
            }

            /// The 43-character base64 secret bound to this codec.
            #[getter]
            fn secret(&self) -> String {
                self.inner.secret()
            }

            /// The 64-character hex form of the secret.
            #[getter]
            fn secret_hex(&self) -> String {
                self.inner.secret_hex()
            }

            /// The raw 32-byte secret material.
            #[getter]
            fn secret_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
                PyBytes::new(py, self.inner.secret_bytes())
            }

            fn __repr__(&self) -> String {
                format!("{}(format='{}')", stringify!($py_name), self.inner.format())
            }
        }
    };
}

// Aags variants
#[cfg(feature = "aags")]
impl_codec_class!(
    AagsB32,
    ::oboron::AagsB32,
    "Aags codec (deterministic AES-GCM-SIV) with B32 encoding"
);
#[cfg(feature = "aags")]
impl_codec_class!(
    AagsB64,
    ::oboron::AagsB64,
    "Aags codec (deterministic AES-GCM-SIV) with B64 encoding"
);
#[cfg(feature = "aags")]
impl_codec_class!(
    AagsC32,
    ::oboron::AagsC32,
    "Aags codec (deterministic AES-GCM-SIV) with C32 encoding"
);
#[cfg(feature = "aags")]
impl_codec_class!(
    AagsHex,
    ::oboron::AagsHex,
    "Aags codec (deterministic AES-GCM-SIV) with Hex encoding"
);

// Aasv variants
#[cfg(feature = "aasv")]
impl_codec_class!(
    AasvB32,
    ::oboron::AasvB32,
    "Aasv codec (deterministic AES-SIV, nonce-misuse resistant) with B32 encoding"
);
#[cfg(feature = "aasv")]
impl_codec_class!(
    AasvB64,
    ::oboron::AasvB64,
    "Aasv codec (deterministic AES-SIV, nonce-misuse resistant) with B64 encoding"
);
#[cfg(feature = "aasv")]
impl_codec_class!(
    AasvC32,
    ::oboron::AasvC32,
    "Aasv codec (deterministic AES-SIV, nonce-misuse resistant) with C32 encoding"
);
#[cfg(feature = "aasv")]
impl_codec_class!(
    AasvHex,
    ::oboron::AasvHex,
    "Aasv codec (deterministic AES-SIV, nonce-misuse resistant) with Hex encoding"
);

// Apgs variants
#[cfg(feature = "apgs")]
impl_codec_class!(
    ApgsB32,
    ::oboron::ApgsB32,
    "Apgs codec (probabilistic AES-GCM-SIV) with B32 encoding"
);
#[cfg(feature = "apgs")]
impl_codec_class!(
    ApgsB64,
    ::oboron::ApgsB64,
    "Apgs codec (probabilistic AES-GCM-SIV) with B64 encoding"
);
#[cfg(feature = "apgs")]
impl_codec_class!(
    ApgsC32,
    ::oboron::ApgsC32,
    "Apgs codec (probabilistic AES-GCM-SIV) with C32 encoding"
);
#[cfg(feature = "apgs")]
impl_codec_class!(
    ApgsHex,
    ::oboron::ApgsHex,
    "Apgs codec (probabilistic AES-GCM-SIV) with Hex encoding"
);

// Apsv variants
#[cfg(feature = "apsv")]
impl_codec_class!(
    ApsvB32,
    ::oboron::ApsvB32,
    "Apsv codec (probabilistic AES-SIV) with B32 encoding"
);
#[cfg(feature = "apsv")]
impl_codec_class!(
    ApsvB64,
    ::oboron::ApsvB64,
    "Apsv codec (probabilistic AES-SIV) with B64 encoding"
);
#[cfg(feature = "apsv")]
impl_codec_class!(
    ApsvC32,
    ::oboron::ApsvC32,
    "Apsv codec (probabilistic AES-SIV) with C32 encoding"
);
#[cfg(feature = "apsv")]
impl_codec_class!(
    ApsvHex,
    ::oboron::ApsvHex,
    "Apsv codec (probabilistic AES-SIV) with Hex encoding"
);

// Upbc variants
#[cfg(feature = "upbc")]
impl_codec_class!(
    UpbcB32,
    ::oboron::UpbcB32,
    "Upbc codec (probabilistic AES-CBC, unauthenticated) with B32 encoding"
);
#[cfg(feature = "upbc")]
impl_codec_class!(
    UpbcB64,
    ::oboron::UpbcB64,
    "Upbc codec (probabilistic AES-CBC, unauthenticated) with B64 encoding"
);
#[cfg(feature = "upbc")]
impl_codec_class!(
    UpbcC32,
    ::oboron::UpbcC32,
    "Upbc codec (probabilistic AES-CBC, unauthenticated) with C32 encoding"
);
#[cfg(feature = "upbc")]
impl_codec_class!(
    UpbcHex,
    ::oboron::UpbcHex,
    "Upbc codec (probabilistic AES-CBC, unauthenticated) with Hex encoding"
);

// Zrbcx variants (z-tier, obfuscation-only)
#[cfg(feature = "zrbcx")]
impl_zcodec_class!(
    ZrbcxB32,
    ::oboron::ztier::ZrbcxB32,
    "Zrbcx codec (deterministic AES-CBC, constant IV — INSECURE, obfuscation only) with B32 encoding"
);
#[cfg(feature = "zrbcx")]
impl_zcodec_class!(
    ZrbcxB64,
    ::oboron::ztier::ZrbcxB64,
    "Zrbcx codec (deterministic AES-CBC, constant IV — INSECURE, obfuscation only) with B64 encoding"
);
#[cfg(feature = "zrbcx")]
impl_zcodec_class!(
    ZrbcxC32,
    ::oboron::ztier::ZrbcxC32,
    "Zrbcx codec (deterministic AES-CBC, constant IV — INSECURE, obfuscation only) with C32 encoding"
);
#[cfg(feature = "zrbcx")]
impl_zcodec_class!(
    ZrbcxHex,
    ::oboron::ztier::ZrbcxHex,
    "Zrbcx codec (deterministic AES-CBC, constant IV — INSECURE, obfuscation only) with Hex encoding"
);

// Mock1 variants (testing — identity scheme, no encryption)
#[cfg(feature = "mock")]
impl_codec_class!(
    Mock1B32,
    ::oboron::Mock1B32,
    "Mock1 codec (identity scheme, for testing) with B32 encoding"
);
#[cfg(feature = "mock")]
impl_codec_class!(
    Mock1B64,
    ::oboron::Mock1B64,
    "Mock1 codec (identity scheme, for testing) with B64 encoding"
);
#[cfg(feature = "mock")]
impl_codec_class!(
    Mock1C32,
    ::oboron::Mock1C32,
    "Mock1 codec (identity scheme, for testing) with C32 encoding"
);
#[cfg(feature = "mock")]
impl_codec_class!(
    Mock1Hex,
    ::oboron::Mock1Hex,
    "Mock1 codec (identity scheme, for testing) with Hex encoding"
);

// Mock2 variants (testing — reverse-plaintext scheme, no encryption)
#[cfg(feature = "mock")]
impl_codec_class!(
    Mock2B32,
    ::oboron::Mock2B32,
    "Mock2 codec (reverse-plaintext scheme, for testing) with B32 encoding"
);
#[cfg(feature = "mock")]
impl_codec_class!(
    Mock2B64,
    ::oboron::Mock2B64,
    "Mock2 codec (reverse-plaintext scheme, for testing) with B64 encoding"
);
#[cfg(feature = "mock")]
impl_codec_class!(
    Mock2C32,
    ::oboron::Mock2C32,
    "Mock2 codec (reverse-plaintext scheme, for testing) with C32 encoding"
);
#[cfg(feature = "mock")]
impl_codec_class!(
    Mock2Hex,
    ::oboron::Mock2Hex,
    "Mock2 codec (reverse-plaintext scheme, for testing) with Hex encoding"
);

// Zmock1 variants (testing z-tier — identity scheme, no encryption)
#[cfg(feature = "mock")]
impl_zcodec_class!(
    Zmock1B32,
    ::oboron::ztier::Zmock1B32,
    "Zmock1 codec (identity z-tier scheme, for testing) with B32 encoding"
);
#[cfg(feature = "mock")]
impl_zcodec_class!(
    Zmock1B64,
    ::oboron::ztier::Zmock1B64,
    "Zmock1 codec (identity z-tier scheme, for testing) with B64 encoding"
);
#[cfg(feature = "mock")]
impl_zcodec_class!(
    Zmock1C32,
    ::oboron::ztier::Zmock1C32,
    "Zmock1 codec (identity z-tier scheme, for testing) with C32 encoding"
);
#[cfg(feature = "mock")]
impl_zcodec_class!(
    Zmock1Hex,
    ::oboron::ztier::Zmock1Hex,
    "Zmock1 codec (identity z-tier scheme, for testing) with Hex encoding"
);

// Legacy — single variant
#[cfg(feature = "legacy")]
impl_zcodec_class!(
    Legacy,
    ::oboron::ztier::Legacy,
    "Legacy codec (deterministic AES-CBC, constant IV, custom padding). \
     Maintained for backward compatibility only — use Zrbcx for new \
     z-tier work, or Aags/Aasv for actual security."
);

// ---------------------------------------------------------------------------
// Ob — runtime-mutable format selection (a/u-tier)
// ---------------------------------------------------------------------------

/// Flexible codec with runtime format selection. Wraps `oboron::Ob`
/// and lets you change the scheme/encoding after construction.
#[pyclass(module = "oboron._oboron")]
struct Ob {
    inner: ::oboron::Ob,
}

#[pymethods]
impl Ob {
    /// Create a new Ob instance.
    ///
    /// Args:
    ///     format:  Format string like `"aasv.c32"`, `"aags.b64"`,
    ///              `"apsv.hex"`.
    ///     key:     128-character hex key (canonical), or 86-character
    ///              base64 (transitional). Required if keyless=False.
    ///     keyless: If True, uses the publicly hardcoded key.
    #[new]
    #[pyo3(signature = (format, key=None, keyless=false))]
    fn new(format: &str, key: Option<&str>, keyless: bool) -> PyResult<Self> {
        let inner = match (key, keyless) {
            (Some(k), false) => ::oboron::Ob::new(format, k).map_err(map_error)?,
            #[cfg(feature = "keyless")]
            (None, true) => ::oboron::Ob::new_keyless(format).map_err(map_error)?,
            #[cfg(not(feature = "keyless"))]
            (None, true) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "keyless support not compiled in",
                ));
            }
            (Some(_), true) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "specify either key or keyless=True, not both",
                ));
            }
            (None, false) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "must provide either key or keyless=True",
                ));
            }
        };
        Ok(Self { inner })
    }

    fn enc(&self, plaintext: &str) -> PyResult<String> {
        self.inner.enc(plaintext).map_err(map_error)
    }

    fn dec(&self, obtext: &str) -> PyResult<String> {
        self.inner.dec(obtext).map_err(map_error)
    }

    /// Decode + decrypt with full format autodetection (delegates to
    /// `Omnib::autodec` on failure of the instance's own encoding).
    fn autodec(&self, obtext: &str) -> PyResult<String> {
        self.inner.autodec(obtext).map_err(map_error)
    }

    #[getter]
    fn format(&self) -> String {
        self.inner.format().to_string()
    }

    #[getter]
    fn scheme(&self) -> String {
        self.inner.scheme().to_string()
    }

    #[getter]
    fn encoding(&self) -> String {
        self.inner.encoding().to_string()
    }

    #[getter]
    fn key(&self) -> String {
        self.inner.key()
    }

    #[getter]
    fn key_hex(&self) -> String {
        self.inner.key_hex()
    }

    #[getter]
    fn key_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.key_bytes())
    }

    /// Switch to a new format (scheme + encoding).
    fn set_format(&mut self, format: &str) -> PyResult<()> {
        self.inner.set_format(format).map_err(map_error)
    }

    /// Switch the scheme, keeping the current encoding.
    fn set_scheme(&mut self, scheme: &str) -> PyResult<()> {
        let s = ::oboron::Scheme::from_str(scheme).map_err(map_error)?;
        self.inner.set_scheme(s).map_err(map_error)
    }

    /// Switch the encoding, keeping the current scheme.
    fn set_encoding(&mut self, encoding: &str) -> PyResult<()> {
        let e = ::oboron::Encoding::from_str(encoding).map_err(map_error)?;
        self.inner.set_encoding(e).map_err(map_error)
    }

    fn __repr__(&self) -> String {
        format!("Ob(format='{}')", self.inner.format())
    }
}

// ---------------------------------------------------------------------------
// Omnib — multi-format with autodetection (a/u-tier)
// ---------------------------------------------------------------------------

/// Multi-format codec — format is supplied per `enc`/`dec` call, and
/// `autodec` detects both scheme and encoding from the obtext.
#[pyclass(module = "oboron._oboron")]
struct Omnib {
    inner: ::oboron::Omnib,
}

#[pymethods]
impl Omnib {
    #[new]
    #[pyo3(signature = (key=None, keyless=false))]
    fn new(key: Option<&str>, keyless: bool) -> PyResult<Self> {
        let inner = match (key, keyless) {
            (Some(k), false) => ::oboron::Omnib::new(k).map_err(map_error)?,
            #[cfg(feature = "keyless")]
            (None, true) => ::oboron::Omnib::new_keyless().map_err(map_error)?,
            #[cfg(not(feature = "keyless"))]
            (None, true) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "keyless support not compiled in",
                ));
            }
            (Some(_), true) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "specify either key or keyless=True, not both",
                ));
            }
            (None, false) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "must provide either key or keyless=True",
                ));
            }
        };
        Ok(Self { inner })
    }

    fn enc(&self, plaintext: &str, format: &str) -> PyResult<String> {
        self.inner.enc(plaintext, format).map_err(map_error)
    }

    fn dec(&self, obtext: &str, format: &str) -> PyResult<String> {
        self.inner.dec(obtext, format).map_err(map_error)
    }

    /// Decode + decrypt with full format autodetection (scheme AND
    /// encoding). The only API surface that auto-detects encoding.
    fn autodec(&self, obtext: &str) -> PyResult<String> {
        self.inner.autodec(obtext).map_err(map_error)
    }

    #[getter]
    fn key(&self) -> String {
        self.inner.key()
    }

    #[getter]
    fn key_hex(&self) -> String {
        self.inner.key_hex()
    }

    #[getter]
    fn key_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.key_bytes())
    }

    fn __repr__(&self) -> &'static str {
        "Omnib()"
    }
}

// ---------------------------------------------------------------------------
// Obz — runtime-mutable format selection (z-tier)
// ---------------------------------------------------------------------------

#[cfg(feature = "zrbcx")]
#[pyclass(module = "oboron._oboron")]
struct Obz {
    inner: ::oboron::ztier::Obz,
}

#[cfg(feature = "zrbcx")]
#[pymethods]
impl Obz {
    /// Create a new Obz instance.
    ///
    /// Args:
    ///     format:  Format string like `"zrbcx.c32"`, `"zrbcx.b64"`.
    ///     secret:  64-character hex secret (canonical) or
    ///              43-character base64 secret (transitional).
    ///              Length-routed by the oboron core.
    ///              Required if keyless=False.
    ///     keyless: If True, uses the publicly hardcoded secret.
    #[new]
    #[pyo3(signature = (format, secret=None, keyless=false))]
    fn new(format: &str, secret: Option<&str>, keyless: bool) -> PyResult<Self> {
        let inner = match (secret, keyless) {
            (Some(s), false) => ::oboron::ztier::Obz::new(format, s).map_err(map_error)?,
            #[cfg(feature = "keyless")]
            (None, true) => ::oboron::ztier::Obz::new_keyless(format).map_err(map_error)?,
            #[cfg(not(feature = "keyless"))]
            (None, true) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "keyless support not compiled in",
                ));
            }
            (Some(_), true) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "specify either secret or keyless=True, not both",
                ));
            }
            (None, false) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "must provide either secret or keyless=True",
                ));
            }
        };
        Ok(Self { inner })
    }

    fn enc(&self, plaintext: &str) -> PyResult<String> {
        self.inner.enc(plaintext).map_err(map_error)
    }

    fn dec(&self, obtext: &str) -> PyResult<String> {
        self.inner.dec(obtext).map_err(map_error)
    }

    fn autodec(&self, obtext: &str) -> PyResult<String> {
        self.inner.autodec(obtext).map_err(map_error)
    }

    #[getter]
    fn format(&self) -> String {
        self.inner.format().to_string()
    }

    #[getter]
    fn scheme(&self) -> String {
        self.inner.scheme().to_string()
    }

    #[getter]
    fn encoding(&self) -> String {
        self.inner.encoding().to_string()
    }

    #[getter]
    fn secret(&self) -> String {
        self.inner.secret()
    }

    #[getter]
    fn secret_hex(&self) -> String {
        self.inner.secret_hex()
    }

    #[getter]
    fn secret_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.secret_bytes())
    }

    fn set_format(&mut self, format: &str) -> PyResult<()> {
        self.inner.set_format(format).map_err(map_error)
    }

    fn set_scheme(&mut self, scheme: &str) -> PyResult<()> {
        let s = ::oboron::Scheme::from_str(scheme).map_err(map_error)?;
        self.inner.set_scheme(s).map_err(map_error)
    }

    fn set_encoding(&mut self, encoding: &str) -> PyResult<()> {
        let e = ::oboron::Encoding::from_str(encoding).map_err(map_error)?;
        self.inner.set_encoding(e).map_err(map_error)
    }

    fn __repr__(&self) -> String {
        format!("Obz(format='{}')", self.inner.format())
    }
}

// ---------------------------------------------------------------------------
// Omnibz — multi-format z-tier with autodetection
// ---------------------------------------------------------------------------

#[cfg(feature = "zrbcx")]
#[pyclass(module = "oboron._oboron")]
struct Omnibz {
    inner: ::oboron::ztier::Omnibz,
}

#[cfg(feature = "zrbcx")]
#[pymethods]
impl Omnibz {
    /// Create a new Omnibz instance.
    ///
    /// Args:
    ///     secret:  64-character hex secret (canonical) or
    ///              43-character base64 secret (transitional).
    ///              Required if keyless=False.
    ///     keyless: If True, uses the publicly hardcoded secret.
    #[new]
    #[pyo3(signature = (secret=None, keyless=false))]
    fn new(secret: Option<&str>, keyless: bool) -> PyResult<Self> {
        let inner = match (secret, keyless) {
            (Some(s), false) => ::oboron::ztier::Omnibz::new(s).map_err(map_error)?,
            #[cfg(feature = "keyless")]
            (None, true) => ::oboron::ztier::Omnibz::new_keyless().map_err(map_error)?,
            #[cfg(not(feature = "keyless"))]
            (None, true) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "keyless support not compiled in",
                ));
            }
            (Some(_), true) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "specify either secret or keyless=True, not both",
                ));
            }
            (None, false) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "must provide either secret or keyless=True",
                ));
            }
        };
        Ok(Self { inner })
    }

    fn enc(&self, plaintext: &str, format: &str) -> PyResult<String> {
        self.inner.enc(plaintext, format).map_err(map_error)
    }

    fn dec(&self, obtext: &str, format: &str) -> PyResult<String> {
        self.inner.dec(obtext, format).map_err(map_error)
    }

    fn autodec(&self, obtext: &str) -> PyResult<String> {
        self.inner.autodec(obtext).map_err(map_error)
    }

    #[getter]
    fn secret(&self) -> String {
        self.inner.secret()
    }

    #[getter]
    fn secret_hex(&self) -> String {
        self.inner.secret_hex()
    }

    #[getter]
    fn secret_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.secret_bytes())
    }

    fn __repr__(&self) -> &'static str {
        "Omnibz()"
    }
}

// ---------------------------------------------------------------------------
// Module-level functions
// ---------------------------------------------------------------------------

/// Generate a fresh random 64-byte key, returned as a 128-character
/// lowercase hex string — the canonical oboron key form.
#[pyfunction]
fn generate_key() -> String {
    ::oboron::generate_key()
}

/// Generate a fresh random 64-byte key as raw `bytes`.
#[pyfunction]
fn generate_key_bytes(py: Python<'_>) -> Bound<'_, PyBytes> {
    PyBytes::new(py, &::oboron::generate_key_bytes())
}

/// Generate a fresh random 32-byte secret (z-tier), returned as a
/// 64-character lowercase hex string.
#[pyfunction]
fn generate_secret() -> String {
    ::oboron::generate_secret()
}

/// Generate a fresh random 32-byte secret as raw `bytes`.
#[pyfunction]
fn generate_secret_bytes(py: Python<'_>) -> Bound<'_, PyBytes> {
    PyBytes::new(py, &::oboron::generate_secret_bytes())
}

/// Encrypt + encode `plaintext` under `format` using `key`.
///
/// Convenience wrapper around `Omnib::enc`; for repeated calls,
/// construct an `Omnib` once and reuse it.
#[pyfunction]
fn enc(plaintext: &str, format: &str, key: &str) -> PyResult<String> {
    ::oboron::enc(plaintext, format, key).map_err(map_error)
}

/// Encrypt + encode `plaintext` under `format` with the hardcoded
/// key (testing / obfuscation only).
#[cfg(feature = "keyless")]
#[pyfunction]
fn enc_keyless(plaintext: &str, format: &str) -> PyResult<String> {
    ::oboron::enc_keyless(plaintext, format).map_err(map_error)
}

/// Decode + decrypt `obtext` under `format` using `key`.
#[pyfunction]
fn dec(obtext: &str, format: &str, key: &str) -> PyResult<String> {
    ::oboron::dec(obtext, format, key).map_err(map_error)
}

/// Decode + decrypt `obtext` under `format` with the hardcoded key.
#[cfg(feature = "keyless")]
#[pyfunction]
fn dec_keyless(obtext: &str, format: &str) -> PyResult<String> {
    ::oboron::dec_keyless(obtext, format).map_err(map_error)
}

/// Decode + decrypt `obtext` with full format autodetection (scheme
/// AND encoding).
#[pyfunction]
fn autodec(obtext: &str, key: &str) -> PyResult<String> {
    ::oboron::autodec(obtext, key).map_err(map_error)
}

/// Decode + decrypt `obtext` with full format autodetection and the
/// hardcoded key.
#[cfg(feature = "keyless")]
#[pyfunction]
fn autodec_keyless(obtext: &str) -> PyResult<String> {
    ::oboron::autodec_keyless(obtext).map_err(map_error)
}

// ---------------------------------------------------------------------------
// Module init
// ---------------------------------------------------------------------------

#[pymodule]
fn _oboron(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    // Exceptions
    m.add("OboronError", py.get_type::<OboronError>())?;
    m.add("InvalidKey", py.get_type::<InvalidKey>())?;
    m.add("InvalidFormat", py.get_type::<InvalidFormat>())?;
    m.add("EncryptionFailed", py.get_type::<EncryptionFailed>())?;
    m.add("DecryptionFailed", py.get_type::<DecryptionFailed>())?;

    // Main flexible interfaces (a/u-tier)
    m.add_class::<Ob>()?;
    m.add_class::<Omnib>()?;

    // Aags variants
    #[cfg(feature = "aags")]
    {
        m.add_class::<AagsC32>()?;
        m.add_class::<AagsB32>()?;
        m.add_class::<AagsB64>()?;
        m.add_class::<AagsHex>()?;
    }

    // Apgs variants
    #[cfg(feature = "apgs")]
    {
        m.add_class::<ApgsC32>()?;
        m.add_class::<ApgsB32>()?;
        m.add_class::<ApgsB64>()?;
        m.add_class::<ApgsHex>()?;
    }

    // Aasv variants
    #[cfg(feature = "aasv")]
    {
        m.add_class::<AasvC32>()?;
        m.add_class::<AasvB32>()?;
        m.add_class::<AasvB64>()?;
        m.add_class::<AasvHex>()?;
    }

    // Apsv variants
    #[cfg(feature = "apsv")]
    {
        m.add_class::<ApsvC32>()?;
        m.add_class::<ApsvB32>()?;
        m.add_class::<ApsvB64>()?;
        m.add_class::<ApsvHex>()?;
    }

    // Upbc variants
    #[cfg(feature = "upbc")]
    {
        m.add_class::<UpbcC32>()?;
        m.add_class::<UpbcB32>()?;
        m.add_class::<UpbcB64>()?;
        m.add_class::<UpbcHex>()?;
    }

    // Mock variants (testing)
    #[cfg(feature = "mock")]
    {
        m.add_class::<Mock1C32>()?;
        m.add_class::<Mock1B32>()?;
        m.add_class::<Mock1B64>()?;
        m.add_class::<Mock1Hex>()?;
        m.add_class::<Mock2C32>()?;
        m.add_class::<Mock2B32>()?;
        m.add_class::<Mock2B64>()?;
        m.add_class::<Mock2Hex>()?;
        m.add_class::<Zmock1C32>()?;
        m.add_class::<Zmock1B32>()?;
        m.add_class::<Zmock1B64>()?;
        m.add_class::<Zmock1Hex>()?;
    }

    // Z-tier flexible interfaces
    #[cfg(feature = "zrbcx")]
    {
        m.add_class::<Obz>()?;
        m.add_class::<Omnibz>()?;
        m.add_class::<ZrbcxC32>()?;
        m.add_class::<ZrbcxB32>()?;
        m.add_class::<ZrbcxB64>()?;
        m.add_class::<ZrbcxHex>()?;
    }

    // Legacy variant
    #[cfg(feature = "legacy")]
    {
        m.add_class::<Legacy>()?;
    }

    // Key / secret generation
    m.add_function(wrap_pyfunction!(generate_key, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(generate_secret, m)?)?;
    m.add_function(wrap_pyfunction!(generate_secret_bytes, m)?)?;

    // Convenience functions
    m.add_function(wrap_pyfunction!(enc, m)?)?;
    m.add_function(wrap_pyfunction!(dec, m)?)?;
    m.add_function(wrap_pyfunction!(autodec, m)?)?;
    #[cfg(feature = "keyless")]
    {
        m.add_function(wrap_pyfunction!(enc_keyless, m)?)?;
        m.add_function(wrap_pyfunction!(dec_keyless, m)?)?;
        m.add_function(wrap_pyfunction!(autodec_keyless, m)?)?;
    }

    Ok(())
}
