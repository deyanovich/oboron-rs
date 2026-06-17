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
        | oboron::Error::InvalidB64
        | oboron::Error::InvalidB32
        | oboron::Error::InvalidC32
        | oboron::Error::InvalidUtf8 => DecryptionFailed::new_err(msg),

        // `oboron::Error` is `#[non_exhaustive]` — future variants
        // fall through here.
        _ => OboronError::new_err(msg),
    }
}

// ---------------------------------------------------------------------------
// Per-scheme codec classes (fixed format)
// ---------------------------------------------------------------------------

/// Generate a Python wrapper class for a fixed-format ObtextCodec
/// type from the oboron core. Each instance binds a key + scheme +
/// encoding; constructors accept the canonical 128-character hex key.
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
            ///     key:     128-character hex key (canonical).
            ///              Required if keyless=False.
            ///     keyless: If True, uses the publicly hardcoded key
            ///              (testing / obfuscation only — provides no
            ///              security).
            ///
            /// Raises:
            ///     InvalidKey:    Bad hex / wrong length.
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

            /// The format string bound to this codec, e.g. `"dsiv.c32"`.
            #[getter]
            fn format(&self) -> String {
                self.inner.format().to_string()
            }

            /// The scheme name bound to this codec, e.g. `"dsiv"`.
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

// Dgcmsiv variants
#[cfg(feature = "dgcmsiv")]
impl_codec_class!(
    DgcmsivB32,
    ::oboron::DgcmsivB32,
    "Dgcmsiv codec (deterministic AES-GCM-SIV) with B32 encoding"
);
#[cfg(feature = "dgcmsiv")]
impl_codec_class!(
    DgcmsivB64,
    ::oboron::DgcmsivB64,
    "Dgcmsiv codec (deterministic AES-GCM-SIV) with B64 encoding"
);
#[cfg(feature = "dgcmsiv")]
impl_codec_class!(
    DgcmsivC32,
    ::oboron::DgcmsivC32,
    "Dgcmsiv codec (deterministic AES-GCM-SIV) with C32 encoding"
);
#[cfg(feature = "dgcmsiv")]
impl_codec_class!(
    DgcmsivHex,
    ::oboron::DgcmsivHex,
    "Dgcmsiv codec (deterministic AES-GCM-SIV) with Hex encoding"
);

// Dsiv variants
#[cfg(feature = "dsiv")]
impl_codec_class!(
    DsivB32,
    ::oboron::DsivB32,
    "Dsiv codec (deterministic AES-SIV, nonce-misuse resistant) with B32 encoding"
);
#[cfg(feature = "dsiv")]
impl_codec_class!(
    DsivB64,
    ::oboron::DsivB64,
    "Dsiv codec (deterministic AES-SIV, nonce-misuse resistant) with B64 encoding"
);
#[cfg(feature = "dsiv")]
impl_codec_class!(
    DsivC32,
    ::oboron::DsivC32,
    "Dsiv codec (deterministic AES-SIV, nonce-misuse resistant) with C32 encoding"
);
#[cfg(feature = "dsiv")]
impl_codec_class!(
    DsivHex,
    ::oboron::DsivHex,
    "Dsiv codec (deterministic AES-SIV, nonce-misuse resistant) with Hex encoding"
);

// Pgcmsiv variants
#[cfg(feature = "pgcmsiv")]
impl_codec_class!(
    PgcmsivB32,
    ::oboron::PgcmsivB32,
    "Pgcmsiv codec (probabilistic AES-GCM-SIV) with B32 encoding"
);
#[cfg(feature = "pgcmsiv")]
impl_codec_class!(
    PgcmsivB64,
    ::oboron::PgcmsivB64,
    "Pgcmsiv codec (probabilistic AES-GCM-SIV) with B64 encoding"
);
#[cfg(feature = "pgcmsiv")]
impl_codec_class!(
    PgcmsivC32,
    ::oboron::PgcmsivC32,
    "Pgcmsiv codec (probabilistic AES-GCM-SIV) with C32 encoding"
);
#[cfg(feature = "pgcmsiv")]
impl_codec_class!(
    PgcmsivHex,
    ::oboron::PgcmsivHex,
    "Pgcmsiv codec (probabilistic AES-GCM-SIV) with Hex encoding"
);

// Psiv variants
#[cfg(feature = "psiv")]
impl_codec_class!(
    PsivB32,
    ::oboron::PsivB32,
    "Psiv codec (probabilistic AES-SIV) with B32 encoding"
);
#[cfg(feature = "psiv")]
impl_codec_class!(
    PsivB64,
    ::oboron::PsivB64,
    "Psiv codec (probabilistic AES-SIV) with B64 encoding"
);
#[cfg(feature = "psiv")]
impl_codec_class!(
    PsivC32,
    ::oboron::PsivC32,
    "Psiv codec (probabilistic AES-SIV) with C32 encoding"
);
#[cfg(feature = "psiv")]
impl_codec_class!(
    PsivHex,
    ::oboron::PsivHex,
    "Psiv codec (probabilistic AES-SIV) with Hex encoding"
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

// ---------------------------------------------------------------------------
// Ob — runtime-mutable format selection
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
    ///     format:  Format string like `"dsiv.c32"`, `"dgcmsiv.b64"`,
    ///              `"psiv.hex"`.
    ///     key:     128-character hex key (canonical). Required if
    ///              keyless=False.
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
// Omnib — multi-format
// ---------------------------------------------------------------------------

/// Multi-format codec — format is supplied per `enc`/`dec` call.
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

    // Main flexible interfaces
    m.add_class::<Ob>()?;
    m.add_class::<Omnib>()?;

    // Dgcmsiv variants
    #[cfg(feature = "dgcmsiv")]
    {
        m.add_class::<DgcmsivC32>()?;
        m.add_class::<DgcmsivB32>()?;
        m.add_class::<DgcmsivB64>()?;
        m.add_class::<DgcmsivHex>()?;
    }

    // Pgcmsiv variants
    #[cfg(feature = "pgcmsiv")]
    {
        m.add_class::<PgcmsivC32>()?;
        m.add_class::<PgcmsivB32>()?;
        m.add_class::<PgcmsivB64>()?;
        m.add_class::<PgcmsivHex>()?;
    }

    // Dsiv variants
    #[cfg(feature = "dsiv")]
    {
        m.add_class::<DsivC32>()?;
        m.add_class::<DsivB32>()?;
        m.add_class::<DsivB64>()?;
        m.add_class::<DsivHex>()?;
    }

    // Psiv variants
    #[cfg(feature = "psiv")]
    {
        m.add_class::<PsivC32>()?;
        m.add_class::<PsivB32>()?;
        m.add_class::<PsivB64>()?;
        m.add_class::<PsivHex>()?;
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
    }

    // Key generation
    m.add_function(wrap_pyfunction!(generate_key, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key_bytes, m)?)?;

    // Convenience functions
    m.add_function(wrap_pyfunction!(enc, m)?)?;
    m.add_function(wrap_pyfunction!(dec, m)?)?;
    #[cfg(feature = "keyless")]
    {
        m.add_function(wrap_pyfunction!(enc_keyless, m)?)?;
        m.add_function(wrap_pyfunction!(dec_keyless, m)?)?;
    }

    Ok(())
}
