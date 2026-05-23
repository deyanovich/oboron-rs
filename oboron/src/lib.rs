//! This library provides encryption-based encoding to various text schemes
//! using AES encryption with multiple scheme options.
//!
//! # Quick Start
//!
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(feature = "aasv")]
//! # {
//! use oboron::{AasvC32, ObtextCodec};
//! let key = oboron::generate_key(); // get key
//! let ob = AasvC32::new(&key)?;     // instantiate ObtextCodec (cipher+encoder)
//! let ot = ob.enc("secret data")?;  // get obtext (encoded ciphertext)
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! # Parameter Order Convention
//!
//! All functions in this library follow a consistent parameter ordering convention:
//!
//! **`data` < `format` < `key`**
//!
//! - `data` (plaintext/obtext) comes first - it's what you're operating on
//! - `format` comes second (when present) - it's configuration/options
//! - `key` comes last (when present) - it's the security credential
//!
//! Examples:
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(feature = "aasv")]
//! # {
//! # use oboron;
//! # let key = oboron::generate_key();
//! # let omb = oboron::Omnib::new(&key)?;
//! // Operations: data, format
//! let ot = omb.enc("plaintext", "aasv.b64")?;
//! omb.dec(&ot, "aasv.b64")?;
//!
//! // Constructors: format, key
//! oboron::Ob::new("aasv.b64", &key)?;
//!
//! // Convenience functions: data, format, key
//! let ot = oboron::enc("plaintext", "aasv.b64", &key)?;
//! oboron::dec(&ot, "aasv.b64", &key)?;
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! # Choosing the Right Type
//!
//! Oboron provides several types optimized for different use cases:
//!
//! ## 1. Fixed-Format Types (Fastest, Compile-Time)
//!
//! Use format-specific types when you know the format at compile time:
//!
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(feature = "aasv")]
//! # {
//! # use oboron::{AasvC32, AasvB64, ObtextCodec};
//! # let key = oboron::generate_key();
//! let aasv = AasvC32::new(&key)?;      // aasv.c32 format (Crockford base32)
//! let aasv_b64 = AasvB64::new(&key)?;  // aasv.b64 format (base64url)
//!
//! let ot = aasv.enc("hello")?;
//! let pt2 = aasv.dec(&ot)?;
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! - Use case: Format is known at compile time
//! - Performance: Fastest (zero overhead)
//! - Flexibility: Format fixed, explicit in type name
//!
//! ## 2. `Ob` - Runtime Format (Flexible)
//!
//! Use `Ob` when you need to choose the format at runtime:
//!
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(feature = "aasv")]
//! # {
//! # use oboron::{Ob, ObtextCodec};
//!  # let key = oboron::generate_key();
//! // Format chosen at runtime
//! let mut ob = Ob::new("aasv.b64", &key)?;
//!
//! let ot = ob.enc("hello")?;
//! let pt2 = ob.dec(&ot)?;
//!
//! // Can change format if needed
//! ob.set_format("aasv.hex")?;
//! # }
//! # Ok(())
//! # }
//!  ```
//!
//! - Use case: Format determined at runtime (config, user input)
//! - Performance: Near-zero overhead (inlines to static functions)
//! - Flexibility: Runtime format selection, can be changed after construction
//!
//! ## 3. `Omnib` - Multi-Format Operations
//!
//! Use `Omnib` when working with different formats in a single context:
//!
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(feature = "aasv")]
//! # {
//! # use oboron::Omnib;
//! # let key = oboron::generate_key();
//! let omb = Omnib::new(&key)?;
//!
//! // Encode to different formats
//! let ot_b32 = omb.enc("data", "aasv.c32")?;
//! let ot_b64 = omb.enc("data", "aasv.b64")?;
//! let ot_hex = omb.enc("data", "aasv.hex")?;
//!
//! // Decode with automatic format detection
//! let pt2 = omb.autodec(&ot_b64)?;
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! - Use case: Working with multiple formats or unknown formats
//! - Performance: Small overhead (format parsing per operation)
//! - Flexibility: Maximum - handles any format, autodetects on dec
//!
//! # Quick Reference
//!
//! | Type            | Format             | Use Case          | Performance         |
//! |-----------------|--------------------|-------------------|---------------------|
//! | `AasvC32`, etc. | Compile-time       | Known format      | Fastest (zero-cost) |
//! | `Ob`            | Runtime, mutable   | Config-driven     | Near-zero overhead  |
//! | `Omnib`       | Per-operation      | Multiple formats  | Small overhead      |
//!
//! # Typical Production Usage: Fixed ObtextCodec
//!
//! Best performance and type safety for multiple operations with the same format:
//!
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(all(feature = "aasv", feature = "apgs"))]
//! # {
//! # use oboron::ObtextCodec;
//! # use oboron;
//! # let key = oboron::generate_key();
//! // Fixed format types (best performance for multiple operations with same format)
//! let aasv = oboron::AasvC32::new(&key)?;  // "aasv.c32" fixed-format ObtextCodec instance
//! let apgs = oboron::ApgsC32::new(&key)?;  // "apgs.c32" fixed-format ObtextCodec instance
//!
//! let ot_aasv = aasv.enc("data1")?;
//! let ot_apgs = apgs.enc("data2")?;
//!
//! // Decoding
//! let pt1 = aasv.dec(&ot_aasv)?;  // Decodes successfully
//! let pt2 = apgs.dec(&ot_apgs)?;
//! assert_eq!(pt1, "data1");
//! assert_eq!(pt2, "data2");
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! # Encryption Schemes
//!
//! - Authenticated:
//!   - `Aags`: deterministic AES-GCM-SIV
//!   - `Aasv`: deterministic AES-SIV (nonce-misuse resistant)
//!   - `Apgs`: probabilistic AES-GCM-SIV
//!   - `Apsv`: probabilistic AES-SIV
//! - Un-authenticated:
//!   - `Upbc`: probabilistic AES-CBC
//! - Insecure (obfuscation only):
//!   - `Zrbcx`: deterministic AES-CBC with constant IV
//!
//! Testing/Demo only schemes using no encryption (`mock` feature group):
//! - `Mock1`: Identity
//! - `Mock2`: Reverse plaintext
//!
//! Each scheme supports four string encodings:
//! - B64 - URL-safe base64 (RFC 4648 base64url standard)
//! - B32 - Standard base32 (RFC 4648)
//! - C32 - Crockford base32
//! - Hex - Hexadecimal
//!
//! # The `ObtextCodec` Trait
//!
//! All types (`Ob`, `AasvC32`, `ApsvB64`, etc.) except `Omnib` implement the `ObtextCodec` trait,
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(feature = "aasv")]
//! # {
//! # use oboron::{ObtextCodec, AasvC32, Ob};
//! # let key = oboron::generate_key();
//! fn process<O: ObtextCodec>(ob: &O, data: &str) -> Result<String, oboron::Error> {
//!     let ot = ob.enc(data)?;
//!     ob.dec(&ot)
//! }
//!
//! let aasv = AasvC32::new(&key)?;
//! let ob = Ob::new("aasv.c32", &key)?;
//!
//! process(&aasv, "hello")?;
//! process(&ob, "hello")?;
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! The `ObtextCodec` trait is automatically imported via the prelude.

mod base32;
mod codec;
mod constants;
mod dec;
mod dec_auto;
mod enc;
mod encoding;
mod error;
mod format;
mod keygen;
mod masterkey;
mod ob;
mod omnib;
mod scheme;
#[cfg(any(feature = "zrbcx", feature = "legacy", feature = "mock"))]
pub mod ztier;

// Re-export public types and constants
pub use constants::{HARDCODED_KEY_BYTES, HARDCODED_KEY_HEX};
#[cfg(feature = "base64-keys")]
#[deprecated(
    since = "0.7.1",
    note = "use HARDCODED_KEY_HEX instead; base64 key support will be removed before oboron 1.0"
)]
#[allow(deprecated)]
pub use constants::HARDCODED_KEY_BASE64;
pub use error::Error;

pub(crate) use masterkey::MasterKey;

#[cfg(feature = "zrbcx")]
pub(crate) use ztier::{decrypt_zrbcx, encrypt_zrbcx};
#[cfg(feature = "mock")]
pub(crate) use ztier::{decrypt_zmock1, encrypt_zmock1};

pub use keygen::generate_key;
pub use keygen::generate_key_bytes;
#[deprecated(
    since = "0.7.1",
    note = "use generate_key() — hex is now the default key format"
)]
#[allow(deprecated)]
pub use keygen::generate_key_hex;
#[cfg(feature = "base64-keys")]
#[deprecated(
    since = "0.7.1",
    note = "use generate_key() (hex) instead; base64 key support will be removed before oboron 1.0"
)]
#[allow(deprecated)]
pub use keygen::generate_key_base64;
pub use keygen::generate_secret;
pub use keygen::generate_secret_bytes;
#[deprecated(
    since = "0.7.1",
    note = "use generate_secret() — hex is now the default secret format"
)]
#[allow(deprecated)]
pub use keygen::generate_secret_hex;
#[cfg(feature = "base64-keys")]
#[deprecated(
    since = "0.7.1",
    note = "use generate_secret() (hex) instead; base64 support will be removed before oboron 1.0"
)]
#[allow(deprecated)]
pub use keygen::generate_secret_base64;

// Re-export core types
pub use encoding::Encoding;
pub use format::Format;
pub use scheme::Scheme;

// Re-export Ob
pub use ob::Ob;

// Factory functions
pub use codec::{from_bytes, from_bytes_with_format};
pub use codec::{from_hex_key, from_hex_key_with_format};
#[allow(deprecated)]
pub use codec::{from_key_hex, from_key_hex_with_format};
pub use codec::{new, new_with_format, ObAny, ObtextCodec};
#[cfg(feature = "keyless")]
pub use codec::{new_keyless, new_keyless_with_format};

// Conditionally export format string constants (scheme+encoding combinations)
#[cfg(feature = "aags")]
pub use constants::aags_constants::*;
#[cfg(feature = "aasv")]
pub use constants::aasv_constants::*;
#[cfg(feature = "apgs")]
pub use constants::apgs_constants::*;
#[cfg(feature = "apsv")]
pub use constants::apsv_constants::*;
#[cfg(feature = "upbc")]
pub use constants::upbc_constants::*;
#[cfg(feature = "zrbcx")]
pub use constants::zrbcx_constants::*;
// Legacy
#[cfg(feature = "legacy")]
pub use constants::legacy_constants::*;
// Testing
#[cfg(feature = "mock")]
pub use constants::mock_constants::*;
#[cfg(feature = "mock")]
pub use constants::zmock_constants::*;

#[cfg(feature = "aags")]
pub use format::aags_formats::*;
#[cfg(feature = "aasv")]
pub use format::aasv_formats::*;
#[cfg(feature = "apgs")]
pub use format::apgs_formats::*;
#[cfg(feature = "apsv")]
pub use format::apsv_formats::*;
#[cfg(feature = "upbc")]
pub use format::upbc_formats::*;
#[cfg(feature = "zrbcx")]
pub use format::zrbcx_formats::*;
// Legacy
#[cfg(feature = "legacy")]
pub use format::legacy_formats::*;
// Testing
#[cfg(feature = "mock")]
pub use format::mock_formats::*;
#[cfg(feature = "mock")]
pub use format::zmock_formats::*;

// Conditionally export format-specific structs (scheme+encoding combinations)
#[cfg(feature = "aags")]
pub use codec::{AagsB32, AagsB64, AagsC32, AagsHex};
#[cfg(feature = "aasv")]
pub use codec::{AasvB32, AasvB64, AasvC32, AasvHex};
#[cfg(feature = "apgs")]
pub use codec::{ApgsB32, ApgsB64, ApgsC32, ApgsHex};
#[cfg(feature = "apsv")]
pub use codec::{ApsvB32, ApsvB64, ApsvC32, ApsvHex};
#[cfg(feature = "upbc")]
pub use codec::{UpbcB32, UpbcB64, UpbcC32, UpbcHex};
// Testing
#[cfg(feature = "mock")]
pub use codec::{Mock1B32, Mock1B64, Mock1C32, Mock1Hex};
#[cfg(feature = "mock")]
pub use codec::{Mock2B32, Mock2B64, Mock2C32, Mock2Hex};

// Re-export multi-format Oboron implementation
pub use omnib::Omnib;

/// Convenience prelude for common imports.
///
/// Import everything you need with:
/// ```rust
/// use oboron::prelude::*;
/// ```
pub mod prelude {
    #[cfg(feature = "aags")]
    pub use crate::{AagsB32, AagsB64, AagsC32, AagsHex};
    #[cfg(feature = "aasv")]
    pub use crate::{AasvB32, AasvB64, AasvC32, AasvHex};
    #[cfg(feature = "apgs")]
    pub use crate::{ApgsB32, ApgsB64, ApgsC32, ApgsHex};
    #[cfg(feature = "apsv")]
    pub use crate::{ApsvB32, ApsvB64, ApsvC32, ApsvHex};
    pub use crate::{Encoding, Error, Format, ObtextCodec, Scheme};
    pub use crate::{Ob, Omnib};
}

// ============================================================================
// Convenience Functions
// ============================================================================
//
// All convenience functions follow the parameter order convention:
//   data < format < key
//
// This ensures consistency across the API:
// - Data (plaintext/obtext) always comes first
// - Format specification comes second (when present)
// - Key comes last (when present)
// ============================================================================

/// Encrypt+encode plaintext with a specified format.
///
/// This is a convenience wrapper around [`Omnib::enc`].
/// For repeated operations, consider creating an [`Omnib`] instance directly.
///
/// # Parameter Order
/// `(data, format, key)` - follows the convention: data < format < key
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(feature = "aasv")]
/// # {
/// # use oboron;
/// # let key = oboron::generate_key();
/// let ot = oboron::enc("secret data", "aasv.b64", &key)?;
/// # }
/// # Ok(())
/// # }
/// ```
pub fn enc(plaintext: &str, format: &str, key: &str) -> Result<String, Error> {
    Omnib::new(key)?.enc(plaintext, format)
}

/// Encrypt+encode plaintext with a specified format using the hardcoded key (testing only).
///
/// # Parameter Order
/// `(data, format)` - key is implicit (hardcoded key)
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(feature = "aasv")]
/// # {
/// # use oboron;
/// let ot = oboron::enc_keyless("test data", "aasv.b64")?;
/// # }
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "keyless")]
pub fn enc_keyless(plaintext: &str, format: &str) -> Result<String, Error> {
    Omnib::new_keyless()?.enc(plaintext, format)
}

/// Decode+decrypt obtext with a specified format.
///
/// This is a convenience wrapper around [`Omnib::dec`].
/// For repeated operations, consider creating an [`Omnib`] instance directly.
///
/// # Parameter Order
/// `(data, format, key)` - follows the convention: data < format < key
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(feature = "aasv")]
/// # use oboron;
/// # {
/// # let key = oboron::generate_key();
/// # let ot = oboron::enc("test123", "aasv.b64", &key)?;
/// let pt2 = oboron::dec(&ot, "aasv.b64", &key)?;
/// # assert_eq!(pt2, "test123");
/// # }
/// # Ok(())
/// # }
/// ```
pub fn dec(obtext: &str, format: &str, key: &str) -> Result<String, Error> {
    Omnib::new(key)?.dec(obtext, format)
}

/// Decode+decrypt obtext with a specified format using the hardcoded key (testing only).
///
/// # Parameter Order
/// `(data, format)` - key is implicit (hardcoded key)
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(feature = "aasv")]
/// # {
/// # use oboron;
/// # let ot = oboron::enc_keyless("test", "aasv.b64")?;
/// let pt2 = oboron::dec_keyless(&ot, "aasv.b64")?;
/// # assert_eq!(pt2, "test");
/// # }
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "keyless")]
pub fn dec_keyless(obtext: &str, format: &str) -> Result<String, Error> {
    Omnib::new_keyless()?.dec(obtext, format)
}

/// Decode+decrypt obtext with automatic format detection.
///
/// Automatically detects both the scheme and encoding used.
/// This is a convenience wrapper around [`Omnib::autodec`].
///
/// # Parameter Order
/// `(data, key)` - format is autodetected
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(feature = "aasv")]
/// # {
/// # use oboron;
/// # let key = oboron::generate_key();
/// # let ot = oboron::enc("secret", "aasv.b64", &key)?;
/// let pt2 = oboron::autodec(&ot, &key)?;  // Format autodetected, including encoding
/// # assert_eq!(pt2, "secret");
/// # }
/// # Ok(())
/// # }
/// ```
pub fn autodec(obtext: &str, key: &str) -> Result<String, Error> {
    Omnib::new(key)?.autodec(obtext)
}

/// Decode+decrypt obtext with automatic format detection using the hardcoded key (testing only).
///
/// # Parameter Order
/// `(data)` - both format and key are implicit
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), oboron::Error> {
/// # #[cfg(feature = "aasv")]
/// # {
/// # use oboron;
/// # let ot = oboron::enc_keyless("test", "mock1.b64")?;
/// let pt2 = oboron::autodec_keyless(&ot)?; // Autodetect format; use hardcoded key
/// # assert_eq!(pt2, "test");
/// # }
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "keyless")]
pub fn autodec_keyless(obtext: &str) -> Result<String, Error> {
    Omnib::new_keyless()?.autodec(obtext)
}
