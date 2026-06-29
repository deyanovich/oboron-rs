//! oboron is a string-in / string-out **authenticated** symmetric
//! encryption layer for UTF-8 text: it encrypts a string under an
//! AES-SIV or AES-GCM-SIV scheme and encodes the result to compact
//! obtext (Crockford base32, base32, base64url, or hex). Every scheme
//! is authenticated; the scheme is supplied by the caller (the obtext
//! carries no marker), and keys are 128-character hex.
//!
//! # Quick Start
//!
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(feature = "dsiv")]
//! # {
//! use oboron::{DsivC32, ObtextCodec};
//! let key = oboron::generate_key(); // get key
//! let ob = DsivC32::new(&key)?;     // instantiate ObtextCodec (cipher+encoder)
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
//! # #[cfg(feature = "dsiv")]
//! # {
//! # use oboron;
//! # let key = oboron::generate_key();
//! # let omb = oboron::Omnib::new(&key)?;
//! // Operations: data, format
//! let ot = omb.enc("plaintext", "dsiv.b64")?;
//! omb.dec(&ot, "dsiv.b64")?;
//!
//! // Constructors: format, key
//! oboron::Ob::new("dsiv.b64", &key)?;
//!
//! // Convenience functions: data, format, key
//! let ot = oboron::enc("plaintext", "dsiv.b64", &key)?;
//! oboron::dec(&ot, "dsiv.b64", &key)?;
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
//! # #[cfg(feature = "dsiv")]
//! # {
//! # use oboron::{DsivC32, DsivB64, ObtextCodec};
//! # let key = oboron::generate_key();
//! let dsiv = DsivC32::new(&key)?;      // dsiv.c32 format (Crockford base32)
//! let dsiv_b64 = DsivB64::new(&key)?;  // dsiv.b64 format (base64url)
//!
//! let ot = dsiv.enc("hello")?;
//! let pt2 = dsiv.dec(&ot)?;
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
//! # #[cfg(feature = "dsiv")]
//! # {
//! # use oboron::{Ob, ObtextCodec};
//!  # let key = oboron::generate_key();
//! // Format chosen at runtime
//! let mut ob = Ob::new("dsiv.b64", &key)?;
//!
//! let ot = ob.enc("hello")?;
//! let pt2 = ob.dec(&ot)?;
//!
//! // Can change format if needed
//! ob.set_format("dsiv.hex")?;
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
//! # #[cfg(feature = "dsiv")]
//! # {
//! # use oboron::Omnib;
//! # let key = oboron::generate_key();
//! let omb = Omnib::new(&key)?;
//!
//! // Encode to different formats
//! let ot_c32 = omb.enc("data", "dsiv.c32")?;
//! let ot_b64 = omb.enc("data", "dsiv.b64")?;
//! let ot_hex = omb.enc("data", "dsiv.hex")?;
//!
//! // Decode with the matching format (the scheme is supplied, not detected)
//! let pt2 = omb.dec(&ot_b64, "dsiv.b64")?;
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! - Use case: Working with multiple formats in one context
//! - Performance: Small overhead (format parsing per operation)
//! - Flexibility: Maximum - handles any format on a per-operation basis
//!
//! # Quick Reference
//!
//! | Type            | Format             | Use Case          | Performance         |
//! |-----------------|--------------------|-------------------|---------------------|
//! | `DsivC32`, etc. | Compile-time       | Known format      | Fastest (zero-cost) |
//! | `Ob`            | Runtime, mutable   | Config-driven     | Near-zero overhead  |
//! | `Omnib`       | Per-operation      | Multiple formats  | Small overhead      |
//!
//! # Typical Production Usage: Fixed ObtextCodec
//!
//! Best performance and type safety for multiple operations with the same format:
//!
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(all(feature = "dsiv", feature = "pgcmsiv"))]
//! # {
//! # use oboron::ObtextCodec;
//! # use oboron;
//! # let key = oboron::generate_key();
//! // Fixed format types (best performance for multiple operations with same format)
//! let dsiv = oboron::DsivC32::new(&key)?;  // "dsiv.c32" fixed-format ObtextCodec instance
//! let pgcmsiv = oboron::PgcmsivC32::new(&key)?;  // "pgcmsiv.c32" fixed-format ObtextCodec instance
//!
//! let ot_dsiv = dsiv.enc("data1")?;
//! let ot_pgcmsiv = pgcmsiv.enc("data2")?;
//!
//! // Decoding
//! let pt1 = dsiv.dec(&ot_dsiv)?;  // Decodes successfully
//! let pt2 = pgcmsiv.dec(&ot_pgcmsiv)?;
//! assert_eq!(pt1, "data1");
//! assert_eq!(pt2, "data2");
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! # Encryption Schemes
//!
//! All four core schemes are authenticated:
//!   - `Dgcmsiv`: deterministic AES-GCM-SIV
//!   - `Dsiv`: deterministic AES-SIV (nonce-misuse resistant)
//!   - `Pgcmsiv`: probabilistic AES-GCM-SIV
//!   - `Psiv`: probabilistic AES-SIV
//!
//! Unauthenticated (`upcbc`) and obfuscation (`zdcbc`) schemes are not
//! part of oboron — they live in the separate
//! [`obu`](https://gitlab.com/oboron/obu-rs) crate.
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
//! # Security
//!
//! oboron is a thin string/encoding layer over the
//! [`obcrypt`](https://docs.rs/obcrypt) authenticated-encryption core;
//! the cryptography, threat model, and usage limits are documented in
//! obcrypt's `SECURITY.md` and summarized in this crate's
//! [`SECURITY.md`](https://gitlab.com/oboron/oboron-rs/-/blob/master/oboron/SECURITY.md).
//! Key points:
//!
//! - **Not independently audited.** Neither oboron nor obcrypt has had
//!   an external security audit. Evaluate accordingly for
//!   high-assurance use.
//! - **Deterministic schemes use a fixed nonce.** `dsiv` / `dgcmsiv`
//!   encrypt under a constant (all-zero) nonce, sound *only* because
//!   AES-SIV / AES-GCM-SIV are nonce-misuse-resistant
//!   ([RFC 5297](https://www.rfc-editor.org/rfc/rfc5297),
//!   [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452)). The
//!   confidentiality cost is the deterministic-equality leak those
//!   schemes expose by design — equal plaintexts yield equal obtext.
//! - **The binding limit is data volume, not nonce reuse.** Security
//!   degrades only as the total data encrypted under one key
//!   approaches the AES-GCM-SIV birthday bound — far out of reach for
//!   the short-string workloads oboron targets. The library is
//!   stateless, so honoring that bound is a deployment responsibility:
//!   under high-volume use, rotate the master key well before it.
//! - **Keys are 128-character lowercase hex.** There is no base64 key
//!   encoding; generate keys with [`generate_key`].
//!
//! # The `ObtextCodec` Trait
//!
//! All types (`Ob`, `DsivC32`, `PsivB64`, etc.) except `Omnib` implement the `ObtextCodec` trait,
//! ```rust
//! # fn main() -> Result<(), oboron::Error> {
//! # #[cfg(feature = "dsiv")]
//! # {
//! # use oboron::{ObtextCodec, DsivC32, Ob};
//! # let key = oboron::generate_key();
//! fn process<O: ObtextCodec>(ob: &O, data: &str) -> Result<String, oboron::Error> {
//!     let ot = ob.enc(data)?;
//!     ob.dec(&ot)
//! }
//!
//! let dsiv = DsivC32::new(&key)?;
//! let ob = Ob::new("dsiv.c32", &key)?;
//!
//! process(&dsiv, "hello")?;
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
mod enc;
mod encoding;
mod error;
mod format;
mod keygen;
mod masterkey;
mod ob;
mod omnib;
mod scheme;

// Re-export public types and constants
pub use constants::{HARDCODED_KEY_BYTES, HARDCODED_KEY_HEX};
pub use error::Error;

pub(crate) use masterkey::MasterKey;

pub use keygen::generate_key;
pub use keygen::generate_key_bytes;
#[deprecated(
    since = "0.7.1",
    note = "use generate_key() — hex is now the default key format"
)]
#[allow(deprecated)]
pub use keygen::generate_key_hex;
// Re-export core types
pub use encoding::Encoding;
pub use format::Format;
pub use scheme::Scheme;

// Re-export Ob
pub use ob::Ob;

// Factory functions
pub use codec::{from_bytes, from_bytes_with_format};
pub use codec::{from_hex_key, from_hex_key_with_format};
pub use codec::{new, new_with_format, ObAny, ObtextCodec};
#[cfg(feature = "keyless")]
pub use codec::{new_keyless, new_keyless_with_format};

// Conditionally export format string constants (scheme+encoding combinations)
#[cfg(feature = "dgcmsiv")]
pub use constants::dgcmsiv_constants::*;
#[cfg(feature = "dsiv")]
pub use constants::dsiv_constants::*;
#[cfg(feature = "pgcmsiv")]
pub use constants::pgcmsiv_constants::*;
#[cfg(feature = "psiv")]
pub use constants::psiv_constants::*;
// Testing
#[cfg(feature = "mock")]
pub use constants::mock_constants::*;

#[cfg(feature = "dgcmsiv")]
pub use format::dgcmsiv_formats::*;
#[cfg(feature = "dsiv")]
pub use format::dsiv_formats::*;
#[cfg(feature = "pgcmsiv")]
pub use format::pgcmsiv_formats::*;
#[cfg(feature = "psiv")]
pub use format::psiv_formats::*;
// Testing
#[cfg(feature = "mock")]
pub use format::mock_formats::*;

// Conditionally export format-specific structs (scheme+encoding combinations)
#[cfg(feature = "dgcmsiv")]
pub use codec::{DgcmsivB32, DgcmsivB64, DgcmsivC32, DgcmsivHex};
#[cfg(feature = "dsiv")]
pub use codec::{DsivB32, DsivB64, DsivC32, DsivHex};
#[cfg(feature = "pgcmsiv")]
pub use codec::{PgcmsivB32, PgcmsivB64, PgcmsivC32, PgcmsivHex};
#[cfg(feature = "psiv")]
pub use codec::{PsivB32, PsivB64, PsivC32, PsivHex};
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
    #[cfg(feature = "dgcmsiv")]
    pub use crate::{DgcmsivB32, DgcmsivB64, DgcmsivC32, DgcmsivHex};
    #[cfg(feature = "dsiv")]
    pub use crate::{DsivB32, DsivB64, DsivC32, DsivHex};
    pub use crate::{Encoding, Error, Format, ObtextCodec, Scheme};
    pub use crate::{Ob, Omnib};
    #[cfg(feature = "pgcmsiv")]
    pub use crate::{PgcmsivB32, PgcmsivB64, PgcmsivC32, PgcmsivHex};
    #[cfg(feature = "psiv")]
    pub use crate::{PsivB32, PsivB64, PsivC32, PsivHex};
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
/// # #[cfg(feature = "dsiv")]
/// # {
/// # use oboron;
/// # let key = oboron::generate_key();
/// let ot = oboron::enc("secret data", "dsiv.b64", &key)?;
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
/// # #[cfg(feature = "dsiv")]
/// # {
/// # use oboron;
/// let ot = oboron::enc_keyless("test data", "dsiv.b64")?;
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
/// # #[cfg(feature = "dsiv")]
/// # use oboron;
/// # {
/// # let key = oboron::generate_key();
/// # let ot = oboron::enc("test123", "dsiv.b64", &key)?;
/// let pt2 = oboron::dec(&ot, "dsiv.b64", &key)?;
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
/// # #[cfg(feature = "dsiv")]
/// # {
/// # use oboron;
/// # let ot = oboron::enc_keyless("test", "dsiv.b64")?;
/// let pt2 = oboron::dec_keyless(&ot, "dsiv.b64")?;
/// # assert_eq!(pt2, "test");
/// # }
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "keyless")]
pub fn dec_keyless(obtext: &str, format: &str) -> Result<String, Error> {
    Omnib::new_keyless()?.dec(obtext, format)
}
