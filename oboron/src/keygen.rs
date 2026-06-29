use rand::RngCore;
use zeroize::Zeroizing;

/// Generate a cryptographically secure random 64-byte key and return
/// it as a 128-character lowercase hex string.
///
/// Hex is the canonical text encoding for oboron keys. The string
/// can be passed directly to `Omnib::new` / `Ob::new` / any
/// fixed-format codec's `::new` constructor.
///
/// # Examples
///
/// ```
/// use oboron::generate_key;
///
/// let key = generate_key();
/// assert_eq!(key.len(), 128);
/// ```
#[must_use]
pub fn generate_key() -> String {
    // Zeroize the raw key bytes once they've been hex-encoded; the
    // returned hex String is the caller's to manage.
    let mut key_bytes = Zeroizing::new([0u8; 64]);
    rand::thread_rng().fill_bytes(&mut *key_bytes);
    // Encode from a slice so no un-zeroized array copy is created.
    hex::encode(key_bytes.as_slice())
}

/// Deprecated alias for [`generate_key`].
///
/// # Examples
///
/// ```
/// # #![allow(deprecated)]
/// use oboron::generate_key_hex;
///
/// let key = generate_key_hex();
/// assert_eq!(key.len(), 128);
/// ```
#[must_use]
#[deprecated(
    since = "0.7.1",
    note = "use generate_key() — hex is now the default key format"
)]
pub fn generate_key_hex() -> String {
    generate_key()
}

/// Generate a cryptographically secure random 64-byte key as raw bytes.
///
/// # Examples
///
/// ```
/// use oboron::generate_key_bytes;
///
/// let key = generate_key_bytes();
/// assert_eq!(key.len(), 64);
/// ```
#[must_use]
pub fn generate_key_bytes() -> [u8; 64] {
    let mut key_bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    key_bytes
}

// Secret generation for the unauthenticated/obfuscation schemes
// (32-byte secrets) lives in the separate `obu` crate — oboron is
// authenticated-only.
