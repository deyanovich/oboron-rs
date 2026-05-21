#[cfg(feature = "base64-keys")]
use data_encoding::BASE64URL_NOPAD;
use rand::RngCore;

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
    let mut key_bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    hex::encode(key_bytes)
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

/// Generate a cryptographically secure random 64-byte key and return
/// it as an 86-character base64 string.
///
/// Deprecated: oboron is moving to hex-only keys before v1.0. Use
/// [`generate_key`] instead.
///
/// The returned string is guaranteed to contain no `-` or `_` characters
/// (so it remains double-click-selectable in GUIs).
#[must_use]
#[cfg(feature = "base64-keys")]
#[deprecated(
    since = "0.7.1",
    note = "use generate_key() instead; base64 key support will be removed before oboron 1.0"
)]
pub fn generate_key_base64() -> String {
    loop {
        let mut key_bytes = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let key_base64 = BASE64URL_NOPAD.encode(&key_bytes);
        if !key_base64.contains('-') && !key_base64.contains('_') {
            return key_base64;
        }
    }
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

/// Generate a random 32-byte secret and return it as a 64-character
/// lowercase hex string.
///
/// Hex is the canonical text encoding for oboron secrets (z-tier).
///
/// # Examples
///
/// ```
/// use oboron::generate_secret;
///
/// let secret = generate_secret();
/// assert_eq!(secret.len(), 64);
/// ```
#[must_use]
pub fn generate_secret() -> String {
    let mut secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    hex::encode(secret_bytes)
}

/// Deprecated alias for [`generate_secret`].
#[must_use]
#[deprecated(
    since = "0.7.1",
    note = "use generate_secret() — hex is now the default secret format"
)]
pub fn generate_secret_hex() -> String {
    generate_secret()
}

/// Generate a random 32-byte secret and return it as a 43-character
/// base64 string.
///
/// Deprecated: oboron is moving to hex-only encodings before v1.0.
/// Use [`generate_secret`] instead.
#[must_use]
#[cfg(feature = "base64-keys")]
#[deprecated(
    since = "0.7.1",
    note = "use generate_secret() instead; base64 support will be removed before oboron 1.0"
)]
pub fn generate_secret_base64() -> String {
    loop {
        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let key_base64 = BASE64URL_NOPAD.encode(&key_bytes);
        if !key_base64.contains('-') && !key_base64.contains('_') {
            return key_base64;
        }
    }
}

/// Generate a random 32-byte secret as raw bytes.
///
/// # Examples
///
/// ```
/// use oboron::generate_secret_bytes;
///
/// let secret_bytes = generate_secret_bytes();
/// assert_eq!(secret_bytes.len(), 32);
/// ```
#[must_use]
pub fn generate_secret_bytes() -> [u8; 32] {
    let mut secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    secret_bytes
}
