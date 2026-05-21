//! Decoding pipeline for z-tier schemes (obfuscation-only)

#![cfg(any(feature = "zrbcx", feature = "legacy", feature = "mock"))]

use crate::{constants::SCHEME_MARKER_SIZE, error::Error, Format, Scheme};

#[cfg(feature = "mock")]
use crate::decrypt_zmock1;
#[cfg(feature = "zrbcx")]
use crate::decrypt_zrbcx;

/// Z-tier decoding pipeline - takes 32-byte secret
#[inline(always)]
pub(crate) fn dec_from_format_ztier(
    obtext: &str,
    format: Format,
    secret: &[u8; 32],
) -> Result<String, Error> {
    let mut buffer = crate::dec::decode_obtext_to_payload(obtext, format.encoding())?;

    if buffer.len() < SCHEME_MARKER_SIZE {
        return Err(Error::PayloadTooShort);
    }

    // XOR and extract marker
    let len = buffer.len();
    let first_byte = buffer[0];
    let scheme_marker = [buffer[len - 2] ^ first_byte, buffer[len - 1] ^ first_byte];

    if scheme_marker != format.scheme().marker() {
        return Err(Error::SchemeMarkerMismatch);
    }

    buffer.truncate(len - SCHEME_MARKER_SIZE);

    // Decrypt using z-tier scheme-specific function
    let plaintext_bytes = match format.scheme() {
        #[cfg(feature = "zrbcx")]
        Scheme::Zrbcx => decrypt_zrbcx(secret, &buffer)?,
        #[cfg(feature = "mock")]
        Scheme::Zmock1 => decrypt_zmock1(secret, &buffer)?,
        #[cfg(feature = "legacy")]
        Scheme::Legacy => unreachable!("legacy uses separate path"),
        _ => return Err(Error::InvalidScheme),
    };

    #[cfg(feature = "unchecked-utf8")]
    {
        Ok(unsafe { String::from_utf8_unchecked(plaintext_bytes) })
    }
    #[cfg(not(feature = "unchecked-utf8"))]
    {
        String::from_utf8(plaintext_bytes).map_err(|_| Error::InvalidUtf8)
    }
}
