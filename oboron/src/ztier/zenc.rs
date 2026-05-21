//! Encoding pipeline for z-tier schemes (obfuscation-only)

#![cfg(any(feature = "zrbcx", feature = "legacy", feature = "mock"))]

use crate::{
    base32::{BASE32_CROCKFORD, BASE32_RFC},
    error::Error,
    Encoding, Format, Scheme,
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};

#[cfg(feature = "mock")]
use crate::encrypt_zmock1;
#[cfg(feature = "zrbcx")]
use crate::encrypt_zrbcx;

/// Z-tier encoding pipeline - takes 32-byte secret
#[inline(always)]
pub(crate) fn enc_to_format_ztier(
    plaintext: &str,
    format: Format,
    secret: &[u8; 32],
) -> Result<String, Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    // Encrypt using z-tier scheme-specific function
    let mut ciphertext: Vec<u8> = match format.scheme() {
        #[cfg(feature = "zrbcx")]
        Scheme::Zrbcx => encrypt_zrbcx(secret, plaintext.as_bytes())?,
        #[cfg(feature = "mock")]
        Scheme::Zmock1 => encrypt_zmock1(secret, plaintext.as_bytes())?,
        #[cfg(feature = "legacy")]
        Scheme::Legacy => unreachable!("legacy uses separate path"),
        _ => return Err(Error::InvalidScheme),
    };

    // Append marker and XOR
    let marker = format.scheme().marker();
    let first_byte = ciphertext[0];
    ciphertext.push(marker[0] ^ first_byte);
    ciphertext.push(marker[1] ^ first_byte);

    // Encode
    Ok(match format.encoding() {
        Encoding::C32 => BASE32_CROCKFORD.encode(&ciphertext),
        Encoding::B32 => BASE32_RFC.encode(&ciphertext),
        Encoding::B64 => BASE64URL_NOPAD.encode(&ciphertext),
        Encoding::Hex => HEXLOWER.encode(&ciphertext),
    })
}
