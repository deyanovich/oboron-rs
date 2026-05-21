use crate::{
    base32::{BASE32_CROCKFORD, BASE32_RFC},
    error::Error,
    Encoding, Format, Scheme,
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};

/// Generic encoding pipeline.
///
/// Calls obcrypt's per-scheme `encrypt` directly (Vec-returning form),
/// then appends the 2-byte XOR'd scheme marker in place, then encodes
/// to obtext. Bypasses `obcrypt::encrypt_into` deliberately — that
/// framed API's extra layer of indirection costs measurable time on
/// this hot path under `opt-level = "z"`. The static-dispatch codec
/// macros (`AasvC32` etc.) use the same pattern.
///
/// Z-tier schemes use a separate path (see `ztier` module) and are
/// `unreachable!` here.
#[inline(always)]
pub(crate) fn enc_to_format(
    plaintext: &str,
    format: Format,
    master_key: &obcrypt::Key,
) -> Result<String, Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    let mut ciphertext: Vec<u8> = match format.scheme() {
        #[cfg(feature = "aags")]
        Scheme::Aags => obcrypt::schemes::aags::encrypt(plaintext.as_bytes(), master_key)?,
        #[cfg(feature = "apgs")]
        Scheme::Apgs => obcrypt::schemes::apgs::encrypt(plaintext.as_bytes(), master_key)?,
        #[cfg(feature = "aasv")]
        Scheme::Aasv => obcrypt::schemes::aasv::encrypt(plaintext.as_bytes(), master_key)?,
        #[cfg(feature = "apsv")]
        Scheme::Apsv => obcrypt::schemes::apsv::encrypt(plaintext.as_bytes(), master_key)?,
        #[cfg(feature = "upbc")]
        Scheme::Upbc => obcrypt::schemes::upbc::encrypt(plaintext.as_bytes(), master_key)?,
        #[cfg(feature = "mock")]
        Scheme::Mock1 => obcrypt::schemes::mock1::encrypt(plaintext.as_bytes(), master_key)?,
        #[cfg(feature = "mock")]
        Scheme::Mock2 => obcrypt::schemes::mock2::encrypt(plaintext.as_bytes(), master_key)?,
        #[cfg(feature = "zrbcx")]
        Scheme::Zrbcx => unreachable!("ztier uses separate path"),
        #[cfg(feature = "mock")]
        Scheme::Zmock1 => unreachable!("ztier uses separate path"),
        #[cfg(feature = "legacy")]
        Scheme::Legacy => unreachable!("legacy uses separate path"),
    };

    // Append marker + XOR with first ciphertext byte.
    let marker = format.scheme().marker();
    let first_byte = ciphertext[0];
    ciphertext.push(marker[0] ^ first_byte);
    ciphertext.push(marker[1] ^ first_byte);

    Ok(match format.encoding() {
        Encoding::C32 => BASE32_CROCKFORD.encode(&ciphertext),
        Encoding::B32 => BASE32_RFC.encode(&ciphertext),
        Encoding::B64 => BASE64URL_NOPAD.encode(&ciphertext),
        Encoding::Hex => HEXLOWER.encode(&ciphertext),
    })
}
