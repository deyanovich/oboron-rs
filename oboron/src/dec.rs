use crate::{
    base32::{BASE32_CROCKFORD, BASE32_RFC},
    constants::SCHEME_MARKER_SIZE,
    error::Error,
    Encoding, Format, Scheme,
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};

/// Generic decoding pipeline.
///
/// Decodes obtext to payload bytes, undoes the 2-byte XOR'd marker
/// framing, verifies the marker matches the expected scheme, then
/// calls obcrypt's per-scheme `decrypt` directly. Bypasses
/// `obcrypt::decrypt_as` deliberately — same reason as the encrypt
/// path: extra framed-API indirection costs measurable time on this
/// hot path under `opt-level = "z"`.
#[inline(always)]
pub(crate) fn dec_from_format(
    obtext: &str,
    format: Format,
    master_key: &obcrypt::Key,
) -> Result<String, Error> {
    let mut buffer = decode_obtext_to_payload(obtext, format.encoding())?;

    if buffer.len() < SCHEME_MARKER_SIZE {
        return Err(Error::PayloadTooShort);
    }

    // Undo XOR'd marker, validate, truncate.
    let len = buffer.len();
    let first_byte = buffer[0];
    let scheme_marker = [buffer[len - 2] ^ first_byte, buffer[len - 1] ^ first_byte];
    if scheme_marker != format.scheme().marker() {
        return Err(Error::SchemeMarkerMismatch);
    }
    buffer.truncate(len - SCHEME_MARKER_SIZE);

    let plaintext_bytes = match format.scheme() {
        #[cfg(feature = "aags")]
        Scheme::Aags => obcrypt::schemes::aags::decrypt(&buffer, master_key)?,
        #[cfg(feature = "apgs")]
        Scheme::Apgs => obcrypt::schemes::apgs::decrypt(&buffer, master_key)?,
        #[cfg(feature = "aasv")]
        Scheme::Aasv => obcrypt::schemes::aasv::decrypt(&buffer, master_key)?,
        #[cfg(feature = "apsv")]
        Scheme::Apsv => obcrypt::schemes::apsv::decrypt(&buffer, master_key)?,
        #[cfg(feature = "upbc")]
        Scheme::Upbc => obcrypt::schemes::upbc::decrypt(&buffer, master_key)?,
        #[cfg(feature = "mock")]
        Scheme::Mock1 => obcrypt::schemes::mock1::decrypt(&buffer, master_key)?,
        #[cfg(feature = "mock")]
        Scheme::Mock2 => obcrypt::schemes::mock2::decrypt(&buffer, master_key)?,
        #[cfg(feature = "zrbcx")]
        Scheme::Zrbcx => unreachable!("ztier uses separate path"),
        #[cfg(feature = "mock")]
        Scheme::Zmock1 => unreachable!("ztier uses separate path"),
        #[cfg(feature = "legacy")]
        Scheme::Legacy => unreachable!("legacy uses separate path"),
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

/// Decode text encoding to raw bytes.
#[inline]
pub(crate) fn decode_obtext_to_payload(obtext: &str, encoding: Encoding) -> Result<Vec<u8>, Error> {
    match encoding {
        Encoding::B32 => BASE32_RFC
            .decode(obtext.as_bytes())
            .map_err(|_| Error::InvalidB32),
        Encoding::C32 => BASE32_CROCKFORD
            .decode(obtext.as_bytes())
            .map_err(|_| Error::InvalidC32),
        Encoding::B64 => BASE64URL_NOPAD
            .decode(obtext.as_bytes())
            .map_err(|_| Error::InvalidB64),
        Encoding::Hex => HEXLOWER
            .decode(obtext.as_bytes())
            .map_err(|_| Error::InvalidHex),
    }
}
