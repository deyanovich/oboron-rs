use crate::{
    base32::{BASE32_CROCKFORD, BASE32_RFC},
    error::Error,
    Encoding, Format, Scheme,
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};

/// Generic decoding pipeline.
///
/// Decodes obtext to the scheme output bytes, then calls obcrypt's
/// per-scheme `decrypt` directly. The obtext carries no scheme marker
/// (the no-marker model): the scheme is fixed by `format`, and
/// supplying the wrong scheme fails the AEAD tag check
/// (`DecryptionFailed`) rather than being caught by a marker compare.
/// Bypasses `obcrypt::decrypt` deliberately — same hot-path reason as
/// the encrypt path.
#[inline(always)]
pub(crate) fn dec_from_format(
    obtext: &str,
    format: Format,
    master_key: &obcrypt::Key,
) -> Result<String, Error> {
    let buffer = decode_obtext_to_payload(obtext, format.encoding())?;

    let plaintext_bytes = match format.scheme() {
        #[cfg(feature = "dgcmsiv")]
        Scheme::Dgcmsiv => obcrypt::schemes::dgcmsiv::decrypt(&buffer, master_key)?,
        #[cfg(feature = "pgcmsiv")]
        Scheme::Pgcmsiv => obcrypt::schemes::pgcmsiv::decrypt(&buffer, master_key)?,
        #[cfg(feature = "dsiv")]
        Scheme::Dsiv => obcrypt::schemes::dsiv::decrypt(&buffer, master_key)?,
        #[cfg(feature = "psiv")]
        Scheme::Psiv => obcrypt::schemes::psiv::decrypt(&buffer, master_key)?,
        #[cfg(feature = "mock")]
        Scheme::Mock1 => obcrypt::schemes::mock1::decrypt(&buffer, master_key)?,
        #[cfg(feature = "mock")]
        Scheme::Mock2 => obcrypt::schemes::mock2::decrypt(&buffer, master_key)?,
    };

    // The core dec path always validates UTF-8 (spec §4.1): a decrypt
    // must never hand back an unchecked `String`. Callers needing raw
    // bytes (non-UTF-8 plaintext) should use obcrypt's bytes-in/bytes-out
    // core directly.
    String::from_utf8(plaintext_bytes).map_err(|_| Error::InvalidUtf8)
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
