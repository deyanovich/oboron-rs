use crate::{
    base32::{BASE32_CROCKFORD, BASE32_RFC},
    error::Error,
    Encoding, Format, Scheme,
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};

/// Generic encoding pipeline.
///
/// Calls obcrypt's per-scheme `encrypt` directly (Vec-returning form),
/// then encodes the scheme output to obtext. The obtext is the text
/// encoding of the raw AEAD output and nothing more — there is no
/// scheme marker on the wire; the scheme is supplied by the caller
/// (the no-marker model). Bypasses `obcrypt::encrypt` deliberately —
/// that dispatch layer's extra indirection costs measurable time on
/// this hot path. The static-dispatch codec macros (`DsivC32` etc.)
/// use the same pattern.
#[inline(always)]
pub(crate) fn enc_to_format(
    plaintext: &str,
    format: Format,
    master_key: &obcrypt::Key,
) -> Result<String, Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    let scheme_output: Vec<u8> = match format.scheme() {
        #[cfg(feature = "dgcmsiv")]
        Scheme::Dgcmsiv => obcrypt::schemes::dgcmsiv::encrypt(plaintext.as_bytes(), master_key)?,
        #[cfg(feature = "pgcmsiv")]
        Scheme::Pgcmsiv => obcrypt::schemes::pgcmsiv::encrypt(plaintext.as_bytes(), master_key)?,
        #[cfg(feature = "dsiv")]
        Scheme::Dsiv => obcrypt::schemes::dsiv::encrypt(plaintext.as_bytes(), master_key)?,
        #[cfg(feature = "psiv")]
        Scheme::Psiv => obcrypt::schemes::psiv::encrypt(plaintext.as_bytes(), master_key)?,
        #[cfg(feature = "mock")]
        Scheme::Mock1 => obcrypt::schemes::mock1::encrypt(plaintext.as_bytes(), master_key)?,
        #[cfg(feature = "mock")]
        Scheme::Mock2 => obcrypt::schemes::mock2::encrypt(plaintext.as_bytes(), master_key)?,
    };

    Ok(match format.encoding() {
        Encoding::C32 => BASE32_CROCKFORD.encode(&scheme_output),
        Encoding::B32 => BASE32_RFC.encode(&scheme_output),
        Encoding::B64 => BASE64URL_NOPAD.encode(&scheme_output),
        Encoding::Hex => HEXLOWER.encode(&scheme_output),
    })
}
