use crate::{constants::SCHEME_MARKER_SIZE, error::Error, Encoding, MasterKey};

#[cfg(feature = "aags")]
use crate::constants::AAGS_MARKER;
#[cfg(feature = "aasv")]
use crate::constants::AASV_MARKER;
#[cfg(feature = "apgs")]
use crate::constants::APGS_MARKER;
#[cfg(feature = "apsv")]
use crate::constants::APSV_MARKER;
#[cfg(feature = "upbc")]
use crate::constants::UPBC_MARKER;
#[cfg(feature = "mock")]
use crate::constants::{MOCK1_MARKER, MOCK2_MARKER};

/// Decode the given encoding, then decrypt autodetecting the scheme (SECURE SCHEMES ONLY).
///
/// Matches on the local marker constants and dispatches directly to
/// `obcrypt::schemes::*::decrypt`. Bypasses `obcrypt::decrypt` for the
/// same hot-path-indirection reason as `dec_from_format`.
pub fn dec_any_scheme(
    masterkey: &MasterKey,
    encoding: Encoding,
    obtext: &str,
) -> Result<String, Error> {
    let mut buffer = crate::dec::decode_obtext_to_payload(obtext, encoding)?;

    if buffer.len() < SCHEME_MARKER_SIZE {
        return Err(Error::PayloadTooShort);
    }

    // Undo XOR'd marker in place.
    let len = buffer.len();
    buffer[len - 1] ^= buffer[0];
    buffer[len - 2] ^= buffer[0];

    let scheme_marker = [buffer[len - 2], buffer[len - 1]];
    buffer.truncate(len - SCHEME_MARKER_SIZE);

    let plaintext_bytes = match scheme_marker {
        #[cfg(feature = "upbc")]
        UPBC_MARKER => obcrypt::schemes::upbc::decrypt(&buffer, masterkey.obcrypt_key())?,
        #[cfg(feature = "aags")]
        AAGS_MARKER => obcrypt::schemes::aags::decrypt(&buffer, masterkey.obcrypt_key())?,
        #[cfg(feature = "apgs")]
        APGS_MARKER => obcrypt::schemes::apgs::decrypt(&buffer, masterkey.obcrypt_key())?,
        #[cfg(feature = "aasv")]
        AASV_MARKER => obcrypt::schemes::aasv::decrypt(&buffer, masterkey.obcrypt_key())?,
        #[cfg(feature = "apsv")]
        APSV_MARKER => obcrypt::schemes::apsv::decrypt(&buffer, masterkey.obcrypt_key())?,
        #[cfg(feature = "mock")]
        MOCK1_MARKER => obcrypt::schemes::mock1::decrypt(&buffer, masterkey.obcrypt_key())?,
        #[cfg(feature = "mock")]
        MOCK2_MARKER => obcrypt::schemes::mock2::decrypt(&buffer, masterkey.obcrypt_key())?,
        _ => return Err(Error::UnknownScheme),
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

/// Decode c32, autodetect the scheme and decrypt accordingly
pub(crate) fn dec_any_scheme_c32(masterkey: &MasterKey, obtext: &str) -> Result<String, Error> {
    dec_any_scheme(masterkey, Encoding::C32, obtext)
}

/// Decode b32, autodetect the scheme and decrypt accordingly
pub(crate) fn dec_any_scheme_b32(masterkey: &MasterKey, obtext: &str) -> Result<String, Error> {
    dec_any_scheme(masterkey, Encoding::B32, obtext)
}

/// Decode b64, autodetect the scheme and decrypt accordingly
pub(crate) fn dec_any_scheme_b64(masterkey: &MasterKey, obtext: &str) -> Result<String, Error> {
    dec_any_scheme(masterkey, Encoding::B64, obtext)
}

/// Decode hex, autodetect the scheme and decrypt accordingly
pub(crate) fn dec_any_scheme_hex(masterkey: &MasterKey, obtext: &str) -> Result<String, Error> {
    dec_any_scheme(masterkey, Encoding::Hex, obtext)
}

/// Autodetect both the encoding and scheme, then decode accordingly (SECURE SCHEMES ONLY).
///
/// This function analyzes the characteristics of the input text to determine
/// the most likely encoding format, then delegates to the appropriate decoder.
/// If the most likely encoding fails, it falls back to trying other encodings.
///
/// Detection logic:
/// 1. If text contains '-', '_', or uppercase letters -> B64 (definitive)
/// 2. Else if text contains non-hex lowercase letters (g-z) -> Try Base32, fallback to B64
/// 3. Else -> Try Hex, fallback to Base32, then B64
pub fn dec_any_format(masterkey: &MasterKey, obtext: &str) -> Result<String, Error> {
    // Single-pass classification
    let mut has_dash = false;
    let mut has_underscore = false;
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_non_hex_lower = false;

    for b in obtext.bytes() {
        match b {
            b'-' => has_dash = true,
            b'_' => has_underscore = true,
            b'A'..=b'Z' => has_upper = true,
            b'a'..=b'f' => has_lower = true,
            b'g'..=b'z' => {
                has_lower = true;
                has_non_hex_lower = true;
            }
            _ => {}
        }
    }

    // Check for B64 indicators: '-', '_', or mixed case letters (definitive)
    if has_dash || has_underscore || (has_lower && has_upper) {
        if let Ok(result) = dec_any_scheme_b64(masterkey, obtext) {
            return Ok(result);
        }
    }

    // Check for uppercase letters, indicating B32
    if has_upper {
        // Try B32 first, fallback to B64 (no point trying hex)
        if let Ok(result) = dec_any_scheme_b32(masterkey, obtext) {
            return Ok(result);
        }
        if let Ok(result) = dec_any_scheme_b64(masterkey, obtext) {
            return Ok(result);
        }
    }

    // Check for non-hex lowercase letters (g-z), indicating C32
    if has_non_hex_lower {
        // Try C32 first, fallback to B64 (no point trying hex)
        if let Ok(result) = dec_any_scheme_c32(masterkey, obtext) {
            return Ok(result);
        }
        if let Ok(result) = dec_any_scheme_b64(masterkey, obtext) {
            return Ok(result);
        }
    }

    // Likely hex - try Hex, then Base32, then B64
    if let Ok(result) = dec_any_scheme_hex(masterkey, obtext) {
        return Ok(result);
    }
    if let Ok(result) = dec_any_scheme_c32(masterkey, obtext) {
        return Ok(result);
    }
    dec_any_scheme_b64(masterkey, obtext)
}
