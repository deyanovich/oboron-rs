//! Autodetection for z-tier schemes (zrbcx, legacy)

#![cfg(any(feature = "zrbcx", feature = "legacy", feature = "mock"))]

use super::zsecret::ZSecret;
use crate::{constants::SCHEME_MARKER_SIZE, error::Error, Encoding};

#[cfg(feature = "mock")]
use super::zmock1::decrypt_zmock1;
#[cfg(feature = "mock")]
use crate::constants::ZMOCK1_MARKER;
#[cfg(feature = "zrbcx")]
use crate::{constants::ZRBCX_MARKER, decrypt_zrbcx};

#[cfg(feature = "legacy")]
use super::legacy::decrypt_legacy;

/// Decode the given encoding, then decrypt autodetecting the z-tier scheme
///
/// This function handles z-tier schemes (zrbcx, legacy) with legacy fallback.  
/// If the payload doesn't have a valid scheme marker or decoding fails,
/// it attempts legacy decryption as a fallback.
pub(crate) fn dec_any_scheme_ztier(
    zsecret: &ZSecret,
    encoding: Encoding,
    obtext: &str,
) -> Result<String, Error> {
    // Step 1: Try to decode obtext using encoding
    let mut buffer = match crate::dec::decode_obtext_to_payload(obtext, encoding) {
        Ok(ct) => ct,
        Err(decode_err) => {
            // Decoding failed - try legacy fallback
            #[cfg(feature = "legacy")]
            {
                return dec_legacy_fallback(zsecret, obtext).or(Err(decode_err));
            }
            #[cfg(not(feature = "legacy"))]
            return Err(decode_err);
        }
    };

    if buffer.len() < SCHEME_MARKER_SIZE {
        // Payload too short for modern scheme - try legacy
        #[cfg(feature = "legacy")]
        {
            return dec_legacy_fallback(zsecret, obtext).or(Err(Error::PayloadTooShort));
        }
        #[cfg(not(feature = "legacy"))]
        return Err(Error::PayloadTooShort);
    }

    // Step 2: XOR the last two bytes with the first two to undo mixing
    let len = buffer.len();
    buffer[len - 1] ^= buffer[0];
    buffer[len - 2] ^= buffer[0];

    // Step 3: Extract 2-byte scheme marker from end
    let scheme_marker = [buffer[len - 2], buffer[len - 1]];
    buffer.truncate(len - SCHEME_MARKER_SIZE);

    // Step 4: Match scheme marker and decrypt with available Z-TIER schemes
    #[cfg(feature = "zrbcx")]
    if scheme_marker == ZRBCX_MARKER {
        let plaintext_bytes = decrypt_zrbcx(zsecret.zrbcx(), &buffer)?;
        return bytes_to_string(plaintext_bytes);
    }
    #[cfg(feature = "mock")]
    if scheme_marker == ZMOCK1_MARKER {
        let plaintext_bytes = decrypt_zmock1(zsecret.zmock1(), &buffer)?;
        return bytes_to_string(plaintext_bytes);
    }

    // Unknown scheme marker - try legacy as fallback
    #[cfg(feature = "legacy")]
    {
        let legacy_result = dec_legacy_fallback(zsecret, obtext)?;
        // Only validate legacy fallback results to avoid false positives
        validate_legacy_output(&legacy_result)?;
        return Ok(legacy_result);
    }

    #[cfg(not(feature = "legacy"))]
    Err(Error::UnknownScheme)
}

/// Helper function to convert bytes to string
#[inline]
fn bytes_to_string(plaintext_bytes: Vec<u8>) -> Result<String, Error> {
    #[cfg(feature = "unchecked-utf8")]
    {
        Ok(unsafe { String::from_utf8_unchecked(plaintext_bytes) })
    }

    #[cfg(not(feature = "unchecked-utf8"))]
    {
        String::from_utf8(plaintext_bytes).map_err(|_| Error::InvalidUtf8)
    }
}

/// Helper function to attempt legacy decryption using B32 encoding.
///
/// Legacy always uses lowercase RFC base32 (BASE32_RFC_LOWER) for encoding,
/// so this function always decodes with B32 regardless of the caller's encoding context.
#[cfg(feature = "legacy")]
fn dec_legacy_fallback(zsecret: &ZSecret, obtext: &str) -> Result<String, Error> {
    // Reverse the obtext before decoding (matches Legacy::dec behaviour)
    let reversed: Vec<u8> = obtext.bytes().rev().collect();
    // Decode using lowercase RFC base32 (the only encoding legacy uses)
    let ciphertext = crate::base32::BASE32_RFC_LOWER
        .decode(&reversed)
        .map_err(|_| Error::InvalidB32)?;
    // Decrypt using legacy AES-CBC
    let plaintext_bytes = decrypt_legacy(zsecret.legacy(), &ciphertext)?;
    bytes_to_string(plaintext_bytes)
}

/// Validate that legacy fallback output looks reasonable
/// This helps avoid false positives when legacy decryption "succeeds" with wrong key
#[cfg(feature = "legacy")]
fn validate_legacy_output(output: &str) -> Result<(), Error> {
    // Check that output contains mostly printable ASCII or valid UTF-8
    // If it's mostly garbage bytes, it's probably a decryption failure
    let printable_count = output
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_whitespace())
        .count();
    let total_count = output.chars().count();

    if total_count > 0 && (printable_count as f32 / total_count as f32) < 0.5 {
        return Err(Error::InvalidLegacyOutput);
    }

    Ok(())
}

/// Decode c32, autodetect the z-tier scheme and decrypt accordingly
#[allow(dead_code)] // May be used by Zob in the future
pub(crate) fn dec_any_scheme_c32_ztier(zsecret: &ZSecret, obtext: &str) -> Result<String, Error> {
    dec_any_scheme_ztier(zsecret, Encoding::C32, obtext)
}

/// Decode b32, autodetect the z-tier scheme and decrypt accordingly
#[allow(dead_code)] // May be used by Zob in the future
pub(crate) fn dec_any_scheme_b32_ztier(zsecret: &ZSecret, obtext: &str) -> Result<String, Error> {
    dec_any_scheme_ztier(zsecret, Encoding::B32, obtext)
}

/// Decode b64, autodetect the z-tier scheme and decrypt accordingly
#[allow(dead_code)] // May be used by Zob in the future
pub(crate) fn dec_any_scheme_b64_ztier(zsecret: &ZSecret, obtext: &str) -> Result<String, Error> {
    dec_any_scheme_ztier(zsecret, Encoding::B64, obtext)
}

/// Decode hex, autodetect the z-tier scheme and decrypt accordingly
#[allow(dead_code)] // May be used by Zob in the future
pub(crate) fn dec_any_scheme_hex_ztier(zsecret: &ZSecret, obtext: &str) -> Result<String, Error> {
    dec_any_scheme_ztier(zsecret, Encoding::Hex, obtext)
}

/// Autodetect both the encoding and z-tier scheme, then decode accordingly.
///
/// This function analyzes the characteristics of the input text to determine
/// the most likely encoding format, then delegates to the appropriate decoder.
/// If the most likely encoding fails, it falls back to trying other encodings.
///
/// Detection logic:
/// 1. If text contains '-', '_', or uppercase letters -> B64 (definitive)
/// 2. Else if text contains non-hex lowercase letters (g-z) -> Try Base32, fallback to B64
/// 3. Else -> Try Hex, fallback to Base32, then B64
pub(crate) fn dec_any_format_ztier(zsecret: &ZSecret, obtext: &str) -> Result<String, Error> {
    // Check for B64 indicators:  '-', '_', or mixed case letters (definitive)
    if obtext.contains('-')
        || obtext.contains('_')
        || (obtext.chars().any(|c| c.is_ascii_lowercase())
            && obtext.chars().any(|c| c.is_ascii_uppercase()))
    {
        if let Ok(result) = dec_any_scheme_b64_ztier(zsecret, obtext) {
            return Ok(result);
        }
    }

    // Check for uppercase letters, indicating B32
    if obtext.chars().any(|c| c.is_ascii_uppercase()) {
        // Try B32 first, fallback to B64 (no point trying hex)
        if let Ok(result) = dec_any_scheme_b32_ztier(zsecret, obtext) {
            return Ok(result);
        }
        if let Ok(result) = dec_any_scheme_b64_ztier(zsecret, obtext) {
            return Ok(result);
        }
    }

    // Check for non-hex lowercase letters (g-z), indicating C32
    if obtext.chars().any(|c| c.is_ascii_lowercase() && c > 'f') {
        // Try C32 first, fallback to B64 (no point trying hex)
        if let Ok(result) = dec_any_scheme_c32_ztier(zsecret, obtext) {
            return Ok(result);
        }
        if let Ok(result) = dec_any_scheme_b64_ztier(zsecret, obtext) {
            return Ok(result);
        }
    }

    // Likely hex - try Hex, then Base32, then B64
    if let Ok(result) = dec_any_scheme_hex_ztier(zsecret, obtext) {
        return Ok(result);
    }
    if let Ok(result) = dec_any_scheme_c32_ztier(zsecret, obtext) {
        return Ok(result);
    }
    dec_any_scheme_b64_ztier(zsecret, obtext)
}
