#![cfg(feature = "legacy")]

use crate::constants::HARDCODED_SECRET_BYTES;
use crate::{error::Error, Encoding, Format, ObtextCodec, Scheme};

// Re-use ZSecret from zcodec module
use super::constants::AES_BLOCK_SIZE;
use super::zsecret::ZSecret;

const LEGACY_PADDING_BYTE: u8 = b'=';

/// **DEPRECATED** Legacy codec.
///
/// ⚠️ This scheme exists for compatibility only.
/// Use secure schemes for new code.
///
/// Format: `"legacy"`
pub struct Legacy {
    zsecret: ZSecret,
}

impl Legacy {
    /// Create with a 43-character base64 secret string
    pub fn new(secret: &str) -> Result<Self, Error> {
        Ok(Self {
            zsecret: ZSecret::from_base64(secret)?,
        })
    }

    /// Create from raw 32-byte master secret (used internally by Obz routing)
    pub(crate) fn from_master_secret(secret: &[u8; 32]) -> Result<Self, Error> {
        Ok(Self {
            zsecret: ZSecret::from_bytes(secret)?,
        })
    }

    /// Create with hardcoded secret (testing/obfuscation only)
    #[cfg(feature = "keyless")]
    pub fn new_keyless() -> Result<Self, Error> {
        Ok(Self {
            zsecret: ZSecret::from_bytes(&HARDCODED_SECRET_BYTES)?,
        })
    }

    /// Create from a 64-character hex secret string
    pub fn from_hex_secret(secret_hex: &str) -> Result<Self, Error> {
        Ok(Self {
            zsecret: ZSecret::from_hex(secret_hex)?,
        })
    }

    /// Create from a 32-byte secret
    pub fn from_bytes(secret_bytes: &[u8; 32]) -> Result<Self, Error> {
        Ok(Self {
            zsecret: ZSecret::from_bytes(secret_bytes)?,
        })
    }

    pub fn secret(&self) -> String {
        self.zsecret.secret_base64()
    }

    pub fn secret_hex(&self) -> String {
        self.zsecret.secret_hex()
    }

    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.zsecret.secret_bytes()
    }
}

impl ObtextCodec for Legacy {
    fn enc(&self, plaintext: &str) -> Result<String, Error> {
        let plaintext_bytes = plaintext.as_bytes();
        if plaintext_bytes.is_empty() {
            return Err(Error::EmptyPlaintext);
        }

        // Encrypt using legacy AES-CBC
        let ciphertext = encrypt_legacy(self.zsecret.master_secret(), plaintext_bytes)?;

        // Encode using lowercase RFC base32
        let mut s = crate::base32::BASE32_RFC_LOWER.encode(&ciphertext);
        // Reverse the obtext string in-place for prefix entropy (all encodings are ASCII)
        // SAFETY: lowercase RFC base32 produces ASCII-only output, so byte-level reversal
        // cannot split any multi-byte UTF-8 sequence.
        debug_assert!(s.is_ascii(), "encoding produced non-ASCII output");
        unsafe { s.as_bytes_mut() }.reverse();
        Ok(s)
    }

    fn dec(&self, obtext: &str) -> Result<String, Error> {
        // Reverse the obtext before decoding (single allocation; all encodings are ASCII)
        let reversed: Vec<u8> = obtext.bytes().rev().collect();
        // Decode using lowercase RFC base32
        let ciphertext = crate::base32::BASE32_RFC_LOWER
            .decode(&reversed)
            .map_err(|_| Error::InvalidB32)?;

        // Decrypt using legacy AES-CBC
        let plaintext_bytes = decrypt_legacy(self.zsecret.master_secret(), &ciphertext)?;

        // Convert to string
        #[cfg(feature = "unchecked-utf8")]
        {
            Ok(unsafe { String::from_utf8_unchecked(plaintext_bytes) })
        }

        #[cfg(not(feature = "unchecked-utf8"))]
        {
            String::from_utf8(plaintext_bytes).map_err(|_| Error::InvalidUtf8)
        }
    }

    fn format(&self) -> Format {
        Format::new(Scheme::Legacy, Encoding::B32)
    }

    fn scheme(&self) -> Scheme {
        Scheme::Legacy
    }

    fn encoding(&self) -> Encoding {
        Encoding::B32
    }
}

// Inherent methods
impl Legacy {
    #[inline]
    pub fn enc(&self, plaintext: &str) -> Result<String, Error> {
        <Self as ObtextCodec>::enc(self, plaintext)
    }

    #[inline]
    pub fn dec(&self, obtext: &str) -> Result<String, Error> {
        <Self as ObtextCodec>::dec(self, obtext)
    }

    #[inline]
    pub fn format(&self) -> Format {
        <Self as ObtextCodec>::format(self)
    }

    #[inline]
    pub fn scheme(&self) -> Scheme {
        <Self as ObtextCodec>::scheme(self)
    }

    #[inline]
    pub fn encoding(&self) -> Encoding {
        <Self as ObtextCodec>::encoding(self)
    }
}

const KEY_OFFSET: usize = 0;
const KEY_LEN: usize = 16;
const IV_OFFSET: usize = 16;
const IV_LEN: usize = 16;

/// Encrypt plaintext bytes using legacy AES-CBC
#[inline(always)]
pub(crate) fn encrypt_legacy(secret: &[u8; 32], plaintext_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    use aes::Aes128;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    use cbc::Encryptor;

    type Aes128CbcEnc = Encryptor<Aes128>;

    if plaintext_bytes.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    // Calculate padding to align to block size
    let data_len = plaintext_bytes.len();
    let padding_size = (AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;
    let total_len = data_len + padding_size;

    // Allocate once with the correct size
    let mut buffer = Vec::with_capacity(total_len);
    buffer.extend_from_slice(plaintext_bytes);
    buffer.resize(total_len, LEGACY_PADDING_BYTE);

    // Encrypt in-place
    let cipher = Aes128CbcEnc::new(
        secret[KEY_OFFSET..KEY_OFFSET + KEY_LEN].into(),
        secret[IV_OFFSET..IV_OFFSET + IV_LEN].into(),
    );
    cipher
        .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buffer, total_len)
        .map_err(|_| Error::EncryptionFailed)?;

    Ok(buffer)
}

/// Decrypt ciphertext using legacy AES-CBC
#[inline(always)]
pub(crate) fn decrypt_legacy(secret: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Error> {
    use aes::Aes128;
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};
    use cbc::Decryptor;

    type Aes128CbcDec = Decryptor<Aes128>;

    // Decrypt with AES-128-CBC
    if data.len() % AES_BLOCK_SIZE != 0 {
        return Err(Error::InvalidBlockLength);
    }

    let cipher = Aes128CbcDec::new(
        secret[KEY_OFFSET..KEY_OFFSET + KEY_LEN].into(),
        secret[IV_OFFSET..IV_OFFSET + IV_LEN].into(),
    );
    let mut buffer = data.to_vec();

    cipher
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buffer)
        .map_err(|_| Error::DecryptionFailed)?;

    // Remove '=' padding by finding the end and truncating
    let end = buffer
        .iter()
        .rposition(|&b| b != LEGACY_PADDING_BYTE)
        .map_or(0, |i| i + 1);
    buffer.truncate(end);

    Ok(buffer)
}
