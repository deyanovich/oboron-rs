//! Z-tier obfuscation schemes (NOT cryptographically secure)
//!
//! ⚠️ **WARNING**:  Everything in this module is for OBFUSCATION ONLY.   
//! Do NOT use z-tier schemes for actual encryption or security.
//!
//! Z-tier schemes use 32-byte secrets instead of 64-byte keys.

#![cfg(any(feature = "zrbcx", feature = "legacy", feature = "mock"))]

mod constants;
#[cfg(feature = "legacy")]
mod legacy;
mod obz;
mod omnibz;
mod zcodec;
mod zdec;
mod zdec_auto;
mod zenc;
#[cfg(feature = "mock")]
mod zmock1;
#[cfg(feature = "zrbcx")]
mod zrbcx;
mod zsecret;

pub(crate) use zdec::dec_from_format_ztier;
pub(crate) use zenc::enc_to_format_ztier;

// Re-export public types
#[cfg(feature = "mock")]
pub use zcodec::{Zmock1B32, Zmock1B64, Zmock1C32, Zmock1Hex};
#[cfg(feature = "zrbcx")]
pub use zcodec::{ZrbcxB32, ZrbcxB64, ZrbcxC32, ZrbcxHex};

pub use obz::Obz;
pub use omnibz::Omnibz;

#[cfg(feature = "mock")]
pub(crate) use zmock1::{decrypt_zmock1, encrypt_zmock1};
#[cfg(feature = "zrbcx")]
pub(crate) use zrbcx::{decrypt_zrbcx, encrypt_zrbcx};

#[cfg(feature = "legacy")]
pub use legacy::Legacy;
