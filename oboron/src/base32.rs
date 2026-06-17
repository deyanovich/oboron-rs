//! Custom BASE32 encoding, using lowercased Douglas Crockford's alphabet
//!
pub(crate) use data_encoding::BASE32_NOPAD as BASE32_RFC;
use data_encoding::{Encoding, Specification};
use once_cell::sync::Lazy;

pub(crate) static BASE32_CROCKFORD: Lazy<Encoding> = Lazy::new(|| {
    let mut spec = Specification::new();
    // spec.symbols.push_str("abcdefghijklmnopqrstuvwxyz234567");
    spec.symbols.push_str("0123456789abcdefghjkmnpqrstvwxyz"); // <- Crockford's base32!
    spec.padding = None;
    spec.encoding().unwrap()
});
