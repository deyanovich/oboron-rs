//! Tests for mock2 (reverse scheme)
//!
//! mock2 reverses the plaintext and is always available for testing.

use oboron::{Encoding, Format, Scheme};

#[test]
fn test_mock2_basic_roundtrip() {
    let key = oboron::generate_key();
    let ob = oboron::Mock2C32::new(&key).unwrap();

    let plaintext = "hello world";
    let ot = ob.enc(plaintext).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(pt2, plaintext);
}

#[test]
fn test_mock2_reverses_plaintext() {
    let key = oboron::generate_key();

    let plaintext = "abc123";

    // The underlying ciphertext should contain reversed text
    // We can't easily test this directly, but we can verify behavior
    let mock2_direct = oboron::Mock2C32::new(&key).unwrap();
    let mock1_direct = oboron::Mock1C32::new(&key).unwrap();

    let ot71 = mock2_direct.enc(plaintext).unwrap();
    let ot70 = mock1_direct.enc(plaintext).unwrap();

    // mock2 and mock1 should produce different outputs
    assert_ne!(ot71, ot70);
}

#[test]
fn test_mock2_all_encodings() {
    let key = oboron::generate_key();

    // C32 (default)
    let ob_b32 = oboron::Mock2C32::new(&key).unwrap();
    let enc_b32 = ob_b32.enc("test").unwrap();
    assert_eq!(ob_b32.dec(&enc_b32).unwrap(), "test");

    // B64
    let ob_b64 = oboron::Mock2B64::new(&key).unwrap();
    let enc_b64 = ob_b64.enc("test").unwrap();
    assert_eq!(ob_b64.dec(&enc_b64).unwrap(), "test");

    // Hex
    let ob_hex = oboron::Mock2Hex::new(&key).unwrap();
    let enc_hex = ob_hex.enc("test").unwrap();
    assert_eq!(ob_hex.dec(&enc_hex).unwrap(), "test");
}

#[test]
fn test_mock2_deterministic() {
    let key = oboron::generate_key();
    let ob = oboron::Mock2C32::new(&key).unwrap();

    let plaintext = "deterministic test";
    let enc1 = ob.enc(plaintext).unwrap();
    let enc2 = ob.enc(plaintext).unwrap();

    // mock2 should be deterministic
    assert_eq!(enc1, enc2);
}

#[test]
fn test_mock2_cross_scheme_with_mock1() {
    let key = oboron::generate_key();
    let mock2 = oboron::Ob::new("mock2.c32", &key).unwrap();
    let mock1 = oboron::Ob::new("mock1.c32", &key).unwrap();

    let plaintext = "cross-scheme test";
    let ot71 = mock2.enc(plaintext).unwrap();
    let ot70 = mock1.enc(plaintext).unwrap();

    // Strict dec should fail across schemes
    assert!(mock2.dec(&ot70).is_err());
    assert!(mock1.dec(&ot71).is_err());

    // But auto-detect dec should work
    assert_eq!(mock2.autodec(&ot70).unwrap(), plaintext);
    assert_eq!(mock1.autodec(&ot71).unwrap(), plaintext);
}

#[test]
fn test_mock2_utf8() {
    let key = oboron::generate_key();
    let ob = oboron::Mock2C32::new(&key).unwrap();

    let test_cases = vec!["UTF-8: こんにちは", "Emoji: 🚀🔥💯", "Mixed: Hello世界! "];

    for plaintext in test_cases {
        let ot = ob.enc(plaintext).unwrap();
        let pt2 = ob.dec(&ot).unwrap();
        assert_eq!(pt2, plaintext, "Failed for: {}", plaintext);
    }
}

#[test]
fn test_mock2_palindrome() {
    let key = oboron::generate_key();
    let ob = oboron::Mock2C32::new(&key).unwrap();

    // Palindromes should still roundtrip correctly
    let plaintext = "racecar";
    let ot = ob.enc(plaintext).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(pt2, plaintext);
}

#[test]
fn test_mock2_empty_string() {
    let key = oboron::generate_key();
    let ob = oboron::Mock2C32::new(&key).unwrap();

    // Empty string should fail
    let result = ob.enc("");
    assert!(result.is_err());
}

#[test]
fn test_mock2_scheme_info() {
    let key = oboron::generate_key();
    let ob = oboron::Mock2C32::new(&key).unwrap();

    assert_eq!(ob.scheme(), Scheme::Mock2);
    assert_eq!(ob.encoding(), Encoding::C32);
    assert!(ob.scheme().is_deterministic());
}

#[test]
fn test_mock2_parse_scheme() {
    let scheme: Scheme = "mock2".parse().unwrap();
    assert_eq!(scheme, Scheme::Mock2);

    let scheme: Scheme = "MOCK2".parse().unwrap(); // case insensitive
    assert_eq!(scheme, Scheme::Mock2);
}

#[test]
fn test_mock2_format_parsing() {
    let format = Format::from_str("mock2.c32").unwrap();
    assert_eq!(format.scheme(), Scheme::Mock2);
    assert_eq!(format.encoding(), Encoding::C32);

    let format = Format::from_str("mock2.b64").unwrap();
    assert_eq!(format.scheme(), Scheme::Mock2);
    assert_eq!(format.encoding(), Encoding::B64);

    let format = Format::from_str("mock2.hex").unwrap();
    assert_eq!(format.scheme(), Scheme::Mock2);
    assert_eq!(format.encoding(), Encoding::Hex);
}

#[test]
fn test_mock2_long_string() {
    let key = oboron::generate_key();
    let ob = oboron::Mock2C32::new(&key).unwrap();

    let plaintext = "a".repeat(10000);
    let ot = ob.enc(&plaintext).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(pt2, plaintext);
}
