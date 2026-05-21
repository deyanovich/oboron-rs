//! Tests for mock1 (identity scheme)
//!
//! mock1 is a non-encrypting identity scheme that's always available.
//! It should be tested first since it has no crypto dependencies.

use oboron::{Encoding, Format, Scheme};

#[test]
fn test_mock1_basic_roundtrip() {
    let key = oboron::generate_key();
    let ob = oboron::Mock1C32::new(&key).unwrap();

    let plaintext = "hello world";
    let ot = ob.enc(plaintext).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(pt2, plaintext);
}

#[test]
fn test_mock1_all_encodings() {
    let key = oboron::generate_key();

    // C32 (default)
    let ob_b32 = oboron::Mock1C32::new(&key).unwrap();
    let enc_b32 = ob_b32.enc("test").unwrap();
    assert_eq!(ob_b32.dec(&enc_b32).unwrap(), "test");

    // B64
    let ob_b64 = oboron::Mock1B64::new(&key).unwrap();
    let enc_b64 = ob_b64.enc("test").unwrap();
    assert_eq!(ob_b64.dec(&enc_b64).unwrap(), "test");

    // Hex
    let ob_hex = oboron::Mock1Hex::new(&key).unwrap();
    let enc_hex = ob_hex.enc("test").unwrap();
    assert_eq!(ob_hex.dec(&enc_hex).unwrap(), "test");
}

#[test]
fn test_mock1_deterministic() {
    let key = oboron::generate_key();
    let ob = oboron::Mock1C32::new(&key).unwrap();

    let plaintext = "deterministic test";
    let enc1 = ob.enc(plaintext).unwrap();
    let enc2 = ob.enc(plaintext).unwrap();

    // mock1 should be deterministic
    assert_eq!(enc1, enc2);
}

#[test]
fn test_mock1_empty_string() {
    let key = oboron::generate_key();
    let ob = oboron::Mock1C32::new(&key).unwrap();

    // Empty string should fail
    let result = ob.enc("");
    assert!(result.is_err());
}

#[test]
fn test_mock1_special_characters() {
    let key = oboron::generate_key();
    let ob = oboron::Mock1C32::new(&key).unwrap();

    let test_cases = vec![
        "Hello, World!",
        "UTF-8: こんにちは",
        "Emoji: 🚀🔥💯",
        "Newlines:\n\nMultiple",
        "Tabs:\t\tMultiple",
        "Mixed: abc123! @#$%^&*()",
    ];

    for plaintext in test_cases {
        let ot = ob.enc(plaintext).unwrap();
        let pt2 = ob.dec(&ot).unwrap();
        assert_eq!(pt2, plaintext, "Failed for: {}", plaintext);
    }
}

#[test]
fn test_mock1_long_string() {
    let key = oboron::generate_key();
    let ob = oboron::Mock1C32::new(&key).unwrap();

    // Test with a long string
    let plaintext = "a".repeat(10000);
    let ot = ob.enc(&plaintext).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(pt2, plaintext);
}

#[test]
fn test_mock1_keyless() {
    let ob = oboron::Mock1C32::new_keyless().unwrap();

    let plaintext = "hardcoded key test";
    let ot = ob.enc(plaintext).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(pt2, plaintext);
}

#[test]
fn test_mock1_dec() {
    let key = oboron::generate_key();
    let mock1 = oboron::Mock1C32::new(&key).unwrap();

    let plaintext = "strict dec test";
    let ot = mock1.enc(plaintext).unwrap();

    // Strict dec should work with matching scheme
    assert_eq!(mock1.dec(&ot).unwrap(), plaintext);
}

#[test]
#[cfg(feature = "aasv")]
fn test_mock1_cannot_dec_other_schemes_strict() {
    let key = oboron::generate_key();
    let mock1 = oboron::Ob::new("mock1.c32", &key).unwrap();
    let aasv = oboron::Ob::new("aasv.c32", &key).unwrap();

    let plaintext = "cross-scheme test";
    let ot_aasv = aasv.enc(plaintext).unwrap();

    // Strict dec should fail when scheme doesn't match
    assert!(mock1.dec(&ot_aasv).is_err());

    // But scheme-autodetecting dec should work
    assert_eq!(mock1.autodec(&ot_aasv).unwrap(), plaintext);
}

#[test]
fn test_mock1_scheme_info() {
    let key = oboron::generate_key();
    let ob = oboron::Mock1C32::new(&key).unwrap();

    assert_eq!(ob.scheme(), Scheme::Mock1);
    assert_eq!(ob.encoding(), Encoding::C32);
    assert!(ob.scheme().is_deterministic());
}

#[test]
fn test_mock1_format_string() {
    let key = oboron::generate_key();

    // Test creating via format string
    let ob = oboron::new("mock1.c32", &key).unwrap();
    let ot = ob.enc("format test").unwrap();
    let pt2 = ob.dec(&ot).unwrap();
    assert_eq!(pt2, "format test");

    // Test all format strings
    let formats = vec!["mock1.c32", "mock1.b64", "mock1.hex"];
    for format_str in formats {
        let ob = oboron::new(format_str, &key).unwrap();
        assert_eq!(ob.scheme(), Scheme::Mock1);
    }
}

#[test]
fn test_mock1_from_bytes() {
    let key_bytes = [0u8; 64];
    let ob = oboron::Mock1C32::from_bytes(&key_bytes).unwrap();

    let plaintext = "from bytes test";
    let ot = ob.enc(plaintext).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(pt2, plaintext);
}

#[test]
fn test_mock1_factory_from_bytes() {
    let key_bytes = [0u8; 64];
    let ob = oboron::from_bytes("mock1.c32", &key_bytes).unwrap();

    let plaintext = "factory from bytes";
    let ot = ob.enc(plaintext).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(pt2, plaintext);
}

#[test]
fn test_mock1_convenience_functions() {
    let key = oboron::generate_key();

    // Test enc/dec convenience functions
    let plaintext = "convenience test";
    let ot = oboron::enc(plaintext, "mock1.c32", &key).unwrap();
    let pt2 = oboron::dec(&ot, "mock1.c32", &key).unwrap();

    assert_eq!(pt2, plaintext);
}

#[test]
fn test_mock1_autodec() {
    let key = oboron::generate_key();

    let plaintext = "autodec test";
    let ot = oboron::enc(plaintext, "mock1.c32", &key).unwrap();

    // Autodec should work without specifying format
    let pt2 = oboron::autodec(&ot, &key).unwrap();
    assert_eq!(pt2, plaintext);
}

#[test]
fn test_mock1_keyless_functions() {
    let plaintext = "keyless convenience";

    let ot = oboron::enc_keyless(plaintext, "mock1.c32").unwrap();
    let pt2 = oboron::dec_keyless(&ot, "mock1.c32").unwrap();

    assert_eq!(pt2, plaintext);
}

#[test]
fn test_mock1_ob_any_default() {
    let key = oboron::generate_key();

    // ObAny should default to mock1 now
    let ob = oboron::ObAny::new(&key).unwrap();
    assert_eq!(ob.scheme(), Scheme::Mock1);

    let plaintext = "ObAny default test";
    let ot = ob.enc(plaintext).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(pt2, plaintext);
}

#[test]
fn test_mock1_multiple_instances_same_key() {
    let key = oboron::generate_key();

    let ob1 = oboron::Mock1C32::new(&key).unwrap();
    let ob2 = oboron::Mock1C32::new(&key).unwrap();

    let plaintext = "multi-instance test";
    let enc1 = ob1.enc(plaintext).unwrap();
    let dec2 = ob2.dec(&enc1).unwrap();

    assert_eq!(dec2, plaintext);
}

#[test]
fn test_mock1_different_keys() {
    let key1 = oboron::generate_key();
    let key2 = oboron::generate_key();

    let ob1 = oboron::Mock1C32::new(&key1).unwrap();
    let ob2 = oboron::Mock1C32::new(&key2).unwrap();

    let plaintext = "different keys test";
    let ot = ob1.enc(plaintext).unwrap();

    // Since mock1 is identity, the key doesn't matter for decoding
    // (though in production this would be a security issue for real crypto)
    let pt2 = ob2.dec(&ot).unwrap();
    assert_eq!(pt2, plaintext);
}

#[test]
fn test_mock1_invalid_hex_key() {
    // Invalid hex key (not 128 chars)
    let result = oboron::Mock1C32::new("invalid");
    assert!(result.is_err());

    // Invalid hex characters
    let bad_key = "Z".repeat(128);
    let result = oboron::Mock1C32::new(&bad_key);
    assert!(result.is_err());
}

#[test]
fn test_mock1_key_getter() {
    let key_bytes = [42u8; 64];
    let ob = oboron::Mock1C32::from_bytes(&key_bytes).unwrap();

    assert_eq!(ob.key_bytes(), &key_bytes);
}

#[test]
fn test_mock1_encoding_mismatch() {
    let key = oboron::generate_key();

    let ob_b32 = oboron::Ob::new("mock1.c32", &key).unwrap();
    let ob_b64 = oboron::Ob::new("mock1.b64", &key).unwrap();

    let plaintext = "encoding mismatch";
    let enc_b32 = ob_b32.enc(plaintext).unwrap();

    // Strict dec with wrong encoding should fail
    assert!(ob_b64.dec(&enc_b32).is_err());

    // But autodetect dec won't work across encodings
    // (autodetect only handles scheme, not encoding)
    assert_eq!(ob_b64.autodec(&enc_b32).unwrap(), plaintext);
}

#[test]
fn test_mock1_scheme_string() {
    let scheme = Scheme::Mock1;

    assert_eq!(scheme.as_str(), "mock1");
    assert_eq!(scheme.to_string(), "mock1");
}

#[test]
fn test_mock1_parse_scheme() {
    let scheme: Scheme = "mock1".parse().unwrap();
    assert_eq!(scheme, Scheme::Mock1);

    let scheme: Scheme = "MOCK1".parse().unwrap(); // case insensitive
    assert_eq!(scheme, Scheme::Mock1);
}

#[test]
fn test_mock1_format_parsing() {
    let format = Format::from_str("mock1.c32").unwrap();
    assert_eq!(format.scheme(), Scheme::Mock1);
    assert_eq!(format.encoding(), Encoding::C32);

    let format = Format::from_str("mock1.b64").unwrap();
    assert_eq!(format.scheme(), Scheme::Mock1);
    assert_eq!(format.encoding(), Encoding::B64);

    let format = Format::from_str("mock1.hex").unwrap();
    assert_eq!(format.scheme(), Scheme::Mock1);
    assert_eq!(format.encoding(), Encoding::Hex);
}

#[test]
fn test_mock1_binary_data_in_string() {
    let key = oboron::generate_key();
    let ob = oboron::Mock1C32::new(&key).unwrap();

    // Test with string containing various byte values
    let plaintext = "Binary: \x01\x02\x03\x7F";
    let ot = ob.enc(plaintext).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(pt2, plaintext);
}

#[test]
fn test_mock1_sequential_operations() {
    let key = oboron::generate_key();
    let ob = oboron::Mock1C32::new(&key).unwrap();

    // Encode multiple values in sequence
    let values = vec!["first", "second", "third"];
    let mut ot_values = vec![];

    for value in &values {
        ot_values.push(ob.enc(value).unwrap());
    }

    // Decode in sequence
    for (i, ot) in ot_values.iter().enumerate() {
        let pt2 = ob.dec(ot).unwrap();
        assert_eq!(pt2, values[i]);
    }
}

#[test]
fn test_mock1_is_deterministic() {
    // mock1 should report as deterministic
    assert!(Scheme::Mock1.is_deterministic());
}
