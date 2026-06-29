//! Tests for mock1 (identity scheme)
//!
//! mock1 is a non-encrypting identity scheme available for testing.
//! It is deliberately *not* selectable through any string/config
//! channel (`Scheme::from_str`, `Format::from_str`, the string-format
//! factories) — a no-encryption scheme must only be constructible
//! explicitly, by value, via `Scheme::Mock1` / `Format::new`.

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
#[cfg(feature = "dsiv")]
fn test_mock1_cannot_dec_other_schemes_strict() {
    let key = oboron::generate_key();
    // mock1 is built by value (it is not string-parseable); a real
    // scheme like dsiv still parses from a string.
    let mock1 = oboron::Ob::new(Format::new(Scheme::Mock1, Encoding::C32), &key).unwrap();
    let dsiv = oboron::Ob::new("dsiv.c32", &key).unwrap();

    let plaintext = "cross-scheme test";
    let ot_dsiv = dsiv.enc(plaintext).unwrap();

    // Strict dec should fail when scheme doesn't match
    assert!(mock1.dec(&ot_dsiv).is_err());

    // But decoding with the matching scheme works.
    assert_eq!(dsiv.dec(&ot_dsiv).unwrap(), plaintext);
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
fn test_mock1_via_new_with_format() {
    let key = oboron::generate_key();

    // mock is reachable through the factory only by value, never by
    // string — `Format::new(Scheme::Mock1, …)` + `new_with_format`.
    let ob = oboron::new_with_format(Format::new(Scheme::Mock1, Encoding::C32), &key).unwrap();
    assert_eq!(ob.scheme(), Scheme::Mock1);

    let ot = ob.enc("format test").unwrap();
    let pt2 = ob.dec(&ot).unwrap();
    assert_eq!(pt2, "format test");
}

#[test]
fn test_mock1_strings_are_fenced() {
    let key = oboron::generate_key();

    // None of the string-format entry points may yield a mock codec.
    for s in ["mock1.c32", "mock1.b32", "mock1.b64", "mock1.hex"] {
        assert!(oboron::new(s, &key).is_err(), "new({s}) should be fenced");
        assert!(
            oboron::enc("x", s, &key).is_err(),
            "enc(.., {s}) should be fenced"
        );
        assert!(Format::from_str(s).is_err(), "Format::from_str({s}) fenced");
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
    // by-value Format (mock strings are fenced)
    let ob = oboron::from_bytes_with_format(Format::new(Scheme::Mock1, Encoding::C32), &key_bytes)
        .unwrap();

    let plaintext = "factory from bytes";
    let ot = ob.enc(plaintext).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(pt2, plaintext);
}

#[test]
fn test_mock1_convenience_functions_reject_string() {
    let key = oboron::generate_key();

    // The string-format convenience functions must reject mock.
    assert!(oboron::enc("convenience test", "mock1.c32", &key).is_err());
    assert!(oboron::dec("whatever", "mock1.c32", &key).is_err());
}

#[test]
fn test_mock1_keyless_functions_reject_string() {
    // The keyless string-format convenience functions must reject mock.
    assert!(oboron::enc_keyless("keyless convenience", "mock1.c32").is_err());
    assert!(oboron::dec_keyless("whatever", "mock1.c32").is_err());
}

#[test]
#[cfg(feature = "dgcmsiv")]
fn test_ob_any_default_is_not_mock() {
    let key = oboron::generate_key();

    // ObAny defaults to the secure dgcmsiv scheme, never to mock.
    let ob = oboron::ObAny::new(&key).unwrap();
    assert_eq!(ob.scheme(), Scheme::Dgcmsiv);

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

    let ob_b32 = oboron::Ob::new(Format::new(Scheme::Mock1, Encoding::C32), &key).unwrap();
    let ob_b64 = oboron::Ob::new(Format::new(Scheme::Mock1, Encoding::B64), &key).unwrap();

    let plaintext = "encoding mismatch";
    let enc_b32 = ob_b32.enc(plaintext).unwrap();

    // Strict dec with wrong encoding should fail
    assert!(ob_b64.dec(&enc_b32).is_err());

    // Decoding with the matching encoding works.
    assert_eq!(ob_b32.dec(&enc_b32).unwrap(), plaintext);
}

#[test]
fn test_mock1_scheme_string() {
    let scheme = Scheme::Mock1;

    assert_eq!(scheme.as_str(), "mock1");
    assert_eq!(scheme.to_string(), "mock1");
}

#[test]
fn test_mock1_scheme_not_string_parseable() {
    // A no-encryption scheme must never be selectable from a string.
    assert!("mock1".parse::<Scheme>().is_err());
    assert!("MOCK1".parse::<Scheme>().is_err());
}

#[test]
fn test_mock1_format_not_string_parseable() {
    // Mock formats are fenced out of the string parser; construct by value.
    assert!(Format::from_str("mock1.c32").is_err());
    assert!(Format::from_str("mock1.b64").is_err());
    assert!(Format::from_str("mock1.hex").is_err());
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

#[test]
fn test_mock1_dec_rejects_non_utf8() {
    // Regression guard for the P0-1 fix: the core dec path ALWAYS
    // validates UTF-8 (spec §4.1) and never returns an unchecked String.
    // mock1 is the identity scheme, so a hex obtext decodes straight to
    // raw bytes as the "plaintext" — feeding bytes that aren't valid
    // UTF-8 must surface Error::InvalidUtf8, not undefined behavior.
    let key = oboron::generate_key();
    let ob = oboron::Mock1Hex::new(&key).unwrap();

    // 0xff 0xfe is not valid UTF-8.
    let result = ob.dec("fffe");
    assert!(
        matches!(result, Err(oboron::Error::InvalidUtf8)),
        "expected InvalidUtf8, got {result:?}"
    );
}
