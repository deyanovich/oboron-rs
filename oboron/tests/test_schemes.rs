#[cfg(feature = "zrbcx")]
use oboron::ztier::ZrbcxB64;
#[cfg(feature = "aags")]
use oboron::AagsB64;
#[cfg(feature = "upbc")]
use oboron::UpbcB64;
#[cfg(feature = "aasv")]
use oboron::{AasvB64, AasvC32, AasvHex};
#[cfg(feature = "apgs")]
use oboron::{ApgsB64, ApgsC32, ApgsHex};
#[cfg(feature = "apsv")]
use oboron::{ApsvB64, ApsvC32, ApsvHex};
use oboron::{Encoding, Ob};

#[test]
#[cfg(feature = "apgs")]
fn test_apgs_basic() {
    let key = [0u8; 64];
    let ob = ApgsC32::from_bytes(&key).expect("Failed to create ApgsC32");

    let plaintext = "Hello, World!";
    let ot1 = ob.enc(plaintext).expect("Failed to enc");
    let ot2 = ob.enc(plaintext).expect("Failed to enc");

    // ApgsC32 is probabilistic, so two encodings should be different
    assert_ne!(
        ot1, ot2,
        "ApgsC32 should produce different ciphertexts for the same plaintext"
    );

    // But both should dec to the same plaintext
    let pt21 = ob.dec(&ot1).expect("Failed to dec first encoding");
    let pt22 = ob.dec(&ot2).expect("Failed to dec second encoding");

    assert_eq!(pt21, plaintext);
    assert_eq!(pt22, plaintext);

    eprintln!("✓ ApgsC32 basic test passed");
}

#[test]
#[cfg(feature = "apgs")]
fn test_apgs_all_encodings() {
    let key = [0u8; 64];
    let plaintext = "Test apgs with different encodings";

    // C32 (default)
    let ob_b32 = ApgsC32::from_bytes(&key).expect("Failed to create ApgsC32");
    let ot = ob_b32.enc(plaintext).expect("Failed to enc with base32");
    let pt2 = ob_b32.dec(&ot).expect("Failed to dec with base32");
    assert_eq!(pt2, plaintext, "Decoding mismatch for base32");

    // B64
    let ob_b64 = ApgsB64::from_bytes(&key).expect("Failed to create ApgsC32");
    let ot = ob_b64.enc(plaintext).expect("Failed to enc with base64");
    let pt2 = ob_b64.dec(&ot).expect("Failed to dec with base64");
    assert_eq!(pt2, plaintext, "Decoding mismatch for base64");

    // Hex
    let ob_hex = ApgsHex::from_bytes(&key).expect("Failed to create ApgsHex");
    let ot = ob_hex.enc(plaintext).expect("Failed to enc with hex");
    let pt2 = ob_hex.dec(&ot).expect("Failed to dec with hex");
    assert_eq!(pt2, plaintext, "Decoding mismatch for hex");

    eprintln!("✓ Apgs all encodings test passed");
}

#[test]
#[cfg(feature = "aasv")]
fn test_aasv_basic() {
    let key = [0u8; 64];
    let ob = AasvC32::from_bytes(&key).expect("Failed to create AasvC32");

    let plaintext = "Testing AasvC32";
    let ot1 = ob.enc(plaintext).expect("Failed to enc");
    let ot2 = ob.enc(plaintext).expect("Failed to enc");

    // AasvC32 is deterministic, so two encodings should be the same
    assert_eq!(
        ot1, ot2,
        "AasvC32 should produce identical ciphertexts for the same plaintext"
    );

    let pt2 = ob.dec(&ot1).expect("Failed to dec");
    assert_eq!(pt2, plaintext);

    eprintln!("✓ AasvC32 basic test passed");
}

#[test]
#[cfg(feature = "aasv")]
fn test_aasv_all_encodings() {
    let key = [0u8; 64];
    let plaintext = "Test aasv with different encodings";

    // C32 (default)
    let ob_b32 = AasvC32::from_bytes(&key).expect("Failed to create AasvC32");
    let ot = ob_b32.enc(plaintext).expect("Failed to enc with base32");
    let pt2 = ob_b32.dec(&ot).expect("Failed to dec with base32");
    assert_eq!(pt2, plaintext, "Decoding mismatch for base32");

    // B64
    let ob_b64 = AasvB64::from_bytes(&key).expect("Failed to create AasvC32");
    let ot = ob_b64.enc(plaintext).expect("Failed to enc with base64");
    let pt2 = ob_b64.dec(&ot).expect("Failed to dec with base64");
    assert_eq!(pt2, plaintext, "Decoding mismatch for base64");

    // Hex
    let ob_hex = AasvHex::from_bytes(&key).expect("Failed to create AasvC32");
    let ot = ob_hex.enc(plaintext).expect("Failed to enc with hex");
    let pt2 = ob_hex.dec(&ot).expect("Failed to dec with hex");
    assert_eq!(pt2, plaintext, "Decoding mismatch for hex");

    eprintln!("✓ Aasv all encodings test passed");
}

#[test]
#[cfg(feature = "apsv")]
fn test_apsv_basic() {
    let key = [0u8; 64];
    let ob = ApsvC32::from_bytes(&key).expect("Failed to create ApsvC32");

    let plaintext = "Testing ApsvC32 scheme";
    let ot1 = ob.enc(plaintext).expect("Failed to enc");
    let ot2 = ob.enc(plaintext).expect("Failed to enc");

    // ApsvC32 is probabilistic, so two encodings should be different
    assert_ne!(
        ot1, ot2,
        "ApsvC32 should produce different ciphertexts for the same plaintext"
    );

    // But both should dec to the same plaintext
    let pt21 = ob.dec(&ot1).expect("Failed to dec first encoding");
    let pt22 = ob.dec(&ot2).expect("Failed to dec second encoding");

    assert_eq!(pt21, plaintext);
    assert_eq!(pt22, plaintext);

    eprintln!("✓ ApsvC32 basic test passed");
}

#[test]
#[cfg(feature = "apsv")]
fn test_apsv_all_encodings() {
    let key = [0u8; 64];
    let plaintext = "Test apsv with different encodings";

    // C32 (default)
    let ob_b32 = ApsvC32::from_bytes(&key).expect("Failed to create ApsvC32");
    let ot = ob_b32.enc(plaintext).expect("Failed to enc with base32");
    let pt2 = ob_b32.dec(&ot).expect("Failed to dec with base32");
    assert_eq!(pt2, plaintext, "Decoding mismatch for base32");

    // B64
    let ob_b64 = ApsvB64::from_bytes(&key).expect("Failed to create ApsvB64");
    let ot = ob_b64.enc(plaintext).expect("Failed to enc with base64");
    let pt2 = ob_b64.dec(&ot).expect("Failed to dec with base64");
    assert_eq!(pt2, plaintext, "Decoding mismatch for base64");

    // Hex
    let ob_hex = ApsvHex::from_bytes(&key).expect("Failed to create ApsvHex");
    let ot = ob_hex.enc(plaintext).expect("Failed to enc with hex");
    let pt2 = ob_hex.dec(&ot).expect("Failed to dec with hex");
    assert_eq!(pt2, plaintext, "Decoding mismatch for hex");

    eprintln!("✓ Apsv all encodings test passed");
}

#[test]
#[cfg(feature = "aags")]
#[cfg(feature = "apgs")]
#[cfg(feature = "aasv")]
#[cfg(feature = "apsv")]
#[cfg(feature = "upbc")]
fn test_ob_basic() {
    use oboron::Scheme;
    let key = [0u8; 64];
    let mut ob = Ob::from_bytes("upbc.c32", &key).expect("Failed to create Ob");

    let plaintext = "Testing Ob";

    // Test with different schemes
    for scheme in &[
        Scheme::Aags,
        Scheme::Apgs,
        Scheme::Aasv,
        Scheme::Apsv,
        Scheme::Upbc,
    ] {
        ob.set_scheme(*scheme)
            .expect(&format!("Failed to set scheme {:?}", scheme));

        let ot = ob
            .enc(plaintext)
            .expect(&format!("Failed to enc with {:?}", scheme));
        let pt2 = ob
            .dec(&ot)
            .expect(&format!("Failed to dec with {:?}", scheme));

        assert_eq!(pt2, plaintext, "Decoding mismatch for scheme {:?}", scheme);
    }

    eprintln!("✓ Ob basic test passed");
}

#[test]
#[cfg(feature = "aags")]
#[cfg(feature = "aasv")]
#[cfg(feature = "apgs")]
#[cfg(feature = "apsv")]
#[cfg(feature = "upbc")]
fn test_ob_all_formats() {
    let key = [0u8; 64];
    let mut ob = Ob::from_bytes("upbc.c32", &key).expect("Failed to create Ob");

    let plaintext = "Testing all Ob formats";

    let formats = [
        "aags.c32", "aags.b32", "aags.b64", "aags.hex", "apgs.c32", "apgs.b32", "apgs.b64",
        "apgs.hex", "aasv.c32", "aasv.b32", "aasv.b64", "aasv.hex", "apsv.c32", "apsv.b32",
        "apsv.b64", "apsv.hex", "upbc.c32", "upbc.b32", "upbc.b64", "upbc.hex",
    ];

    for format in &formats {
        ob.set_format(*format)
            .expect(&format!("Failed to set format {}", format));

        let ot = ob
            .enc(plaintext)
            .expect(&format!("Failed to enc with {}", format));
        let pt2 = ob
            .dec(&ot)
            .expect(&format!("Failed to dec with {}", format));

        assert_eq!(pt2, plaintext, "Decoding mismatch for format {}", format);
    }

    eprintln!("✓ Ob all formats test passed ({})", formats.len());
}

#[test]
#[cfg(feature = "aags")]
fn test_ob_encoding_changes() {
    let key = [0u8; 64];
    let mut ob = Ob::from_bytes("aags.c32", &key).expect("Failed to create Ob");

    let plaintext = "Testing encoding changes";

    for encoding in &[Encoding::C32, Encoding::B64, Encoding::Hex] {
        ob.set_encoding(*encoding)
            .expect(&format!("Failed to set encoding {:?}", encoding));

        let ot = ob
            .enc(plaintext)
            .expect(&format!("Failed to enc with {:?}", encoding));
        let pt2 = ob
            .dec(&ot)
            .expect(&format!("Failed to dec with {:?}", encoding));

        assert_eq!(
            pt2, plaintext,
            "Decoding mismatch for encoding {:?}",
            encoding
        );
    }

    eprintln!("✓ Ob encoding changes test passed");
}

#[test]
#[cfg(feature = "apgs")]
#[cfg(feature = "aasv")]
#[cfg(feature = "apsv")]
fn test_all_schemes_special_characters() {
    let key = [0u8; 64];
    let plaintext = "Special: !@#$%^&*(){}[]|\\:;\"'<>,.?/~`±§";

    // Test Apgs
    let apgs = ApgsB64::from_bytes(&key).expect("Failed to create ApgsB64");
    let ot = apgs.enc(plaintext).expect("Failed to enc with apgs");
    let pt2 = apgs.dec(&ot).expect("Failed to dec with apgs");
    assert_eq!(
        pt2, plaintext,
        "Special characters decoding mismatch for apgs"
    );

    // Test Aasv
    let aasv = AasvB64::from_bytes(&key).expect("Failed to create AasvB64");
    let ot = aasv.enc(plaintext).expect("Failed to enc with aasv");
    let pt2 = aasv.dec(&ot).expect("Failed to dec with aasv");
    assert_eq!(
        pt2, plaintext,
        "Special characters decoding mismatch for aasv"
    );

    // Test Apsv
    let apsv = ApsvB64::from_bytes(&key).expect("Failed to create ApsvB64");
    let ot = apsv.enc(plaintext).expect("Failed to enc with apsv");
    let pt2 = apsv.dec(&ot).expect("Failed to dec with apsv");
    assert_eq!(
        pt2, plaintext,
        "Special characters decoding mismatch for apsv"
    );

    eprintln!("✓ All schemes special characters test passed");
}

#[test]
#[cfg(feature = "apgs")]
#[cfg(feature = "aasv")]
#[cfg(feature = "apsv")]
fn test_all_schemes_empty_string() {
    let key = [0u8; 64];
    let plaintext = "";

    // Empty strings cannot be ot - this is expected behavior
    // Test that all schemes correctly reject empty strings

    // Test Apgs
    let apgs = ApgsB64::from_bytes(&key).expect("Failed to create ApgsB64");
    let result = apgs.enc(plaintext);
    assert!(result.is_err(), "ApgsB64 should reject empty string");

    // Test Aasv
    let aasv = AasvB64::from_bytes(&key).expect("Failed to create AasvB64");
    let result = aasv.enc(plaintext);
    assert!(result.is_err(), "AasvB64 should reject empty string");

    // Test Apsv
    let apsv = ApsvB64::from_bytes(&key).expect("Failed to create ApsvB64");
    let result = apsv.enc(plaintext);
    assert!(result.is_err(), "ApsvB64 should reject empty string");

    eprintln!("✓ All schemes correctly reject empty strings");
}

#[test]
#[cfg(feature = "apgs")]
#[cfg(feature = "aasv")]
#[cfg(feature = "apsv")]
fn test_all_schemes_long_string() {
    let key = [0u8; 64];
    let plaintext = "a".repeat(10000);

    // Test Apgs
    let apgs = ApgsB64::from_bytes(&key).expect("Failed to create Apgs");
    let ot = apgs
        .enc(&plaintext)
        .expect("Failed to enc long string with apgs");
    let pt2 = apgs.dec(&ot).expect("Failed to dec long string with apgs");
    assert_eq!(pt2, plaintext, "Long string decoding mismatch for apgs");

    // Test Aasv
    let aasv = AasvB64::from_bytes(&key).expect("Failed to create AasvB64");
    let ot = aasv
        .enc(&plaintext)
        .expect("Failed to enc long string with aasv");
    let pt2 = aasv.dec(&ot).expect("Failed to dec long string with aasv");
    assert_eq!(pt2, plaintext, "Long string decoding mismatch for aasv");

    // Test ApsvB64
    let apsv = ApsvB64::from_bytes(&key).expect("Failed to create ApsvB64");
    let ot = apsv
        .enc(&plaintext)
        .expect("Failed to enc long string with apsv");
    let pt2 = apsv.dec(&ot).expect("Failed to dec long string with apsv");
    assert_eq!(pt2, plaintext, "Long string decoding mismatch for apsv");

    eprintln!("✓ All schemes long string test passed");
}

#[test]
#[cfg(feature = "aags")]
#[cfg(feature = "aasv")]
fn test_cross_scheme_decoding_should_fail() {
    let key = [0u8; 64];
    let plaintext = "Test cross-scheme decoding";

    // Encode with aags
    let aags = AagsB64::from_bytes(&key).expect("Failed to create aags");
    let ot_aags = aags.enc(plaintext).expect("Failed to enc with aags");

    // Try to dec with aasv using dec (should fail)
    let aasv = AasvB64::from_bytes(&key).expect("Failed to create aasv");
    let result = aasv.dec(&ot_aags);

    assert!(
        result.is_err(),
        "dec should fail when decoding aags ciphertext with aasv decr"
    );

    eprintln!("✓ Cross-scheme decoding failure test passed");
}

#[test]
#[cfg(feature = "upbc")]
#[cfg(feature = "apgs")]
#[cfg(feature = "apsv")]
fn test_probabilistic_schemes_uniqueness() {
    let key = [0u8; 64];
    let plaintext = "Testing probabilistic uniqueness";
    let iterations = 100;

    // Test Upbc
    let upbc = UpbcB64::from_bytes(&key).expect("Failed to create upbc");
    let mut encodings = std::collections::HashSet::new();
    for _ in 0..iterations {
        let ot = upbc.enc(plaintext).expect("Failed to enc with upbc");
        encodings.insert(ot);
    }
    assert_eq!(
        encodings.len(),
        iterations,
        "UpbcB64 should produce {} unique obtexts",
        iterations
    );

    // Test Apgs
    let apgs = ApgsB64::from_bytes(&key).expect("Failed to create apgs");
    encodings.clear();
    for _ in 0..iterations {
        let ot = apgs.enc(plaintext).expect("Failed to enc with apgs");
        encodings.insert(ot);
    }
    assert_eq!(
        encodings.len(),
        iterations,
        "ApgsB64 should produce {} unique ciphertexts",
        iterations
    );

    // Test ApsvB64
    let apsv = ApsvB64::from_bytes(&key).expect("Failed to create ApsvB64");
    encodings.clear();
    for _ in 0..iterations {
        let ot = apsv.enc(plaintext).expect("Failed to enc with ApsvB64");
        encodings.insert(ot);
    }
    assert_eq!(
        encodings.len(),
        iterations,
        "ApsvB64 should produce {} unique ciphertexts",
        iterations
    );

    eprintln!(
        "✓ Probabilistic schemes uniqueness test passed ({} iterations per scheme)",
        iterations
    );
}

#[test]
#[cfg(feature = "zrbcx")]
#[cfg(feature = "aags")]
#[cfg(feature = "aasv")]
fn test_deterministic_schemes_consistency() {
    let key = [0u8; 64];
    let plaintext = "Testing deterministic consistency";
    let iterations = 100;

    // Test Zrbcx
    let zrbcx = ZrbcxB64::new_keyless().expect("Failed to create zrbcx");
    let first = zrbcx.enc(plaintext).expect("Failed to enc with zrbcx");
    for _ in 0..iterations {
        let ot = zrbcx.enc(plaintext).expect("Failed to enc with zrbcx");
        assert_eq!(ot, first, "ZrbcxB64 should produce identical obtexts");
    }

    // Test Aags
    let aags = AagsB64::from_bytes(&key).expect("Failed to create aags");
    let first = aags.enc(plaintext).expect("Failed to enc with aags");
    for _ in 0..iterations {
        let ot = aags.enc(plaintext).expect("Failed to enc with aags");
        assert_eq!(ot, first, "Aags should produce identical obtexts");
    }

    // Test Aasv
    let aasv = AasvB64::from_bytes(&key).expect("Failed to create aasv");
    let first = aasv.enc(plaintext).expect("Failed to enc with aasv");
    for _ in 0..iterations {
        let ot = aasv.enc(plaintext).expect("Failed to enc with aasv");
        assert_eq!(ot, first, "AasvB64 should produce identical obtexts");
    }

    eprintln!(
        "✓ Deterministic schemes consistency test passed ({} iterations per scheme)",
        iterations
    );
}
