#[cfg(feature = "dgcmsiv")]
use oboron::DgcmsivB64;
#[cfg(feature = "dsiv")]
use oboron::{DsivB64, DsivC32, DsivHex};
use oboron::{Encoding, Ob};
#[cfg(feature = "pgcmsiv")]
use oboron::{PgcmsivB64, PgcmsivC32, PgcmsivHex};
#[cfg(feature = "psiv")]
use oboron::{PsivB64, PsivC32, PsivHex};

#[test]
#[cfg(feature = "pgcmsiv")]
fn test_pgcmsiv_basic() {
    let key = [0u8; 64];
    let ob = PgcmsivC32::from_bytes(&key).expect("Failed to create PgcmsivC32");

    let plaintext = "Hello, World!";
    let ot1 = ob.enc(plaintext).expect("Failed to enc");
    let ot2 = ob.enc(plaintext).expect("Failed to enc");

    // PgcmsivC32 is probabilistic, so two encodings should be different
    assert_ne!(
        ot1, ot2,
        "PgcmsivC32 should produce different ciphertexts for the same plaintext"
    );

    // But both should dec to the same plaintext
    let pt21 = ob.dec(&ot1).expect("Failed to dec first encoding");
    let pt22 = ob.dec(&ot2).expect("Failed to dec second encoding");

    assert_eq!(pt21, plaintext);
    assert_eq!(pt22, plaintext);

    eprintln!("✓ PgcmsivC32 basic test passed");
}

#[test]
#[cfg(feature = "pgcmsiv")]
fn test_pgcmsiv_all_encodings() {
    let key = [0u8; 64];
    let plaintext = "Test pgcmsiv with different encodings";

    // C32 (default)
    let ob_b32 = PgcmsivC32::from_bytes(&key).expect("Failed to create PgcmsivC32");
    let ot = ob_b32.enc(plaintext).expect("Failed to enc with base32");
    let pt2 = ob_b32.dec(&ot).expect("Failed to dec with base32");
    assert_eq!(pt2, plaintext, "Decoding mismatch for base32");

    // B64
    let ob_b64 = PgcmsivB64::from_bytes(&key).expect("Failed to create PgcmsivC32");
    let ot = ob_b64.enc(plaintext).expect("Failed to enc with base64");
    let pt2 = ob_b64.dec(&ot).expect("Failed to dec with base64");
    assert_eq!(pt2, plaintext, "Decoding mismatch for base64");

    // Hex
    let ob_hex = PgcmsivHex::from_bytes(&key).expect("Failed to create PgcmsivHex");
    let ot = ob_hex.enc(plaintext).expect("Failed to enc with hex");
    let pt2 = ob_hex.dec(&ot).expect("Failed to dec with hex");
    assert_eq!(pt2, plaintext, "Decoding mismatch for hex");

    eprintln!("✓ Pgcmsiv all encodings test passed");
}

#[test]
#[cfg(feature = "dsiv")]
fn test_dsiv_basic() {
    let key = [0u8; 64];
    let ob = DsivC32::from_bytes(&key).expect("Failed to create DsivC32");

    let plaintext = "Testing DsivC32";
    let ot1 = ob.enc(plaintext).expect("Failed to enc");
    let ot2 = ob.enc(plaintext).expect("Failed to enc");

    // DsivC32 is deterministic, so two encodings should be the same
    assert_eq!(
        ot1, ot2,
        "DsivC32 should produce identical ciphertexts for the same plaintext"
    );

    let pt2 = ob.dec(&ot1).expect("Failed to dec");
    assert_eq!(pt2, plaintext);

    eprintln!("✓ DsivC32 basic test passed");
}

#[test]
#[cfg(feature = "dsiv")]
fn test_dsiv_all_encodings() {
    let key = [0u8; 64];
    let plaintext = "Test dsiv with different encodings";

    // C32 (default)
    let ob_b32 = DsivC32::from_bytes(&key).expect("Failed to create DsivC32");
    let ot = ob_b32.enc(plaintext).expect("Failed to enc with base32");
    let pt2 = ob_b32.dec(&ot).expect("Failed to dec with base32");
    assert_eq!(pt2, plaintext, "Decoding mismatch for base32");

    // B64
    let ob_b64 = DsivB64::from_bytes(&key).expect("Failed to create DsivC32");
    let ot = ob_b64.enc(plaintext).expect("Failed to enc with base64");
    let pt2 = ob_b64.dec(&ot).expect("Failed to dec with base64");
    assert_eq!(pt2, plaintext, "Decoding mismatch for base64");

    // Hex
    let ob_hex = DsivHex::from_bytes(&key).expect("Failed to create DsivC32");
    let ot = ob_hex.enc(plaintext).expect("Failed to enc with hex");
    let pt2 = ob_hex.dec(&ot).expect("Failed to dec with hex");
    assert_eq!(pt2, plaintext, "Decoding mismatch for hex");

    eprintln!("✓ Dsiv all encodings test passed");
}

#[test]
#[cfg(feature = "psiv")]
fn test_psiv_basic() {
    let key = [0u8; 64];
    let ob = PsivC32::from_bytes(&key).expect("Failed to create PsivC32");

    let plaintext = "Testing PsivC32 scheme";
    let ot1 = ob.enc(plaintext).expect("Failed to enc");
    let ot2 = ob.enc(plaintext).expect("Failed to enc");

    // PsivC32 is probabilistic, so two encodings should be different
    assert_ne!(
        ot1, ot2,
        "PsivC32 should produce different ciphertexts for the same plaintext"
    );

    // But both should dec to the same plaintext
    let pt21 = ob.dec(&ot1).expect("Failed to dec first encoding");
    let pt22 = ob.dec(&ot2).expect("Failed to dec second encoding");

    assert_eq!(pt21, plaintext);
    assert_eq!(pt22, plaintext);

    eprintln!("✓ PsivC32 basic test passed");
}

#[test]
#[cfg(feature = "psiv")]
fn test_psiv_all_encodings() {
    let key = [0u8; 64];
    let plaintext = "Test psiv with different encodings";

    // C32 (default)
    let ob_b32 = PsivC32::from_bytes(&key).expect("Failed to create PsivC32");
    let ot = ob_b32.enc(plaintext).expect("Failed to enc with base32");
    let pt2 = ob_b32.dec(&ot).expect("Failed to dec with base32");
    assert_eq!(pt2, plaintext, "Decoding mismatch for base32");

    // B64
    let ob_b64 = PsivB64::from_bytes(&key).expect("Failed to create PsivB64");
    let ot = ob_b64.enc(plaintext).expect("Failed to enc with base64");
    let pt2 = ob_b64.dec(&ot).expect("Failed to dec with base64");
    assert_eq!(pt2, plaintext, "Decoding mismatch for base64");

    // Hex
    let ob_hex = PsivHex::from_bytes(&key).expect("Failed to create PsivHex");
    let ot = ob_hex.enc(plaintext).expect("Failed to enc with hex");
    let pt2 = ob_hex.dec(&ot).expect("Failed to dec with hex");
    assert_eq!(pt2, plaintext, "Decoding mismatch for hex");

    eprintln!("✓ Psiv all encodings test passed");
}

#[test]
#[cfg(feature = "dgcmsiv")]
#[cfg(feature = "pgcmsiv")]
#[cfg(feature = "dsiv")]
#[cfg(feature = "psiv")]
fn test_ob_basic() {
    use oboron::Scheme;
    let key = [0u8; 64];
    let mut ob = Ob::from_bytes("dgcmsiv.c32", &key).expect("Failed to create Ob");

    let plaintext = "Testing Ob";

    // Test with different schemes
    for scheme in &[Scheme::Dgcmsiv, Scheme::Pgcmsiv, Scheme::Dsiv, Scheme::Psiv] {
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
#[cfg(feature = "dgcmsiv")]
#[cfg(feature = "dsiv")]
#[cfg(feature = "pgcmsiv")]
#[cfg(feature = "psiv")]
fn test_ob_all_formats() {
    let key = [0u8; 64];
    let mut ob = Ob::from_bytes("dgcmsiv.c32", &key).expect("Failed to create Ob");

    let plaintext = "Testing all Ob formats";

    let formats = [
        "dgcmsiv.c32",
        "dgcmsiv.b32",
        "dgcmsiv.b64",
        "dgcmsiv.hex",
        "pgcmsiv.c32",
        "pgcmsiv.b32",
        "pgcmsiv.b64",
        "pgcmsiv.hex",
        "dsiv.c32",
        "dsiv.b32",
        "dsiv.b64",
        "dsiv.hex",
        "psiv.c32",
        "psiv.b32",
        "psiv.b64",
        "psiv.hex",
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
#[cfg(feature = "dgcmsiv")]
fn test_ob_encoding_changes() {
    let key = [0u8; 64];
    let mut ob = Ob::from_bytes("dgcmsiv.c32", &key).expect("Failed to create Ob");

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
#[cfg(feature = "pgcmsiv")]
#[cfg(feature = "dsiv")]
#[cfg(feature = "psiv")]
fn test_all_schemes_special_characters() {
    let key = [0u8; 64];
    let plaintext = "Special: !@#$%^&*(){}[]|\\:;\"'<>,.?/~`±§";

    // Test Pgcmsiv
    let pgcmsiv = PgcmsivB64::from_bytes(&key).expect("Failed to create PgcmsivB64");
    let ot = pgcmsiv.enc(plaintext).expect("Failed to enc with pgcmsiv");
    let pt2 = pgcmsiv.dec(&ot).expect("Failed to dec with pgcmsiv");
    assert_eq!(
        pt2, plaintext,
        "Special characters decoding mismatch for pgcmsiv"
    );

    // Test Dsiv
    let dsiv = DsivB64::from_bytes(&key).expect("Failed to create DsivB64");
    let ot = dsiv.enc(plaintext).expect("Failed to enc with dsiv");
    let pt2 = dsiv.dec(&ot).expect("Failed to dec with dsiv");
    assert_eq!(
        pt2, plaintext,
        "Special characters decoding mismatch for dsiv"
    );

    // Test Psiv
    let psiv = PsivB64::from_bytes(&key).expect("Failed to create PsivB64");
    let ot = psiv.enc(plaintext).expect("Failed to enc with psiv");
    let pt2 = psiv.dec(&ot).expect("Failed to dec with psiv");
    assert_eq!(
        pt2, plaintext,
        "Special characters decoding mismatch for psiv"
    );

    eprintln!("✓ All schemes special characters test passed");
}

#[test]
#[cfg(feature = "pgcmsiv")]
#[cfg(feature = "dsiv")]
#[cfg(feature = "psiv")]
fn test_all_schemes_empty_string() {
    let key = [0u8; 64];
    let plaintext = "";

    // Empty strings cannot be ot - this is expected behavior
    // Test that all schemes correctly reject empty strings

    // Test Pgcmsiv
    let pgcmsiv = PgcmsivB64::from_bytes(&key).expect("Failed to create PgcmsivB64");
    let result = pgcmsiv.enc(plaintext);
    assert!(result.is_err(), "PgcmsivB64 should reject empty string");

    // Test Dsiv
    let dsiv = DsivB64::from_bytes(&key).expect("Failed to create DsivB64");
    let result = dsiv.enc(plaintext);
    assert!(result.is_err(), "DsivB64 should reject empty string");

    // Test Psiv
    let psiv = PsivB64::from_bytes(&key).expect("Failed to create PsivB64");
    let result = psiv.enc(plaintext);
    assert!(result.is_err(), "PsivB64 should reject empty string");

    eprintln!("✓ All schemes correctly reject empty strings");
}

#[test]
#[cfg(feature = "pgcmsiv")]
#[cfg(feature = "dsiv")]
#[cfg(feature = "psiv")]
fn test_all_schemes_long_string() {
    let key = [0u8; 64];
    let plaintext = "a".repeat(10000);

    // Test Pgcmsiv
    let pgcmsiv = PgcmsivB64::from_bytes(&key).expect("Failed to create Pgcmsiv");
    let ot = pgcmsiv
        .enc(&plaintext)
        .expect("Failed to enc long string with pgcmsiv");
    let pt2 = pgcmsiv
        .dec(&ot)
        .expect("Failed to dec long string with pgcmsiv");
    assert_eq!(pt2, plaintext, "Long string decoding mismatch for pgcmsiv");

    // Test Dsiv
    let dsiv = DsivB64::from_bytes(&key).expect("Failed to create DsivB64");
    let ot = dsiv
        .enc(&plaintext)
        .expect("Failed to enc long string with dsiv");
    let pt2 = dsiv.dec(&ot).expect("Failed to dec long string with dsiv");
    assert_eq!(pt2, plaintext, "Long string decoding mismatch for dsiv");

    // Test PsivB64
    let psiv = PsivB64::from_bytes(&key).expect("Failed to create PsivB64");
    let ot = psiv
        .enc(&plaintext)
        .expect("Failed to enc long string with psiv");
    let pt2 = psiv.dec(&ot).expect("Failed to dec long string with psiv");
    assert_eq!(pt2, plaintext, "Long string decoding mismatch for psiv");

    eprintln!("✓ All schemes long string test passed");
}

#[test]
#[cfg(feature = "dgcmsiv")]
#[cfg(feature = "dsiv")]
fn test_cross_scheme_decoding_should_fail() {
    let key = [0u8; 64];
    let plaintext = "Test cross-scheme decoding";

    // Encode with dgcmsiv
    let dgcmsiv = DgcmsivB64::from_bytes(&key).expect("Failed to create dgcmsiv");
    let ot_dgcmsiv = dgcmsiv.enc(plaintext).expect("Failed to enc with dgcmsiv");

    // Try to dec with dsiv using dec (should fail)
    let dsiv = DsivB64::from_bytes(&key).expect("Failed to create dsiv");
    let result = dsiv.dec(&ot_dgcmsiv);

    assert!(
        result.is_err(),
        "dec should fail when decoding dgcmsiv ciphertext with dsiv decr"
    );

    eprintln!("✓ Cross-scheme decoding failure test passed");
}

#[test]
#[cfg(feature = "pgcmsiv")]
#[cfg(feature = "psiv")]
fn test_probabilistic_schemes_uniqueness() {
    let key = [0u8; 64];
    let plaintext = "Testing probabilistic uniqueness";
    let iterations = 100;

    // Test Pgcmsiv
    let pgcmsiv = PgcmsivB64::from_bytes(&key).expect("Failed to create pgcmsiv");
    let mut encodings = std::collections::HashSet::new();
    for _ in 0..iterations {
        let ot = pgcmsiv.enc(plaintext).expect("Failed to enc with pgcmsiv");
        encodings.insert(ot);
    }
    assert_eq!(
        encodings.len(),
        iterations,
        "PgcmsivB64 should produce {} unique ciphertexts",
        iterations
    );

    // Test PsivB64
    let psiv = PsivB64::from_bytes(&key).expect("Failed to create PsivB64");
    encodings.clear();
    for _ in 0..iterations {
        let ot = psiv.enc(plaintext).expect("Failed to enc with PsivB64");
        encodings.insert(ot);
    }
    assert_eq!(
        encodings.len(),
        iterations,
        "PsivB64 should produce {} unique ciphertexts",
        iterations
    );

    eprintln!(
        "✓ Probabilistic schemes uniqueness test passed ({} iterations per scheme)",
        iterations
    );
}

#[test]
#[cfg(feature = "dgcmsiv")]
#[cfg(feature = "dsiv")]
fn test_deterministic_schemes_consistency() {
    let key = [0u8; 64];
    let plaintext = "Testing deterministic consistency";
    let iterations = 100;

    // Test Dgcmsiv
    let dgcmsiv = DgcmsivB64::from_bytes(&key).expect("Failed to create dgcmsiv");
    let first = dgcmsiv.enc(plaintext).expect("Failed to enc with dgcmsiv");
    for _ in 0..iterations {
        let ot = dgcmsiv.enc(plaintext).expect("Failed to enc with dgcmsiv");
        assert_eq!(ot, first, "Dgcmsiv should produce identical obtexts");
    }

    // Test Dsiv
    let dsiv = DsivB64::from_bytes(&key).expect("Failed to create dsiv");
    let first = dsiv.enc(plaintext).expect("Failed to enc with dsiv");
    for _ in 0..iterations {
        let ot = dsiv.enc(plaintext).expect("Failed to enc with dsiv");
        assert_eq!(ot, first, "DsivB64 should produce identical obtexts");
    }

    eprintln!(
        "✓ Deterministic schemes consistency test passed ({} iterations per scheme)",
        iterations
    );
}
