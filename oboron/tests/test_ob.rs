use oboron::{Encoding, Format, Ob, ObtextCodec, Scheme};

// The testing-only mock schemes are deliberately not string-parseable
// (a no-encryption scheme must never be selectable through a string
// channel). These tests exercise the generic `Ob` codec with mock1
// built by value via `Format::new`.
fn mock1(encoding: Encoding) -> Format {
    Format::new(Scheme::Mock1, encoding)
}

#[test]
fn test_ob_basic_roundtrip() {
    let key = [0u8; 64];
    let ob = Ob::from_bytes(mock1(Encoding::C32), &key).expect("Failed to create Ob");

    let plaintext = "Hello, Ob!";
    let ot = ob.enc(plaintext).expect("Failed to enc");
    let pt2 = ob.dec(&ot).expect("Failed to dec");

    assert_eq!(pt2, plaintext);
}

#[test]
#[cfg(feature = "dsiv")]
fn test_ob_deterministic() {
    let key = [0u8; 64];
    let ob = Ob::from_bytes("dsiv.b64", &key).expect("Failed to create Ob with dsiv");

    let plaintext = "Deterministic test";
    let ot1 = ob.enc(plaintext).expect("Failed to enc");
    let ot2 = ob.enc(plaintext).expect("Failed to enc");

    // Dsiv is deterministic
    assert_eq!(ot1, ot2);
}

#[test]
#[cfg(feature = "psiv")]
fn test_ob_probabilistic() {
    let key = [0u8; 64];
    let ob = Ob::from_bytes("psiv.b64", &key).expect("Failed to create Ob with psiv");

    let plaintext = "Probabilistic test";
    let ot1 = ob.enc(plaintext).expect("Failed to enc");
    let ot2 = ob.enc(plaintext).expect("Failed to enc");

    // Psiv is probabilistic
    assert_ne!(ot1, ot2);

    // But both dec correctly
    assert_eq!(ob.dec(&ot1).unwrap(), plaintext);
    assert_eq!(ob.dec(&ot2).unwrap(), plaintext);
}

#[test]
fn test_ob_all_encodings() {
    let key = [0u8; 64];
    let plaintext = "Test all encodings";

    for encoding in [Encoding::C32, Encoding::B64, Encoding::Hex] {
        let ob = Ob::from_bytes(mock1(encoding), &key)
            .expect(&format!("Failed to create Ob with {:?}", encoding));

        let ot = ob
            .enc(plaintext)
            .expect(&format!("Failed to enc with {:?}", encoding));
        let pt2 = ob
            .dec(&ot)
            .expect(&format!("Failed to dec with {:?}", encoding));

        assert_eq!(pt2, plaintext, "Mismatch for encoding {:?}", encoding);
    }
}

#[test]
fn test_ob_from_hex_key() {
    let hex_key = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let ob = Ob::from_hex_key(mock1(Encoding::C32), hex_key).expect("Failed to create Ob from hex");

    let plaintext = "Testing hex key";
    let ot = ob.enc(plaintext).expect("Failed to enc");
    let pt2 = ob.dec(&ot).expect("Failed to dec");

    assert_eq!(pt2, plaintext);
}

#[test]
fn test_ob_with_format_instance() {
    let key = [0u8; 64];
    let format = mock1(Encoding::B64);
    let ob = Ob::from_bytes(format, &key).expect("Failed to create Ob with format instance");

    assert_eq!(ob.scheme(), Scheme::Mock1);
    assert_eq!(ob.encoding(), Encoding::B64);
}

#[test]
fn test_ob_format_getter() {
    let key = [0u8; 64];
    let ob = Ob::from_bytes(mock1(Encoding::B64), &key).expect("Failed to create Ob");

    let format = ob.format();
    assert_eq!(format.scheme(), Scheme::Mock1);
    assert_eq!(format.encoding(), Encoding::B64);
}

#[test]
#[cfg(feature = "dsiv")]
fn test_ob_scheme_mismatch_strict() {
    let key = [0u8; 64];

    // Encode with dsiv
    let dsiv = Ob::from_bytes("dsiv.b64", &key).expect("Failed to create Ob with dsiv.b64 format");
    let ot = dsiv.enc("test").expect("Failed to enc");

    // Decoding with the matching scheme works.
    assert_eq!(dsiv.dec(&ot).unwrap(), "test");

    // But strict dec with a different scheme fails (scheme mismatch).
    let mock1 =
        Ob::from_bytes(mock1(Encoding::B64), &key).expect("Failed to create Ob with mock1.b64");
    assert!(mock1.dec(&ot).is_err());
}

#[test]
fn test_ob_key_getter() {
    let key =
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let ob = Ob::new(mock1(Encoding::C32), &key).expect("Failed to create Ob");

    assert_eq!(ob.key(), key);
}

#[test]
fn test_ob_special_characters() {
    let key =
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let ob = Ob::new(mock1(Encoding::B64), &key).expect("Failed to create Ob");

    let plaintext = "Special: !@#$%^&*(){}[]|\\:;\"'<>,.?/~`±§";
    let ot = ob.enc(plaintext).expect("Failed to enc");
    let pt2 = ob.dec(&ot).expect("Failed to dec");

    assert_eq!(pt2, plaintext);
}

#[test]
fn test_ob_keyless() {
    let ob = Ob::new_keyless(mock1(Encoding::C32)).expect("Failed to create Ob with hardcoded key");

    let plaintext = "keyless test";
    let ot = ob.enc(plaintext).expect("Failed to enc");
    let pt2 = ob.dec(&ot).expect("Failed to dec");

    assert_eq!(pt2, plaintext);
}

#[test]
fn test_ob_generic_usage() {
    // Test that Ob works with generic ObtextCodec trait
    fn enc_with_oboron<O: ObtextCodec>(ob: &O, data: &str) -> String {
        ob.enc(data).unwrap()
    }

    let key =
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let ob = Ob::new(mock1(Encoding::C32), key).expect("Failed to create Ob");

    let ot = enc_with_oboron(&ob, "generic test");
    assert!(ot.len() > 0);
}

#[test]
fn test_ob_new_autodetect_hex() {
    // 128-char hex key — the new canonical format.
    let key_hex = &"0".repeat(128);
    let ob = Ob::new(mock1(Encoding::C32), key_hex).expect("Ob::new should accept hex key");
    let ot = ob.enc("auto-detect").expect("enc");
    assert_eq!(ob.dec(&ot).expect("dec"), "auto-detect");
}

#[test]
fn test_ob_new_rejects_unknown_length() {
    let bad = &"a".repeat(50);
    assert!(matches!(
        Ob::new(mock1(Encoding::C32), bad),
        Err(oboron::Error::InvalidKeyLength)
    ));
}

#[test]
#[cfg(feature = "dsiv")]
fn test_uppercase_hex_key_rejected() {
    // Spec §3.3: keys MUST be lowercase hex; a 128-char hex string with
    // any uppercase digit is rejected (the hex crate would otherwise
    // accept it case-insensitively).
    let upper = format!("{}A", "0".repeat(127)); // 128 hex chars, one uppercase
    let lower = "0".repeat(128);

    // MasterKey path (Ob::new / concrete codec from_hex_key).
    assert!(matches!(
        Ob::new(Format::new(Scheme::Dsiv, Encoding::C32), &upper),
        Err(oboron::Error::InvalidHex)
    ));
    assert!(Ob::new(Format::new(Scheme::Dsiv, Encoding::C32), &lower).is_ok());

    // ObAny factory path (from_hex_key_with_format_internal).
    assert!(matches!(
        oboron::from_hex_key("dsiv.c32", &upper),
        Err(oboron::Error::InvalidHex)
    ));
    assert!(oboron::from_hex_key("dsiv.c32", &lower).is_ok());
}
