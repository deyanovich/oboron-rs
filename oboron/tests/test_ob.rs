use oboron::{Encoding, Ob, ObtextCodec, Scheme};

#[test]
fn test_ob_basic_roundtrip() {
    let key = [0u8; 64];
    let ob = Ob::from_bytes("mock1.c32", &key).expect("Failed to create Ob");

    let plaintext = "Hello, Ob!";
    let ot = ob.enc(plaintext).expect("Failed to enc");
    let pt2 = ob.dec(&ot).expect("Failed to dec");

    assert_eq!(pt2, plaintext);
}

#[test]
#[cfg(feature = "aasv")]
fn test_ob_deterministic() {
    let key = [0u8; 64];
    let ob = Ob::from_bytes("aasv.b64", &key).expect("Failed to create Ob with aasv");

    let plaintext = "Deterministic test";
    let ot1 = ob.enc(plaintext).expect("Failed to enc");
    let ot2 = ob.enc(plaintext).expect("Failed to enc");

    // Aasv is deterministic
    assert_eq!(ot1, ot2);
}

#[test]
#[cfg(feature = "apsv")]
fn test_ob_probabilistic() {
    let key = [0u8; 64];
    let ob = Ob::from_bytes("apsv.b64", &key).expect("Failed to create Ob with apsv");

    let plaintext = "Probabilistic test";
    let ot1 = ob.enc(plaintext).expect("Failed to enc");
    let ot2 = ob.enc(plaintext).expect("Failed to enc");

    // Apsv is probabilistic
    assert_ne!(ot1, ot2);

    // But both dec correctly
    assert_eq!(ob.dec(&ot1).unwrap(), plaintext);
    assert_eq!(ob.dec(&ot2).unwrap(), plaintext);
}

#[test]
fn test_ob_all_encodings() {
    let key = [0u8; 64];
    let plaintext = "Test all encodings";

    for format in ["mock1.c32", "mock1.b64", "mock1.hex"] {
        let ob =
            Ob::from_bytes(format, &key).expect(&format!("Failed to create Ob with {}", format));

        let ot = ob
            .enc(plaintext)
            .expect(&format!("Failed to enc with {}", format));
        let pt2 = ob
            .dec(&ot)
            .expect(&format!("Failed to dec with {}", format));

        assert_eq!(pt2, plaintext, "Mismatch for format {}", format);
    }
}

#[test]
fn test_ob_from_hex_key() {
    let hex_key = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let ob = Ob::from_hex_key("mock1.c32", hex_key).expect("Failed to create Ob from hex");

    let plaintext = "Testing hex key";
    let ot = ob.enc(plaintext).expect("Failed to enc");
    let pt2 = ob.dec(&ot).expect("Failed to dec");

    assert_eq!(pt2, plaintext);
}

#[test]
fn test_ob_with_format_instance() {
    let key = [0u8; 64];
    let format = "mock1.b64";
    let ob = Ob::from_bytes(format, &key).expect("Failed to create Ob with format string");

    assert_eq!(ob.scheme(), Scheme::Mock1);
    assert_eq!(ob.encoding(), Encoding::B64);
}

#[test]
fn test_ob_format_getter() {
    let key = [0u8; 64];
    let ob = Ob::from_bytes("mock1.b64", &key).expect("Failed to create Ob");

    let format = ob.format();
    assert_eq!(format.scheme(), Scheme::Mock1);
    assert_eq!(format.encoding(), Encoding::B64);
}

#[test]
#[cfg(feature = "aasv")]
fn test_ob_scheme_autodetection() {
    let key = [0u8; 64];

    // Encode with aasv
    let aasv = Ob::from_bytes("aasv.b64", &key).expect("Failed to create Ob with aasv.b64 format");
    let ot = aasv.enc("test").expect("Failed to enc");

    // Decode with mock1 (different scheme, same encoding)
    let mock1 =
        Ob::from_bytes("mock1.b64", &key).expect("Failed to create Ob with mock1.b64 format");
    let pt2 = mock1
        .autodec(&ot)
        .expect("Failed to dec with autodetection");
    assert_eq!(pt2, "test");

    // But strict dec fails (scheme mismatch)
    assert!(mock1.dec(&ot).is_err());
}

#[test]
fn test_ob_autodec() {
    let key = [0u8; 64];

    // Encode with C32
    let ob_b32 = Ob::from_bytes("mock1.c32", &key).expect("Failed to create Ob with b32");
    let ot = ob_b32.enc("test").expect("Failed to enc");

    // Dec with B64
    let ob_b64 = Ob::from_bytes("mock1.b64", &key).expect("Failed to create Ob with b64");
    assert_eq!(ob_b64.autodec(&ot).unwrap(), "test");
}

#[test]
fn test_ob_key_getter() {
    let key =
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let ob = Ob::new("mock1.c32", &key).expect("Failed to create Ob");

    assert_eq!(ob.key(), key);
}

#[test]
fn test_ob_special_characters() {
    let key =
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let ob = Ob::new("mock1.b64", &key).expect("Failed to create Ob");

    let plaintext = "Special: !@#$%^&*(){}[]|\\:;\"'<>,.?/~`±§";
    let ot = ob.enc(plaintext).expect("Failed to enc");
    let pt2 = ob.dec(&ot).expect("Failed to dec");

    assert_eq!(pt2, plaintext);
}

#[test]
fn test_ob_keyless() {
    let ob = Ob::new_keyless("mock1.c32").expect("Failed to create Ob with hardcoded key");

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
    let ob = Ob::new("mock1.c32", key).expect("Failed to create Ob");

    let ot = enc_with_oboron(&ob, "generic test");
    assert!(ot.len() > 0);
}

#[cfg(feature = "base64-keys")]
#[test]
fn test_ob_new_autodetect_base64_during_transition() {
    // 86-char base64 key should still work via auto-detect during the
    // base64 → hex deprecation period.
    let key_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let ob = Ob::new("mock1.c32", key_b64).expect("Ob::new should accept legacy base64 key");
    let ot = ob.enc("auto-detect").expect("enc");
    assert_eq!(ob.dec(&ot).expect("dec"), "auto-detect");
}

#[test]
fn test_ob_new_autodetect_hex() {
    // 128-char hex key — the new canonical format.
    let key_hex = &"0".repeat(128);
    let ob = Ob::new("mock1.c32", key_hex).expect("Ob::new should accept hex key");
    let ot = ob.enc("auto-detect").expect("enc");
    assert_eq!(ob.dec(&ot).expect("dec"), "auto-detect");
}

#[test]
fn test_ob_new_rejects_unknown_length() {
    let bad = &"a".repeat(50);
    assert!(matches!(
        Ob::new("mock1.c32", bad),
        Err(oboron::Error::InvalidKeyLength)
    ));
}
