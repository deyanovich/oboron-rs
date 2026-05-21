//! Integration tests for feature flag combinations

// Test that compiles with any feature combination
#[test]
fn test_available_schemes() {
    let key = oboron::generate_key();

    // Test each scheme if its feature is enabled

    #[cfg(feature = "zrbcx")]
    {
        let ob = oboron::ztier::ZrbcxC32::new_keyless().unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }

    #[cfg(feature = "upbc")]
    {
        let ob = oboron::UpbcC32::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }

    #[cfg(feature = "aags")]
    {
        let ob = oboron::AagsC32::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }

    #[cfg(feature = "apgs")]
    {
        let ob = oboron::ApgsC32::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }

    #[cfg(feature = "aasv")]
    {
        let ob = oboron::AasvC32::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }

    #[cfg(feature = "apsv")]
    {
        let ob = oboron::ApsvC32::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }
}

#[test]
fn test_format_string_parsing() {
    // Test parsing format strings for enabled schemes
    #[cfg(feature = "aasv")]
    {
        use oboron::Format;
        let format = Format::from_str("aasv.c32").unwrap();
        assert_eq!(format.to_string(), "aasv.c32");
    }

    // Test that disabled schemes return error
    #[cfg(not(feature = "zrbcx"))]
    {
        use oboron::Format;
        assert!(Format::from_str("zrbcx.c32").is_err());
    }
}

#[test]
fn test_ob_any_default() {
    // ObAny::new() should work with any feature combination
    let key = oboron::generate_key();
    let ob = oboron::ObAny::new(&key).unwrap();
    let enc = ob.enc("test data").unwrap();
    assert_eq!(ob.dec(&enc).unwrap(), "test data");
}

// Cross-scheme decoding test (only if multiple schemes enabled)
#[cfg(all(feature = "aags", feature = "aasv"))]
#[test]
fn test_cross_scheme_decoding() {
    let key = oboron::generate_key();
    let aags = oboron::Ob::new("aags.c32", &key).unwrap();
    let aasv = oboron::Ob::new("aasv.c32", &key).unwrap();

    let enc31 = aags.enc("hello").unwrap();
    let enc32 = aasv.enc("world").unwrap();

    // Auto-detection should work across schemes
    assert_eq!(aags.autodec(&enc32).unwrap(), "world");
    assert_eq!(aasv.autodec(&enc31).unwrap(), "hello");

    // Strict decoding should fail
    assert!(aags.dec(&enc32).is_err());
    assert!(aasv.dec(&enc31).is_err());
}
