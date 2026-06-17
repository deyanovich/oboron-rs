//! Integration tests for feature flag combinations

// Test that compiles with any feature combination
#[test]
fn test_available_schemes() {
    let key = oboron::generate_key();

    // Test each scheme if its feature is enabled

    #[cfg(feature = "dgcmsiv")]
    {
        let ob = oboron::DgcmsivC32::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }

    #[cfg(feature = "pgcmsiv")]
    {
        let ob = oboron::PgcmsivC32::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }

    #[cfg(feature = "dsiv")]
    {
        let ob = oboron::DsivC32::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }

    #[cfg(feature = "psiv")]
    {
        let ob = oboron::PsivC32::new(&key).unwrap();
        let enc = ob.enc("test").unwrap();
        assert_eq!(ob.dec(&enc).unwrap(), "test");
    }
}

#[test]
fn test_format_string_parsing() {
    // Test parsing format strings for enabled schemes
    #[cfg(feature = "dsiv")]
    {
        use oboron::Format;
        let format = Format::from_str("dsiv.c32").unwrap();
        assert_eq!(format.to_string(), "dsiv.c32");
    }

    // z-tier scheme strings live in the `obu` crate now and are not
    // valid oboron formats.
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
#[cfg(all(feature = "dgcmsiv", feature = "dsiv"))]
#[test]
fn test_cross_scheme_decoding() {
    let key = oboron::generate_key();
    let dgcmsiv = oboron::Ob::new("dgcmsiv.c32", &key).unwrap();
    let dsiv = oboron::Ob::new("dsiv.c32", &key).unwrap();

    let enc31 = dgcmsiv.enc("hello").unwrap();
    let enc32 = dsiv.enc("world").unwrap();

    // Decoding with the matching scheme works.
    assert_eq!(dsiv.dec(&enc32).unwrap(), "world");
    assert_eq!(dgcmsiv.dec(&enc31).unwrap(), "hello");

    // Strict decoding with the wrong scheme should fail.
    assert!(dgcmsiv.dec(&enc32).is_err());
    assert!(dsiv.dec(&enc31).is_err());
}
