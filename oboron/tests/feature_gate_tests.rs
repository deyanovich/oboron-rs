//!  Compile-time tests to verify feature gates are correctly applied
//!  Each test configuration compiles with a specific feature set

#![cfg(test)]

// bytes-key constructors are unconditional.
mod bytes_keys {
    use oboron::*;

    #[test]
    fn test_bytes_key_constructors() {
        let key = generate_key_bytes();

        #[cfg(feature = "dsiv")]
        {
            let _ = DsivC32::from_bytes(&key);
            let _ = Ob::from_bytes("dsiv.c32", &key);
            let _ = Omnib::from_bytes(&key);
        }
    }

    #[test]
    fn test_key_bytes_methods() {
        #[cfg(feature = "dsiv")]
        {
            let key = generate_key();
            let ob = DsivC32::new(&key).unwrap();

            let _key_bytes: &[u8; 64] = ob.key_bytes();
        }
    }
}

// hex-key constructors are unconditional (hex is the canonical key format).
mod hex_keys {
    use oboron::*;

    #[test]
    fn test_hex_key_constructors() {
        #[allow(deprecated)]
        let key = generate_key_hex();

        #[cfg(feature = "dsiv")]
        {
            let _ = DsivC32::from_hex_key(&key);
            let _ = Ob::from_hex_key("dsiv.c32", &key);
            let _ = Omnib::from_hex_key(&key);
        }
    }

    #[test]
    fn test_key_hex_methods() {
        #[cfg(feature = "dsiv")]
        {
            let key = generate_key();
            let ob = DsivC32::new(&key).unwrap();

            let _key_hex = ob.key_hex();
        }
    }
}

// Test that keyless feature enables new_keyless methods
#[cfg(feature = "keyless")]
mod keyless_enabled {
    use oboron::*;

    #[test]
    fn test_keyless_constructors() {
        // These should all compile with keyless feature
        #[cfg(feature = "dsiv")]
        {
            let _ = DsivC32::new_keyless();
            let _ = Ob::new_keyless("dsiv.c32");
            let _ = Omnib::new_keyless();
        }
    }

    #[test]
    fn test_keyless_convenience_functions() {
        #[cfg(feature = "dsiv")]
        {
            // These should compile with keyless feature
            let ot = enc_keyless("test", "dsiv.c32").unwrap();
            let _pt = dec_keyless(&ot, "dsiv.c32").unwrap();
        }
    }

    #[test]
    fn test_keyless_roundtrip() {
        #[cfg(feature = "dsiv")]
        {
            let ob = DsivC32::new_keyless().unwrap();
            let plaintext = "hello keyless";
            let obtext = ob.enc(plaintext).unwrap();
            let recovered = ob.dec(&obtext).unwrap();
            assert_eq!(plaintext, recovered);
        }
    }
}

#[cfg(not(feature = "keyless"))]
mod keyless_disabled {
    #[test]
    fn test_keyless_methods_not_available() {
        // This test just ensures we can compile without keyless
        // The actual verification is that the keyless methods don't compile
        assert!(true);
    }
}

// Cross-feature validation: all key-input forms work together.
mod combined_features {
    use oboron::*;

    #[test]
    fn test_all_key_formats_work_together() {
        #[cfg(feature = "dsiv")]
        {
            #[allow(deprecated)]
            let key_hex = generate_key_hex();
            let key_bytes = generate_key_bytes();
            let key_str = generate_key();

            // All constructors should work
            let ob1 = DsivC32::new(&key_str).unwrap();
            let ob2 = DsivC32::from_hex_key(&key_hex).unwrap();
            let ob3 = DsivC32::from_bytes(&key_bytes).unwrap();

            // All key getters should work
            let _ = ob1.key();
            let _ = ob1.key_hex();
            let _ = ob1.key_bytes();

            // Test roundtrip with each
            let pt = "test";
            assert_eq!(ob1.dec(&ob1.enc(pt).unwrap()).unwrap(), pt);
            assert_eq!(ob2.dec(&ob2.enc(pt).unwrap()).unwrap(), pt);
            assert_eq!(ob3.dec(&ob3.enc(pt).unwrap()).unwrap(), pt);
        }
    }
}
