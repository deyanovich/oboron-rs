// Fixed key for oboron (testing only - NOT SECURE)
// Master value
#[doc(hidden)]
pub const HARDCODED_KEY_BYTES: [u8; 64] = [
    0x38, 0x12, 0x84, 0x63, 0x3d, 0x02, 0xea, 0x5f, 0x35, 0xdf, 0x85, 0x96, 0xb5, 0xcc, 0x42, 0x18,
    0x31, 0x00, 0x60, 0x46, 0x8e, 0x8b, 0x46, 0x54, 0x55, 0xa4, 0x15, 0x17, 0x4e, 0xa6, 0xe9, 0x66,
    0xa9, 0xf4, 0x8e, 0xec, 0x4b, 0xa4, 0x46, 0xdd, 0xfc, 0x8b, 0x78, 0x58, 0x78, 0x95, 0x35, 0x6f,
    0x45, 0xa7, 0x5a, 0x1a, 0xb7, 0x41, 0x94, 0x54, 0xdd, 0x9f, 0x7a, 0xa8, 0xa9, 0x5d, 0xbd, 0xd5,
];

#[doc(hidden)]
pub const HARDCODED_KEY_HEX: &str =
    "38128463\
3d02ea5f\
35df8596\
b5cc4218\
31006046\
8e8b4654\
55a41517\
4ea6e966\
a9f48eec\
4ba446dd\
fc8b7858\
7895356f\
45a75a1a\
b7419454\
dd9f7aa8\
a95dbdd5";

#[allow(dead_code)]
#[doc(hidden)]
#[cfg(feature = "base64-keys")]
#[deprecated(
    since = "0.7.1",
    note = "use HARDCODED_KEY_HEX instead; base64 key support will be removed before oboron 1.0"
)]
pub const HARDCODED_KEY_BASE64: &str =
    "OBKEYz0C6l8134WWtcxCGDEAYEaOi0ZUVaQVF06m6Wap9I7sS6RG3fyLeFh4lTVvRadaGrdBlFTdn3qoqV291Q";
#[cfg(any(feature = "zrbcx", feature = "legacy", feature = "mock"))]
#[doc(hidden)]
pub const HARDCODED_SECRET_BYTES: [u8; 32] = [
    0x38, 0x12, 0x84, 0x63, 0x3d, 0x02, 0xea, 0x5f, 0x35, 0xdf, 0x85, 0x96, 0xb5, 0xcc, 0x42, 0x18,
    0x31, 0x00, 0x60, 0x46, 0x8e, 0x8b, 0x46, 0x54, 0x55, 0xa4, 0x15, 0x17, 0x4e, 0xa6, 0xe9, 0x66,
];

// Scheme marker size (2 bytes). Reserved for ztier (which does its own
// framing); obcrypt re-exports its own copy for the secure-tier paths.
#[allow(dead_code)]
pub const SCHEME_MARKER_SIZE: usize = 2;

// Scheme marker structure (2 bytes = 16 bits):
// Byte 1: [ext:1][version:4][tier:3]
// Byte 2: [properties:4][algorithm:4]
//
// Note: During encoding, both marker bytes are XORed with the first ciphertext byte
// for entropy mixing. This ensures the marker appears random even for short payloads.
//
// ext (1 bit): Extension flag (0 = no extension, 1 = more bytes follow)
// version (4 bits): Format version (0000 = v0)
// tier (3 bits): Security tier
//   - 000 (0): `mock` - testing
//   - 001 (1): `a` - authenticated (secure)
//   - 010 (2): `u` - unauthenticated (secure)
//   - 110 (6): `z` - insecure/obfuscation
//   - 111 (7): `zmock` - ztier testing
// properties (4 bits): Scheme properties
//   - 0000 (0): `p` - probabilistic
//   - 0001 (1): `a` - deterministic avalanche
//   - 0010 (2): `r` - deterministic referenceable / prefix-restricted avalanche
//   - 0100 (4): 'd' - deterministic non-referenceable (no prefix-restricted avalanche)
// algorithm (4 bits): Encryption algorithm
//   - 0001 (1): CBC
//   - 0010 (2): GCM-SIV
//   - 0011 (3): SIV

// Helper function to construct scheme marker
const fn make_marker(tier: u8, properties: u8, algorithm: u8) -> [u8; 2] {
    let byte1 = (0 << 7) | (0 << 3) | tier; // ext=0, version=0000, tier
    let byte2 = (properties << 4) | algorithm;
    [byte1, byte2]
}

// `a`-tier - Secure, authenticated
// ---------------------------------
// aags: tier=001, properties=0001 (det/avalanche), algorithm=0010 (GCM-SIV)
#[cfg(feature = "aags")]
pub const AAGS_MARKER: [u8; 2] = make_marker(1, 1, 2);

// apgs: tier=001, properties=0000 (probabilistic), algorithm=0010 (GCM-SIV)
#[cfg(feature = "apgs")]
pub const APGS_MARKER: [u8; 2] = make_marker(1, 0, 2);

// aasv: tier=001, properties=0001 (det/avalanche), algorithm=0011 (SIV)
#[cfg(feature = "aasv")]
pub const AASV_MARKER: [u8; 2] = make_marker(1, 1, 3);

// apsv: tier=001, properties=0000 (probabilistic), algorithm=0011 (SIV)
#[cfg(feature = "apsv")]
pub const APSV_MARKER: [u8; 2] = make_marker(1, 0, 3);

// `u`-tier - Secure, unauthenticated
// ----------------------------------
// upbc: tier=010, properties=0000 (probabilistic), algorithm=0001 (CBC)
#[cfg(feature = "upbc")]
pub const UPBC_MARKER: [u8; 2] = make_marker(2, 0, 1);

// `z`-tier - Not IND-CPA secure; obfuscation only
// -----------------------------------------------
// zrbcx:  tier=110, properties=0010 (det/referenceable), algorithm=0001 (CBC)
#[cfg(feature = "zrbcx")]
pub const ZRBCX_MARKER: [u8; 2] = make_marker(6, 2, 1);

// Tier mock - Testing (non-encrypted)
// -----------------------------------
// mock1:  tier=000, properties=0100 (det/non-ref), algorithm=1111 (identity)
#[cfg(feature = "mock")]
pub const MOCK1_MARKER: [u8; 2] = make_marker(0, 4, 15);

// mock2: tier=000, properties=0100 (det/non-ref), algorithm=1110 (reversed)
#[cfg(feature = "mock")]
pub const MOCK2_MARKER: [u8; 2] = make_marker(0, 4, 14);

// Tier zmock - Z-tier Testing (non-encrypted)
// -------------------------------------------

// zmock1:  tier=111, properties=0100 (det/non-ref), algorithm=1111 (none)
#[cfg(feature = "mock")]
pub const ZMOCK1_MARKER: [u8; 2] = make_marker(7, 4, 15);

// Format identifiers
//
#[cfg(feature = "aags")]
pub(crate) mod aags_constants {
    pub const AAGS_C32_STR: &str = "aags.c32";
    pub const AAGS_B32_STR: &str = "aags.b32";
    pub const AAGS_B64_STR: &str = "aags.b64";
    pub const AAGS_HEX_STR: &str = "aags.hex";
}

#[cfg(feature = "apgs")]
pub(crate) mod apgs_constants {
    pub const APGS_C32_STR: &str = "apgs.c32";
    pub const APGS_B32_STR: &str = "apgs.b32";
    pub const APGS_B64_STR: &str = "apgs.b64";
    pub const APGS_HEX_STR: &str = "apgs.hex";
}

#[cfg(feature = "aasv")]
pub(crate) mod aasv_constants {
    pub const AASV_C32_STR: &str = "aasv.c32";
    pub const AASV_B32_STR: &str = "aasv.b32";
    pub const AASV_B64_STR: &str = "aasv.b64";
    pub const AASV_HEX_STR: &str = "aasv.hex";
}

#[cfg(feature = "apsv")]
pub(crate) mod apsv_constants {
    pub const APSV_C32_STR: &str = "apsv.c32";
    pub const APSV_B32_STR: &str = "apsv.b32";
    pub const APSV_B64_STR: &str = "apsv.b64";
    pub const APSV_HEX_STR: &str = "apsv.hex";
}

#[cfg(feature = "upbc")]
pub(crate) mod upbc_constants {
    pub const UPBC_C32_STR: &str = "upbc.c32";
    pub const UPBC_B32_STR: &str = "upbc.b32";
    pub const UPBC_B64_STR: &str = "upbc.b64";
    pub const UPBC_HEX_STR: &str = "upbc.hex";
}

#[cfg(feature = "zrbcx")]
pub(crate) mod zrbcx_constants {
    pub const ZRBCX_C32_STR: &str = "zrbcx.c32";
    pub const ZRBCX_B32_STR: &str = "zrbcx.b32";
    pub const ZRBCX_B64_STR: &str = "zrbcx.b64";
    pub const ZRBCX_HEX_STR: &str = "zrbcx.hex";
}

#[cfg(feature = "mock")]
pub(crate) mod mock_constants {
    pub const MOCK1_B32_STR: &str = "mock1.b32";
    pub const MOCK1_B64_STR: &str = "mock1.b64";
    pub const MOCK1_C32_STR: &str = "mock1.c32";
    pub const MOCK1_HEX_STR: &str = "mock1.hex";
    pub const MOCK2_B32_STR: &str = "mock2.b32";
    pub const MOCK2_B64_STR: &str = "mock2.b64";
    pub const MOCK2_C32_STR: &str = "mock2.c32";
    pub const MOCK2_HEX_STR: &str = "mock2.hex";
}

#[cfg(feature = "mock")]
pub(crate) mod zmock_constants {
    pub const ZMOCK1_B32_STR: &str = "zmock1.b32";
    pub const ZMOCK1_B64_STR: &str = "zmock1.b64";
    pub const ZMOCK1_C32_STR: &str = "zmock1.c32";
    pub const ZMOCK1_HEX_STR: &str = "zmock1.hex";
}

#[cfg(feature = "legacy")]
pub(crate) mod legacy_constants {
    pub const LEGACY_STR: &str = "legacy";
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE64URL_NOPAD;

    #[test]
    #[cfg(feature = "base64-keys")]
    fn test_hardcoded_key_consistency() {
        // Decode base64 to bytes
        #[allow(deprecated)]
        let decoded = BASE64URL_NOPAD
            .decode(HARDCODED_KEY_BASE64.as_bytes())
            .expect("Failed to decode base64");

        // Verify length
        assert_eq!(decoded.len(), 64, "Decoded key should be 64 bytes");

        // Verify the bytes match
        assert_eq!(
            decoded.as_slice(),
            &HARDCODED_KEY_BYTES,
            "Base64 and bytes constants must match"
        );

        // Also verify encoding back
        let encoded = BASE64URL_NOPAD.encode(&HARDCODED_KEY_BYTES);
        #[allow(deprecated)]
        let expected = HARDCODED_KEY_BASE64;
        assert_eq!(
            encoded, expected,
            "Bytes encoded back to base64 must match original"
        );
    }

    #[test]
    fn test_scheme_marker_structure() {
        // Test that markers are correctly formed
        #[cfg(feature = "aags")]
        {
            let marker = AAGS_MARKER;
            let byte1 = marker[0];
            let byte2 = marker[1];

            let ext = (byte1 >> 7) & 0x01;
            let version = (byte1 >> 3) & 0x0F;
            let tier = byte1 & 0x07;
            let properties = (byte2 >> 4) & 0x0F;
            let algorithm = byte2 & 0x0F;

            assert_eq!(ext, 0, "Extension bit should be 0");
            assert_eq!(version, 0, "Version should be 0");
            assert_eq!(tier, 1, "AAGS tier should be 1 (authenticated)");
            assert_eq!(properties, 1, "AAGS properties should be 1 (det/avalanche)");
            assert_eq!(algorithm, 2, "AAGS algorithm should be 2 (GCM-SIV)");
        }

        #[cfg(feature = "zrbcx")]
        {
            let marker = ZRBCX_MARKER;
            let byte1 = marker[0];
            let byte2 = marker[1];

            let tier = byte1 & 0x07;
            let properties = (byte2 >> 4) & 0x0F;
            let algorithm = byte2 & 0x0F;

            assert_eq!(tier, 6, "ZRBCX tier should be 6 (insecure)");
            assert_eq!(
                properties, 2,
                "ZRBCX properties should be 2 (det/referenceable)"
            );
            assert_eq!(algorithm, 1, "ZRBCX algorithm should be 1 (CBC)");
        }
    }
}
