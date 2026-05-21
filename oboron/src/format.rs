//! Format combines a scheme (encryption method) with an encoding (text representation).  

use crate::{Encoding, Error, Scheme};

/// Format combines a scheme (encryption method) with an encoding (text representation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Format {
    scheme: Scheme,
    encoding: Encoding,
}

impl Format {
    /// Create a new format with the specified scheme and encoding.
    pub const fn new(scheme: Scheme, encoding: Encoding) -> Self {
        Self { scheme, encoding }
    }

    /// Get the scheme.
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Get the encoding.
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }
}

#[cfg(feature = "zrbcx")]
pub(crate) mod zrbcx_formats {
    use super::{Encoding, Format, Scheme};
    pub const ZRBCX_C32: Format = Format::new(Scheme::Zrbcx, Encoding::C32);
    pub const ZRBCX_B32: Format = Format::new(Scheme::Zrbcx, Encoding::B32);
    pub const ZRBCX_B64: Format = Format::new(Scheme::Zrbcx, Encoding::B64);
    pub const ZRBCX_HEX: Format = Format::new(Scheme::Zrbcx, Encoding::Hex);
}

#[cfg(feature = "upbc")]
pub(crate) mod upbc_formats {
    use super::{Encoding, Format, Scheme};
    pub const UPBC_C32: Format = Format::new(Scheme::Upbc, Encoding::C32);
    pub const UPBC_B32: Format = Format::new(Scheme::Upbc, Encoding::B32);
    pub const UPBC_B64: Format = Format::new(Scheme::Upbc, Encoding::B64);
    pub const UPBC_HEX: Format = Format::new(Scheme::Upbc, Encoding::Hex);
}

#[cfg(feature = "aags")]
pub(crate) mod aags_formats {
    use super::{Encoding, Format, Scheme};
    pub const AAGS_C32: Format = Format::new(Scheme::Aags, Encoding::C32);
    pub const AAGS_B32: Format = Format::new(Scheme::Aags, Encoding::B32);
    pub const AAGS_B64: Format = Format::new(Scheme::Aags, Encoding::B64);
    pub const AAGS_HEX: Format = Format::new(Scheme::Aags, Encoding::Hex);
}

#[cfg(feature = "apgs")]
pub(crate) mod apgs_formats {
    use super::{Encoding, Format, Scheme};
    pub const APGS_C32: Format = Format::new(Scheme::Apgs, Encoding::C32);
    pub const APGS_B32: Format = Format::new(Scheme::Apgs, Encoding::B32);
    pub const APGS_B64: Format = Format::new(Scheme::Apgs, Encoding::B64);
    pub const APGS_HEX: Format = Format::new(Scheme::Apgs, Encoding::Hex);
}

#[cfg(feature = "aasv")]
pub(crate) mod aasv_formats {
    use super::{Encoding, Format, Scheme};
    pub const AASV_C32: Format = Format::new(Scheme::Aasv, Encoding::C32);
    pub const AASV_B32: Format = Format::new(Scheme::Aasv, Encoding::B32);
    pub const AASV_B64: Format = Format::new(Scheme::Aasv, Encoding::B64);
    pub const AASV_HEX: Format = Format::new(Scheme::Aasv, Encoding::Hex);
}

#[cfg(feature = "apsv")]
pub(crate) mod apsv_formats {
    use super::{Encoding, Format, Scheme};
    pub const APSV_C32: Format = Format::new(Scheme::Apsv, Encoding::C32);
    pub const APSV_B32: Format = Format::new(Scheme::Apsv, Encoding::B32);
    pub const APSV_B64: Format = Format::new(Scheme::Apsv, Encoding::B64);
    pub const APSV_HEX: Format = Format::new(Scheme::Apsv, Encoding::Hex);
}

#[cfg(feature = "legacy")]
pub(crate) mod legacy_formats {
    use super::{Encoding, Format, Scheme};
    pub const LEGACY: Format = Format::new(Scheme::Legacy, Encoding::B32);
}

#[cfg(feature = "mock")]
pub(crate) mod mock_formats {
    use super::{Encoding, Format, Scheme};
    pub const MOCK1_C32: Format = Format::new(Scheme::Mock1, Encoding::C32);
    pub const MOCK1_B32: Format = Format::new(Scheme::Mock1, Encoding::B32);
    pub const MOCK1_B64: Format = Format::new(Scheme::Mock1, Encoding::B64);
    pub const MOCK1_HEX: Format = Format::new(Scheme::Mock1, Encoding::Hex);
    pub const MOCK2_C32: Format = Format::new(Scheme::Mock2, Encoding::C32);
    pub const MOCK2_B32: Format = Format::new(Scheme::Mock2, Encoding::B32);
    pub const MOCK2_B64: Format = Format::new(Scheme::Mock2, Encoding::B64);
    pub const MOCK2_HEX: Format = Format::new(Scheme::Mock2, Encoding::Hex);
}
#[cfg(feature = "mock")]
pub(crate) mod zmock_formats {
    use super::{Encoding, Format, Scheme};
    pub const ZMOCK1_C32: Format = Format::new(Scheme::Zmock1, Encoding::C32);
    pub const ZMOCK1_B32: Format = Format::new(Scheme::Zmock1, Encoding::B32);
    pub const ZMOCK1_B64: Format = Format::new(Scheme::Zmock1, Encoding::B64);
    pub const ZMOCK1_HEX: Format = Format::new(Scheme::Zmock1, Encoding::Hex);
}

impl Format {
    /// Parse format from compact string representation (e.g., "zrbcx.c32", "aags.b64")
    ///
    /// This uses fast match-based parsing for maximum performance.
    pub fn from_str(s: &str) -> Result<Self, Error> {
        Ok(match s {
            #[cfg(feature = "zrbcx")]
            crate::ZRBCX_C32_STR => zrbcx_formats::ZRBCX_C32,
            #[cfg(feature = "zrbcx")]
            crate::ZRBCX_B32_STR => zrbcx_formats::ZRBCX_B32,
            #[cfg(feature = "zrbcx")]
            crate::ZRBCX_B64_STR => zrbcx_formats::ZRBCX_B64,
            #[cfg(feature = "zrbcx")]
            crate::ZRBCX_HEX_STR => zrbcx_formats::ZRBCX_HEX,

            #[cfg(feature = "upbc")]
            crate::UPBC_C32_STR => upbc_formats::UPBC_C32,
            #[cfg(feature = "upbc")]
            crate::UPBC_B32_STR => upbc_formats::UPBC_B32,
            #[cfg(feature = "upbc")]
            crate::UPBC_B64_STR => upbc_formats::UPBC_B64,
            #[cfg(feature = "upbc")]
            crate::UPBC_HEX_STR => upbc_formats::UPBC_HEX,

            #[cfg(feature = "aags")]
            crate::AAGS_C32_STR => aags_formats::AAGS_C32,
            #[cfg(feature = "aags")]
            crate::AAGS_B32_STR => aags_formats::AAGS_B32,
            #[cfg(feature = "aags")]
            crate::AAGS_B64_STR => aags_formats::AAGS_B64,
            #[cfg(feature = "aags")]
            crate::AAGS_HEX_STR => aags_formats::AAGS_HEX,

            #[cfg(feature = "apgs")]
            crate::APGS_C32_STR => apgs_formats::APGS_C32,
            #[cfg(feature = "apgs")]
            crate::APGS_B32_STR => apgs_formats::APGS_B32,
            #[cfg(feature = "apgs")]
            crate::APGS_B64_STR => apgs_formats::APGS_B64,
            #[cfg(feature = "apgs")]
            crate::APGS_HEX_STR => apgs_formats::APGS_HEX,

            #[cfg(feature = "aasv")]
            crate::AASV_C32_STR => aasv_formats::AASV_C32,
            #[cfg(feature = "aasv")]
            crate::AASV_B32_STR => aasv_formats::AASV_B32,
            #[cfg(feature = "aasv")]
            crate::AASV_B64_STR => aasv_formats::AASV_B64,
            #[cfg(feature = "aasv")]
            crate::AASV_HEX_STR => aasv_formats::AASV_HEX,

            #[cfg(feature = "apsv")]
            crate::APSV_C32_STR => apsv_formats::APSV_C32,
            #[cfg(feature = "apsv")]
            crate::APSV_B32_STR => apsv_formats::APSV_B32,
            #[cfg(feature = "apsv")]
            crate::APSV_B64_STR => apsv_formats::APSV_B64,
            #[cfg(feature = "apsv")]
            crate::APSV_HEX_STR => apsv_formats::APSV_HEX,

            // Testing

            // mock1 variants
            #[cfg(feature = "mock")]
            crate::MOCK1_C32_STR => mock_formats::MOCK1_C32,
            #[cfg(feature = "mock")]
            crate::MOCK1_B32_STR => mock_formats::MOCK1_B32,
            #[cfg(feature = "mock")]
            crate::MOCK1_B64_STR => mock_formats::MOCK1_B64,
            #[cfg(feature = "mock")]
            crate::MOCK1_HEX_STR => mock_formats::MOCK1_HEX,

            // mock2 variants
            #[cfg(feature = "mock")]
            crate::MOCK2_C32_STR => mock_formats::MOCK2_C32,
            #[cfg(feature = "mock")]
            crate::MOCK2_B32_STR => mock_formats::MOCK2_B32,
            #[cfg(feature = "mock")]
            crate::MOCK2_B64_STR => mock_formats::MOCK2_B64,
            #[cfg(feature = "mock")]
            crate::MOCK2_HEX_STR => mock_formats::MOCK2_HEX,

            // zmock1 variants
            #[cfg(feature = "mock")]
            crate::ZMOCK1_C32_STR => zmock_formats::ZMOCK1_C32,
            #[cfg(feature = "mock")]
            crate::ZMOCK1_B32_STR => zmock_formats::ZMOCK1_B32,
            #[cfg(feature = "mock")]
            crate::ZMOCK1_B64_STR => zmock_formats::ZMOCK1_B64,
            #[cfg(feature = "mock")]
            crate::ZMOCK1_HEX_STR => zmock_formats::ZMOCK1_HEX,

            // Legacy
            #[cfg(feature = "legacy")]
            crate::LEGACY_STR => legacy_formats::LEGACY,

            _ => return Err(Error::InvalidFormat),
        })
    }
}

impl std::str::FromStr for Format {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Format::from_str(s)
    }
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Legacy has a single format with no encoding suffix
        #[cfg(feature = "legacy")]
        if self.scheme == Scheme::Legacy {
            return write!(f, "legacy");
        }
        write!(f, "{}.{}", self.scheme.as_str(), self.encoding.as_str())
    }
}

/// Trait for types that can be converted into a Format.
///
/// This trait is sealed and only implemented for `&str`, `Format`, and `&Format`.
pub trait IntoFormat: private::Sealed {
    /// Convert into a Format, possibly returning an error.
    fn into_format(self) -> Result<Format, Error>;
}

impl IntoFormat for Format {
    fn into_format(self) -> Result<Format, Error> {
        Ok(self)
    }
}

impl IntoFormat for &Format {
    fn into_format(self) -> Result<Format, Error> {
        Ok(*self)
    }
}

impl IntoFormat for &str {
    fn into_format(self) -> Result<Format, Error> {
        Format::from_str(self)
    }
}

impl IntoFormat for String {
    fn into_format(self) -> Result<Format, Error> {
        Format::from_str(&self)
    }
}

impl IntoFormat for &String {
    fn into_format(self) -> Result<Format, Error> {
        Format::from_str(self)
    }
}

// Seal the trait to prevent external implementations
mod private {
    pub trait Sealed {}
    impl Sealed for &str {}
    impl Sealed for String {}
    impl Sealed for &String {}
    impl Sealed for super::Format {}
    impl Sealed for &super::Format {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_from_str_all_combinations() {
        // Define all schemes
        let schemes = vec![
            #[cfg(feature = "zrbcx")]
            Scheme::Zrbcx,
            #[cfg(feature = "upbc")]
            Scheme::Upbc,
            #[cfg(feature = "aags")]
            Scheme::Aags,
            #[cfg(feature = "apgs")]
            Scheme::Apgs,
            #[cfg(feature = "aasv")]
            Scheme::Aasv,
            #[cfg(feature = "apsv")]
            Scheme::Apsv,
            // Testing
            #[cfg(feature = "mock")]
            Scheme::Mock1,
            #[cfg(feature = "mock")]
            Scheme::Mock2,
            // Legacy
            #[cfg(feature = "legacy")]
            Scheme::Legacy,
        ];

        // Define all encodings
        let encodings = vec![Encoding::C32, Encoding::B32, Encoding::B64, Encoding::Hex];

        for scheme in &schemes {
            // Legacy uses a single "legacy" format string (no encoding suffix) — tested separately
            #[cfg(feature = "legacy")]
            if *scheme == Scheme::Legacy {
                continue;
            }

            for encoding in &encodings {
                let format_str = format!("{}.{}", scheme.as_str(), encoding.as_str());
                let result = Format::from_str(&format_str);
                assert!(result.is_ok(), "Failed to parse: {}", format_str);
                let format = result.unwrap();
                assert_eq!(
                    format.scheme(),
                    *scheme,
                    "Scheme mismatch for {}",
                    format_str
                );
                assert_eq!(
                    format.encoding(),
                    *encoding,
                    "Encoding mismatch for {}",
                    format_str
                );
            }
        }
    }

    #[test]
    fn test_format_from_str_invalid() {
        // Test invalid format strings
        assert!(Format::from_str("invalid").is_err());
        assert!(Format::from_str("zrbcx").is_err());
        assert!(Format::from_str("zrbcx.").is_err());
        assert!(Format::from_str(".b64").is_err());
        assert!(Format::from_str("mock1:invalid").is_err());
    }

    #[test]
    fn test_format_to_string_roundtrip() {
        // Define test cases: (scheme, encoding, expected_string)
        #[cfg(feature = "mock")]
        let mut test_cases = vec![
            (Scheme::Mock2, Encoding::C32, "mock2.c32"),
            (Scheme::Mock2, Encoding::B32, "mock2.b32"),
            (Scheme::Mock2, Encoding::B64, "mock2.b64"),
            (Scheme::Mock2, Encoding::Hex, "mock2.hex"),
            (Scheme::Mock1, Encoding::C32, "mock1.c32"),
            (Scheme::Mock1, Encoding::B32, "mock1.b32"),
            (Scheme::Mock1, Encoding::B64, "mock1.b64"),
            (Scheme::Mock1, Encoding::Hex, "mock1.hex"),
        ];

        #[cfg(feature = "legacy")]
        test_cases.extend(vec![
            (Scheme::Legacy, Encoding::B32, "legacy"),
        ]);

        #[cfg(feature = "zrbcx")]
        test_cases.extend(vec![
            (Scheme::Zrbcx, Encoding::C32, "zrbcx.c32"),
            (Scheme::Zrbcx, Encoding::B32, "zrbcx.b32"),
            (Scheme::Zrbcx, Encoding::B64, "zrbcx.b64"),
            (Scheme::Zrbcx, Encoding::Hex, "zrbcx.hex"),
        ]);

        #[cfg(feature = "upbc")]
        test_cases.extend(vec![
            (Scheme::Upbc, Encoding::C32, "upbc.c32"),
            (Scheme::Upbc, Encoding::B32, "upbc.b32"),
            (Scheme::Upbc, Encoding::B64, "upbc.b64"),
            (Scheme::Upbc, Encoding::Hex, "upbc.hex"),
        ]);

        #[cfg(feature = "aags")]
        test_cases.extend(vec![
            (Scheme::Aags, Encoding::C32, "aags.c32"),
            (Scheme::Aags, Encoding::B32, "aags.b32"),
            (Scheme::Aags, Encoding::B64, "aags.b64"),
            (Scheme::Aags, Encoding::Hex, "aags.hex"),
        ]);

        #[cfg(feature = "apgs")]
        test_cases.extend(vec![
            (Scheme::Apgs, Encoding::C32, "apgs.c32"),
            (Scheme::Apgs, Encoding::B32, "apgs.b32"),
            (Scheme::Apgs, Encoding::B64, "apgs.b64"),
            (Scheme::Apgs, Encoding::Hex, "apgs.hex"),
        ]);

        #[cfg(feature = "aasv")]
        test_cases.extend(vec![
            (Scheme::Aasv, Encoding::C32, "aasv.c32"),
            (Scheme::Aasv, Encoding::B32, "aasv.b32"),
            (Scheme::Aasv, Encoding::B64, "aasv.b64"),
            (Scheme::Aasv, Encoding::Hex, "aasv.hex"),
        ]);

        #[cfg(feature = "apsv")]
        test_cases.extend(vec![
            (Scheme::Apsv, Encoding::C32, "apsv.c32"),
            (Scheme::Apsv, Encoding::B32, "apsv.b32"),
            (Scheme::Apsv, Encoding::B64, "apsv.b64"),
            (Scheme::Apsv, Encoding::Hex, "apsv.hex"),
        ]);

        for (scheme, encoding, expected_str) in test_cases {
            // Test Format::to_string()
            let format = Format::new(scheme, encoding);
            let format_str = format.to_string();
            assert_eq!(
                format_str, expected_str,
                "Format string mismatch for {:? }.{:? }",
                scheme, encoding
            );

            // Test roundtrip: parse it back
            let parsed = Format::from_str(&format_str).unwrap();
            assert_eq!(
                parsed.scheme(),
                scheme,
                "Scheme mismatch after roundtrip for {}",
                format_str
            );
            assert_eq!(
                parsed.encoding(),
                encoding,
                "Encoding mismatch after roundtrip for {}",
                format_str
            );
        }
    }

    #[test]
    #[cfg(feature = "legacy")]
    fn test_legacy_format() {
        // legacy uses a single format string "legacy" with no encoding suffix
        let format = Format::from_str("legacy").unwrap();
        assert_eq!(format.scheme(), Scheme::Legacy);
        assert_eq!(format.encoding(), Encoding::B32);
        assert_eq!(format.to_string(), "legacy");
    }

    #[test]
    #[cfg(all(feature = "secure-schemes", feature = "zrbcx", feature = "mock"))]
    fn test_all_schemes_support_both_base32_variants() {
        // All schemes should support both RFC 4648 base32 (b32) and Crockford base32 (c32)
        let schemes = vec![
            "zrbcx", "upbc", "aags", "apgs", "aasv", "apsv", "mock1", "mock2",
        ];

        for scheme_str in schemes {
            // Test Crockford base32 (c32)
            let format_str_crock = format!("{}.c32", scheme_str);
            let result_crock = Format::from_str(&format_str_crock);
            if result_crock.is_ok() {
                // Only test if feature is enabled
                assert_eq!(
                    result_crock.unwrap().encoding(),
                    Encoding::C32,
                    "{} should support c32",
                    scheme_str
                );
            }

            // Test RFC 4648 base32 (b32)
            let format_str_rfc = format!("{}.b32", scheme_str);
            let result_rfc = Format::from_str(&format_str_rfc);
            if result_rfc.is_ok() {
                // Only test if feature is enabled
                assert_eq!(
                    result_rfc.unwrap().encoding(),
                    Encoding::B32,
                    "{} should support b32",
                    scheme_str
                );
            }
        }
    }
}
