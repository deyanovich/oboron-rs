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

#[cfg(feature = "dgcmsiv")]
pub(crate) mod dgcmsiv_formats {
    use super::{Encoding, Format, Scheme};
    pub const DGCMSIV_C32: Format = Format::new(Scheme::Dgcmsiv, Encoding::C32);
    pub const DGCMSIV_B32: Format = Format::new(Scheme::Dgcmsiv, Encoding::B32);
    pub const DGCMSIV_B64: Format = Format::new(Scheme::Dgcmsiv, Encoding::B64);
    pub const DGCMSIV_HEX: Format = Format::new(Scheme::Dgcmsiv, Encoding::Hex);
}

#[cfg(feature = "pgcmsiv")]
pub(crate) mod pgcmsiv_formats {
    use super::{Encoding, Format, Scheme};
    pub const PGCMSIV_C32: Format = Format::new(Scheme::Pgcmsiv, Encoding::C32);
    pub const PGCMSIV_B32: Format = Format::new(Scheme::Pgcmsiv, Encoding::B32);
    pub const PGCMSIV_B64: Format = Format::new(Scheme::Pgcmsiv, Encoding::B64);
    pub const PGCMSIV_HEX: Format = Format::new(Scheme::Pgcmsiv, Encoding::Hex);
}

#[cfg(feature = "dsiv")]
pub(crate) mod dsiv_formats {
    use super::{Encoding, Format, Scheme};
    pub const DSIV_C32: Format = Format::new(Scheme::Dsiv, Encoding::C32);
    pub const DSIV_B32: Format = Format::new(Scheme::Dsiv, Encoding::B32);
    pub const DSIV_B64: Format = Format::new(Scheme::Dsiv, Encoding::B64);
    pub const DSIV_HEX: Format = Format::new(Scheme::Dsiv, Encoding::Hex);
}

#[cfg(feature = "psiv")]
pub(crate) mod psiv_formats {
    use super::{Encoding, Format, Scheme};
    pub const PSIV_C32: Format = Format::new(Scheme::Psiv, Encoding::C32);
    pub const PSIV_B32: Format = Format::new(Scheme::Psiv, Encoding::B32);
    pub const PSIV_B64: Format = Format::new(Scheme::Psiv, Encoding::B64);
    pub const PSIV_HEX: Format = Format::new(Scheme::Psiv, Encoding::Hex);
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

impl Format {
    /// Parse format from compact string representation (e.g., "dsiv.c32", "dgcmsiv.b64")
    ///
    /// This uses fast match-based parsing for maximum performance.
    pub fn from_str(s: &str) -> Result<Self, Error> {
        Ok(match s {
            #[cfg(feature = "dgcmsiv")]
            crate::DGCMSIV_C32_STR => dgcmsiv_formats::DGCMSIV_C32,
            #[cfg(feature = "dgcmsiv")]
            crate::DGCMSIV_B32_STR => dgcmsiv_formats::DGCMSIV_B32,
            #[cfg(feature = "dgcmsiv")]
            crate::DGCMSIV_B64_STR => dgcmsiv_formats::DGCMSIV_B64,
            #[cfg(feature = "dgcmsiv")]
            crate::DGCMSIV_HEX_STR => dgcmsiv_formats::DGCMSIV_HEX,

            #[cfg(feature = "pgcmsiv")]
            crate::PGCMSIV_C32_STR => pgcmsiv_formats::PGCMSIV_C32,
            #[cfg(feature = "pgcmsiv")]
            crate::PGCMSIV_B32_STR => pgcmsiv_formats::PGCMSIV_B32,
            #[cfg(feature = "pgcmsiv")]
            crate::PGCMSIV_B64_STR => pgcmsiv_formats::PGCMSIV_B64,
            #[cfg(feature = "pgcmsiv")]
            crate::PGCMSIV_HEX_STR => pgcmsiv_formats::PGCMSIV_HEX,

            #[cfg(feature = "dsiv")]
            crate::DSIV_C32_STR => dsiv_formats::DSIV_C32,
            #[cfg(feature = "dsiv")]
            crate::DSIV_B32_STR => dsiv_formats::DSIV_B32,
            #[cfg(feature = "dsiv")]
            crate::DSIV_B64_STR => dsiv_formats::DSIV_B64,
            #[cfg(feature = "dsiv")]
            crate::DSIV_HEX_STR => dsiv_formats::DSIV_HEX,

            #[cfg(feature = "psiv")]
            crate::PSIV_C32_STR => psiv_formats::PSIV_C32,
            #[cfg(feature = "psiv")]
            crate::PSIV_B32_STR => psiv_formats::PSIV_B32,
            #[cfg(feature = "psiv")]
            crate::PSIV_B64_STR => psiv_formats::PSIV_B64,
            #[cfg(feature = "psiv")]
            crate::PSIV_HEX_STR => psiv_formats::PSIV_HEX,

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
            #[cfg(feature = "dgcmsiv")]
            Scheme::Dgcmsiv,
            #[cfg(feature = "pgcmsiv")]
            Scheme::Pgcmsiv,
            #[cfg(feature = "dsiv")]
            Scheme::Dsiv,
            #[cfg(feature = "psiv")]
            Scheme::Psiv,
            // Testing
            #[cfg(feature = "mock")]
            Scheme::Mock1,
            #[cfg(feature = "mock")]
            Scheme::Mock2,
        ];

        // Define all encodings
        let encodings = vec![Encoding::C32, Encoding::B32, Encoding::B64, Encoding::Hex];

        for scheme in &schemes {
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
        assert!(Format::from_str("dsiv").is_err());
        assert!(Format::from_str("dsiv.").is_err());
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

        #[cfg(feature = "dgcmsiv")]
        test_cases.extend(vec![
            (Scheme::Dgcmsiv, Encoding::C32, "dgcmsiv.c32"),
            (Scheme::Dgcmsiv, Encoding::B32, "dgcmsiv.b32"),
            (Scheme::Dgcmsiv, Encoding::B64, "dgcmsiv.b64"),
            (Scheme::Dgcmsiv, Encoding::Hex, "dgcmsiv.hex"),
        ]);

        #[cfg(feature = "pgcmsiv")]
        test_cases.extend(vec![
            (Scheme::Pgcmsiv, Encoding::C32, "pgcmsiv.c32"),
            (Scheme::Pgcmsiv, Encoding::B32, "pgcmsiv.b32"),
            (Scheme::Pgcmsiv, Encoding::B64, "pgcmsiv.b64"),
            (Scheme::Pgcmsiv, Encoding::Hex, "pgcmsiv.hex"),
        ]);

        #[cfg(feature = "dsiv")]
        test_cases.extend(vec![
            (Scheme::Dsiv, Encoding::C32, "dsiv.c32"),
            (Scheme::Dsiv, Encoding::B32, "dsiv.b32"),
            (Scheme::Dsiv, Encoding::B64, "dsiv.b64"),
            (Scheme::Dsiv, Encoding::Hex, "dsiv.hex"),
        ]);

        #[cfg(feature = "psiv")]
        test_cases.extend(vec![
            (Scheme::Psiv, Encoding::C32, "psiv.c32"),
            (Scheme::Psiv, Encoding::B32, "psiv.b32"),
            (Scheme::Psiv, Encoding::B64, "psiv.b64"),
            (Scheme::Psiv, Encoding::Hex, "psiv.hex"),
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
    #[cfg(all(feature = "secure-schemes", feature = "mock"))]
    fn test_all_schemes_support_both_base32_variants() {
        // All schemes should support both RFC 4648 base32 (b32) and Crockford base32 (c32)
        let schemes = vec!["dgcmsiv", "pgcmsiv", "dsiv", "psiv", "mock1", "mock2"];

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
