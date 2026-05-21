//! Scheme identifiers for oboron encryption schemes.

use crate::{constants, error::Error};

/// Scheme identifier for oboron encoding schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    #[cfg(feature = "aags")]
    Aags,
    #[cfg(feature = "apgs")]
    Apgs,
    #[cfg(feature = "aasv")]
    Aasv,
    #[cfg(feature = "apsv")]
    Apsv,
    #[cfg(feature = "upbc")]
    Upbc,
    // Z-tier
    #[cfg(feature = "zrbcx")]
    Zrbcx,
    // Testing
    #[cfg(feature = "mock")]
    Mock1,
    #[cfg(feature = "mock")]
    Mock2,
    #[cfg(feature = "mock")]
    Zmock1,
    // Legacy
    #[cfg(feature = "legacy")]
    Legacy,
}

impl Scheme {
    /// Convert scheme to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            #[cfg(feature = "aags")]
            Scheme::Aags => "aags",
            #[cfg(feature = "apgs")]
            Scheme::Apgs => "apgs",
            #[cfg(feature = "aasv")]
            Scheme::Aasv => "aasv",
            #[cfg(feature = "apsv")]
            Scheme::Apsv => "apsv",
            #[cfg(feature = "upbc")]
            Scheme::Upbc => "upbc",
            // Z-tier
            #[cfg(feature = "zrbcx")]
            Scheme::Zrbcx => "zrbcx",
            // Testing
            #[cfg(feature = "mock")]
            Scheme::Mock1 => "mock1",
            #[cfg(feature = "mock")]
            Scheme::Mock2 => "mock2",
            #[cfg(feature = "mock")]
            Scheme::Zmock1 => "zmock1",
            // Legacy
            #[cfg(feature = "legacy")]
            Scheme::Legacy => "legacy",
        }
    }

    /// Parse scheme from string.
    pub fn from_str(s: &str) -> Result<Self, Error> {
        s.parse()
    }

    /// Check if this scheme is deterministic (produces the same output for the same input).
    pub fn is_deterministic(&self) -> bool {
        match self {
            #[cfg(feature = "aags")]
            Scheme::Aags => true,
            #[cfg(feature = "apgs")]
            Scheme::Apgs => false,
            #[cfg(feature = "aasv")]
            Scheme::Aasv => true,
            #[cfg(feature = "apsv")]
            Scheme::Apsv => false,
            #[cfg(feature = "upbc")]
            Scheme::Upbc => false,
            // Z-tier
            #[cfg(feature = "zrbcx")]
            Scheme::Zrbcx => true,
            // Testing
            #[cfg(feature = "mock")]
            Scheme::Mock1 => true,
            #[cfg(feature = "mock")]
            Scheme::Mock2 => true,
            #[cfg(feature = "mock")]
            Scheme::Zmock1 => true,
            // Legacy
            #[cfg(feature = "legacy")]
            Scheme::Legacy => true,
        }
    }

    /// Check if this scheme is probabilistic (produces different output each time).
    pub fn is_probabilistic(&self) -> bool {
        !self.is_deterministic()
    }

    /// Get the 2-byte scheme marker for this scheme.
    pub fn marker(&self) -> [u8; 2] {
        match self {
            #[cfg(feature = "aags")]
            Scheme::Aags => constants::AAGS_MARKER,
            #[cfg(feature = "apgs")]
            Scheme::Apgs => constants::APGS_MARKER,
            #[cfg(feature = "aasv")]
            Scheme::Aasv => constants::AASV_MARKER,
            #[cfg(feature = "apsv")]
            Scheme::Apsv => constants::APSV_MARKER,
            #[cfg(feature = "upbc")]
            Scheme::Upbc => constants::UPBC_MARKER,
            // Z-tier
            #[cfg(feature = "zrbcx")]
            Scheme::Zrbcx => constants::ZRBCX_MARKER,
            // Testing
            #[cfg(feature = "mock")]
            Scheme::Mock1 => constants::MOCK1_MARKER,
            #[cfg(feature = "mock")]
            Scheme::Mock2 => constants::MOCK2_MARKER,
            #[cfg(feature = "mock")]
            Scheme::Zmock1 => constants::ZMOCK1_MARKER,
            // Legacy
            #[cfg(feature = "legacy")]
            Scheme::Legacy => unreachable!("legacy does not use a scheme marker"),
        }
    }

    /// Legacy compatibility:  get single byte representation (deprecated)
    #[deprecated(
        since = "1.0.0",
        note = "Use marker() instead for 2-byte scheme markers"
    )]
    pub fn byte(&self) -> u8 {
        // Return second byte of marker for legacy compatibility
        self.marker()[1]
    }
}

impl std::str::FromStr for Scheme {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            #[cfg(feature = "aags")]
            "aags" => Ok(Scheme::Aags),
            #[cfg(feature = "apgs")]
            "apgs" => Ok(Scheme::Apgs),
            #[cfg(feature = "aasv")]
            "aasv" => Ok(Scheme::Aasv),
            #[cfg(feature = "apsv")]
            "apsv" => Ok(Scheme::Apsv),
            #[cfg(feature = "upbc")]
            "upbc" => Ok(Scheme::Upbc),
            // Z-tier
            #[cfg(feature = "zrbcx")]
            "zrbcx" => Ok(Scheme::Zrbcx),
            // Testing
            #[cfg(feature = "mock")]
            "mock1" => Ok(Scheme::Mock1),
            #[cfg(feature = "mock")]
            "mock2" => Ok(Scheme::Mock2),
            #[cfg(feature = "mock")]
            "zmock1" => Ok(Scheme::Zmock1),
            // Legacy
            #[cfg(feature = "legacy")]
            "legacy" => Ok(Scheme::Legacy),
            _ => Err(Error::UnknownScheme),
        }
    }
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
