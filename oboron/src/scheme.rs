//! Scheme identifiers for oboron encryption schemes.

use crate::error::Error;

/// Scheme identifier for oboron encoding schemes.
///
/// Every core scheme is authenticated. A scheme ID is a one-letter
/// property code (`d` deterministic, `p` probabilistic) followed by
/// the AEAD algorithm code (`siv` = AES-SIV, `gcmsiv` = AES-GCM-SIV).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    #[cfg(feature = "dgcmsiv")]
    Dgcmsiv,
    #[cfg(feature = "pgcmsiv")]
    Pgcmsiv,
    #[cfg(feature = "dsiv")]
    Dsiv,
    #[cfg(feature = "psiv")]
    Psiv,
    // Testing
    #[cfg(feature = "mock")]
    Mock1,
    #[cfg(feature = "mock")]
    Mock2,
}

impl Scheme {
    /// Convert scheme to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            #[cfg(feature = "dgcmsiv")]
            Scheme::Dgcmsiv => "dgcmsiv",
            #[cfg(feature = "pgcmsiv")]
            Scheme::Pgcmsiv => "pgcmsiv",
            #[cfg(feature = "dsiv")]
            Scheme::Dsiv => "dsiv",
            #[cfg(feature = "psiv")]
            Scheme::Psiv => "psiv",
            // Testing
            #[cfg(feature = "mock")]
            Scheme::Mock1 => "mock1",
            #[cfg(feature = "mock")]
            Scheme::Mock2 => "mock2",
        }
    }

    /// Parse scheme from string.
    // Intentional inherent shortcut alongside the `FromStr` impl, so
    // callers can write `Scheme::from_str(s)` without the trait import.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, Error> {
        s.parse()
    }

    /// Check if this scheme is deterministic (produces the same output for the same input).
    pub fn is_deterministic(&self) -> bool {
        match self {
            #[cfg(feature = "dgcmsiv")]
            Scheme::Dgcmsiv => true,
            #[cfg(feature = "pgcmsiv")]
            Scheme::Pgcmsiv => false,
            #[cfg(feature = "dsiv")]
            Scheme::Dsiv => true,
            #[cfg(feature = "psiv")]
            Scheme::Psiv => false,
            // Testing
            #[cfg(feature = "mock")]
            Scheme::Mock1 => true,
            #[cfg(feature = "mock")]
            Scheme::Mock2 => true,
        }
    }

    /// Check if this scheme is probabilistic (produces different output each time).
    pub fn is_probabilistic(&self) -> bool {
        !self.is_deterministic()
    }
}

impl std::str::FromStr for Scheme {
    type Err = Error;

    /// Parse a scheme from its identifier.
    ///
    /// Inverse of [`Scheme::as_str`] **for the four authenticated core
    /// schemes only**. The testing-only `mock1` / `mock2` schemes are
    /// deliberately *not* parseable from a string, even when the `mock`
    /// feature is enabled: a no-encryption scheme must never be
    /// selectable through a string/config channel (the channel most
    /// likely to carry external input). Construct them explicitly via
    /// the `Scheme::Mock1` / `Scheme::Mock2` variants when needed in
    /// tests.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownScheme`] if `s` doesn't match a feature-enabled
    /// core scheme name (`"mock1"` / `"mock2"` always return this error).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            #[cfg(feature = "dgcmsiv")]
            "dgcmsiv" => Ok(Scheme::Dgcmsiv),
            #[cfg(feature = "pgcmsiv")]
            "pgcmsiv" => Ok(Scheme::Pgcmsiv),
            #[cfg(feature = "dsiv")]
            "dsiv" => Ok(Scheme::Dsiv),
            #[cfg(feature = "psiv")]
            "psiv" => Ok(Scheme::Psiv),
            _ => Err(Error::UnknownScheme),
        }
    }
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
