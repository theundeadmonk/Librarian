//! Issue #17 origin-policy foundation; not an authorization or credential API.

use std::fmt;

use librarian_vault_format::MAX_ORIGIN_BYTES;
use url::Url;
use zeroize::Zeroizing;

/// A canonical HTTPS origin, independently parsed at the agent boundary.
///
/// This is only a comparison value. It is not proof of a browser document,
/// authenticated client, selected record, current unlock state, or user action.
/// It deliberately has no formatting or serialization implementation.
pub struct BrowserOrigin(Zeroizing<String>);

impl BrowserOrigin {
    /// Accepts only canonical origin serialization, never a full website URL.
    ///
    /// # Errors
    ///
    /// Returns a non-secret error for non-HTTPS, malformed, noncanonical, or
    /// oversized input. The browser must normalize its API-observed URL first.
    pub fn parse(value: &str) -> Result<Self, BrowserOriginError> {
        if value.len() > MAX_ORIGIN_BYTES {
            return Err(BrowserOriginError);
        }
        let parsed = Url::parse(value).map_err(|_| BrowserOriginError)?;
        if parsed.scheme() != "https" || parsed.origin().ascii_serialization() != value {
            return Err(BrowserOriginError);
        }
        Ok(Self(Zeroizing::new(value.to_owned())))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A bounded public failure that never embeds the caller's origin or URL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowserOriginError;

impl fmt::Display for BrowserOriginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("browser origin is invalid")
    }
}

impl std::error::Error for BrowserOriginError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_browser_origin_corpus() {
        let corpus = include_str!("../../../tests/fixtures/browser-origin-policy.tsv");
        for line in corpus.lines().filter(|line| !line.starts_with('#')) {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 3, "invalid fixture row");
            let actual = BrowserOrigin::parse(fields[1]);
            if fields[2] == "-" {
                assert!(actual.is_err(), "{}", fields[0]);
            } else {
                assert_eq!(actual.unwrap().as_str(), fields[2], "{}", fields[0]);
            }
        }
    }

    #[test]
    fn rejects_controls_and_oversized_browser_origins() {
        for value in [
            "https://exam\nple.com".to_owned(),
            "https://exam\tple.com".to_owned(),
            "https://example.com\0".to_owned(),
            format!("https://{}.example", "a".repeat(MAX_ORIGIN_BYTES)),
        ] {
            assert!(BrowserOrigin::parse(&value).is_err());
        }
    }
}
