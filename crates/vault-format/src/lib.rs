//! Version boundary for Librarian vault formats.
//!
//! This foundation crate intentionally defines no credential schema or
//! cryptographic construction. Those require the threat model and issue #9
//! security decision before implementation.

#![forbid(unsafe_code)]

/// Security maturity of the vault format in this repository revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatReadiness {
    /// The workspace exists, but no production vault format is approved.
    ScaffoldOnly,
}

/// Returns the only valid format state until the security design is accepted.
#[must_use]
pub const fn readiness() -> FormatReadiness {
    FormatReadiness::ScaffoldOnly
}

#[cfg(test)]
mod tests {
    use super::{FormatReadiness, readiness};

    #[test]
    fn foundation_does_not_claim_an_approved_format() {
        assert_eq!(readiness(), FormatReadiness::ScaffoldOnly);
    }
}
