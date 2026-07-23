//! Portable security-core boundary for Librarian.
//!
//! No passwords, passkeys, authentication codes, or recovery material may be
//! stored through this crate until the security design gates are complete.

#![forbid(unsafe_code)]

pub use librarian_vault_format::FormatReadiness;

/// Reports whether this revision has an approved credential-storage format.
#[must_use]
pub const fn credential_storage_is_approved() -> bool {
    match librarian_vault_format::readiness() {
        FormatReadiness::ScaffoldOnly => false,
    }
}

#[cfg(test)]
mod tests {
    use super::credential_storage_is_approved;

    #[test]
    fn credential_storage_stays_disabled_in_the_foundation() {
        assert!(!credential_storage_is_approved());
    }
}
