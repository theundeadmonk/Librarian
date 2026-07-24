use std::fmt;

/// Non-secret failure categories retained inside the trusted agent.
///
/// These variants intentionally contain no paths, database contents, keys, or
/// other attacker-controlled data. Public APIs collapse them at the trust
/// boundary while tests can still assert the failing subsystem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StorageError {
    Filesystem,
    Identity,
    Sidecar,
    Snapshot,
    InvalidDatabaseHeader,
    Sqlite,
    Integrity,
    Schema,
    ResourceLimit,
    Randomness,
    Clock,
}

/// A non-secret failure while creating a new local vault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateError {
    AlreadyExists,
    Failed,
}

impl fmt::Display for CreateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyExists => "a vault already exists at the selected location",
            Self::Failed => "vault creation failed",
        })
    }
}

impl std::error::Error for CreateError {}

/// The deliberately uniform result exposed for an unsuccessful unlock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnlockError {
    Failed,
    Cancelled,
}

impl fmt::Display for UnlockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Failed => "vault unlock failed",
            Self::Cancelled => "vault unlock was cancelled",
        })
    }
}

impl std::error::Error for UnlockError {}
