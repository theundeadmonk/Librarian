//! `SQLite`, key-state, and constrained-protocol ownership for the trusted
//! local vault agent.

#![forbid(unsafe_code)]

mod errors;
mod filesystem;
mod lifecycle;
mod passkeys;
mod records;
mod runtime;
mod snapshot;
mod sqlite;
mod storage;
mod windows_hello;

pub use errors::{AccountError, CreateError, UnlockError};
pub use librarian_vault_core::{
    PasskeyAssertion, PasskeyCredential, PasskeyInput, PasskeyInputError, PasskeySummary, RecordId,
    WebsiteAccount, WebsiteAccountInput, WebsiteAccountInputError, WindowsHelloInstallationKey,
    WindowsHelloPrfOutput,
};
pub use lifecycle::{OperationPermit, VaultAgent};
pub use runtime::{AgentRuntime, DispatchError, RuntimeStartError};

#[cfg(test)]
pub(crate) use filesystem::{parent_directory, sqlite_sidecar, sync_parent_directory};
#[cfg(all(test, windows))]
pub(crate) use sqlite::acquire_sqlite_input_guards;
#[cfg(test)]
pub(crate) use sqlite::{
    MAX_SQLITE_SHM_BYTES, SQLITE_HEADER_BYTES, SQLITE_READ_VERSION_OFFSET, SQLITE_WAL_VERSION,
    SQLITE_WRITE_VERSION_OFFSET, configure_limits, initialize_database,
    read_empty_vault_with_connection_hooks, verify_application_schema,
};
#[cfg(all(test, unix))]
pub(crate) use sqlite::{read_empty_vault, read_empty_vault_with_hooks};
#[cfg(all(test, unix))]
pub(crate) use storage::publish_staged_vault_with_before_link;
#[cfg(test)]
pub(crate) use storage::{publish_staged_vault, reserve_staging_file, validate_new_target};
#[cfg(all(test, windows))]
pub(crate) use storage::{seal_published_vault, verify_published_vault};

#[cfg(test)]
mod unit_tests;
