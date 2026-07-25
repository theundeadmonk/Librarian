use std::{
    env, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use librarian_vault_core::{
    CancellationFlag, MasterPassword, RecoveryKey, UnlockedVault, create_vault, unlock_vault,
};

use crate::{
    errors::{CreateError, StorageError, UnlockError},
    filesystem::{
        ensure_sidecars_absent_with_ancestor_guards, remove_file_with_ancestor_guards,
        sync_parent_directory_with_ancestor_guards,
    },
    sqlite::{initialize_database, read_guarded_vault, read_vault_from_guards},
    storage::{
        publish_staged_vault_with_before_link, remove_target_if_guarded_matches,
        reserve_staging_file, seal_published_vault_with_ancestor_guards, validate_new_target,
        verify_published_vault,
    },
};

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

/// A non-secret capability snapshot for one in-process operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationPermit {
    session_id: u64,
    authorization_epoch: u64,
}

/// The local agent's vault lifecycle state.
///
/// This type intentionally does not implement `Debug` because it owns the
/// unlocked core session.
pub struct VaultAgent {
    pub(super) path: Option<PathBuf>,
    pub(super) session: Option<UnlockedVault>,
    pub(super) authenticated_header: Option<Vec<u8>>,
    pub(super) authenticated_manifest: Option<Vec<u8>>,
    pub(super) session_id: Option<u64>,
    pub(super) authorization_epoch: u64,
}

impl VaultAgent {
    /// Atomically initializes a new empty vault and leaves this agent unlocked.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyExists` without replacing an existing target. Every
    /// other staging, cryptographic, format, `SQLite`, or durability failure
    /// returns `Failed`. The target name is published only after the staged
    /// database is fully initialized and durable.
    pub fn create(
        path: impl AsRef<Path>,
        password: MasterPassword,
    ) -> Result<(Self, RecoveryKey), CreateError> {
        Self::create_with_before_publish(path, password, || Ok(()))
    }

    pub(crate) fn create_with_before_publish(
        path: impl AsRef<Path>,
        password: MasterPassword,
        before_publish: impl FnOnce() -> Result<(), CreateError>,
    ) -> Result<(Self, RecoveryKey), CreateError> {
        let path = bind_vault_path(path.as_ref()).map_err(|_| CreateError::Failed)?;
        validate_new_target(&path)?;
        let mut staging = reserve_staging_file(&path)?;

        let created_at_ms = unix_time_ms().map_err(|_| CreateError::Failed)?;
        let created = create_vault(password, created_at_ms).map_err(|_| CreateError::Failed)?;
        let (header, manifest, recovery_key, session) = created.into_parts();
        let session_id = next_session_id().ok_or(CreateError::Failed)?;

        initialize_database(&mut staging, &header, &manifest).map_err(|_| CreateError::Failed)?;
        ensure_sidecars_absent_with_ancestor_guards(staging.ancestor_guards(), staging.path())
            .map_err(|_| CreateError::Failed)?;
        let published_guard =
            publish_staged_vault_with_before_link(&mut staging, &path, before_publish)?;
        if staging.remove_name().is_err() {
            drop(published_guard);
            let _ = remove_file_with_ancestor_guards(staging.ancestor_guards(), &path);
            return Err(CreateError::Failed);
        }
        let sealed_guard = match seal_published_vault_with_ancestor_guards(
            &published_guard,
            &path,
            staging.ancestor_guards(),
        ) {
            Ok(guard) => guard,
            Err(error) => {
                remove_target_if_guarded_matches(
                    &published_guard,
                    &path,
                    staging.ancestor_guards(),
                );
                return Err(error);
            }
        };
        drop(published_guard);
        if sync_parent_directory_with_ancestor_guards(&path, staging.ancestor_guards()).is_err() {
            drop(sealed_guard);
            let _ = remove_file_with_ancestor_guards(staging.ancestor_guards(), &path);
            let _ = sync_parent_directory_with_ancestor_guards(&path, staging.ancestor_guards());
            return Err(CreateError::Failed);
        }
        let _verified_snapshot =
            match verify_published_vault(&sealed_guard, &path, &header, &manifest) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    remove_target_if_guarded_matches(
                        &sealed_guard,
                        &path,
                        staging.ancestor_guards(),
                    );
                    let _ = sync_parent_directory_with_ancestor_guards(
                        &path,
                        staging.ancestor_guards(),
                    );
                    return Err(error);
                }
            };

        Ok((
            Self {
                path: Some(path),
                session: Some(session),
                authenticated_header: Some(header),
                authenticated_manifest: Some(manifest),
                session_id: Some(session_id),
                authorization_epoch: 1,
            },
            recovery_key,
        ))
    }

    /// Creates a locked handle without parsing or authenticating the vault.
    #[must_use]
    pub fn open_locked(path: impl AsRef<Path>) -> Self {
        Self {
            path: bind_vault_path(path.as_ref()).ok(),
            session: None,
            authenticated_header: None,
            authenticated_manifest: None,
            session_id: None,
            authorization_epoch: 0,
        }
    }

    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.session.is_some()
    }

    #[cfg(test)]
    pub(crate) fn bound_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Unlocks with no diagnostic distinction between password, corruption,
    /// version, schema, or authentication failures.
    ///
    /// # Errors
    ///
    /// Returns `Cancelled` when cancellation wins and `Failed` for every other
    /// unsuccessful unlock condition. The agent remains locked in both cases.
    pub fn unlock(
        &mut self,
        password: MasterPassword,
        cancellation: &CancellationFlag,
    ) -> Result<(), UnlockError> {
        self.unlock_with_before_publish(password, cancellation, || {})
    }

    pub(crate) fn unlock_with_before_publish(
        &mut self,
        password: MasterPassword,
        cancellation: &CancellationFlag,
        before_publish: impl FnOnce(),
    ) -> Result<(), UnlockError> {
        self.lock();
        if cancellation.is_cancelled() {
            return Err(UnlockError::Cancelled);
        }
        let path = self.path.clone().ok_or(UnlockError::Failed)?;
        let mut snapshot = read_guarded_vault(&path).map_err(|_| UnlockError::Failed)?;
        let session = match unlock_vault(
            password,
            &snapshot.header,
            &snapshot.manifest,
            &snapshot.records,
            cancellation,
        ) {
            Ok(session) => session,
            Err(librarian_vault_core::UnlockError::Cancelled) => {
                return Err(UnlockError::Cancelled);
            }
            Err(librarian_vault_core::UnlockError::Failed) => return Err(UnlockError::Failed),
        };

        before_publish();
        if cancellation.is_cancelled() {
            return Err(UnlockError::Cancelled);
        }
        let current = read_vault_from_guards(&path, &mut snapshot.input_guards, || {}, || {})
            .map_err(|_| UnlockError::Failed)?;
        if current.header != snapshot.header
            || current.manifest != snapshot.manifest
            || current.records != snapshot.records
        {
            return Err(UnlockError::Failed);
        }
        let Some(session_id) = next_session_id() else {
            return Err(UnlockError::Failed);
        };
        if !self.advance_authorization_epoch() {
            return Err(UnlockError::Failed);
        }
        self.session = Some(session);
        self.authenticated_header = Some(snapshot.header);
        self.authenticated_manifest = Some(snapshot.manifest);
        self.session_id = Some(session_id);
        if cancellation.is_cancelled() {
            self.lock();
            return Err(UnlockError::Cancelled);
        }
        Ok(())
    }

    /// Drops and zeroizes reusable key state, invalidating existing permits.
    pub fn lock(&mut self) {
        self.session = None;
        self.authenticated_header = None;
        self.authenticated_manifest = None;
        self.session_id = None;
        let _ = self.advance_authorization_epoch();
    }

    #[must_use]
    pub fn begin_operation(&self) -> Option<OperationPermit> {
        self.session
            .as_ref()
            .zip(self.session_id)
            .map(|(_, session_id)| OperationPermit {
                session_id,
                authorization_epoch: self.authorization_epoch,
            })
    }

    #[must_use]
    pub fn operation_is_authorized(&self, permit: OperationPermit) -> bool {
        self.session.is_some()
            && self.session_id == Some(permit.session_id)
            && permit.authorization_epoch == self.authorization_epoch
    }

    fn advance_authorization_epoch(&mut self) -> bool {
        let Some(next) = self.authorization_epoch.checked_add(1) else {
            return false;
        };
        self.authorization_epoch = next;
        true
    }
}

fn bind_vault_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(env::current_dir()?.join(path))
    }
}

fn next_session_id() -> Option<u64> {
    NEXT_SESSION_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .ok()
}

pub(crate) fn unix_time_ms() -> Result<u64, StorageError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StorageError::Clock)?;
    u64::try_from(duration.as_millis()).map_err(|_| StorageError::Clock)
}
