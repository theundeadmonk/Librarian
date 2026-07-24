use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    errors::CreateError,
    filesystem::{
        AncestorGuards, acquire_ancestor_guards, create_staging_reservation,
        ensure_sidecars_absent_with_ancestor_guards,
        guarded_file_matches_path_with_ancestor_guards, guarded_files_match,
        hard_link_with_ancestor_guards, is_reparse_point, open_existing_guard_with_ancestor_guards,
        open_regular_file_guard_with_ancestor_guards, parent_directory,
        remove_file_with_ancestor_guards, sqlite_sidecar,
    },
    sqlite::{GuardedEmptyVault, read_guarded_empty_vault},
};

pub(crate) const MAX_STAGING_ATTEMPTS: u64 = 128;
static NEXT_STAGING_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn validate_new_target(path: &Path) -> Result<(), CreateError> {
    let ancestor_guards = acquire_ancestor_guards(path).map_err(|_| CreateError::Failed)?;
    validate_new_target_with_guarded_ancestors(path, &ancestor_guards)
}

pub(crate) fn validate_new_target_with_guarded_ancestors(
    path: &Path,
    ancestor_guards: &AncestorGuards,
) -> Result<(), CreateError> {
    if path.file_name().is_none() {
        return Err(CreateError::Failed);
    }
    match open_existing_guard_with_ancestor_guards(ancestor_guards, path, true, true) {
        Ok(file) => {
            if is_reparse_point(&file.metadata().map_err(|_| CreateError::Failed)?) {
                return Err(CreateError::Failed);
            }
            return Err(CreateError::AlreadyExists);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(CreateError::Failed),
    }
    Ok(())
}

pub(crate) fn reserve_staging_file(target: &Path) -> Result<StagedVault, CreateError> {
    let ancestor_guards = acquire_ancestor_guards(target).map_err(|_| CreateError::Failed)?;
    validate_new_target_with_guarded_ancestors(target, &ancestor_guards)?;
    let parent = parent_directory(target);
    let target_name = target.file_name().ok_or(CreateError::Failed)?;
    for _ in 0..MAX_STAGING_ATTEMPTS {
        let sequence = NEXT_STAGING_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| CreateError::Failed)?;
        let mut staging_name = target_name.to_os_string();
        staging_name.push(format!(
            ".librarian-stage-{}-{sequence}",
            std::process::id()
        ));
        let staging_path = parent.join(staging_name);
        match create_staging_reservation(&ancestor_guards, &staging_path) {
            Ok(reservation) => {
                return Ok(StagedVault {
                    path: staging_path,
                    reservation: Some(reservation),
                    ancestor_guards,
                });
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(CreateError::Failed),
        }
    }
    Err(CreateError::Failed)
}

pub(crate) fn publish_staged_vault(
    staging: &mut StagedVault,
    target: &Path,
) -> Result<File, CreateError> {
    publish_staged_vault_with_before_link(staging, target, || {})
}

pub(crate) fn publish_staged_vault_with_before_link(
    staging: &mut StagedVault,
    target: &Path,
    before_link: impl FnOnce(),
) -> Result<File, CreateError> {
    ensure_sidecars_absent_with_ancestor_guards(staging.ancestor_guards(), target)
        .map_err(|_| CreateError::Failed)?;
    let reservation = staging
        .try_clone_reservation()
        .map_err(|_| CreateError::Failed)?;
    guarded_file_matches_path_with_ancestor_guards(
        &reservation,
        staging.path(),
        staging.ancestor_guards(),
    )
    .map_err(|_| CreateError::Failed)?;
    before_link();
    match hard_link_with_ancestor_guards(staging.ancestor_guards(), staging.path(), target) {
        Ok(()) => {
            let published_guard = open_regular_file_guard_with_ancestor_guards(
                staging.ancestor_guards(),
                target,
                true,
                true,
            );
            let publication_is_valid = published_guard
                .as_ref()
                .is_ok_and(|published| guarded_files_match(&reservation, published).is_ok());
            if !publication_is_valid
                || ensure_sidecars_absent_with_ancestor_guards(staging.ancestor_guards(), target)
                    .is_err()
            {
                drop(published_guard);
                staging.release_reservation();
                drop(reservation);
                let _ = remove_file_with_ancestor_guards(staging.ancestor_guards(), target);
                return Err(CreateError::Failed);
            }
            published_guard.map_err(|_| CreateError::Failed)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            Err(CreateError::AlreadyExists)
        }
        Err(_) => Err(CreateError::Failed),
    }
}

#[cfg(all(test, windows))]
pub(crate) fn seal_published_vault(published: &File, target: &Path) -> Result<File, CreateError> {
    let ancestor_guards = acquire_ancestor_guards(target).map_err(|_| CreateError::Failed)?;
    seal_published_vault_with_ancestor_guards(published, target, &ancestor_guards)
}

pub(crate) fn seal_published_vault_with_ancestor_guards(
    published: &File,
    target: &Path,
    ancestor_guards: &AncestorGuards,
) -> Result<File, CreateError> {
    let sealed = open_regular_file_guard_with_ancestor_guards(ancestor_guards, target, false, true)
        .map_err(|_| CreateError::Failed)?;
    guarded_files_match(published, &sealed).map_err(|_| CreateError::Failed)?;
    ensure_sidecars_absent_with_ancestor_guards(ancestor_guards, target)
        .map_err(|_| CreateError::Failed)?;
    Ok(sealed)
}

pub(crate) fn verify_published_vault(
    published: &File,
    target: &Path,
    expected_header: &[u8],
    expected_manifest: &[u8],
) -> Result<GuardedEmptyVault, CreateError> {
    let snapshot = read_guarded_empty_vault(target).map_err(|_| CreateError::Failed)?;
    guarded_files_match(published, &snapshot.input_guards.database)
        .map_err(|_| CreateError::Failed)?;
    if snapshot.header != expected_header || snapshot.manifest != expected_manifest {
        return Err(CreateError::Failed);
    }
    Ok(snapshot)
}

pub(crate) fn remove_target_if_guarded_matches(
    published: &File,
    target: &Path,
    ancestor_guards: &AncestorGuards,
) {
    let Ok(current) =
        open_regular_file_guard_with_ancestor_guards(ancestor_guards, target, true, true)
    else {
        return;
    };
    if guarded_files_match(published, &current).is_err() {
        return;
    }
    drop(current);
    let _ = remove_file_with_ancestor_guards(ancestor_guards, target);
}

pub(crate) struct StagedVault {
    path: PathBuf,
    reservation: Option<File>,
    ancestor_guards: AncestorGuards,
}

impl StagedVault {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn release_reservation(&mut self) {
        drop(self.reservation.take());
    }

    pub(crate) fn reservation_mut(&mut self) -> Option<&mut File> {
        self.reservation.as_mut()
    }

    #[cfg(all(test, unix))]
    pub(crate) fn reservation(&self) -> Option<&File> {
        self.reservation.as_ref()
    }

    pub(crate) fn ancestor_guards(&self) -> &AncestorGuards {
        &self.ancestor_guards
    }

    pub(crate) fn try_clone_reservation(&self) -> io::Result<File> {
        self.reservation
            .as_ref()
            .ok_or_else(|| io::Error::other("staging reservation is not live"))?
            .try_clone()
    }

    pub(crate) fn remove_name(&mut self) -> io::Result<()> {
        self.release_reservation();
        remove_file_with_ancestor_guards(&self.ancestor_guards, &self.path)
    }
}

impl Drop for StagedVault {
    fn drop(&mut self) {
        self.release_reservation();
        let _ = remove_file_with_ancestor_guards(&self.ancestor_guards, &self.path);
        let _ = remove_file_with_ancestor_guards(
            &self.ancestor_guards,
            &sqlite_sidecar(&self.path, "-wal"),
        );
        let _ = remove_file_with_ancestor_guards(
            &self.ancestor_guards,
            &sqlite_sidecar(&self.path, "-shm"),
        );
    }
}
