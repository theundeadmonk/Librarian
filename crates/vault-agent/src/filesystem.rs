#[cfg(unix)]
use std::path::Component;
#[cfg(not(unix))]
use std::{env, fs::OpenOptions};
use std::{
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};

use crate::errors::StorageError;

#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const FILE_SHARE_READ: u32 = 0x0000_0001;
#[cfg(windows)]
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
#[cfg(windows)]
const FILE_SHARE_DELETE: u32 = 0x0000_0004;

#[cfg(windows)]
pub(crate) fn sync_parent_directory(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;

    OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(parent_directory(path))?
        .sync_all()
}

#[cfg(all(test, unix))]
pub(crate) fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let ancestor_guards = acquire_ancestor_guards(path)?;
    sync_parent_directory_with_ancestor_guards(path, &ancestor_guards)
}

#[cfg(all(not(unix), not(windows)))]
pub(crate) fn sync_parent_directory(path: &Path) -> io::Result<()> {
    File::open(parent_directory(path))?.sync_all()
}

pub(crate) fn guarded_optional_file_matches_path_with_ancestor_guards(
    file: Option<&File>,
    path: &Path,
    ancestor_guards: &AncestorGuards,
) -> Result<(), StorageError> {
    match file {
        Some(file) => guarded_file_matches_path_with_ancestor_guards(file, path, ancestor_guards),
        None => match open_existing_guard_with_ancestor_guards(ancestor_guards, path, true, true) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(StorageError::Identity),
            Err(_) => Err(StorageError::Filesystem),
        },
    }
}

#[cfg(unix)]
pub(crate) fn guarded_files_match(left: &File, right: &File) -> Result<(), StorageError> {
    use std::os::unix::fs::MetadataExt;

    let left = left.metadata().map_err(|_| StorageError::Filesystem)?;
    let right = right.metadata().map_err(|_| StorageError::Filesystem)?;
    if !left.is_file() || !right.is_file() || left.dev() != right.dev() || left.ino() != right.ino()
    {
        return Err(StorageError::Identity);
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn guarded_files_match(left: &File, right: &File) -> Result<(), StorageError> {
    let left =
        same_file::Handle::from_file(left.try_clone().map_err(|_| StorageError::Filesystem)?)
            .map_err(|_| StorageError::Filesystem)?;
    let right =
        same_file::Handle::from_file(right.try_clone().map_err(|_| StorageError::Filesystem)?)
            .map_err(|_| StorageError::Filesystem)?;
    if left != right {
        return Err(StorageError::Identity);
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn guarded_files_match(left: &File, right: &File) -> Result<(), StorageError> {
    let left = left.metadata().map_err(|_| StorageError::Filesystem)?;
    let right = right.metadata().map_err(|_| StorageError::Filesystem)?;
    if !left.is_file() || !right.is_file() || left.len() != right.len() {
        return Err(StorageError::Identity);
    }
    Ok(())
}

pub(crate) fn guarded_file_matches_path_with_ancestor_guards(
    file: &File,
    path: &Path,
    ancestor_guards: &AncestorGuards,
) -> Result<(), StorageError> {
    let current = open_regular_file_guard_with_ancestor_guards(ancestor_guards, path, true, true)
        .map_err(|_| StorageError::Filesystem)?;
    guarded_files_match(file, &current)
}

pub(crate) fn guarded_file_size(
    file: Option<&File>,
    maximum_bytes: u64,
) -> Result<u64, StorageError> {
    let Some(file) = file else {
        return Ok(0);
    };
    let metadata = file.metadata().map_err(|_| StorageError::Filesystem)?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(StorageError::Identity);
    }
    if metadata.len() > maximum_bytes {
        return Err(StorageError::ResourceLimit);
    }
    Ok(metadata.len())
}

pub(crate) fn open_optional_regular_file_guard_with_ancestor_guards(
    ancestor_guards: &AncestorGuards,
    path: &Path,
    share_writes: bool,
    share_deletes: bool,
) -> Result<Option<File>, StorageError> {
    match open_regular_file_guard_with_ancestor_guards(
        ancestor_guards,
        path,
        share_writes,
        share_deletes,
    ) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(StorageError::Filesystem),
    }
}

pub(crate) fn open_regular_file_guard_with_ancestor_guards(
    ancestor_guards: &AncestorGuards,
    path: &Path,
    share_writes: bool,
    share_deletes: bool,
) -> io::Result<File> {
    let file = open_existing_guard_with_ancestor_guards(
        ancestor_guards,
        path,
        share_writes,
        share_deletes,
    )?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "non-regular or redirected file rejected",
        ));
    }
    Ok(file)
}

#[cfg(unix)]
pub(crate) fn open_existing_guard_with_ancestor_guards(
    ancestor_guards: &AncestorGuards,
    path: &Path,
    _share_writes: bool,
    _share_deletes: bool,
) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags, openat};

    let name = child_name(path)?;
    Ok(File::from(openat(
        &ancestor_guards.directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?))
}

#[cfg(not(unix))]
pub(crate) fn open_existing_guard_with_ancestor_guards(
    _ancestor_guards: &AncestorGuards,
    path: &Path,
    share_writes: bool,
    share_deletes: bool,
) -> io::Result<File> {
    open_existing_guard(path, share_writes, share_deletes)
}

#[cfg(windows)]
pub(crate) fn open_existing_guard(
    path: &Path,
    share_writes: bool,
    share_deletes: bool,
) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    let mut share_mode = FILE_SHARE_READ;
    if share_writes {
        share_mode |= FILE_SHARE_WRITE;
    }
    if share_deletes {
        share_mode |= FILE_SHARE_DELETE;
    }
    OpenOptions::new()
        .read(true)
        .share_mode(share_mode)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn open_existing_guard(
    path: &Path,
    _share_writes: bool,
    _share_deletes: bool,
) -> io::Result<File> {
    reject_reparse(path)?;
    OpenOptions::new().read(true).open(path)
}

#[cfg(windows)]
pub(crate) fn create_staging_reservation(
    _ancestor_guards: &AncestorGuards,
    path: &Path,
) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(unix)]
pub(crate) fn create_staging_reservation(
    ancestor_guards: &AncestorGuards,
    path: &Path,
) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags, openat};

    Ok(File::from(openat(
        &ancestor_guards.directory,
        child_name(path)?,
        OFlags::RDWR
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
    )?))
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn create_staging_reservation(
    _ancestor_guards: &AncestorGuards,
    path: &Path,
) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

pub(crate) struct AncestorGuards {
    #[cfg(windows)]
    _handles: Vec<File>,
    #[cfg(unix)]
    directory: File,
}

#[cfg(windows)]
pub(crate) fn acquire_ancestor_guards(path: &Path) -> io::Result<AncestorGuards> {
    use std::os::windows::fs::OpenOptionsExt;

    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    let mut ancestors = parent_directory(&absolute_path)
        .ancestors()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .collect::<Vec<_>>();
    ancestors.reverse();

    let mut handles = Vec::with_capacity(ancestors.len());
    for ancestor in ancestors {
        let handle = OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(ancestor)?;
        let metadata = handle.metadata()?;
        if !metadata.is_dir() || is_reparse_point(&metadata) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "redirected ancestor rejected",
            ));
        }
        handles.push(handle);
    }
    Ok(AncestorGuards { _handles: handles })
}

#[cfg(unix)]
pub(crate) fn acquire_ancestor_guards(path: &Path) -> io::Result<AncestorGuards> {
    use rustix::fs::{Mode, OFlags, open, openat};

    if path.file_name().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "vault path must have a file name",
        ));
    }

    let directory_flags =
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let mut directory = if path.is_absolute() {
        File::from(open("/", directory_flags, Mode::empty())?)
    } else {
        File::from(open(".", directory_flags, Mode::empty())?)
    };
    for component in parent_directory(path).components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::ParentDir => Path::new("..").as_os_str(),
            Component::Normal(name) => name,
            Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported Unix path prefix",
                ));
            }
        };
        directory = File::from(openat(&directory, name, directory_flags, Mode::empty())?);
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || is_reparse_point(&metadata) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "redirected ancestor rejected",
            ));
        }
    }
    Ok(AncestorGuards { directory })
}

#[cfg(all(not(unix), not(windows)))]
pub(crate) fn acquire_ancestor_guards(path: &Path) -> io::Result<AncestorGuards> {
    reject_reparse_ancestors(path)?;
    Ok(AncestorGuards {})
}

#[cfg(unix)]
pub(crate) fn child_name(path: &Path) -> io::Result<&std::ffi::OsStr> {
    path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "vault path must have a file name",
        )
    })
}

#[cfg(unix)]
pub(crate) fn hard_link_with_ancestor_guards(
    ancestor_guards: &AncestorGuards,
    source: &Path,
    target: &Path,
) -> io::Result<()> {
    use rustix::fs::{AtFlags, linkat};

    Ok(linkat(
        &ancestor_guards.directory,
        child_name(source)?,
        &ancestor_guards.directory,
        child_name(target)?,
        AtFlags::empty(),
    )?)
}

#[cfg(not(unix))]
pub(crate) fn hard_link_with_ancestor_guards(
    _ancestor_guards: &AncestorGuards,
    source: &Path,
    target: &Path,
) -> io::Result<()> {
    fs::hard_link(source, target)
}

#[cfg(unix)]
pub(crate) fn remove_file_with_ancestor_guards(
    ancestor_guards: &AncestorGuards,
    path: &Path,
) -> io::Result<()> {
    use rustix::fs::{AtFlags, unlinkat};

    Ok(unlinkat(
        &ancestor_guards.directory,
        child_name(path)?,
        AtFlags::empty(),
    )?)
}

#[cfg(not(unix))]
pub(crate) fn remove_file_with_ancestor_guards(
    _ancestor_guards: &AncestorGuards,
    path: &Path,
) -> io::Result<()> {
    fs::remove_file(path)
}

#[cfg(unix)]
pub(crate) fn sync_parent_directory_with_ancestor_guards(
    _path: &Path,
    ancestor_guards: &AncestorGuards,
) -> io::Result<()> {
    ancestor_guards.directory.sync_all()
}

#[cfg(not(unix))]
pub(crate) fn sync_parent_directory_with_ancestor_guards(
    path: &Path,
    _ancestor_guards: &AncestorGuards,
) -> io::Result<()> {
    sync_parent_directory(path)
}

pub(crate) fn ensure_sidecars_absent_with_ancestor_guards(
    ancestor_guards: &AncestorGuards,
    path: &Path,
) -> Result<(), StorageError> {
    for suffix in ["-wal", "-shm"] {
        match open_existing_guard_with_ancestor_guards(
            ancestor_guards,
            &sqlite_sidecar(path, suffix),
            true,
            true,
        ) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => return Err(StorageError::Sidecar),
            Err(_) => return Err(StorageError::Filesystem),
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn reject_reparse(path: &Path) -> io::Result<fs::Metadata> {
    reject_reparse_ancestors(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if is_reparse_point(&metadata) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path redirection rejected",
        )),
        Ok(metadata) => Ok(metadata),
        Err(error) => Err(error),
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn reject_reparse_ancestors(path: &Path) -> io::Result<()> {
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    for ancestor in parent_directory(&absolute_path).ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        if is_reparse_point(&fs::symlink_metadata(ancestor)?) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "redirected ancestor rejected",
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
pub(crate) fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

pub(crate) fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

pub(crate) fn sqlite_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{StorageError, guarded_file_size};

    static FILE_COUNTER: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn guarded_file_size_reports_the_resource_limit_category() {
        let sequence = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "librarian-filesystem-limit-{}-{sequence}",
            std::process::id()
        ));
        std::fs::write(&path, [0_u8; 2]).expect("limit fixture must be written");
        let file = std::fs::File::open(&path).expect("limit fixture must open");

        assert_eq!(
            guarded_file_size(Some(&file), 1),
            Err(StorageError::ResourceLimit)
        );

        drop(file);
        std::fs::remove_file(path).expect("limit fixture must be removed");
    }
}
