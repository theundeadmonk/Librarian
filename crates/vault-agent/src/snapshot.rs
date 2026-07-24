use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use rusqlite::{Connection, OpenFlags};

use crate::{
    errors::StorageError,
    filesystem::sqlite_sidecar,
    sqlite::{
        SQLITE_HEADER_BYTES, SQLITE_MAGIC, SQLITE_READ_VERSION_OFFSET, SQLITE_WAL_VERSION,
        SQLITE_WRITE_VERSION_OFFSET, SqliteInputGuards,
    },
    storage::MAX_STAGING_ATTEMPTS,
};

pub(crate) fn validate_wal_database_header(database: &mut File) -> Result<(), StorageError> {
    let mut header = [0_u8; SQLITE_HEADER_BYTES];
    database
        .seek(SeekFrom::Start(0))
        .map_err(|_| StorageError::Filesystem)?;
    database
        .read_exact(&mut header)
        .map_err(|_| StorageError::Filesystem)?;
    database
        .seek(SeekFrom::Start(0))
        .map_err(|_| StorageError::Filesystem)?;
    if &header[..SQLITE_MAGIC.len()] != SQLITE_MAGIC
        || header[SQLITE_READ_VERSION_OFFSET] != SQLITE_WAL_VERSION
        || header[SQLITE_WRITE_VERSION_OFFSET] != SQLITE_WAL_VERSION
    {
        return Err(StorageError::InvalidDatabaseHeader);
    }
    Ok(())
}

#[cfg(any(unix, windows))]
pub(crate) fn open_guarded_read_connection(
    _path: &Path,
    input_guards: &mut SqliteInputGuards,
) -> Result<GuardedReadConnection, StorageError> {
    let snapshot = GuardedSqliteSnapshot::create(input_guards)?;
    let connection = Connection::open_with_flags(
        &snapshot.database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| StorageError::Sqlite)?;
    Ok(GuardedReadConnection {
        connection,
        _snapshot: snapshot,
    })
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn open_guarded_read_connection(
    path: &Path,
    _input_guards: &mut SqliteInputGuards,
) -> Result<GuardedReadConnection, StorageError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| StorageError::Sqlite)?;
    Ok(GuardedReadConnection { connection })
}

pub(crate) struct GuardedReadConnection {
    connection: Connection,
    #[cfg(any(unix, windows))]
    _snapshot: GuardedSqliteSnapshot,
}

impl std::ops::Deref for GuardedReadConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

#[cfg(any(unix, windows))]
pub(crate) struct GuardedSqliteSnapshot {
    database: PathBuf,
    directory: PathBuf,
}

#[cfg(any(unix, windows))]
impl GuardedSqliteSnapshot {
    fn create(input: &SqliteInputGuards) -> Result<Self, StorageError> {
        let directory = reserve_sqlite_snapshot_directory()?;
        let database = directory.join("vault.sqlite3");
        if copy_guarded_snapshot_file(&input.database, &database).is_err()
            || input.wal.as_ref().is_some_and(|wal| {
                copy_guarded_snapshot_file(wal, &sqlite_sidecar(&database, "-wal")).is_err()
            })
        {
            let snapshot = Self {
                database,
                directory,
            };
            drop(snapshot);
            return Err(StorageError::Snapshot);
        }
        Ok(Self {
            database,
            directory,
        })
    }
}

#[cfg(any(unix, windows))]
impl Drop for GuardedSqliteSnapshot {
    fn drop(&mut self) {
        for suffix in ["-shm", "-wal", "-journal"] {
            let _ = fs::remove_file(sqlite_sidecar(&self.database, suffix));
        }
        let _ = fs::remove_file(&self.database);
        let _ = fs::remove_dir(&self.directory);
    }
}

#[cfg(any(unix, windows))]
pub(crate) fn reserve_sqlite_snapshot_directory() -> Result<PathBuf, StorageError> {
    for _ in 0..MAX_STAGING_ATTEMPTS {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| StorageError::Randomness)?;
        let directory = env::temp_dir().join(format!(
            "librarian-vault-snapshot-{:032x}",
            u128::from_le_bytes(random)
        ));
        match create_private_snapshot_directory(&directory) {
            Ok(()) => return Ok(directory),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(StorageError::Filesystem),
        }
    }
    Err(StorageError::Snapshot)
}

#[cfg(unix)]
pub(crate) fn create_private_snapshot_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(windows)]
pub(crate) fn create_private_snapshot_directory(path: &Path) -> io::Result<()> {
    fs::create_dir(path)
}

#[cfg(any(unix, windows))]
pub(crate) fn copy_guarded_snapshot_file(source: &File, target: &Path) -> Result<(), StorageError> {
    let expected_bytes = source
        .metadata()
        .map_err(|_| StorageError::Filesystem)?
        .len();
    let mut source = source.try_clone().map_err(|_| StorageError::Filesystem)?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| StorageError::Filesystem)?;
    let mut target = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(|_| StorageError::Filesystem)?;
    let copied_bytes = io::copy(&mut source.take(expected_bytes), &mut target)
        .map_err(|_| StorageError::Filesystem)?;
    if copied_bytes != expected_bytes {
        return Err(StorageError::Snapshot);
    }
    target.sync_all().map_err(|_| StorageError::Filesystem)
}

#[cfg(test)]
mod tests {
    use std::{
        fs::OpenOptions,
        io::Write,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::{SQLITE_HEADER_BYTES, StorageError, validate_wal_database_header};

    static FILE_COUNTER: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn malformed_sqlite_header_has_a_non_secret_internal_category() {
        let sequence = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "librarian-snapshot-header-{}-{sequence}",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("header fixture must be created");
        file.write_all(&[0_u8; SQLITE_HEADER_BYTES])
            .expect("header fixture must be written");

        assert_eq!(
            validate_wal_database_header(&mut file),
            Err(StorageError::InvalidDatabaseHeader)
        );

        drop(file);
        std::fs::remove_file(path).expect("header fixture must be removed");
    }
}
