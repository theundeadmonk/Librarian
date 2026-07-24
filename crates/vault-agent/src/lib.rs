//! `SQLite` ownership and lock-state lifecycle for the trusted local vault agent.
//!
//! This is not an IPC server yet. Issue #13 will expose a constrained protocol;
//! for the code slice tracked by issue #10, this crate proves that only the
//! agent opens the vault file and that a restart begins locked. Issue #10
//! remains open until its slowest-supported-Windows benchmark gate is met.

#![forbid(unsafe_code)]

use std::{
    env, fmt,
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use librarian_vault_core::{
    CancellationFlag, MasterPassword, RecoveryKey, UnlockedVault, create_vault, unlock_empty_vault,
};
#[cfg(unix)]
use rusqlite::MAIN_DB;
#[cfg(not(unix))]
use rusqlite::OpenFlags;
use rusqlite::{Connection, TransactionBehavior, config::DbConfig, limits::Limit, params};
#[cfg(unix)]
use std::io::{Read, Seek, SeekFrom, Write};

const MAX_SQLITE_VALUE_BYTES: i32 = 8 * 1024 * 1024;
const MAX_PAGE_COUNT: u32 = 131_072;
const MAX_SQLITE_SHM_BYTES: u64 = 8 * 1024 * 1024;
const MAX_STAGING_ATTEMPTS: u64 = 128;

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

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_STAGING_ID: AtomicU64 = AtomicU64::new(1);

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
    path: PathBuf,
    session: Option<UnlockedVault>,
    session_id: Option<u64>,
    authorization_epoch: u64,
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
        let path = path.as_ref().to_path_buf();
        validate_new_target(&path)?;
        let mut staging = reserve_staging_file(&path)?;

        let created_at_ms = unix_time_ms().map_err(|()| CreateError::Failed)?;
        let created = create_vault(password, created_at_ms).map_err(|_| CreateError::Failed)?;
        let (header, manifest, recovery_key, session) = created.into_parts();
        let session_id = next_session_id().ok_or(CreateError::Failed)?;

        initialize_database(&mut staging, &header, &manifest).map_err(|_| CreateError::Failed)?;
        ensure_sidecars_absent(staging.path()).map_err(|()| CreateError::Failed)?;
        publish_staged_vault(&mut staging, &path)?;
        if staging.remove_name().is_err() {
            let _ = fs::remove_file(&path);
            return Err(CreateError::Failed);
        }
        if sync_parent_directory(&path).is_err() {
            let _ = fs::remove_file(&path);
            let _ = sync_parent_directory(&path);
            return Err(CreateError::Failed);
        }

        Ok((
            Self {
                path,
                session: Some(session),
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
            path: path.as_ref().to_path_buf(),
            session: None,
            session_id: None,
            authorization_epoch: 0,
        }
    }

    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.session.is_some()
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

    fn unlock_with_before_publish(
        &mut self,
        password: MasterPassword,
        cancellation: &CancellationFlag,
        before_publish: impl FnOnce(),
    ) -> Result<(), UnlockError> {
        self.lock();
        let (header, manifest) = read_empty_vault(&self.path).map_err(|()| UnlockError::Failed)?;
        let session = match unlock_empty_vault(password, &header, &manifest, cancellation) {
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
        let Some(session_id) = next_session_id() else {
            return Err(UnlockError::Failed);
        };
        if !self.advance_authorization_epoch() {
            return Err(UnlockError::Failed);
        }
        self.session = Some(session);
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

fn validate_new_target(path: &Path) -> Result<(), CreateError> {
    let _ancestor_guards = acquire_ancestor_guards(path).map_err(|_| CreateError::Failed)?;
    validate_new_target_with_guarded_ancestors(path)
}

fn validate_new_target_with_guarded_ancestors(path: &Path) -> Result<(), CreateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if is_reparse_point(&metadata) => return Err(CreateError::Failed),
        Ok(_) => return Err(CreateError::AlreadyExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(CreateError::Failed),
    }
    if path.file_name().is_none() {
        return Err(CreateError::Failed);
    }
    Ok(())
}

fn reserve_staging_file(target: &Path) -> Result<StagedVault, CreateError> {
    let ancestor_guards = acquire_ancestor_guards(target).map_err(|_| CreateError::Failed)?;
    validate_new_target_with_guarded_ancestors(target)?;
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
        match create_staging_reservation(&staging_path) {
            Ok(reservation) => {
                return Ok(StagedVault {
                    path: staging_path,
                    reservation: Some(reservation),
                    _ancestor_guards: ancestor_guards,
                });
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(CreateError::Failed),
        }
    }
    Err(CreateError::Failed)
}

fn publish_staged_vault(staging: &mut StagedVault, target: &Path) -> Result<(), CreateError> {
    reject_reparse_ancestors(target).map_err(|_| CreateError::Failed)?;
    ensure_sidecars_absent(target).map_err(|()| CreateError::Failed)?;
    let reservation = staging
        .try_clone_reservation()
        .map_err(|_| CreateError::Failed)?;
    guarded_file_matches_path(&reservation, staging.path()).map_err(|()| CreateError::Failed)?;
    match fs::hard_link(staging.path(), target) {
        Ok(()) => {
            let published_guard = open_regular_file_guard(target, true, false);
            #[cfg(unix)]
            let publication_is_valid = published_guard
                .as_ref()
                .is_ok_and(|published| guarded_files_match(&reservation, published).is_ok());
            #[cfg(not(unix))]
            let publication_is_valid = published_guard.is_ok();
            if !publication_is_valid || ensure_sidecars_absent(target).is_err() {
                drop(published_guard);
                staging.release_reservation();
                let _ = fs::remove_file(target);
                return Err(CreateError::Failed);
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            Err(CreateError::AlreadyExists)
        }
        Err(_) => Err(CreateError::Failed),
    }
}

#[cfg(windows)]
fn sync_parent_directory(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;

    OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(parent_directory(path))?
        .sync_all()
}

#[cfg(not(windows))]
fn sync_parent_directory(path: &Path) -> io::Result<()> {
    fs::File::open(parent_directory(path))?.sync_all()
}

#[cfg(not(unix))]
fn initialize_database(
    staging: &mut StagedVault,
    header: &[u8],
    manifest: &[u8],
) -> rusqlite::Result<()> {
    let path = staging.path();
    let mut connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    initialize_connection(&mut connection, header, manifest, true)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(connection);

    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(())
}

#[cfg(unix)]
fn initialize_database(
    staging: &mut StagedVault,
    header: &[u8],
    manifest: &[u8],
) -> rusqlite::Result<()> {
    let mut connection = Connection::open_in_memory()?;
    initialize_connection(&mut connection, header, manifest, false)?;
    let image = connection.serialize(MAIN_DB)?;
    let reservation = staging
        .reservation
        .as_mut()
        .ok_or(rusqlite::Error::InvalidQuery)?;
    reservation
        .seek(SeekFrom::Start(0))
        .and_then(|_| reservation.write_all(&image))
        .and_then(|()| reservation.set_len(u64::try_from(image.len()).map_err(io::Error::other)?))
        .and_then(|()| reservation.sync_all())
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(())
}

fn initialize_connection(
    connection: &mut Connection,
    header: &[u8],
    manifest: &[u8],
    use_wal: bool,
) -> rusqlite::Result<()> {
    configure_limits(connection)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    connection.pragma_update(None, "page_size", 4096)?;
    if use_wal {
        connection.pragma_update(None, "journal_mode", "WAL")?;
    }
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "max_page_count", MAX_PAGE_COUNT)?;
    connection.execute_batch(
        "
        CREATE TABLE vault_header (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            header BLOB NOT NULL
        ) STRICT;

        CREATE TABLE vault_manifest (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            envelope BLOB NOT NULL
        ) STRICT;

        CREATE TABLE encrypted_records (
            record_id BLOB PRIMARY KEY NOT NULL CHECK (length(record_id) = 16),
            envelope BLOB NOT NULL
        ) STRICT, WITHOUT ROWID;
        ",
    )?;

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT INTO vault_header(singleton, header) VALUES (1, ?1)",
        params![header],
    )?;
    transaction.execute(
        "INSERT INTO vault_manifest(singleton, envelope) VALUES (1, ?1)",
        params![manifest],
    )?;
    transaction.commit()?;
    Ok(())
}

fn read_empty_vault(path: &Path) -> Result<(Vec<u8>, Vec<u8>), ()> {
    read_empty_vault_with_connection_hooks(path, || {}, || {})
}

fn read_empty_vault_with_connection_hooks(
    path: &Path,
    before_connection: impl FnOnce(),
    after_connection: impl FnOnce(),
) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let mut input_guards = acquire_sqlite_input_guards(path)?;
    validate_guarded_sqlite_input_sizes(&input_guards)?;
    validate_guarded_sqlite_input_paths(path, &input_guards)?;

    before_connection();
    let connection = open_guarded_read_connection(path, &mut input_guards)?;
    after_connection();
    configure_limits(&connection).map_err(|_| ())?;
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(|_| ())?;
    connection
        .pragma_update(None, "trusted_schema", false)
        .map_err(|_| ())?;
    refresh_sqlite_sidecar_guards(path, &mut input_guards)?;
    validate_guarded_sqlite_input_sizes(&input_guards)?;
    validate_sqlite_input_sizes(
        path,
        input_guards.database.metadata().map_err(|_| ())?.len(),
    )?;
    validate_guarded_sqlite_input_paths(path, &input_guards)?;
    verify_application_schema(&connection)?;

    let header: Vec<u8> = connection
        .query_row(
            "SELECT header FROM vault_header WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| ())?;
    let manifest: Vec<u8> = connection
        .query_row(
            "SELECT envelope FROM vault_manifest WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| ())?;
    let (header_count, manifest_count, record_count): (i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM vault_header),
                (SELECT COUNT(*) FROM vault_manifest),
                (SELECT COUNT(*) FROM encrypted_records)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| ())?;

    if header.len() > librarian_vault_format::MAX_HEADER_BYTES
        || manifest.len() > librarian_vault_format::MAX_MANIFEST_ENVELOPE_BYTES
        || header_count != 1
        || manifest_count != 1
        || record_count != 0
    {
        return Err(());
    }
    reacquire_sqlite_sidecar_guards(path, &mut input_guards)?;
    validate_guarded_sqlite_input_sizes(&input_guards)?;
    validate_sqlite_input_sizes(
        path,
        input_guards.database.metadata().map_err(|_| ())?.len(),
    )?;
    validate_guarded_sqlite_input_paths(path, &input_guards)?;
    Ok((header, manifest))
}

#[cfg(unix)]
fn open_guarded_read_connection(
    _path: &Path,
    input_guards: &mut SqliteInputGuards,
) -> Result<Connection, ()> {
    if input_guards.wal.is_some() || input_guards.shm.is_some() {
        return Err(());
    }
    let database_bytes = input_guards.database.metadata().map_err(|_| ())?.len();
    let database_bytes = usize::try_from(database_bytes).map_err(|_| ())?;
    input_guards
        .database
        .seek(SeekFrom::Start(0))
        .map_err(|_| ())?;
    let mut connection = Connection::open_in_memory().map_err(|_| ())?;
    connection
        .deserialize_read_exact(
            MAIN_DB,
            Read::by_ref(&mut input_guards.database)
                .take(u64::try_from(database_bytes).map_err(|_| ())?),
            database_bytes,
            true,
        )
        .map_err(|_| ())?;
    Ok(connection)
}

#[cfg(not(unix))]
fn open_guarded_read_connection(
    path: &Path,
    _input_guards: &mut SqliteInputGuards,
) -> Result<Connection, ()> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| ())
}

fn verify_application_schema(connection: &Connection) -> Result<(), ()> {
    let mut statement = connection
        .prepare(
            "SELECT type, name FROM sqlite_schema
             WHERE name NOT GLOB 'sqlite_*'
             ORDER BY type, name",
        )
        .map_err(|_| ())?;
    let application_objects = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| ())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ())?;
    if application_objects
        != [
            ("table".to_owned(), "encrypted_records".to_owned()),
            ("table".to_owned(), "vault_header".to_owned()),
            ("table".to_owned(), "vault_manifest".to_owned()),
        ]
    {
        return Err(());
    }

    let expected_schema = [
        (
            "encrypted_records",
            "CREATE TABLE encrypted_records ( record_id BLOB PRIMARY KEY NOT NULL CHECK (length(record_id) = 16), envelope BLOB NOT NULL ) STRICT, WITHOUT ROWID",
        ),
        (
            "vault_header",
            "CREATE TABLE vault_header ( singleton INTEGER PRIMARY KEY CHECK (singleton = 1), header BLOB NOT NULL ) STRICT",
        ),
        (
            "vault_manifest",
            "CREATE TABLE vault_manifest ( singleton INTEGER PRIMARY KEY CHECK (singleton = 1), envelope BLOB NOT NULL ) STRICT",
        ),
    ];
    for (table, expected_sql) in expected_schema {
        let strict: u32 = connection
            .query_row(
                "SELECT strict FROM pragma_table_list WHERE name = ?1",
                [table],
                |row| row.get(0),
            )
            .map_err(|_| ())?;
        if strict != 1 {
            return Err(());
        }
        let schema_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .map_err(|_| ())?;
        if schema_sql.split_whitespace().collect::<Vec<_>>().join(" ") != expected_sql {
            return Err(());
        }
    }

    Ok(())
}

fn configure_limits(connection: &Connection) -> rusqlite::Result<()> {
    connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, MAX_SQLITE_VALUE_BYTES)?;
    connection.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 64 * 1024)?;
    connection.set_limit(Limit::SQLITE_LIMIT_COLUMN, 16)?;
    connection.set_limit(Limit::SQLITE_LIMIT_EXPR_DEPTH, 32)?;
    connection.set_limit(Limit::SQLITE_LIMIT_COMPOUND_SELECT, 4)?;
    connection.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)?;
    Ok(())
}

fn validate_sqlite_input_sizes(path: &Path, database_bytes: u64) -> Result<(), ()> {
    let wal_bytes =
        optional_sidecar_size(path, "-wal", librarian_vault_format::MAX_DATABASE_BYTES)?;
    let shm_bytes = optional_sidecar_size(path, "-shm", MAX_SQLITE_SHM_BYTES)?;
    let total_bytes = database_bytes
        .checked_add(wal_bytes)
        .and_then(|value| value.checked_add(shm_bytes))
        .ok_or(())?;
    if total_bytes > librarian_vault_format::MAX_DATABASE_BYTES {
        return Err(());
    }
    Ok(())
}

fn optional_sidecar_size(path: &Path, suffix: &str, maximum_bytes: u64) -> Result<u64, ()> {
    let sidecar_path = sqlite_sidecar(path, suffix);
    match reject_reparse(&sidecar_path) {
        Ok(metadata) if metadata.is_file() && metadata.len() <= maximum_bytes => Ok(metadata.len()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Ok(_) | Err(_) => Err(()),
    }
}

fn ensure_sidecars_absent(path: &Path) -> Result<(), ()> {
    for suffix in ["-wal", "-shm"] {
        match fs::symlink_metadata(sqlite_sidecar(path, suffix)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(()),
        }
    }
    Ok(())
}

struct SqliteInputGuards {
    database: File,
    wal: Option<File>,
    shm: Option<File>,
    _ancestor_guards: AncestorGuards,
}

fn acquire_sqlite_input_guards(path: &Path) -> Result<SqliteInputGuards, ()> {
    let ancestor_guards = acquire_ancestor_guards(path).map_err(|_| ())?;
    let database = open_regular_file_guard(path, false, false).map_err(|_| ())?;
    let wal = open_optional_regular_file_guard(&sqlite_sidecar(path, "-wal"))?;
    let shm = open_optional_regular_file_guard(&sqlite_sidecar(path, "-shm"))?;
    Ok(SqliteInputGuards {
        database,
        wal,
        shm,
        _ancestor_guards: ancestor_guards,
    })
}

fn refresh_sqlite_sidecar_guards(path: &Path, input: &mut SqliteInputGuards) -> Result<(), ()> {
    if input.wal.is_none() {
        input.wal = open_optional_regular_file_guard(&sqlite_sidecar(path, "-wal"))?;
    }
    if input.shm.is_none() {
        input.shm = open_optional_regular_file_guard(&sqlite_sidecar(path, "-shm"))?;
    }
    Ok(())
}

fn reacquire_sqlite_sidecar_guards(path: &Path, input: &mut SqliteInputGuards) -> Result<(), ()> {
    input.wal = None;
    input.shm = None;
    refresh_sqlite_sidecar_guards(path, input)
}

fn validate_guarded_sqlite_input_sizes(input: &SqliteInputGuards) -> Result<(), ()> {
    let database_bytes = input.database.metadata().map_err(|_| ())?.len();
    let wal_bytes = guarded_file_size(
        input.wal.as_ref(),
        librarian_vault_format::MAX_DATABASE_BYTES,
    )?;
    let shm_bytes = guarded_file_size(input.shm.as_ref(), MAX_SQLITE_SHM_BYTES)?;
    let total_bytes = database_bytes
        .checked_add(wal_bytes)
        .and_then(|value| value.checked_add(shm_bytes))
        .ok_or(())?;
    if total_bytes > librarian_vault_format::MAX_DATABASE_BYTES {
        return Err(());
    }
    Ok(())
}

fn validate_guarded_sqlite_input_paths(path: &Path, input: &SqliteInputGuards) -> Result<(), ()> {
    guarded_file_matches_path(&input.database, path)?;
    guarded_optional_file_matches_path(input.wal.as_ref(), &sqlite_sidecar(path, "-wal"))?;
    guarded_optional_file_matches_path(input.shm.as_ref(), &sqlite_sidecar(path, "-shm"))?;
    Ok(())
}

fn guarded_optional_file_matches_path(file: Option<&File>, path: &Path) -> Result<(), ()> {
    match file {
        Some(file) => guarded_file_matches_path(file, path),
        None => match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Ok(_) | Err(_) => Err(()),
        },
    }
}

#[cfg(unix)]
fn guarded_files_match(left: &File, right: &File) -> Result<(), ()> {
    use std::os::unix::fs::MetadataExt;

    let left = left.metadata().map_err(|_| ())?;
    let right = right.metadata().map_err(|_| ())?;
    if !left.is_file() || !right.is_file() || left.dev() != right.dev() || left.ino() != right.ino()
    {
        return Err(());
    }
    Ok(())
}

#[cfg(unix)]
fn guarded_file_matches_path(file: &File, path: &Path) -> Result<(), ()> {
    use std::os::unix::fs::MetadataExt;

    let guarded = file.metadata().map_err(|_| ())?;
    let current = fs::symlink_metadata(path).map_err(|_| ())?;
    if is_reparse_point(&current)
        || !current.is_file()
        || guarded.dev() != current.dev()
        || guarded.ino() != current.ino()
    {
        return Err(());
    }
    Ok(())
}

#[cfg(windows)]
fn guarded_file_matches_path(file: &File, path: &Path) -> Result<(), ()> {
    let guarded = file.metadata().map_err(|_| ())?;
    let current = fs::symlink_metadata(path).map_err(|_| ())?;
    if is_reparse_point(&guarded)
        || is_reparse_point(&current)
        || !guarded.is_file()
        || !current.is_file()
        || guarded.len() != current.len()
    {
        return Err(());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn guarded_file_matches_path(file: &File, path: &Path) -> Result<(), ()> {
    let guarded = file.metadata().map_err(|_| ())?;
    let current = reject_reparse(path).map_err(|_| ())?;
    if !guarded.is_file() || !current.is_file() || guarded.len() != current.len() {
        return Err(());
    }
    Ok(())
}

fn guarded_file_size(file: Option<&File>, maximum_bytes: u64) -> Result<u64, ()> {
    let Some(file) = file else {
        return Ok(0);
    };
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file() || is_reparse_point(&metadata) || metadata.len() > maximum_bytes {
        return Err(());
    }
    Ok(metadata.len())
}

fn open_optional_regular_file_guard(path: &Path) -> Result<Option<File>, ()> {
    match open_regular_file_guard(path, true, true) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(()),
    }
}

fn open_regular_file_guard(
    path: &Path,
    share_writes: bool,
    share_deletes: bool,
) -> io::Result<File> {
    let file = open_existing_guard(path, share_writes, share_deletes)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "non-regular or redirected file rejected",
        ));
    }
    Ok(file)
}

#[cfg(windows)]
fn open_existing_guard(path: &Path, share_writes: bool, share_deletes: bool) -> io::Result<File> {
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

#[cfg(unix)]
fn open_existing_guard(path: &Path, _share_writes: bool, _share_deletes: bool) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_existing_guard(path: &Path, _share_writes: bool, _share_deletes: bool) -> io::Result<File> {
    reject_reparse(path)?;
    OpenOptions::new().read(true).open(path)
}

#[cfg(windows)]
fn create_staging_reservation(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(unix)]
fn create_staging_reservation(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn create_staging_reservation(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

struct AncestorGuards {
    #[cfg(windows)]
    _handles: Vec<File>,
}

#[cfg(windows)]
fn acquire_ancestor_guards(path: &Path) -> io::Result<AncestorGuards> {
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

#[cfg(not(windows))]
fn acquire_ancestor_guards(path: &Path) -> io::Result<AncestorGuards> {
    reject_reparse_ancestors(path)?;
    Ok(AncestorGuards {})
}

fn reject_reparse(path: &Path) -> io::Result<fs::Metadata> {
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

fn reject_reparse_ancestors(path: &Path) -> io::Result<()> {
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
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn next_session_id() -> Option<u64> {
    NEXT_SESSION_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .ok()
}

fn unix_time_ms() -> Result<u64, ()> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?;
    u64::try_from(duration.as_millis()).map_err(|_| ())
}

struct StagedVault {
    path: PathBuf,
    reservation: Option<File>,
    _ancestor_guards: AncestorGuards,
}

impl StagedVault {
    fn path(&self) -> &Path {
        &self.path
    }

    fn release_reservation(&mut self) {
        drop(self.reservation.take());
    }

    fn try_clone_reservation(&self) -> io::Result<File> {
        self.reservation
            .as_ref()
            .ok_or_else(|| io::Error::other("staging reservation is not live"))?
            .try_clone()
    }

    fn remove_name(&mut self) -> io::Result<()> {
        self.release_reservation();
        fs::remove_file(&self.path)
    }
}

impl Drop for StagedVault {
    fn drop(&mut self) {
        self.release_reservation();
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_file(sqlite_sidecar(&self.path, "-wal"));
        let _ = fs::remove_file(sqlite_sidecar(&self.path, "-shm"));
    }
}

fn sqlite_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use librarian_vault_core::{CancellationFlag, MasterPassword};
    use rusqlite::Connection;
    #[cfg(windows)]
    use rusqlite::OpenFlags;

    #[cfg(windows)]
    use super::acquire_sqlite_input_guards;
    use super::{
        CreateError, UnlockError, VaultAgent, parent_directory, reserve_staging_file,
        sqlite_sidecar, sync_parent_directory, validate_new_target,
    };
    #[cfg(unix)]
    use super::{
        initialize_database, publish_staged_vault, read_empty_vault,
        read_empty_vault_with_connection_hooks,
    };

    static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "librarian-vault-agent-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test directory must be created");
            Self(path)
        }

        fn vault_path(&self) -> PathBuf {
            self.0.join("vault.sqlite3")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn password(value: &str) -> MasterPassword {
        MasterPassword::new(value).expect("test password must be valid")
    }

    fn create_test_vault(path: &Path, value: &str) -> VaultAgent {
        VaultAgent::create(path, password(value))
            .expect("test vault must be created")
            .0
    }

    #[test]
    fn create_lock_restart_and_unlock_round_trip() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let mut created = create_test_vault(&path, "restart password");
        assert!(created.is_unlocked());

        created.lock();
        assert!(!created.is_unlocked());
        drop(created);

        let mut restarted = VaultAgent::open_locked(&path);
        assert!(!restarted.is_unlocked());
        restarted
            .unlock(password("restart password"), &CancellationFlag::new())
            .expect("correct password must unlock after restart");
        assert!(restarted.is_unlocked());
    }

    #[test]
    fn lock_invalidates_existing_operation_permits() {
        let directory = TestDirectory::new();
        let mut agent = create_test_vault(&directory.vault_path(), "permit password");
        let permit = agent
            .begin_operation()
            .expect("unlocked vault must issue a permit");
        assert!(agent.operation_is_authorized(permit));

        agent.lock();
        assert!(!agent.operation_is_authorized(permit));
        assert!(agent.begin_operation().is_none());
    }

    #[test]
    fn operation_permits_are_bound_to_the_issuing_session() {
        let first_directory = TestDirectory::new();
        let second_directory = TestDirectory::new();
        let first = create_test_vault(&first_directory.vault_path(), "first permit password");
        let second = create_test_vault(&second_directory.vault_path(), "second permit password");
        let first_permit = first
            .begin_operation()
            .expect("first vault must issue a permit");
        let second_permit = second
            .begin_operation()
            .expect("second vault must issue a permit");

        assert!(first.operation_is_authorized(first_permit));
        assert!(second.operation_is_authorized(second_permit));
        assert!(!first.operation_is_authorized(second_permit));
        assert!(!second.operation_is_authorized(first_permit));
    }

    #[test]
    fn wrong_password_and_corruption_have_the_same_public_error() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let mut agent = create_test_vault(&path, "right password");
        agent.lock();
        let wrong = agent.unlock(password("wrong password"), &CancellationFlag::new());
        assert_eq!(wrong, Err(UnlockError::Failed));
        assert!(!agent.is_unlocked());

        let connection = Connection::open(&path).expect("test database must open");
        let mut header: Vec<u8> = connection
            .query_row("SELECT header FROM vault_header", [], |row| row.get(0))
            .expect("header must exist");
        let last = header.last_mut().expect("header must not be empty");
        *last ^= 1;
        connection
            .execute("UPDATE vault_header SET header = ?1", [&header])
            .expect("test must tamper with header");
        drop(connection);

        let corrupted = agent.unlock(password("right password"), &CancellationFlag::new());
        assert_eq!(corrupted, Err(UnlockError::Failed));
        assert!(!agent.is_unlocked());
    }

    #[test]
    fn cancellation_leaves_the_agent_locked() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let mut agent = create_test_vault(&path, "cancel password");
        agent.lock();
        let cancellation = CancellationFlag::new();
        cancellation.cancel();

        assert_eq!(
            agent.unlock(password("cancel password"), &cancellation),
            Err(UnlockError::Cancelled)
        );
        assert!(!agent.is_unlocked());
    }

    #[test]
    fn cancellation_after_core_unlock_does_not_publish_the_session() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let mut agent = create_test_vault(&path, "late cancel password");
        agent.lock();
        let cancellation = CancellationFlag::new();

        assert_eq!(
            agent.unlock_with_before_publish(
                password("late cancel password"),
                &cancellation,
                || cancellation.cancel()
            ),
            Err(UnlockError::Cancelled)
        );
        assert!(!agent.is_unlocked());
        assert!(agent.begin_operation().is_none());
    }

    #[test]
    fn truncated_database_fails_closed() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let agent = create_test_vault(&path, "truncate password");
        drop(agent);

        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("test vault must open")
            .set_len(64)
            .expect("test vault must truncate");

        let mut restarted = VaultAgent::open_locked(&path);
        assert_eq!(
            restarted.unlock(password("truncate password"), &CancellationFlag::new()),
            Err(UnlockError::Failed)
        );
        assert!(!restarted.is_unlocked());
    }

    #[test]
    fn unexpected_application_tables_fail_closed() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let agent = create_test_vault(&path, "schema password");
        drop(agent);

        let connection = Connection::open(&path).expect("test database must open");
        connection
            .execute_batch("CREATE TABLE unexpected_plaintext(value TEXT) STRICT;")
            .expect("test must add an unexpected table");
        drop(connection);

        let mut restarted = VaultAgent::open_locked(&path);
        assert_eq!(
            restarted.unlock(password("schema password"), &CancellationFlag::new()),
            Err(UnlockError::Failed)
        );
        assert!(!restarted.is_unlocked());
    }

    #[test]
    fn unexpected_views_and_triggers_fail_closed() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let agent = create_test_vault(&path, "schema object password");
        drop(agent);

        let connection = Connection::open(&path).expect("test database must open");
        connection
            .execute_batch(
                "CREATE VIEW unexpected_view AS SELECT header FROM vault_header;
                 CREATE TRIGGER unexpected_trigger
                 AFTER INSERT ON encrypted_records
                 BEGIN
                     SELECT 1;
                 END;",
            )
            .expect("test must add unexpected schema objects");
        drop(connection);

        let mut restarted = VaultAgent::open_locked(&path);
        assert_eq!(
            restarted.unlock(password("schema object password"), &CancellationFlag::new()),
            Err(UnlockError::Failed)
        );
        assert!(!restarted.is_unlocked());
    }

    #[test]
    fn sqlite_similar_prefix_objects_fail_closed() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let agent = create_test_vault(&path, "schema prefix password");
        drop(agent);

        let connection = Connection::open(&path).expect("test database must open");
        connection
            .execute_batch("CREATE TABLE sqliteXplaintext(value TEXT) STRICT;")
            .expect("test must add an application-owned lookalike table");
        drop(connection);

        let mut restarted = VaultAgent::open_locked(&path);
        assert_eq!(
            restarted.unlock(password("schema prefix password"), &CancellationFlag::new()),
            Err(UnlockError::Failed)
        );
        assert!(!restarted.is_unlocked());
    }

    #[test]
    fn extra_singleton_rows_fail_closed() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let agent = create_test_vault(&path, "singleton password");
        drop(agent);

        let connection = Connection::open(&path).expect("test database must open");
        connection
            .execute_batch(
                "PRAGMA ignore_check_constraints = ON;
                 INSERT INTO vault_header(singleton, header)
                 SELECT 2, header FROM vault_header WHERE singleton = 1;",
            )
            .expect("test must add an extra header row");
        drop(connection);

        let mut restarted = VaultAgent::open_locked(&path);
        assert_eq!(
            restarted.unlock(password("singleton password"), &CancellationFlag::new()),
            Err(UnlockError::Failed)
        );

        let connection = Connection::open(&path).expect("test database must reopen");
        connection
            .execute_batch(
                "PRAGMA ignore_check_constraints = ON;
                 DELETE FROM vault_header WHERE singleton = 2;
                 INSERT INTO vault_manifest(singleton, envelope)
                 SELECT 2, envelope FROM vault_manifest WHERE singleton = 1;",
            )
            .expect("test must replace the extra row with an extra manifest row");
        drop(connection);

        assert_eq!(
            restarted.unlock(password("singleton password"), &CancellationFlag::new()),
            Err(UnlockError::Failed)
        );
        assert!(!restarted.is_unlocked());
    }

    #[test]
    fn creation_never_overwrites_an_existing_file() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        fs::write(&path, b"existing data").expect("fixture must be written");

        let result = VaultAgent::create(&path, password("do not overwrite"));
        assert!(matches!(result, Err(CreateError::AlreadyExists)));
        assert_eq!(
            fs::read(&path).expect("fixture must remain readable"),
            b"existing data"
        );
    }

    #[test]
    fn creation_rejects_final_path_sidecars() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let wal_path = sqlite_sidecar(&path, "-wal");
        fs::write(&wal_path, b"stale wal").expect("WAL fixture must be written");

        assert!(matches!(
            VaultAgent::create(&path, password("sidecar create password")),
            Err(CreateError::Failed)
        ));
        assert!(!path.exists());
        assert_eq!(
            fs::read(&wal_path).expect("WAL fixture must remain"),
            b"stale wal"
        );

        fs::remove_file(&wal_path).expect("WAL fixture must be removed");
        let shm_path = sqlite_sidecar(&path, "-shm");
        fs::write(&shm_path, b"stale shm").expect("SHM fixture must be written");
        assert!(matches!(
            VaultAgent::create(&path, password("sidecar create password")),
            Err(CreateError::Failed)
        ));
        assert!(!path.exists());
    }

    #[test]
    fn partial_staging_never_publishes_the_target_name() {
        let directory = TestDirectory::new();
        let target = directory.vault_path();
        validate_new_target(&target).expect("new target must be accepted");
        let staging =
            reserve_staging_file(&target).expect("staging file must be reserved atomically");

        fs::write(staging.path(), b"partial database").expect("partial fixture must be written");
        assert!(
            !target.exists(),
            "the final path must not exist during initialization"
        );

        let staging_path = staging.path().to_path_buf();
        drop(staging);
        assert!(!target.exists());
        assert!(!staging_path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn staging_reservation_cannot_be_replaced_during_initialization() {
        let directory = TestDirectory::new();
        let target = directory.vault_path();
        let staging =
            reserve_staging_file(&target).expect("staging file must be reserved atomically");
        let replacement = directory.0.join("replacement.sqlite3");
        fs::write(&replacement, b"replacement").expect("replacement fixture must be written");

        assert!(
            fs::remove_file(staging.path()).is_err(),
            "the live reservation must deny deletion"
        );
        assert!(
            fs::rename(&replacement, staging.path()).is_err(),
            "the live reservation must deny replacement"
        );
        assert!(replacement.exists());
    }

    #[cfg(unix)]
    #[test]
    fn initialization_writes_only_to_the_reserved_staging_inode() {
        use std::io::{Read, Seek, SeekFrom};

        let directory = TestDirectory::new();
        let target = directory.vault_path();
        let mut staging =
            reserve_staging_file(&target).expect("staging file must be reserved atomically");
        let mut reserved = staging
            .reservation
            .as_ref()
            .expect("reservation must remain live")
            .try_clone()
            .expect("reservation must be clonable");

        fs::remove_file(staging.path()).expect("Unix permits unlinking a live reservation");
        fs::write(staging.path(), b"attacker replacement")
            .expect("replacement staging name must be created");
        initialize_database(&mut staging, b"header", b"manifest")
            .expect("initialization through the reserved descriptor must succeed");

        assert_eq!(
            fs::read(staging.path()).expect("replacement must remain readable"),
            b"attacker replacement"
        );
        reserved
            .seek(SeekFrom::Start(0))
            .expect("reserved descriptor must rewind");
        let mut signature = [0_u8; 16];
        reserved
            .read_exact(&mut signature)
            .expect("reserved inode must contain a SQLite image");
        assert_eq!(&signature, b"SQLite format 3\0");
        assert!(
            publish_staged_vault(&mut staging, &target).is_err(),
            "a replaced staging pathname must never be published"
        );
        assert!(!target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn created_vault_is_owner_read_write_only() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let agent = create_test_vault(&path, "permission password");
        drop(agent);

        let mode = fs::metadata(&path)
            .expect("created vault metadata must be readable")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn bare_relative_vault_paths_use_the_current_directory_as_parent() {
        assert_eq!(parent_directory(Path::new("vault.sqlite3")), Path::new("."));
    }

    #[test]
    fn parent_directory_durability_barrier_succeeds() {
        let directory = TestDirectory::new();
        sync_parent_directory(&directory.vault_path())
            .expect("parent directory must support a durability barrier");
    }

    #[test]
    fn oversized_wal_and_shm_sidecars_fail_before_unlock() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let agent = create_test_vault(&path, "sidecar password");
        drop(agent);

        let wal_path = sqlite_sidecar(&path, "-wal");
        fs::File::create(&wal_path)
            .expect("WAL fixture must be created")
            .set_len(librarian_vault_format::MAX_DATABASE_BYTES)
            .expect("WAL fixture must be sized");
        let mut wal_agent = VaultAgent::open_locked(&path);
        assert_eq!(
            wal_agent.unlock(password("sidecar password"), &CancellationFlag::new()),
            Err(UnlockError::Failed)
        );
        fs::remove_file(&wal_path).expect("WAL fixture must be removed");

        let shm_path = sqlite_sidecar(&path, "-shm");
        fs::File::create(&shm_path)
            .expect("SHM fixture must be created")
            .set_len(super::MAX_SQLITE_SHM_BYTES + 1)
            .expect("SHM fixture must be sized");
        let mut shm_agent = VaultAgent::open_locked(&path);
        assert_eq!(
            shm_agent.unlock(password("sidecar password"), &CancellationFlag::new()),
            Err(UnlockError::Failed)
        );
    }

    #[cfg(windows)]
    #[test]
    fn checked_vault_file_cannot_be_replaced_before_sqlite_opens() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let agent = create_test_vault(&path, "stable file password");
        drop(agent);
        let replacement = directory.0.join("replacement.sqlite3");
        fs::write(&replacement, b"replacement").expect("replacement fixture must be written");

        let input_guards =
            acquire_sqlite_input_guards(&path).expect("vault inputs must be guarded");
        assert!(
            fs::remove_file(&path).is_err(),
            "the checked vault file must deny deletion"
        );
        assert!(
            fs::rename(&replacement, &path).is_err(),
            "the checked vault file must deny replacement"
        );
        assert!(
            fs::OpenOptions::new().write(true).open(&path).is_err(),
            "the checked vault file must deny concurrent writers"
        );
        let sqlite = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("the trusted read-only SQLite connection must open while guarded");
        drop(sqlite);
        drop(input_guards);
        assert!(path.exists());
        assert!(replacement.exists());
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_snapshot_is_bound_to_the_guarded_inode_during_path_replacement() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let replacement = directory.0.join("replacement.sqlite3");
        let parked = directory.0.join("parked.sqlite3");
        let original = create_test_vault(&path, "original password");
        let alternate = create_test_vault(&replacement, "replacement password");
        drop(original);
        drop(alternate);
        let expected = read_empty_vault(&path).expect("original vault must be readable");

        let actual = read_empty_vault_with_connection_hooks(
            &path,
            || {
                fs::rename(&path, &parked).expect("original path must be parked");
                fs::rename(&replacement, &path).expect("replacement must take the vault path");
            },
            || {
                fs::rename(&path, &replacement).expect("replacement must be moved back");
                fs::rename(&parked, &path).expect("original path must be restored");
            },
        )
        .expect("the guarded original inode must remain the SQLite input");

        assert_eq!(actual, expected);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn symlinked_vault_ancestors_fail_closed() {
        let directory = TestDirectory::new();
        let real_parent = directory.0.join("real");
        let linked_parent = directory.0.join("linked");
        fs::create_dir(&real_parent).expect("real parent must be created");
        let real_path = real_parent.join("vault.sqlite3");
        let agent = create_test_vault(&real_path, "ancestor password");
        drop(agent);
        create_directory_symlink(&real_parent, &linked_parent);

        let mut linked_agent = VaultAgent::open_locked(linked_parent.join("vault.sqlite3"));
        assert_eq!(
            linked_agent.unlock(password("ancestor password"), &CancellationFlag::new()),
            Err(UnlockError::Failed)
        );
        assert!(matches!(
            VaultAgent::create(
                linked_parent.join("new-vault.sqlite3"),
                password("new password")
            ),
            Err(CreateError::Failed)
        ));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn symlinked_vault_files_fail_closed() {
        let directory = TestDirectory::new();
        let real_path = directory.vault_path();
        let linked_path = directory.0.join("linked-vault.sqlite3");
        let agent = create_test_vault(&real_path, "file symlink password");
        drop(agent);
        create_file_symlink(&real_path, &linked_path);

        let mut linked_agent = VaultAgent::open_locked(&linked_path);
        assert_eq!(
            linked_agent.unlock(password("file symlink password"), &CancellationFlag::new()),
            Err(UnlockError::Failed)
        );
        assert!(!linked_agent.is_unlocked());
    }

    #[cfg(windows)]
    #[test]
    fn junction_ancestors_fail_closed() {
        let directory = TestDirectory::new();
        let real_parent = directory.0.join("real-junction-target");
        let junction_parent = directory.0.join("junction");
        fs::create_dir(&real_parent).expect("junction target must be created");
        let real_path = real_parent.join("vault.sqlite3");
        let agent = create_test_vault(&real_path, "junction password");
        drop(agent);
        create_directory_junction(&real_parent, &junction_parent);

        let mut linked_agent = VaultAgent::open_locked(junction_parent.join("vault.sqlite3"));
        assert_eq!(
            linked_agent.unlock(password("junction password"), &CancellationFlag::new()),
            Err(UnlockError::Failed)
        );
        assert!(matches!(
            VaultAgent::create(
                junction_parent.join("new-vault.sqlite3"),
                password("new junction password")
            ),
            Err(CreateError::Failed)
        ));
    }

    #[test]
    fn password_never_appears_in_the_database_image() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let marker = "UNIQUE-PLAINTEXT-PASSWORD-MARKER";
        let agent = create_test_vault(&path, marker);
        drop(agent);

        let image = fs::read(&path).expect("database image must be readable");
        assert!(
            !image
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
        );
    }

    #[cfg(unix)]
    fn create_directory_symlink(original: &Path, link: &Path) {
        std::os::unix::fs::symlink(original, link).expect("directory symlink must be created");
    }

    #[cfg(unix)]
    fn create_file_symlink(original: &Path, link: &Path) {
        std::os::unix::fs::symlink(original, link).expect("file symlink must be created");
    }

    #[cfg(windows)]
    fn create_directory_symlink(original: &Path, link: &Path) {
        std::os::windows::fs::symlink_dir(original, link)
            .expect("directory symlink must be created");
    }

    #[cfg(windows)]
    fn create_file_symlink(original: &Path, link: &Path) {
        std::os::windows::fs::symlink_file(original, link).expect("file symlink must be created");
    }

    #[cfg(windows)]
    fn create_directory_junction(original: &Path, link: &Path) {
        let status = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(link)
            .arg(original)
            .status()
            .expect("junction command must start");
        assert!(status.success(), "junction command must succeed");
    }
}
