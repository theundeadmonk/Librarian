//! `SQLite` ownership and lock-state lifecycle for the trusted local vault agent.
//!
//! This is not an IPC server yet. Issue #13 will expose a constrained protocol;
//! for issue #10, this crate proves that only the agent opens the vault file and
//! that a restart begins locked.

#![forbid(unsafe_code)]

use std::{
    fmt,
    fs::{self, OpenOptions},
    io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use librarian_vault_core::{
    CancellationFlag, MasterPassword, RecoveryKey, UnlockedVault, create_vault, unlock_empty_vault,
};
use rusqlite::{
    Connection, OpenFlags, TransactionBehavior, config::DbConfig, limits::Limit, params,
};

const MAX_SQLITE_VALUE_BYTES: i32 = 8 * 1024 * 1024;
const MAX_PAGE_COUNT: u32 = 131_072;

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
    authorization_epoch: u64,
}

/// The local agent's vault lifecycle state.
///
/// This type intentionally does not implement `Debug` because it owns the
/// unlocked core session.
pub struct VaultAgent {
    path: PathBuf,
    session: Option<UnlockedVault>,
    authorization_epoch: u64,
}

impl VaultAgent {
    /// Atomically initializes a new empty vault and leaves this agent unlocked.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyExists` without replacing an existing target. Every
    /// other reservation, cryptographic, format, `SQLite`, or durability failure
    /// returns `Failed` and removes partial files.
    pub fn create(
        path: impl AsRef<Path>,
        password: MasterPassword,
    ) -> Result<(Self, RecoveryKey), CreateError> {
        let path = path.as_ref().to_path_buf();
        reserve_new_file(&path)?;
        let mut cleanup = PartialVaultCleanup::new(path.clone());

        let created_at_ms = unix_time_ms().map_err(|()| CreateError::Failed)?;
        let created = create_vault(password, created_at_ms).map_err(|_| CreateError::Failed)?;
        let (header, manifest, recovery_key, session) = created.into_parts();

        initialize_database(&path, &header, &manifest).map_err(|_| CreateError::Failed)?;
        cleanup.disarm();

        Ok((
            Self {
                path,
                session: Some(session),
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
        self.lock();
        let (header, manifest) = read_empty_vault(&self.path).map_err(|()| UnlockError::Failed)?;
        let session = match unlock_empty_vault(password, &header, &manifest, cancellation) {
            Ok(session) => session,
            Err(librarian_vault_core::UnlockError::Cancelled) => {
                return Err(UnlockError::Cancelled);
            }
            Err(librarian_vault_core::UnlockError::Failed) => return Err(UnlockError::Failed),
        };

        if !self.advance_authorization_epoch() {
            return Err(UnlockError::Failed);
        }
        self.session = Some(session);
        Ok(())
    }

    /// Drops and zeroizes reusable key state, invalidating existing permits.
    pub fn lock(&mut self) {
        self.session = None;
        let _ = self.advance_authorization_epoch();
    }

    #[must_use]
    pub fn begin_operation(&self) -> Option<OperationPermit> {
        self.session.as_ref().map(|_| OperationPermit {
            authorization_epoch: self.authorization_epoch,
        })
    }

    #[must_use]
    pub fn operation_is_authorized(&self, permit: OperationPermit) -> bool {
        self.session.is_some() && permit.authorization_epoch == self.authorization_epoch
    }

    fn advance_authorization_epoch(&mut self) -> bool {
        let Some(next) = self.authorization_epoch.checked_add(1) else {
            return false;
        };
        self.authorization_epoch = next;
        true
    }
}

fn reserve_new_file(path: &Path) -> Result<(), CreateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => return Err(CreateError::Failed),
        Ok(_) => return Err(CreateError::AlreadyExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                let parent_metadata =
                    fs::symlink_metadata(parent).map_err(|_| CreateError::Failed)?;
                if parent_metadata.file_type().is_symlink() {
                    return Err(CreateError::Failed);
                }
            }
        }
        Err(_) => return Err(CreateError::Failed),
    }
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            Err(CreateError::AlreadyExists)
        }
        Err(_) => Err(CreateError::Failed),
    }
}

fn initialize_database(path: &Path, header: &[u8], manifest: &[u8]) -> rusqlite::Result<()> {
    let mut connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    configure_limits(&connection)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    connection.pragma_update(None, "page_size", 4096)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
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

fn read_empty_vault(path: &Path) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let metadata = reject_symlink(path).map_err(|_| ())?;
    if !metadata.is_file() || metadata.len() > librarian_vault_format::MAX_DATABASE_BYTES {
        return Err(());
    }

    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| ())?;
    configure_limits(&connection).map_err(|_| ())?;
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(|_| ())?;
    connection
        .pragma_update(None, "trusted_schema", false)
        .map_err(|_| ())?;
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
    let record_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM encrypted_records", [], |row| {
            row.get(0)
        })
        .map_err(|_| ())?;

    if header.len() > librarian_vault_format::MAX_HEADER_BYTES
        || manifest.len() > librarian_vault_format::MAX_MANIFEST_ENVELOPE_BYTES
        || record_count != 0
    {
        return Err(());
    }
    Ok((header, manifest))
}

fn verify_application_schema(connection: &Connection) -> Result<(), ()> {
    let mut statement = connection
        .prepare(
            "SELECT name FROM sqlite_schema
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )
        .map_err(|_| ())?;
    let table_names = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| ())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ())?;
    if table_names
        != [
            "encrypted_records".to_owned(),
            "vault_header".to_owned(),
            "vault_manifest".to_owned(),
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

fn reject_symlink(path: &Path) -> io::Result<fs::Metadata> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "symlink rejected",
        )),
        Ok(metadata) => Ok(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                let parent_metadata = fs::symlink_metadata(parent)?;
                if parent_metadata.file_type().is_symlink() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "symlink parent rejected",
                    ));
                }
            }
            Err(error)
        }
        Err(error) => Err(error),
    }
}

fn unix_time_ms() -> Result<u64, ()> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?;
    u64::try_from(duration.as_millis()).map_err(|_| ())
}

struct PartialVaultCleanup {
    path: PathBuf,
    armed: bool,
}

impl PartialVaultCleanup {
    const fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PartialVaultCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
            let _ = fs::remove_file(sqlite_sidecar(&self.path, "-wal"));
            let _ = fs::remove_file(sqlite_sidecar(&self.path, "-shm"));
        }
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

    use super::{CreateError, UnlockError, VaultAgent};

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
}
