#[cfg(not(any(unix, windows)))]
use std::fs::OpenOptions;
#[cfg(any(unix, windows))]
use std::io::{Seek, SeekFrom, Write};
use std::{fs::File, io, path::Path};

#[cfg(any(unix, windows))]
use rusqlite::MAIN_DB;
#[cfg(not(any(unix, windows)))]
use rusqlite::OpenFlags;
use rusqlite::{Connection, TransactionBehavior, config::DbConfig, limits::Limit, params};

use crate::{
    errors::StorageError,
    filesystem::{
        AncestorGuards, acquire_ancestor_guards, guarded_file_matches_path_with_ancestor_guards,
        guarded_file_size, guarded_optional_file_matches_path_with_ancestor_guards,
        open_optional_regular_file_guard_with_ancestor_guards,
        open_regular_file_guard_with_ancestor_guards, sqlite_sidecar,
    },
    snapshot::{open_guarded_read_connection, validate_wal_database_header},
    storage::StagedVault,
};

pub(crate) const MAX_SQLITE_ROW_BYTES: i32 = 8 * 1024 * 1024 + 64 * 1024;
pub(crate) const MAX_PAGE_COUNT: u32 = 131_072;
pub(crate) const MAX_SQLITE_SHM_BYTES: u64 = 8 * 1024 * 1024;
pub(crate) const SQLITE_HEADER_BYTES: usize = 20;
pub(crate) const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
pub(crate) const SQLITE_READ_VERSION_OFFSET: usize = 18;
pub(crate) const SQLITE_WRITE_VERSION_OFFSET: usize = 19;
pub(crate) const SQLITE_WAL_VERSION: u8 = 2;

#[cfg(not(any(unix, windows)))]
pub(crate) fn initialize_database(
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

#[cfg(any(unix, windows))]
pub(crate) fn initialize_database(
    staging: &mut StagedVault,
    header: &[u8],
    manifest: &[u8],
) -> rusqlite::Result<()> {
    let mut connection = Connection::open_in_memory()?;
    initialize_connection(&mut connection, header, manifest, false)?;
    let mut image = connection.serialize(MAIN_DB)?.to_vec();
    mark_database_image_as_wal(&mut image)?;
    let reservation = staging
        .reservation_mut()
        .ok_or(rusqlite::Error::InvalidQuery)?;
    reservation
        .seek(SeekFrom::Start(0))
        .and_then(|_| reservation.write_all(&image))
        .and_then(|()| reservation.set_len(u64::try_from(image.len()).map_err(io::Error::other)?))
        .and_then(|()| reservation.sync_all())
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(())
}

#[cfg(any(unix, windows))]
pub(crate) fn mark_database_image_as_wal(image: &mut [u8]) -> rusqlite::Result<()> {
    if image.len() < SQLITE_HEADER_BYTES || &image[..SQLITE_MAGIC.len()] != SQLITE_MAGIC {
        return Err(rusqlite::Error::InvalidQuery);
    }
    image[SQLITE_READ_VERSION_OFFSET] = SQLITE_WAL_VERSION;
    image[SQLITE_WRITE_VERSION_OFFSET] = SQLITE_WAL_VERSION;
    Ok(())
}

pub(crate) fn initialize_connection(
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

pub(crate) struct GuardedEmptyVault {
    pub(crate) header: Vec<u8>,
    pub(crate) manifest: Vec<u8>,
    pub(crate) input_guards: SqliteInputGuards,
}

pub(crate) fn read_guarded_empty_vault(path: &Path) -> Result<GuardedEmptyVault, StorageError> {
    read_guarded_empty_vault_with_hooks(path, || {}, || {}, || {})
}

#[cfg(all(test, unix))]
pub(crate) fn read_empty_vault(path: &Path) -> Result<(Vec<u8>, Vec<u8>), StorageError> {
    let snapshot = read_guarded_empty_vault(path)?;
    Ok((snapshot.header, snapshot.manifest))
}

#[cfg(all(test, any(unix, windows)))]
pub(crate) fn read_empty_vault_with_connection_hooks(
    path: &Path,
    before_connection: impl FnOnce(),
    after_connection: impl FnOnce(),
) -> Result<(Vec<u8>, Vec<u8>), StorageError> {
    let snapshot =
        read_guarded_empty_vault_with_hooks(path, || {}, before_connection, after_connection)?;
    Ok((snapshot.header, snapshot.manifest))
}

#[cfg(all(test, unix))]
pub(crate) fn read_empty_vault_with_hooks(
    path: &Path,
    after_ancestor_guards: impl FnOnce(),
    before_connection: impl FnOnce(),
    after_connection: impl FnOnce(),
) -> Result<(Vec<u8>, Vec<u8>), StorageError> {
    let snapshot = read_guarded_empty_vault_with_hooks(
        path,
        after_ancestor_guards,
        before_connection,
        after_connection,
    )?;
    Ok((snapshot.header, snapshot.manifest))
}

pub(crate) fn read_guarded_empty_vault_with_hooks(
    path: &Path,
    after_ancestor_guards: impl FnOnce(),
    before_connection: impl FnOnce(),
    after_connection: impl FnOnce(),
) -> Result<GuardedEmptyVault, StorageError> {
    let mut input_guards = acquire_sqlite_input_guards_with_hook(path, after_ancestor_guards)?;
    let (header, manifest) =
        read_empty_vault_from_guards(path, &mut input_guards, before_connection, after_connection)?;
    Ok(GuardedEmptyVault {
        header,
        manifest,
        input_guards,
    })
}

pub(crate) fn read_empty_vault_from_guards(
    path: &Path,
    input_guards: &mut SqliteInputGuards,
    before_connection: impl FnOnce(),
    after_connection: impl FnOnce(),
) -> Result<(Vec<u8>, Vec<u8>), StorageError> {
    validate_guarded_sqlite_input_sizes(input_guards)?;
    validate_guarded_sqlite_input_paths(path, input_guards)?;
    validate_wal_database_header(&mut input_guards.database)?;

    before_connection();
    let connection = open_guarded_read_connection(path, input_guards)?;
    after_connection();
    configure_limits(&connection).map_err(|_| StorageError::Sqlite)?;
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(|_| StorageError::Sqlite)?;
    connection
        .pragma_update(None, "trusted_schema", false)
        .map_err(|_| StorageError::Sqlite)?;
    validate_guarded_sqlite_input_sizes(input_guards)?;
    validate_guarded_sqlite_input_paths(path, input_guards)?;
    verify_database_integrity(&connection)?;
    verify_application_schema(&connection)?;

    let header: Vec<u8> = connection
        .query_row(
            "SELECT header FROM vault_header WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::Sqlite)?;
    let manifest: Vec<u8> = connection
        .query_row(
            "SELECT envelope FROM vault_manifest WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::Sqlite)?;
    let (header_count, manifest_count, record_count): (i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM vault_header),
                (SELECT COUNT(*) FROM vault_manifest),
                (SELECT COUNT(*) FROM encrypted_records)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| StorageError::Sqlite)?;

    if header.len() > librarian_vault_format::MAX_HEADER_BYTES
        || manifest.len() > librarian_vault_format::MAX_MANIFEST_ENVELOPE_BYTES
    {
        return Err(StorageError::ResourceLimit);
    }
    if header_count != 1 || manifest_count != 1 || record_count != 0 {
        return Err(StorageError::Schema);
    }
    validate_guarded_sqlite_input_sizes(input_guards)?;
    validate_guarded_sqlite_input_paths(path, input_guards)?;
    Ok((header, manifest))
}

pub(crate) fn verify_application_schema(connection: &Connection) -> Result<(), StorageError> {
    let mut statement = connection
        .prepare(
            "SELECT type, name FROM sqlite_schema
             ORDER BY type, name",
        )
        .map_err(|_| StorageError::Sqlite)?;
    let application_objects = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| StorageError::Sqlite)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StorageError::Sqlite)?;
    if application_objects
        != [
            ("table".to_owned(), "encrypted_records".to_owned()),
            ("table".to_owned(), "vault_header".to_owned()),
            ("table".to_owned(), "vault_manifest".to_owned()),
        ]
    {
        return Err(StorageError::Schema);
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
            .map_err(|_| StorageError::Sqlite)?;
        if strict != 1 {
            return Err(StorageError::Schema);
        }
        let schema_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .map_err(|_| StorageError::Sqlite)?;
        if schema_sql.split_whitespace().collect::<Vec<_>>().join(" ") != expected_sql {
            return Err(StorageError::Schema);
        }
    }

    Ok(())
}

pub(crate) fn verify_database_integrity(connection: &Connection) -> Result<(), StorageError> {
    let status: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| StorageError::Sqlite)?;
    if status != "ok" {
        return Err(StorageError::Integrity);
    }
    Ok(())
}

pub(crate) fn configure_limits(connection: &Connection) -> rusqlite::Result<()> {
    connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, MAX_SQLITE_ROW_BYTES)?;
    connection.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 64 * 1024)?;
    connection.set_limit(Limit::SQLITE_LIMIT_COLUMN, 16)?;
    connection.set_limit(Limit::SQLITE_LIMIT_EXPR_DEPTH, 32)?;
    connection.set_limit(Limit::SQLITE_LIMIT_COMPOUND_SELECT, 4)?;
    connection.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)?;
    Ok(())
}

pub(crate) struct SqliteInputGuards {
    pub(crate) database: File,
    pub(crate) wal: Option<File>,
    pub(crate) shm: Option<File>,
    pub(crate) ancestor_guards: AncestorGuards,
}

#[cfg(all(test, windows))]
pub(crate) fn acquire_sqlite_input_guards(path: &Path) -> Result<SqliteInputGuards, StorageError> {
    acquire_sqlite_input_guards_with_hook(path, || {})
}

pub(crate) fn acquire_sqlite_input_guards_with_hook(
    path: &Path,
    after_ancestor_guards: impl FnOnce(),
) -> Result<SqliteInputGuards, StorageError> {
    let ancestor_guards = acquire_ancestor_guards(path).map_err(|_| StorageError::Filesystem)?;
    after_ancestor_guards();
    let database =
        open_regular_file_guard_with_ancestor_guards(&ancestor_guards, path, false, false)
            .map_err(|_| StorageError::Filesystem)?;
    let wal = open_optional_regular_file_guard_with_ancestor_guards(
        &ancestor_guards,
        &sqlite_sidecar(path, "-wal"),
        false,
        false,
    )?;
    let shm = open_optional_regular_file_guard_with_ancestor_guards(
        &ancestor_guards,
        &sqlite_sidecar(path, "-shm"),
        false,
        false,
    )?;
    Ok(SqliteInputGuards {
        database,
        wal,
        shm,
        ancestor_guards,
    })
}

pub(crate) fn validate_guarded_sqlite_input_sizes(
    input: &SqliteInputGuards,
) -> Result<(), StorageError> {
    let database_bytes = input
        .database
        .metadata()
        .map_err(|_| StorageError::Filesystem)?
        .len();
    let wal_bytes = guarded_file_size(
        input.wal.as_ref(),
        librarian_vault_format::MAX_DATABASE_BYTES,
    )?;
    let shm_bytes = guarded_file_size(input.shm.as_ref(), MAX_SQLITE_SHM_BYTES)?;
    let total_bytes = database_bytes
        .checked_add(wal_bytes)
        .and_then(|value| value.checked_add(shm_bytes))
        .ok_or(StorageError::ResourceLimit)?;
    if total_bytes > librarian_vault_format::MAX_DATABASE_BYTES {
        return Err(StorageError::ResourceLimit);
    }
    Ok(())
}

pub(crate) fn validate_guarded_sqlite_input_paths(
    path: &Path,
    input: &SqliteInputGuards,
) -> Result<(), StorageError> {
    guarded_file_matches_path_with_ancestor_guards(&input.database, path, &input.ancestor_guards)?;
    guarded_optional_file_matches_path_with_ancestor_guards(
        input.wal.as_ref(),
        &sqlite_sidecar(path, "-wal"),
        &input.ancestor_guards,
    )?;
    guarded_optional_file_matches_path_with_ancestor_guards(
        input.shm.as_ref(),
        &sqlite_sidecar(path, "-shm"),
        &input.ancestor_guards,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::{StorageError, verify_application_schema};

    #[test]
    fn unexpected_application_schema_has_a_non_secret_internal_category() {
        let connection = Connection::open_in_memory().expect("test database must open");
        connection
            .execute_batch("CREATE TABLE attacker_controlled(value BLOB) STRICT;")
            .expect("unexpected table fixture must be created");

        assert_eq!(
            verify_application_schema(&connection),
            Err(StorageError::Schema)
        );
    }
}
