#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use librarian_vault_core::{CancellationFlag, MasterPassword, WebsiteAccountInput};
    use rusqlite::Connection;
    #[cfg(windows)]
    use rusqlite::OpenFlags;

    use crate::errors::StorageError;
    #[cfg(any(unix, windows))]
    use crate::read_empty_vault_with_connection_hooks;
    use crate::{
        AccountError, CreateError, UnlockError, VaultAgent, parent_directory, reserve_staging_file,
        sqlite_sidecar, sync_parent_directory, validate_new_target,
    };
    #[cfg(windows)]
    use crate::{
        acquire_sqlite_input_guards, initialize_database, publish_staged_vault,
        seal_published_vault,
    };
    #[cfg(unix)]
    use crate::{
        initialize_database, publish_staged_vault, publish_staged_vault_with_before_link,
        read_empty_vault, read_empty_vault_with_hooks,
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

    fn account_input(label: &str) -> WebsiteAccountInput {
        WebsiteAccountInput::new(
            label,
            "https://unit.example",
            "unit-user",
            "unit-test-password",
        )
        .expect("unit-test account input must be valid")
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
    fn created_vault_persists_wal_journal_mode() {
        use std::io::Read as _;

        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let agent = create_test_vault(&path, "wal mode password");
        drop(agent);

        let mut database = File::open(&path).expect("created database must open");
        let mut header = [0_u8; crate::SQLITE_HEADER_BYTES];
        database
            .read_exact(&mut header)
            .expect("created database header must be readable");
        assert_eq!(
            header[crate::SQLITE_READ_VERSION_OFFSET],
            crate::SQLITE_WAL_VERSION
        );
        assert_eq!(
            header[crate::SQLITE_WRITE_VERSION_OFFSET],
            crate::SQLITE_WAL_VERSION
        );

        let connection = Connection::open(&path).expect("created database must open in SQLite");
        let journal_mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("journal mode must be queryable");
        assert_eq!(journal_mode, "wal");
    }

    #[test]
    fn sqlite_row_limit_allows_the_maximum_manifest_payload() {
        let connection = Connection::open_in_memory().expect("SQLite fixture must open");
        crate::configure_limits(&connection).expect("production limits must apply");
        connection
            .execute_batch(
                "CREATE TABLE manifest_fixture (
                    singleton INTEGER PRIMARY KEY,
                    envelope BLOB NOT NULL
                ) STRICT;",
            )
            .expect("manifest fixture schema must initialize");
        let envelope = vec![0_u8; librarian_vault_format::MAX_MANIFEST_ENVELOPE_BYTES];
        connection
            .execute(
                "INSERT INTO manifest_fixture(singleton, envelope) VALUES (1, ?1)",
                [&envelope],
            )
            .expect("a format-valid maximum manifest must fit within the SQLite row limit");
        let stored_bytes: i64 = connection
            .query_row(
                "SELECT length(envelope) FROM manifest_fixture WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("maximum manifest length must remain readable");
        assert_eq!(
            usize::try_from(stored_bytes).expect("stored length must fit"),
            envelope.len()
        );
    }

    #[test]
    fn reserved_prefix_schema_objects_fail_closed() {
        let connection = Connection::open_in_memory().expect("SQLite fixture must open");
        connection
            .execute_batch(
                "CREATE TABLE vault_header (
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
                ) STRICT, WITHOUT ROWID;",
            )
            .expect("production schema fixture must initialize");
        connection
            .pragma_update(None, "writable_schema", true)
            .expect("schema-tampering fixture must enable direct writes");
        connection
            .execute(
                "INSERT INTO sqlite_schema(type, name, tbl_name, rootpage, sql)
                 VALUES ('view', 'sqlite_attacker', 'sqlite_attacker', 0,
                         'CREATE VIEW sqlite_attacker AS SELECT 1')",
                [],
            )
            .expect("reserved-prefix schema row must be injected");
        connection
            .pragma_update(None, "writable_schema", false)
            .expect("schema-tampering fixture must restore normal behavior");

        assert!(
            crate::verify_application_schema(&connection).is_err(),
            "every unexpected schema row must fail closed, including reserved prefixes"
        );
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
    fn pre_cancelled_unlock_does_not_read_the_vault_path() {
        let directory = TestDirectory::new();
        let mut agent = VaultAgent::open_locked(directory.vault_path());
        let cancellation = CancellationFlag::new();
        cancellation.cancel();

        assert_eq!(
            agent.unlock(password("cancel before read"), &cancellation),
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

    #[cfg(unix)]
    #[test]
    fn vault_rewrite_during_password_work_prevents_unlock_publication() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let agent = create_test_vault(&path, "rewrite race password");
        drop(agent);
        let mut restarted = VaultAgent::open_locked(&path);

        assert_eq!(
            restarted.unlock_with_before_publish(
                password("rewrite race password"),
                &CancellationFlag::new(),
                || fs::write(&path, b"rewritten during password work")
                    .expect("Unix fixture must rewrite the guarded inode")
            ),
            Err(UnlockError::Failed)
        );
        assert!(!restarted.is_unlocked());
        assert!(restarted.begin_operation().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn vault_replacement_during_password_work_prevents_unlock_publication() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let replacement = directory.0.join("replacement.sqlite3");
        let parked = directory.0.join("parked.sqlite3");
        let agent = create_test_vault(&path, "replacement race password");
        let other = create_test_vault(&replacement, "other replacement password");
        drop(agent);
        drop(other);
        let mut restarted = VaultAgent::open_locked(&path);

        assert_eq!(
            restarted.unlock_with_before_publish(
                password("replacement race password"),
                &CancellationFlag::new(),
                || {
                    fs::rename(&path, &parked).expect("original vault must be parked");
                    fs::rename(&replacement, &path).expect("replacement must take the vault path");
                }
            ),
            Err(UnlockError::Failed)
        );
        assert!(!restarted.is_unlocked());
        assert!(restarted.begin_operation().is_none());
    }

    #[cfg(windows)]
    #[test]
    fn vault_writers_remain_blocked_through_unlock_publication() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let agent = create_test_vault(&path, "guarded unlock password");
        drop(agent);
        let mut restarted = VaultAgent::open_locked(&path);

        restarted
            .unlock_with_before_publish(
                password("guarded unlock password"),
                &CancellationFlag::new(),
                || {
                    assert!(
                        File::options().write(true).open(&path).is_err(),
                        "the input guard must deny writers until unlock is published"
                    );
                },
            )
            .expect("the unchanged guarded vault must unlock");
        assert!(restarted.is_unlocked());
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
    fn freelist_corruption_fails_closed() {
        use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let agent = create_test_vault(&path, "integrity password");
        drop(agent);

        let connection = Connection::open(&path).expect("test database must open");
        connection
            .execute_batch(
                "CREATE TABLE transient_pages(payload BLOB) STRICT;
                 INSERT INTO transient_pages(payload) VALUES (zeroblob(65536));
                 DROP TABLE transient_pages;
                 PRAGMA wal_checkpoint(TRUNCATE);",
            )
            .expect("fixture must create and free non-live pages");
        drop(connection);

        let mut database = File::options()
            .read(true)
            .write(true)
            .open(&path)
            .expect("database fixture must reopen");
        let mut header = [0_u8; 100];
        database
            .read_exact(&mut header)
            .expect("SQLite header must be readable");
        let encoded_page_size = u16::from_be_bytes([header[16], header[17]]);
        let page_size = if encoded_page_size == 1 {
            65_536_u64
        } else {
            u64::from(encoded_page_size)
        };
        let first_freelist_trunk =
            u32::from_be_bytes([header[32], header[33], header[34], header[35]]);
        assert_ne!(
            first_freelist_trunk, 0,
            "fixture must leave at least one freelist trunk"
        );
        let trunk_offset = u64::from(first_freelist_trunk - 1)
            .checked_mul(page_size)
            .expect("freelist trunk offset must fit");
        database
            .seek(SeekFrom::Start(trunk_offset))
            .and_then(|_| database.write_all(&u32::MAX.to_be_bytes()))
            .and_then(|()| database.write_all(&u32::MAX.to_be_bytes()))
            .and_then(|()| database.sync_all())
            .expect("freelist trunk must be corrupted beyond the live rows");
        drop(database);

        let mut restarted = VaultAgent::open_locked(&path);
        assert_eq!(
            restarted.unlock(password("integrity password"), &CancellationFlag::new()),
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
        use std::io::Write;

        let directory = TestDirectory::new();
        let target = directory.vault_path();
        validate_new_target(&target).expect("new target must be accepted");
        let mut staging =
            reserve_staging_file(&target).expect("staging file must be reserved atomically");

        staging
            .reservation_mut()
            .expect("reservation must remain live")
            .write_all(b"partial database")
            .expect("partial fixture must be written through the reservation");
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
        let mut staging =
            reserve_staging_file(&target).expect("staging file must be reserved atomically");
        let replacement = directory.0.join("replacement.sqlite3");
        fs::write(&replacement, b"replacement").expect("replacement fixture must be written");

        assert!(
            fs::OpenOptions::new()
                .write(true)
                .open(staging.path())
                .is_err(),
            "the live reservation must deny external writers"
        );
        assert!(
            fs::remove_file(staging.path()).is_err(),
            "the live reservation must deny deletion"
        );
        assert!(
            fs::rename(&replacement, staging.path()).is_err(),
            "the live reservation must deny replacement"
        );
        assert!(replacement.exists());

        initialize_database(&mut staging, b"header", b"manifest")
            .expect("initialization through the reserved handle must succeed");
        let image = fs::read(staging.path()).expect("staged database must remain readable");
        assert_eq!(&image[..16], b"SQLite format 3\0");
    }

    #[cfg(windows)]
    #[test]
    fn publication_rejects_a_same_size_replacement_after_linking() {
        let directory = TestDirectory::new();
        let target = directory.vault_path();
        let mut staging =
            reserve_staging_file(&target).expect("staging file must be reserved atomically");
        initialize_database(&mut staging, b"header", b"manifest")
            .expect("staged database must initialize");
        let published = publish_staged_vault(&mut staging, &target)
            .expect("the staged database must be linked and identity-checked");
        staging
            .remove_name()
            .expect("the staging name must be removed");

        let replacement_size = usize::try_from(
            published
                .metadata()
                .expect("published metadata must be readable")
                .len(),
        )
        .expect("test database size must fit in memory");
        fs::remove_file(&target).expect("the deletion-sharing test guard must permit replacement");
        fs::write(&target, vec![0_u8; replacement_size])
            .expect("same-size replacement must be written");

        assert!(
            seal_published_vault(&published, &target).is_err(),
            "stable Windows identity must reject a same-size replacement"
        );
    }

    #[cfg(windows)]
    #[test]
    fn publication_revalidation_rejects_in_place_transition_mutation() {
        use std::io::{Seek as _, SeekFrom, Write as _};

        let directory = TestDirectory::new();
        let target = directory.vault_path();
        let mut staging =
            reserve_staging_file(&target).expect("staging file must be reserved atomically");
        initialize_database(&mut staging, b"header", b"manifest")
            .expect("staged database must initialize");
        let published = publish_staged_vault(&mut staging, &target)
            .expect("the staged database must be linked and identity-checked");
        staging
            .remove_name()
            .expect("the staging name must be removed");

        let mut writer = File::options()
            .write(true)
            .open(&target)
            .expect("the fixture must exercise the handle-transition window");
        writer
            .seek(SeekFrom::Start(0))
            .and_then(|_| writer.write_all(b"X"))
            .and_then(|()| writer.sync_all())
            .expect("the published inode must be modified in place");
        drop(writer);

        let sealed = seal_published_vault(&published, &target)
            .expect("the same inode must pass the identity seal");
        assert!(
            crate::verify_published_vault(&sealed, &target, b"header", b"manifest").is_err(),
            "content revalidation must reject mutation during the handle transition"
        );
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
            .reservation()
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
    fn publication_removes_a_replacement_linked_after_identity_check() {
        let directory = TestDirectory::new();
        let target = directory.vault_path();
        let mut staging =
            reserve_staging_file(&target).expect("staging file must be reserved atomically");
        initialize_database(&mut staging, b"header", b"manifest")
            .expect("staged database must initialize");
        let staging_path = staging.path().to_path_buf();

        let result = publish_staged_vault_with_before_link(&mut staging, &target, || {
            fs::remove_file(&staging_path)
                .expect("reserved staging name must be removed after identity validation");
            fs::write(&staging_path, b"attacker replacement")
                .expect("replacement staging name must be created");
            Ok(())
        });

        assert!(matches!(result, Err(CreateError::Failed)));
        assert!(
            !target.exists(),
            "a replacement linked during publication must be removed"
        );
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
        let agent = VaultAgent::open_locked("vault.sqlite3");
        let bound = agent
            .bound_path()
            .map(Path::to_path_buf)
            .expect("a relative path must be bound while the agent is constructed");
        assert!(bound.is_absolute());
        assert_eq!(
            bound,
            std::env::current_dir()
                .expect("current directory must remain available")
                .join("vault.sqlite3")
        );
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
            .set_len(crate::MAX_SQLITE_SHM_BYTES + 1)
            .expect("SHM fixture must be sized");
        let mut shm_agent = VaultAgent::open_locked(&path);
        assert_eq!(
            shm_agent.unlock(password("sidecar password"), &CancellationFlag::new()),
            Err(UnlockError::Failed)
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn sqlite_snapshot_rejects_sidecars_created_after_snapshotting() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let agent = create_test_vault(&path, "late sidecar password");
        drop(agent);

        for suffix in ["-wal", "-shm"] {
            let sidecar = sqlite_sidecar(&path, suffix);
            let result = read_empty_vault_with_connection_hooks(
                &path,
                || {},
                || {
                    fs::write(&sidecar, b"late sidecar")
                        .expect("late sidecar fixture must be written");
                },
            );
            assert!(
                result.is_err(),
                "a {suffix} file created after snapshotting must fail closed"
            );
            fs::remove_file(&sidecar).expect("late sidecar fixture must be removed");
        }
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_snapshot_rechecks_size_immediately_before_allocation() {
        let oversized_directory = TestDirectory::new();
        let oversized_path = oversized_directory.vault_path();
        let agent = create_test_vault(&oversized_path, "oversized snapshot password");
        drop(agent);
        let oversized = read_empty_vault_with_connection_hooks(
            &oversized_path,
            || {
                File::options()
                    .write(true)
                    .open(&oversized_path)
                    .expect("oversized fixture must open")
                    .set_len(librarian_vault_format::MAX_DATABASE_BYTES + 1)
                    .expect("oversized fixture must be sparse-grown");
            },
            || {},
        );
        assert!(
            oversized.is_err(),
            "a post-validation growth must fail before allocation"
        );

        let short_directory = TestDirectory::new();
        let short_path = short_directory.vault_path();
        let agent = create_test_vault(&short_path, "short snapshot password");
        drop(agent);
        let short = read_empty_vault_with_connection_hooks(
            &short_path,
            || {
                File::options()
                    .write(true)
                    .open(&short_path)
                    .expect("short fixture must open")
                    .set_len(1)
                    .expect("short fixture must be truncated");
            },
            || {},
        );
        assert!(
            short.is_err(),
            "a post-validation truncation must fail without indexing a short image"
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_regular_unix_vault_paths_fail_without_blocking() {
        use rustix::fs::{CWD, Mode, mkfifoat};

        let directory = TestDirectory::new();
        let path = directory.vault_path();
        mkfifoat(CWD, &path, Mode::RUSR | Mode::WUSR).expect("FIFO vault fixture must be created");

        let mut agent = VaultAgent::open_locked(&path);
        assert_eq!(
            agent.unlock(password("fifo password"), &CancellationFlag::new()),
            Err(UnlockError::Failed)
        );
        assert!(!agent.is_unlocked());
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

        let wal_path = sqlite_sidecar(&path, "-wal");
        let shm_path = sqlite_sidecar(&path, "-shm");
        fs::write(&wal_path, b"guarded WAL").expect("WAL fixture must be written");
        fs::write(&shm_path, b"guarded SHM").expect("SHM fixture must be written");
        let sidecar_guards =
            acquire_sqlite_input_guards(&path).expect("SQLite sidecars must be guarded");
        for sidecar in [&wal_path, &shm_path] {
            assert!(
                File::options().write(true).open(sidecar).is_err(),
                "checked SQLite sidecars must deny concurrent writers"
            );
            assert!(
                fs::remove_file(sidecar).is_err(),
                "checked SQLite sidecars must deny replacement"
            );
        }
        drop(sidecar_guards);
        fs::remove_file(&wal_path).expect("WAL fixture must be removable after guard drop");
        fs::remove_file(&shm_path).expect("SHM fixture must be removable after guard drop");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn valid_wal_is_read_from_a_guarded_snapshot() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let agent = create_test_vault(&path, "WAL recovery password");
        drop(agent);

        let connection = Connection::open(&path).expect("WAL fixture database must open");
        connection
            .pragma_update(None, "wal_autocheckpoint", 0)
            .expect("automatic checkpoints must be disabled");
        connection
            .pragma_update(None, "user_version", 1)
            .expect("a valid committed WAL frame must be written");
        let database_before_checkpoint =
            fs::read(&path).expect("pre-checkpoint database must be captured");
        let wal_path = sqlite_sidecar(&path, "-wal");
        let committed_wal = fs::read(&wal_path).expect("committed WAL must be captured");
        assert!(
            committed_wal.len() > 32,
            "fixture must contain a WAL header and at least one frame"
        );
        drop(connection);

        let shm_path = sqlite_sidecar(&path, "-shm");
        if shm_path.exists() {
            fs::remove_file(&shm_path).expect("closed fixture SHM must be removable");
        }
        if wal_path.exists() {
            fs::remove_file(&wal_path).expect("closed fixture WAL must be removable");
        }
        fs::write(&path, database_before_checkpoint)
            .expect("pre-checkpoint database must be restored");
        fs::write(&wal_path, committed_wal).expect("committed WAL must be restored");

        let mut restarted = VaultAgent::open_locked(&path);
        restarted
            .unlock(password("WAL recovery password"), &CancellationFlag::new())
            .expect("a valid crash-recovery WAL must unlock from the guarded snapshot");
        assert!(restarted.is_unlocked());
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

    #[cfg(unix)]
    #[test]
    fn sqlite_snapshot_remains_bound_when_an_ancestor_is_replaced() {
        let directory = TestDirectory::new();
        let visible_parent = directory.0.join("visible");
        let parked_parent = directory.0.join("parked");
        let attacker_parent = directory.0.join("attacker");
        fs::create_dir(&visible_parent).expect("visible parent must be created");
        fs::create_dir(&attacker_parent).expect("attacker parent must be created");
        let path = visible_parent.join("vault.sqlite3");
        let attacker_path = attacker_parent.join("vault.sqlite3");
        let original = create_test_vault(&path, "original ancestor password");
        let attacker = create_test_vault(&attacker_path, "attacker ancestor password");
        drop(original);
        drop(attacker);
        let expected = read_empty_vault(&path).expect("original vault must be readable");

        let actual = read_empty_vault_with_hooks(
            &path,
            || {
                fs::rename(&visible_parent, &parked_parent).expect("guarded parent must be parked");
                create_directory_symlink(&attacker_parent, &visible_parent);
            },
            || {},
            || {
                fs::remove_file(&visible_parent).expect("redirecting symlink must be removed");
                fs::rename(&parked_parent, &visible_parent)
                    .expect("guarded parent must be restored");
            },
        )
        .expect("directory-relative reads must stay bound to the guarded parent");

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

    #[test]
    fn interrupted_record_transaction_commits_neither_row_nor_manifest() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let mut agent = create_test_vault(&path, "interrupted transaction password");

        assert_eq!(
            agent
                .add_website_account_with_before_commit(account_input("Interrupted"), || Err(
                    StorageError::Sqlite
                ))
                .err(),
            Some(AccountError::Failed)
        );
        assert!(!agent.is_unlocked());
        drop(agent);

        let mut restarted = VaultAgent::open_locked(&path);
        restarted
            .unlock(
                password("interrupted transaction password"),
                &CancellationFlag::new(),
            )
            .expect("rolled-back vault must remain authentic");
        assert!(
            restarted
                .list_website_accounts()
                .expect("rolled-back vault must remain empty")
                .is_empty()
        );
    }

    #[test]
    fn record_mutation_rejects_oversized_sidecars_before_sqlite_opens() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let mut agent = create_test_vault(&path, "oversized mutation sidecar password");
        let shm = sqlite_sidecar(&path, "-shm");
        File::create(&shm)
            .and_then(|file| file.set_len(crate::MAX_SQLITE_SHM_BYTES + 1))
            .expect("oversized shared-memory fixture must be created");

        assert_eq!(
            agent
                .add_website_account(account_input("Oversized Sidecar"))
                .err(),
            Some(AccountError::Failed)
        );
        assert!(!agent.is_unlocked());
        assert_eq!(
            fs::metadata(shm)
                .expect("oversized sidecar must remain available")
                .len(),
            crate::MAX_SQLITE_SHM_BYTES + 1
        );
    }

    #[test]
    fn lock_before_plaintext_return_discards_the_result() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let mut agent = create_test_vault(&path, "lock race record password");
        let id = agent
            .add_website_account(account_input("Lock Race"))
            .expect("account must be added");

        assert_eq!(
            agent
                .get_website_account_with_before_return(id, VaultAgent::lock)
                .err(),
            Some(AccountError::Locked)
        );
        assert!(!agent.is_unlocked());
    }

    #[test]
    fn account_page_authentication_honors_mid_visit_cancellation() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let mut agent = create_test_vault(&path, "page cancellation password");
        agent
            .add_website_account(account_input("Page Cancellation"))
            .expect("account must be added");
        let mut checks = 0_usize;

        assert_eq!(
            agent
                .list_website_account_page_with_check(0, 100, || {
                    checks = checks.saturating_add(1);
                    true
                })
                .err(),
            Some(AccountError::Aborted)
        );
        assert_eq!(checks, 1);
        assert!(agent.is_unlocked());
    }

    #[test]
    fn account_mutation_authentication_honors_mid_visit_cancellation() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let mut agent = create_test_vault(&path, "mutation cancellation password");
        let id = agent
            .add_website_account(account_input("Existing"))
            .expect("account must be added");

        let mut add_committed = false;
        assert_eq!(
            agent
                .add_website_account_with_before_commit_and_check(
                    account_input("Cancelled Add"),
                    || true,
                    || {
                        add_committed = true;
                        Ok(())
                    },
                )
                .err(),
            Some(AccountError::Aborted)
        );
        assert!(!add_committed);

        let mut update_committed = false;
        assert_eq!(
            agent
                .update_website_account_with_before_commit_and_check(
                    id,
                    account_input("Cancelled Update"),
                    || true,
                    || {
                        update_committed = true;
                        Ok(())
                    },
                )
                .err(),
            Some(AccountError::Aborted)
        );
        assert!(!update_committed);

        let mut delete_committed = false;
        assert_eq!(
            agent
                .delete_website_account_with_before_commit_and_check(
                    id,
                    || true,
                    || {
                        delete_committed = true;
                        Ok(())
                    },
                )
                .err(),
            Some(AccountError::Aborted)
        );
        assert!(!delete_committed);
        assert!(agent.is_unlocked());
        assert!(
            agent.get_website_account(id).is_ok(),
            "existing account must remain authenticated"
        );
    }

    #[test]
    fn sqlite_primary_key_rejects_duplicate_record_identifiers() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let mut agent = create_test_vault(&path, "duplicate identifier password");
        agent
            .add_website_account(account_input("Duplicate"))
            .expect("account must be added");
        agent.lock();
        drop(agent);

        let connection = Connection::open(&path).expect("test database must open");
        let (record_id, envelope): (Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT record_id, envelope FROM encrypted_records LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("record fixture must exist");
        assert!(
            connection
                .execute(
                    "INSERT INTO encrypted_records(record_id, envelope) VALUES (?1, ?2)",
                    rusqlite::params![record_id, envelope],
                )
                .is_err(),
            "duplicate identifiers must fail at the SQLite boundary"
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
