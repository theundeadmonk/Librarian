use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use librarian_vault_agent::{
    AccountError, RecordId, UnlockError, VaultAgent, WebsiteAccountInput, WebsiteAccountInputError,
};
use librarian_vault_core::{CancellationFlag, MasterPassword};
use rusqlite::Connection;

static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "librarian-website-account-integration-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("integration-test directory must be created");
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
    MasterPassword::new(value).expect("integration-test password must be valid")
}

fn account(
    service_name: &str,
    origin: &str,
    username: &str,
    password: &str,
) -> WebsiteAccountInput {
    WebsiteAccountInput::new(service_name, origin, username, password)
        .expect("integration-test account input must be valid")
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[test]
fn website_account_crud_survives_lock_and_restart() {
    let directory = TestDirectory::new();
    let path = directory.vault_path();
    let (mut agent, _recovery) =
        VaultAgent::create(&path, password("website account lifecycle password"))
            .expect("vault must be created");

    let id = agent
        .add_website_account(account(
            "Example",
            "HTTPS://EXAMPLE.COM:443/",
            "first@example.com",
            "first disposable password",
        ))
        .expect("account must be added");
    let added = agent
        .get_website_account(id)
        .expect("added account must be retrievable");
    assert_eq!(added.id(), id);
    assert_eq!(added.revision(), 1);
    assert_eq!(added.service_name(), "Example");
    assert_eq!(added.permitted_origin(), "https://example.com");
    assert_eq!(added.username(), "first@example.com");
    assert_eq!(added.password(), "first disposable password");
    let created_at_ms = added.created_at_ms();
    drop(added);

    let listed = agent
        .list_website_accounts()
        .expect("account list must authenticate");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id(), id);
    drop(listed);

    agent
        .update_website_account(
            id,
            account(
                "Example Updated",
                "https://login.example.com/",
                "second@example.com",
                "second disposable password",
            ),
        )
        .expect("account must update");
    let updated = agent
        .get_website_account(id)
        .expect("updated account must be retrievable");
    assert_eq!(updated.revision(), 2);
    assert_eq!(updated.created_at_ms(), created_at_ms);
    assert!(updated.modified_at_ms() >= updated.created_at_ms());
    assert_eq!(updated.service_name(), "Example Updated");
    assert_eq!(updated.permitted_origin(), "https://login.example.com");
    assert_eq!(updated.username(), "second@example.com");
    assert_eq!(updated.password(), "second disposable password");
    drop(updated);

    agent.lock();
    drop(agent);
    let mut restarted = VaultAgent::open_locked(&path);
    restarted
        .unlock(
            password("website account lifecycle password"),
            &CancellationFlag::new(),
        )
        .expect("non-empty vault must unlock after restart");
    let persisted = restarted
        .get_website_account(id)
        .expect("updated account must survive restart");
    assert_eq!(persisted.revision(), 2);
    assert_eq!(persisted.password(), "second disposable password");
    drop(persisted);

    restarted
        .delete_website_account(id)
        .expect("account must delete");
    assert_eq!(
        restarted.get_website_account(id).err(),
        Some(AccountError::NotFound)
    );
    assert!(
        restarted
            .list_website_accounts()
            .expect("empty list must authenticate")
            .is_empty()
    );
    assert!(restarted.is_unlocked());
}

#[test]
fn locked_agent_rejects_every_record_operation_without_reading_plaintext() {
    let directory = TestDirectory::new();
    let path = directory.vault_path();
    let (mut agent, _recovery) =
        VaultAgent::create(&path, password("locked record operation password"))
            .expect("vault must be created");
    agent.lock();
    let unknown = RecordId::from_bytes([0xA5; 16]);

    assert_eq!(
        agent
            .add_website_account(account(
                "Locked",
                "https://locked.example",
                "person",
                "password",
            ))
            .err(),
        Some(AccountError::Locked)
    );
    assert_eq!(
        agent.get_website_account(unknown).err(),
        Some(AccountError::Locked)
    );
    assert_eq!(
        agent.list_website_accounts().err(),
        Some(AccountError::Locked)
    );
    assert_eq!(
        agent
            .update_website_account(
                unknown,
                account("Locked", "https://locked.example", "person", "password",),
            )
            .err(),
        Some(AccountError::Locked)
    );
    assert_eq!(
        agent.delete_website_account(unknown),
        Err(AccountError::Locked)
    );
}

#[test]
fn invalid_origins_are_rejected_before_a_vault_operation() {
    for invalid in [
        "https://example.com/login",
        "https://user@example.com/",
        "https://example.com/?redirect=login",
        "https://example.com/#login",
        "file:///tmp/example",
        "not an origin",
    ] {
        assert!(matches!(
            WebsiteAccountInput::new("Example", invalid, "person", "password"),
            Err(WebsiteAccountInputError::InvalidOrigin)
        ));
    }
}

#[test]
fn plaintext_fields_never_appear_in_database_or_sidecars() {
    let directory = TestDirectory::new();
    let path = directory.vault_path();
    let markers = [
        "UNIQUE-SERVICE-NAME-4B6B84",
        "unique-user-12f70@example.test",
        "UNIQUE-PASSWORD-7DE1CB",
        "unique-origin-0f4e.example.test",
    ];
    let (mut agent, _recovery) =
        VaultAgent::create(&path, password("database inspection password"))
            .expect("vault must be created");
    agent
        .add_website_account(account(
            markers[0],
            "https://UNIQUE-ORIGIN-0f4e.example.test",
            markers[1],
            markers[2],
        ))
        .expect("account must be added");
    agent.lock();
    drop(agent);

    for file in [path.clone(), sidecar(&path, "-wal"), sidecar(&path, "-shm")] {
        let Ok(bytes) = fs::read(file) else {
            continue;
        };
        for marker in markers {
            assert!(
                !bytes
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes()),
                "plaintext marker must not be present in SQLite files"
            );
        }
    }
}

#[test]
fn stale_concurrent_agent_fails_closed_instead_of_losing_an_update() {
    let directory = TestDirectory::new();
    let path = directory.vault_path();
    let (mut first, _recovery) = VaultAgent::create(&path, password("concurrent writer password"))
        .expect("vault must be created");
    let mut second = VaultAgent::open_locked(&path);
    second
        .unlock(
            password("concurrent writer password"),
            &CancellationFlag::new(),
        )
        .expect("second agent must authenticate the initial generation");

    first
        .add_website_account(account(
            "First",
            "https://first.example",
            "first",
            "first password",
        ))
        .expect("first agent must commit");
    assert_eq!(
        second
            .add_website_account(account(
                "Second",
                "https://second.example",
                "second",
                "second password",
            ))
            .err(),
        Some(AccountError::Failed)
    );
    assert!(!second.is_unlocked());
    assert_eq!(
        first
            .list_website_accounts()
            .expect("winning session must remain valid")
            .len(),
        1
    );
}

#[test]
fn record_corruption_blocks_unlock_without_exposing_a_distinction() {
    let directory = TestDirectory::new();
    let path = directory.vault_path();
    let (mut agent, _recovery) = VaultAgent::create(&path, password("corrupted record password"))
        .expect("vault must be created");
    agent
        .add_website_account(account(
            "Corruptible",
            "https://corruptible.example",
            "person",
            "disposable password",
        ))
        .expect("account must be added");
    agent.lock();
    drop(agent);

    let connection = Connection::open(&path).expect("test database must open");
    let mut envelope: Vec<u8> = connection
        .query_row(
            "SELECT envelope FROM encrypted_records LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("record envelope must exist");
    let last = envelope
        .last_mut()
        .expect("record envelope must not be empty");
    *last ^= 1;
    connection
        .execute("UPDATE encrypted_records SET envelope = ?1", [&envelope])
        .expect("test must corrupt the record envelope");
    drop(connection);

    let mut corrupted = VaultAgent::open_locked(&path);
    assert_eq!(
        corrupted.unlock(
            password("corrupted record password"),
            &CancellationFlag::new(),
        ),
        Err(UnlockError::Failed)
    );
    assert!(!corrupted.is_unlocked());
}

#[test]
fn manifest_rejects_missing_and_extra_record_rows() {
    for tamper in ["missing", "extra"] {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let vault_password = format!("{tamper} record-set password");
        let (mut agent, _recovery) =
            VaultAgent::create(&path, password(&vault_password)).expect("vault must be created");
        agent
            .add_website_account(account(
                "Record Set",
                "https://record-set.example",
                "person",
                "disposable password",
            ))
            .expect("account must be added");
        agent.lock();
        drop(agent);

        let connection = Connection::open(&path).expect("test database must open");
        if tamper == "missing" {
            connection
                .execute("DELETE FROM encrypted_records", [])
                .expect("test must remove the committed row");
        } else {
            let envelope: Vec<u8> = connection
                .query_row(
                    "SELECT envelope FROM encrypted_records LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .expect("record envelope must exist");
            connection
                .execute(
                    "INSERT INTO encrypted_records(record_id, envelope) VALUES (?1, ?2)",
                    rusqlite::params![[0xE7_u8; 16].as_slice(), envelope],
                )
                .expect("test must add an uncommitted row");
        }
        drop(connection);

        let mut corrupted = VaultAgent::open_locked(&path);
        assert_eq!(
            corrupted.unlock(password(&vault_password), &CancellationFlag::new()),
            Err(UnlockError::Failed)
        );
        assert!(!corrupted.is_unlocked());
    }
}

#[test]
fn replaying_an_older_record_envelope_blocks_unlock() {
    let directory = TestDirectory::new();
    let path = directory.vault_path();
    let (mut agent, _recovery) = VaultAgent::create(&path, password("replayed envelope password"))
        .expect("vault must be created");
    let id = agent
        .add_website_account(account(
            "Replay",
            "https://replay.example",
            "first",
            "first password",
        ))
        .expect("account must be added");
    let connection = Connection::open(&path).expect("test database must open");
    let old_envelope: Vec<u8> = connection
        .query_row(
            "SELECT envelope FROM encrypted_records WHERE record_id = ?1",
            [id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("old record envelope must exist");
    drop(connection);

    agent
        .update_website_account(
            id,
            account(
                "Replay Updated",
                "https://replay.example",
                "second",
                "second password",
            ),
        )
        .expect("account must update");
    agent.lock();
    drop(agent);

    let connection = Connection::open(&path).expect("test database must open");
    connection
        .execute(
            "UPDATE encrypted_records SET envelope = ?1 WHERE record_id = ?2",
            rusqlite::params![old_envelope, id.as_bytes().as_slice()],
        )
        .expect("test must replay the older record envelope");
    drop(connection);

    let mut replayed = VaultAgent::open_locked(&path);
    assert_eq!(
        replayed.unlock(
            password("replayed envelope password"),
            &CancellationFlag::new(),
        ),
        Err(UnlockError::Failed)
    );
    assert!(!replayed.is_unlocked());
}

#[test]
fn single_record_get_authenticates_every_other_row_before_returning_plaintext() {
    let directory = TestDirectory::new();
    let path = directory.vault_path();
    let (mut agent, _recovery) =
        VaultAgent::create(&path, password("streaming authentication password"))
            .expect("vault must be created");
    let requested = agent
        .add_website_account(account(
            "Requested",
            "https://requested.example",
            "requested",
            "requested password",
        ))
        .expect("requested account must be added");
    let corrupted = agent
        .add_website_account(account(
            "Corrupted",
            "https://corrupted.example",
            "corrupted",
            "corrupted password",
        ))
        .expect("second account must be added");

    let connection = Connection::open(&path).expect("test database must open");
    let mut envelope: Vec<u8> = connection
        .query_row(
            "SELECT envelope FROM encrypted_records WHERE record_id = ?1",
            [corrupted.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("second record envelope must exist");
    let last = envelope
        .last_mut()
        .expect("record envelope must not be empty");
    *last ^= 1;
    connection
        .execute(
            "UPDATE encrypted_records SET envelope = ?1 WHERE record_id = ?2",
            rusqlite::params![envelope, corrupted.as_bytes().as_slice()],
        )
        .expect("test must corrupt the second record");
    drop(connection);

    assert_eq!(
        agent.get_website_account(requested).err(),
        Some(AccountError::Failed)
    );
    assert!(!agent.is_unlocked());
}

#[test]
fn unknown_record_id_is_not_found_only_after_authentication() {
    let directory = TestDirectory::new();
    let path = directory.vault_path();
    let (mut agent, _recovery) = VaultAgent::create(&path, password("unknown identifier password"))
        .expect("vault must be created");
    let unknown = RecordId::from_bytes([0x5A; 16]);

    assert_eq!(
        agent.get_website_account(unknown).err(),
        Some(AccountError::NotFound)
    );
    assert_eq!(
        agent.delete_website_account(unknown),
        Err(AccountError::NotFound)
    );
    assert!(agent.is_unlocked());
}
