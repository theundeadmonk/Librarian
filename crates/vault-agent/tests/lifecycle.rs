use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use librarian_vault_agent::{CreateError, UnlockError, VaultAgent};
use librarian_vault_core::{CancellationFlag, MasterPassword};

static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "librarian-vault-agent-integration-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("integration-test directory must be created");
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
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

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[test]
fn create_lock_restart_and_unlock_uses_only_the_public_api() {
    let directory = TestDirectory::new();
    let path = directory.path("vault.sqlite3");
    let (mut created, _recovery_key) =
        VaultAgent::create(&path, password("integration restart password"))
            .expect("vault must be created");

    assert!(created.is_unlocked());
    assert!(created.begin_operation().is_some());

    created.lock();
    assert!(!created.is_unlocked());
    assert!(created.begin_operation().is_none());
    drop(created);

    let mut restarted = VaultAgent::open_locked(&path);
    assert!(!restarted.is_unlocked());
    restarted
        .unlock(
            password("integration restart password"),
            &CancellationFlag::new(),
        )
        .expect("matching password must unlock after restart");
    assert!(restarted.is_unlocked());
}

#[test]
fn create_never_replaces_an_existing_target() {
    let directory = TestDirectory::new();
    let path = directory.path("existing.sqlite3");
    let sentinel = b"existing non-vault bytes";
    fs::write(&path, sentinel).expect("sentinel file must be written");

    let result = VaultAgent::create(&path, password("unused integration password"));

    assert!(matches!(result, Err(CreateError::AlreadyExists)));
    assert_eq!(
        fs::read(&path).expect("sentinel file must remain readable"),
        sentinel
    );
}

#[test]
fn create_rejects_preexisting_sqlite_sidecars() {
    for suffix in ["-wal", "-shm"] {
        let directory = TestDirectory::new();
        let path = directory.path("vault.sqlite3");
        let sidecar_path = sidecar(&path, suffix);
        fs::write(&sidecar_path, b"attacker-controlled sidecar")
            .expect("sidecar fixture must be written");

        let result = VaultAgent::create(&path, password("sidecar integration password"));

        assert!(matches!(result, Err(CreateError::Failed)));
        assert!(!path.exists(), "failed creation must not publish a vault");
        assert_eq!(
            fs::read(sidecar_path).expect("existing sidecar must remain untouched"),
            b"attacker-controlled sidecar"
        );
    }
}

#[test]
fn wrong_password_and_corruption_share_the_public_failure() {
    let directory = TestDirectory::new();
    let path = directory.path("vault.sqlite3");
    let (mut created, _recovery_key) =
        VaultAgent::create(&path, password("correct integration password"))
            .expect("vault must be created");
    created.lock();
    drop(created);

    let mut wrong_password = VaultAgent::open_locked(&path);
    assert_eq!(
        wrong_password.unlock(
            password("wrong integration password"),
            &CancellationFlag::new(),
        ),
        Err(UnlockError::Failed)
    );
    assert!(!wrong_password.is_unlocked());

    fs::write(&path, b"not a sqlite database").expect("corruption fixture must be written");
    let mut corrupted = VaultAgent::open_locked(&path);
    assert_eq!(
        corrupted.unlock(
            password("correct integration password"),
            &CancellationFlag::new(),
        ),
        Err(UnlockError::Failed)
    );
    assert!(!corrupted.is_unlocked());
}

#[test]
fn pre_cancelled_unlock_never_publishes_a_session() {
    let directory = TestDirectory::new();
    let path = directory.path("vault.sqlite3");
    let (mut created, _recovery_key) =
        VaultAgent::create(&path, password("cancel integration password"))
            .expect("vault must be created");
    created.lock();
    drop(created);

    let cancellation = CancellationFlag::new();
    cancellation.cancel();
    let mut restarted = VaultAgent::open_locked(&path);

    assert_eq!(
        restarted.unlock(password("cancel integration password"), &cancellation),
        Err(UnlockError::Cancelled)
    );
    assert!(!restarted.is_unlocked());
    assert!(restarted.begin_operation().is_none());
}

#[test]
fn operation_permits_are_invalidated_by_lock_and_session_changes() {
    let directory = TestDirectory::new();
    let path = directory.path("vault.sqlite3");
    let (mut created, _recovery_key) =
        VaultAgent::create(&path, password("permit integration password"))
            .expect("vault must be created");
    let original = created
        .begin_operation()
        .expect("unlocked session must issue a permit");
    assert!(created.operation_is_authorized(original));

    created.lock();
    assert!(!created.operation_is_authorized(original));
    drop(created);

    let mut restarted = VaultAgent::open_locked(&path);
    restarted
        .unlock(
            password("permit integration password"),
            &CancellationFlag::new(),
        )
        .expect("vault must unlock");
    let replacement = restarted
        .begin_operation()
        .expect("new session must issue a permit");

    assert!(!restarted.operation_is_authorized(original));
    assert!(restarted.operation_is_authorized(replacement));
}

#[test]
fn missing_vault_fails_closed_and_remains_locked() {
    let directory = TestDirectory::new();
    let path = directory.path("missing.sqlite3");
    let mut agent = VaultAgent::open_locked(&path);

    assert_eq!(
        agent.unlock(
            password("missing integration password"),
            &CancellationFlag::new(),
        ),
        Err(UnlockError::Failed)
    );
    assert!(!agent.is_unlocked());
}

#[test]
fn public_errors_do_not_disclose_paths_or_failure_details() {
    assert_eq!(
        CreateError::AlreadyExists.to_string(),
        "a vault already exists at the selected location"
    );
    assert_eq!(CreateError::Failed.to_string(), "vault creation failed");
    assert_eq!(UnlockError::Failed.to_string(), "vault unlock failed");
    assert_eq!(
        UnlockError::Cancelled.to_string(),
        "vault unlock was cancelled"
    );
}
