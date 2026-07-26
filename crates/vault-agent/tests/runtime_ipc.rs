use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use librarian_agent_protocol::{
    AgentState, CURRENT_VERSION, ClientHello, ClientRole, Connection, ConnectionError,
    ConnectionLimits, FrameHeader, MessageKind, OperationCode, OperationRequest, PublicErrorCode,
    RequestEnvelope, ResponseEnvelope,
};
use librarian_vault_agent::{AgentRuntime, DispatchError, RuntimeStartError};
use minicbor::Decoder;
use zeroize::Zeroizing;

static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(1);
const BUILD_ID: [u8; 32] = [0x42; 32];

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "librarian-runtime-integration-{}-{sequence}",
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

fn connection(role: ClientRole, runtime: &AgentRuntime, marker: u8) -> Connection {
    let (state, epoch) = runtime
        .status_snapshot()
        .expect("handshake status snapshot");
    let hello = ClientHello::new(
        [marker; 32],
        CURRENT_VERSION,
        CURRENT_VERSION,
        role,
        BUILD_ID,
        Vec::new(),
    )
    .expect("client hello");
    Connection::negotiate(
        role,
        BUILD_ID,
        &hello,
        &[],
        [marker.wrapping_add(1); 32],
        [marker.wrapping_add(2); 16],
        state,
        epoch,
        ConnectionLimits::default(),
    )
    .expect("connection negotiation")
    .0
}

fn dispatch(
    runtime: &AgentRuntime,
    connection: &Connection,
    request_id: u64,
    operation: &OperationRequest,
    idempotency_key: Option<[u8; 16]>,
) -> ResponseEnvelope {
    let (request, header) =
        request_parts(runtime, connection, request_id, operation, idempotency_key);
    runtime
        .dispatch(connection, &header, &request, copy_response)
        .expect("request dispatch")
}

fn request_parts(
    runtime: &AgentRuntime,
    connection: &Connection,
    request_id: u64,
    operation: &OperationRequest,
    idempotency_key: Option<[u8; 16]>,
) -> (RequestEnvelope, FrameHeader) {
    let body = operation.encode().expect("operation body");
    let request = RequestEnvelope::new(
        operation.operation(),
        runtime.unlock_epoch(),
        30_000,
        idempotency_key,
        body,
    )
    .expect("request envelope");
    let request_bytes = request.encode().expect("encoded request");
    let header = FrameHeader::new(
        MessageKind::Request,
        CURRENT_VERSION,
        request_bytes.len(),
        *connection.connection_id(),
        request_id,
    )
    .expect("request header");
    (request, header)
}

fn copy_response(response: &ResponseEnvelope) -> Result<ResponseEnvelope, DispatchError> {
    let encoded = response.encode().map_err(|_| DispatchError::Internal)?;
    ResponseEnvelope::decode(&encoded).map_err(|_| DispatchError::Internal)
}

fn create(password: &str) -> OperationRequest {
    OperationRequest::CreateVault {
        master_password: Zeroizing::new(password.to_owned()),
    }
}

fn unlock(password: &str) -> OperationRequest {
    OperationRequest::UnlockMasterPassword {
        master_password: Zeroizing::new(password.to_owned()),
    }
}

fn fields() -> librarian_agent_protocol::AccountFields {
    librarian_agent_protocol::AccountFields::new(
        "Runtime Example",
        "https://runtime.example",
        "runtime-user@example.test",
        "RUNTIME-PASSWORD-CANARY-CA1C88",
    )
    .expect("bounded account fields")
}

fn different_fields() -> librarian_agent_protocol::AccountFields {
    librarian_agent_protocol::AccountFields::new(
        "Different Runtime Example",
        "https://different-runtime.example",
        "different-runtime-user@example.test",
        "DIFFERENT-RUNTIME-PASSWORD-CANARY-7A13D2",
    )
    .expect("bounded account fields")
}

fn decode_account_id(body: &[u8]) -> [u8; 16] {
    let mut decoder = Decoder::new(body);
    assert_eq!(decoder.array().expect("array"), Some(1));
    decoder
        .bytes()
        .expect("record ID")
        .try_into()
        .expect("16-byte record ID")
}

#[test]
fn desktop_protocol_crud_is_typed_paged_idempotent_and_lock_bound() {
    let directory = TestDirectory::new();
    let runtime = AgentRuntime::start(directory.vault_path()).expect("runtime starts");
    let client = connection(ClientRole::Desktop, &runtime, 3);

    let created = dispatch(
        &runtime,
        &client,
        1,
        &create("runtime integration password"),
        Some([1; 16]),
    );
    assert_eq!(created.error(), None);
    assert_eq!(runtime.state(), AgentState::Unlocked);

    let added = dispatch(
        &runtime,
        &client,
        2,
        &OperationRequest::AddAccount { fields: fields() },
        Some([2; 16]),
    );
    assert_eq!(added.error(), None);
    let account_id = decode_account_id(added.body());

    let replayed = dispatch(
        &runtime,
        &client,
        3,
        &OperationRequest::AddAccount { fields: fields() },
        Some([2; 16]),
    );
    assert_eq!(replayed.error(), None);
    assert_eq!(replayed.body(), added.body());

    let conflicting_reuse = dispatch(
        &runtime,
        &client,
        4,
        &OperationRequest::AddAccount {
            fields: different_fields(),
        },
        Some([2; 16]),
    );
    assert_eq!(conflicting_reuse.error(), Some(PublicErrorCode::Conflict));

    let listed = dispatch(
        &runtime,
        &client,
        5,
        &OperationRequest::ListAccountSummaries {
            offset: 0,
            limit: 1,
        },
        None,
    );
    assert_eq!(listed.error(), None);
    assert!(
        !listed
            .body()
            .windows(b"RUNTIME-PASSWORD-CANARY-CA1C88".len())
            .any(|window| window == b"RUNTIME-PASSWORD-CANARY-CA1C88")
    );

    let retrieved = dispatch(
        &runtime,
        &client,
        6,
        &OperationRequest::GetAccount { id: account_id },
        None,
    );
    assert_eq!(retrieved.error(), None);
    assert!(
        retrieved
            .body()
            .windows(b"RUNTIME-PASSWORD-CANARY-CA1C88".len())
            .any(|window| window == b"RUNTIME-PASSWORD-CANARY-CA1C88")
    );

    let locked = dispatch(&runtime, &client, 7, &OperationRequest::Lock, None);
    assert_eq!(locked.error(), None);
    assert_eq!(runtime.state(), AgentState::Locked);

    let stale = dispatch(
        &runtime,
        &client,
        8,
        &OperationRequest::GetAccount { id: account_id },
        None,
    );
    assert_eq!(stale.error(), Some(PublicErrorCode::Locked));
    assert!(
        !format!("{retrieved:?}").contains("RUNTIME-PASSWORD-CANARY-CA1C88"),
        "response debug output must redact plaintext"
    );
}

#[test]
fn secret_response_write_completes_before_lock_acknowledgement() {
    let directory = TestDirectory::new();
    let runtime = Arc::new(AgentRuntime::start(directory.vault_path()).expect("runtime starts"));
    let setup_client = connection(ClientRole::Desktop, &runtime, 9);
    assert_eq!(
        dispatch(
            &runtime,
            &setup_client,
            1,
            &create("response barrier password"),
            Some([0x11; 16]),
        )
        .error(),
        None
    );
    let added = dispatch(
        &runtime,
        &setup_client,
        2,
        &OperationRequest::AddAccount { fields: fields() },
        Some([0x12; 16]),
    );
    let account_id = decode_account_id(added.body());

    let get_client = Arc::new(connection(ClientRole::Desktop, &runtime, 19));
    let lock_client = connection(ClientRole::Desktop, &runtime, 29);
    let get_operation = OperationRequest::GetAccount { id: account_id };
    let (get_request, get_header) = request_parts(&runtime, &get_client, 1, &get_operation, None);
    let (write_started_tx, write_started_rx) = mpsc::channel();
    let (release_write_tx, release_write_rx) = mpsc::channel();
    let get_runtime = Arc::clone(&runtime);
    let get_worker = thread::spawn(move || {
        get_runtime
            .dispatch(&get_client, &get_header, &get_request, |response| {
                write_started_tx.send(()).expect("write started");
                release_write_rx.recv().expect("release response write");
                copy_response(response)
            })
            .expect("get dispatch")
    });
    write_started_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("secret response entered transport writer");

    let lock_runtime = Arc::clone(&runtime);
    let (lock_done_tx, lock_done_rx) = mpsc::channel();
    let lock_worker = thread::spawn(move || {
        let response = dispatch(
            &lock_runtime,
            &lock_client,
            1,
            &OperationRequest::Lock,
            None,
        );
        lock_done_tx.send(response).expect("lock result");
    });
    assert!(
        matches!(
            lock_done_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "lock must not acknowledge while a secret response write is pending"
    );

    release_write_tx.send(()).expect("release response");
    let retrieved = get_worker.join().expect("get worker");
    assert!(
        retrieved
            .body()
            .windows(b"RUNTIME-PASSWORD-CANARY-CA1C88".len())
            .any(|window| window == b"RUNTIME-PASSWORD-CANARY-CA1C88")
    );
    let locked = lock_done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("lock completes after response write");
    assert_eq!(locked.error(), None);
    lock_worker.join().expect("lock worker");
    assert_eq!(runtime.state(), AgentState::Locked);
}

#[test]
fn disconnect_closes_admission_before_returning() {
    let directory = TestDirectory::new();
    let runtime = AgentRuntime::start(directory.vault_path()).expect("runtime starts");
    let client = connection(ClientRole::Desktop, &runtime, 39);
    runtime.disconnect(&client).expect("disconnect");

    let operation = OperationRequest::Status;
    let (request, header) = request_parts(&runtime, &client, 1, &operation, None);
    let writer_called = AtomicBool::new(false);
    assert!(matches!(
        runtime.dispatch(&client, &header, &request, |response| {
            writer_called.store(true, Ordering::Release);
            copy_response(response)
        }),
        Err(DispatchError::Connection(ConnectionError::ConnectionClosed))
    ));
    assert!(!writer_called.load(Ordering::Acquire));
}

#[test]
fn core_integrity_failure_locks_runtime_advances_epoch_and_allows_unlock_attempt() {
    let directory = TestDirectory::new();
    let path = directory.vault_path();
    let runtime = AgentRuntime::start(&path).expect("runtime starts");
    let client = connection(ClientRole::Desktop, &runtime, 11);
    assert_eq!(
        dispatch(
            &runtime,
            &client,
            1,
            &create("integrity failure integration password"),
            Some([0x11; 16]),
        )
        .error(),
        None
    );
    let unlocked_epoch = runtime.unlock_epoch();
    fs::write(&path, b"intentionally corrupted vault fixture").expect("corrupt vault fixture");

    let failed = dispatch(
        &runtime,
        &client,
        2,
        &OperationRequest::ListAccountSummaries {
            offset: 0,
            limit: 1,
        },
        None,
    );
    assert_eq!(failed.error(), Some(PublicErrorCode::OperationFailed));
    assert_eq!(runtime.state(), AgentState::Locked);
    assert!(runtime.unlock_epoch() > unlocked_epoch);

    let unlock_attempt = dispatch(
        &runtime,
        &client,
        3,
        &unlock("integrity failure integration password"),
        None,
    );
    assert_eq!(
        unlock_attempt.error(),
        Some(PublicErrorCode::OperationFailed),
        "a synchronized runtime must attempt unlock instead of returning conflict"
    );
    assert_eq!(runtime.state(), AgentState::Locked);
}

#[test]
fn role_authorization_precedes_operation_body_decoding() {
    let directory = TestDirectory::new();
    let runtime = AgentRuntime::start(directory.vault_path()).expect("runtime starts");
    let native_host = connection(ClientRole::NativeHost, &runtime, 17);
    let request = RequestEnvelope::new(
        OperationCode::ListAccountSummaries,
        runtime.unlock_epoch(),
        5_000,
        None,
        Zeroizing::new(vec![0xff]),
    )
    .expect("bounded opaque body");
    let header = FrameHeader::new(
        MessageKind::Request,
        CURRENT_VERSION,
        request.encode().expect("request encoding").len(),
        *native_host.connection_id(),
        1,
    )
    .expect("request header");

    let response = runtime
        .dispatch(&native_host, &header, &request, copy_response)
        .expect("unauthorized request is terminal");
    assert_eq!(
        response.error(),
        Some(PublicErrorCode::UnauthorizedOperation)
    );
}

#[test]
fn cancellation_wins_an_in_flight_password_unlock() {
    let directory = TestDirectory::new();
    let runtime = Arc::new(AgentRuntime::start(directory.vault_path()).expect("runtime starts"));
    let setup = connection(ClientRole::Desktop, &runtime, 31);
    assert_eq!(
        dispatch(
            &runtime,
            &setup,
            1,
            &create("cancellation integration password"),
            Some([3; 16]),
        )
        .error(),
        None
    );
    assert_eq!(
        dispatch(&runtime, &setup, 2, &OperationRequest::Lock, None).error(),
        None
    );

    let unlock_client = Arc::new(connection(ClientRole::Desktop, &runtime, 47));
    let connection_id = *unlock_client.connection_id();
    let operation = unlock("cancellation integration password");
    let body = operation.encode().expect("unlock body");
    let request = RequestEnvelope::new(
        OperationCode::UnlockMasterPassword,
        runtime.unlock_epoch(),
        30_000,
        None,
        body,
    )
    .expect("unlock envelope");
    let header = FrameHeader::new(
        MessageKind::Request,
        CURRENT_VERSION,
        request.encode().expect("request bytes").len(),
        connection_id,
        1,
    )
    .expect("unlock header");
    let worker_runtime = Arc::clone(&runtime);
    let worker_client = Arc::clone(&unlock_client);
    let worker = thread::spawn(move || {
        worker_runtime
            .dispatch(&worker_client, &header, &request, copy_response)
            .expect("unlock dispatch")
    });

    let wait_deadline = Instant::now() + Duration::from_secs(5);
    while runtime.state() != AgentState::Unlocking && Instant::now() < wait_deadline {
        thread::yield_now();
    }
    assert_eq!(runtime.state(), AgentState::Unlocking);
    let cancel = FrameHeader::new(MessageKind::Cancel, CURRENT_VERSION, 0, connection_id, 1)
        .expect("cancel header");
    runtime
        .apply_cancel(&unlock_client, &cancel)
        .expect("protocol cancellation");
    let response = worker.join().expect("unlock worker");
    assert_eq!(response.error(), Some(PublicErrorCode::Cancelled));
    assert_eq!(runtime.state(), AgentState::Locked);
}

#[test]
fn lock_wins_create_before_atomic_publication() {
    let directory = TestDirectory::new();
    let path = directory.vault_path();
    let runtime = Arc::new(AgentRuntime::start(&path).expect("runtime starts"));
    let create_client = connection(ClientRole::Desktop, &runtime, 51);
    let create_runtime = Arc::clone(&runtime);
    let worker = thread::spawn(move || {
        dispatch(
            &create_runtime,
            &create_client,
            1,
            &create("cancelled create integration password"),
            Some([5; 16]),
        )
    });

    let wait_deadline = Instant::now() + Duration::from_secs(5);
    while !has_staging_reservation(&directory) && Instant::now() < wait_deadline {
        thread::yield_now();
    }
    assert!(
        has_staging_reservation(&directory),
        "create must reach its private staging file before the lock race"
    );

    let lock_client = connection(ClientRole::Desktop, &runtime, 56);
    assert_eq!(
        dispatch(&runtime, &lock_client, 1, &OperationRequest::Lock, None,).error(),
        None
    );
    assert_eq!(
        worker.join().expect("create worker").error(),
        Some(PublicErrorCode::Cancelled)
    );
    assert_eq!(runtime.state(), AgentState::NoVault);
    assert!(
        !path.exists(),
        "cancelled create must never publish a vault"
    );
    assert!(
        !has_staging_reservation(&directory),
        "cancelled create must remove its private staging file"
    );
}

fn has_staging_reservation(directory: &TestDirectory) -> bool {
    fs::read_dir(&directory.0)
        .expect("read integration directory")
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .contains(".librarian-stage-")
        })
}

#[test]
fn lock_and_signout_shutdown_win_unlock_races_and_restart_locked() {
    let directory = TestDirectory::new();
    let path = directory.vault_path();
    let runtime = Arc::new(AgentRuntime::start(&path).expect("runtime starts"));
    let password = "lifecycle race integration password";
    let setup = connection(ClientRole::Desktop, &runtime, 61);
    assert_eq!(
        dispatch(&runtime, &setup, 1, &create(password), Some([6; 16]),).error(),
        None
    );
    assert_eq!(
        dispatch(&runtime, &setup, 2, &OperationRequest::Lock, None).error(),
        None
    );

    let run_unlock = |runtime: &Arc<AgentRuntime>, marker: u8| {
        let unlock_client = connection(ClientRole::Desktop, runtime, marker);
        let worker_runtime = Arc::clone(runtime);
        thread::spawn(move || dispatch(&worker_runtime, &unlock_client, 1, &unlock(password), None))
    };

    let unlock_worker = run_unlock(&runtime, 71);
    wait_for_state(&runtime, AgentState::Unlocking);
    let lock_client = connection(ClientRole::Desktop, &runtime, 81);
    assert_eq!(
        dispatch(&runtime, &lock_client, 1, &OperationRequest::Lock, None,).error(),
        None
    );
    assert_eq!(
        unlock_worker.join().expect("unlock worker").error(),
        Some(PublicErrorCode::Cancelled)
    );
    assert_eq!(runtime.state(), AgentState::Locked);

    let signout_worker = run_unlock(&runtime, 91);
    wait_for_state(&runtime, AgentState::Unlocking);
    runtime.shutdown().expect("sign-out shutdown");
    assert_eq!(
        signout_worker
            .join()
            .expect("sign-out unlock worker")
            .error(),
        Some(PublicErrorCode::Cancelled)
    );
    assert_eq!(runtime.state(), AgentState::ShuttingDown);
    drop(runtime);

    let restarted = AgentRuntime::start(&path).expect("runtime restarts");
    assert_eq!(restarted.state(), AgentState::Locked);
    let restarted_client = connection(ClientRole::Desktop, &restarted, 101);
    assert_eq!(
        dispatch(&restarted, &restarted_client, 1, &unlock(password), None,).error(),
        None
    );
    assert_eq!(restarted.state(), AgentState::Unlocked);
}

fn wait_for_state(runtime: &AgentRuntime, expected: AgentState) {
    let wait_deadline = Instant::now() + Duration::from_secs(5);
    while runtime.state() != expected && Instant::now() < wait_deadline {
        thread::yield_now();
    }
    assert_eq!(runtime.state(), expected);
}

#[test]
fn vault_path_has_exactly_one_runtime_owner() {
    let directory = TestDirectory::new();
    let path = directory.vault_path();
    let first = AgentRuntime::start(&path).expect("first runtime");
    assert_eq!(
        AgentRuntime::start(&path).err(),
        Some(RuntimeStartError::AlreadyOwned)
    );
    let dotted_alias = path
        .parent()
        .expect("vault parent")
        .join(".")
        .join("vault.sqlite3");
    assert_eq!(
        AgentRuntime::start(dotted_alias).err(),
        Some(RuntimeStartError::AlreadyOwned)
    );
    drop(first);
    AgentRuntime::start(&path).expect("ownership releases on clean shutdown");

    fs::write(&path, b"existing target identity").expect("existing target");
    let existing = AgentRuntime::start(&path).expect("existing vault path");
    let hard_link_alias = path
        .parent()
        .expect("vault parent")
        .join("vault-hard-link.sqlite3");
    fs::hard_link(&path, &hard_link_alias).expect("hard-link alias");
    assert_eq!(
        AgentRuntime::start(hard_link_alias).err(),
        Some(RuntimeStartError::AlreadyOwned),
        "filesystem aliases must not acquire a second ownership lease"
    );
    #[cfg(windows)]
    assert_eq!(
        AgentRuntime::start(path.parent().expect("vault parent").join("VAULT.SQLITE3")).err(),
        Some(RuntimeStartError::AlreadyOwned),
        "Windows-equivalent casing must not acquire a second ownership lease"
    );
    drop(existing);
}

#[test]
fn unlock_revalidates_the_authenticated_vault_ownership_lease() {
    let directory = TestDirectory::new();
    let path = directory.vault_path();
    let original = AgentRuntime::start(&path).expect("original runtime");
    let original_client = connection(ClientRole::Desktop, &original, 111);
    assert_eq!(
        dispatch(
            &original,
            &original_client,
            1,
            &create("original ownership password"),
            Some([0x71; 16]),
        )
        .error(),
        None
    );
    assert_eq!(
        dispatch(
            &original,
            &original_client,
            2,
            &OperationRequest::Lock,
            None,
        )
        .error(),
        None
    );

    let replacement_path = directory.0.join("replacement.sqlite3");
    let replacement = AgentRuntime::start(&replacement_path).expect("replacement runtime");
    let replacement_client = connection(ClientRole::Desktop, &replacement, 121);
    assert_eq!(
        dispatch(
            &replacement,
            &replacement_client,
            1,
            &create("replacement ownership password"),
            Some([0x72; 16]),
        )
        .error(),
        None
    );
    assert_eq!(
        dispatch(
            &replacement,
            &replacement_client,
            2,
            &OperationRequest::Lock,
            None,
        )
        .error(),
        None
    );
    drop(replacement);

    fs::remove_file(&path).expect("remove original pathname");
    fs::rename(&replacement_path, &path).expect("install replacement vault");
    let alias = directory.0.join("replacement-hard-link.sqlite3");
    fs::hard_link(&path, &alias).expect("replacement hard-link alias");
    let competing = AgentRuntime::start(&alias).expect("competing replacement owner");

    let unlock_client = connection(ClientRole::Desktop, &original, 131);
    let response = dispatch(
        &original,
        &unlock_client,
        1,
        &unlock("replacement ownership password"),
        None,
    );
    assert_eq!(response.error(), Some(PublicErrorCode::OperationFailed));
    assert_eq!(original.state(), AgentState::Locked);
    drop(competing);
}
