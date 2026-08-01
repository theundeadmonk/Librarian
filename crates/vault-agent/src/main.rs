//! Production process boundary for the trusted local vault agent.

#![forbid(unsafe_code)]

#[cfg(windows)]
use std::{
    env,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
    thread::{self, JoinHandle},
    time::Duration,
};

#[cfg(windows)]
use librarian_agent_protocol::{
    CURRENT_VERSION, ClientHello, Connection, ConnectionLimits, EndpointDescriptor,
    FEATURE_WINDOWS_HELLO, Frame, FrameHeader, HANDSHAKE_TIMEOUT_MS, MessageKind, RequestEnvelope,
    ResponseEnvelope,
};
#[cfg(windows)]
use librarian_vault_agent::{AgentRuntime, DispatchError};
#[cfg(windows)]
use librarian_windows_ipc::{
    ComponentRole, EndpointDescriptorStore, ListenerPool, PeerObservation, PeerPolicy,
    PipeConnection, TransportError, current_process_observation, observe_pipe_client,
};
#[cfg(windows)]
use sha2::{Digest, Sha256};
#[cfg(windows)]
use zeroize::Zeroizing;

#[cfg(windows)]
const AGENT_EXECUTABLE: &str = "Librarian.VaultAgent.exe";
#[cfg(windows)]
const DESKTOP_EXECUTABLE: &str = "Librarian.Windows.exe";
#[cfg(windows)]
const LOCAL_STATE_DIRECTORY: &str = "Librarian";
#[cfg(windows)]
const ENDPOINT_FILE: &str = "agent-endpoint-v1.cbor";
#[cfg(windows)]
const VAULT_FILE: &str = "vault.db";
#[cfg(windows)]
const WINDOWS_HELLO_STATE_FILE: &str = "windows-hello-state.bin";
#[cfg(windows)]
const MEDIUM_INTEGRITY_RID: u32 = 0x2000;
#[cfg(windows)]
const ACCEPT_TIMEOUT: Duration = Duration::from_millis(250);
#[cfg(windows)]
const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(125);
#[cfg(windows)]
const FRAME_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(windows)]
#[derive(Clone, Copy, Debug)]
enum HostError {
    Identity,
    LocalState,
    Runtime,
    Discovery,
    Transport,
}

#[cfg(windows)]
struct HostPaths {
    vault: PathBuf,
    windows_hello_state: PathBuf,
    endpoint: PathBuf,
}

#[cfg(windows)]
struct PublishedEndpoint<'a> {
    store: &'a EndpointDescriptorStore,
}

#[cfg(windows)]
impl Drop for PublishedEndpoint<'_> {
    fn drop(&mut self) {
        let _ = self.store.remove();
    }
}

#[cfg(windows)]
fn main() {
    if run().is_err() {
        eprintln!("Librarian vault agent could not start securely.");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Librarian vault agent is available only on Windows.");
    std::process::exit(1);
}

#[cfg(windows)]
fn run() -> Result<(), HostError> {
    let current = current_process_observation().map_err(|_| HostError::Identity)?;
    let observation = current.observation();
    let (package_full_name, package_family_name, install_root) = validate_agent(observation)?;
    let paths = local_state_paths(package_family_name)?;
    let runtime = Arc::new(
        AgentRuntime::start_with_windows_hello(&paths.vault, &paths.windows_hello_state)
            .map_err(|_| HostError::Runtime)?,
    );
    let policies = vec![desktop_policy(
        observation,
        package_full_name,
        package_family_name,
        &install_root,
    )];
    let store = EndpointDescriptorStore::new(&paths.endpoint).map_err(|_| HostError::Discovery)?;
    let (recycle_tx, recycle_rx) = mpsc::channel();
    let mut workers = Vec::new();
    let mut pool = publish_listener_pool(&store, observation, package_full_name)?;
    let _published = PublishedEndpoint { store: &store };

    loop {
        reap_finished(&mut workers);
        drain_recycled(&mut pool, &recycle_rx)?;
        if pool.available_listeners() == 0 {
            if workers.is_empty() {
                store.remove().map_err(|_| HostError::Discovery)?;
                drop(pool);
                pool = publish_listener_pool(&store, observation, package_full_name)?;
                continue;
            }
            thread::sleep(Duration::from_millis(25));
            continue;
        }
        match pool.accept(&policies, ACCEPT_TIMEOUT) {
            Ok(pipe) => {
                let worker_runtime = Arc::clone(&runtime);
                let worker_recycle = recycle_tx.clone();
                workers.push(thread::spawn(move || {
                    let pipe = serve_connection(&worker_runtime, pipe);
                    if let Some(pipe) = pipe {
                        let _ = worker_recycle.send(pipe);
                    }
                }));
            }
            Err(
                TransportError::Timeout
                | TransportError::AccessDenied
                | TransportError::PeerExited
                | TransportError::Unavailable,
            ) => {}
            Err(TransportError::ResourceLimit) => thread::sleep(Duration::from_millis(25)),
            Err(TransportError::ListenerLost) => {
                store.remove().map_err(|_| HostError::Discovery)?;
                drop(pool);
                pool = publish_listener_pool(&store, observation, package_full_name)?;
            }
            Err(TransportError::MalformedFrame | TransportError::Internal) => {
                return Err(HostError::Transport);
            }
        }
    }
}

#[cfg(windows)]
fn validate_agent(observation: &PeerObservation) -> Result<(&str, &str, PathBuf), HostError> {
    let package_full_name = observation
        .package_full_name
        .as_deref()
        .ok_or(HostError::Identity)?;
    let package_family_name = observation
        .package_family_name
        .as_deref()
        .ok_or(HostError::Identity)?;
    let expected_application = format!("{package_family_name}!VaultAgent");
    let valid_image = observation
        .image_path
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case(AGENT_EXECUTABLE));
    if observation.elevated
        || observation.app_container
        || observation.integrity_rid != MEDIUM_INTEGRITY_RID
        || observation.application_user_model_id.as_deref() != Some(&expected_application)
        || !valid_image
    {
        return Err(HostError::Identity);
    }
    let install_root = observation
        .image_path
        .parent()
        .ok_or(HostError::Identity)?
        .to_path_buf();
    Ok((package_full_name, package_family_name, install_root))
}

#[cfg(windows)]
fn local_state_paths(package_family_name: &str) -> Result<HostPaths, HostError> {
    let local_app_data = env::var_os("LOCALAPPDATA").ok_or(HostError::LocalState)?;
    let local_state = PathBuf::from(local_app_data)
        .join("Packages")
        .join(package_family_name)
        .join("LocalState");
    if !local_state.is_absolute()
        || !fs::metadata(&local_state).is_ok_and(|metadata| metadata.is_dir())
    {
        return Err(HostError::LocalState);
    }
    let root = local_state.join(LOCAL_STATE_DIRECTORY);
    match fs::create_dir(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(HostError::LocalState),
    }
    if !fs::symlink_metadata(&root).is_ok_and(|metadata| metadata.is_dir()) {
        return Err(HostError::LocalState);
    }
    Ok(HostPaths {
        vault: root.join(VAULT_FILE),
        windows_hello_state: root.join(WINDOWS_HELLO_STATE_FILE),
        endpoint: root.join(ENDPOINT_FILE),
    })
}

#[cfg(windows)]
fn desktop_policy(
    current: &PeerObservation,
    package_full_name: &str,
    package_family_name: &str,
    install_root: &Path,
) -> PeerPolicy {
    PeerPolicy {
        role: ComponentRole::Desktop,
        session_id: current.session_id,
        user_sid: current.user_sid.clone(),
        logon_sid: current.logon_sid.clone(),
        maximum_integrity_rid: MEDIUM_INTEGRITY_RID,
        image_path: install_root.join(DESKTOP_EXECUTABLE),
        package_full_name: package_full_name.to_owned(),
        package_family_name: package_family_name.to_owned(),
        application_user_model_id: Some(format!("{package_family_name}!Desktop")),
    }
}

#[cfg(windows)]
fn publish_listener_pool(
    store: &EndpointDescriptorStore,
    observation: &PeerObservation,
    package_full_name: &str,
) -> Result<ListenerPool, HostError> {
    let pool = ListenerPool::create().map_err(|_| HostError::Transport)?;
    let mut startup_nonce = [0_u8; 32];
    getrandom::fill(&mut startup_nonce).map_err(|_| HostError::Transport)?;
    let descriptor = EndpointDescriptor::new(
        pool.pipe_name().to_owned(),
        observation.process_id,
        observation.process_creation_time,
        package_full_name.to_owned(),
        CURRENT_VERSION.major(),
        CURRENT_VERSION.major(),
        startup_nonce,
    )
    .map_err(|_| HostError::Discovery)?;
    store
        .publish(&descriptor)
        .map_err(|_| HostError::Discovery)?;
    Ok(pool)
}

#[cfg(windows)]
fn drain_recycled(
    pool: &mut ListenerPool,
    recycle_rx: &mpsc::Receiver<PipeConnection>,
) -> Result<(), HostError> {
    while let Ok(connection) = recycle_rx.try_recv() {
        pool.recycle(connection).map_err(|_| HostError::Transport)?;
    }
    Ok(())
}

#[cfg(windows)]
fn reap_finished(workers: &mut Vec<JoinHandle<()>>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            let _ = worker.join();
        } else {
            index += 1;
        }
    }
}

#[cfg(windows)]
fn serve_connection(runtime: &Arc<AgentRuntime>, pipe: PipeConnection) -> Option<PipeConnection> {
    let Some(connection) = negotiate_connection(runtime, &pipe) else {
        return Some(pipe);
    };
    let pipe = Arc::new(pipe);
    let connection = Arc::new(connection);
    serve_frames(runtime, &pipe, &connection);
    drop(connection);
    Arc::try_unwrap(pipe).ok()
}

#[cfg(windows)]
fn negotiate_connection(runtime: &AgentRuntime, pipe: &PipeConnection) -> Option<Connection> {
    let client = observe_pipe_client(pipe).ok()?.observation();
    let role = pipe.component_role().client_role()?;
    let expected_build_id = sha256_file(&client.image_path).ok()?;
    let hello_frame = pipe
        .read_frame(Duration::from_millis(u64::from(HANDSHAKE_TIMEOUT_MS)))
        .ok()?;
    if hello_frame.header().kind() != MessageKind::ClientHello {
        return None;
    }
    let hello = ClientHello::decode(hello_frame.payload()).ok()?;
    let mut server_nonce = [0_u8; 32];
    let mut connection_id = [0_u8; 16];
    getrandom::fill(&mut server_nonce).ok()?;
    getrandom::fill(&mut connection_id).ok()?;
    let (state, unlock_epoch) = runtime.status_snapshot().ok()?;
    let supported_features = if role == librarian_agent_protocol::ClientRole::Desktop {
        &[FEATURE_WINDOWS_HELLO][..]
    } else {
        &[]
    };
    let (connection, server_hello) = Connection::negotiate(
        role,
        client.process_id,
        expected_build_id,
        &hello,
        supported_features,
        server_nonce,
        connection_id,
        state,
        unlock_epoch,
        ConnectionLimits::default(),
    )
    .ok()?;
    let hello_payload = Zeroizing::new(server_hello.encode());
    let hello_header = FrameHeader::new(
        MessageKind::ServerHello,
        server_hello.selected_version(),
        hello_payload.len(),
        connection_id,
        0,
    )
    .ok()?;
    let hello_response = Frame::new(hello_header, hello_payload).ok()?;
    pipe.write_frame(&hello_response, FRAME_WRITE_TIMEOUT)
        .ok()?;
    Some(connection)
}

#[cfg(windows)]
fn serve_frames(
    runtime: &Arc<AgentRuntime>,
    pipe: &Arc<PipeConnection>,
    connection: &Arc<Connection>,
) {
    let mut workers = Vec::new();
    loop {
        reap_finished(&mut workers);
        let Ok(frame) = pipe.read_frame(FRAME_READ_TIMEOUT) else {
            break;
        };
        let (header, payload) = frame.into_parts();
        match header.kind() {
            MessageKind::Cancel => {
                if runtime.apply_cancel(connection, &header).is_err() {
                    break;
                }
            }
            MessageKind::Request => {
                let Ok(envelope) = RequestEnvelope::decode(&payload) else {
                    break;
                };
                let worker_runtime = Arc::clone(runtime);
                let worker_pipe = Arc::clone(pipe);
                let worker_connection = Arc::clone(connection);
                let (admission_tx, admission_rx) = mpsc::sync_channel(1);
                workers.push(thread::spawn(move || {
                    let callback_tx = admission_tx.clone();
                    let result = worker_runtime.dispatch_with_admission(
                        &worker_connection,
                        &header,
                        &envelope,
                        move || {
                            let _ = callback_tx.send(true);
                        },
                        |response| {
                            write_response(
                                &worker_pipe,
                                &worker_connection,
                                header.request_id(),
                                response,
                            )
                        },
                    );
                    if result.is_err() {
                        let _ = admission_tx.send(false);
                    }
                }));
                if admission_rx.recv_timeout(Duration::from_millis(u64::from(HANDSHAKE_TIMEOUT_MS)))
                    != Ok(true)
                {
                    break;
                }
            }
            MessageKind::ClientHello
            | MessageKind::ServerHello
            | MessageKind::Response
            | MessageKind::Event => break,
        }
    }
    let _ = runtime.disconnect(connection);
    for worker in workers {
        let _ = worker.join();
    }
}

#[cfg(windows)]
fn write_response(
    pipe: &PipeConnection,
    connection: &Connection,
    request_id: u64,
    response: &ResponseEnvelope,
) -> Result<(), DispatchError> {
    let payload = response.encode().map_err(|_| DispatchError::Internal)?;
    let header = FrameHeader::new(
        MessageKind::Response,
        connection.version(),
        payload.len(),
        *connection.connection_id(),
        request_id,
    )
    .map_err(|_| DispatchError::Internal)?;
    let frame = Frame::new(header, payload).map_err(|_| DispatchError::Internal)?;
    pipe.write_frame(&frame, FRAME_WRITE_TIMEOUT)
        .map_err(|_| DispatchError::Internal)
}

#[cfg(windows)]
fn sha256_file(path: &Path) -> Result<[u8; 32], HostError> {
    let mut file = File::open(path).map_err(|_| HostError::Identity)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| HostError::Identity)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}
