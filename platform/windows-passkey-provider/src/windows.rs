use std::{
    ffi::c_void,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    ptr,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use librarian_agent_protocol::{
    AgentState, CURRENT_VERSION, ClientHello, ClientRole, FEATURE_PASSKEY_PROVIDER, Frame,
    FrameHeader, MessageKind, OperationRequest, PASSKEY_TIMEOUT_MS, PasskeyAssertionView,
    PasskeyCredentialView, PasskeyRequestProof, PasskeySummaryView, PasskeyTransactionProof,
    PublicErrorCode, RequestEnvelope, ResponseEnvelope, ServerHello, Version,
    encode_passkey_assertion, encode_passkey_credential, encode_passkey_summaries,
};
use librarian_windows_ipc::{
    ComponentRole, EndpointDescriptorStore, PeerObservation, PeerPolicy, PipeConnection,
    current_process_observation,
};
use minicbor::Decoder;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const PROVIDER_EXECUTABLE: &str = "Librarian.PasskeyProvider.exe";
const AGENT_EXECUTABLE: &str = "Librarian.VaultAgent.exe";
const LOCAL_STATE_DIRECTORY: &str = "Librarian";
const ENDPOINT_FILE: &str = "agent-endpoint-v1.cbor";
const MEDIUM_INTEGRITY_RID: u32 = 0x2000;
const PIPE_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const FRAME_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(125);
const CANCELLATION_POLL: Duration = Duration::from_millis(25);
const CREDENTIAL_ID_BYTES: usize = 32;
const USER_HANDLE_CAPACITY: usize = 64;
const USER_NAME_CAPACITY: usize = 256;
const PUBLIC_KEY_BYTES: usize = 65;
const AUTHENTICATOR_DATA_BYTES: usize = 37;
const SIGNATURE_CAPACITY: usize = 80;
const MAX_SUMMARIES: usize = 64;
const CALLBACK_SUCCESS: u32 = 0;
const CALLBACK_FAILED: u32 = PublicErrorCode::OperationFailed as u32;

#[derive(Clone, Copy, Debug)]
pub(crate) enum ProviderError {
    Identity,
    Discovery,
    Transport,
    Protocol,
    Native,
    NotRegistered,
}

impl ProviderError {
    pub(crate) const fn process_exit_code(self) -> i32 {
        match self {
            Self::Identity | Self::Protocol => PublicErrorCode::Incompatible as i32,
            Self::Discovery | Self::Transport => PublicErrorCode::AgentUnavailable as i32,
            Self::Native => PublicErrorCode::OperationFailed as i32,
            Self::NotRegistered => PublicErrorCode::NotFound as i32,
        }
    }
}

struct ProviderContext {
    endpoint: EndpointDescriptorStore,
    agent_policy: PeerPolicy,
    package_full_name: String,
    build_id: [u8; 32],
    prepared: Mutex<Option<PreparedSession>>,
}

struct PreparedSession {
    transaction_id: [u8; 16],
    session: AgentSession,
}

struct AgentSession {
    pipe: Arc<PipeConnection>,
    version: Version,
    connection_id: [u8; 16],
    unlock_epoch: u64,
    state: AgentState,
    next_request_id: u64,
}

#[repr(C)]
struct NativeRequest {
    parent_window: usize,
    transaction_id: *const u8,
    request_type: u32,
    request_signature: *const u8,
    request_signature_bytes: u32,
    encoded_request: *const u8,
    encoded_request_bytes: u32,
    agent_challenge: *const u8,
    agent_challenge_bytes: u32,
    user_verification_signature: *const u8,
    user_verification_signature_bytes: u32,
}

#[repr(C)]
struct NativeSummary {
    credential_id: [u8; CREDENTIAL_ID_BYTES],
    user_handle: [u8; USER_HANDLE_CAPACITY],
    user_handle_bytes: u32,
    user_name: [u8; USER_NAME_CAPACITY],
    user_name_bytes: u32,
    user_display_name: [u8; USER_NAME_CAPACITY],
    user_display_name_bytes: u32,
}

impl Default for NativeSummary {
    fn default() -> Self {
        Self {
            credential_id: [0; CREDENTIAL_ID_BYTES],
            user_handle: [0; USER_HANDLE_CAPACITY],
            user_handle_bytes: 0,
            user_name: [0; USER_NAME_CAPACITY],
            user_name_bytes: 0,
            user_display_name: [0; USER_NAME_CAPACITY],
            user_display_name_bytes: 0,
        }
    }
}

#[repr(C)]
struct NativeCredential {
    credential_id: [u8; CREDENTIAL_ID_BYTES],
    user_handle: [u8; USER_HANDLE_CAPACITY],
    user_handle_bytes: u32,
    public_key: [u8; PUBLIC_KEY_BYTES],
}

impl Default for NativeCredential {
    fn default() -> Self {
        Self {
            credential_id: [0; CREDENTIAL_ID_BYTES],
            user_handle: [0; USER_HANDLE_CAPACITY],
            user_handle_bytes: 0,
            public_key: [0; PUBLIC_KEY_BYTES],
        }
    }
}

#[repr(C)]
struct NativeAssertion {
    credential_id: [u8; CREDENTIAL_ID_BYTES],
    user_handle: [u8; USER_HANDLE_CAPACITY],
    user_handle_bytes: u32,
    authenticator_data: [u8; AUTHENTICATOR_DATA_BYTES],
    signature: [u8; SIGNATURE_CAPACITY],
    signature_bytes: u32,
}

impl Default for NativeAssertion {
    fn default() -> Self {
        Self {
            credential_id: [0; CREDENTIAL_ID_BYTES],
            user_handle: [0; USER_HANDLE_CAPACITY],
            user_handle_bytes: 0,
            authenticator_data: [0; AUTHENTICATOR_DATA_BYTES],
            signature: [0; SIGNATURE_CAPACITY],
            signature_bytes: 0,
        }
    }
}

type StatusCallback = unsafe extern "C" fn(*mut c_void, *mut u32) -> u32;
type PrepareCallback = unsafe extern "C" fn(*mut c_void, *const u8, u32, *mut u8, u32) -> u32;
type DiscardCallback = unsafe extern "C" fn(*mut c_void, *const u8, u32);
type ListCallback = unsafe extern "C" fn(
    *mut c_void,
    *const NativeRequest,
    *mut NativeSummary,
    u32,
    *mut u32,
) -> u32;
type MakeCallback =
    unsafe extern "C" fn(*mut c_void, *const NativeRequest, *mut NativeCredential) -> u32;
type RollbackMakeCallback =
    unsafe extern "C" fn(*mut c_void, *const NativeRequest, *const u8, u32) -> u32;
type AssertionCallback = unsafe extern "C" fn(
    *mut c_void,
    *const NativeRequest,
    *const u8,
    u32,
    *mut NativeAssertion,
) -> u32;
#[repr(C)]
struct NativeCallbacks {
    context: *mut c_void,
    status: StatusCallback,
    prepare: PrepareCallback,
    discard: DiscardCallback,
    list: ListCallback,
    make: MakeCallback,
    rollback_make: RollbackMakeCallback,
    get_assertion: AssertionCallback,
}

unsafe extern "C" {
    fn librarian_windows_passkey_provider_run(callbacks: *const NativeCallbacks) -> u32;
    fn librarian_windows_passkey_provider_register() -> u32;
    fn librarian_windows_passkey_provider_unregister() -> u32;
    fn librarian_windows_passkey_provider_registration_state(registered: *mut u32) -> u32;
    fn librarian_windows_passkey_provider_request_cancelled(
        transaction_id: *const u8,
        transaction_id_bytes: u32,
    ) -> u32;
}

pub(crate) fn register() -> Result<(), ProviderError> {
    validate_current_provider_identity()?;
    // SAFETY: the registration bridge takes no pointers and returns an HRESULT.
    let result = unsafe { librarian_windows_passkey_provider_register() };
    native_result(result)
}

pub(crate) fn unregister() -> Result<(), ProviderError> {
    validate_current_provider_identity()?;
    // SAFETY: the registration bridge takes no pointers and returns an HRESULT.
    let result = unsafe { librarian_windows_passkey_provider_unregister() };
    native_result(result)
}

pub(crate) fn require_registered() -> Result<(), ProviderError> {
    validate_current_provider_identity()?;
    let mut registered = 0_u32;
    // SAFETY: the bridge receives one valid writable scalar.
    let result =
        unsafe { librarian_windows_passkey_provider_registration_state(&raw mut registered) };
    native_result(result)?;
    (registered == 1)
        .then_some(())
        .ok_or(ProviderError::NotRegistered)
}

pub(crate) fn run() -> Result<(), ProviderError> {
    let mut context = ProviderContext::new()?;
    let callbacks = NativeCallbacks {
        context: ptr::from_mut(&mut context).cast::<c_void>(),
        status: status_callback,
        prepare: prepare_callback,
        discard: discard_callback,
        list: list_callback,
        make: make_callback,
        rollback_make: rollback_make_callback,
        get_assertion: assertion_callback,
    };
    // SAFETY: `callbacks` and its context remain live until the synchronous
    // native local-server loop returns. Every callback validates pointers and
    // catches panics before crossing the ABI.
    let result = unsafe { librarian_windows_passkey_provider_run(&raw const callbacks) };
    native_result(result)
}

fn native_result(result: u32) -> Result<(), ProviderError> {
    (result == 0).then_some(()).ok_or(ProviderError::Native)
}

fn validate_current_provider_identity() -> Result<(), ProviderError> {
    let current = current_process_observation().map_err(|_| ProviderError::Identity)?;
    validate_provider(current.observation())?;
    Ok(())
}

impl ProviderContext {
    fn new() -> Result<Self, ProviderError> {
        let current = current_process_observation().map_err(|_| ProviderError::Identity)?;
        let observation = current.observation();
        let (package_full_name, package_family_name, install_root) =
            validate_provider(observation)?;
        let endpoint_path = local_endpoint_path(package_family_name)?;
        let endpoint =
            EndpointDescriptorStore::new(endpoint_path).map_err(|_| ProviderError::Discovery)?;
        let build_id = sha256_file(&observation.image_path)?;
        let agent_policy = PeerPolicy {
            role: ComponentRole::Agent,
            session_id: observation.session_id,
            user_sid: observation.user_sid.clone(),
            logon_sid: observation.logon_sid.clone(),
            maximum_integrity_rid: MEDIUM_INTEGRITY_RID,
            image_path: install_root.join(AGENT_EXECUTABLE),
            package_full_name: package_full_name.to_owned(),
            package_family_name: package_family_name.to_owned(),
            application_user_model_id: Some(format!("{package_family_name}!VaultAgent")),
        };
        Ok(Self {
            endpoint,
            agent_policy,
            package_full_name: package_full_name.to_owned(),
            build_id,
            prepared: Mutex::new(None),
        })
    }

    fn connect(&self) -> Result<AgentSession, ProviderError> {
        let descriptor = self.endpoint.load().map_err(|_| ProviderError::Discovery)?;
        if descriptor.package_full_name() != self.package_full_name
            || descriptor.minimum_major() > CURRENT_VERSION.major()
            || descriptor.maximum_major() < CURRENT_VERSION.major()
        {
            return Err(ProviderError::Identity);
        }
        let pipe = Arc::new(
            PipeConnection::connect(
                descriptor.pipe_name(),
                descriptor.agent_process_id(),
                descriptor.agent_process_creation_time(),
                &self.agent_policy,
                PIPE_CONNECT_TIMEOUT,
            )
            .map_err(|_| ProviderError::Transport)?,
        );
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| ProviderError::Transport)?;
        let hello = ClientHello::new(
            nonce,
            CURRENT_VERSION,
            CURRENT_VERSION,
            ClientRole::PasskeyProvider,
            self.build_id,
            vec![FEATURE_PASSKEY_PROVIDER],
        )
        .map_err(|_| ProviderError::Protocol)?;
        let payload = Zeroizing::new(hello.encode());
        let header = FrameHeader::new(
            MessageKind::ClientHello,
            Version::new(0, 0),
            payload.len(),
            [0; 16],
            0,
        )
        .map_err(|_| ProviderError::Protocol)?;
        pipe.write_frame(
            &Frame::new(header, payload).map_err(|_| ProviderError::Protocol)?,
            FRAME_WRITE_TIMEOUT,
        )
        .map_err(|_| ProviderError::Transport)?;
        let frame = pipe
            .read_frame(PIPE_CONNECT_TIMEOUT)
            .map_err(|_| ProviderError::Transport)?;
        if frame.header().kind() != MessageKind::ServerHello {
            return Err(ProviderError::Protocol);
        }
        let server = ServerHello::decode(frame.payload()).map_err(|_| ProviderError::Protocol)?;
        if server.selected_version() != CURRENT_VERSION
            || frame.header().version() != CURRENT_VERSION
            || server.derived_role() != ClientRole::PasskeyProvider
            || server.granted_features() != [FEATURE_PASSKEY_PROVIDER]
            || frame.header().connection_id() == &[0; 16]
        {
            return Err(ProviderError::Protocol);
        }
        Ok(AgentSession {
            pipe,
            version: server.selected_version(),
            connection_id: *frame.header().connection_id(),
            unlock_epoch: server.unlock_epoch(),
            state: server.agent_state(),
            next_request_id: 1,
        })
    }

    fn execute(
        &self,
        operation: &OperationRequest,
        transaction_id: Option<&[u8; 16]>,
    ) -> Result<ResponseEnvelope, ProviderError> {
        self.connect()?.execute(operation, transaction_id)
    }

    fn prepare(&self, transaction_id: [u8; 16]) -> Result<[u8; 16], ProviderError> {
        let session = self.connect()?;
        let challenge = session.connection_id;
        let mut prepared = self.prepared.lock().map_err(|_| ProviderError::Protocol)?;
        *prepared = Some(PreparedSession {
            transaction_id,
            session,
        });
        Ok(challenge)
    }

    fn take_prepared(
        &self,
        transaction_id: &[u8; 16],
        challenge: &[u8; 16],
    ) -> Result<AgentSession, ProviderError> {
        let mut prepared = self.prepared.lock().map_err(|_| ProviderError::Protocol)?;
        let prepared = prepared.take().ok_or(ProviderError::Protocol)?;
        if &prepared.transaction_id != transaction_id
            || &prepared.session.connection_id != challenge
        {
            return Err(ProviderError::Protocol);
        }
        Ok(prepared.session)
    }

    fn restore_prepared(
        &self,
        transaction_id: [u8; 16],
        session: AgentSession,
    ) -> Result<(), ProviderError> {
        let mut prepared = self.prepared.lock().map_err(|_| ProviderError::Protocol)?;
        if prepared.is_some() {
            return Err(ProviderError::Protocol);
        }
        *prepared = Some(PreparedSession {
            transaction_id,
            session,
        });
        Ok(())
    }

    fn discard(&self, transaction_id: &[u8; 16]) {
        if let Ok(mut prepared) = self.prepared.lock()
            && prepared
                .as_ref()
                .is_some_and(|value| &value.transaction_id == transaction_id)
        {
            prepared.take();
        }
    }
}

impl AgentSession {
    fn execute(
        &mut self,
        operation: &OperationRequest,
        transaction_id: Option<&[u8; 16]>,
    ) -> Result<ResponseEnvelope, ProviderError> {
        let request_id = self.next_request_id;
        let body = operation.encode().map_err(|_| ProviderError::Protocol)?;
        let mut idempotency_key = None;
        if operation.operation().requires_idempotency_key() {
            let mut value = [0_u8; 16];
            getrandom::fill(&mut value).map_err(|_| ProviderError::Transport)?;
            if value == [0; 16] {
                return Err(ProviderError::Transport);
            }
            idempotency_key = Some(value);
        }
        let envelope = RequestEnvelope::new(
            operation.operation(),
            self.unlock_epoch,
            PASSKEY_TIMEOUT_MS,
            idempotency_key,
            body,
        )
        .map_err(|_| ProviderError::Protocol)?;
        let payload = envelope.encode().map_err(|_| ProviderError::Protocol)?;
        let header = FrameHeader::new(
            MessageKind::Request,
            self.version,
            payload.len(),
            self.connection_id,
            request_id,
        )
        .map_err(|_| ProviderError::Protocol)?;
        self.pipe
            .write_frame(
                &Frame::new(header, payload).map_err(|_| ProviderError::Protocol)?,
                FRAME_WRITE_TIMEOUT,
            )
            .map_err(|_| ProviderError::Transport)?;
        let pipe = Arc::clone(&self.pipe);
        let frame = thread::scope(|scope| {
            let reader = scope.spawn(move || pipe.read_frame(FRAME_READ_TIMEOUT));
            let mut cancel_sent = false;
            while !reader.is_finished() {
                if !cancel_sent && transaction_id.is_some_and(request_cancelled) {
                    let cancel_header = FrameHeader::new(
                        MessageKind::Cancel,
                        self.version,
                        0,
                        self.connection_id,
                        request_id,
                    )
                    .map_err(|_| ProviderError::Protocol)?;
                    self.pipe
                        .write_frame(
                            &Frame::new(cancel_header, Zeroizing::new(Vec::new()))
                                .map_err(|_| ProviderError::Protocol)?,
                            FRAME_WRITE_TIMEOUT,
                        )
                        .map_err(|_| ProviderError::Transport)?;
                    cancel_sent = true;
                }
                thread::sleep(CANCELLATION_POLL);
            }
            reader
                .join()
                .map_err(|_| ProviderError::Transport)?
                .map_err(|_| ProviderError::Transport)
        })?;
        if frame.header().kind() != MessageKind::Response
            || frame.header().version() != self.version
            || frame.header().connection_id() != &self.connection_id
            || frame.header().request_id() != request_id
        {
            return Err(ProviderError::Protocol);
        }
        let response =
            ResponseEnvelope::decode(frame.payload()).map_err(|_| ProviderError::Protocol)?;
        self.next_request_id = request_id.checked_add(1).ok_or(ProviderError::Protocol)?;
        Ok(response)
    }
}

fn validate_provider(
    observation: &PeerObservation,
) -> Result<(&str, &str, PathBuf), ProviderError> {
    let package_full_name = observation
        .package_full_name
        .as_deref()
        .ok_or(ProviderError::Identity)?;
    let package_family_name = observation
        .package_family_name
        .as_deref()
        .ok_or(ProviderError::Identity)?;
    let valid_image = observation
        .image_path
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case(PROVIDER_EXECUTABLE));
    if observation.elevated
        || observation.app_container
        || observation.integrity_rid != MEDIUM_INTEGRITY_RID
        || observation.application_user_model_id.as_deref()
            != Some(format!("{package_family_name}!PasskeyProvider").as_str())
        || !valid_image
    {
        return Err(ProviderError::Identity);
    }
    let install_root = observation
        .image_path
        .parent()
        .ok_or(ProviderError::Identity)?
        .to_path_buf();
    Ok((package_full_name, package_family_name, install_root))
}

fn local_endpoint_path(package_family_name: &str) -> Result<PathBuf, ProviderError> {
    let local_app_data = std::env::var_os("LOCALAPPDATA").ok_or(ProviderError::Discovery)?;
    let local_state = PathBuf::from(local_app_data)
        .join("Packages")
        .join(package_family_name)
        .join("LocalState")
        .join(LOCAL_STATE_DIRECTORY);
    if !local_state.is_absolute()
        || !std::fs::symlink_metadata(&local_state).is_ok_and(|metadata| metadata.is_dir())
    {
        return Err(ProviderError::Discovery);
    }
    Ok(local_state.join(ENDPOINT_FILE))
}

fn sha256_file(path: &Path) -> Result<[u8; 32], ProviderError> {
    let mut file = File::open(path).map_err(|_| ProviderError::Identity)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| ProviderError::Identity)?;
        if read == 0 {
            return Ok(hasher.finalize().into());
        }
        hasher.update(&buffer[..read]);
    }
}

unsafe extern "C" fn status_callback(context: *mut c_void, unlocked: *mut u32) -> u32 {
    ffi_result(|| {
        let context = unsafe { context_ref(context)? };
        if unlocked.is_null() {
            return Err(CALLBACK_FAILED);
        }
        let session = context.connect().map_err(map_provider_error)?;
        // SAFETY: the native bridge supplied one writable `u32`.
        unsafe {
            unlocked.write(u32::from(session.state == AgentState::Unlocked));
        }
        Ok(())
    })
}

unsafe extern "C" fn prepare_callback(
    context: *mut c_void,
    transaction_id: *const u8,
    transaction_id_bytes: u32,
    challenge: *mut u8,
    challenge_bytes: u32,
) -> u32 {
    ffi_result(|| {
        let context = unsafe { context_ref(context)? };
        if challenge.is_null() {
            return Err(CALLBACK_FAILED);
        }
        let transaction_id = fixed_input::<16>(transaction_id, transaction_id_bytes)?;
        let prepared = context
            .prepare(transaction_id)
            .map_err(map_provider_error)?;
        if usize::try_from(challenge_bytes).map_err(|_| CALLBACK_FAILED)? != prepared.len() {
            context.discard(&transaction_id);
            return Err(CALLBACK_FAILED);
        }
        // SAFETY: the bridge supplied a writable fixed-size challenge buffer.
        unsafe {
            challenge.copy_from_nonoverlapping(prepared.as_ptr(), prepared.len());
        }
        Ok(())
    })
}

unsafe extern "C" fn discard_callback(
    context: *mut c_void,
    transaction_id: *const u8,
    transaction_id_bytes: u32,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let Some(context) = (unsafe { context.cast::<ProviderContext>().as_ref() }) else {
            return;
        };
        let Ok(transaction_id) = fixed_input::<16>(transaction_id, transaction_id_bytes) else {
            return;
        };
        context.discard(&transaction_id);
    }));
}

unsafe extern "C" fn list_callback(
    context: *mut c_void,
    request: *const NativeRequest,
    summaries: *mut NativeSummary,
    summary_capacity: u32,
    summary_count: *mut u32,
) -> u32 {
    ffi_result(|| {
        let context = unsafe { context_ref(context)? };
        if summaries.is_null() || summary_count.is_null() {
            return Err(CALLBACK_FAILED);
        }
        let request = unsafe { request_ref(request)? };
        let proof = request.request_proof()?;
        let transaction_id = *proof.transaction_id();
        let operation = OperationRequest::ListPasskeysForAssertion { proof };
        let response = context
            .execute(&operation, Some(&transaction_id))
            .map_err(map_provider_error)?;
        response_success(&response)?;
        let decoded = decode_summaries(response.body())?;
        if decoded.len() > usize::try_from(summary_capacity).map_err(|_| CALLBACK_FAILED)? {
            return Err(CALLBACK_FAILED);
        }
        for (index, summary) in decoded.iter().enumerate() {
            // SAFETY: capacity was supplied by the native allocation and the
            // decoded count is bounded above by that capacity.
            unsafe {
                summaries.add(index).write(summary.to_native()?);
            }
        }
        // SAFETY: the bridge supplied one writable `u32`.
        unsafe {
            summary_count.write(u32::try_from(decoded.len()).map_err(|_| CALLBACK_FAILED)?);
        }
        Ok(())
    })
}

unsafe extern "C" fn make_callback(
    context: *mut c_void,
    request: *const NativeRequest,
    credential: *mut NativeCredential,
) -> u32 {
    ffi_result(|| {
        let context = unsafe { context_ref(context)? };
        if credential.is_null() {
            return Err(CALLBACK_FAILED);
        }
        let request = unsafe { request_ref(request)? };
        let proof = request.transaction_proof()?;
        let transaction_id = *proof.transaction_id();
        let mut session = context
            .take_prepared(proof.transaction_id(), proof.agent_challenge())
            .map_err(map_provider_error)?;
        let response = session
            .execute(
                &OperationRequest::MakePasskey { proof },
                Some(&transaction_id),
            )
            .map_err(map_provider_error)?;
        response_success(&response)?;
        context
            .restore_prepared(transaction_id, session)
            .map_err(map_provider_error)?;
        let decoded = decode_credential(response.body())?;
        // SAFETY: the bridge supplied one writable result structure.
        unsafe {
            credential.write(decoded);
        }
        Ok(())
    })
}

unsafe extern "C" fn rollback_make_callback(
    context: *mut c_void,
    request: *const NativeRequest,
    credential_id: *const u8,
    credential_id_bytes: u32,
) -> u32 {
    ffi_result(|| {
        let context = unsafe { context_ref(context)? };
        let request = unsafe { request_ref(request)? };
        let proof = request.transaction_proof()?;
        let credential_id = fixed_input::<CREDENTIAL_ID_BYTES>(credential_id, credential_id_bytes)?;
        let mut session = context
            .take_prepared(proof.transaction_id(), proof.agent_challenge())
            .map_err(map_provider_error)?;
        let response = session
            .execute(
                &OperationRequest::RollbackPasskeyCreation {
                    proof,
                    credential_id,
                },
                None,
            )
            .map_err(map_provider_error)?;
        response_success(&response)
    })
}

unsafe extern "C" fn assertion_callback(
    context: *mut c_void,
    request: *const NativeRequest,
    credential_id: *const u8,
    credential_id_bytes: u32,
    assertion: *mut NativeAssertion,
) -> u32 {
    ffi_result(|| {
        let context = unsafe { context_ref(context)? };
        if assertion.is_null()
            || credential_id.is_null()
            || usize::try_from(credential_id_bytes).map_err(|_| CALLBACK_FAILED)?
                != CREDENTIAL_ID_BYTES
        {
            return Err(CALLBACK_FAILED);
        }
        let request = unsafe { request_ref(request)? };
        let proof = request.transaction_proof()?;
        let transaction_id = *proof.transaction_id();
        // SAFETY: the bridge guarantees the fixed credential-ID allocation.
        let credential_id: [u8; CREDENTIAL_ID_BYTES] = unsafe {
            std::slice::from_raw_parts(credential_id, CREDENTIAL_ID_BYTES)
                .try_into()
                .map_err(|_| CALLBACK_FAILED)?
        };
        let mut session = context
            .take_prepared(proof.transaction_id(), proof.agent_challenge())
            .map_err(map_provider_error)?;
        let response = session
            .execute(
                &OperationRequest::GetPasskeyAssertion {
                    proof,
                    credential_id,
                },
                Some(&transaction_id),
            )
            .map_err(map_provider_error)?;
        response_success(&response)?;
        let decoded = decode_assertion(response.body())?;
        // SAFETY: the bridge supplied one writable result structure.
        unsafe {
            assertion.write(decoded);
        }
        Ok(())
    })
}

fn ffi_result(operation: impl FnOnce() -> Result<(), u32>) -> u32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
        .map_or(CALLBACK_FAILED, |result| {
            result.map_or_else(|error| error, |()| CALLBACK_SUCCESS)
        })
}

unsafe fn context_ref<'a>(context: *mut c_void) -> Result<&'a ProviderContext, u32> {
    // SAFETY: caller guarantees the pointer is the live context installed by
    // `run`; null is rejected before dereference.
    unsafe { context.cast::<ProviderContext>().as_ref() }.ok_or(CALLBACK_FAILED)
}

unsafe fn request_ref<'a>(request: *const NativeRequest) -> Result<&'a NativeRequest, u32> {
    // SAFETY: the native bridge supplies one live request for the duration of
    // each synchronous callback; null is rejected before dereference.
    unsafe { request.as_ref() }.ok_or(CALLBACK_FAILED)
}

impl NativeRequest {
    fn request_proof(&self) -> Result<PasskeyRequestProof, u32> {
        let transaction_id = fixed_input::<16>(self.transaction_id, 16)?;
        let request_signature = bounded_input(
            self.request_signature,
            self.request_signature_bytes,
            2 * 1024,
        )?;
        let encoded_request =
            bounded_input(self.encoded_request, self.encoded_request_bytes, 48 * 1024)?;
        PasskeyRequestProof::new(
            transaction_id,
            u8::try_from(self.request_type).map_err(|_| CALLBACK_FAILED)?,
            request_signature,
            encoded_request,
        )
        .map_err(|_| CALLBACK_FAILED)
    }

    fn transaction_proof(&self) -> Result<PasskeyTransactionProof, u32> {
        let request = self.request_proof()?;
        let uv = bounded_input(
            self.user_verification_signature,
            self.user_verification_signature_bytes,
            2 * 1024,
        )?;
        PasskeyTransactionProof::new(
            *request.transaction_id(),
            request.request_type(),
            request.request_signature(),
            request.encoded_request(),
            fixed_input::<16>(self.agent_challenge, self.agent_challenge_bytes)?,
            uv,
        )
        .map_err(|_| CALLBACK_FAILED)
    }
}

fn bounded_input<'a>(pointer: *const u8, length: u32, maximum: usize) -> Result<&'a [u8], u32> {
    let length = usize::try_from(length).map_err(|_| CALLBACK_FAILED)?;
    if pointer.is_null() || length == 0 || length > maximum {
        return Err(CALLBACK_FAILED);
    }
    // SAFETY: the native bridge owns a live allocation of the validated length
    // for the synchronous callback.
    Ok(unsafe { std::slice::from_raw_parts(pointer, length) })
}

fn fixed_input<const LENGTH: usize>(pointer: *const u8, length: u32) -> Result<[u8; LENGTH], u32> {
    if usize::try_from(length).map_err(|_| CALLBACK_FAILED)? != LENGTH {
        return Err(CALLBACK_FAILED);
    }
    bounded_input(pointer, length, LENGTH)?
        .try_into()
        .map_err(|_| CALLBACK_FAILED)
}

fn request_cancelled(transaction_id: &[u8; 16]) -> bool {
    // SAFETY: the fixed transaction buffer remains live for the call.
    unsafe {
        librarian_windows_passkey_provider_request_cancelled(
            transaction_id.as_ptr(),
            u32::try_from(transaction_id.len()).unwrap_or(0),
        ) != 0
    }
}

fn map_provider_error(error: ProviderError) -> u32 {
    match error {
        ProviderError::Identity | ProviderError::Protocol => PublicErrorCode::Incompatible as u32,
        ProviderError::Discovery | ProviderError::Transport => {
            PublicErrorCode::AgentUnavailable as u32
        }
        ProviderError::Native => CALLBACK_FAILED,
        ProviderError::NotRegistered => PublicErrorCode::NotFound as u32,
    }
}

fn response_success(response: &ResponseEnvelope) -> Result<(), u32> {
    response.error().map_or(Ok(()), |error| Err(error as u32))
}

struct OwnedSummary {
    credential_id: [u8; CREDENTIAL_ID_BYTES],
    user_handle: Zeroizing<Vec<u8>>,
    user_name: Zeroizing<String>,
    user_display_name: Zeroizing<String>,
}

impl OwnedSummary {
    fn to_native(&self) -> Result<NativeSummary, u32> {
        if self.user_handle.len() > USER_HANDLE_CAPACITY
            || self.user_name.len() > USER_NAME_CAPACITY
            || self.user_display_name.len() > USER_NAME_CAPACITY
        {
            return Err(CALLBACK_FAILED);
        }
        let mut result = NativeSummary {
            credential_id: self.credential_id,
            user_handle_bytes: u32::try_from(self.user_handle.len())
                .map_err(|_| CALLBACK_FAILED)?,
            user_name_bytes: u32::try_from(self.user_name.len()).map_err(|_| CALLBACK_FAILED)?,
            user_display_name_bytes: u32::try_from(self.user_display_name.len())
                .map_err(|_| CALLBACK_FAILED)?,
            ..NativeSummary::default()
        };
        result.user_handle[..self.user_handle.len()].copy_from_slice(&self.user_handle);
        result.user_name[..self.user_name.len()].copy_from_slice(self.user_name.as_bytes());
        result.user_display_name[..self.user_display_name.len()]
            .copy_from_slice(self.user_display_name.as_bytes());
        Ok(result)
    }
}

fn decode_summaries(bytes: &[u8]) -> Result<Vec<OwnedSummary>, u32> {
    let mut decoder = Decoder::new(bytes);
    let count = decoder
        .array()
        .map_err(|_| CALLBACK_FAILED)?
        .ok_or(CALLBACK_FAILED)?;
    let count = usize::try_from(count).map_err(|_| CALLBACK_FAILED)?;
    if count > MAX_SUMMARIES {
        return Err(CALLBACK_FAILED);
    }
    let mut summaries = Vec::with_capacity(count);
    for _ in 0..count {
        if decoder.array().map_err(|_| CALLBACK_FAILED)? != Some(4) {
            return Err(CALLBACK_FAILED);
        }
        let credential_id = decoder
            .bytes()
            .map_err(|_| CALLBACK_FAILED)?
            .try_into()
            .map_err(|_| CALLBACK_FAILED)?;
        let user_handle = Zeroizing::new(decoder.bytes().map_err(|_| CALLBACK_FAILED)?.to_vec());
        let user_name = Zeroizing::new(decoder.str().map_err(|_| CALLBACK_FAILED)?.to_owned());
        let user_display_name =
            Zeroizing::new(decoder.str().map_err(|_| CALLBACK_FAILED)?.to_owned());
        summaries.push(OwnedSummary {
            credential_id,
            user_handle,
            user_name,
            user_display_name,
        });
    }
    if decoder.position() != bytes.len() {
        return Err(CALLBACK_FAILED);
    }
    let views: Vec<_> = summaries
        .iter()
        .map(|summary| PasskeySummaryView {
            credential_id: summary.credential_id,
            user_handle: &summary.user_handle,
            user_name: &summary.user_name,
            user_display_name: &summary.user_display_name,
        })
        .collect();
    if encode_passkey_summaries(&views)
        .map_err(|_| CALLBACK_FAILED)?
        .as_slice()
        != bytes
    {
        return Err(CALLBACK_FAILED);
    }
    Ok(summaries)
}

fn decode_credential(bytes: &[u8]) -> Result<NativeCredential, u32> {
    let mut decoder = Decoder::new(bytes);
    if decoder.array().map_err(|_| CALLBACK_FAILED)? != Some(3) {
        return Err(CALLBACK_FAILED);
    }
    let credential_id = decoder
        .bytes()
        .map_err(|_| CALLBACK_FAILED)?
        .try_into()
        .map_err(|_| CALLBACK_FAILED)?;
    let user_handle = decoder.bytes().map_err(|_| CALLBACK_FAILED)?;
    let public_key = decoder
        .bytes()
        .map_err(|_| CALLBACK_FAILED)?
        .try_into()
        .map_err(|_| CALLBACK_FAILED)?;
    if decoder.position() != bytes.len() || user_handle.len() > USER_HANDLE_CAPACITY {
        return Err(CALLBACK_FAILED);
    }
    let view = PasskeyCredentialView {
        credential_id,
        user_handle,
        public_key,
    };
    if encode_passkey_credential(&view)
        .map_err(|_| CALLBACK_FAILED)?
        .as_slice()
        != bytes
    {
        return Err(CALLBACK_FAILED);
    }
    let mut result = NativeCredential {
        credential_id,
        user_handle_bytes: u32::try_from(user_handle.len()).map_err(|_| CALLBACK_FAILED)?,
        public_key,
        ..NativeCredential::default()
    };
    result.user_handle[..user_handle.len()].copy_from_slice(user_handle);
    Ok(result)
}

fn decode_assertion(bytes: &[u8]) -> Result<NativeAssertion, u32> {
    let mut decoder = Decoder::new(bytes);
    if decoder.array().map_err(|_| CALLBACK_FAILED)? != Some(4) {
        return Err(CALLBACK_FAILED);
    }
    let credential_id = decoder
        .bytes()
        .map_err(|_| CALLBACK_FAILED)?
        .try_into()
        .map_err(|_| CALLBACK_FAILED)?;
    let user_handle = decoder.bytes().map_err(|_| CALLBACK_FAILED)?;
    let authenticator_data = decoder
        .bytes()
        .map_err(|_| CALLBACK_FAILED)?
        .try_into()
        .map_err(|_| CALLBACK_FAILED)?;
    let signature = decoder.bytes().map_err(|_| CALLBACK_FAILED)?;
    if decoder.position() != bytes.len()
        || user_handle.len() > USER_HANDLE_CAPACITY
        || signature.len() > SIGNATURE_CAPACITY
    {
        return Err(CALLBACK_FAILED);
    }
    let view = PasskeyAssertionView {
        credential_id,
        user_handle,
        authenticator_data,
        signature_der: signature,
    };
    if encode_passkey_assertion(&view)
        .map_err(|_| CALLBACK_FAILED)?
        .as_slice()
        != bytes
    {
        return Err(CALLBACK_FAILED);
    }
    let mut result = NativeAssertion {
        credential_id,
        user_handle_bytes: u32::try_from(user_handle.len()).map_err(|_| CALLBACK_FAILED)?,
        authenticator_data,
        signature_bytes: u32::try_from(signature.len()).map_err(|_| CALLBACK_FAILED)?,
        ..NativeAssertion::default()
    };
    result.user_handle[..user_handle.len()].copy_from_slice(user_handle);
    result.signature[..signature.len()].copy_from_slice(signature);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_response_decoders_require_exact_canonical_bodies() {
        let summaries = [PasskeySummaryView {
            credential_id: [0x11; CREDENTIAL_ID_BYTES],
            user_handle: &[0x12; 16],
            user_name: "disposable@example.com",
            user_display_name: "Disposable User",
        }];
        let summaries = encode_passkey_summaries(&summaries).expect("summary response");
        assert_eq!(decode_summaries(&summaries).map(|value| value.len()), Ok(1));
        assert_trailing_rejected(&summaries, decode_summaries);

        let mut public_key = [0x13; PUBLIC_KEY_BYTES];
        public_key[0] = 0x04;
        let credential = encode_passkey_credential(&PasskeyCredentialView {
            credential_id: [0x14; CREDENTIAL_ID_BYTES],
            user_handle: &[0x15; 16],
            public_key,
        })
        .expect("credential response");
        assert!(decode_credential(&credential).is_ok());
        assert_trailing_rejected(&credential, decode_credential);

        let assertion = encode_passkey_assertion(&PasskeyAssertionView {
            credential_id: [0x16; CREDENTIAL_ID_BYTES],
            user_handle: &[0x17; 16],
            authenticator_data: [0x18; AUTHENTICATOR_DATA_BYTES],
            signature_der: &[0x30, 0x00],
        })
        .expect("assertion response");
        assert!(decode_assertion(&assertion).is_ok());
        assert_trailing_rejected(&assertion, decode_assertion);
    }

    fn assert_trailing_rejected<T>(canonical: &[u8], decode: impl Fn(&[u8]) -> Result<T, u32>) {
        let mut trailing = canonical.to_vec();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
    }
}
