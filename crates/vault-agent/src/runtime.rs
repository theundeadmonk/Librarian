use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use hmac::{Hmac, KeyInit, Mac};
use librarian_agent_protocol::{
    AccountView, AgentState, BeginRequestError, Connection, ConnectionError, CorrelationId,
    FrameHeader, MAX_IN_FLIGHT_GLOBAL, OperationCode, OperationRequest, PasskeyAssertionView,
    PasskeyCredentialView, PasskeyManagementSummaryView, PasskeyRequestProof, PasskeySummaryView,
    PasskeyTransactionProof, ProtocolError, PublicErrorCode, RequestCompletion, RequestEnvelope,
    RequestPermit, ResponseEnvelope, RetryCategory, encode_account, encode_account_id,
    encode_account_summaries, encode_empty_result, encode_passkey_assertion,
    encode_passkey_credential, encode_passkey_management_summaries, encode_passkey_summaries,
    encode_status,
};
use librarian_vault_core::{CancellationFlag, MasterPassword, PasskeyInput};
use sha2::Sha256;
use zeroize::Zeroizing;

#[cfg(windows)]
use crate::windows_hello::{PlatformWindowsHelloProvider, WindowsHelloStateStore};
use crate::{
    AccountError, CreateError, RecordId, UnlockError, VaultAgent, WebsiteAccount,
    WebsiteAccountInput, WindowsHelloInstallationKey,
    passkeys::{
        PasskeyRequestVerifier, PasskeyVerificationError, platform_passkey_request_verifier,
    },
    windows_hello::{
        WindowsHelloEnrollment, WindowsHelloLocalState, WindowsHelloProvider,
        WindowsHelloProviderError, WindowsHelloStateError, WindowsHelloStateRepository,
    },
};

const MAX_IDEMPOTENCY_RESULTS: usize = 1_024;

/// Startup failures contain no vault path or platform details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeStartError {
    InvalidVaultPath,
    InvalidLocalStatePath,
    AlreadyOwned,
    Internal,
}

/// Connection-fatal dispatch failure. Request-level failures use the public
/// protocol error model instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchError {
    Connection(ConnectionError),
    Internal,
}

impl From<ConnectionError> for DispatchError {
    fn from(value: ConnectionError) -> Self {
        Self::Connection(value)
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct RequestKey {
    connection_id: [u8; 16],
    request_id: u64,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct PendingPasskeyCreationKey {
    connection_id: [u8; 16],
    transaction_id: [u8; 16],
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct PendingPasskeyCreation {
    credential_id: [u8; 32],
    authenticated_process_id: u32,
    unlock_epoch: u64,
}

struct CachedOutcome {
    request_fingerprint: [u8; 32],
    error: Option<PublicErrorCode>,
    retry: RetryCategory,
    body: Zeroizing<Vec<u8>>,
}

struct IdempotencyState {
    authenticated_vault_id: Option<[u8; 16]>,
    cached: BTreeMap<[u8; 16], CachedOutcome>,
    insertion_order: VecDeque<[u8; 16]>,
    in_flight: BTreeSet<[u8; 16]>,
}

impl IdempotencyState {
    fn new() -> Self {
        Self {
            authenticated_vault_id: None,
            cached: BTreeMap::new(),
            insertion_order: VecDeque::new(),
            in_flight: BTreeSet::new(),
        }
    }
}

struct Coordinator {
    epoch: AtomicU64,
    global_in_flight: AtomicUsize,
    kdf_active: AtomicBool,
    mutation_active: AtomicBool,
    lock_active: AtomicBool,
    creation_gate: Mutex<()>,
    commit_gate: Mutex<()>,
    cancellations: Mutex<BTreeMap<RequestKey, Arc<CancellationFlag>>>,
}

impl Coordinator {
    fn new() -> Self {
        Self {
            epoch: AtomicU64::new(1),
            global_in_flight: AtomicUsize::new(0),
            kdf_active: AtomicBool::new(false),
            mutation_active: AtomicBool::new(false),
            lock_active: AtomicBool::new(false),
            creation_gate: Mutex::new(()),
            commit_gate: Mutex::new(()),
            cancellations: Mutex::new(BTreeMap::new()),
        }
    }

    fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    fn advance_epoch(&self) -> Result<u64, DispatchError> {
        let next = self.increment_epoch()?;
        for cancellation in lock(&self.cancellations)?.values() {
            cancellation.cancel();
        }
        Ok(next)
    }

    fn advance_epoch_without_cancellation(&self) -> Result<u64, DispatchError> {
        self.increment_epoch()
    }

    fn increment_epoch(&self) -> Result<u64, DispatchError> {
        let next = self
            .epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch.checked_add(1)
            })
            .map_err(|_| DispatchError::Internal)?
            .checked_add(1)
            .ok_or(DispatchError::Internal)?;
        Ok(next)
    }

    fn register(self: &Arc<Self>, key: RequestKey) -> Result<RequestRegistration, DispatchError> {
        let cancellation = Arc::new(CancellationFlag::new());
        if lock(&self.cancellations)?
            .insert(key, Arc::clone(&cancellation))
            .is_some()
        {
            return Err(DispatchError::Internal);
        }
        Ok(RequestRegistration {
            coordinator: Arc::clone(self),
            key,
            cancellation,
        })
    }

    fn cancel(&self, key: RequestKey) -> Result<bool, DispatchError> {
        let cancellations = lock(&self.cancellations)?;
        Ok(cancellations.get(&key).is_some_and(|flag| {
            flag.cancel();
            true
        }))
    }

    fn cancel_connection(&self, connection_id: [u8; 16]) -> Result<(), DispatchError> {
        for (key, cancellation) in lock(&self.cancellations)?.iter() {
            if key.connection_id == connection_id {
                cancellation.cancel();
            }
        }
        Ok(())
    }
}

struct RequestRegistration {
    coordinator: Arc<Coordinator>,
    key: RequestKey,
    cancellation: Arc<CancellationFlag>,
}

struct DispatchContext<'a> {
    connection: &'a Connection,
    permit: RequestPermit,
    _global: CounterPermit<'a>,
    registration: RequestRegistration,
    deadline: Instant,
    correlation: CorrelationId,
}

enum RequestAdmission<'a> {
    Admitted(DispatchContext<'a>),
    Rejected {
        response: ResponseEnvelope,
        _commit: MutexGuard<'a, ()>,
    },
}

impl Drop for RequestRegistration {
    fn drop(&mut self) {
        if let Ok(mut cancellations) = self.coordinator.cancellations.lock() {
            cancellations.remove(&self.key);
        }
    }
}

struct CounterPermit<'a>(&'a AtomicUsize);

impl CounterPermit<'_> {
    fn acquire(counter: &AtomicUsize, maximum: usize) -> Option<CounterPermit<'_>> {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < maximum).then_some(current + 1)
            })
            .ok()
            .map(|_| CounterPermit(counter))
    }
}

impl Drop for CounterPermit<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct FlagPermit<'a>(Option<&'a AtomicBool>);

impl<'a> FlagPermit<'a> {
    fn acquire(flag: &'a AtomicBool) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| FlagPermit(Some(flag)))
    }

    fn take_over_active(flag: &'a AtomicBool) -> Self {
        debug_assert!(flag.load(Ordering::Acquire));
        Self(Some(flag))
    }

    fn handoff(mut self) {
        self.0 = None;
    }
}

impl Drop for FlagPermit<'_> {
    fn drop(&mut self) {
        if let Some(flag) = self.0 {
            flag.store(false, Ordering::Release);
        }
    }
}

#[cfg(windows)]
#[derive(Eq, PartialEq)]
struct FileIdentity(same_file::Handle);

#[cfg(not(windows))]
#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    volume: u64,
    file: u64,
}

struct OwnershipRecord {
    normalized_path: PathBuf,
    identity: Option<FileIdentity>,
}

impl OwnershipRecord {
    fn conflicts_with(&self, other: &Self) -> bool {
        self.normalized_path == other.normalized_path
            || matches!(
                (&self.identity, &other.identity),
                (Some(left), Some(right)) if left == right
            )
    }

    fn is_same_existing_target(&self, other: &Self) -> bool {
        self.normalized_path == other.normalized_path
            && matches!(
                (&self.identity, &other.identity),
                (Some(left), Some(right)) if left == right
            )
    }
}

struct RuntimeOwnership {
    vault: OwnershipRecord,
    windows_hello_state: Option<OwnershipRecord>,
}

impl RuntimeOwnership {
    fn conflicts_with(&self, record: &OwnershipRecord) -> bool {
        self.vault.conflicts_with(record)
            || self
                .windows_hello_state
                .as_ref()
                .is_some_and(|state| state.conflicts_with(record))
    }
}

struct OwnershipLease {
    token: u64,
}

impl OwnershipLease {
    fn bind_existing(
        &self,
        registry: &mut BTreeMap<u64, RuntimeOwnership>,
        path: &Path,
    ) -> Result<(), DispatchError> {
        let record = ownership_record(path).map_err(|_| DispatchError::Internal)?;
        if record.identity.is_none()
            || registry
                .iter()
                .any(|(token, existing)| *token != self.token && existing.conflicts_with(&record))
        {
            return Err(DispatchError::Internal);
        }
        let current = registry
            .get_mut(&self.token)
            .ok_or(DispatchError::Internal)?;
        if current.vault.normalized_path != record.normalized_path {
            return Err(DispatchError::Internal);
        }
        current.vault = record;
        Ok(())
    }

    fn bind_windows_hello_state(
        &self,
        registry: &mut BTreeMap<u64, RuntimeOwnership>,
        path: &Path,
    ) -> Result<(), DispatchError> {
        let record = ownership_record(path).map_err(|_| DispatchError::Internal)?;
        if registry
            .iter()
            .any(|(token, existing)| *token != self.token && existing.conflicts_with(&record))
        {
            return Err(DispatchError::Internal);
        }
        let current = registry
            .get_mut(&self.token)
            .ok_or(DispatchError::Internal)?;
        if current.vault.conflicts_with(&record) {
            return Err(DispatchError::Internal);
        }
        let state = current
            .windows_hello_state
            .as_mut()
            .ok_or(DispatchError::Internal)?;
        if state.normalized_path != record.normalized_path {
            return Err(DispatchError::Internal);
        }
        *state = record;
        Ok(())
    }

    fn bind_authenticated(
        &self,
        registry: &mut BTreeMap<u64, RuntimeOwnership>,
        path: &Path,
        authenticated: &OwnershipRecord,
        bind_authenticated_vault: impl FnOnce() -> Result<(), DispatchError>,
    ) -> Result<(), DispatchError> {
        let current = ownership_record(path).map_err(|_| DispatchError::Internal)?;
        if !authenticated.is_same_existing_target(&current) {
            return Err(DispatchError::Internal);
        }
        if registry
            .iter()
            .any(|(token, existing)| *token != self.token && existing.conflicts_with(&current))
        {
            return Err(DispatchError::Internal);
        }
        let leased = registry
            .get_mut(&self.token)
            .ok_or(DispatchError::Internal)?;
        if leased.vault.normalized_path != current.normalized_path {
            return Err(DispatchError::Internal);
        }
        bind_authenticated_vault()?;
        leased.vault = current;
        Ok(())
    }
}

impl Drop for OwnershipLease {
    fn drop(&mut self) {
        if let Ok(mut owned) = owned_vaults().lock() {
            owned.remove(&self.token);
        }
    }
}

/// The sole in-process owner of vault state, unlocked keys, persistence, and
/// typed operation dispatch.
pub struct AgentRuntime {
    vault_path: PathBuf,
    vault: Mutex<VaultAgent>,
    state: AtomicU8,
    coordinator: Arc<Coordinator>,
    idempotency: Mutex<IdempotencyState>,
    pending_passkey_creations: Mutex<BTreeMap<PendingPasskeyCreationKey, PendingPasskeyCreation>>,
    idempotency_fingerprint_key: Zeroizing<[u8; 32]>,
    windows_hello_provider: Option<Arc<dyn WindowsHelloProvider>>,
    windows_hello_state: Option<Arc<dyn WindowsHelloStateRepository>>,
    windows_hello_active: AtomicBool,
    windows_hello_gate: Mutex<()>,
    passkey_verifier: Arc<dyn PasskeyRequestVerifier>,
    ownership: OwnershipLease,
}

impl AgentRuntime {
    /// Binds one absolute vault path to exactly one runtime in this process.
    ///
    /// # Errors
    ///
    /// Rejects relative paths, duplicate ownership, and path inspection
    /// failures. It does not open or decrypt the vault.
    pub fn start(vault_path: impl AsRef<Path>) -> Result<Self, RuntimeStartError> {
        Self::start_with_components(vault_path.as_ref(), None, None)
    }

    /// Enables the production Windows Hello provider with one agent-owned
    /// protected-state path selected by the trusted process bootstrap.
    ///
    /// # Errors
    ///
    /// Returns a detail-free startup failure for an invalid vault or local
    /// state path, duplicate ownership, randomness, or path inspection error.
    #[cfg(windows)]
    pub fn start_with_windows_hello(
        vault_path: impl AsRef<Path>,
        protected_state_path: impl AsRef<Path>,
    ) -> Result<Self, RuntimeStartError> {
        let protected_state_path = protected_state_path.as_ref();
        let store = WindowsHelloStateStore::new(protected_state_path)
            .map_err(|_| RuntimeStartError::InvalidLocalStatePath)?;
        Self::start_with_components_and_state_path(
            vault_path.as_ref(),
            Some(Arc::new(PlatformWindowsHelloProvider)),
            Some(Arc::new(store)),
            Some(protected_state_path),
        )
    }

    fn start_with_components(
        vault_path: &Path,
        windows_hello_provider: Option<Arc<dyn WindowsHelloProvider>>,
        windows_hello_state: Option<Arc<dyn WindowsHelloStateRepository>>,
    ) -> Result<Self, RuntimeStartError> {
        Self::start_with_components_and_state_path(
            vault_path,
            windows_hello_provider,
            windows_hello_state,
            None,
        )
    }

    fn start_with_components_and_state_path(
        vault_path: &Path,
        windows_hello_provider: Option<Arc<dyn WindowsHelloProvider>>,
        windows_hello_state: Option<Arc<dyn WindowsHelloStateRepository>>,
        protected_state_path: Option<&Path>,
    ) -> Result<Self, RuntimeStartError> {
        if windows_hello_provider.is_some() != windows_hello_state.is_some() {
            return Err(RuntimeStartError::InvalidLocalStatePath);
        }
        if !vault_path.is_absolute() {
            return Err(RuntimeStartError::InvalidVaultPath);
        }
        let mut idempotency_fingerprint_key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut *idempotency_fingerprint_key)
            .map_err(|_| RuntimeStartError::Internal)?;
        if *idempotency_fingerprint_key == [0; 32] {
            return Err(RuntimeStartError::Internal);
        }
        let vault_ownership_record = ownership_record(vault_path)?;
        let protected_state_record = protected_state_path
            .map(ownership_record)
            .transpose()
            .map_err(|_| RuntimeStartError::InvalidLocalStatePath)?;
        if protected_state_record
            .as_ref()
            .is_some_and(|state| state.conflicts_with(&vault_ownership_record))
        {
            return Err(RuntimeStartError::InvalidLocalStatePath);
        }
        let ownership_token = next_ownership_token()?;
        let mut owned = owned_vaults()
            .lock()
            .map_err(|_| RuntimeStartError::Internal)?;
        if owned.values().any(|existing| {
            existing.conflicts_with(&vault_ownership_record)
                || protected_state_record
                    .as_ref()
                    .is_some_and(|state| existing.conflicts_with(state))
        }) {
            return Err(RuntimeStartError::AlreadyOwned);
        }
        owned.insert(
            ownership_token,
            RuntimeOwnership {
                vault: vault_ownership_record,
                windows_hello_state: protected_state_record,
            },
        );
        drop(owned);
        let state = match fs::symlink_metadata(vault_path) {
            Ok(_) => AgentState::Locked,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => AgentState::NoVault,
            Err(_) => {
                if let Ok(mut owned) = owned_vaults().lock() {
                    owned.remove(&ownership_token);
                }
                return Err(RuntimeStartError::InvalidVaultPath);
            }
        };
        Ok(Self {
            vault_path: vault_path.to_path_buf(),
            vault: Mutex::new(VaultAgent::open_locked(vault_path)),
            state: AtomicU8::new(state as u8),
            coordinator: Arc::new(Coordinator::new()),
            idempotency: Mutex::new(IdempotencyState::new()),
            pending_passkey_creations: Mutex::new(BTreeMap::new()),
            idempotency_fingerprint_key,
            windows_hello_provider,
            windows_hello_state,
            windows_hello_active: AtomicBool::new(false),
            windows_hello_gate: Mutex::new(()),
            passkey_verifier: platform_passkey_request_verifier(),
            ownership: OwnershipLease {
                token: ownership_token,
            },
        })
    }

    #[must_use]
    pub fn state(&self) -> AgentState {
        decode_state(self.state.load(Ordering::Acquire))
    }

    #[must_use]
    pub fn unlock_epoch(&self) -> u64 {
        self.coordinator.epoch()
    }

    /// Captures the non-secret state advertised during protocol negotiation.
    ///
    /// The state and unlock epoch are read under the same transition gate so a
    /// handshake cannot combine values from opposite sides of a lock or unlock
    /// transition.
    ///
    /// # Errors
    ///
    /// Returns `Internal` only if the transition gate is poisoned.
    pub fn status_snapshot(&self) -> Result<(AgentState, u64), DispatchError> {
        let _commit = lock(&self.coordinator.commit_gate)?;
        Ok((self.state(), self.unlock_epoch()))
    }

    /// Cancels one connection-bound request. Unknown/completed identifiers are
    /// handled by the protocol connection state before this method is called.
    ///
    /// # Errors
    ///
    /// Returns `Internal` only if cancellation state is poisoned.
    pub fn cancel_request(
        &self,
        connection_id: [u8; 16],
        request_id: u64,
    ) -> Result<bool, DispatchError> {
        self.coordinator.cancel(RequestKey {
            connection_id,
            request_id,
        })
    }

    /// Validates one protocol cancellation and applies it to the matching
    /// runtime request flag.
    ///
    /// # Errors
    ///
    /// Invalid or never-issued request IDs are connection-fatal.
    pub fn apply_cancel(
        &self,
        connection: &Connection,
        header: &FrameHeader,
    ) -> Result<(), DispatchError> {
        let _commit = lock(&self.coordinator.commit_gate)?;
        let connection_id = *connection.connection_id();
        connection.cancel(header)?;
        let _ = self.cancel_request(connection_id, header.request_id())?;
        Ok(())
    }

    /// Cancels every request owned by a disconnected or exited peer.
    ///
    /// # Errors
    ///
    /// Returns `Internal` only if cancellation state is poisoned.
    pub fn disconnect(&self, connection: &Connection) -> Result<(), DispatchError> {
        let _commit = lock(&self.coordinator.commit_gate)?;
        let connection_id = *connection.connection_id();
        connection.close();
        lock(&self.pending_passkey_creations)?.retain(|key, _| key.connection_id != connection_id);
        self.coordinator.cancel_connection(connection_id)
    }

    /// Locks and cancels all work before Windows sign-out or agent shutdown.
    ///
    /// # Errors
    ///
    /// Returns `Internal` if lifecycle state is poisoned or exhausted.
    pub fn shutdown(&self) -> Result<(), DispatchError> {
        {
            let _commit = lock(&self.coordinator.commit_gate)?;
            self.coordinator.lock_active.store(true, Ordering::Release);
            self.state
                .store(AgentState::ShuttingDown as u8, Ordering::Release);
            self.coordinator.advance_epoch()?;
        }
        let _creation = lock(&self.coordinator.creation_gate)?;
        let _windows_hello = lock(&self.windows_hello_gate)?;
        lock(&self.vault)?.lock();
        self.state
            .store(AgentState::ShuttingDown as u8, Ordering::Release);
        Ok(())
    }

    /// Admits and executes one already authenticated request.
    ///
    /// Role authorization and request-ID validation run before the
    /// operation-specific body is decoded.
    ///
    /// # Errors
    ///
    /// Returns only connection-fatal state-machine or internal failures.
    /// Request failures are encoded as detail-free public responses.
    /// `write_response` must synchronously encode and write the complete
    /// response to the authenticated transport. It must not queue or retain
    /// response bytes after returning. Lock, cancellation, and disconnect are
    /// serialized against this callback.
    pub fn dispatch<T>(
        &self,
        connection: &Connection,
        header: &FrameHeader,
        envelope: &RequestEnvelope,
        write_response: impl FnOnce(&ResponseEnvelope) -> Result<T, DispatchError>,
    ) -> Result<T, DispatchError> {
        self.dispatch_with_admission(connection, header, envelope, || {}, write_response)
    }

    /// Admits and executes one authenticated request while notifying the
    /// transport after the request identifier has been issued.
    ///
    /// A concurrent transport reader must not process a later cancellation
    /// until this callback runs. Fatal admission errors return without calling
    /// it, while every admitted or public-rejection path calls it exactly once.
    ///
    /// # Errors
    ///
    /// Returns the same connection-fatal failures as [`Self::dispatch`].
    pub fn dispatch_with_admission<T>(
        &self,
        connection: &Connection,
        header: &FrameHeader,
        envelope: &RequestEnvelope,
        on_admitted: impl FnOnce(),
        write_response: impl FnOnce(&ResponseEnvelope) -> Result<T, DispatchError>,
    ) -> Result<T, DispatchError> {
        let correlation = correlation_id()?;
        let context = match self.admit_request(connection, header, envelope, correlation)? {
            RequestAdmission::Admitted(context) => context,
            RequestAdmission::Rejected {
                response,
                _commit: _commit_gate,
            } => {
                on_admitted();
                let response = Self::bounded_response(connection, response, correlation)?;
                return write_response(&response);
            }
        };
        on_admitted();
        let outcome = if context.permit.operation().requires_idempotency_key() {
            let idempotency_key = envelope.idempotency_key().ok_or(DispatchError::Internal)?;
            let request_fingerprint = self.request_fingerprint(
                envelope.operation(),
                context.permit.unlock_epoch(),
                envelope.body(),
            )?;
            self.execute_idempotent(
                *idempotency_key,
                request_fingerprint,
                || match OperationRequest::decode(envelope.operation(), envelope.body()) {
                    Ok(operation) => Ok(Self::passkey_binding_failure(&operation, &context)),
                    Err(_) => Ok(None),
                },
                || match OperationRequest::decode(envelope.operation(), envelope.body()) {
                    Ok(operation) => self.execute_decoded(operation, &context),
                    Err(error) => Ok(map_operation_decode_error(error)),
                },
            )?
        } else {
            match OperationRequest::decode(envelope.operation(), envelope.body()) {
                Ok(operation) => self.execute_decoded(operation, &context)?,
                Err(error) => map_operation_decode_error(error),
            }
        };
        self.finish_dispatch(context, outcome, write_response)
    }

    fn admit_request<'a>(
        &'a self,
        connection: &'a Connection,
        header: &FrameHeader,
        envelope: &RequestEnvelope,
        correlation: CorrelationId,
    ) -> Result<RequestAdmission<'a>, DispatchError> {
        let admission_started = Instant::now();
        // Establish connection-local request ordering before contending with
        // independently scheduled cancel, disconnect, or lifecycle workers.
        let permit = connection.begin_request(header, envelope, self.unlock_epoch());
        let admission = lock(&self.coordinator.commit_gate)?;
        let permit = match permit {
            Ok(permit) => permit,
            Err(BeginRequestError::Unauthorized) => {
                return Ok(RequestAdmission::Rejected {
                    response: ResponseEnvelope::failure(
                        PublicErrorCode::UnauthorizedOperation,
                        RetryCategory::Never,
                        correlation,
                    )?,
                    _commit: admission,
                });
            }
            Err(BeginRequestError::Busy {
                effective_timeout_ms,
            }) => {
                let deadline = request_deadline(admission_started, effective_timeout_ms)?;
                let outcome = if Instant::now() >= deadline {
                    ExecutionOutcome::deadline()
                } else {
                    ExecutionOutcome::busy()
                };
                return Ok(RequestAdmission::Rejected {
                    response: ResponseEnvelope::failure(
                        outcome.error.ok_or(DispatchError::Internal)?,
                        outcome.retry,
                        correlation,
                    )?,
                    _commit: admission,
                });
            }
            Err(BeginRequestError::StaleEpoch) => {
                return Ok(RequestAdmission::Rejected {
                    response: ResponseEnvelope::failure(
                        PublicErrorCode::Locked,
                        RetryCategory::AfterUnlock,
                        correlation,
                    )?,
                    _commit: admission,
                });
            }
            Err(BeginRequestError::MissingIdempotencyKey) => {
                return Ok(RequestAdmission::Rejected {
                    response: ResponseEnvelope::failure(
                        PublicErrorCode::InvalidRequest,
                        RetryCategory::Never,
                        correlation,
                    )?,
                    _commit: admission,
                });
            }
            Err(BeginRequestError::Connection(error)) => return Err(error.into()),
        };
        let deadline = request_deadline(admission_started, permit.effective_timeout_ms())?;

        let Some(global) =
            CounterPermit::acquire(&self.coordinator.global_in_flight, MAX_IN_FLIGHT_GLOBAL)
        else {
            connection.finish(permit)?;
            let outcome = if Instant::now() >= deadline {
                ExecutionOutcome::deadline()
            } else {
                ExecutionOutcome::busy()
            };
            return Ok(RequestAdmission::Rejected {
                response: ResponseEnvelope::failure(
                    outcome.error.ok_or(DispatchError::Internal)?,
                    outcome.retry,
                    correlation,
                )?,
                _commit: admission,
            });
        };
        let key = RequestKey {
            connection_id: *connection.connection_id(),
            request_id: permit.request_id(),
        };
        let registration = self.coordinator.register(key)?;
        if connection.is_cancelled(permit) {
            registration.cancellation.cancel();
        }
        drop(admission);
        Ok(RequestAdmission::Admitted(DispatchContext {
            connection,
            permit,
            _global: global,
            registration,
            deadline,
            correlation,
        }))
    }

    fn execute_idempotent(
        &self,
        key: [u8; 16],
        request_fingerprint: [u8; 32],
        validate_replay: impl FnOnce() -> Result<Option<ExecutionOutcome>, DispatchError>,
        execute: impl FnOnce() -> Result<ExecutionOutcome, DispatchError>,
    ) -> Result<ExecutionOutcome, DispatchError> {
        let (reservation, replay) = {
            let mut state = lock(&self.idempotency)?;
            if let Some(cached) = state.cached.get(&key) {
                if cached.request_fingerprint != request_fingerprint {
                    return Ok(ExecutionOutcome::failure(
                        PublicErrorCode::Conflict,
                        RetryCategory::Never,
                    ));
                }
                (
                    None,
                    Some(ExecutionOutcome {
                        error: cached.error,
                        retry: cached.retry,
                        body: Zeroizing::new(cached.body.to_vec()),
                        replayed: true,
                        holds_lock_transition: false,
                        committed: false,
                    }),
                )
            } else {
                if state.in_flight.contains(&key) {
                    return Ok(ExecutionOutcome::busy());
                }

                while state
                    .cached
                    .len()
                    .checked_add(state.in_flight.len())
                    .is_none_or(|count| count >= MAX_IDEMPOTENCY_RESULTS)
                {
                    let Some(oldest) = state.insertion_order.pop_front() else {
                        return Ok(ExecutionOutcome::busy());
                    };
                    state.cached.remove(&oldest);
                }

                state.in_flight.insert(key);
                (
                    Some(IdempotencyReservation {
                        state: &self.idempotency,
                        key,
                        active: true,
                    }),
                    None,
                )
            }
        };

        if let Some(replay) = replay {
            if let Some(rejection) = validate_replay()? {
                return Ok(rejection);
            }
            return Ok(replay);
        }

        let reservation = reservation.ok_or(DispatchError::Internal)?;
        let outcome = execute()?;
        let cached = should_cache(&outcome).then(|| CachedOutcome {
            request_fingerprint,
            error: outcome.error,
            retry: outcome.retry,
            body: Zeroizing::new(outcome.body.to_vec()),
        });
        reservation.complete(cached)?;
        Ok(outcome)
    }

    fn request_fingerprint(
        &self,
        operation: OperationCode,
        unlock_epoch: u64,
        body: &[u8],
    ) -> Result<[u8; 32], DispatchError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&*self.idempotency_fingerprint_key)
            .map_err(|_| DispatchError::Internal)?;
        mac.update(b"Librarian idempotency request v2\0");
        mac.update(&(operation as u16).to_be_bytes());
        let requires_unlocked_epoch = operation.requires_unlocked_epoch();
        mac.update(&[u8::from(requires_unlocked_epoch)]);
        if requires_unlocked_epoch {
            mac.update(&unlock_epoch.to_be_bytes());
        }
        mac.update(body);
        Ok(mac.finalize().into_bytes().into())
    }

    fn finish_dispatch<T>(
        &self,
        context: DispatchContext<'_>,
        mut outcome: ExecutionOutcome,
        write_response: impl FnOnce(&ResponseEnvelope) -> Result<T, DispatchError>,
    ) -> Result<T, DispatchError> {
        let _lock_transition = outcome
            .holds_lock_transition
            .then(|| FlagPermit::take_over_active(&self.coordinator.lock_active));
        let _commit = lock(&self.coordinator.commit_gate)?;
        let completion = context.connection.finish(context.permit)?;
        if !outcome.committed {
            if completion == RequestCompletion::Cancelled {
                outcome = ExecutionOutcome::cancelled();
            } else if outcome.error.is_none() || outcome.error == Some(PublicErrorCode::NotFound) {
                if context.registration.cancellation.is_cancelled()
                    && context.permit.operation() != OperationCode::Lock
                {
                    outcome = ExecutionOutcome::cancelled();
                } else if Instant::now() >= context.deadline {
                    outcome = ExecutionOutcome::deadline();
                } else if !(self.outcome_is_still_authorized(context.permit, &outcome)
                    || outcome.replayed && context.permit.operation() == OperationCode::CreateVault)
                {
                    outcome = ExecutionOutcome::locked();
                }
            }
        }
        if outcome.error.is_none()
            && matches!(
                context.permit.operation(),
                OperationCode::Status | OperationCode::CreateVault
            )
        {
            outcome = ExecutionOutcome::success(encode_status(self.state(), self.unlock_epoch())?);
        }
        let response = outcome.into_response(context.correlation)?;
        let response = Self::bounded_response(context.connection, response, context.correlation)?;
        let write_result = write_response(&response);
        drop(context);
        write_result
    }

    fn bounded_response(
        connection: &Connection,
        response: ResponseEnvelope,
        correlation: CorrelationId,
    ) -> Result<ResponseEnvelope, DispatchError> {
        if connection.response_fits(&response) {
            return Ok(response);
        }
        drop(response);
        let failure = ResponseEnvelope::failure(
            PublicErrorCode::OperationFailed,
            RetryCategory::Never,
            correlation,
        )?;
        if !connection.response_fits(&failure) {
            return Err(DispatchError::Connection(ConnectionError::InvalidLimit));
        }
        Ok(failure)
    }

    fn outcome_is_still_authorized(
        &self,
        permit: RequestPermit,
        outcome: &ExecutionOutcome,
    ) -> bool {
        match permit.operation() {
            OperationCode::Status | OperationCode::Lock => outcome.error.is_none(),
            OperationCode::CreateVault
            | OperationCode::UnlockMasterPassword
            | OperationCode::UnlockWindowsHello => {
                !self.coordinator.lock_active.load(Ordering::Acquire)
                    && self.state() == AgentState::Unlocked
            }
            operation if operation.requires_unlocked_epoch() => {
                !self.coordinator.lock_active.load(Ordering::Acquire)
                    && self.state() == AgentState::Unlocked
                    && self.coordinator.epoch() == permit.unlock_epoch()
            }
            _ => false,
        }
    }

    fn execute(
        &self,
        operation: OperationRequest,
        request_epoch: u64,
        connection_id: [u8; 16],
        authenticated_process_id: u32,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        if registration.cancellation.is_cancelled() {
            return Ok(ExecutionOutcome::cancelled());
        }
        if Instant::now() >= deadline {
            return Ok(ExecutionOutcome::deadline());
        }
        match operation {
            OperationRequest::Status => Ok(ExecutionOutcome::success(Zeroizing::new(Vec::new()))),
            OperationRequest::CreateVault { master_password } => {
                self.create_vault(&master_password, registration, deadline)
            }
            OperationRequest::UnlockMasterPassword { master_password } => {
                self.unlock_vault(&master_password, registration, deadline)
            }
            OperationRequest::Lock => self.lock_vault(),
            OperationRequest::ListAccountSummaries { offset, limit } => {
                self.list_accounts(offset, limit, request_epoch, registration, deadline)
            }
            OperationRequest::GetAccount { id } => {
                self.get_account(id, request_epoch, registration, deadline)
            }
            OperationRequest::AddAccount { fields } => {
                self.add_account(&fields, request_epoch, registration, deadline)
            }
            OperationRequest::UpdateAccount { id, fields } => {
                self.update_account(id, &fields, request_epoch, registration, deadline)
            }
            OperationRequest::DeleteAccount { id } => {
                self.delete_account(id, request_epoch, registration, deadline)
            }
            OperationRequest::EnrollWindowsHello { parent_window } => self.enroll_windows_hello(
                parent_window,
                authenticated_process_id,
                request_epoch,
                registration,
                deadline,
            ),
            OperationRequest::UnlockWindowsHello { parent_window } => self.unlock_windows_hello(
                parent_window,
                authenticated_process_id,
                request_epoch,
                registration,
                deadline,
            ),
            OperationRequest::RemoveWindowsHello => {
                self.remove_windows_hello(request_epoch, registration, deadline)
            }
            OperationRequest::MakePasskey { proof } => self.make_passkey(
                &proof,
                connection_id,
                authenticated_process_id,
                request_epoch,
                registration,
                deadline,
            ),
            OperationRequest::GetPasskeyAssertion {
                proof,
                credential_id,
            } => self.get_passkey_assertion(
                &proof,
                &credential_id,
                request_epoch,
                registration,
                deadline,
            ),
            OperationRequest::DeletePasskey { credential_id } => {
                self.delete_passkey(&credential_id, request_epoch, registration, deadline)
            }
            OperationRequest::ListPasskeysForAssertion { proof } => {
                self.list_passkeys_for_assertion(&proof, request_epoch, registration, deadline)
            }
            OperationRequest::ListPasskeys => {
                self.list_passkeys(request_epoch, registration, deadline)
            }
            OperationRequest::RollbackPasskeyCreation {
                proof,
                credential_id,
            } => self.rollback_passkey_creation(
                &proof,
                &credential_id,
                connection_id,
                authenticated_process_id,
                request_epoch,
                registration,
                deadline,
            ),
        }
    }

    fn execute_decoded(
        &self,
        operation: OperationRequest,
        context: &DispatchContext<'_>,
    ) -> Result<ExecutionOutcome, DispatchError> {
        if let Some(rejection) = Self::passkey_binding_failure(&operation, context) {
            return Ok(rejection);
        }
        self.execute(
            operation,
            context.permit.unlock_epoch(),
            *context.connection.connection_id(),
            context.connection.authenticated_process_id(),
            &context.registration,
            context.deadline,
        )
    }

    fn passkey_binding_failure(
        operation: &OperationRequest,
        context: &DispatchContext<'_>,
    ) -> Option<ExecutionOutcome> {
        let expected_request_id = match operation {
            OperationRequest::RollbackPasskeyCreation { .. } => 2,
            _ => 1,
        };
        operation
            .passkey_proof()
            .is_some_and(|proof| {
                context.permit.request_id() != expected_request_id
                    || proof.agent_challenge() != context.connection.connection_id()
            })
            .then(|| {
                ExecutionOutcome::failure(PublicErrorCode::InvalidRequest, RetryCategory::Never)
            })
    }

    fn create_vault(
        &self,
        password: &str,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        if self.state() != AgentState::NoVault {
            return Ok(ExecutionOutcome::failure(
                PublicErrorCode::Conflict,
                RetryCategory::Never,
            ));
        }
        let Some(_mutation) = FlagPermit::acquire(&self.coordinator.mutation_active) else {
            return Ok(ExecutionOutcome::busy());
        };
        let _creation = lock(&self.coordinator.creation_gate)?;
        if registration.cancellation.is_cancelled() {
            return Ok(ExecutionOutcome::cancelled());
        }
        if Instant::now() >= deadline {
            return Ok(ExecutionOutcome::deadline());
        }
        if self.coordinator.lock_active.load(Ordering::Acquire) {
            return Ok(ExecutionOutcome::busy());
        }
        let Ok(password) = MasterPassword::new(password) else {
            return Ok(ExecutionOutcome::invalid());
        };
        let start_epoch = self.coordinator.epoch();
        let coordinator = Arc::clone(&self.coordinator);
        let cancellation = Arc::clone(&registration.cancellation);
        let mut commit_guard = None;
        let mut ownership_guard = None;
        let result = VaultAgent::create_with_before_publish(&self.vault_path, password, || {
            let guard = coordinator
                .commit_gate
                .lock()
                .map_err(|_| CreateError::Failed)?;
            let owned = owned_vaults().lock().map_err(|_| CreateError::Failed)?;
            if coordinator.epoch() != start_epoch
                || cancellation.is_cancelled()
                || Instant::now() >= deadline
                || coordinator.lock_active.load(Ordering::Acquire)
                || self.state() != AgentState::NoVault
            {
                return Err(CreateError::Failed);
            }
            commit_guard = Some(guard);
            ownership_guard = Some(owned);
            Ok(())
        });
        match result {
            Ok((mut created, recovery_key)) => {
                let Some(_commit) = commit_guard else {
                    return Err(DispatchError::Internal);
                };
                let Some(mut owned) = ownership_guard else {
                    return Err(DispatchError::Internal);
                };
                if self
                    .ownership
                    .bind_existing(&mut owned, &self.vault_path)
                    .is_err()
                {
                    created.lock();
                    return Err(DispatchError::Internal);
                }
                let authenticated_vault_id = created
                    .authenticated_vault_id()
                    .ok_or(DispatchError::Internal)?;
                self.initialize_idempotency_vault(authenticated_vault_id)?;
                drop(recovery_key);
                *lock(&self.vault)? = created;
                self.coordinator.advance_epoch_without_cancellation()?;
                self.state
                    .store(AgentState::Unlocked as u8, Ordering::Release);
                Ok(ExecutionOutcome::success(encode_status(
                    AgentState::Unlocked,
                    self.unlock_epoch(),
                )?))
            }
            Err(CreateError::AlreadyExists) => Ok(ExecutionOutcome::failure(
                PublicErrorCode::Conflict,
                RetryCategory::Never,
            )),
            Err(CreateError::Failed) if registration.cancellation.is_cancelled() => {
                Ok(ExecutionOutcome::cancelled())
            }
            Err(CreateError::Failed) if Instant::now() >= deadline => {
                Ok(ExecutionOutcome::deadline())
            }
            Err(CreateError::Failed) => Ok(ExecutionOutcome::failed()),
        }
    }

    fn unlock_vault(
        &self,
        password: &str,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        self.unlock_vault_with_after_core(password, registration, deadline, || {})
    }

    fn unlock_vault_with_after_core(
        &self,
        password: &str,
        registration: &RequestRegistration,
        deadline: Instant,
        after_core_unlock: impl FnOnce(),
    ) -> Result<ExecutionOutcome, DispatchError> {
        if self.state() == AgentState::Unlocking {
            return Ok(ExecutionOutcome::busy());
        }
        if self.state() != AgentState::Locked {
            return Ok(ExecutionOutcome::failure(
                PublicErrorCode::Conflict,
                RetryCategory::Never,
            ));
        }
        let Some(_kdf) = FlagPermit::acquire(&self.coordinator.kdf_active) else {
            return Ok(ExecutionOutcome::busy());
        };
        let Ok(password) = MasterPassword::new(password) else {
            return Ok(ExecutionOutcome::invalid());
        };
        {
            let _commit = lock(&self.coordinator.commit_gate)?;
            if self.coordinator.lock_active.load(Ordering::Acquire) {
                return Ok(ExecutionOutcome::busy());
            }
            if self
                .state
                .compare_exchange(
                    AgentState::Locked as u8,
                    AgentState::Unlocking as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                return Ok(ExecutionOutcome::failure(
                    PublicErrorCode::Conflict,
                    RetryCategory::Never,
                ));
            }
        }
        let mut authenticated_ownership = None;
        let (result, authenticated_vault_id) = {
            let mut vault = lock(&self.vault)?;
            let result =
                vault.unlock_with_before_publish(password, &registration.cancellation, || {
                    authenticated_ownership = ownership_record(&self.vault_path).ok();
                });
            let authenticated_vault_id = if result.is_ok() {
                after_core_unlock();
                vault.authenticated_vault_id()
            } else {
                None
            };
            (result, authenticated_vault_id)
        };
        if registration.cancellation.is_cancelled() {
            lock(&self.vault)?.lock();
            self.set_locked_unless_shutting_down();
            return Ok(ExecutionOutcome::cancelled());
        }
        if Instant::now() >= deadline {
            lock(&self.vault)?.lock();
            self.set_locked_unless_shutting_down();
            return Ok(ExecutionOutcome::deadline());
        }
        match result {
            Ok(()) => {
                let authenticated_vault_id =
                    authenticated_vault_id.ok_or(DispatchError::Internal)?;
                self.publish_authenticated_unlock(
                    authenticated_ownership,
                    authenticated_vault_id,
                    registration,
                    deadline,
                )
            }
            Err(UnlockError::Cancelled) => {
                self.set_locked_unless_shutting_down();
                Ok(ExecutionOutcome::cancelled())
            }
            Err(UnlockError::Failed) => {
                self.set_locked_unless_shutting_down();
                Ok(ExecutionOutcome::failed())
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the explicit authorization inputs must remain visible at the trust boundary"
    )]
    fn enroll_windows_hello(
        &self,
        parent_window: u64,
        authenticated_process_id: u32,
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        let (Some(provider), Some(state_store)) = (
            self.windows_hello_provider.as_deref(),
            self.windows_hello_state.as_deref(),
        ) else {
            return Ok(ExecutionOutcome::failed());
        };
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let Some(_hello) = FlagPermit::acquire(&self.windows_hello_active) else {
            return Ok(ExecutionOutcome::busy());
        };
        let _hello_gate = lock(&self.windows_hello_gate)?;
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let (permit, binding) = {
            let vault = lock(&self.vault)?;
            let Some(permit) = vault.begin_operation() else {
                return Ok(ExecutionOutcome::locked());
            };
            let Some(binding) = vault.authenticated_vault_binding() else {
                return Ok(ExecutionOutcome::locked());
            };
            (permit, binding)
        };
        let mut previous = match self.load_windows_hello_state(state_store) {
            Ok(state) => Some(state),
            Err(WindowsHelloStateError::NotFound) => {
                if !self.ensure_absent_windows_hello_state(state_store) {
                    return Ok(ExecutionOutcome::retryable_failure());
                }
                None
            }
            Err(
                WindowsHelloStateError::Invalid
                | WindowsHelloStateError::Failed
                | WindowsHelloStateError::Published,
            ) => return Ok(ExecutionOutcome::failed()),
        };
        let recovering_retirement = previous
            .as_ref()
            .is_some_and(|state| state.pending_removal_credential_id().is_some());
        if let Some(state) = previous.as_mut()
            && !self.retry_persisted_windows_hello_retirement(provider, state_store, state)
        {
            return Ok(ExecutionOutcome::retryable_failure());
        }
        if previous
            .as_ref()
            .is_some_and(|state| state.vault_binding().is_none())
        {
            previous = None;
        } else if recovering_retirement
            && previous
                .as_ref()
                .is_some_and(|state| state.vault_binding() == Some(binding))
        {
            if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline)
            {
                return Ok(outcome);
            }
            return Ok(ExecutionOutcome::success(encode_empty_result()?));
        }
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let operation_id = windows_hello_operation_id()?;
        let enrollment =
            self.run_windows_hello_ceremony(provider, operation_id, registration, deadline, || {
                provider.enroll(parent_window, authenticated_process_id, operation_id)
            });
        let enrollment = match enrollment {
            Ok(enrollment) => enrollment,
            Err(WindowsHelloProviderError::CleanupRequired(credential_id)) => {
                return Ok(
                    if self.persist_windows_hello_cleanup(
                        state_store,
                        previous.as_mut(),
                        &credential_id,
                    ) {
                        ExecutionOutcome::retryable_failure()
                    } else {
                        ExecutionOutcome::failed()
                    },
                );
            }
            Err(error) => return Ok(map_windows_hello_provider_error(&error)),
        };
        if let Some(outcome) = self.windows_hello_terminal_abort(registration, deadline) {
            return self.remove_enrollment_or(
                provider,
                state_store,
                previous.as_mut(),
                &enrollment,
                outcome,
            );
        }
        if self.coordinator.epoch() != request_epoch {
            return self.remove_enrollment_or(
                provider,
                state_store,
                previous.as_mut(),
                &enrollment,
                ExecutionOutcome::locked(),
            );
        }

        let mut installation_key = Zeroizing::new([0_u8; 32]);
        if getrandom::fill(&mut *installation_key).is_err() || *installation_key == [0; 32] {
            return self.remove_enrollment_or(
                provider,
                state_store,
                previous.as_mut(),
                &enrollment,
                ExecutionOutcome::failed(),
            );
        }
        let WindowsHelloEnrollment {
            credential_id,
            prf_salt,
            prf_output,
        } = enrollment;
        let protector = {
            let vault = lock(&self.vault)?;
            if !vault.operation_is_authorized(permit)
                || vault.authenticated_vault_binding() != Some(binding)
                || self.coordinator.epoch() != request_epoch
            {
                drop(vault);
                return self.remove_windows_hello_credential_or(
                    provider,
                    state_store,
                    previous.as_mut(),
                    &credential_id,
                    ExecutionOutcome::locked(),
                );
            }
            vault.create_windows_hello_protector(
                &WindowsHelloInstallationKey::from_zeroizing(installation_key.clone()),
                &credential_id,
                prf_salt,
                prf_output,
            )
        };
        let Ok(protector) = protector else {
            return self.remove_windows_hello_credential_or(
                provider,
                state_store,
                previous.as_mut(),
                &credential_id,
                ExecutionOutcome::failed(),
            );
        };
        let Ok(mut local_state) = WindowsHelloLocalState::new(
            binding.0,
            binding.1,
            installation_key,
            credential_id.clone(),
            prf_salt,
            protector,
        ) else {
            return self.remove_windows_hello_credential_or(
                provider,
                state_store,
                previous.as_mut(),
                &credential_id,
                ExecutionOutcome::failed(),
            );
        };
        if let Some(previous_credential_id) = previous
            .as_ref()
            .and_then(WindowsHelloLocalState::credential_id)
            && previous_credential_id != credential_id
            && local_state
                .set_pending_removal_credential_id(previous_credential_id)
                .is_err()
        {
            return self.remove_windows_hello_credential_or(
                provider,
                state_store,
                previous.as_mut(),
                &credential_id,
                ExecutionOutcome::failed(),
            );
        }
        if let Some(outcome) = self.windows_hello_terminal_abort(registration, deadline) {
            return self.remove_windows_hello_credential_or(
                provider,
                state_store,
                previous.as_mut(),
                &credential_id,
                outcome,
            );
        }
        let commit = lock(&self.coordinator.commit_gate)?;
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            drop(commit);
            return self.remove_windows_hello_credential_or(
                provider,
                state_store,
                previous.as_mut(),
                &credential_id,
                outcome,
            );
        }
        match self.save_windows_hello_state(state_store, &local_state) {
            Ok(()) => {}
            Err(WindowsHelloStateError::Published) => {
                // Publication selected the new credential before a later
                // verification or durability failure. Restore the previous
                // complete record before removing the new key when possible;
                // otherwise preserve the key referenced by published state.
                return if let Some(previous) = previous.as_mut() {
                    self.rollback_windows_hello_enrollment(
                        provider,
                        state_store,
                        previous,
                        &local_state,
                    )
                } else {
                    Ok(ExecutionOutcome::retryable_failure())
                };
            }
            Err(
                WindowsHelloStateError::NotFound
                | WindowsHelloStateError::Invalid
                | WindowsHelloStateError::Failed,
            ) => {
                drop(commit);
                let outcome = self
                    .windows_hello_terminal_abort(registration, deadline)
                    .unwrap_or_else(ExecutionOutcome::failed);
                return self.remove_windows_hello_credential_or(
                    provider,
                    state_store,
                    previous.as_mut(),
                    &credential_id,
                    outcome,
                );
            }
        }
        // ADR 0005 requires the complete replacement record, including the
        // crash-recoverable retirement ID, to publish before old credential
        // removal. Clearing that ID is a second durable commit.
        if let Some(pending_removal) = local_state
            .pending_removal_credential_id()
            .map(<[u8]>::to_vec)
        {
            if provider.remove(&pending_removal).is_err() {
                return if let Some(previous) = previous.as_mut() {
                    self.rollback_windows_hello_enrollment(
                        provider,
                        state_store,
                        previous,
                        &local_state,
                    )
                } else {
                    Ok(ExecutionOutcome::retryable_failure())
                };
            }
            if !local_state.clear_pending_removal_credential_id() {
                return Err(DispatchError::Internal);
            }
            match self.save_windows_hello_state(state_store, &local_state) {
                Ok(()) | Err(WindowsHelloStateError::Published) => {}
                Err(
                    WindowsHelloStateError::NotFound
                    | WindowsHelloStateError::Invalid
                    | WindowsHelloStateError::Failed,
                ) => return Ok(ExecutionOutcome::retryable_failure()),
            }
        }
        Ok(ExecutionOutcome::success(encode_empty_result()?).commit_point())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the unlock transition keeps prompt, core authentication, and publication checks explicit"
    )]
    fn unlock_windows_hello(
        &self,
        parent_window: u64,
        authenticated_process_id: u32,
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        let (Some(provider), Some(state_store)) = (
            self.windows_hello_provider.as_deref(),
            self.windows_hello_state.as_deref(),
        ) else {
            return Ok(ExecutionOutcome::failed());
        };
        if self.state() == AgentState::Unlocking {
            return Ok(ExecutionOutcome::busy());
        }
        if self.state() != AgentState::Locked {
            return Ok(ExecutionOutcome::failure(
                PublicErrorCode::Conflict,
                RetryCategory::Never,
            ));
        }
        let Some(_hello) = FlagPermit::acquire(&self.windows_hello_active) else {
            return Ok(ExecutionOutcome::busy());
        };
        let _hello_gate = lock(&self.windows_hello_gate)?;
        let mut local_state = match self.load_windows_hello_state(state_store) {
            Ok(state) => state,
            Err(WindowsHelloStateError::NotFound) => {
                return if self.ensure_absent_windows_hello_state(state_store) {
                    Ok(ExecutionOutcome::failed())
                } else {
                    Ok(ExecutionOutcome::retryable_failure())
                };
            }
            Err(
                WindowsHelloStateError::Invalid
                | WindowsHelloStateError::Failed
                | WindowsHelloStateError::Published,
            ) => return Ok(ExecutionOutcome::failed()),
        };
        if !self.retry_persisted_windows_hello_retirement(provider, state_store, &mut local_state) {
            return Ok(ExecutionOutcome::retryable_failure());
        }
        let (Some(credential_id), Some(prf_salt)) =
            (local_state.credential_id(), local_state.prf_salt())
        else {
            return Ok(ExecutionOutcome::failed());
        };
        let credential_id = credential_id.to_vec();
        let prf_salt = *prf_salt;
        let operation_id = windows_hello_operation_id()?;
        let start_epoch;
        {
            let _commit = lock(&self.coordinator.commit_gate)?;
            if let Some(outcome) = self.windows_hello_terminal_abort(registration, deadline) {
                return Ok(outcome);
            }
            if self.coordinator.epoch() != request_epoch {
                return Ok(ExecutionOutcome::locked());
            }
            start_epoch = self.coordinator.epoch();
            if self
                .state
                .compare_exchange(
                    AgentState::Locked as u8,
                    AgentState::Unlocking as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                return Ok(ExecutionOutcome::failure(
                    PublicErrorCode::Conflict,
                    RetryCategory::Never,
                ));
            }
        }
        let prf_output =
            self.run_windows_hello_ceremony(provider, operation_id, registration, deadline, || {
                provider.evaluate(
                    parent_window,
                    authenticated_process_id,
                    operation_id,
                    &credential_id,
                    &prf_salt,
                )
            });
        let prf_output = match prf_output {
            Ok(output) => output,
            Err(error) => {
                self.set_locked_unless_shutting_down();
                return Ok(map_windows_hello_provider_error(&error));
            }
        };
        if let Some(outcome) = self.windows_hello_terminal_abort(registration, deadline) {
            self.set_locked_unless_shutting_down();
            return Ok(outcome);
        }
        if self.coordinator.epoch() != start_epoch || self.state() != AgentState::Unlocking {
            self.set_locked_unless_shutting_down();
            return Ok(ExecutionOutcome::cancelled());
        }

        let mut authenticated_ownership = None;
        let (result, authenticated_vault_id) = {
            let mut vault = lock(&self.vault)?;
            let Some(installation_key) = local_state.installation_key() else {
                self.set_locked_unless_shutting_down();
                return Ok(ExecutionOutcome::failed());
            };
            let Some(protector) = local_state.protector() else {
                self.set_locked_unless_shutting_down();
                return Ok(ExecutionOutcome::failed());
            };
            let result = vault.unlock_with_windows_hello_before_publish(
                prf_output,
                &installation_key,
                &credential_id,
                protector,
                &registration.cancellation,
                || {
                    authenticated_ownership = ownership_record(&self.vault_path).ok();
                },
            );
            let authenticated_vault_id = result
                .is_ok()
                .then(|| vault.authenticated_vault_id())
                .flatten();
            (result, authenticated_vault_id)
        };
        if let Some(outcome) = self.windows_hello_terminal_abort(registration, deadline) {
            lock(&self.vault)?.lock();
            self.set_locked_unless_shutting_down();
            return Ok(outcome);
        }
        match result {
            Ok(()) => self.publish_authenticated_unlock(
                authenticated_ownership,
                authenticated_vault_id.ok_or(DispatchError::Internal)?,
                registration,
                deadline,
            ),
            Err(UnlockError::Cancelled) => {
                self.set_locked_unless_shutting_down();
                Ok(ExecutionOutcome::cancelled())
            }
            Err(UnlockError::Failed) => {
                self.set_locked_unless_shutting_down();
                Ok(ExecutionOutcome::failed())
            }
        }
    }

    fn remove_windows_hello(
        &self,
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        let (Some(provider), Some(state_store)) = (
            self.windows_hello_provider.as_deref(),
            self.windows_hello_state.as_deref(),
        ) else {
            return Ok(ExecutionOutcome::failed());
        };
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let Some(_hello) = FlagPermit::acquire(&self.windows_hello_active) else {
            return Ok(ExecutionOutcome::busy());
        };
        let _hello_gate = lock(&self.windows_hello_gate)?;
        let mut local_state = match self.load_windows_hello_state(state_store) {
            Ok(state) => state,
            Err(WindowsHelloStateError::NotFound) => {
                return if self.ensure_absent_windows_hello_state(state_store) {
                    Ok(ExecutionOutcome::success(encode_empty_result()?))
                } else {
                    Ok(ExecutionOutcome::retryable_failure())
                };
            }
            Err(
                WindowsHelloStateError::Invalid
                | WindowsHelloStateError::Failed
                | WindowsHelloStateError::Published,
            ) => {
                return Ok(ExecutionOutcome::failed());
            }
        };
        if !self.retry_persisted_windows_hello_retirement(provider, state_store, &mut local_state) {
            return Ok(ExecutionOutcome::retryable_failure());
        }
        let Some(binding) = local_state.vault_binding() else {
            return Ok(ExecutionOutcome::success(encode_empty_result()?));
        };
        let Some(credential_id) = local_state.credential_id().map(<[u8]>::to_vec) else {
            return Err(DispatchError::Internal);
        };
        {
            let vault = lock(&self.vault)?;
            if vault.authenticated_vault_binding() != Some(binding) {
                return Ok(ExecutionOutcome::failed());
            }
        }
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let _commit = lock(&self.coordinator.commit_gate)?;
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        {
            let vault = lock(&self.vault)?;
            if vault.authenticated_vault_binding() != Some(binding) {
                return Ok(ExecutionOutcome::failed());
            }
        }
        if provider.remove(&credential_id).is_err() {
            return Ok(ExecutionOutcome::retryable_failure());
        }
        match self.remove_windows_hello_state(state_store) {
            Ok(()) | Err(WindowsHelloStateError::NotFound) => {
                Ok(ExecutionOutcome::success(encode_empty_result()?).commit_point())
            }
            Err(
                WindowsHelloStateError::Invalid
                | WindowsHelloStateError::Failed
                | WindowsHelloStateError::Published,
            ) => Ok(ExecutionOutcome::retryable_failure()),
        }
    }

    fn run_windows_hello_ceremony<T>(
        &self,
        provider: &dyn WindowsHelloProvider,
        operation_id: [u8; 16],
        registration: &RequestRegistration,
        deadline: Instant,
        ceremony: impl FnOnce() -> Result<T, WindowsHelloProviderError>,
    ) -> Result<T, WindowsHelloProviderError> {
        let finished = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let watcher = scope.spawn(|| {
                while !finished.load(Ordering::Acquire) {
                    if registration.cancellation.is_cancelled()
                        || self.coordinator.lock_active.load(Ordering::Acquire)
                        || Instant::now() >= deadline
                    {
                        provider.cancel(operation_id);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
            let result = ceremony();
            finished.store(true, Ordering::Release);
            let _ = watcher.join();
            result
        })
    }

    fn windows_hello_terminal_abort(
        &self,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Option<ExecutionOutcome> {
        if registration.cancellation.is_cancelled()
            || self.coordinator.lock_active.load(Ordering::Acquire)
        {
            return Some(ExecutionOutcome::cancelled());
        }
        (Instant::now() >= deadline).then(ExecutionOutcome::deadline)
    }

    fn remove_enrollment_or(
        &self,
        provider: &dyn WindowsHelloProvider,
        state_store: &dyn WindowsHelloStateRepository,
        previous: Option<&mut WindowsHelloLocalState>,
        enrollment: &WindowsHelloEnrollment,
        outcome: ExecutionOutcome,
    ) -> Result<ExecutionOutcome, DispatchError> {
        self.remove_windows_hello_credential_or(
            provider,
            state_store,
            previous,
            &enrollment.credential_id,
            outcome,
        )
    }

    #[allow(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        reason = "cleanup stays on the fallible operation boundary shared by every caller"
    )]
    fn remove_windows_hello_credential_or(
        &self,
        provider: &dyn WindowsHelloProvider,
        state_store: &dyn WindowsHelloStateRepository,
        previous: Option<&mut WindowsHelloLocalState>,
        credential_id: &[u8],
        outcome: ExecutionOutcome,
    ) -> Result<ExecutionOutcome, DispatchError> {
        if provider.remove(credential_id).is_ok() {
            return Ok(outcome);
        }
        if self.persist_windows_hello_cleanup(state_store, previous, credential_id) {
            Ok(ExecutionOutcome::retryable_failure())
        } else {
            Ok(ExecutionOutcome::failed())
        }
    }

    fn load_windows_hello_state(
        &self,
        state_store: &dyn WindowsHelloStateRepository,
    ) -> Result<WindowsHelloLocalState, WindowsHelloStateError> {
        let Some(path) = state_store.ownership_path() else {
            return state_store.load();
        };
        let mut owned = owned_vaults()
            .lock()
            .map_err(|_| WindowsHelloStateError::Failed)?;
        self.ownership
            .bind_windows_hello_state(&mut owned, path)
            .map_err(|_| WindowsHelloStateError::Failed)?;
        let result = state_store.load();
        self.ownership
            .bind_windows_hello_state(&mut owned, path)
            .map_err(|_| WindowsHelloStateError::Failed)?;
        result
    }

    fn save_windows_hello_state(
        &self,
        state_store: &dyn WindowsHelloStateRepository,
        state: &WindowsHelloLocalState,
    ) -> Result<(), WindowsHelloStateError> {
        let Some(path) = state_store.ownership_path() else {
            return state_store.save(state);
        };
        let mut owned = owned_vaults()
            .lock()
            .map_err(|_| WindowsHelloStateError::Failed)?;
        self.ownership
            .bind_windows_hello_state(&mut owned, path)
            .map_err(|_| WindowsHelloStateError::Failed)?;
        let result = state_store.save(state);
        let published = matches!(result, Ok(()) | Err(WindowsHelloStateError::Published));
        if self
            .ownership
            .bind_windows_hello_state(&mut owned, path)
            .is_err()
        {
            return Err(if published {
                WindowsHelloStateError::Published
            } else {
                WindowsHelloStateError::Failed
            });
        }
        result
    }

    fn remove_windows_hello_state(
        &self,
        state_store: &dyn WindowsHelloStateRepository,
    ) -> Result<(), WindowsHelloStateError> {
        let Some(path) = state_store.ownership_path() else {
            return state_store.remove();
        };
        let mut owned = owned_vaults()
            .lock()
            .map_err(|_| WindowsHelloStateError::Failed)?;
        self.ownership
            .bind_windows_hello_state(&mut owned, path)
            .map_err(|_| WindowsHelloStateError::Failed)?;
        let result = state_store.remove();
        self.ownership
            .bind_windows_hello_state(&mut owned, path)
            .map_err(|_| WindowsHelloStateError::Failed)?;
        result
    }

    fn persist_windows_hello_cleanup(
        &self,
        state_store: &dyn WindowsHelloStateRepository,
        previous: Option<&mut WindowsHelloLocalState>,
        credential_id: &[u8],
    ) -> bool {
        if let Some(previous) = previous
            && previous.vault_binding().is_some()
        {
            if previous
                .set_pending_removal_credential_id(credential_id)
                .is_err()
            {
                return false;
            }
            return matches!(
                self.save_windows_hello_state(state_store, previous),
                Ok(()) | Err(WindowsHelloStateError::Published)
            );
        }
        let Ok(pending) = WindowsHelloLocalState::pending_removal(credential_id) else {
            return false;
        };
        matches!(
            self.save_windows_hello_state(state_store, &pending),
            Ok(()) | Err(WindowsHelloStateError::Published)
        )
    }

    fn ensure_absent_windows_hello_state(
        &self,
        state_store: &dyn WindowsHelloStateRepository,
    ) -> bool {
        matches!(
            self.remove_windows_hello_state(state_store),
            Ok(()) | Err(WindowsHelloStateError::NotFound)
        )
    }

    fn retry_persisted_windows_hello_retirement(
        &self,
        provider: &dyn WindowsHelloProvider,
        state_store: &dyn WindowsHelloStateRepository,
        state: &mut WindowsHelloLocalState,
    ) -> bool {
        let Some(credential_id) = state.pending_removal_credential_id().map(<[u8]>::to_vec) else {
            return true;
        };
        if provider.remove(&credential_id).is_err() {
            return false;
        }
        if state.clear_pending_removal_credential_id() {
            matches!(
                self.save_windows_hello_state(state_store, state),
                Ok(()) | Err(WindowsHelloStateError::Published)
            )
        } else {
            self.ensure_absent_windows_hello_state(state_store)
        }
    }

    fn rollback_windows_hello_enrollment(
        &self,
        provider: &dyn WindowsHelloProvider,
        state_store: &dyn WindowsHelloStateRepository,
        previous: &mut WindowsHelloLocalState,
        replacement: &WindowsHelloLocalState,
    ) -> Result<ExecutionOutcome, DispatchError> {
        let (Some(previous_credential_id), Some(replacement_credential_id)) =
            (previous.credential_id(), replacement.credential_id())
        else {
            return Ok(ExecutionOutcome::failed());
        };
        if previous_credential_id == replacement_credential_id {
            return Ok(ExecutionOutcome::failed());
        }
        match self.save_windows_hello_state(state_store, previous) {
            Ok(()) | Err(WindowsHelloStateError::Published) => {}
            Err(
                WindowsHelloStateError::NotFound
                | WindowsHelloStateError::Invalid
                | WindowsHelloStateError::Failed,
            ) => return Ok(ExecutionOutcome::failed()),
        }
        let replacement_credential_id = replacement_credential_id.to_vec();
        self.remove_windows_hello_credential_or(
            provider,
            state_store,
            Some(previous),
            &replacement_credential_id,
            ExecutionOutcome::retryable_failure(),
        )
    }

    fn publish_authenticated_unlock(
        &self,
        authenticated_ownership: Option<OwnershipRecord>,
        authenticated_vault_id: [u8; 16],
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        let _commit = lock(&self.coordinator.commit_gate)?;
        if self.coordinator.lock_active.load(Ordering::Acquire)
            || registration.cancellation.is_cancelled()
            || self.state() != AgentState::Unlocking
        {
            lock(&self.vault)?.lock();
            self.set_locked_unless_shutting_down();
            return Ok(ExecutionOutcome::cancelled());
        }
        if Instant::now() >= deadline {
            lock(&self.vault)?.lock();
            self.set_locked_unless_shutting_down();
            return Ok(ExecutionOutcome::deadline());
        }
        let Some(authenticated_ownership) = authenticated_ownership else {
            lock(&self.vault)?.lock();
            self.set_locked_unless_shutting_down();
            return Ok(ExecutionOutcome::failed());
        };
        let mut owned = owned_vaults().lock().map_err(|_| DispatchError::Internal)?;
        if self
            .ownership
            .bind_authenticated(
                &mut owned,
                &self.vault_path,
                &authenticated_ownership,
                || self.bind_authenticated_idempotency_vault(authenticated_vault_id),
            )
            .is_err()
        {
            drop(owned);
            lock(&self.vault)?.lock();
            self.set_locked_unless_shutting_down();
            return Ok(ExecutionOutcome::failed());
        }
        drop(owned);
        self.coordinator.advance_epoch_without_cancellation()?;
        if self
            .state
            .compare_exchange(
                AgentState::Unlocking as u8,
                AgentState::Unlocked as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            lock(&self.vault)?.lock();
            self.set_locked_unless_shutting_down();
            return Ok(ExecutionOutcome::cancelled());
        }
        Ok(ExecutionOutcome::success(encode_status(
            AgentState::Unlocked,
            self.unlock_epoch(),
        )?))
    }

    fn lock_vault(&self) -> Result<ExecutionOutcome, DispatchError> {
        let (lock_transition, target_state) = {
            let _commit = lock(&self.coordinator.commit_gate)?;
            let Some(lock_transition) = FlagPermit::acquire(&self.coordinator.lock_active) else {
                return Ok(ExecutionOutcome::busy());
            };
            let target_state = match self.state() {
                AgentState::NoVault => AgentState::NoVault,
                AgentState::Updating => AgentState::Updating,
                AgentState::ShuttingDown => AgentState::ShuttingDown,
                _ => AgentState::Locked,
            };
            self.state.store(target_state as u8, Ordering::Release);
            self.coordinator.advance_epoch()?;
            (lock_transition, target_state)
        };
        let _creation = lock(&self.coordinator.creation_gate)?;
        let _windows_hello = lock(&self.windows_hello_gate)?;
        lock(&self.vault)?.lock();
        if !matches!(
            self.state(),
            AgentState::Updating | AgentState::ShuttingDown
        ) {
            self.state.store(target_state as u8, Ordering::Release);
        }
        let outcome = ExecutionOutcome::success(encode_empty_result()?).hold_lock_transition();
        lock_transition.handoff();
        Ok(outcome)
    }

    fn set_locked_unless_shutting_down(&self) {
        let _ = self
            .state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                (state != AgentState::Updating as u8 && state != AgentState::ShuttingDown as u8)
                    .then_some(AgentState::Locked as u8)
            });
    }

    fn account_error_after_core(
        &self,
        mut vault: MutexGuard<'_, VaultAgent>,
        error: AccountError,
    ) -> Result<ExecutionOutcome, DispatchError> {
        if error != AccountError::Failed {
            return Ok(map_account_error(error));
        }
        vault.lock();
        drop(vault);
        let _commit = lock(&self.coordinator.commit_gate)?;
        self.set_locked_unless_shutting_down();
        self.coordinator.advance_epoch()?;
        Ok(ExecutionOutcome::failed())
    }

    fn authenticated_read_error_after_core(
        &self,
        mut vault: MutexGuard<'_, VaultAgent>,
        error: AccountError,
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        if error == AccountError::Failed {
            return self.account_error_after_core(vault, error);
        }
        if let Some(outcome) =
            self.post_secret_operation(&mut vault, request_epoch, registration, deadline)
        {
            return Ok(outcome);
        }
        Ok(map_account_error(error))
    }

    fn list_accounts(
        &self,
        offset: u32,
        limit: u16,
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let response_offset = offset;
        let offset = usize::try_from(offset).map_err(|_| DispatchError::Internal)?;
        let limit = usize::from(limit);
        let mut vault = lock(&self.vault)?;
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let result = vault.list_website_account_page_with_check(offset, limit, || {
            self.secret_operation_should_abort(request_epoch, registration, deadline)
        });
        let (accounts, has_more) = match result {
            Ok(page) => page,
            Err(AccountError::Aborted) => {
                return self.abort_after_core(&mut vault, request_epoch, registration, deadline);
            }
            Err(error) => {
                return self.authenticated_read_error_after_core(
                    vault,
                    error,
                    request_epoch,
                    registration,
                    deadline,
                );
            }
        };
        if let Some(outcome) =
            self.post_secret_operation(&mut vault, request_epoch, registration, deadline)
        {
            drop(accounts);
            return Ok(outcome);
        }
        let views: Vec<_> = accounts.iter().map(account_view).collect();
        Self::encode_summary_page(&views, response_offset, has_more)
    }

    fn get_account(
        &self,
        id: [u8; 16],
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let mut vault = lock(&self.vault)?;
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let account = match vault.get_website_account_with_check(RecordId::from_bytes(id), || {
            self.secret_operation_should_abort(request_epoch, registration, deadline)
        }) {
            Ok(account) => account,
            Err(AccountError::Aborted) => {
                return self.abort_after_core(&mut vault, request_epoch, registration, deadline);
            }
            Err(error) => {
                return self.authenticated_read_error_after_core(
                    vault,
                    error,
                    request_epoch,
                    registration,
                    deadline,
                );
            }
        };
        if let Some(outcome) =
            self.post_secret_operation(&mut vault, request_epoch, registration, deadline)
        {
            drop(account);
            return Ok(outcome);
        }
        Ok(ExecutionOutcome::success(encode_account(&account_view(
            &account,
        ))?))
    }

    fn add_account(
        &self,
        fields: &librarian_agent_protocol::AccountFields,
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        let Some(_mutation) = FlagPermit::acquire(&self.coordinator.mutation_active) else {
            return Ok(ExecutionOutcome::busy());
        };
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let Ok(input) = account_input(fields) else {
            return Ok(ExecutionOutcome::invalid());
        };
        let coordinator = Arc::clone(&self.coordinator);
        let cancellation = Arc::clone(&registration.cancellation);
        let mut commit_guard = None;
        let mut vault = lock(&self.vault)?;
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let result = vault.add_website_account_with_before_commit_and_check(
            input,
            || self.secret_operation_should_abort(request_epoch, registration, deadline),
            || {
                let guard = coordinator
                    .commit_gate
                    .lock()
                    .map_err(|_| crate::errors::StorageError::Conflict)?;
                if coordinator.epoch() != request_epoch
                    || coordinator.lock_active.load(Ordering::Acquire)
                    || cancellation.is_cancelled()
                    || Instant::now() >= deadline
                {
                    return Err(crate::errors::StorageError::Aborted);
                }
                commit_guard = Some(guard);
                Ok(())
            },
        );
        release_failed_commit_guard(&result, &mut commit_guard);
        match result {
            Ok(id) => Ok(ExecutionOutcome::success(encode_account_id(
                *id.as_bytes(),
            )?)),
            Err(AccountError::Aborted) => {
                self.abort_after_core(&mut vault, request_epoch, registration, deadline)
            }
            Err(AccountError::Failed) => self.account_error_after_core(vault, AccountError::Failed),
            Err(error) => {
                if let Some(outcome) =
                    self.post_secret_operation(&mut vault, request_epoch, registration, deadline)
                {
                    return Ok(outcome);
                }
                Ok(map_account_error(error))
            }
        }
    }

    fn update_account(
        &self,
        id: [u8; 16],
        fields: &librarian_agent_protocol::AccountFields,
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        let Some(_mutation) = FlagPermit::acquire(&self.coordinator.mutation_active) else {
            return Ok(ExecutionOutcome::busy());
        };
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let Ok(input) = account_input(fields) else {
            return Ok(ExecutionOutcome::invalid());
        };
        let coordinator = Arc::clone(&self.coordinator);
        let cancellation = Arc::clone(&registration.cancellation);
        let mut commit_guard = None;
        let mut vault = lock(&self.vault)?;
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let result = vault.update_website_account_with_before_commit_and_check(
            RecordId::from_bytes(id),
            input,
            || self.secret_operation_should_abort(request_epoch, registration, deadline),
            || {
                let guard = coordinator
                    .commit_gate
                    .lock()
                    .map_err(|_| crate::errors::StorageError::Conflict)?;
                if coordinator.epoch() != request_epoch
                    || coordinator.lock_active.load(Ordering::Acquire)
                    || cancellation.is_cancelled()
                    || Instant::now() >= deadline
                {
                    return Err(crate::errors::StorageError::Aborted);
                }
                commit_guard = Some(guard);
                Ok(())
            },
        );
        release_failed_commit_guard(&result, &mut commit_guard);
        match result {
            Ok(()) => Ok(ExecutionOutcome::success(encode_empty_result()?)),
            Err(AccountError::Aborted) => {
                self.abort_after_core(&mut vault, request_epoch, registration, deadline)
            }
            Err(AccountError::Failed) => self.account_error_after_core(vault, AccountError::Failed),
            Err(error) => {
                if let Some(outcome) =
                    self.post_secret_operation(&mut vault, request_epoch, registration, deadline)
                {
                    return Ok(outcome);
                }
                Ok(map_account_error(error))
            }
        }
    }

    fn delete_account(
        &self,
        id: [u8; 16],
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        let Some(_mutation) = FlagPermit::acquire(&self.coordinator.mutation_active) else {
            return Ok(ExecutionOutcome::busy());
        };
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let coordinator = Arc::clone(&self.coordinator);
        let cancellation = Arc::clone(&registration.cancellation);
        let mut commit_guard = None;
        let mut vault = lock(&self.vault)?;
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let result = vault.delete_website_account_with_before_commit_and_check(
            RecordId::from_bytes(id),
            || self.secret_operation_should_abort(request_epoch, registration, deadline),
            || {
                let guard = coordinator
                    .commit_gate
                    .lock()
                    .map_err(|_| crate::errors::StorageError::Conflict)?;
                if coordinator.epoch() != request_epoch
                    || coordinator.lock_active.load(Ordering::Acquire)
                    || cancellation.is_cancelled()
                    || Instant::now() >= deadline
                {
                    return Err(crate::errors::StorageError::Aborted);
                }
                commit_guard = Some(guard);
                Ok(())
            },
        );
        release_failed_commit_guard(&result, &mut commit_guard);
        match result {
            Ok(()) => Ok(ExecutionOutcome::success(encode_empty_result()?)),
            Err(AccountError::Aborted) => {
                self.abort_after_core(&mut vault, request_epoch, registration, deadline)
            }
            Err(AccountError::Failed) => self.account_error_after_core(vault, AccountError::Failed),
            Err(error) => {
                if let Some(outcome) =
                    self.post_secret_operation(&mut vault, request_epoch, registration, deadline)
                {
                    return Ok(outcome);
                }
                Ok(map_account_error(error))
            }
        }
    }

    fn make_passkey(
        &self,
        proof: &PasskeyTransactionProof,
        connection_id: [u8; 16],
        authenticated_process_id: u32,
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let verified = match self.passkey_verifier.verify_make(proof) {
            Ok(verified) => verified,
            Err(error) => return Ok(map_passkey_verification_error(error)),
        };
        let pending_key = PendingPasskeyCreationKey {
            connection_id,
            transaction_id: *proof.transaction_id(),
        };
        if lock(&self.pending_passkey_creations)?.contains_key(&pending_key) {
            return Ok(ExecutionOutcome::invalid());
        }
        let Some(_mutation) = FlagPermit::acquire(&self.coordinator.mutation_active) else {
            return Ok(ExecutionOutcome::busy());
        };
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let Ok(input) = PasskeyInput::new(
            verified.rp_id(),
            verified.user_handle(),
            verified.user_name(),
            verified.user_display_name(),
        ) else {
            return Ok(ExecutionOutcome::invalid());
        };
        let coordinator = Arc::clone(&self.coordinator);
        let cancellation = Arc::clone(&registration.cancellation);
        let mut commit_guard = None;
        let mut vault = lock(&self.vault)?;
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let result = vault.add_passkey_with_before_commit_and_check(
            input,
            verified.excluded_credential_ids(),
            || self.secret_operation_should_abort(request_epoch, registration, deadline),
            || {
                let guard = coordinator
                    .commit_gate
                    .lock()
                    .map_err(|_| crate::errors::StorageError::Conflict)?;
                if coordinator.epoch() != request_epoch
                    || coordinator.lock_active.load(Ordering::Acquire)
                    || cancellation.is_cancelled()
                    || Instant::now() >= deadline
                {
                    return Err(crate::errors::StorageError::Aborted);
                }
                commit_guard = Some(guard);
                Ok(())
            },
        );
        release_failed_commit_guard(&result, &mut commit_guard);
        match result {
            Ok(credential) => {
                let pending = PendingPasskeyCreation {
                    credential_id: *credential.credential_id(),
                    authenticated_process_id,
                    unlock_epoch: request_epoch,
                };
                if lock(&self.pending_passkey_creations)?
                    .insert(pending_key, pending)
                    .is_some()
                {
                    return Err(DispatchError::Internal);
                }
                Ok(
                    ExecutionOutcome::success(encode_passkey_credential(&PasskeyCredentialView {
                        credential_id: *credential.credential_id(),
                        user_handle: credential.user_handle(),
                        public_key: *credential.public_key(),
                    })?)
                    .commit_point(),
                )
            }
            Err(AccountError::Aborted) => {
                self.abort_after_core(&mut vault, request_epoch, registration, deadline)
            }
            Err(AccountError::Failed) => self.account_error_after_core(vault, AccountError::Failed),
            Err(error) => {
                if let Some(outcome) =
                    self.post_secret_operation(&mut vault, request_epoch, registration, deadline)
                {
                    return Ok(outcome);
                }
                Ok(map_account_error(error))
            }
        }
    }

    fn get_passkey_assertion(
        &self,
        proof: &PasskeyTransactionProof,
        credential_id: &[u8; 32],
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let verified = match self.passkey_verifier.verify_assertion(proof, credential_id) {
            Ok(verified) => verified,
            Err(error) => return Ok(map_passkey_verification_error(error)),
        };
        let Some(_mutation) = FlagPermit::acquire(&self.coordinator.mutation_active) else {
            return Ok(ExecutionOutcome::busy());
        };
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let coordinator = Arc::clone(&self.coordinator);
        let cancellation = Arc::clone(&registration.cancellation);
        let mut commit_guard = None;
        let mut vault = lock(&self.vault)?;
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let result = vault.sign_passkey_assertion_with_before_commit_and_check(
            verified.rp_id(),
            credential_id,
            verified.client_data_hash(),
            || self.secret_operation_should_abort(request_epoch, registration, deadline),
            || {
                let guard = coordinator
                    .commit_gate
                    .lock()
                    .map_err(|_| crate::errors::StorageError::Conflict)?;
                if coordinator.epoch() != request_epoch
                    || coordinator.lock_active.load(Ordering::Acquire)
                    || cancellation.is_cancelled()
                    || Instant::now() >= deadline
                {
                    return Err(crate::errors::StorageError::Aborted);
                }
                commit_guard = Some(guard);
                Ok(())
            },
        );
        release_failed_commit_guard(&result, &mut commit_guard);
        match result {
            Ok(assertion) => Ok(ExecutionOutcome::success(encode_passkey_assertion(
                &PasskeyAssertionView {
                    credential_id: *assertion.credential_id(),
                    user_handle: assertion.user_handle(),
                    authenticator_data: *assertion.authenticator_data(),
                    signature_der: assertion.signature_der(),
                },
            )?)
            .commit_point()),
            Err(AccountError::Aborted) => {
                self.abort_after_core(&mut vault, request_epoch, registration, deadline)
            }
            Err(AccountError::Failed) => self.account_error_after_core(vault, AccountError::Failed),
            Err(error) => {
                if let Some(outcome) =
                    self.post_secret_operation(&mut vault, request_epoch, registration, deadline)
                {
                    return Ok(outcome);
                }
                Ok(map_account_error(error))
            }
        }
    }

    fn list_passkeys_for_assertion(
        &self,
        proof: &PasskeyRequestProof,
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let verified = match self.passkey_verifier.verify_assertion_lookup(proof) {
            Ok(verified) => verified,
            Err(error) => return Ok(map_passkey_verification_error(error)),
        };
        let mut vault = lock(&self.vault)?;
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let passkeys = match vault.list_passkeys_for_assertion_with_check(
            verified.rp_id(),
            verified.allowed_credential_ids(),
            verified.allow_list_present(),
            || self.secret_operation_should_abort(request_epoch, registration, deadline),
        ) {
            Ok(passkeys) => passkeys,
            Err(AccountError::Aborted) => {
                return self.abort_after_core(&mut vault, request_epoch, registration, deadline);
            }
            Err(error) => {
                return self.authenticated_read_error_after_core(
                    vault,
                    error,
                    request_epoch,
                    registration,
                    deadline,
                );
            }
        };
        if let Some(outcome) =
            self.post_secret_operation(&mut vault, request_epoch, registration, deadline)
        {
            drop(passkeys);
            return Ok(outcome);
        }
        let views: Vec<_> = passkeys
            .iter()
            .map(|passkey| PasskeySummaryView {
                credential_id: *passkey.credential_id(),
                user_handle: passkey.user_handle(),
                user_name: passkey.user_name(),
                user_display_name: passkey.user_display_name(),
            })
            .collect();
        Ok(ExecutionOutcome::success(encode_passkey_summaries(&views)?))
    }

    fn list_passkeys(
        &self,
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let mut vault = lock(&self.vault)?;
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let passkeys = match vault.list_passkeys_with_check(|| {
            self.secret_operation_should_abort(request_epoch, registration, deadline)
        }) {
            Ok(passkeys) => passkeys,
            Err(AccountError::Aborted) => {
                return self.abort_after_core(&mut vault, request_epoch, registration, deadline);
            }
            Err(error) => {
                return self.authenticated_read_error_after_core(
                    vault,
                    error,
                    request_epoch,
                    registration,
                    deadline,
                );
            }
        };
        if let Some(outcome) =
            self.post_secret_operation(&mut vault, request_epoch, registration, deadline)
        {
            drop(passkeys);
            return Ok(outcome);
        }
        let views: Vec<_> = passkeys
            .iter()
            .map(|passkey| PasskeyManagementSummaryView {
                credential_id: *passkey.credential_id(),
                rp_id: passkey.rp_id(),
                user_name: passkey.user_name(),
                user_display_name: passkey.user_display_name(),
            })
            .collect();
        Ok(ExecutionOutcome::success(
            encode_passkey_management_summaries(&views)?,
        ))
    }

    fn delete_passkey(
        &self,
        credential_id: &[u8; 32],
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        let Some(_mutation) = FlagPermit::acquire(&self.coordinator.mutation_active) else {
            return Ok(ExecutionOutcome::busy());
        };
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let coordinator = Arc::clone(&self.coordinator);
        let cancellation = Arc::clone(&registration.cancellation);
        let mut commit_guard = None;
        let mut vault = lock(&self.vault)?;
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let result = vault.delete_passkey_with_before_commit_and_check(
            credential_id,
            || self.secret_operation_should_abort(request_epoch, registration, deadline),
            || {
                let guard = coordinator
                    .commit_gate
                    .lock()
                    .map_err(|_| crate::errors::StorageError::Conflict)?;
                if coordinator.epoch() != request_epoch
                    || coordinator.lock_active.load(Ordering::Acquire)
                    || cancellation.is_cancelled()
                    || Instant::now() >= deadline
                {
                    return Err(crate::errors::StorageError::Aborted);
                }
                commit_guard = Some(guard);
                Ok(())
            },
        );
        release_failed_commit_guard(&result, &mut commit_guard);
        match result {
            Ok(()) => Ok(ExecutionOutcome::success(encode_empty_result()?).commit_point()),
            Err(AccountError::Aborted) => {
                self.abort_after_core(&mut vault, request_epoch, registration, deadline)
            }
            Err(AccountError::Failed) => self.account_error_after_core(vault, AccountError::Failed),
            Err(error) => {
                if let Some(outcome) =
                    self.post_secret_operation(&mut vault, request_epoch, registration, deadline)
                {
                    return Ok(outcome);
                }
                Ok(map_account_error(error))
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "transaction, peer, epoch, cancellation, and deadline bindings remain explicit"
    )]
    fn rollback_passkey_creation(
        &self,
        proof: &PasskeyTransactionProof,
        credential_id: &[u8; 32],
        connection_id: [u8; 16],
        authenticated_process_id: u32,
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        if let Err(error) = self.passkey_verifier.verify_make(proof) {
            return Ok(map_passkey_verification_error(error));
        }
        let pending_key = PendingPasskeyCreationKey {
            connection_id,
            transaction_id: *proof.transaction_id(),
        };
        let expected = PendingPasskeyCreation {
            credential_id: *credential_id,
            authenticated_process_id,
            unlock_epoch: request_epoch,
        };
        if lock(&self.pending_passkey_creations)?.get(&pending_key) != Some(&expected) {
            return Ok(ExecutionOutcome::invalid());
        }
        let Some(_mutation) = FlagPermit::acquire(&self.coordinator.mutation_active) else {
            return Ok(ExecutionOutcome::busy());
        };
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let coordinator = Arc::clone(&self.coordinator);
        let cancellation = Arc::clone(&registration.cancellation);
        let mut commit_guard = None;
        let mut vault = lock(&self.vault)?;
        if let Some(outcome) = self.pre_secret_operation(request_epoch, registration, deadline) {
            return Ok(outcome);
        }
        let result = vault.delete_passkey_with_before_commit_and_check(
            credential_id,
            || self.secret_operation_should_abort(request_epoch, registration, deadline),
            || {
                let guard = coordinator
                    .commit_gate
                    .lock()
                    .map_err(|_| crate::errors::StorageError::Conflict)?;
                if coordinator.epoch() != request_epoch
                    || coordinator.lock_active.load(Ordering::Acquire)
                    || cancellation.is_cancelled()
                    || Instant::now() >= deadline
                {
                    return Err(crate::errors::StorageError::Aborted);
                }
                commit_guard = Some(guard);
                Ok(())
            },
        );
        release_failed_commit_guard(&result, &mut commit_guard);
        match result {
            Ok(()) | Err(AccountError::NotFound) => {
                let removed = lock(&self.pending_passkey_creations)?.remove(&pending_key);
                if removed.is_some_and(|pending| pending != expected) {
                    return Err(DispatchError::Internal);
                }
                Ok(ExecutionOutcome::success(encode_empty_result()?).commit_point())
            }
            Err(AccountError::Aborted) => {
                self.abort_after_core(&mut vault, request_epoch, registration, deadline)
            }
            Err(AccountError::Failed) => self.account_error_after_core(vault, AccountError::Failed),
            Err(error) => {
                if let Some(outcome) =
                    self.post_secret_operation(&mut vault, request_epoch, registration, deadline)
                {
                    return Ok(outcome);
                }
                Ok(map_account_error(error))
            }
        }
    }

    fn abort_after_core(
        &self,
        vault: &mut VaultAgent,
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        self.post_secret_operation(vault, request_epoch, registration, deadline)
            .ok_or(DispatchError::Internal)
    }

    fn secret_operation_should_abort(
        &self,
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> bool {
        self.coordinator.lock_active.load(Ordering::Acquire)
            || registration.cancellation.is_cancelled()
            || Instant::now() >= deadline
            || self.state() != AgentState::Unlocked
            || self.coordinator.epoch() != request_epoch
    }

    fn pre_secret_operation(
        &self,
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Option<ExecutionOutcome> {
        if self.coordinator.lock_active.load(Ordering::Acquire) {
            Some(ExecutionOutcome::locked())
        } else if registration.cancellation.is_cancelled() {
            Some(ExecutionOutcome::cancelled())
        } else if Instant::now() >= deadline {
            Some(ExecutionOutcome::deadline())
        } else if self.state() != AgentState::Unlocked || self.coordinator.epoch() != request_epoch
        {
            Some(ExecutionOutcome::locked())
        } else {
            None
        }
    }

    fn post_secret_operation(
        &self,
        vault: &mut VaultAgent,
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Option<ExecutionOutcome> {
        if self.coordinator.lock_active.load(Ordering::Acquire)
            || self.state() != AgentState::Unlocked
            || self.coordinator.epoch() != request_epoch
        {
            vault.lock();
            self.set_locked_unless_shutting_down();
            Some(ExecutionOutcome::locked())
        } else if registration.cancellation.is_cancelled() {
            Some(ExecutionOutcome::cancelled())
        } else if Instant::now() >= deadline {
            Some(ExecutionOutcome::deadline())
        } else {
            None
        }
    }

    fn encode_summary_page(
        views: &[AccountView<'_>],
        offset: u32,
        source_has_more: bool,
    ) -> Result<ExecutionOutcome, DispatchError> {
        if views.is_empty() {
            if source_has_more {
                return Ok(ExecutionOutcome::failed());
            }
            return encode_account_summaries(views, None)
                .map(ExecutionOutcome::success)
                .map_err(DispatchError::from);
        }

        let mut lower = 1_usize;
        let mut upper = views.len();
        let mut best = None;
        while lower <= upper {
            let count = lower + (upper - lower) / 2;
            let has_more = source_has_more || count < views.len();
            let next_offset = if has_more {
                Some(
                    offset
                        .checked_add(u32::try_from(count).map_err(|_| DispatchError::Internal)?)
                        .ok_or(DispatchError::Internal)?,
                )
            } else {
                None
            };
            match encode_account_summaries(&views[..count], next_offset) {
                Ok(body) => {
                    best = Some(body);
                    lower = count + 1;
                }
                Err(ProtocolError::TooLarge) => {
                    upper = count - 1;
                }
                Err(_) => return Err(DispatchError::Internal),
            }
        }
        Ok(best.map_or_else(ExecutionOutcome::failed, ExecutionOutcome::success))
    }

    fn initialize_idempotency_vault(
        &self,
        authenticated_vault_id: [u8; 16],
    ) -> Result<(), DispatchError> {
        let mut state = lock(&self.idempotency)?;
        match state.authenticated_vault_id {
            Some(current) if current != authenticated_vault_id => {
                return Err(DispatchError::Internal);
            }
            Some(_) => {}
            None => {
                state.cached.clear();
                state.insertion_order.clear();
                state.authenticated_vault_id = Some(authenticated_vault_id);
            }
        }
        Ok(())
    }

    fn bind_authenticated_idempotency_vault(
        &self,
        authenticated_vault_id: [u8; 16],
    ) -> Result<(), DispatchError> {
        let mut state = lock(&self.idempotency)?;
        if state.authenticated_vault_id == Some(authenticated_vault_id) {
            return Ok(());
        }
        if !state.in_flight.is_empty() {
            return Err(DispatchError::Internal);
        }
        state.cached.clear();
        state.insertion_order.clear();
        state.authenticated_vault_id = Some(authenticated_vault_id);
        Ok(())
    }
}

impl Drop for AgentRuntime {
    fn drop(&mut self) {
        if let Ok(vault) = self.vault.get_mut() {
            vault.lock();
        }
        let _ = &self.ownership;
    }
}

struct IdempotencyReservation<'a> {
    state: &'a Mutex<IdempotencyState>,
    key: [u8; 16],
    active: bool,
}

impl IdempotencyReservation<'_> {
    fn complete(mut self, cached: Option<CachedOutcome>) -> Result<(), DispatchError> {
        let mut state = lock(self.state)?;
        if !state.in_flight.remove(&self.key) {
            return Err(DispatchError::Internal);
        }
        if let Some(cached) = cached {
            if state.cached.insert(self.key, cached).is_some() {
                return Err(DispatchError::Internal);
            }
            state.insertion_order.push_back(self.key);
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for IdempotencyReservation<'_> {
    fn drop(&mut self) {
        if self.active
            && let Ok(mut state) = self.state.lock()
        {
            state.in_flight.remove(&self.key);
        }
    }
}

struct ExecutionOutcome {
    error: Option<PublicErrorCode>,
    retry: RetryCategory,
    body: Zeroizing<Vec<u8>>,
    replayed: bool,
    holds_lock_transition: bool,
    committed: bool,
}

impl ExecutionOutcome {
    fn success(body: Zeroizing<Vec<u8>>) -> Self {
        Self {
            error: None,
            retry: RetryCategory::Never,
            body,
            replayed: false,
            holds_lock_transition: false,
            committed: false,
        }
    }

    fn failure(error: PublicErrorCode, retry: RetryCategory) -> Self {
        Self {
            error: Some(error),
            retry,
            body: Zeroizing::new(Vec::new()),
            replayed: false,
            holds_lock_transition: false,
            committed: false,
        }
    }

    fn commit_point(mut self) -> Self {
        self.committed = true;
        self
    }

    fn hold_lock_transition(mut self) -> Self {
        self.holds_lock_transition = true;
        self
    }

    fn invalid() -> Self {
        Self::failure(PublicErrorCode::InvalidRequest, RetryCategory::Never)
    }

    fn locked() -> Self {
        Self::failure(PublicErrorCode::Locked, RetryCategory::AfterUnlock)
    }

    fn busy() -> Self {
        Self::failure(PublicErrorCode::Busy, RetryCategory::Backoff)
    }

    fn cancelled() -> Self {
        Self::failure(PublicErrorCode::Cancelled, RetryCategory::Never)
    }

    fn deadline() -> Self {
        Self::failure(PublicErrorCode::DeadlineExceeded, RetryCategory::Never)
    }

    fn failed() -> Self {
        Self::failure(PublicErrorCode::OperationFailed, RetryCategory::Never)
    }

    fn retryable_failure() -> Self {
        Self::failure(PublicErrorCode::OperationFailed, RetryCategory::Backoff)
    }

    fn into_response(self, correlation: CorrelationId) -> Result<ResponseEnvelope, DispatchError> {
        if let Some(error) = self.error {
            return ResponseEnvelope::failure(error, self.retry, correlation)
                .map_err(DispatchError::from);
        }
        ResponseEnvelope::success(correlation, self.body).map_err(|_| DispatchError::Internal)
    }
}

impl From<ProtocolError> for DispatchError {
    fn from(_: ProtocolError) -> Self {
        Self::Internal
    }
}

fn map_operation_decode_error(error: ProtocolError) -> ExecutionOutcome {
    if error == ProtocolError::Unsupported {
        ExecutionOutcome::failed()
    } else {
        ExecutionOutcome::invalid()
    }
}

fn map_account_error(error: AccountError) -> ExecutionOutcome {
    match error {
        AccountError::Locked => ExecutionOutcome::locked(),
        AccountError::NotFound => {
            ExecutionOutcome::failure(PublicErrorCode::NotFound, RetryCategory::Never)
        }
        AccountError::Conflict => {
            ExecutionOutcome::failure(PublicErrorCode::Conflict, RetryCategory::Never)
        }
        AccountError::Aborted | AccountError::Failed => ExecutionOutcome::failed(),
    }
}

fn map_passkey_verification_error(error: PasskeyVerificationError) -> ExecutionOutcome {
    match error {
        #[cfg(any(windows, test))]
        PasskeyVerificationError::Invalid => ExecutionOutcome::invalid(),
        PasskeyVerificationError::Unavailable => ExecutionOutcome::failed(),
        #[cfg(any(windows, test))]
        PasskeyVerificationError::Failed => ExecutionOutcome::failed(),
    }
}

fn map_windows_hello_provider_error(error: &WindowsHelloProviderError) -> ExecutionOutcome {
    match error {
        WindowsHelloProviderError::InvalidRequest => ExecutionOutcome::invalid(),
        WindowsHelloProviderError::Cancelled => ExecutionOutcome::cancelled(),
        WindowsHelloProviderError::Unavailable
        | WindowsHelloProviderError::Failed
        | WindowsHelloProviderError::RemovalFailed
        | WindowsHelloProviderError::CleanupRequired(_) => ExecutionOutcome::failed(),
    }
}

fn windows_hello_operation_id() -> Result<[u8; 16], DispatchError> {
    let mut value = [0_u8; 16];
    getrandom::fill(&mut value).map_err(|_| DispatchError::Internal)?;
    if value == [0; 16] {
        return Err(DispatchError::Internal);
    }
    Ok(value)
}

fn account_input(
    fields: &librarian_agent_protocol::AccountFields,
) -> Result<WebsiteAccountInput, ()> {
    WebsiteAccountInput::new(
        fields.service_name(),
        fields.permitted_origin(),
        fields.username(),
        fields.password(),
    )
    .map_err(|_| ())
}

fn account_view(account: &WebsiteAccount) -> AccountView<'_> {
    AccountView {
        id: *account.id().as_bytes(),
        revision: account.revision(),
        created_at_ms: account.created_at_ms(),
        modified_at_ms: account.modified_at_ms(),
        service_name: account.service_name(),
        permitted_origin: account.permitted_origin(),
        username: account.username(),
        password: account.password(),
    }
}

fn correlation_id() -> Result<CorrelationId, DispatchError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| DispatchError::Internal)?;
    if bytes == [0; 16] {
        return Err(DispatchError::Internal);
    }
    Ok(CorrelationId::new(bytes))
}

fn request_deadline(started: Instant, effective_timeout_ms: u32) -> Result<Instant, DispatchError> {
    started
        .checked_add(Duration::from_millis(u64::from(effective_timeout_ms)))
        .ok_or(DispatchError::Internal)
}

fn should_cache(outcome: &ExecutionOutcome) -> bool {
    outcome.error.is_none()
        || matches!(
            outcome.error,
            Some(
                PublicErrorCode::InvalidRequest
                    | PublicErrorCode::NotFound
                    | PublicErrorCode::Conflict
            )
        )
        || outcome.error == Some(PublicErrorCode::OperationFailed)
            && outcome.retry == RetryCategory::Never
}

fn decode_state(value: u8) -> AgentState {
    match value {
        value if value == AgentState::Starting as u8 => AgentState::Starting,
        value if value == AgentState::NoVault as u8 => AgentState::NoVault,
        value if value == AgentState::Locked as u8 => AgentState::Locked,
        value if value == AgentState::Unlocking as u8 => AgentState::Unlocking,
        value if value == AgentState::Unlocked as u8 => AgentState::Unlocked,
        value if value == AgentState::Updating as u8 => AgentState::Updating,
        value if value == AgentState::ShuttingDown as u8 => AgentState::ShuttingDown,
        _ => AgentState::ShuttingDown,
    }
}

fn ownership_record(path: &Path) -> Result<OwnershipRecord, RuntimeStartError> {
    match fs::metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() {
                return Err(RuntimeStartError::InvalidVaultPath);
            }
            let normalized_path = path
                .canonicalize()
                .map_err(|_| RuntimeStartError::InvalidVaultPath)?;
            #[cfg(windows)]
            let normalized_path = normalize_ownership_path(normalized_path)?;
            #[cfg(not(windows))]
            let normalized_path = normalize_ownership_path(normalized_path);
            #[cfg(windows)]
            let identity = file_identity(path, &metadata)?;
            #[cfg(unix)]
            let identity = file_identity(path, &metadata);
            #[cfg(not(any(windows, unix)))]
            let identity = return Err(RuntimeStartError::InvalidVaultPath);
            Ok(OwnershipRecord {
                normalized_path,
                identity: Some(identity),
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if fs::symlink_metadata(path).is_ok() {
                return Err(RuntimeStartError::InvalidVaultPath);
            }
            let parent = path.parent().ok_or(RuntimeStartError::InvalidVaultPath)?;
            let name = path
                .file_name()
                .ok_or(RuntimeStartError::InvalidVaultPath)?;
            let parent = parent
                .canonicalize()
                .map_err(|_| RuntimeStartError::InvalidVaultPath)?;
            #[cfg(windows)]
            let normalized_path = normalize_ownership_path(parent.join(name))?;
            #[cfg(not(windows))]
            let normalized_path = normalize_ownership_path(parent.join(name));
            Ok(OwnershipRecord {
                normalized_path,
                identity: None,
            })
        }
        Err(_) => Err(RuntimeStartError::InvalidVaultPath),
    }
}

#[cfg(windows)]
fn normalize_ownership_path(path: PathBuf) -> Result<PathBuf, RuntimeStartError> {
    let path = path
        .into_os_string()
        .into_string()
        .map_err(|_| RuntimeStartError::InvalidVaultPath)?;
    Ok(PathBuf::from(path.to_lowercase()))
}

#[cfg(not(windows))]
fn normalize_ownership_path(path: PathBuf) -> PathBuf {
    path
}

#[cfg(windows)]
fn file_identity(path: &Path, _: &fs::Metadata) -> Result<FileIdentity, RuntimeStartError> {
    same_file::Handle::from_path(path)
        .map(FileIdentity)
        .map_err(|_| RuntimeStartError::InvalidVaultPath)
}

#[cfg(unix)]
fn file_identity(_: &Path, metadata: &fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;

    FileIdentity {
        volume: metadata.dev(),
        file: metadata.ino(),
    }
}

fn next_ownership_token() -> Result<u64, RuntimeStartError> {
    static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
    NEXT_TOKEN
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |token| {
            token.checked_add(1)
        })
        .map_err(|_| RuntimeStartError::Internal)
}

fn owned_vaults() -> &'static Mutex<BTreeMap<u64, RuntimeOwnership>> {
    static OWNED: OnceLock<Mutex<BTreeMap<u64, RuntimeOwnership>>> = OnceLock::new();
    OWNED.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, DispatchError> {
    mutex.lock().map_err(|_| DispatchError::Internal)
}

fn release_failed_commit_guard<T, E>(
    result: &Result<T, E>,
    commit_guard: &mut Option<MutexGuard<'_, ()>>,
) {
    if result.is_err() {
        drop(commit_guard.take());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use librarian_agent_protocol::{
        CURRENT_VERSION, ClientHello, ClientRole, ConnectionLimits, FEATURE_PASSKEY_PROVIDER,
        MessageKind,
    };
    use minicbor::Decoder;

    static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(1);
    const TEST_BUILD_ID: [u8; 32] = [0xB4; 32];
    const TEST_HELLO_PRF: [u8; 32] = [0x63; 32];
    const TEST_HELLO_SALT: [u8; 32] = [0x52; 32];
    const TEST_PASSKEY_USER_HANDLE: [u8; 16] = [0x42; 16];
    const TEST_PASSKEY_CLIENT_DATA_HASH: [u8; 32] = [0xA5; 32];

    #[derive(Default)]
    struct TestPasskeyRequestVerifier {
        calls: AtomicUsize,
    }

    impl TestPasskeyRequestVerifier {
        fn calls(&self) -> usize {
            self.calls.load(Ordering::Acquire)
        }

        fn request_error(proof: &PasskeyRequestProof) -> Option<PasskeyVerificationError> {
            match proof.request_signature().first() {
                Some(0xEE) => Some(PasskeyVerificationError::Invalid),
                Some(0xEF) => Some(PasskeyVerificationError::Failed),
                _ => None,
            }
        }

        fn proof_error(proof: &PasskeyTransactionProof) -> Option<PasskeyVerificationError> {
            Self::request_error(proof.request())
        }
    }

    impl PasskeyRequestVerifier for TestPasskeyRequestVerifier {
        fn verify_assertion_lookup(
            &self,
            proof: &PasskeyRequestProof,
        ) -> Result<crate::passkeys::VerifiedAssertionLookup, PasskeyVerificationError> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            if let Some(error) = Self::request_error(proof) {
                return Err(error);
            }
            Ok(crate::passkeys::VerifiedAssertionLookup::new_for_test(
                "example.com",
                Vec::new(),
                false,
            ))
        }

        fn verify_make(
            &self,
            proof: &PasskeyTransactionProof,
        ) -> Result<crate::passkeys::VerifiedMakeRequest, PasskeyVerificationError> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            if let Some(error) = Self::proof_error(proof) {
                return Err(error);
            }
            Ok(crate::passkeys::VerifiedMakeRequest::new_for_test(
                "example.com",
                &TEST_PASSKEY_USER_HANDLE,
                "disposable@example.com",
                "Disposable User",
                Vec::new(),
            ))
        }

        fn verify_assertion(
            &self,
            proof: &PasskeyTransactionProof,
            _: &[u8; 32],
        ) -> Result<crate::passkeys::VerifiedAssertionRequest, PasskeyVerificationError> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            if let Some(error) = Self::proof_error(proof) {
                return Err(error);
            }
            Ok(crate::passkeys::VerifiedAssertionRequest::new_for_test(
                "example.com",
                TEST_PASSKEY_CLIENT_DATA_HASH,
            ))
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "librarian-runtime-unit-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("runtime unit-test directory");
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

    struct TestWindowsHelloProvider {
        next_credential: AtomicUsize,
        invalid_next_enrollment: AtomicBool,
        next_cleanup_failure: Mutex<Option<Vec<u8>>>,
        evaluated: Mutex<Vec<(u64, u32, Vec<u8>)>>,
        removed: Mutex<Vec<Vec<u8>>>,
        removal_failures: Mutex<BTreeSet<Vec<u8>>>,
        transient_removal_failures: Mutex<BTreeMap<Vec<u8>, usize>>,
        block_removal: AtomicBool,
        removal_started: AtomicBool,
        allow_removal: AtomicBool,
    }

    impl TestWindowsHelloProvider {
        fn new() -> Self {
            Self {
                next_credential: AtomicUsize::new(0),
                invalid_next_enrollment: AtomicBool::new(false),
                next_cleanup_failure: Mutex::new(None),
                evaluated: Mutex::new(Vec::new()),
                removed: Mutex::new(Vec::new()),
                removal_failures: Mutex::new(BTreeSet::new()),
                transient_removal_failures: Mutex::new(BTreeMap::new()),
                block_removal: AtomicBool::new(false),
                removal_started: AtomicBool::new(false),
                allow_removal: AtomicBool::new(true),
            }
        }

        fn removed(&self) -> Vec<Vec<u8>> {
            self.removed.lock().expect("removed credentials").clone()
        }

        fn evaluated(&self) -> Vec<(u64, u32, Vec<u8>)> {
            self.evaluated
                .lock()
                .expect("evaluated credentials")
                .clone()
        }

        fn fail_removal_for(&self, credential_id: Vec<u8>) {
            self.removal_failures
                .lock()
                .expect("removal failures")
                .insert(credential_id);
        }

        fn fail_next_removals_for(&self, credential_id: Vec<u8>, attempts: usize) {
            self.transient_removal_failures
                .lock()
                .expect("transient removal failures")
                .insert(credential_id, attempts);
        }

        fn invalidate_next_enrollment(&self) {
            self.invalid_next_enrollment.store(true, Ordering::Release);
        }

        fn fail_next_enrollment_cleanup(&self, credential_id: Vec<u8>) {
            *self
                .next_cleanup_failure
                .lock()
                .expect("next cleanup failure") = Some(credential_id);
        }

        fn block_removal(&self) {
            self.allow_removal.store(false, Ordering::Release);
            self.block_removal.store(true, Ordering::Release);
        }

        fn release_removal(&self) {
            self.allow_removal.store(true, Ordering::Release);
        }
    }

    impl WindowsHelloProvider for TestWindowsHelloProvider {
        fn enroll(
            &self,
            parent_window: u64,
            authenticated_process_id: u32,
            operation_id: [u8; 16],
        ) -> Result<WindowsHelloEnrollment, WindowsHelloProviderError> {
            if parent_window == 0 || authenticated_process_id == 0 || operation_id == [0; 16] {
                return Err(WindowsHelloProviderError::InvalidRequest);
            }
            if let Some(credential_id) = self
                .next_cleanup_failure
                .lock()
                .map_err(|_| WindowsHelloProviderError::Failed)?
                .take()
            {
                return Err(WindowsHelloProviderError::CleanupRequired(credential_id));
            }
            let ordinal = self.next_credential.fetch_add(1, Ordering::AcqRel);
            let marker = u8::try_from(ordinal).map_err(|_| WindowsHelloProviderError::Failed)?;
            Ok(WindowsHelloEnrollment {
                credential_id: vec![0xA0, marker],
                prf_salt: if self.invalid_next_enrollment.swap(false, Ordering::AcqRel) {
                    [0; 32]
                } else {
                    TEST_HELLO_SALT
                },
                prf_output: crate::WindowsHelloPrfOutput::new(TEST_HELLO_PRF),
            })
        }

        fn evaluate(
            &self,
            parent_window: u64,
            authenticated_process_id: u32,
            operation_id: [u8; 16],
            credential_id: &[u8],
            prf_salt: &[u8; 32],
        ) -> Result<crate::WindowsHelloPrfOutput, WindowsHelloProviderError> {
            if parent_window == 0
                || authenticated_process_id == 0
                || operation_id == [0; 16]
                || credential_id.is_empty()
                || prf_salt != &TEST_HELLO_SALT
            {
                return Err(WindowsHelloProviderError::InvalidRequest);
            }
            if credential_id.first() != Some(&0xA0) {
                return Err(WindowsHelloProviderError::Failed);
            }
            self.evaluated
                .lock()
                .map_err(|_| WindowsHelloProviderError::Failed)?
                .push((
                    parent_window,
                    authenticated_process_id,
                    credential_id.to_vec(),
                ));
            Ok(crate::WindowsHelloPrfOutput::new(TEST_HELLO_PRF))
        }

        fn cancel(&self, _operation_id: [u8; 16]) {}

        fn remove(&self, credential_id: &[u8]) -> Result<(), WindowsHelloProviderError> {
            if self.block_removal.load(Ordering::Acquire) {
                self.removal_started.store(true, Ordering::Release);
                while !self.allow_removal.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
            }
            if let Some(remaining) = self
                .transient_removal_failures
                .lock()
                .map_err(|_| WindowsHelloProviderError::RemovalFailed)?
                .get_mut(credential_id)
                && *remaining != 0
            {
                *remaining -= 1;
                return Err(WindowsHelloProviderError::RemovalFailed);
            }
            if self
                .removal_failures
                .lock()
                .map_err(|_| WindowsHelloProviderError::RemovalFailed)?
                .contains(credential_id)
            {
                return Err(WindowsHelloProviderError::RemovalFailed);
            }
            self.removed
                .lock()
                .map_err(|_| WindowsHelloProviderError::RemovalFailed)?
                .push(credential_id.to_vec());
            Ok(())
        }
    }

    #[derive(Default)]
    struct TestWindowsHelloStateRepository {
        encoded: Mutex<Option<Zeroizing<Vec<u8>>>>,
        save_count: AtomicUsize,
        fail_next_save_after_publication: AtomicBool,
        fail_next_remove: AtomicBool,
        fail_next_remove_after_publication: AtomicBool,
        remove_count: AtomicUsize,
    }

    impl TestWindowsHelloStateRepository {
        fn credential_id(&self) -> Option<Vec<u8>> {
            self.load()
                .ok()
                .and_then(|state| state.credential_id().map(<[u8]>::to_vec))
        }

        fn pending_removal_credential_id(&self) -> Option<Vec<u8>> {
            self.load()
                .ok()
                .and_then(|state| state.pending_removal_credential_id().map(<[u8]>::to_vec))
        }

        fn vault_binding(&self) -> Option<([u8; 16], u32)> {
            self.load().ok().and_then(|state| state.vault_binding())
        }

        fn is_empty(&self) -> bool {
            self.encoded.lock().expect("protected state").is_none()
        }

        fn fail_next_save_after_publication(&self) {
            self.fail_next_save_after_publication
                .store(true, Ordering::Release);
        }

        fn fail_next_remove(&self) {
            self.fail_next_remove.store(true, Ordering::Release);
        }

        fn fail_next_remove_after_publication(&self) {
            self.fail_next_remove_after_publication
                .store(true, Ordering::Release);
        }

        fn save_count(&self) -> usize {
            self.save_count.load(Ordering::Acquire)
        }

        fn remove_count(&self) -> usize {
            self.remove_count.load(Ordering::Acquire)
        }

        fn corrupt(&self) {
            *self.encoded.lock().expect("protected state") =
                Some(Zeroizing::new(b"corrupt local state".to_vec()));
        }
    }

    impl WindowsHelloStateRepository for TestWindowsHelloStateRepository {
        fn load(&self) -> Result<WindowsHelloLocalState, WindowsHelloStateError> {
            let encoded = self
                .encoded
                .lock()
                .map_err(|_| WindowsHelloStateError::Failed)?;
            let encoded = encoded.as_ref().ok_or(WindowsHelloStateError::NotFound)?;
            WindowsHelloLocalState::decode(encoded)
        }

        fn save(&self, state: &WindowsHelloLocalState) -> Result<(), WindowsHelloStateError> {
            *self
                .encoded
                .lock()
                .map_err(|_| WindowsHelloStateError::Failed)? = Some(state.encode()?);
            self.save_count.fetch_add(1, Ordering::AcqRel);
            if self
                .fail_next_save_after_publication
                .swap(false, Ordering::AcqRel)
            {
                Err(WindowsHelloStateError::Published)
            } else {
                Ok(())
            }
        }

        fn remove(&self) -> Result<(), WindowsHelloStateError> {
            self.remove_count.fetch_add(1, Ordering::AcqRel);
            if self.fail_next_remove.swap(false, Ordering::AcqRel) {
                return Err(WindowsHelloStateError::Failed);
            }
            let removed = self
                .encoded
                .lock()
                .map_err(|_| WindowsHelloStateError::Failed)?
                .take();
            if self
                .fail_next_remove_after_publication
                .swap(false, Ordering::AcqRel)
            {
                return Err(WindowsHelloStateError::Published);
            }
            removed.map(|_| ()).ok_or(WindowsHelloStateError::NotFound)
        }
    }

    struct PathPublishingWindowsHelloStateRepository {
        path: PathBuf,
        state: TestWindowsHelloStateRepository,
    }

    impl PathPublishingWindowsHelloStateRepository {
        fn new(path: PathBuf) -> Self {
            Self {
                path,
                state: TestWindowsHelloStateRepository::default(),
            }
        }

        fn replace_identity(&self) -> Result<(), WindowsHelloStateError> {
            let replacement = self.path.with_extension("replacement");
            fs::write(&replacement, b"disposable protected-state identity")
                .map_err(|_| WindowsHelloStateError::Failed)?;
            match fs::remove_file(&self.path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(WindowsHelloStateError::Failed),
            }
            fs::rename(&replacement, &self.path).map_err(|_| WindowsHelloStateError::Failed)
        }
    }

    impl WindowsHelloStateRepository for PathPublishingWindowsHelloStateRepository {
        fn load(&self) -> Result<WindowsHelloLocalState, WindowsHelloStateError> {
            self.state.load()
        }

        fn save(&self, state: &WindowsHelloLocalState) -> Result<(), WindowsHelloStateError> {
            self.replace_identity()?;
            self.state.save(state)
        }

        fn remove(&self) -> Result<(), WindowsHelloStateError> {
            match fs::remove_file(&self.path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(WindowsHelloStateError::Failed),
            }
            self.state.remove()
        }

        fn ownership_path(&self) -> Option<&Path> {
            Some(&self.path)
        }
    }

    struct CancellingWindowsHelloProvider {
        started: AtomicBool,
        cancelled: Mutex<BTreeSet<[u8; 16]>>,
        ignored_cancellations: usize,
        cancellation_attempts: AtomicUsize,
    }

    impl CancellingWindowsHelloProvider {
        fn new(ignored_cancellations: usize) -> Self {
            Self {
                started: AtomicBool::new(false),
                cancelled: Mutex::new(BTreeSet::new()),
                ignored_cancellations,
                cancellation_attempts: AtomicUsize::new(0),
            }
        }
    }

    impl WindowsHelloProvider for CancellingWindowsHelloProvider {
        fn enroll(
            &self,
            _parent_window: u64,
            _authenticated_process_id: u32,
            operation_id: [u8; 16],
        ) -> Result<WindowsHelloEnrollment, WindowsHelloProviderError> {
            self.started.store(true, Ordering::Release);
            let wait_deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if self
                    .cancelled
                    .lock()
                    .map_err(|_| WindowsHelloProviderError::Failed)?
                    .contains(&operation_id)
                {
                    return Err(WindowsHelloProviderError::Cancelled);
                }
                if Instant::now() >= wait_deadline {
                    return Err(WindowsHelloProviderError::Failed);
                }
                std::thread::yield_now();
            }
        }

        fn evaluate(
            &self,
            _parent_window: u64,
            _authenticated_process_id: u32,
            _operation_id: [u8; 16],
            _credential_id: &[u8],
            _prf_salt: &[u8; 32],
        ) -> Result<crate::WindowsHelloPrfOutput, WindowsHelloProviderError> {
            Err(WindowsHelloProviderError::Unavailable)
        }

        fn cancel(&self, operation_id: [u8; 16]) {
            let attempt = self.cancellation_attempts.fetch_add(1, Ordering::AcqRel);
            if attempt < self.ignored_cancellations {
                return;
            }
            self.cancelled
                .lock()
                .expect("cancelled operations")
                .insert(operation_id);
        }

        fn remove(&self, _credential_id: &[u8]) -> Result<(), WindowsHelloProviderError> {
            Ok(())
        }
    }

    fn test_registration(runtime: &AgentRuntime, marker: u8) -> RequestRegistration {
        runtime
            .coordinator
            .register(RequestKey {
                connection_id: [marker; 16],
                request_id: 1,
            })
            .expect("test registration")
    }

    fn create_test_vault(runtime: &AgentRuntime, password: &str) {
        let registration = test_registration(runtime, 0xC0);
        let outcome = runtime
            .create_vault(
                password,
                &registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("create outcome");
        assert_eq!(outcome.error, None);
        assert_eq!(runtime.state(), AgentState::Unlocked);
    }

    fn complete_test_lock(runtime: &AgentRuntime) {
        let outcome = runtime.lock_vault().expect("lock outcome");
        assert_eq!(outcome.error, None);
        assert!(outcome.holds_lock_transition);
        drop(FlagPermit::take_over_active(
            &runtime.coordinator.lock_active,
        ));
        assert_eq!(runtime.state(), AgentState::Locked);
    }

    fn connection(runtime: &AgentRuntime, marker: u8) -> Connection {
        connection_with_limits(runtime, marker, ConnectionLimits::default())
    }

    fn connection_with_limits(
        runtime: &AgentRuntime,
        marker: u8,
        limits: ConnectionLimits,
    ) -> Connection {
        let (state, epoch) = runtime
            .status_snapshot()
            .expect("handshake status snapshot");
        let hello = ClientHello::new(
            [marker; 32],
            CURRENT_VERSION,
            CURRENT_VERSION,
            ClientRole::Desktop,
            TEST_BUILD_ID,
            Vec::new(),
        )
        .expect("client hello");
        Connection::negotiate(
            ClientRole::Desktop,
            17,
            TEST_BUILD_ID,
            &hello,
            &[],
            [marker.wrapping_add(1); 32],
            [marker.wrapping_add(2); 16],
            state,
            epoch,
            limits,
        )
        .expect("connection")
        .0
    }

    fn passkey_connection(runtime: &AgentRuntime, marker: u8) -> Connection {
        let (state, epoch) = runtime
            .status_snapshot()
            .expect("passkey handshake status snapshot");
        let hello = ClientHello::new(
            [marker; 32],
            CURRENT_VERSION,
            CURRENT_VERSION,
            ClientRole::PasskeyProvider,
            TEST_BUILD_ID,
            vec![FEATURE_PASSKEY_PROVIDER],
        )
        .expect("passkey client hello");
        Connection::negotiate(
            ClientRole::PasskeyProvider,
            23,
            TEST_BUILD_ID,
            &hello,
            &[FEATURE_PASSKEY_PROVIDER],
            [marker.wrapping_add(1); 32],
            [marker.wrapping_add(2); 16],
            state,
            epoch,
            ConnectionLimits::default(),
        )
        .expect("passkey connection")
        .0
    }

    fn desktop_passkey_connection(runtime: &AgentRuntime, marker: u8) -> Connection {
        let (state, epoch) = runtime
            .status_snapshot()
            .expect("desktop passkey handshake status snapshot");
        let hello = ClientHello::new(
            [marker; 32],
            CURRENT_VERSION,
            CURRENT_VERSION,
            ClientRole::Desktop,
            TEST_BUILD_ID,
            vec![FEATURE_PASSKEY_PROVIDER],
        )
        .expect("desktop passkey client hello");
        Connection::negotiate(
            ClientRole::Desktop,
            17,
            TEST_BUILD_ID,
            &hello,
            &[FEATURE_PASSKEY_PROVIDER],
            [marker.wrapping_add(1); 32],
            [marker.wrapping_add(2); 16],
            state,
            epoch,
            ConnectionLimits::default(),
        )
        .expect("desktop passkey connection")
        .0
    }

    fn test_passkey_proof(marker: u8, agent_challenge: [u8; 16]) -> PasskeyTransactionProof {
        PasskeyTransactionProof::new(
            [marker; 16],
            1,
            &[marker; 64],
            &[marker.wrapping_add(1); 96],
            agent_challenge,
            &[marker.wrapping_add(2); 64],
        )
        .expect("bounded passkey proof")
    }

    fn test_passkey_request_proof(marker: u8) -> PasskeyRequestProof {
        PasskeyRequestProof::new(
            [marker; 16],
            1,
            &[marker; 64],
            &[marker.wrapping_add(1); 96],
        )
        .expect("bounded passkey request proof")
    }

    fn dispatch_passkey_request(
        runtime: &AgentRuntime,
        connection: &Connection,
        request_id: u64,
        idempotency_marker: u8,
        operation: &OperationRequest,
    ) -> ResponseEnvelope {
        let body = operation.encode().expect("passkey operation body");
        let request = RequestEnvelope::new(
            operation.operation(),
            runtime.unlock_epoch(),
            5_000,
            operation
                .operation()
                .requires_idempotency_key()
                .then_some([idempotency_marker; 16]),
            body,
        )
        .expect("passkey request");
        let header = FrameHeader::new(
            MessageKind::Request,
            CURRENT_VERSION,
            request.encode().expect("passkey request bytes").len(),
            *connection.connection_id(),
            request_id,
        )
        .expect("passkey header");
        runtime
            .dispatch(connection, &header, &request, copy_response)
            .expect("passkey dispatch")
    }

    fn unlock_test_vault(runtime: &AgentRuntime, password: &str) {
        let registration = test_registration(runtime, 0xC1);
        let outcome = runtime
            .unlock_vault(
                password,
                &registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("unlock outcome");
        assert_eq!(outcome.error, None);
        assert_eq!(runtime.state(), AgentState::Unlocked);
    }

    fn admitted_request(
        runtime: &AgentRuntime,
        connection: &Connection,
        request_id: u64,
        operation: &OperationRequest,
    ) -> (RequestEnvelope, FrameHeader, RequestPermit) {
        let body = operation.encode().expect("operation body");
        let request = RequestEnvelope::new(
            operation.operation(),
            runtime.unlock_epoch(),
            5_000,
            None,
            body,
        )
        .expect("request");
        let header = FrameHeader::new(
            MessageKind::Request,
            CURRENT_VERSION,
            request.encode().expect("request bytes").len(),
            *connection.connection_id(),
            request_id,
        )
        .expect("header");
        let permit = connection
            .begin_request(&header, &request, runtime.unlock_epoch())
            .expect("request admission");
        (request, header, permit)
    }

    fn copy_response(response: &ResponseEnvelope) -> Result<ResponseEnvelope, DispatchError> {
        let encoded = response.encode().map_err(|_| DispatchError::Internal)?;
        ResponseEnvelope::decode(&encoded).map_err(|_| DispatchError::Internal)
    }

    fn decode_status_response(response: &ResponseEnvelope) -> (AgentState, u64) {
        let mut decoder = Decoder::new(response.body());
        assert_eq!(decoder.array().expect("status array"), Some(2));
        let state = decode_state(decoder.u8().expect("status state"));
        let epoch = decoder.u64().expect("status epoch");
        assert_eq!(decoder.position(), response.body().len());
        (state, epoch)
    }

    fn decode_created_passkey(response: &ResponseEnvelope) -> [u8; 32] {
        let mut decoder = Decoder::new(response.body());
        assert_eq!(decoder.array().expect("credential response"), Some(3));
        let credential_id = decoder
            .bytes()
            .expect("credential id")
            .try_into()
            .expect("fixed credential id");
        assert_ne!(credential_id, [0; 32]);
        assert_eq!(
            decoder.bytes().expect("user handle"),
            TEST_PASSKEY_USER_HANDLE
        );
        let public_key = decoder.bytes().expect("public key");
        assert_eq!(public_key.len(), 65);
        assert_eq!(public_key[0], 0x04);
        assert_eq!(decoder.position(), response.body().len());
        credential_id
    }

    fn assert_passkey_assertion_response(response: &ResponseEnvelope, credential_id: &[u8; 32]) {
        let mut decoder = Decoder::new(response.body());
        assert_eq!(decoder.array().expect("assertion response"), Some(4));
        assert_eq!(
            decoder.bytes().expect("assertion credential"),
            credential_id
        );
        assert_eq!(
            decoder.bytes().expect("assertion user"),
            TEST_PASSKEY_USER_HANDLE
        );
        let authenticator_data = decoder.bytes().expect("authenticator data");
        assert_eq!(authenticator_data.len(), 37);
        assert_eq!(authenticator_data[32], 0x0D);
        assert_eq!(&authenticator_data[33..], &1_u32.to_be_bytes());
        assert!(!decoder.bytes().expect("DER signature").is_empty());
        assert_eq!(decoder.position(), response.body().len());
    }

    fn assert_passkey_lookup_response(response: &ResponseEnvelope, credential_id: &[u8; 32]) {
        let mut decoder = Decoder::new(response.body());
        assert_eq!(decoder.array().expect("passkey list"), Some(1));
        assert_eq!(decoder.array().expect("passkey summary"), Some(4));
        assert_eq!(decoder.bytes().expect("summary credential"), credential_id);
        assert_eq!(
            decoder.bytes().expect("summary user"),
            TEST_PASSKEY_USER_HANDLE
        );
        assert_eq!(
            decoder.str().expect("summary user name"),
            "disposable@example.com"
        );
        assert_eq!(
            decoder.str().expect("summary display name"),
            "Disposable User"
        );
        assert_eq!(decoder.position(), response.body().len());
    }

    fn assert_passkey_management_response(response: &ResponseEnvelope, credential_id: &[u8; 32]) {
        let mut decoder = Decoder::new(response.body());
        assert_eq!(decoder.array().expect("management list"), Some(1));
        assert_eq!(decoder.array().expect("management summary"), Some(4));
        assert_eq!(
            decoder.bytes().expect("management credential"),
            credential_id
        );
        assert_eq!(decoder.str().expect("management RP"), "example.com");
        assert_eq!(
            decoder.str().expect("management user name"),
            "disposable@example.com"
        );
        assert_eq!(
            decoder.str().expect("management display name"),
            "Disposable User"
        );
        assert_eq!(decoder.position(), response.body().len());
    }

    #[test]
    fn passkey_ipc_lifecycle_survives_lock_and_restart() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let verifier = Arc::new(TestPasskeyRequestVerifier::default());
        let mut runtime = AgentRuntime::start(&path).expect("runtime");
        runtime.passkey_verifier = verifier.clone();
        create_test_vault(&runtime, "disposable passkey test password");
        let client = passkey_connection(&runtime, 0x31);

        let created = dispatch_passkey_request(
            &runtime,
            &client,
            1,
            0x41,
            &OperationRequest::MakePasskey {
                proof: test_passkey_proof(0x11, *client.connection_id()),
            },
        );
        assert_eq!(created.error(), None);
        let credential_id = decode_created_passkey(&created);

        let lookup = dispatch_passkey_request(
            &runtime,
            &client,
            2,
            0,
            &OperationRequest::ListPasskeysForAssertion {
                proof: test_passkey_request_proof(0x15),
            },
        );
        assert_eq!(lookup.error(), None);
        assert_passkey_lookup_response(&lookup, &credential_id);

        let desktop = desktop_passkey_connection(&runtime, 0x34);
        let management =
            dispatch_passkey_request(&runtime, &desktop, 1, 0, &OperationRequest::ListPasskeys);
        assert_eq!(management.error(), None);
        assert_passkey_management_response(&management, &credential_id);

        drop(client);
        complete_test_lock(&runtime);
        let locked_client = passkey_connection(&runtime, 0x32);
        let locked = dispatch_passkey_request(
            &runtime,
            &locked_client,
            1,
            0x42,
            &OperationRequest::GetPasskeyAssertion {
                proof: test_passkey_proof(0x12, *locked_client.connection_id()),
                credential_id,
            },
        );
        assert_eq!(locked.error(), Some(PublicErrorCode::Locked));
        assert_eq!(verifier.calls(), 2);
        drop(locked_client);
        drop(runtime);

        let verifier = Arc::new(TestPasskeyRequestVerifier::default());
        let mut runtime = AgentRuntime::start(&path).expect("restarted runtime");
        runtime.passkey_verifier = verifier.clone();
        unlock_test_vault(&runtime, "disposable passkey test password");
        let client = passkey_connection(&runtime, 0x33);
        let assertion = dispatch_passkey_request(
            &runtime,
            &client,
            1,
            0x43,
            &OperationRequest::GetPasskeyAssertion {
                proof: test_passkey_proof(0x13, *client.connection_id()),
                credential_id,
            },
        );
        assert_eq!(assertion.error(), None);
        assert_passkey_assertion_response(&assertion, &credential_id);

        let desktop = desktop_passkey_connection(&runtime, 0x35);
        let deleted = dispatch_passkey_request(
            &runtime,
            &desktop,
            1,
            0x44,
            &OperationRequest::DeletePasskey { credential_id },
        );
        assert_eq!(deleted.error(), None);
        let missing_client = passkey_connection(&runtime, 0x36);
        let missing = dispatch_passkey_request(
            &runtime,
            &missing_client,
            1,
            0x45,
            &OperationRequest::GetPasskeyAssertion {
                proof: test_passkey_proof(0x14, *missing_client.connection_id()),
                credential_id,
            },
        );
        assert_eq!(missing.error(), Some(PublicErrorCode::NotFound));
        assert_eq!(verifier.calls(), 2);
    }

    #[test]
    fn passkey_creation_rollback_is_exact_and_connection_bound() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let verifier = Arc::new(TestPasskeyRequestVerifier::default());
        let mut runtime = AgentRuntime::start(&path).expect("runtime");
        runtime.passkey_verifier = verifier.clone();
        create_test_vault(&runtime, "disposable rollback test password");
        let client = passkey_connection(&runtime, 0x61);
        let proof = test_passkey_proof(0x21, *client.connection_id());

        let created = dispatch_passkey_request(
            &runtime,
            &client,
            1,
            0x71,
            &OperationRequest::MakePasskey {
                proof: test_passkey_proof(0x21, *client.connection_id()),
            },
        );
        assert_eq!(created.error(), None);
        let credential_id = decode_created_passkey(&created);

        let rolled_back = dispatch_passkey_request(
            &runtime,
            &client,
            2,
            0x72,
            &OperationRequest::RollbackPasskeyCreation {
                proof,
                credential_id,
            },
        );
        assert_eq!(rolled_back.error(), None);
        assert_eq!(rolled_back.body(), &[0x80]);
        assert!(
            lock(&runtime.pending_passkey_creations)
                .expect("pending passkey creations")
                .is_empty()
        );

        let desktop = desktop_passkey_connection(&runtime, 0x62);
        let management =
            dispatch_passkey_request(&runtime, &desktop, 1, 0, &OperationRequest::ListPasskeys);
        assert_eq!(management.error(), None);
        assert_eq!(management.body(), &[0x80]);
        assert_eq!(verifier.calls(), 2);
    }

    #[test]
    fn passkey_ipc_rejects_malformed_or_unverified_transactions_before_mutation() {
        let directory = TestDirectory::new();
        let verifier = Arc::new(TestPasskeyRequestVerifier::default());
        let mut runtime = AgentRuntime::start(directory.vault_path()).expect("runtime");
        runtime.passkey_verifier = verifier.clone();
        create_test_vault(&runtime, "disposable proof test password");
        let client = passkey_connection(&runtime, 0x35);

        let malformed_request = RequestEnvelope::new(
            OperationCode::MakePasskey,
            runtime.unlock_epoch(),
            5_000,
            Some([0x51; 16]),
            Zeroizing::new(vec![0x80]),
        )
        .expect("malformed request envelope");
        let malformed_header = FrameHeader::new(
            MessageKind::Request,
            CURRENT_VERSION,
            malformed_request.encode().expect("request bytes").len(),
            *client.connection_id(),
            1,
        )
        .expect("malformed header");
        let malformed = runtime
            .dispatch(
                &client,
                &malformed_header,
                &malformed_request,
                copy_response,
            )
            .expect("malformed dispatch");
        assert_eq!(malformed.error(), Some(PublicErrorCode::InvalidRequest));
        assert_eq!(verifier.calls(), 0);

        let invalid_client = passkey_connection(&runtime, 0x36);
        let invalid = dispatch_passkey_request(
            &runtime,
            &invalid_client,
            1,
            0x52,
            &OperationRequest::MakePasskey {
                proof: test_passkey_proof(0xEE, *invalid_client.connection_id()),
            },
        );
        assert_eq!(invalid.error(), Some(PublicErrorCode::InvalidRequest));
        let failed_client = passkey_connection(&runtime, 0x37);
        let failed = dispatch_passkey_request(
            &runtime,
            &failed_client,
            1,
            0x53,
            &OperationRequest::MakePasskey {
                proof: test_passkey_proof(0xEF, *failed_client.connection_id()),
            },
        );
        assert_eq!(failed.error(), Some(PublicErrorCode::OperationFailed));

        let create_client = passkey_connection(&runtime, 0x38);
        let created = dispatch_passkey_request(
            &runtime,
            &create_client,
            1,
            0x54,
            &OperationRequest::MakePasskey {
                proof: test_passkey_proof(0x15, *create_client.connection_id()),
            },
        );
        assert_eq!(created.error(), None);
        assert_eq!(verifier.calls(), 3);

        let same_connection_replay = dispatch_passkey_request(
            &runtime,
            &create_client,
            2,
            0x54,
            &OperationRequest::MakePasskey {
                proof: test_passkey_proof(0x15, *create_client.connection_id()),
            },
        );
        assert_eq!(
            same_connection_replay.error(),
            Some(PublicErrorCode::InvalidRequest)
        );

        let replay_client = passkey_connection(&runtime, 0x39);
        let new_connection_replay = dispatch_passkey_request(
            &runtime,
            &replay_client,
            1,
            0x54,
            &OperationRequest::MakePasskey {
                proof: test_passkey_proof(0x15, *create_client.connection_id()),
            },
        );
        assert_eq!(
            new_connection_replay.error(),
            Some(PublicErrorCode::InvalidRequest)
        );
        assert_eq!(verifier.calls(), 3);
    }

    #[test]
    fn global_and_serial_resource_permits_are_exact_and_reusable() {
        let counter = AtomicUsize::new(0);
        let permits: Vec<_> = (0..MAX_IN_FLIGHT_GLOBAL)
            .map(|_| CounterPermit::acquire(&counter, MAX_IN_FLIGHT_GLOBAL))
            .collect();
        assert!(permits.iter().all(Option::is_some));
        assert!(CounterPermit::acquire(&counter, MAX_IN_FLIGHT_GLOBAL).is_none());
        drop(permits);
        assert!(CounterPermit::acquire(&counter, MAX_IN_FLIGHT_GLOBAL).is_some());

        let flag = AtomicBool::new(false);
        let permit = FlagPermit::acquire(&flag).expect("first serial permit");
        assert!(FlagPermit::acquire(&flag).is_none());
        drop(permit);
        assert!(FlagPermit::acquire(&flag).is_some());
    }

    #[test]
    fn windows_hello_state_paths_are_disjoint_and_exclusively_owned() {
        let directory = TestDirectory::new();
        let first_vault = directory.0.join("first.sqlite3");
        let second_vault = directory.0.join("second.sqlite3");
        let protected_state = directory.0.join("windows-hello.dat");
        let first = AgentRuntime::start_with_components_and_state_path(
            &first_vault,
            Some(Arc::new(TestWindowsHelloProvider::new())),
            Some(Arc::new(TestWindowsHelloStateRepository::default())),
            Some(&protected_state),
        )
        .expect("first protected-state owner");

        assert_eq!(
            AgentRuntime::start_with_components_and_state_path(
                &second_vault,
                Some(Arc::new(TestWindowsHelloProvider::new())),
                Some(Arc::new(TestWindowsHelloStateRepository::default())),
                Some(&protected_state),
            )
            .err(),
            Some(RuntimeStartError::AlreadyOwned)
        );
        assert_eq!(
            AgentRuntime::start_with_components_and_state_path(
                &second_vault,
                Some(Arc::new(TestWindowsHelloProvider::new())),
                Some(Arc::new(TestWindowsHelloStateRepository::default())),
                Some(&second_vault),
            )
            .err(),
            Some(RuntimeStartError::InvalidLocalStatePath)
        );

        let existing_vault = directory.0.join("existing.sqlite3");
        let alias = directory.0.join("existing-alias.dat");
        fs::write(&existing_vault, b"disposable identity marker").expect("identity file");
        fs::hard_link(&existing_vault, &alias).expect("identity alias");
        assert_eq!(
            AgentRuntime::start_with_components_and_state_path(
                &existing_vault,
                Some(Arc::new(TestWindowsHelloProvider::new())),
                Some(Arc::new(TestWindowsHelloStateRepository::default())),
                Some(&alias),
            )
            .err(),
            Some(RuntimeStartError::InvalidLocalStatePath)
        );

        drop(first);
    }

    #[test]
    fn windows_hello_state_ownership_tracks_replaced_file_identity() {
        let directory = TestDirectory::new();
        let first_vault = directory.0.join("first.sqlite3");
        let second_vault = directory.0.join("second.sqlite3");
        let protected_state = directory.0.join("windows-hello.dat");
        let alias = directory.0.join("windows-hello-alias.dat");
        let provider = Arc::new(TestWindowsHelloProvider::new());
        let state = Arc::new(PathPublishingWindowsHelloStateRepository::new(
            protected_state.clone(),
        ));
        let runtime = AgentRuntime::start_with_components_and_state_path(
            &first_vault,
            Some(provider),
            Some(state),
            Some(&protected_state),
        )
        .expect("protected-state owner");
        create_test_vault(&runtime, "disposable protected-state ownership password");

        for marker in [0xB7, 0xB8] {
            let registration = test_registration(&runtime, marker);
            let outcome = runtime
                .enroll_windows_hello(
                    0x1234,
                    17,
                    runtime.unlock_epoch(),
                    &registration,
                    Instant::now() + Duration::from_secs(10),
                )
                .expect("Windows Hello enrollment");
            assert_eq!(outcome.error, None);
        }

        fs::hard_link(&protected_state, &alias).expect("protected-state identity alias");
        assert_eq!(
            AgentRuntime::start_with_components_and_state_path(
                &second_vault,
                Some(Arc::new(TestWindowsHelloProvider::new())),
                Some(Arc::new(TestWindowsHelloStateRepository::default())),
                Some(&alias),
            )
            .err(),
            Some(RuntimeStartError::AlreadyOwned)
        );
    }

    #[test]
    fn lock_transition_remains_active_through_terminal_response_write() {
        let directory = TestDirectory::new();
        let runtime = AgentRuntime::start(directory.vault_path()).expect("runtime");
        runtime
            .state
            .store(AgentState::Unlocked as u8, Ordering::Release);
        let client = connection(&runtime, 76);
        let (_request, _header, permit) =
            admitted_request(&runtime, &client, 1, &OperationRequest::Lock);
        let registration = runtime
            .coordinator
            .register(RequestKey {
                connection_id: *client.connection_id(),
                request_id: 1,
            })
            .expect("registration");

        let outcome = runtime.lock_vault().expect("lock outcome");
        assert!(outcome.holds_lock_transition);
        assert!(runtime.coordinator.lock_active.load(Ordering::Acquire));
        let response = runtime
            .finish_dispatch(
                DispatchContext {
                    connection: &client,
                    permit,
                    _global: CounterPermit::acquire(
                        &runtime.coordinator.global_in_flight,
                        MAX_IN_FLIGHT_GLOBAL,
                    )
                    .expect("global permit"),
                    registration,
                    deadline: Instant::now() + Duration::from_secs(1),
                    correlation: CorrelationId::new([0x76; 16]),
                },
                outcome,
                |response| {
                    assert!(runtime.coordinator.lock_active.load(Ordering::Acquire));
                    copy_response(response)
                },
            )
            .expect("lock response");
        assert_eq!(response.error(), None);
        assert!(!runtime.coordinator.lock_active.load(Ordering::Acquire));
    }

    #[test]
    fn lock_waits_for_creation_gate_before_returning() {
        let directory = TestDirectory::new();
        let runtime = Arc::new(AgentRuntime::start(directory.vault_path()).expect("runtime"));
        let creation = lock(&runtime.coordinator.creation_gate).expect("creation gate");
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let worker_runtime = Arc::clone(&runtime);
        let worker = std::thread::spawn(move || {
            result_tx
                .send(worker_runtime.lock_vault())
                .expect("lock result");
        });
        let wait_deadline = Instant::now() + Duration::from_secs(1);
        while !runtime.coordinator.lock_active.load(Ordering::Acquire) {
            assert!(Instant::now() < wait_deadline, "lock transition must start");
            std::thread::yield_now();
        }
        assert!(
            result_rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "lock must wait until local creation material has drained"
        );

        drop(creation);
        let outcome = result_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("lock completes after creation drains")
            .expect("lock outcome");
        assert!(outcome.holds_lock_transition);
        drop(FlagPermit::take_over_active(
            &runtime.coordinator.lock_active,
        ));
        worker.join().expect("lock worker");
    }

    #[test]
    fn lock_wins_after_core_unlock_before_authenticated_id_publication() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let runtime = Arc::new(AgentRuntime::start(&path).expect("runtime"));
        let password = "authenticated id publication race password";
        let (mut vault, recovery_key) =
            VaultAgent::create(&path, MasterPassword::new(password).expect("password"))
                .expect("vault");
        drop(recovery_key);
        vault.lock();
        *lock(&runtime.vault).expect("runtime vault") = vault;
        runtime
            .state
            .store(AgentState::Locked as u8, Ordering::Release);

        let client = connection(&runtime, 77);
        let registration = runtime
            .coordinator
            .register(RequestKey {
                connection_id: *client.connection_id(),
                request_id: 1,
            })
            .expect("unlock registration");
        let (core_tx, core_rx) = std::sync::mpsc::channel();
        let worker_runtime = Arc::clone(&runtime);
        let worker = std::thread::spawn(move || {
            worker_runtime.unlock_vault_with_after_core(
                password,
                &registration,
                Instant::now() + Duration::from_secs(10),
                || {
                    core_tx.send(()).expect("core unlock signal");
                    let wait_deadline = Instant::now() + Duration::from_secs(1);
                    while !worker_runtime
                        .coordinator
                        .lock_active
                        .load(Ordering::Acquire)
                    {
                        assert!(
                            Instant::now() < wait_deadline,
                            "lock transition must begin while the vault guard is retained"
                        );
                        std::thread::yield_now();
                    }
                },
            )
        });
        core_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("core unlock completes");

        let lock_outcome = runtime.lock_vault().expect("lock outcome");
        assert!(lock_outcome.holds_lock_transition);
        let unlock_outcome = worker
            .join()
            .expect("unlock worker")
            .expect("terminal unlock outcome");
        assert_eq!(
            unlock_outcome.error,
            Some(PublicErrorCode::Cancelled),
            "a winning lock must produce a terminal lifecycle result, not an internal failure"
        );
        drop(FlagPermit::take_over_active(
            &runtime.coordinator.lock_active,
        ));
        assert_eq!(runtime.state(), AgentState::Locked);
    }

    #[test]
    fn unlock_publication_preserves_deadline_expiry() {
        let directory = TestDirectory::new();
        let runtime = Arc::new(AgentRuntime::start(directory.vault_path()).expect("runtime"));
        runtime
            .state
            .store(AgentState::Unlocking as u8, Ordering::Release);
        let registration = runtime
            .coordinator
            .register(RequestKey {
                connection_id: [0x83; 16],
                request_id: 1,
            })
            .expect("unlock registration");
        let commit = lock(&runtime.coordinator.commit_gate).expect("hold publication gate");
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let worker_runtime = Arc::clone(&runtime);
        let worker = std::thread::spawn(move || {
            started_tx.send(()).expect("publication worker started");
            worker_runtime.publish_authenticated_unlock(
                None,
                [0x83; 16],
                &registration,
                Instant::now() + Duration::from_millis(50),
            )
        });
        started_rx.recv().expect("publication worker start");
        std::thread::sleep(Duration::from_millis(100));
        drop(commit);
        let outcome = worker
            .join()
            .expect("publication worker")
            .expect("deadline outcome");
        assert_eq!(
            outcome.error,
            Some(PublicErrorCode::DeadlineExceeded),
            "deadline expiry at publication must not be reported as cancellation"
        );
        assert_eq!(outcome.retry, RetryCategory::Never);
        assert_eq!(runtime.state(), AgentState::Locked);
    }

    #[test]
    fn mutation_commit_guard_is_released_before_failure_handling() {
        let coordinator = Coordinator::new();
        let mut commit_guard = Some(lock(&coordinator.commit_gate).expect("mutation commit gate"));
        let failed: Result<(), AccountError> = Err(AccountError::Failed);

        release_failed_commit_guard(&failed, &mut commit_guard);

        assert!(
            coordinator.commit_gate.try_lock().is_ok(),
            "failure handling must be able to re-enter the commit gate"
        );
    }

    #[test]
    fn idempotency_cache_rotates_completed_entries_without_permanent_busy() {
        let directory = TestDirectory::new();
        let runtime = AgentRuntime::start(directory.vault_path()).expect("runtime");
        {
            let mut state = lock(&runtime.idempotency).expect("idempotency state");
            for sequence in 0..MAX_IDEMPOTENCY_RESULTS {
                let key = (sequence as u128).to_be_bytes();
                state.cached.insert(
                    key,
                    CachedOutcome {
                        request_fingerprint: [u8::try_from(sequence % 256).expect("bounded marker");
                            32],
                        error: None,
                        retry: RetryCategory::Never,
                        body: Zeroizing::new(Vec::new()),
                    },
                );
                state.insertion_order.push_back(key);
            }
        }

        let client = connection(&runtime, 3);
        let registration = runtime
            .coordinator
            .register(RequestKey {
                connection_id: *client.connection_id(),
                request_id: 1,
            })
            .expect("registration");
        let operation = OperationRequest::Status;
        let body = operation.encode().expect("status body");
        let fingerprint = runtime
            .request_fingerprint(operation.operation(), runtime.unlock_epoch(), &body)
            .expect("request fingerprint");
        let newest = u128::MAX.to_be_bytes();
        let outcome = runtime
            .execute_idempotent(
                newest,
                fingerprint,
                || Ok(None),
                || {
                    runtime.execute(
                        operation,
                        runtime.unlock_epoch(),
                        *client.connection_id(),
                        17,
                        &registration,
                        Instant::now() + Duration::from_secs(1),
                    )
                },
            )
            .expect("rotated execution");
        assert_eq!(outcome.error, None);

        let state = lock(&runtime.idempotency).expect("idempotency state");
        assert_eq!(state.cached.len(), MAX_IDEMPOTENCY_RESULTS);
        assert_eq!(state.insertion_order.len(), MAX_IDEMPOTENCY_RESULTS);
        assert!(state.in_flight.is_empty());
        assert!(!state.cached.contains_key(&0_u128.to_be_bytes()));
        assert!(state.cached.contains_key(&newest));
    }

    #[test]
    fn unlocked_idempotency_fingerprints_are_epoch_scoped() {
        let directory = TestDirectory::new();
        let runtime = AgentRuntime::start(directory.vault_path()).expect("runtime");
        let body = b"disposable canonical request body";

        let first_epoch = runtime
            .request_fingerprint(OperationCode::AddAccount, 7, body)
            .expect("first unlocked fingerprint");
        let next_epoch = runtime
            .request_fingerprint(OperationCode::AddAccount, 8, body)
            .expect("next unlocked fingerprint");
        assert_ne!(
            first_epoch, next_epoch,
            "unlocked-operation cache identity must change with the admitted epoch"
        );

        let first_status = runtime
            .request_fingerprint(OperationCode::Status, 7, body)
            .expect("first status fingerprint");
        let next_status = runtime
            .request_fingerprint(OperationCode::Status, 8, body)
            .expect("next status fingerprint");
        assert_eq!(
            first_status, next_status,
            "operations that do not require an unlocked epoch retain stable replay identity"
        );
    }

    #[test]
    fn idempotency_scope_tracks_the_authenticated_cryptographic_vault() {
        let directory = TestDirectory::new();
        let runtime = AgentRuntime::start(directory.vault_path()).expect("runtime");
        let cached_key = [0x41; 16];
        {
            let mut state = lock(&runtime.idempotency).expect("idempotency state");
            state.cached.insert(
                cached_key,
                CachedOutcome {
                    request_fingerprint: [0x42; 32],
                    error: None,
                    retry: RetryCategory::Never,
                    body: Zeroizing::new(Vec::new()),
                },
            );
            state.insertion_order.push_back(cached_key);
        }

        let first_vault = [0x43; 16];
        runtime
            .initialize_idempotency_vault(first_vault)
            .expect("initial vault binding");
        {
            let mut state = lock(&runtime.idempotency).expect("idempotency state");
            assert!(state.cached.is_empty());
            state.cached.insert(
                cached_key,
                CachedOutcome {
                    request_fingerprint: [0x44; 32],
                    error: None,
                    retry: RetryCategory::Never,
                    body: Zeroizing::new(Vec::new()),
                },
            );
            state.insertion_order.push_back(cached_key);
            assert!(state.in_flight.insert([0x45; 16]));
        }

        runtime
            .bind_authenticated_idempotency_vault(first_vault)
            .expect("same vault binding");
        assert!(
            lock(&runtime.idempotency)
                .expect("idempotency state")
                .cached
                .contains_key(&cached_key)
        );
        assert_eq!(
            runtime.bind_authenticated_idempotency_vault([0x46; 16]),
            Err(DispatchError::Internal)
        );
        lock(&runtime.idempotency)
            .expect("idempotency state")
            .in_flight
            .clear();
        runtime
            .bind_authenticated_idempotency_vault([0x46; 16])
            .expect("changed vault binding");
        let state = lock(&runtime.idempotency).expect("idempotency state");
        assert_eq!(state.authenticated_vault_id, Some([0x46; 16]));
        assert!(state.cached.is_empty());
        assert!(state.insertion_order.is_empty());
    }

    #[test]
    fn terminal_operation_failures_remain_idempotent() {
        let directory = TestDirectory::new();
        let runtime = AgentRuntime::start(directory.vault_path()).expect("runtime");
        let key = [0x44; 16];
        let fingerprint = [0x45; 32];
        {
            let mut state = lock(&runtime.idempotency).expect("idempotency state");
            assert!(state.in_flight.insert(key));
        }
        let failed = ExecutionOutcome::failed();
        assert!(should_cache(&failed));
        IdempotencyReservation {
            state: &runtime.idempotency,
            key,
            active: true,
        }
        .complete(Some(CachedOutcome {
            request_fingerprint: fingerprint,
            error: failed.error,
            retry: failed.retry,
            body: Zeroizing::new(failed.body.to_vec()),
        }))
        .expect("cache terminal failure");

        let replay = runtime
            .execute_idempotent(
                key,
                fingerprint,
                || Ok(None),
                || panic!("a cached terminal result must not execute again"),
            )
            .expect("cached terminal failure");
        assert_eq!(replay.error, Some(PublicErrorCode::OperationFailed));
        assert!(replay.replayed);
    }

    #[test]
    fn idempotency_key_is_reserved_before_body_decoding_or_execution() {
        let directory = TestDirectory::new();
        let runtime = AgentRuntime::start(directory.vault_path()).expect("runtime");
        let key = [0x47; 16];
        let fingerprint = [0x48; 32];
        let outcome = runtime
            .execute_idempotent(
                key,
                fingerprint,
                || Ok(None),
                || {
                    assert!(
                        lock(&runtime.idempotency)
                            .expect("idempotency state")
                            .in_flight
                            .contains(&key),
                        "the key must be claimed before the body is decoded"
                    );
                    Ok(ExecutionOutcome::invalid())
                },
            )
            .expect("invalid request outcome");
        assert_eq!(outcome.error, Some(PublicErrorCode::InvalidRequest));
        let state = lock(&runtime.idempotency).expect("idempotency state");
        assert!(state.in_flight.is_empty());
        assert_eq!(
            state
                .cached
                .get(&key)
                .map(|cached| cached.request_fingerprint),
            Some(fingerprint)
        );
    }

    #[test]
    fn handshake_status_snapshot_waits_for_the_transition_gate() {
        let directory = TestDirectory::new();
        let runtime = Arc::new(AgentRuntime::start(directory.vault_path()).expect("runtime"));
        let commit = lock(&runtime.coordinator.commit_gate).expect("commit gate");
        runtime
            .state
            .store(AgentState::Unlocked as u8, Ordering::Release);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (snapshot_tx, snapshot_rx) = std::sync::mpsc::channel();
        let worker_runtime = Arc::clone(&runtime);
        let worker = std::thread::spawn(move || {
            started_tx.send(()).expect("snapshot worker started");
            snapshot_tx
                .send(worker_runtime.status_snapshot())
                .expect("snapshot result");
        });
        started_rx.recv().expect("snapshot worker start");
        assert!(
            snapshot_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "snapshot must wait behind the transition gate"
        );

        runtime
            .state
            .store(AgentState::Locked as u8, Ordering::Release);
        let epoch = runtime
            .coordinator
            .advance_epoch_without_cancellation()
            .expect("lock epoch");
        drop(commit);

        assert_eq!(
            snapshot_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("coherent snapshot")
                .expect("snapshot result"),
            (AgentState::Locked, epoch)
        );
        worker.join().expect("snapshot worker");
    }

    #[test]
    fn request_deadline_includes_admission_gate_wait() {
        let directory = TestDirectory::new();
        let runtime = Arc::new(AgentRuntime::start(directory.vault_path()).expect("runtime"));
        let client = connection(&runtime, 73);
        let operation = OperationRequest::Status;
        let body = operation.encode().expect("status body");
        let request = RequestEnvelope::new(
            OperationCode::Status,
            runtime.unlock_epoch(),
            50,
            None,
            body,
        )
        .expect("short status request");
        let header = FrameHeader::new(
            MessageKind::Request,
            CURRENT_VERSION,
            request.encode().expect("status request bytes").len(),
            *client.connection_id(),
            1,
        )
        .expect("status header");
        let commit = lock(&runtime.coordinator.commit_gate).expect("hold admission gate");
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let worker_runtime = Arc::clone(&runtime);
        let worker = std::thread::spawn(move || {
            started_tx.send(()).expect("request worker started");
            worker_runtime.dispatch(&client, &header, &request, copy_response)
        });
        started_rx.recv().expect("request worker start");
        std::thread::sleep(Duration::from_millis(100));
        drop(commit);

        let response = worker
            .join()
            .expect("request worker")
            .expect("deadline response");
        assert_eq!(response.error(), Some(PublicErrorCode::DeadlineExceeded));
    }

    #[test]
    fn request_ordering_precedes_admission_gate_for_cancellation() {
        let directory = TestDirectory::new();
        let runtime = Arc::new(AgentRuntime::start(directory.vault_path()).expect("runtime"));
        let client = Arc::new(connection(&runtime, 74));
        let operation = OperationRequest::Status;
        let body = operation.encode().expect("status body");
        let request = RequestEnvelope::new(
            OperationCode::Status,
            runtime.unlock_epoch(),
            5_000,
            None,
            body,
        )
        .expect("status request");
        let connection_id = *client.connection_id();
        let header = FrameHeader::new(
            MessageKind::Request,
            CURRENT_VERSION,
            request.encode().expect("status request bytes").len(),
            connection_id,
            1,
        )
        .expect("status header");
        let commit = lock(&runtime.coordinator.commit_gate).expect("hold admission gate");
        let worker_runtime = Arc::clone(&runtime);
        let worker_client = Arc::clone(&client);
        let worker = std::thread::spawn(move || {
            worker_runtime.dispatch(&worker_client, &header, &request, copy_response)
        });

        let wait_deadline = Instant::now() + Duration::from_secs(1);
        while client.in_flight_count() != 1 {
            assert!(
                Instant::now() < wait_deadline,
                "request ordering must be established before the admission gate"
            );
            std::thread::yield_now();
        }
        let cancel = FrameHeader::new(MessageKind::Cancel, CURRENT_VERSION, 0, connection_id, 1)
            .expect("cancel header");
        client
            .cancel(&cancel)
            .expect("cancel observes the already-issued request");
        assert!(
            !runtime
                .cancel_request(connection_id, 1)
                .expect("runtime cancellation lookup"),
            "the runtime registration is intentionally still behind the gate"
        );
        drop(commit);

        let response = worker
            .join()
            .expect("request worker")
            .expect("cancelled response");
        assert_eq!(response.error(), Some(PublicErrorCode::Cancelled));
        assert_eq!(client.in_flight_count(), 0);
        assert!(!client.is_closed());
    }

    #[test]
    fn transport_admission_callback_follows_request_id_issuance() {
        let directory = TestDirectory::new();
        let runtime = AgentRuntime::start(directory.vault_path()).expect("runtime");
        let client = connection(&runtime, 75);
        let operation = OperationRequest::Status;
        let body = operation.encode().expect("status body");
        let request = RequestEnvelope::new(
            OperationCode::Status,
            runtime.unlock_epoch(),
            5_000,
            None,
            body,
        )
        .expect("status request");
        let header = FrameHeader::new(
            MessageKind::Request,
            CURRENT_VERSION,
            request.encode().expect("status request bytes").len(),
            *client.connection_id(),
            1,
        )
        .expect("status header");
        let callback_count = AtomicUsize::new(0);

        runtime
            .dispatch_with_admission(
                &client,
                &header,
                &request,
                || {
                    assert_eq!(client.in_flight_count(), 1);
                    callback_count.fetch_add(1, Ordering::AcqRel);
                },
                copy_response,
            )
            .expect("status response");

        assert_eq!(callback_count.load(Ordering::Acquire), 1);
        assert_eq!(client.in_flight_count(), 0);
    }

    #[test]
    fn transport_admission_callback_skips_connection_fatal_headers() {
        let directory = TestDirectory::new();
        let runtime = AgentRuntime::start(directory.vault_path()).expect("runtime");
        let client = connection(&runtime, 76);
        let operation = OperationRequest::Status;
        let body = operation.encode().expect("status body");
        let request = RequestEnvelope::new(
            OperationCode::Status,
            runtime.unlock_epoch(),
            5_000,
            None,
            body,
        )
        .expect("status request");
        let mut wrong_connection = *client.connection_id();
        wrong_connection[0] ^= 0xff;
        let header = FrameHeader::new(
            MessageKind::Request,
            CURRENT_VERSION,
            request.encode().expect("status request bytes").len(),
            wrong_connection,
            1,
        )
        .expect("wrong-connection header");
        let callback_count = AtomicUsize::new(0);

        let result = runtime.dispatch_with_admission(
            &client,
            &header,
            &request,
            || {
                callback_count.fetch_add(1, Ordering::AcqRel);
            },
            copy_response,
        );

        assert!(matches!(
            result,
            Err(DispatchError::Connection(ConnectionError::InvalidFrame))
        ));
        assert_eq!(callback_count.load(Ordering::Acquire), 0);
    }

    #[test]
    fn expired_admission_reports_deadline_when_global_capacity_is_full() {
        let directory = TestDirectory::new();
        let runtime = Arc::new(AgentRuntime::start(directory.vault_path()).expect("runtime"));
        let global_permits: Vec<_> = (0..MAX_IN_FLIGHT_GLOBAL)
            .map(|_| {
                CounterPermit::acquire(&runtime.coordinator.global_in_flight, MAX_IN_FLIGHT_GLOBAL)
                    .expect("reserve global capacity")
            })
            .collect();
        let client = connection(&runtime, 78);
        let operation = OperationRequest::Status;
        let body = operation.encode().expect("status body");
        let request = RequestEnvelope::new(
            OperationCode::Status,
            runtime.unlock_epoch(),
            50,
            None,
            body,
        )
        .expect("short status request");
        let header = FrameHeader::new(
            MessageKind::Request,
            CURRENT_VERSION,
            request.encode().expect("status request bytes").len(),
            *client.connection_id(),
            1,
        )
        .expect("status header");
        let commit = lock(&runtime.coordinator.commit_gate).expect("hold admission gate");
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let worker_runtime = Arc::clone(&runtime);
        let worker = std::thread::spawn(move || {
            started_tx.send(()).expect("request worker started");
            worker_runtime.dispatch(&client, &header, &request, copy_response)
        });
        started_rx.recv().expect("request worker start");
        std::thread::sleep(Duration::from_millis(100));
        drop(commit);

        let response = worker
            .join()
            .expect("request worker")
            .expect("deadline response");
        assert_eq!(response.error(), Some(PublicErrorCode::DeadlineExceeded));
        assert_eq!(response.retry(), RetryCategory::Never);
        drop(global_permits);
    }

    #[test]
    fn expired_admission_reports_deadline_when_connection_capacity_is_full() {
        let directory = TestDirectory::new();
        let runtime = Arc::new(AgentRuntime::start(directory.vault_path()).expect("runtime"));
        let client = Arc::new(connection(&runtime, 79));
        let operation = OperationRequest::Status;
        let body = operation.encode().expect("status body");
        let ordinary_request = RequestEnvelope::new(
            OperationCode::Status,
            runtime.unlock_epoch(),
            5_000,
            None,
            Zeroizing::new(body.to_vec()),
        )
        .expect("ordinary status request");
        let ordinary_length = ordinary_request
            .encode()
            .expect("ordinary status request bytes")
            .len();
        let active: Vec<_> = (1..=4)
            .map(|request_id| {
                let header = FrameHeader::new(
                    MessageKind::Request,
                    CURRENT_VERSION,
                    ordinary_length,
                    *client.connection_id(),
                    request_id,
                )
                .expect("active status header");
                client
                    .begin_request(&header, &ordinary_request, runtime.unlock_epoch())
                    .expect("fill per-connection capacity")
            })
            .collect();

        let request = RequestEnvelope::new(
            OperationCode::Status,
            runtime.unlock_epoch(),
            50,
            None,
            body,
        )
        .expect("short status request");
        let header = FrameHeader::new(
            MessageKind::Request,
            CURRENT_VERSION,
            request.encode().expect("status request bytes").len(),
            *client.connection_id(),
            5,
        )
        .expect("status header");
        let commit = lock(&runtime.coordinator.commit_gate).expect("hold admission gate");
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let worker_runtime = Arc::clone(&runtime);
        let worker_client = Arc::clone(&client);
        let worker = std::thread::spawn(move || {
            started_tx.send(()).expect("request worker started");
            worker_runtime.dispatch(&worker_client, &header, &request, copy_response)
        });
        started_rx.recv().expect("request worker start");
        std::thread::sleep(Duration::from_millis(100));
        drop(commit);

        let response = worker
            .join()
            .expect("request worker")
            .expect("deadline response");
        assert_eq!(response.error(), Some(PublicErrorCode::DeadlineExceeded));
        assert_eq!(response.retry(), RetryCategory::Never);
        for permit in active {
            client.finish(permit).expect("release active request");
        }
    }

    #[test]
    fn authenticated_not_found_rechecks_terminal_authorization() {
        let directory = TestDirectory::new();
        let runtime = AgentRuntime::start(directory.vault_path()).expect("runtime");
        runtime
            .state
            .store(AgentState::Unlocked as u8, Ordering::Release);
        let epoch = runtime.unlock_epoch();
        let registration = runtime
            .coordinator
            .register(RequestKey {
                connection_id: [0x74; 16],
                request_id: 1,
            })
            .expect("registration");

        let expired = runtime
            .authenticated_read_error_after_core(
                lock(&runtime.vault).expect("vault"),
                AccountError::NotFound,
                epoch,
                &registration,
                Instant::now(),
            )
            .expect("deadline outcome");
        assert_eq!(expired.error, Some(PublicErrorCode::DeadlineExceeded));
        drop(registration);

        let not_found_connection = connection(&runtime, 75);
        let (_request, _header, permit) = admitted_request(
            &runtime,
            &not_found_connection,
            1,
            &OperationRequest::GetAccount { id: [0x75; 16] },
        );
        let registration = runtime
            .coordinator
            .register(RequestKey {
                connection_id: *not_found_connection.connection_id(),
                request_id: 1,
            })
            .expect("terminal registration");
        runtime
            .state
            .store(AgentState::Locked as u8, Ordering::Release);
        runtime
            .coordinator
            .advance_epoch_without_cancellation()
            .expect("lock epoch");
        let stale = runtime
            .finish_dispatch(
                DispatchContext {
                    connection: &not_found_connection,
                    permit,
                    _global: CounterPermit::acquire(
                        &runtime.coordinator.global_in_flight,
                        MAX_IN_FLIGHT_GLOBAL,
                    )
                    .expect("global permit"),
                    registration,
                    deadline: Instant::now() + Duration::from_secs(1),
                    correlation: CorrelationId::new([0x75; 16]),
                },
                ExecutionOutcome::failure(PublicErrorCode::NotFound, RetryCategory::Never),
                copy_response,
            )
            .expect("terminal response");
        assert_eq!(stale.error(), Some(PublicErrorCode::Locked));
    }

    #[test]
    fn terminal_commit_suppresses_cancelled_and_stale_successes() {
        let directory = TestDirectory::new();
        let runtime = AgentRuntime::start(directory.vault_path()).expect("runtime");

        let status_connection = connection(&runtime, 7);
        let (_request, _header, permit) =
            admitted_request(&runtime, &status_connection, 1, &OperationRequest::Status);
        let registration = runtime
            .coordinator
            .register(RequestKey {
                connection_id: *status_connection.connection_id(),
                request_id: 1,
            })
            .expect("registration");
        let cancel = FrameHeader::new(
            MessageKind::Cancel,
            CURRENT_VERSION,
            0,
            *status_connection.connection_id(),
            1,
        )
        .expect("cancel");
        status_connection.cancel(&cancel).expect("cancel request");
        let global =
            CounterPermit::acquire(&runtime.coordinator.global_in_flight, MAX_IN_FLIGHT_GLOBAL)
                .expect("global permit");
        let cancelled = runtime
            .finish_dispatch(
                DispatchContext {
                    connection: &status_connection,
                    permit,
                    _global: global,
                    registration,
                    deadline: Instant::now() + Duration::from_secs(1),
                    correlation: CorrelationId::new([0x31; 16]),
                },
                ExecutionOutcome::success(Zeroizing::new(b"SECRET-CANARY".to_vec())),
                copy_response,
            )
            .expect("terminal response");
        assert_eq!(cancelled.error(), Some(PublicErrorCode::Cancelled));
        assert!(cancelled.body().is_empty());

        runtime
            .state
            .store(AgentState::Unlocked as u8, Ordering::Release);
        let secret_connection = connection(&runtime, 17);
        let (_request, _header, permit) = admitted_request(
            &runtime,
            &secret_connection,
            1,
            &OperationRequest::GetAccount { id: [0x41; 16] },
        );
        let registration = runtime
            .coordinator
            .register(RequestKey {
                connection_id: *secret_connection.connection_id(),
                request_id: 1,
            })
            .expect("registration");
        runtime
            .state
            .store(AgentState::Locked as u8, Ordering::Release);
        runtime
            .coordinator
            .advance_epoch_without_cancellation()
            .expect("epoch transition");
        let global =
            CounterPermit::acquire(&runtime.coordinator.global_in_flight, MAX_IN_FLIGHT_GLOBAL)
                .expect("global permit");
        let stale = runtime
            .finish_dispatch(
                DispatchContext {
                    connection: &secret_connection,
                    permit,
                    _global: global,
                    registration,
                    deadline: Instant::now() + Duration::from_secs(1),
                    correlation: CorrelationId::new([0x32; 16]),
                },
                ExecutionOutcome::success(Zeroizing::new(b"SECRET-CANARY".to_vec())),
                copy_response,
            )
            .expect("terminal response");
        assert_eq!(stale.error(), Some(PublicErrorCode::Locked));
        assert!(stale.body().is_empty());
    }

    #[test]
    fn committed_empty_result_wins_a_later_cancellation() {
        let directory = TestDirectory::new();
        let runtime = AgentRuntime::start(directory.vault_path()).expect("runtime");
        let client = connection(&runtime, 0xA7);
        let (_request, _header, permit) =
            admitted_request(&runtime, &client, 1, &OperationRequest::Status);
        let registration = runtime
            .coordinator
            .register(RequestKey {
                connection_id: *client.connection_id(),
                request_id: 1,
            })
            .expect("registration");
        let cancel = FrameHeader::new(
            MessageKind::Cancel,
            CURRENT_VERSION,
            0,
            *client.connection_id(),
            1,
        )
        .expect("cancel");
        client.cancel(&cancel).expect("cancel request");

        let response = runtime
            .finish_dispatch(
                DispatchContext {
                    connection: &client,
                    permit,
                    _global: CounterPermit::acquire(
                        &runtime.coordinator.global_in_flight,
                        MAX_IN_FLIGHT_GLOBAL,
                    )
                    .expect("global permit"),
                    registration,
                    deadline: Instant::now() + Duration::from_secs(1),
                    correlation: CorrelationId::new([0xA7; 16]),
                },
                ExecutionOutcome::success(Zeroizing::new(Vec::new())).commit_point(),
                copy_response,
            )
            .expect("committed response");
        assert_eq!(response.error(), None);
    }

    #[test]
    fn terminal_responses_honor_the_negotiated_connection_payload_limit() {
        let directory = TestDirectory::new();
        let runtime = AgentRuntime::start(directory.vault_path()).expect("runtime");
        runtime
            .state
            .store(AgentState::Unlocked as u8, Ordering::Release);
        let limit = 96_u32;
        let client = connection_with_limits(
            &runtime,
            82,
            ConnectionLimits::new(limit, 4).expect("small connection limit"),
        );
        let (_request, _header, permit) = admitted_request(
            &runtime,
            &client,
            1,
            &OperationRequest::GetAccount { id: [0x82; 16] },
        );
        let registration = runtime
            .coordinator
            .register(RequestKey {
                connection_id: *client.connection_id(),
                request_id: 1,
            })
            .expect("registration");
        let response = runtime
            .finish_dispatch(
                DispatchContext {
                    connection: &client,
                    permit,
                    _global: CounterPermit::acquire(
                        &runtime.coordinator.global_in_flight,
                        MAX_IN_FLIGHT_GLOBAL,
                    )
                    .expect("global permit"),
                    registration,
                    deadline: Instant::now() + Duration::from_secs(1),
                    correlation: CorrelationId::new([0x82; 16]),
                },
                ExecutionOutcome::success(Zeroizing::new(vec![0xA5; 256])),
                copy_response,
            )
            .expect("bounded terminal response");
        assert_eq!(response.error(), Some(PublicErrorCode::OperationFailed));
        assert!(response.body().is_empty());
        assert!(
            response.encode().expect("response encoding").len()
                <= usize::try_from(limit).expect("payload limit")
        );
    }

    #[test]
    fn terminal_commit_refreshes_status_snapshot() {
        let directory = TestDirectory::new();
        let runtime = AgentRuntime::start(directory.vault_path()).expect("runtime");
        runtime
            .state
            .store(AgentState::Unlocked as u8, Ordering::Release);
        runtime
            .coordinator
            .advance_epoch_without_cancellation()
            .expect("first epoch");
        let stale_epoch = runtime.unlock_epoch();

        let status_connection = connection(&runtime, 71);
        let (_request, _header, status_permit) =
            admitted_request(&runtime, &status_connection, 1, &OperationRequest::Status);
        let status_registration = runtime
            .coordinator
            .register(RequestKey {
                connection_id: *status_connection.connection_id(),
                request_id: 1,
            })
            .expect("status registration");
        runtime
            .state
            .store(AgentState::Locked as u8, Ordering::Release);
        runtime
            .coordinator
            .advance_epoch_without_cancellation()
            .expect("lock epoch");
        let current_epoch = runtime.unlock_epoch();
        let status = runtime
            .finish_dispatch(
                DispatchContext {
                    connection: &status_connection,
                    permit: status_permit,
                    _global: CounterPermit::acquire(
                        &runtime.coordinator.global_in_flight,
                        MAX_IN_FLIGHT_GLOBAL,
                    )
                    .expect("status global permit"),
                    registration: status_registration,
                    deadline: Instant::now() + Duration::from_secs(1),
                    correlation: CorrelationId::new([0x71; 16]),
                },
                ExecutionOutcome::success(
                    encode_status(AgentState::Unlocked, stale_epoch).expect("stale status body"),
                ),
                copy_response,
            )
            .expect("status response");
        assert_eq!(
            decode_status_response(&status),
            (AgentState::Locked, current_epoch)
        );
    }

    #[test]
    fn terminal_commit_refreshes_replayed_create_epoch() {
        let directory = TestDirectory::new();
        let runtime = AgentRuntime::start(directory.vault_path()).expect("runtime");
        runtime
            .state
            .store(AgentState::Unlocked as u8, Ordering::Release);
        runtime
            .coordinator
            .advance_epoch_without_cancellation()
            .expect("creation epoch");
        let stale_epoch = runtime.unlock_epoch();
        let create_connection = connection(&runtime, 81);
        let create = OperationRequest::CreateVault {
            master_password: Zeroizing::new("replayed create password".to_owned()),
        };
        let body = create.encode().expect("create body");
        let envelope =
            RequestEnvelope::new(OperationCode::CreateVault, 0, 5_000, Some([0x81; 16]), body)
                .expect("create envelope");
        let header = FrameHeader::new(
            MessageKind::Request,
            CURRENT_VERSION,
            envelope.encode().expect("create bytes").len(),
            *create_connection.connection_id(),
            1,
        )
        .expect("create header");
        let create_permit = create_connection
            .begin_request(&header, &envelope, stale_epoch)
            .expect("create admission");
        let create_registration = runtime
            .coordinator
            .register(RequestKey {
                connection_id: *create_connection.connection_id(),
                request_id: 1,
            })
            .expect("create registration");
        runtime
            .state
            .store(AgentState::Locked as u8, Ordering::Release);
        runtime
            .coordinator
            .advance_epoch_without_cancellation()
            .expect("lock epoch");
        let replay_epoch = runtime.unlock_epoch();
        let mut cached = ExecutionOutcome::success(
            encode_status(AgentState::Unlocked, stale_epoch).expect("cached create status body"),
        );
        cached.replayed = true;
        let replay = runtime
            .finish_dispatch(
                DispatchContext {
                    connection: &create_connection,
                    permit: create_permit,
                    _global: CounterPermit::acquire(
                        &runtime.coordinator.global_in_flight,
                        MAX_IN_FLIGHT_GLOBAL,
                    )
                    .expect("create global permit"),
                    registration: create_registration,
                    deadline: Instant::now() + Duration::from_secs(1),
                    correlation: CorrelationId::new([0x81; 16]),
                },
                cached,
                copy_response,
            )
            .expect("replayed create response");
        assert_eq!(
            decode_status_response(&replay),
            (AgentState::Locked, replay_epoch)
        );
    }

    #[test]
    fn page_deadline_is_rechecked_after_waiting_for_the_vault_mutex() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let runtime = Arc::new(AgentRuntime::start(&path).expect("runtime"));
        let password = MasterPassword::new("page deadline password").expect("password");
        let (created, recovery_key) = VaultAgent::create(&path, password).expect("vault");
        drop(recovery_key);
        *lock(&runtime.vault).expect("vault lock") = created;
        runtime
            .state
            .store(AgentState::Unlocked as u8, Ordering::Release);
        runtime
            .coordinator
            .advance_epoch_without_cancellation()
            .expect("unlock epoch");
        let epoch = runtime.unlock_epoch();
        let registration = runtime
            .coordinator
            .register(RequestKey {
                connection_id: [0x91; 16],
                request_id: 1,
            })
            .expect("registration");

        let held_vault = lock(&runtime.vault).expect("hold vault mutex");
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let worker_runtime = Arc::clone(&runtime);
        let deadline = Instant::now() + Duration::from_millis(500);
        let worker = std::thread::spawn(move || {
            started_tx.send(()).expect("worker start");
            worker_runtime.list_accounts(0, 10, epoch, &registration, deadline)
        });
        started_rx.recv().expect("worker started");
        std::thread::sleep(Duration::from_millis(700));
        drop(held_vault);

        let outcome = worker.join().expect("page worker").expect("page outcome");
        assert_eq!(outcome.error, Some(PublicErrorCode::DeadlineExceeded));
        assert_eq!(runtime.state(), AgentState::Unlocked);
        assert_eq!(runtime.unlock_epoch(), epoch);
    }

    #[test]
    fn request_local_cancellation_does_not_lock_the_shared_session() {
        let directory = TestDirectory::new();
        let runtime = AgentRuntime::start(directory.vault_path()).expect("runtime");
        runtime
            .state
            .store(AgentState::Unlocked as u8, Ordering::Release);
        let epoch = runtime.unlock_epoch();
        let registration = runtime
            .coordinator
            .register(RequestKey {
                connection_id: [0x51; 16],
                request_id: 1,
            })
            .expect("registration");
        registration.cancellation.cancel();

        let mut vault = lock(&runtime.vault).expect("vault lock");
        let outcome = runtime
            .post_secret_operation(
                &mut vault,
                epoch,
                &registration,
                Instant::now() + Duration::from_secs(1),
            )
            .expect("cancel outcome");
        drop(vault);
        assert_eq!(outcome.error, Some(PublicErrorCode::Cancelled));
        assert_eq!(runtime.state(), AgentState::Unlocked);
        assert_eq!(runtime.unlock_epoch(), epoch);
    }

    #[test]
    fn mutation_commit_cancellation_rolls_back_without_locking_the_session() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let runtime = Arc::new(AgentRuntime::start(&path).expect("runtime"));
        let password = MasterPassword::new("mutation cancellation password").expect("password");
        let (created, recovery_key) = VaultAgent::create(&path, password).expect("vault");
        drop(recovery_key);
        *lock(&runtime.vault).expect("vault lock") = created;
        runtime
            .state
            .store(AgentState::Unlocked as u8, Ordering::Release);
        runtime
            .coordinator
            .advance_epoch_without_cancellation()
            .expect("unlock epoch");
        let epoch = runtime.unlock_epoch();
        let registration = runtime
            .coordinator
            .register(RequestKey {
                connection_id: [0x61; 16],
                request_id: 1,
            })
            .expect("registration");
        let cancellation = Arc::clone(&registration.cancellation);
        let fields = librarian_agent_protocol::AccountFields::new(
            "Cancelled Mutation",
            "https://cancelled-mutation.example",
            "cancelled@example.test",
            "CANCELLED-MUTATION-PASSWORD-CANARY",
        )
        .expect("account fields");

        let commit_guard = lock(&runtime.coordinator.commit_gate).expect("commit gate");
        let worker_runtime = Arc::clone(&runtime);
        let worker = std::thread::spawn(move || {
            worker_runtime.add_account(
                &fields,
                epoch,
                &registration,
                Instant::now() + Duration::from_secs(5),
            )
        });
        let wait_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mutation_active = runtime.coordinator.mutation_active.load(Ordering::Acquire);
            let vault_is_held = runtime.vault.try_lock().is_err();
            if mutation_active && vault_is_held {
                break;
            }
            assert!(
                Instant::now() < wait_deadline,
                "mutation must reach the commit barrier"
            );
            std::thread::yield_now();
        }
        cancellation.cancel();
        drop(commit_guard);

        let outcome = worker
            .join()
            .expect("mutation worker")
            .expect("mutation outcome");
        assert_eq!(outcome.error, Some(PublicErrorCode::Cancelled));
        assert_eq!(runtime.state(), AgentState::Unlocked);
        assert_eq!(runtime.unlock_epoch(), epoch);
        let mut vault = lock(&runtime.vault).expect("vault lock");
        assert!(vault.is_unlocked());
        assert!(
            vault
                .list_website_accounts()
                .expect("authenticated empty vault")
                .is_empty()
        );
    }

    #[test]
    fn windows_hello_cycle_reenrolls_unlocks_removes_and_preserves_password_fallback() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let provider = Arc::new(TestWindowsHelloProvider::new());
        let state = Arc::new(TestWindowsHelloStateRepository::default());
        let runtime =
            AgentRuntime::start_with_components(&path, Some(provider.clone()), Some(state.clone()))
                .expect("runtime");
        let password = "disposable hello runtime password";
        create_test_vault(&runtime, password);

        let first_registration = test_registration(&runtime, 0xC1);
        let first = runtime
            .enroll_windows_hello(
                0x1234,
                17,
                runtime.unlock_epoch(),
                &first_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("first enrollment outcome");
        assert_eq!(first.error, None);
        drop(first_registration);
        assert_eq!(state.credential_id(), Some(vec![0xA0, 0]));

        let second_registration = test_registration(&runtime, 0xC2);
        let second = runtime
            .enroll_windows_hello(
                0x1234,
                17,
                runtime.unlock_epoch(),
                &second_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("replacement enrollment outcome");
        assert_eq!(second.error, None);
        drop(second_registration);
        assert_eq!(state.credential_id(), Some(vec![0xA0, 1]));
        assert_eq!(provider.removed(), vec![vec![0xA0, 0]]);

        complete_test_lock(&runtime);
        let unlock_registration = test_registration(&runtime, 0xC3);
        let unlocked = runtime
            .unlock_windows_hello(
                0x1234,
                17,
                runtime.unlock_epoch(),
                &unlock_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("hello unlock outcome");
        assert_eq!(unlocked.error, None);
        assert_eq!(runtime.state(), AgentState::Unlocked);
        drop(unlock_registration);
        assert_eq!(provider.evaluated(), vec![(0x1234, 17, vec![0xA0, 1])]);

        let remove_registration = test_registration(&runtime, 0xC4);
        let removed = runtime
            .remove_windows_hello(
                runtime.unlock_epoch(),
                &remove_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("remove outcome");
        assert_eq!(removed.error, None);
        drop(remove_registration);
        assert!(state.is_empty());
        assert_eq!(provider.removed(), vec![vec![0xA0, 0], vec![0xA0, 1]]);

        complete_test_lock(&runtime);
        let fallback_registration = test_registration(&runtime, 0xC5);
        let fallback = runtime
            .unlock_vault(
                password,
                &fallback_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("password fallback outcome");
        assert_eq!(fallback.error, None);
        assert_eq!(runtime.state(), AgentState::Unlocked);
    }

    #[test]
    fn windows_hello_corrupt_existing_state_blocks_enrollment() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let provider = Arc::new(TestWindowsHelloProvider::new());
        let state = Arc::new(TestWindowsHelloStateRepository::default());
        let runtime =
            AgentRuntime::start_with_components(&path, Some(provider.clone()), Some(state.clone()))
                .expect("runtime");
        create_test_vault(&runtime, "disposable corrupt state password");
        state.corrupt();

        let registration = test_registration(&runtime, 0xDD);
        let outcome = runtime
            .enroll_windows_hello(
                0x1234,
                17,
                runtime.unlock_epoch(),
                &registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("corrupt-state outcome");
        assert_eq!(outcome.error, Some(PublicErrorCode::OperationFailed));
        assert_eq!(provider.next_credential.load(Ordering::Acquire), 0);
        assert_eq!(state.save_count(), 0);
        assert!(!state.is_empty());
    }

    #[test]
    fn windows_hello_reenrollment_persists_retirement_until_deletion() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let provider = Arc::new(TestWindowsHelloProvider::new());
        let state = Arc::new(TestWindowsHelloStateRepository::default());
        let runtime = Arc::new(
            AgentRuntime::start_with_components(&path, Some(provider.clone()), Some(state.clone()))
                .expect("runtime"),
        );
        create_test_vault(&runtime, "disposable durable retirement password");

        let first_registration = test_registration(&runtime, 0xDE);
        let first = runtime
            .enroll_windows_hello(
                0x1234,
                17,
                runtime.unlock_epoch(),
                &first_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("first enrollment");
        assert_eq!(first.error, None);
        drop(first_registration);

        provider.block_removal();
        let request_epoch = runtime.unlock_epoch();
        let worker_runtime = Arc::clone(&runtime);
        let worker = std::thread::spawn(move || {
            let registration = test_registration(&worker_runtime, 0xDF);
            worker_runtime.enroll_windows_hello(
                0x1234,
                17,
                request_epoch,
                &registration,
                Instant::now() + Duration::from_secs(10),
            )
        });
        let wait_deadline = Instant::now() + Duration::from_secs(5);
        while !provider.removal_started.load(Ordering::Acquire) {
            assert!(
                Instant::now() < wait_deadline,
                "retirement removal must start"
            );
            std::thread::yield_now();
        }
        assert_eq!(state.credential_id(), Some(vec![0xA0, 1]));
        assert_eq!(state.pending_removal_credential_id(), Some(vec![0xA0, 0]));

        provider.release_removal();
        let outcome = worker
            .join()
            .expect("reenrollment worker")
            .expect("reenrollment outcome");
        assert_eq!(outcome.error, None);
        assert_eq!(state.credential_id(), Some(vec![0xA0, 1]));
        assert_eq!(state.pending_removal_credential_id(), None);
        assert_eq!(provider.removed(), vec![vec![0xA0, 0]]);
    }

    #[test]
    fn windows_hello_retries_persisted_retirement_without_a_new_ceremony() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let provider = Arc::new(TestWindowsHelloProvider::new());
        let state = Arc::new(TestWindowsHelloStateRepository::default());
        let runtime =
            AgentRuntime::start_with_components(&path, Some(provider.clone()), Some(state.clone()))
                .expect("runtime");
        create_test_vault(&runtime, "disposable retirement retry password");

        let first_registration = test_registration(&runtime, 0xE3);
        let first = runtime
            .enroll_windows_hello(
                0x1234,
                17,
                runtime.unlock_epoch(),
                &first_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("first enrollment");
        assert_eq!(first.error, None);
        drop(first_registration);
        let mut persisted = state.load().expect("persisted enrollment");
        persisted
            .set_pending_removal_credential_id(&[0xB0, 0])
            .expect("pending retirement");
        state.save(&persisted).expect("pending retirement save");

        let retry_registration = test_registration(&runtime, 0xE4);
        let retry = runtime
            .enroll_windows_hello(
                0x1234,
                17,
                runtime.unlock_epoch(),
                &retry_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("retirement retry");
        assert_eq!(retry.error, None);
        assert_eq!(provider.next_credential.load(Ordering::Acquire), 1);
        assert_eq!(state.credential_id(), Some(vec![0xA0, 0]));
        assert_eq!(state.pending_removal_credential_id(), None);
        assert_eq!(provider.removed(), vec![vec![0xB0, 0]]);
    }

    #[test]
    fn windows_hello_recovered_retirement_reenrolls_for_a_different_vault() {
        let first_directory = TestDirectory::new();
        let provider = Arc::new(TestWindowsHelloProvider::new());
        let state = Arc::new(TestWindowsHelloStateRepository::default());
        let first_runtime = AgentRuntime::start_with_components(
            &first_directory.vault_path(),
            Some(provider.clone()),
            Some(state.clone()),
        )
        .expect("first runtime");
        create_test_vault(
            &first_runtime,
            "disposable first recovered binding password",
        );
        let first_registration = test_registration(&first_runtime, 0xE5);
        let first = first_runtime
            .enroll_windows_hello(
                0x1234,
                17,
                first_runtime.unlock_epoch(),
                &first_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("first enrollment");
        assert_eq!(first.error, None);
        drop(first_registration);
        let first_binding = state.vault_binding().expect("first binding");
        let mut persisted = state.load().expect("persisted first enrollment");
        persisted
            .set_pending_removal_credential_id(&[0xB1, 0])
            .expect("pending retirement");
        state.save(&persisted).expect("pending retirement save");
        drop(first_runtime);

        let second_directory = TestDirectory::new();
        let second_runtime = AgentRuntime::start_with_components(
            &second_directory.vault_path(),
            Some(provider.clone()),
            Some(state.clone()),
        )
        .expect("second runtime");
        create_test_vault(
            &second_runtime,
            "disposable second recovered binding password",
        );
        let second_registration = test_registration(&second_runtime, 0xE6);
        let second = second_runtime
            .enroll_windows_hello(
                0x1234,
                17,
                second_runtime.unlock_epoch(),
                &second_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("second enrollment");
        assert_eq!(second.error, None);
        assert_eq!(provider.next_credential.load(Ordering::Acquire), 2);
        assert_eq!(state.credential_id(), Some(vec![0xA0, 1]));
        assert_ne!(state.vault_binding(), Some(first_binding));
        assert_eq!(
            state.vault_binding(),
            lock(&second_runtime.vault)
                .expect("second vault")
                .authenticated_vault_binding()
        );
        assert_eq!(provider.removed(), vec![vec![0xB1, 0], vec![0xA0, 0]]);
    }

    #[test]
    fn windows_hello_reenrollment_requires_previous_credential_retirement() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let provider = Arc::new(TestWindowsHelloProvider::new());
        let state = Arc::new(TestWindowsHelloStateRepository::default());
        let runtime =
            AgentRuntime::start_with_components(&path, Some(provider.clone()), Some(state.clone()))
                .expect("runtime");
        create_test_vault(&runtime, "disposable retirement failure password");

        let first_registration = test_registration(&runtime, 0xD1);
        let first = runtime
            .enroll_windows_hello(
                0x1234,
                17,
                runtime.unlock_epoch(),
                &first_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("first enrollment");
        assert_eq!(first.error, None);
        drop(first_registration);

        provider.fail_removal_for(vec![0xA0, 0]);
        let second_registration = test_registration(&runtime, 0xD2);
        let second = runtime
            .enroll_windows_hello(
                0x1234,
                17,
                runtime.unlock_epoch(),
                &second_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("failed replacement enrollment");
        assert_eq!(second.error, Some(PublicErrorCode::OperationFailed));
        assert_eq!(second.retry, RetryCategory::Backoff);
        assert!(!should_cache(&second));
        assert_eq!(state.credential_id(), Some(vec![0xA0, 0]));
        assert_eq!(
            state.save_count(),
            3,
            "replacement must publish before retirement failure rolls back"
        );
        assert_eq!(provider.removed(), vec![vec![0xA0, 1]]);
    }

    #[test]
    fn windows_hello_published_rollback_still_removes_the_replacement() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let provider = Arc::new(TestWindowsHelloProvider::new());
        let state = Arc::new(TestWindowsHelloStateRepository::default());
        let runtime = Arc::new(
            AgentRuntime::start_with_components(&path, Some(provider.clone()), Some(state.clone()))
                .expect("runtime"),
        );
        create_test_vault(&runtime, "disposable published rollback password");
        let first_registration = test_registration(&runtime, 0xE7);
        let first = runtime
            .enroll_windows_hello(
                0x1234,
                17,
                runtime.unlock_epoch(),
                &first_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("first enrollment");
        assert_eq!(first.error, None);
        drop(first_registration);

        provider.fail_next_removals_for(vec![0xA0, 0], 1);
        provider.block_removal();
        let request_epoch = runtime.unlock_epoch();
        let worker_runtime = Arc::clone(&runtime);
        let worker = std::thread::spawn(move || {
            let registration = test_registration(&worker_runtime, 0xE8);
            worker_runtime.enroll_windows_hello(
                0x1234,
                17,
                request_epoch,
                &registration,
                Instant::now() + Duration::from_secs(10),
            )
        });
        let wait_deadline = Instant::now() + Duration::from_secs(5);
        while !provider.removal_started.load(Ordering::Acquire) {
            assert!(
                Instant::now() < wait_deadline,
                "old credential removal must start"
            );
            std::thread::yield_now();
        }
        state.fail_next_save_after_publication();
        provider.release_removal();

        let second = worker
            .join()
            .expect("reenrollment worker")
            .expect("reenrollment outcome");
        assert_eq!(second.error, Some(PublicErrorCode::OperationFailed));
        assert_eq!(second.retry, RetryCategory::Backoff);
        assert_eq!(state.credential_id(), Some(vec![0xA0, 0]));
        assert_eq!(state.pending_removal_credential_id(), None);
        assert_eq!(provider.removed(), vec![vec![0xA0, 1]]);
    }

    #[test]
    fn windows_hello_post_publication_failure_preserves_the_published_credential() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let provider = Arc::new(TestWindowsHelloProvider::new());
        let state = Arc::new(TestWindowsHelloStateRepository::default());
        let runtime =
            AgentRuntime::start_with_components(&path, Some(provider.clone()), Some(state.clone()))
                .expect("runtime");
        create_test_vault(&runtime, "disposable publication failure password");

        state.fail_next_save_after_publication();
        let registration = test_registration(&runtime, 0xD3);
        let outcome = runtime
            .enroll_windows_hello(
                0x1234,
                17,
                runtime.unlock_epoch(),
                &registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("post-publication failure");
        assert_eq!(outcome.error, Some(PublicErrorCode::OperationFailed));
        assert_eq!(outcome.retry, RetryCategory::Backoff);
        assert!(!should_cache(&outcome));
        assert_eq!(state.credential_id(), Some(vec![0xA0, 0]));
        assert!(provider.removed().is_empty());
        drop(registration);

        let retry_registration = test_registration(&runtime, 0xD4);
        let retry = runtime
            .enroll_windows_hello(
                0x1234,
                17,
                runtime.unlock_epoch(),
                &retry_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("published enrollment reconciliation");
        assert_eq!(retry.error, None);
        assert_eq!(state.credential_id(), Some(vec![0xA0, 1]));
        assert_eq!(provider.removed(), vec![vec![0xA0, 0]]);
    }

    #[test]
    fn windows_hello_stale_unlock_epoch_never_starts_a_ceremony() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let provider = Arc::new(TestWindowsHelloProvider::new());
        let state = Arc::new(TestWindowsHelloStateRepository::default());
        let runtime =
            AgentRuntime::start_with_components(&path, Some(provider.clone()), Some(state))
                .expect("runtime");
        create_test_vault(&runtime, "disposable stale hello epoch password");

        let enroll_registration = test_registration(&runtime, 0xD4);
        let enrolled = runtime
            .enroll_windows_hello(
                0x1234,
                17,
                runtime.unlock_epoch(),
                &enroll_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("enrollment");
        assert_eq!(enrolled.error, None);
        drop(enroll_registration);

        let stale_epoch = runtime.unlock_epoch();
        complete_test_lock(&runtime);
        assert_ne!(runtime.unlock_epoch(), stale_epoch);
        let unlock_registration = test_registration(&runtime, 0xD5);
        let outcome = runtime
            .unlock_windows_hello(
                0x1234,
                17,
                stale_epoch,
                &unlock_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("stale unlock outcome");
        assert_eq!(outcome.error, Some(PublicErrorCode::Locked));
        assert!(provider.evaluated().is_empty());
        assert_eq!(runtime.state(), AgentState::Locked);
    }

    #[test]
    fn windows_hello_cancelled_while_waiting_never_starts_unlock_prompt() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let provider = Arc::new(TestWindowsHelloProvider::new());
        let state = Arc::new(TestWindowsHelloStateRepository::default());
        let runtime = Arc::new(
            AgentRuntime::start_with_components(&path, Some(provider.clone()), Some(state))
                .expect("runtime"),
        );
        create_test_vault(&runtime, "disposable waiting unlock password");
        let enroll_registration = test_registration(&runtime, 0xE0);
        let enrolled = runtime
            .enroll_windows_hello(
                0x1234,
                17,
                runtime.unlock_epoch(),
                &enroll_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("enrollment");
        assert_eq!(enrolled.error, None);
        drop(enroll_registration);
        complete_test_lock(&runtime);

        let gate = lock(&runtime.windows_hello_gate).expect("Hello gate");
        let request_epoch = runtime.unlock_epoch();
        let registration = test_registration(&runtime, 0xE1);
        let cancellation = Arc::clone(&registration.cancellation);
        let worker_runtime = Arc::clone(&runtime);
        let worker = std::thread::spawn(move || {
            worker_runtime.unlock_windows_hello(
                0x1234,
                17,
                request_epoch,
                &registration,
                Instant::now() + Duration::from_secs(10),
            )
        });
        let wait_deadline = Instant::now() + Duration::from_secs(5);
        while !runtime.windows_hello_active.load(Ordering::Acquire) {
            assert!(
                Instant::now() < wait_deadline,
                "unlock must wait for the Hello gate"
            );
            std::thread::yield_now();
        }
        cancellation.cancel();
        drop(gate);

        let outcome = worker
            .join()
            .expect("unlock worker")
            .expect("unlock outcome");
        assert_eq!(outcome.error, Some(PublicErrorCode::Cancelled));
        assert!(provider.evaluated().is_empty());
        assert_eq!(runtime.state(), AgentState::Locked);
    }

    #[test]
    fn windows_hello_partial_removal_failure_remains_retryable() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let provider = Arc::new(TestWindowsHelloProvider::new());
        let state = Arc::new(TestWindowsHelloStateRepository::default());
        let runtime =
            AgentRuntime::start_with_components(&path, Some(provider.clone()), Some(state.clone()))
                .expect("runtime");
        create_test_vault(&runtime, "disposable retryable removal password");

        let enroll_registration = test_registration(&runtime, 0xD5);
        let enrolled = runtime
            .enroll_windows_hello(
                0x1234,
                17,
                runtime.unlock_epoch(),
                &enroll_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("enrollment");
        assert_eq!(enrolled.error, None);
        drop(enroll_registration);

        state.fail_next_remove();
        let first_remove_registration = test_registration(&runtime, 0xD6);
        let first_remove = runtime
            .remove_windows_hello(
                runtime.unlock_epoch(),
                &first_remove_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("first removal");
        assert_eq!(first_remove.error, Some(PublicErrorCode::OperationFailed));
        assert_eq!(first_remove.retry, RetryCategory::Backoff);
        assert!(!should_cache(&first_remove));
        assert_eq!(state.credential_id(), Some(vec![0xA0, 0]));
        drop(first_remove_registration);

        let retry_registration = test_registration(&runtime, 0xD7);
        let retry = runtime
            .remove_windows_hello(
                runtime.unlock_epoch(),
                &retry_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("retry removal");
        assert_eq!(retry.error, None);
        assert!(retry.committed);
        assert!(state.is_empty());
    }

    #[test]
    fn windows_hello_absent_state_retries_the_removal_durability_barrier() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let provider = Arc::new(TestWindowsHelloProvider::new());
        let state = Arc::new(TestWindowsHelloStateRepository::default());
        let runtime =
            AgentRuntime::start_with_components(&path, Some(provider.clone()), Some(state.clone()))
                .expect("runtime");
        create_test_vault(&runtime, "disposable removal durability password");
        let enrollment_registration = test_registration(&runtime, 0xE9);
        let enrollment = runtime
            .enroll_windows_hello(
                0x1234,
                17,
                runtime.unlock_epoch(),
                &enrollment_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("enrollment");
        assert_eq!(enrollment.error, None);
        drop(enrollment_registration);

        let baseline_remove_count = state.remove_count();
        state.fail_next_remove_after_publication();
        let first_registration = test_registration(&runtime, 0xEA);
        let first = runtime
            .remove_windows_hello(
                runtime.unlock_epoch(),
                &first_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("first removal");
        assert_eq!(first.error, Some(PublicErrorCode::OperationFailed));
        assert_eq!(first.retry, RetryCategory::Backoff);
        assert!(state.is_empty());
        drop(first_registration);

        let retry_registration = test_registration(&runtime, 0xEB);
        let retry = runtime
            .remove_windows_hello(
                runtime.unlock_epoch(),
                &retry_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("durability retry");
        assert_eq!(retry.error, None);
        assert_eq!(state.remove_count(), baseline_remove_count + 2);
        assert_eq!(provider.removed(), vec![vec![0xA0, 0]]);
    }

    #[test]
    fn windows_hello_removal_commit_precedes_a_waiting_lock() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let provider = Arc::new(TestWindowsHelloProvider::new());
        let state = Arc::new(TestWindowsHelloStateRepository::default());
        let runtime = Arc::new(
            AgentRuntime::start_with_components(&path, Some(provider.clone()), Some(state))
                .expect("runtime"),
        );
        create_test_vault(&runtime, "disposable removal commit password");

        let enroll_registration = test_registration(&runtime, 0xD8);
        let enrolled = runtime
            .enroll_windows_hello(
                0x1234,
                17,
                runtime.unlock_epoch(),
                &enroll_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("enrollment");
        assert_eq!(enrolled.error, None);
        drop(enroll_registration);

        provider.block_removal();
        let request_epoch = runtime.unlock_epoch();
        let remove_runtime = Arc::clone(&runtime);
        let remove_worker = std::thread::spawn(move || {
            let registration = test_registration(&remove_runtime, 0xD9);
            remove_runtime.remove_windows_hello(
                request_epoch,
                &registration,
                Instant::now() + Duration::from_secs(10),
            )
        });
        let wait_deadline = Instant::now() + Duration::from_secs(5);
        while !provider.removal_started.load(Ordering::Acquire) {
            assert!(
                Instant::now() < wait_deadline,
                "credential removal must start"
            );
            std::thread::yield_now();
        }

        let lock_started = Arc::new(AtomicBool::new(false));
        let lock_runtime = Arc::clone(&runtime);
        let lock_worker_started = Arc::clone(&lock_started);
        let lock_worker = std::thread::spawn(move || {
            lock_worker_started.store(true, Ordering::Release);
            lock_runtime.lock_vault()
        });
        while !lock_started.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        std::thread::sleep(Duration::from_millis(25));
        assert!(
            !runtime.coordinator.lock_active.load(Ordering::Acquire),
            "lock intent must wait behind the removal commit point"
        );

        provider.release_removal();
        let removed = remove_worker
            .join()
            .expect("remove worker")
            .expect("remove outcome");
        assert_eq!(removed.error, None);
        assert!(removed.committed);
        let locked = lock_worker
            .join()
            .expect("lock worker")
            .expect("lock outcome");
        assert_eq!(locked.error, None);
        assert_eq!(runtime.state(), AgentState::Locked);
    }

    #[test]
    fn windows_hello_cancellation_reaches_the_provider_and_publishes_no_state() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let provider = Arc::new(CancellingWindowsHelloProvider::new(2));
        let state = Arc::new(TestWindowsHelloStateRepository::default());
        let runtime = Arc::new(
            AgentRuntime::start_with_components(&path, Some(provider.clone()), Some(state.clone()))
                .expect("runtime"),
        );
        create_test_vault(&runtime, "disposable cancelled hello password");
        let request_epoch = runtime.unlock_epoch();
        let registration = test_registration(&runtime, 0xC6);
        let cancellation = Arc::clone(&registration.cancellation);
        let worker_runtime = Arc::clone(&runtime);
        let worker = std::thread::spawn(move || {
            worker_runtime.enroll_windows_hello(
                0x5678,
                23,
                request_epoch,
                &registration,
                Instant::now() + Duration::from_secs(10),
            )
        });

        let wait_deadline = Instant::now() + Duration::from_secs(5);
        while !provider.started.load(Ordering::Acquire) {
            assert!(
                Instant::now() < wait_deadline,
                "provider ceremony must start"
            );
            std::thread::yield_now();
        }
        cancellation.cancel();
        let outcome = worker
            .join()
            .expect("enrollment worker")
            .expect("cancellation outcome");
        assert_eq!(outcome.error, Some(PublicErrorCode::Cancelled));
        assert!(
            provider.cancellation_attempts.load(Ordering::Acquire) >= 3,
            "cancellation must be retried until the provider observes it"
        );
        assert!(state.is_empty());
        assert_eq!(runtime.state(), AgentState::Unlocked);
    }

    #[test]
    fn windows_hello_lock_cancels_the_ceremony_before_locking_the_vault() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let provider = Arc::new(CancellingWindowsHelloProvider::new(1));
        let state = Arc::new(TestWindowsHelloStateRepository::default());
        let runtime = Arc::new(
            AgentRuntime::start_with_components(&path, Some(provider.clone()), Some(state.clone()))
                .expect("runtime"),
        );
        create_test_vault(&runtime, "disposable lock cancellation password");
        let request_epoch = runtime.unlock_epoch();
        let worker_runtime = Arc::clone(&runtime);
        let worker = std::thread::spawn(move || {
            let registration = test_registration(&worker_runtime, 0xDA);
            worker_runtime.enroll_windows_hello(
                0x5678,
                23,
                request_epoch,
                &registration,
                Instant::now() + Duration::from_secs(10),
            )
        });

        let wait_deadline = Instant::now() + Duration::from_secs(5);
        while !provider.started.load(Ordering::Acquire) {
            assert!(
                Instant::now() < wait_deadline,
                "provider ceremony must start"
            );
            std::thread::yield_now();
        }
        let locked = runtime.lock_vault().expect("lock outcome");
        assert_eq!(locked.error, None);
        assert!(locked.holds_lock_transition);
        let enrollment = worker
            .join()
            .expect("enrollment worker")
            .expect("enrollment outcome");
        assert_eq!(enrollment.error, Some(PublicErrorCode::Cancelled));
        assert!(
            provider.cancellation_attempts.load(Ordering::Acquire) >= 2,
            "lock cancellation must be retried until the provider observes it"
        );
        assert!(state.is_empty());
        assert_eq!(runtime.state(), AgentState::Locked);
        drop(FlagPermit::take_over_active(
            &runtime.coordinator.lock_active,
        ));
    }

    #[test]
    fn windows_hello_shutdown_cancels_and_waits_for_the_ceremony() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let provider = Arc::new(CancellingWindowsHelloProvider::new(1));
        let state = Arc::new(TestWindowsHelloStateRepository::default());
        let runtime = Arc::new(
            AgentRuntime::start_with_components(&path, Some(provider.clone()), Some(state.clone()))
                .expect("runtime"),
        );
        create_test_vault(&runtime, "disposable shutdown cancellation password");
        let request_epoch = runtime.unlock_epoch();
        let worker_runtime = Arc::clone(&runtime);
        let worker = std::thread::spawn(move || {
            let registration = test_registration(&worker_runtime, 0xE2);
            worker_runtime.enroll_windows_hello(
                0x5678,
                23,
                request_epoch,
                &registration,
                Instant::now() + Duration::from_secs(10),
            )
        });

        let wait_deadline = Instant::now() + Duration::from_secs(5);
        while !provider.started.load(Ordering::Acquire) {
            assert!(
                Instant::now() < wait_deadline,
                "provider ceremony must start"
            );
            std::thread::yield_now();
        }
        runtime.shutdown().expect("shutdown");
        let enrollment = worker
            .join()
            .expect("enrollment worker")
            .expect("enrollment outcome");
        assert_eq!(enrollment.error, Some(PublicErrorCode::Cancelled));
        assert!(
            provider.cancellation_attempts.load(Ordering::Acquire) >= 2,
            "shutdown cancellation must be retried until observed"
        );
        assert!(state.is_empty());
        assert_eq!(runtime.state(), AgentState::ShuttingDown);
        assert!(!runtime.windows_hello_active.load(Ordering::Acquire));
    }

    #[test]
    fn windows_hello_native_cleanup_failure_persists_credential_for_restart_retry() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let provider = Arc::new(TestWindowsHelloProvider::new());
        let state = Arc::new(TestWindowsHelloStateRepository::default());
        let runtime =
            AgentRuntime::start_with_components(&path, Some(provider.clone()), Some(state.clone()))
                .expect("runtime");
        let password = "disposable native cleanup recovery password";
        create_test_vault(&runtime, password);

        let orphaned_credential_id = vec![0xC1, 0xC2];
        provider.fail_next_enrollment_cleanup(orphaned_credential_id.clone());
        let first_registration = test_registration(&runtime, 0xDA);
        let first = runtime
            .enroll_windows_hello(
                0x5678,
                23,
                runtime.unlock_epoch(),
                &first_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("native cleanup failure");
        assert_eq!(first.error, Some(PublicErrorCode::OperationFailed));
        assert_eq!(first.retry, RetryCategory::Backoff);
        assert!(!should_cache(&first));
        assert_eq!(state.credential_id(), None);
        assert_eq!(
            state.pending_removal_credential_id(),
            Some(orphaned_credential_id.clone())
        );
        drop(first_registration);
        drop(runtime);

        let runtime =
            AgentRuntime::start_with_components(&path, Some(provider.clone()), Some(state.clone()))
                .expect("restarted runtime");
        let unlock_registration = test_registration(&runtime, 0xDB);
        let unlocked = runtime
            .unlock_vault(
                password,
                &unlock_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("password unlock after restart");
        assert_eq!(unlocked.error, None);
        drop(unlock_registration);

        let retry_registration = test_registration(&runtime, 0xDC);
        let retry = runtime
            .enroll_windows_hello(
                0x5678,
                23,
                runtime.unlock_epoch(),
                &retry_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("cleanup retry enrollment");
        assert_eq!(retry.error, None);
        assert_eq!(state.credential_id(), Some(vec![0xA0, 0]));
        assert_eq!(state.pending_removal_credential_id(), None);
        assert_eq!(provider.removed(), vec![orphaned_credential_id]);
    }

    #[test]
    fn windows_hello_failed_cleanup_retains_the_credential_for_retry() {
        let directory = TestDirectory::new();
        let path = directory.vault_path();
        let provider = Arc::new(TestWindowsHelloProvider::new());
        let state = Arc::new(TestWindowsHelloStateRepository::default());
        let runtime =
            AgentRuntime::start_with_components(&path, Some(provider.clone()), Some(state.clone()))
                .expect("runtime");
        let password = "disposable retained cleanup password";
        create_test_vault(&runtime, password);

        provider.invalidate_next_enrollment();
        provider.fail_next_removals_for(vec![0xA0, 0], 1);
        let first_registration = test_registration(&runtime, 0xDB);
        let first = runtime
            .enroll_windows_hello(
                0x5678,
                23,
                runtime.unlock_epoch(),
                &first_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("failed enrollment cleanup");
        assert_eq!(first.error, Some(PublicErrorCode::OperationFailed));
        assert_eq!(first.retry, RetryCategory::Backoff);
        assert!(!should_cache(&first));
        assert_eq!(state.credential_id(), None);
        assert_eq!(state.pending_removal_credential_id(), Some(vec![0xA0, 0]));
        drop(first_registration);
        drop(runtime);

        let runtime =
            AgentRuntime::start_with_components(&path, Some(provider.clone()), Some(state.clone()))
                .expect("restarted runtime");
        let unlock_registration = test_registration(&runtime, 0xDC);
        let unlocked = runtime
            .unlock_vault(
                password,
                &unlock_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("password unlock after restart");
        assert_eq!(unlocked.error, None);
        drop(unlock_registration);

        provider.invalidate_next_enrollment();
        let retry_registration = test_registration(&runtime, 0xDD);
        let retry = runtime
            .enroll_windows_hello(
                0x5678,
                23,
                runtime.unlock_epoch(),
                &retry_registration,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("cleanup retry");
        assert_eq!(retry.error, Some(PublicErrorCode::OperationFailed));
        assert_eq!(retry.retry, RetryCategory::Never);
        assert_eq!(provider.removed(), vec![vec![0xA0, 0], vec![0xA0, 1]]);
        assert!(state.is_empty());
    }

    #[test]
    fn summary_pages_shrink_to_the_bounded_response_size() {
        let service_name = "s".repeat(256);
        let permitted_origin = "o".repeat(2_048);
        let username = "u".repeat(1_024);
        let views: Vec<_> = (0_u8..100)
            .map(|marker| AccountView {
                id: [marker; 16],
                revision: u64::MAX,
                created_at_ms: u64::MAX,
                modified_at_ms: u64::MAX,
                service_name: &service_name,
                permitted_origin: &permitted_origin,
                username: &username,
                password: "SUMMARY-PASSWORD-MUST-NOT-ENCODE",
            })
            .collect();

        let outcome = AgentRuntime::encode_summary_page(&views, 0, false).expect("bounded page");
        assert_eq!(outcome.error, None);
        assert!(outcome.body.len() < librarian_agent_protocol::MAX_PAYLOAD_BYTES);
        assert!(
            !outcome
                .body
                .windows(15)
                .any(|window| window == b"SUMMARY-PASSWOR")
        );
        let mut decoder = Decoder::new(&outcome.body);
        assert_eq!(decoder.array().expect("outer array"), Some(2));
        let next_offset = decoder.u32().expect("partial page offset");
        let count = decoder
            .array()
            .expect("summary array")
            .expect("fixed array");
        assert!(count > 0 && count < 100);
        assert_eq!(u64::from(next_offset), count);
    }
}
