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
    FrameHeader, MAX_IN_FLIGHT_GLOBAL, OperationCode, OperationRequest, ProtocolError,
    PublicErrorCode, RequestCompletion, RequestEnvelope, RequestPermit, ResponseEnvelope,
    RetryCategory, encode_account, encode_account_id, encode_account_summaries,
    encode_empty_result, encode_status,
};
use librarian_vault_core::{CancellationFlag, MasterPassword};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    AccountError, CreateError, RecordId, UnlockError, VaultAgent, WebsiteAccount,
    WebsiteAccountInput,
};

const MAX_IDEMPOTENCY_RESULTS: usize = 1_024;

/// Startup failures contain no vault path or platform details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeStartError {
    InvalidVaultPath,
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
    Rejected(ResponseEnvelope),
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

struct FlagPermit<'a>(&'a AtomicBool);

impl FlagPermit<'_> {
    fn acquire(flag: &AtomicBool) -> Option<FlagPermit<'_>> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| FlagPermit(flag))
    }
}

impl Drop for FlagPermit<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
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

struct OwnershipLease {
    token: u64,
}

impl OwnershipLease {
    fn bind_existing(
        &self,
        registry: &mut BTreeMap<u64, OwnershipRecord>,
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
        if current.normalized_path != record.normalized_path {
            return Err(DispatchError::Internal);
        }
        *current = record;
        Ok(())
    }

    fn bind_authenticated(
        &self,
        registry: &mut BTreeMap<u64, OwnershipRecord>,
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
        if leased.normalized_path != current.normalized_path {
            return Err(DispatchError::Internal);
        }
        bind_authenticated_vault()?;
        *leased = current;
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
    idempotency_fingerprint_key: Zeroizing<[u8; 32]>,
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
        let vault_path = vault_path.as_ref();
        if !vault_path.is_absolute() {
            return Err(RuntimeStartError::InvalidVaultPath);
        }
        let mut idempotency_fingerprint_key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut *idempotency_fingerprint_key)
            .map_err(|_| RuntimeStartError::Internal)?;
        if *idempotency_fingerprint_key == [0; 32] {
            return Err(RuntimeStartError::Internal);
        }
        let ownership_record = ownership_record(vault_path)?;
        let ownership_token = next_ownership_token()?;
        let mut owned = owned_vaults()
            .lock()
            .map_err(|_| RuntimeStartError::Internal)?;
        if owned
            .values()
            .any(|existing| existing.conflicts_with(&ownership_record))
        {
            return Err(RuntimeStartError::AlreadyOwned);
        }
        owned.insert(ownership_token, ownership_record);
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
            idempotency_fingerprint_key,
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
        connection.close();
        self.coordinator
            .cancel_connection(*connection.connection_id())
    }

    /// Locks and cancels all work before Windows sign-out or agent shutdown.
    ///
    /// # Errors
    ///
    /// Returns `Internal` if lifecycle state is poisoned or exhausted.
    pub fn shutdown(&self) -> Result<(), DispatchError> {
        self.coordinator.lock_active.store(true, Ordering::Release);
        {
            let _commit = lock(&self.coordinator.commit_gate)?;
            self.state
                .store(AgentState::ShuttingDown as u8, Ordering::Release);
            self.coordinator.advance_epoch()?;
        }
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
        let correlation = correlation_id()?;
        let context = match self.admit_request(connection, header, envelope, correlation)? {
            RequestAdmission::Admitted(context) => context,
            RequestAdmission::Rejected(response) => return write_response(&response),
        };
        let operation = match OperationRequest::decode(envelope.operation(), envelope.body()) {
            Ok(operation) => operation,
            Err(ProtocolError::Unsupported) => {
                return self.finish_dispatch(context, ExecutionOutcome::failed(), write_response);
            }
            Err(_) => {
                return self.finish_dispatch(context, ExecutionOutcome::invalid(), write_response);
            }
        };

        let outcome = if context.permit.operation().requires_idempotency_key() {
            let idempotency_key = envelope.idempotency_key().ok_or(DispatchError::Internal)?;
            let request_fingerprint =
                self.request_fingerprint(envelope.operation(), envelope.body())?;
            self.execute_idempotent(
                *idempotency_key,
                request_fingerprint,
                operation,
                context.permit.unlock_epoch(),
                &context.registration,
                context.deadline,
            )?
        } else {
            self.execute(
                operation,
                context.permit.unlock_epoch(),
                &context.registration,
                context.deadline,
            )?
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
        let admission = lock(&self.coordinator.commit_gate)?;
        let permit = match connection.begin_request(header, envelope, self.unlock_epoch()) {
            Ok(permit) => permit,
            Err(BeginRequestError::Unauthorized) => {
                return Ok(RequestAdmission::Rejected(ResponseEnvelope::failure(
                    PublicErrorCode::UnauthorizedOperation,
                    RetryCategory::Never,
                    correlation,
                )?));
            }
            Err(BeginRequestError::Busy) => {
                return Ok(RequestAdmission::Rejected(ResponseEnvelope::failure(
                    PublicErrorCode::Busy,
                    RetryCategory::Backoff,
                    correlation,
                )?));
            }
            Err(BeginRequestError::StaleEpoch) => {
                return Ok(RequestAdmission::Rejected(ResponseEnvelope::failure(
                    PublicErrorCode::Locked,
                    RetryCategory::AfterUnlock,
                    correlation,
                )?));
            }
            Err(BeginRequestError::MissingIdempotencyKey) => {
                return Ok(RequestAdmission::Rejected(ResponseEnvelope::failure(
                    PublicErrorCode::InvalidRequest,
                    RetryCategory::Never,
                    correlation,
                )?));
            }
            Err(BeginRequestError::Connection(error)) => return Err(error.into()),
        };

        let Some(global) =
            CounterPermit::acquire(&self.coordinator.global_in_flight, MAX_IN_FLIGHT_GLOBAL)
        else {
            connection.finish(permit)?;
            return Ok(RequestAdmission::Rejected(ResponseEnvelope::failure(
                PublicErrorCode::Busy,
                RetryCategory::Backoff,
                correlation,
            )?));
        };
        let key = RequestKey {
            connection_id: *connection.connection_id(),
            request_id: permit.request_id(),
        };
        let registration = self.coordinator.register(key)?;
        let deadline = admission_started
            .checked_add(Duration::from_millis(u64::from(
                permit.effective_timeout_ms(),
            )))
            .ok_or(DispatchError::Internal)?;
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
        operation: OperationRequest,
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        let reservation = {
            let mut state = lock(&self.idempotency)?;
            if let Some(cached) = state.cached.get(&key) {
                if cached.request_fingerprint != request_fingerprint {
                    return Ok(ExecutionOutcome::failure(
                        PublicErrorCode::Conflict,
                        RetryCategory::Never,
                    ));
                }
                return Ok(ExecutionOutcome {
                    error: cached.error,
                    retry: cached.retry,
                    body: Zeroizing::new(cached.body.to_vec()),
                    replayed: true,
                });
            }
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
            IdempotencyReservation {
                state: &self.idempotency,
                key,
                active: true,
            }
        };
        let outcome = self.execute(operation, request_epoch, registration, deadline)?;
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
        body: &[u8],
    ) -> Result<[u8; 32], DispatchError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&*self.idempotency_fingerprint_key)
            .map_err(|_| DispatchError::Internal)?;
        mac.update(b"Librarian idempotency request v1\0");
        mac.update(&(operation as u16).to_be_bytes());
        mac.update(body);
        Ok(mac.finalize().into_bytes().into())
    }

    fn finish_dispatch<T>(
        &self,
        context: DispatchContext<'_>,
        mut outcome: ExecutionOutcome,
        write_response: impl FnOnce(&ResponseEnvelope) -> Result<T, DispatchError>,
    ) -> Result<T, DispatchError> {
        let _commit = lock(&self.coordinator.commit_gate)?;
        let completion = context.connection.finish(context.permit)?;
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
        if outcome.error.is_none()
            && matches!(
                context.permit.operation(),
                OperationCode::Status | OperationCode::CreateVault
            )
        {
            outcome = ExecutionOutcome::success(encode_status(self.state(), self.unlock_epoch())?);
        }
        let response = outcome.into_response(context.correlation)?;
        let write_result = write_response(&response);
        drop(context);
        write_result
    }

    fn outcome_is_still_authorized(
        &self,
        permit: RequestPermit,
        outcome: &ExecutionOutcome,
    ) -> bool {
        match permit.operation() {
            OperationCode::Status | OperationCode::Lock => outcome.error.is_none(),
            OperationCode::CreateVault | OperationCode::UnlockMasterPassword => {
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
        }
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
        let result = lock(&self.vault)?.unlock_with_before_publish(
            password,
            &registration.cancellation,
            || {
                authenticated_ownership = ownership_record(&self.vault_path).ok();
            },
        );
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
                let authenticated_vault_id = lock(&self.vault)?
                    .authenticated_vault_id()
                    .ok_or(DispatchError::Internal)?;
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
            || Instant::now() >= deadline
            || self.state() != AgentState::Unlocking
        {
            lock(&self.vault)?.lock();
            self.set_locked_unless_shutting_down();
            return Ok(ExecutionOutcome::cancelled());
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
        let Some(_lock_transition) = FlagPermit::acquire(&self.coordinator.lock_active) else {
            return Ok(ExecutionOutcome::busy());
        };
        let target_state = {
            let _commit = lock(&self.coordinator.commit_gate)?;
            let target_state = match self.state() {
                AgentState::NoVault => AgentState::NoVault,
                AgentState::Updating => AgentState::Updating,
                AgentState::ShuttingDown => AgentState::ShuttingDown,
                _ => AgentState::Locked,
            };
            self.state.store(target_state as u8, Ordering::Release);
            self.coordinator.advance_epoch()?;
            target_state
        };
        lock(&self.vault)?.lock();
        if !matches!(
            self.state(),
            AgentState::Updating | AgentState::ShuttingDown
        ) {
            self.state.store(target_state as u8, Ordering::Release);
        }
        Ok(ExecutionOutcome::success(encode_empty_result()?))
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
}

impl ExecutionOutcome {
    fn success(body: Zeroizing<Vec<u8>>) -> Self {
        Self {
            error: None,
            retry: RetryCategory::Never,
            body,
            replayed: false,
        }
    }

    fn failure(error: PublicErrorCode, retry: RetryCategory) -> Self {
        Self {
            error: Some(error),
            retry,
            body: Zeroizing::new(Vec::new()),
            replayed: false,
        }
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

fn map_account_error(error: AccountError) -> ExecutionOutcome {
    match error {
        AccountError::Locked => ExecutionOutcome::locked(),
        AccountError::NotFound => {
            ExecutionOutcome::failure(PublicErrorCode::NotFound, RetryCategory::Never)
        }
        AccountError::Aborted | AccountError::Failed => ExecutionOutcome::failed(),
    }
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

fn should_cache(outcome: &ExecutionOutcome) -> bool {
    outcome.error.is_none()
        || matches!(
            outcome.error,
            Some(
                PublicErrorCode::InvalidRequest
                    | PublicErrorCode::NotFound
                    | PublicErrorCode::Conflict
                    | PublicErrorCode::OperationFailed
            )
        )
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

fn owned_vaults() -> &'static Mutex<BTreeMap<u64, OwnershipRecord>> {
    static OWNED: OnceLock<Mutex<BTreeMap<u64, OwnershipRecord>>> = OnceLock::new();
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
        CURRENT_VERSION, ClientHello, ClientRole, ConnectionLimits, MessageKind,
    };
    use minicbor::Decoder;

    static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(1);
    const TEST_BUILD_ID: [u8; 32] = [0xB4; 32];

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

    fn connection(runtime: &AgentRuntime, marker: u8) -> Connection {
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
            TEST_BUILD_ID,
            &hello,
            &[],
            [marker.wrapping_add(1); 32],
            [marker.wrapping_add(2); 16],
            state,
            epoch,
            ConnectionLimits::default(),
        )
        .expect("connection")
        .0
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
            .request_fingerprint(operation.operation(), &body)
            .expect("request fingerprint");
        let newest = u128::MAX.to_be_bytes();
        let outcome = runtime
            .execute_idempotent(
                newest,
                fingerprint,
                operation,
                runtime.unlock_epoch(),
                &registration,
                Instant::now() + Duration::from_secs(1),
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

        let client = connection(&runtime, 67);
        let registration = runtime
            .coordinator
            .register(RequestKey {
                connection_id: *client.connection_id(),
                request_id: 1,
            })
            .expect("registration");
        let replay = runtime
            .execute_idempotent(
                key,
                fingerprint,
                OperationRequest::Status,
                runtime.unlock_epoch(),
                &registration,
                Instant::now() + Duration::from_secs(1),
            )
            .expect("cached terminal failure");
        assert_eq!(replay.error, Some(PublicErrorCode::OperationFailed));
        assert!(replay.replayed);
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
