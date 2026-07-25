use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use librarian_agent_protocol::{
    AccountView, AgentState, BeginRequestError, Connection, ConnectionError, CorrelationId,
    FrameHeader, MAX_IN_FLIGHT_GLOBAL, OperationCode, OperationRequest, ProtocolError,
    PublicErrorCode, RequestEnvelope, ResponseEnvelope, RetryCategory, encode_account,
    encode_account_id, encode_account_summaries, encode_empty_result, encode_status,
};
use librarian_vault_core::{CancellationFlag, MasterPassword};
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
    operation: OperationCode,
    error: Option<PublicErrorCode>,
    retry: RetryCategory,
    body: Zeroizing<Vec<u8>>,
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

struct OwnershipLease(PathBuf);

impl Drop for OwnershipLease {
    fn drop(&mut self) {
        if let Ok(mut owned) = owned_vault_paths().lock() {
            owned.remove(&self.0);
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
    idempotency: Mutex<BTreeMap<[u8; 16], CachedOutcome>>,
    idempotency_in_flight: Mutex<BTreeSet<[u8; 16]>>,
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
        let bound_path = bind_ownership_path(vault_path)?;
        let mut owned = owned_vault_paths()
            .lock()
            .map_err(|_| RuntimeStartError::Internal)?;
        if !owned.insert(bound_path.clone()) {
            return Err(RuntimeStartError::AlreadyOwned);
        }
        drop(owned);
        let state = match fs::symlink_metadata(vault_path) {
            Ok(_) => AgentState::Locked,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => AgentState::NoVault,
            Err(_) => {
                if let Ok(mut owned) = owned_vault_paths().lock() {
                    owned.remove(&bound_path);
                }
                return Err(RuntimeStartError::InvalidVaultPath);
            }
        };
        Ok(Self {
            vault_path: vault_path.to_path_buf(),
            vault: Mutex::new(VaultAgent::open_locked(vault_path)),
            state: AtomicU8::new(state as u8),
            coordinator: Arc::new(Coordinator::new()),
            idempotency: Mutex::new(BTreeMap::new()),
            idempotency_in_flight: Mutex::new(BTreeSet::new()),
            ownership: OwnershipLease(bound_path),
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
    pub fn disconnect(&self, connection_id: [u8; 16]) -> Result<(), DispatchError> {
        self.coordinator.cancel_connection(connection_id)
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
    pub fn dispatch(
        &self,
        connection: &Connection,
        header: &FrameHeader,
        envelope: &RequestEnvelope,
    ) -> Result<ResponseEnvelope, DispatchError> {
        let correlation = correlation_id()?;
        let permit = match connection.begin_request(header, envelope, self.unlock_epoch()) {
            Ok(permit) => permit,
            Err(BeginRequestError::Unauthorized) => {
                return Ok(ResponseEnvelope::failure(
                    PublicErrorCode::UnauthorizedOperation,
                    RetryCategory::Never,
                    correlation,
                ));
            }
            Err(BeginRequestError::Busy) => {
                return Ok(ResponseEnvelope::failure(
                    PublicErrorCode::Busy,
                    RetryCategory::Backoff,
                    correlation,
                ));
            }
            Err(BeginRequestError::StaleEpoch) => {
                return Ok(ResponseEnvelope::failure(
                    PublicErrorCode::Locked,
                    RetryCategory::AfterUnlock,
                    correlation,
                ));
            }
            Err(BeginRequestError::MissingIdempotencyKey) => {
                return Ok(ResponseEnvelope::failure(
                    PublicErrorCode::InvalidRequest,
                    RetryCategory::Never,
                    correlation,
                ));
            }
            Err(BeginRequestError::Connection(error)) => return Err(error.into()),
        };

        let Some(_global) =
            CounterPermit::acquire(&self.coordinator.global_in_flight, MAX_IN_FLIGHT_GLOBAL)
        else {
            connection.finish(permit)?;
            return Ok(ResponseEnvelope::failure(
                PublicErrorCode::Busy,
                RetryCategory::Backoff,
                correlation,
            ));
        };
        let key = RequestKey {
            connection_id: *connection.connection_id(),
            request_id: permit.request_id(),
        };
        let registration = self.coordinator.register(key)?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(u64::from(
                permit.effective_timeout_ms(),
            )))
            .ok_or(DispatchError::Internal)?;

        let operation = match OperationRequest::decode(envelope.operation(), envelope.body()) {
            Ok(operation) => operation,
            Err(ProtocolError::Unsupported) => {
                connection.finish(permit)?;
                return Ok(ResponseEnvelope::failure(
                    PublicErrorCode::OperationFailed,
                    RetryCategory::Never,
                    correlation,
                ));
            }
            Err(_) => {
                connection.finish(permit)?;
                return Ok(ResponseEnvelope::failure(
                    PublicErrorCode::InvalidRequest,
                    RetryCategory::Never,
                    correlation,
                ));
            }
        };

        let outcome = if let Some(idempotency_key) = envelope.idempotency_key() {
            self.execute_idempotent(
                *idempotency_key,
                operation,
                permit.unlock_epoch(),
                &registration,
                deadline,
            )?
        } else {
            self.execute(operation, permit.unlock_epoch(), &registration, deadline)?
        };
        connection.finish(permit)?;
        outcome.into_response(correlation)
    }

    fn execute_idempotent(
        &self,
        key: [u8; 16],
        operation: OperationRequest,
        request_epoch: u64,
        registration: &RequestRegistration,
        deadline: Instant,
    ) -> Result<ExecutionOutcome, DispatchError> {
        if let Some(cached) = lock(&self.idempotency)?.get(&key) {
            if cached.operation != operation.operation() {
                return Ok(ExecutionOutcome::failure(
                    PublicErrorCode::Conflict,
                    RetryCategory::Never,
                ));
            }
            return Ok(ExecutionOutcome {
                error: cached.error,
                retry: cached.retry,
                body: Zeroizing::new(cached.body.to_vec()),
            });
        }
        let reservation = {
            let cache = lock(&self.idempotency)?;
            let mut in_flight = lock(&self.idempotency_in_flight)?;
            if in_flight.contains(&key)
                || cache
                    .len()
                    .checked_add(in_flight.len())
                    .is_none_or(|count| count >= MAX_IDEMPOTENCY_RESULTS)
            {
                return Ok(ExecutionOutcome::busy());
            }
            in_flight.insert(key);
            IdempotencyReservation {
                in_flight: &self.idempotency_in_flight,
                key,
            }
        };
        let operation_code = operation.operation();
        let outcome = self.execute(operation, request_epoch, registration, deadline)?;
        if should_cache(&outcome) {
            let mut cache = lock(&self.idempotency)?;
            cache.insert(
                key,
                CachedOutcome {
                    operation: operation_code,
                    error: outcome.error,
                    retry: outcome.retry,
                    body: Zeroizing::new(outcome.body.to_vec()),
                },
            );
        }
        drop(reservation);
        Ok(outcome)
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
            OperationRequest::Status => Ok(ExecutionOutcome::success(encode_status(
                self.state(),
                self.unlock_epoch(),
            )?)),
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
        let result = VaultAgent::create_with_before_publish(&self.vault_path, password, || {
            let guard = coordinator
                .commit_gate
                .lock()
                .map_err(|_| CreateError::Failed)?;
            if coordinator.epoch() != start_epoch
                || cancellation.is_cancelled()
                || Instant::now() >= deadline
                || coordinator.lock_active.load(Ordering::Acquire)
                || self.state() != AgentState::NoVault
            {
                return Err(CreateError::Failed);
            }
            commit_guard = Some(guard);
            Ok(())
        });
        match result {
            Ok((created, recovery_key)) => {
                let Some(_commit) = commit_guard else {
                    return Err(DispatchError::Internal);
                };
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
        let result = lock(&self.vault)?.unlock(password, &registration.cancellation);
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
        let offset = usize::try_from(offset).map_err(|_| DispatchError::Internal)?;
        let limit = usize::from(limit);
        let mut vault = lock(&self.vault)?;
        let result = vault.list_website_account_page(offset, limit);
        let (accounts, has_more) = match result {
            Ok(page) => page,
            Err(error) => return Ok(map_account_error(error)),
        };
        if let Some(outcome) =
            self.post_secret_operation(&mut vault, request_epoch, registration, deadline)
        {
            drop(accounts);
            return Ok(outcome);
        }
        let next_offset = if has_more {
            offset
                .checked_add(accounts.len())
                .and_then(|value| u32::try_from(value).ok())
        } else {
            None
        };
        if has_more && next_offset.is_none() {
            return Ok(ExecutionOutcome::failed());
        }
        let views: Vec<_> = accounts.iter().map(account_view).collect();
        Ok(ExecutionOutcome::success(encode_account_summaries(
            &views,
            next_offset,
        )?))
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
        let account = match vault.get_website_account(RecordId::from_bytes(id)) {
            Ok(account) => account,
            Err(error) => return Ok(map_account_error(error)),
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
        let mut _commit_guard = None;
        let mut vault = lock(&self.vault)?;
        let result = vault.add_website_account_with_before_commit(input, || {
            let guard = coordinator
                .commit_gate
                .lock()
                .map_err(|_| crate::errors::StorageError::Conflict)?;
            if coordinator.epoch() != request_epoch
                || coordinator.lock_active.load(Ordering::Acquire)
                || cancellation.is_cancelled()
                || Instant::now() >= deadline
            {
                return Err(crate::errors::StorageError::Conflict);
            }
            _commit_guard = Some(guard);
            Ok(())
        });
        match result {
            Ok(id) => Ok(ExecutionOutcome::success(encode_account_id(
                *id.as_bytes(),
            )?)),
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
        let mut _commit_guard = None;
        let mut vault = lock(&self.vault)?;
        let result = vault.update_website_account_with_before_commit(
            RecordId::from_bytes(id),
            input,
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
                    return Err(crate::errors::StorageError::Conflict);
                }
                _commit_guard = Some(guard);
                Ok(())
            },
        );
        match result {
            Ok(()) => Ok(ExecutionOutcome::success(encode_empty_result()?)),
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
        let mut _commit_guard = None;
        let mut vault = lock(&self.vault)?;
        let result =
            vault.delete_website_account_with_before_commit(RecordId::from_bytes(id), || {
                let guard = coordinator
                    .commit_gate
                    .lock()
                    .map_err(|_| crate::errors::StorageError::Conflict)?;
                if coordinator.epoch() != request_epoch
                    || coordinator.lock_active.load(Ordering::Acquire)
                    || cancellation.is_cancelled()
                    || Instant::now() >= deadline
                {
                    return Err(crate::errors::StorageError::Conflict);
                }
                _commit_guard = Some(guard);
                Ok(())
            });
        match result {
            Ok(()) => Ok(ExecutionOutcome::success(encode_empty_result()?)),
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
        let outcome = self.pre_secret_operation(request_epoch, registration, deadline);
        if outcome.is_some() {
            vault.lock();
            self.set_locked_unless_shutting_down();
        }
        outcome
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
    in_flight: &'a Mutex<BTreeSet<[u8; 16]>>,
    key: [u8; 16],
}

impl Drop for IdempotencyReservation<'_> {
    fn drop(&mut self) {
        if let Ok(mut in_flight) = self.in_flight.lock() {
            in_flight.remove(&self.key);
        }
    }
}

struct ExecutionOutcome {
    error: Option<PublicErrorCode>,
    retry: RetryCategory,
    body: Zeroizing<Vec<u8>>,
}

impl ExecutionOutcome {
    fn success(body: Zeroizing<Vec<u8>>) -> Self {
        Self {
            error: None,
            retry: RetryCategory::Never,
            body,
        }
    }

    fn failure(error: PublicErrorCode, retry: RetryCategory) -> Self {
        Self {
            error: Some(error),
            retry,
            body: Zeroizing::new(Vec::new()),
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
            return Ok(ResponseEnvelope::failure(error, self.retry, correlation));
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
        AccountError::Failed => ExecutionOutcome::failed(),
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

fn bind_ownership_path(path: &Path) -> Result<PathBuf, RuntimeStartError> {
    let parent = path.parent().ok_or(RuntimeStartError::InvalidVaultPath)?;
    let name = path
        .file_name()
        .ok_or(RuntimeStartError::InvalidVaultPath)?;
    let parent = parent
        .canonicalize()
        .map_err(|_| RuntimeStartError::InvalidVaultPath)?;
    Ok(parent.join(name))
}

fn owned_vault_paths() -> &'static Mutex<BTreeSet<PathBuf>> {
    static OWNED: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();
    OWNED.get_or_init(|| Mutex::new(BTreeSet::new()))
}

fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, DispatchError> {
    mutex.lock().map_err(|_| DispatchError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
