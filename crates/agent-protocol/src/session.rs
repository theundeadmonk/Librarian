use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Mutex, MutexGuard},
};

use crate::{
    AgentState, CURRENT_VERSION, ClientHello, ClientRole, FEATURE_PASSKEY_PROVIDER,
    FEATURE_WINDOWS_HELLO, FrameHeader, MAX_IN_FLIGHT_PER_CONNECTION, MAX_PAYLOAD_BYTES,
    MIN_NEGOTIATED_PAYLOAD_BYTES, MINIMUM_VERSION, MessageKind, OperationCode,
    PASSKEY_PROVIDER_VERSION, PASSKEY_TIMEOUT_MS, RequestEnvelope, ResponseEnvelope, ServerHello,
    UNLOCK_TIMEOUT_MS, Version, WINDOWS_HELLO_VERSION,
};

/// Bounded number of issued IDs retained to distinguish a completed request
/// from a never-issued cancellation target.
pub const MAX_REQUESTS_PER_CONNECTION: usize = 65_536;

/// Negotiated limits for one authenticated connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionLimits {
    maximum_payload_bytes: u32,
    maximum_in_flight: u8,
}

impl ConnectionLimits {
    /// Creates bounded per-connection limits.
    ///
    /// # Errors
    ///
    /// Rejects zero or values above the version-1 hard limits.
    pub fn new(maximum_payload_bytes: u32, maximum_in_flight: u8) -> Result<Self, ConnectionError> {
        if usize::try_from(maximum_payload_bytes).map_or(true, |maximum| {
            !(MIN_NEGOTIATED_PAYLOAD_BYTES..=MAX_PAYLOAD_BYTES).contains(&maximum)
        }) || maximum_in_flight == 0
            || usize::from(maximum_in_flight) > MAX_IN_FLIGHT_PER_CONNECTION
        {
            return Err(ConnectionError::InvalidLimit);
        }
        Ok(Self {
            maximum_payload_bytes,
            maximum_in_flight,
        })
    }

    #[must_use]
    pub const fn maximum_payload_bytes(self) -> u32 {
        self.maximum_payload_bytes
    }

    #[must_use]
    pub const fn maximum_in_flight(self) -> u8 {
        self.maximum_in_flight
    }
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            maximum_payload_bytes: u32::try_from(MAX_PAYLOAD_BYTES).unwrap_or(u32::MAX),
            maximum_in_flight: u8::try_from(MAX_IN_FLIGHT_PER_CONNECTION).unwrap_or(u8::MAX),
        }
    }
}

/// Handshake or connection-fatal validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionError {
    InvalidLimit,
    IdentityClaimMismatch,
    BuildMismatch,
    IncompatibleVersion,
    UnsupportedFeature,
    InvalidRandomValue,
    InvalidFrame,
    WrongDirection,
    ConnectionClosed,
    RequestLimit,
    InvalidCancel,
}

/// Nonfatal request admission outcome for an authenticated peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeginRequestError {
    Connection(ConnectionError),
    Unauthorized,
    Busy { effective_timeout_ms: u32 },
    StaleEpoch,
    MissingIdempotencyKey,
}

/// Atomic terminal state observed when the server commits a response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestCompletion {
    Active,
    Cancelled,
}

impl From<ConnectionError> for BeginRequestError {
    fn from(value: ConnectionError) -> Self {
        Self::Connection(value)
    }
}

/// One admitted request. Dropping it has no implicit completion semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestPermit {
    request_id: u64,
    operation: OperationCode,
    unlock_epoch: u64,
    effective_timeout_ms: u32,
}

impl RequestPermit {
    #[must_use]
    pub const fn request_id(self) -> u64 {
        self.request_id
    }

    #[must_use]
    pub const fn operation(self) -> OperationCode {
        self.operation
    }

    #[must_use]
    pub const fn unlock_epoch(self) -> u64 {
        self.unlock_epoch
    }

    #[must_use]
    pub const fn effective_timeout_ms(self) -> u32 {
        self.effective_timeout_ms
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestState {
    Active,
    Cancelled,
}

/// Server-side state for one mutually authenticated transport connection.
/// Admission/completion and cancellation are internally synchronized so a
/// reader can process a cancel frame while a worker executes the request.
#[allow(clippy::struct_field_names)]
pub struct Connection {
    role: ClientRole,
    version: Version,
    authenticated_process_id: u32,
    granted_features: Vec<u16>,
    connection_id: [u8; 16],
    limits: ConnectionLimits,
    state: Mutex<ConnectionState>,
}

struct ConnectionState {
    last_request_id: u64,
    issued_request_ids: BTreeSet<u64>,
    in_flight: BTreeMap<u64, RequestState>,
    closed: bool,
}

impl Connection {
    /// Authenticates handshake claims and negotiates protocol version/features.
    ///
    /// The caller supplies role and build identity derived from the connected
    /// process. Values claimed by the payload never grant authority.
    ///
    /// # Errors
    ///
    /// Fails closed for claim/build mismatch, unsupported version/features,
    /// invalid random values, or limits.
    #[allow(clippy::too_many_arguments)]
    pub fn negotiate(
        derived_role: ClientRole,
        authenticated_process_id: u32,
        expected_build_id: [u8; 32],
        hello: &ClientHello,
        supported_features: &[u16],
        server_nonce: [u8; 32],
        connection_id: [u8; 16],
        agent_state: AgentState,
        unlock_epoch: u64,
        limits: ConnectionLimits,
    ) -> Result<(Self, ServerHello), ConnectionError> {
        if hello.claimed_role() != derived_role {
            return Err(ConnectionError::IdentityClaimMismatch);
        }
        if hello.component_build_id() != &expected_build_id {
            return Err(ConnectionError::BuildMismatch);
        }
        let selected_version = hello.maximum().min(CURRENT_VERSION);
        if hello.minimum() > selected_version
            || selected_version < MINIMUM_VERSION
            || selected_version.major() != CURRENT_VERSION.major()
        {
            return Err(ConnectionError::IncompatibleVersion);
        }
        if supported_features.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ConnectionError::UnsupportedFeature);
        }
        if hello
            .required_features()
            .iter()
            .any(|required| supported_features.binary_search(required).is_err())
        {
            return Err(ConnectionError::UnsupportedFeature);
        }
        if hello
            .required_features()
            .binary_search(&FEATURE_WINDOWS_HELLO)
            .is_ok()
            && selected_version < WINDOWS_HELLO_VERSION
        {
            return Err(ConnectionError::UnsupportedFeature);
        }
        if hello
            .required_features()
            .binary_search(&FEATURE_PASSKEY_PROVIDER)
            .is_ok()
            && selected_version < PASSKEY_PROVIDER_VERSION
        {
            return Err(ConnectionError::UnsupportedFeature);
        }
        if authenticated_process_id == 0 || server_nonce == [0; 32] || connection_id == [0; 16] {
            return Err(ConnectionError::InvalidRandomValue);
        }

        let granted_features = hello.required_features().to_vec();
        let response = ServerHello::new(
            server_nonce,
            selected_version,
            derived_role,
            granted_features.clone(),
            limits.maximum_payload_bytes,
            limits.maximum_in_flight,
            agent_state,
            unlock_epoch,
        )
        .map_err(|_| ConnectionError::InvalidLimit)?;
        Ok((
            Self {
                role: derived_role,
                version: selected_version,
                authenticated_process_id,
                granted_features,
                connection_id,
                limits,
                state: Mutex::new(ConnectionState {
                    last_request_id: 0,
                    issued_request_ids: BTreeSet::new(),
                    in_flight: BTreeMap::new(),
                    closed: false,
                }),
            },
            response,
        ))
    }

    #[must_use]
    pub const fn role(&self) -> ClientRole {
        self.role
    }

    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    #[must_use]
    pub const fn authenticated_process_id(&self) -> u32 {
        self.authenticated_process_id
    }

    #[must_use]
    pub const fn connection_id(&self) -> &[u8; 16] {
        &self.connection_id
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state.lock().map_or(true, |state| state.closed)
    }

    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.state
            .lock()
            .map_or(MAX_IN_FLIGHT_PER_CONNECTION, |state| state.in_flight.len())
    }

    /// Returns whether a canonical response respects this connection's
    /// negotiated payload limit.
    #[must_use]
    pub fn response_fits(&self, response: &ResponseEnvelope) -> bool {
        response.encoded_len() <= self.limits.maximum_payload_bytes as usize
    }

    /// Admits one already framed request after role-first operation peeking and
    /// full canonical request decoding.
    ///
    /// # Errors
    ///
    /// Connection errors close the connection. Role, epoch, idempotency, and
    /// backpressure errors are terminal public outcomes for this request.
    pub fn begin_request(
        &self,
        header: &FrameHeader,
        request: &RequestEnvelope,
        current_unlock_epoch: u64,
    ) -> Result<RequestPermit, BeginRequestError> {
        let mut state = self.lock_state()?;
        self.validate_request_header(&mut state, header)?;
        Self::record_request_id(&mut state, header.request_id())?;

        if !request.operation().is_authorized_for(self.role) {
            return Err(BeginRequestError::Unauthorized);
        }
        if request
            .operation()
            .required_feature()
            .is_some_and(|feature| self.granted_features.binary_search(&feature).is_err())
        {
            return Err(BeginRequestError::Unauthorized);
        }
        if request.operation().requires_idempotency_key() && request.idempotency_key().is_none() {
            return Err(BeginRequestError::MissingIdempotencyKey);
        }
        if request.operation().requires_unlocked_epoch()
            && request.unlock_epoch() != current_unlock_epoch
        {
            return Err(BeginRequestError::StaleEpoch);
        }
        let effective_timeout_ms = effective_timeout(request.operation(), request.timeout_ms());
        if state.in_flight.len() >= usize::from(self.limits.maximum_in_flight) {
            return Err(BeginRequestError::Busy {
                effective_timeout_ms,
            });
        }
        let permit = RequestPermit {
            request_id: header.request_id(),
            operation: request.operation(),
            unlock_epoch: request.unlock_epoch(),
            effective_timeout_ms,
        };
        state
            .in_flight
            .insert(header.request_id(), RequestState::Active);
        Ok(permit)
    }

    /// Marks one request cancelled using the target ID carried by the cancel
    /// header. Repeating cancellation and cancelling a completed request are
    /// idempotent.
    ///
    /// # Errors
    ///
    /// A wrong connection/version/direction or never-issued ID closes the
    /// connection.
    pub fn cancel(&self, header: &FrameHeader) -> Result<(), ConnectionError> {
        let mut state = self.lock_state()?;
        self.validate_common_header(&mut state, header, MessageKind::Cancel)?;
        let request_id = header.request_id();
        if !state.issued_request_ids.contains(&request_id) {
            state.closed = true;
            return Err(ConnectionError::InvalidCancel);
        }
        if let Some(request_state) = state.in_flight.get_mut(&request_id) {
            *request_state = RequestState::Cancelled;
        }
        Ok(())
    }

    #[must_use]
    pub fn is_cancelled(&self, permit: RequestPermit) -> bool {
        self.state.lock().map_or(true, |state| {
            state.in_flight.get(&permit.request_id) == Some(&RequestState::Cancelled)
        })
    }

    /// Completes one active or cancelled request exactly once.
    ///
    /// # Errors
    ///
    /// Unknown or duplicate completion is connection-fatal.
    pub fn finish(&self, permit: RequestPermit) -> Result<RequestCompletion, ConnectionError> {
        let mut state = self.lock_state()?;
        let Some(request_state) = state.in_flight.remove(&permit.request_id) else {
            state.closed = true;
            return Err(ConnectionError::InvalidFrame);
        };
        Ok(match request_state {
            RequestState::Active => RequestCompletion::Active,
            RequestState::Cancelled => RequestCompletion::Cancelled,
        })
    }

    /// Cancels all in-flight work and closes this connection.
    pub fn close(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.closed = true;
        for request_state in state.in_flight.values_mut() {
            *request_state = RequestState::Cancelled;
        }
    }

    fn validate_request_header(
        &self,
        state: &mut ConnectionState,
        header: &FrameHeader,
    ) -> Result<(), ConnectionError> {
        self.validate_common_header(state, header, MessageKind::Request)?;
        if usize::try_from(header.payload_length()).map_or(true, |length| {
            length > self.limits.maximum_payload_bytes as usize
        }) {
            state.closed = true;
            return Err(ConnectionError::InvalidFrame);
        }
        Ok(())
    }

    fn validate_common_header(
        &self,
        state: &mut ConnectionState,
        header: &FrameHeader,
        expected_kind: MessageKind,
    ) -> Result<(), ConnectionError> {
        if state.closed {
            return Err(ConnectionError::ConnectionClosed);
        }
        if header.kind() != expected_kind {
            state.closed = true;
            return Err(ConnectionError::WrongDirection);
        }
        if header.version() != self.version || header.connection_id() != &self.connection_id {
            state.closed = true;
            return Err(ConnectionError::InvalidFrame);
        }
        Ok(())
    }

    fn record_request_id(
        state: &mut ConnectionState,
        request_id: u64,
    ) -> Result<(), ConnectionError> {
        if (state.last_request_id == 0 && request_id != 1)
            || (state.last_request_id != 0 && request_id <= state.last_request_id)
        {
            state.closed = true;
            return Err(ConnectionError::InvalidFrame);
        }
        if state.issued_request_ids.len() >= MAX_REQUESTS_PER_CONNECTION {
            state.closed = true;
            return Err(ConnectionError::RequestLimit);
        }
        state.last_request_id = request_id;
        state.issued_request_ids.insert(request_id);
        Ok(())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, ConnectionState>, ConnectionError> {
        self.state
            .lock()
            .map_err(|_| ConnectionError::ConnectionClosed)
    }
}

fn effective_timeout(operation: OperationCode, requested: u32) -> u32 {
    let maximum = match operation {
        OperationCode::CreateVault | OperationCode::UnlockMasterPassword | OperationCode::Lock => {
            UNLOCK_TIMEOUT_MS
        }
        OperationCode::MakePasskey
        | OperationCode::GetPasskeyAssertion
        | OperationCode::DeletePasskey
        | OperationCode::ListPasskeysForAssertion
        | OperationCode::EnrollWindowsHello
        | OperationCode::UnlockWindowsHello
        | OperationCode::RemoveWindowsHello => PASSKEY_TIMEOUT_MS,
        _ => crate::ORDINARY_TIMEOUT_MS,
    };
    requested.min(maximum)
}
