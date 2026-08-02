use core::fmt;

use minicbor::{Decoder, Encoder};
use zeroize::Zeroizing;

use crate::{
    AgentState, ClientRole, CorrelationId, MAX_ENDPOINT_DESCRIPTOR_BYTES, MAX_PAYLOAD_BYTES,
    MIN_NEGOTIATED_PAYLOAD_BYTES, OperationCode, PublicErrorCode, RetryCategory, Version,
    cbor::{
        SecretWriter, decode_array_length, decode_bounded_bytes, decode_bounded_text,
        decode_fixed_bytes, decode_optional_fixed_bytes, decode_u8, decode_u16, decode_u32,
        decode_u64, encode_array, encode_bytes, encode_null, encode_text, encode_u8, encode_u16,
        encode_u32, encode_u64, expect_array, require_end,
    },
};

const MAX_FEATURES: usize = 16;
const MAX_PIPE_NAME_BYTES: usize = 512;
const MAX_PACKAGE_NAME_BYTES: usize = 256;
const MAX_REQUEST_BODY_BYTES: usize = MAX_PAYLOAD_BYTES - 128;
const MAX_RESPONSE_BODY_BYTES: usize = MAX_PAYLOAD_BYTES - 96;
const ENDPOINT_SCHEMA: u8 = 1;

/// Bounded protocol-payload failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    TooLarge,
    Malformed,
    NonCanonical,
    Unsupported,
    InvariantViolation,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLarge => "protocol payload exceeds its limit",
            Self::Malformed => "protocol payload is malformed",
            Self::NonCanonical => "protocol payload is not canonical",
            Self::Unsupported => "protocol payload is unsupported",
            Self::InvariantViolation => "protocol payload violates an invariant",
        })
    }
}

impl std::error::Error for ProtocolError {}

/// Pre-negotiation offer from an already authenticated peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHello {
    client_nonce: [u8; 32],
    minimum: Version,
    maximum: Version,
    claimed_role: ClientRole,
    component_build_id: [u8; 32],
    required_features: Vec<u16>,
}

impl ClientHello {
    /// Constructs a canonical version offer.
    ///
    /// # Errors
    ///
    /// Rejects zero or reversed ranges, zero nonces/build IDs, excessive
    /// features, and feature lists that are not strictly increasing.
    pub fn new(
        client_nonce: [u8; 32],
        minimum: Version,
        maximum: Version,
        claimed_role: ClientRole,
        component_build_id: [u8; 32],
        required_features: Vec<u16>,
    ) -> Result<Self, ProtocolError> {
        if client_nonce == [0; 32]
            || component_build_id == [0; 32]
            || minimum.major() == 0
            || maximum.major() == 0
            || minimum > maximum
            || required_features.len() > MAX_FEATURES
            || required_features.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ProtocolError::InvariantViolation);
        }
        Ok(Self {
            client_nonce,
            minimum,
            maximum,
            claimed_role,
            component_build_id,
            required_features,
        })
    }

    #[must_use]
    pub const fn client_nonce(&self) -> &[u8; 32] {
        &self.client_nonce
    }

    #[must_use]
    pub const fn minimum(&self) -> Version {
        self.minimum
    }

    #[must_use]
    pub const fn maximum(&self) -> Version {
        self.maximum
    }

    #[must_use]
    pub const fn claimed_role(&self) -> ClientRole {
        self.claimed_role
    }

    #[must_use]
    pub const fn component_build_id(&self) -> &[u8; 32] {
        &self.component_build_id
    }

    #[must_use]
    pub fn required_features(&self) -> &[u16] {
        &self.required_features
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encode_array(&mut encoder, 8);
        encode_bytes(&mut encoder, &self.client_nonce);
        encode_u16(&mut encoder, self.minimum.major());
        encode_u16(&mut encoder, self.maximum.major());
        encode_u16(&mut encoder, self.minimum.minor());
        encode_u16(&mut encoder, self.maximum.minor());
        encode_u8(&mut encoder, self.claimed_role as u8);
        encode_bytes(&mut encoder, &self.component_build_id);
        encode_array(
            &mut encoder,
            u64::try_from(self.required_features.len()).unwrap_or(u64::MAX),
        );
        for feature in &self.required_features {
            encode_u16(&mut encoder, *feature);
        }
        encoder.into_writer()
    }

    /// Decodes and byte-for-byte canonicalizes a client offer.
    ///
    /// # Errors
    ///
    /// Rejects malformed, unsupported, oversized, or noncanonical input.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(ProtocolError::TooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        expect_array(&mut decoder, 8)?;
        let client_nonce = decode_fixed_bytes(&mut decoder)?;
        let minimum_major = decode_u16(&mut decoder)?;
        let maximum_major = decode_u16(&mut decoder)?;
        let minimum_minor = decode_u16(&mut decoder)?;
        let maximum_minor = decode_u16(&mut decoder)?;
        let claimed_role = ClientRole::from_u64(u64::from(decode_u8(&mut decoder)?))
            .ok_or(ProtocolError::Unsupported)?;
        let component_build_id = decode_fixed_bytes(&mut decoder)?;
        let feature_count = decode_array_length(&mut decoder, MAX_FEATURES)?;
        let mut features = Vec::with_capacity(feature_count);
        for _ in 0..feature_count {
            features.push(decode_u16(&mut decoder)?);
        }
        require_end(&decoder, bytes)?;
        let hello = Self::new(
            client_nonce,
            Version::new(minimum_major, minimum_minor),
            Version::new(maximum_major, maximum_minor),
            claimed_role,
            component_build_id,
            features,
        )?;
        if hello.encode().as_slice() != bytes {
            return Err(ProtocolError::NonCanonical);
        }
        Ok(hello)
    }
}

/// Negotiated response from the authenticated agent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerHello {
    server_nonce: [u8; 32],
    selected_version: Version,
    derived_role: ClientRole,
    granted_features: Vec<u16>,
    maximum_payload_bytes: u32,
    maximum_in_flight: u8,
    agent_state: AgentState,
    unlock_epoch: u64,
}

impl ServerHello {
    /// Constructs a canonical negotiated response.
    ///
    /// # Errors
    ///
    /// Rejects invalid version, nonce, features, or advertised limits.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server_nonce: [u8; 32],
        selected_version: Version,
        derived_role: ClientRole,
        granted_features: Vec<u16>,
        maximum_payload_bytes: u32,
        maximum_in_flight: u8,
        agent_state: AgentState,
        unlock_epoch: u64,
    ) -> Result<Self, ProtocolError> {
        if server_nonce == [0; 32]
            || selected_version.major() == 0
            || granted_features.len() > MAX_FEATURES
            || granted_features.windows(2).any(|pair| pair[0] >= pair[1])
            || maximum_payload_bytes == 0
            || usize::try_from(maximum_payload_bytes).map_or(true, |maximum| {
                !(MIN_NEGOTIATED_PAYLOAD_BYTES..=MAX_PAYLOAD_BYTES).contains(&maximum)
            })
            || maximum_in_flight == 0
            || usize::from(maximum_in_flight) > crate::MAX_IN_FLIGHT_PER_CONNECTION
        {
            return Err(ProtocolError::InvariantViolation);
        }
        Ok(Self {
            server_nonce,
            selected_version,
            derived_role,
            granted_features,
            maximum_payload_bytes,
            maximum_in_flight,
            agent_state,
            unlock_epoch,
        })
    }

    #[must_use]
    pub const fn selected_version(&self) -> Version {
        self.selected_version
    }

    #[must_use]
    pub const fn derived_role(&self) -> ClientRole {
        self.derived_role
    }

    #[must_use]
    pub const fn agent_state(&self) -> AgentState {
        self.agent_state
    }

    #[must_use]
    pub const fn unlock_epoch(&self) -> u64 {
        self.unlock_epoch
    }

    #[must_use]
    pub fn granted_features(&self) -> &[u16] {
        &self.granted_features
    }

    #[must_use]
    pub const fn maximum_payload_bytes(&self) -> u32 {
        self.maximum_payload_bytes
    }

    #[must_use]
    pub const fn maximum_in_flight(&self) -> u8 {
        self.maximum_in_flight
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encode_array(&mut encoder, 9);
        encode_bytes(&mut encoder, &self.server_nonce);
        encode_u16(&mut encoder, self.selected_version.major());
        encode_u16(&mut encoder, self.selected_version.minor());
        encode_u8(&mut encoder, self.derived_role as u8);
        encode_array(
            &mut encoder,
            u64::try_from(self.granted_features.len()).unwrap_or(u64::MAX),
        );
        for feature in &self.granted_features {
            encode_u16(&mut encoder, *feature);
        }
        encode_u32(&mut encoder, self.maximum_payload_bytes);
        encode_u8(&mut encoder, self.maximum_in_flight);
        encode_u8(&mut encoder, self.agent_state as u8);
        encode_u64(&mut encoder, self.unlock_epoch);
        encoder.into_writer()
    }

    /// Decodes and canonicalizes a server response.
    ///
    /// # Errors
    ///
    /// Rejects malformed, unsupported, oversized, or noncanonical input.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(ProtocolError::TooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        expect_array(&mut decoder, 9)?;
        let server_nonce = decode_fixed_bytes(&mut decoder)?;
        let version = Version::new(decode_u16(&mut decoder)?, decode_u16(&mut decoder)?);
        let role = ClientRole::from_u64(u64::from(decode_u8(&mut decoder)?))
            .ok_or(ProtocolError::Unsupported)?;
        let feature_count = decode_array_length(&mut decoder, MAX_FEATURES)?;
        let mut features = Vec::with_capacity(feature_count);
        for _ in 0..feature_count {
            features.push(decode_u16(&mut decoder)?);
        }
        let maximum_payload_bytes = decode_u32(&mut decoder)?;
        let maximum_in_flight = decode_u8(&mut decoder)?;
        let agent_state = AgentState::from_u64(u64::from(decode_u8(&mut decoder)?))
            .ok_or(ProtocolError::Unsupported)?;
        let unlock_epoch = decode_u64(&mut decoder)?;
        require_end(&decoder, bytes)?;
        let hello = Self::new(
            server_nonce,
            version,
            role,
            features,
            maximum_payload_bytes,
            maximum_in_flight,
            agent_state,
            unlock_epoch,
        )?;
        if hello.encode().as_slice() != bytes {
            return Err(ProtocolError::NonCanonical);
        }
        Ok(hello)
    }
}

/// Non-secret discovery record. It is never an authorization credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointDescriptor {
    pipe_name: String,
    agent_process_id: u32,
    agent_process_creation_time: u64,
    package_full_name: String,
    minimum_major: u16,
    maximum_major: u16,
    startup_nonce: [u8; 32],
}

impl EndpointDescriptor {
    /// Constructs one bounded discovery descriptor.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized names, invalid process/version data, or a zero
    /// startup nonce.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pipe_name: String,
        agent_process_id: u32,
        agent_process_creation_time: u64,
        package_full_name: String,
        minimum_major: u16,
        maximum_major: u16,
        startup_nonce: [u8; 32],
    ) -> Result<Self, ProtocolError> {
        if pipe_name.is_empty()
            || pipe_name.len() > MAX_PIPE_NAME_BYTES
            || package_full_name.is_empty()
            || package_full_name.len() > MAX_PACKAGE_NAME_BYTES
            || agent_process_id == 0
            || agent_process_creation_time == 0
            || minimum_major == 0
            || minimum_major > maximum_major
            || startup_nonce == [0; 32]
        {
            return Err(ProtocolError::InvariantViolation);
        }
        let descriptor = Self {
            pipe_name,
            agent_process_id,
            agent_process_creation_time,
            package_full_name,
            minimum_major,
            maximum_major,
            startup_nonce,
        };
        if descriptor.encode().len() > MAX_ENDPOINT_DESCRIPTOR_BYTES {
            return Err(ProtocolError::TooLarge);
        }
        Ok(descriptor)
    }

    #[must_use]
    pub const fn minimum_major(&self) -> u16 {
        self.minimum_major
    }

    #[must_use]
    pub const fn maximum_major(&self) -> u16 {
        self.maximum_major
    }

    #[must_use]
    pub const fn startup_nonce(&self) -> &[u8; 32] {
        &self.startup_nonce
    }

    #[must_use]
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    #[must_use]
    pub const fn agent_process_id(&self) -> u32 {
        self.agent_process_id
    }

    #[must_use]
    pub const fn agent_process_creation_time(&self) -> u64 {
        self.agent_process_creation_time
    }

    #[must_use]
    pub fn package_full_name(&self) -> &str {
        &self.package_full_name
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encode_array(&mut encoder, 8);
        encode_u8(&mut encoder, ENDPOINT_SCHEMA);
        encode_text(&mut encoder, &self.pipe_name);
        encode_u32(&mut encoder, self.agent_process_id);
        encode_u64(&mut encoder, self.agent_process_creation_time);
        encode_text(&mut encoder, &self.package_full_name);
        encode_u16(&mut encoder, self.minimum_major);
        encode_u16(&mut encoder, self.maximum_major);
        encode_bytes(&mut encoder, &self.startup_nonce);
        encoder.into_writer()
    }

    /// Decodes and canonicalizes one endpoint descriptor.
    ///
    /// # Errors
    ///
    /// Rejects stale-schema, malformed, oversized, or noncanonical input.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > MAX_ENDPOINT_DESCRIPTOR_BYTES {
            return Err(ProtocolError::TooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        expect_array(&mut decoder, 8)?;
        if decode_u8(&mut decoder)? != ENDPOINT_SCHEMA {
            return Err(ProtocolError::Unsupported);
        }
        let pipe_name = decode_bounded_text(&mut decoder, MAX_PIPE_NAME_BYTES)?;
        let process_id = decode_u32(&mut decoder)?;
        let creation_time = decode_u64(&mut decoder)?;
        let package = decode_bounded_text(&mut decoder, MAX_PACKAGE_NAME_BYTES)?;
        let minimum = decode_u16(&mut decoder)?;
        let maximum = decode_u16(&mut decoder)?;
        let nonce = decode_fixed_bytes(&mut decoder)?;
        require_end(&decoder, bytes)?;
        let descriptor = Self::new(
            pipe_name,
            process_id,
            creation_time,
            package,
            minimum,
            maximum,
            nonce,
        )?;
        if descriptor.encode().as_slice() != bytes {
            return Err(ProtocolError::NonCanonical);
        }
        Ok(descriptor)
    }
}

/// Authorized operation envelope. The body is zeroized and never formatted.
pub struct RequestEnvelope {
    operation: OperationCode,
    unlock_epoch: u64,
    timeout_ms: u32,
    idempotency_key: Option<[u8; 16]>,
    body: Zeroizing<Vec<u8>>,
}

impl RequestEnvelope {
    /// Constructs a bounded request.
    ///
    /// # Errors
    ///
    /// Rejects a zero timeout or body beyond the version-1 bound.
    pub fn new(
        operation: OperationCode,
        unlock_epoch: u64,
        timeout_ms: u32,
        idempotency_key: Option<[u8; 16]>,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<Self, ProtocolError> {
        if timeout_ms == 0
            || body.len() > MAX_REQUEST_BODY_BYTES
            || (idempotency_key.is_some() && !operation.requires_idempotency_key())
        {
            return Err(ProtocolError::InvariantViolation);
        }
        Ok(Self {
            operation,
            unlock_epoch,
            timeout_ms,
            idempotency_key,
            body,
        })
    }

    #[must_use]
    pub const fn operation(&self) -> OperationCode {
        self.operation
    }

    #[must_use]
    pub const fn unlock_epoch(&self) -> u64 {
        self.unlock_epoch
    }

    #[must_use]
    pub const fn timeout_ms(&self) -> u32 {
        self.timeout_ms
    }

    #[must_use]
    pub const fn idempotency_key(&self) -> Option<&[u8; 16]> {
        self.idempotency_key.as_ref()
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Encodes directly into a pre-sized zeroizing buffer.
    ///
    /// # Errors
    ///
    /// Returns `TooLarge` if the resulting envelope exceeds the frame bound.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let mut encoder = Encoder::new(SecretWriter::with_capacity(MAX_PAYLOAD_BYTES));
        encode_array(&mut encoder, 5);
        encode_u16(&mut encoder, self.operation as u16);
        encode_u64(&mut encoder, self.unlock_epoch);
        encode_u32(&mut encoder, self.timeout_ms);
        if let Some(key) = self.idempotency_key {
            encode_bytes(&mut encoder, &key);
        } else {
            encode_null(&mut encoder);
        }
        encode_bytes(&mut encoder, &self.body);
        let bytes = encoder.into_writer().into_bytes();
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(ProtocolError::TooLarge);
        }
        Ok(bytes)
    }

    /// Decodes and canonicalizes a secret-bearing request.
    ///
    /// # Errors
    ///
    /// Rejects malformed, unknown-operation, oversized, or noncanonical input.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(ProtocolError::TooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        expect_array(&mut decoder, 5)?;
        let operation = OperationCode::from_u64(u64::from(decode_u16(&mut decoder)?))
            .ok_or(ProtocolError::Unsupported)?;
        let unlock_epoch = decode_u64(&mut decoder)?;
        let timeout_ms = decode_u32(&mut decoder)?;
        let idempotency_key = decode_optional_fixed_bytes(&mut decoder)?;
        let body = Zeroizing::new(decode_bounded_bytes(&mut decoder, MAX_REQUEST_BODY_BYTES)?);
        require_end(&decoder, bytes)?;
        let request = Self::new(operation, unlock_epoch, timeout_ms, idempotency_key, body)?;
        if request.encode()?.as_slice() != bytes {
            return Err(ProtocolError::NonCanonical);
        }
        Ok(request)
    }

    /// Reads only the fixed operation code so role authorization can run
    /// before the operation-specific body is decoded.
    ///
    /// # Errors
    ///
    /// Rejects a missing array or unknown operation. Full canonical validation
    /// remains mandatory after authorization.
    pub fn peek_operation(bytes: &[u8]) -> Result<OperationCode, ProtocolError> {
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(ProtocolError::TooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        expect_array(&mut decoder, 5)?;
        OperationCode::from_u64(u64::from(decode_u16(&mut decoder)?))
            .ok_or(ProtocolError::Unsupported)
    }
}

fn encoded_byte_string_len(length: usize) -> usize {
    let header = if length < 24 {
        1
    } else if u8::try_from(length).is_ok() {
        2
    } else if u16::try_from(length).is_ok() {
        3
    } else if u32::try_from(length).is_ok() {
        5
    } else {
        9
    };
    header + length
}

impl fmt::Debug for RequestEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestEnvelope")
            .field("operation", &self.operation)
            .field("unlock_epoch", &self.unlock_epoch)
            .field("timeout_ms", &self.timeout_ms)
            .field("idempotency_key", &self.idempotency_key.map(|_| "REDACTED"))
            .field("body", &"REDACTED")
            .finish()
    }
}

/// Terminal response envelope. Body bytes are always zeroized.
pub struct ResponseEnvelope {
    error: Option<PublicErrorCode>,
    retry: RetryCategory,
    correlation_id: CorrelationId,
    body: Zeroizing<Vec<u8>>,
}

impl ResponseEnvelope {
    /// Constructs a successful response.
    ///
    /// # Errors
    ///
    /// Rejects an oversized response body.
    pub fn success(
        correlation_id: CorrelationId,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<Self, ProtocolError> {
        Self::new(None, RetryCategory::Never, correlation_id, body)
    }

    /// Constructs a public failure with no attacker-controlled details.
    ///
    /// # Errors
    ///
    /// Rejects a zero correlation identifier.
    pub fn failure(
        error: PublicErrorCode,
        retry: RetryCategory,
        correlation_id: CorrelationId,
    ) -> Result<Self, ProtocolError> {
        Self::new(
            Some(error),
            retry,
            correlation_id,
            Zeroizing::new(Vec::new()),
        )
    }

    fn new(
        error: Option<PublicErrorCode>,
        retry: RetryCategory,
        correlation_id: CorrelationId,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<Self, ProtocolError> {
        if body.len() > MAX_RESPONSE_BODY_BYTES
            || (error.is_some() && !body.is_empty())
            || (error.is_none() && retry != RetryCategory::Never)
            || correlation_id.as_bytes() == &[0; 16]
        {
            return Err(ProtocolError::InvariantViolation);
        }
        Ok(Self {
            error,
            retry,
            correlation_id,
            body,
        })
    }

    #[must_use]
    pub const fn error(&self) -> Option<PublicErrorCode> {
        self.error
    }

    #[must_use]
    pub const fn retry(&self) -> RetryCategory {
        self.retry
    }

    #[must_use]
    pub const fn correlation_id(&self) -> CorrelationId {
        self.correlation_id
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the exact canonical payload length without copying the body.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        const FIXED_BYTES: usize = 20;
        FIXED_BYTES + encoded_byte_string_len(self.body.len())
    }

    /// Encodes directly into a pre-sized zeroizing buffer.
    ///
    /// # Errors
    ///
    /// Returns `TooLarge` if the payload exceeds the frame bound.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let mut encoder = Encoder::new(SecretWriter::with_capacity(MAX_PAYLOAD_BYTES));
        encode_array(&mut encoder, 4);
        encode_u8(&mut encoder, self.error.map_or(0, |value| value as u8));
        encode_u8(&mut encoder, self.retry as u8);
        encode_bytes(&mut encoder, self.correlation_id.as_bytes());
        encode_bytes(&mut encoder, &self.body);
        let bytes = encoder.into_writer().into_bytes();
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(ProtocolError::TooLarge);
        }
        Ok(bytes)
    }

    /// Decodes and canonicalizes a response.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, detail-bearing failure, or noncanonical
    /// input.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(ProtocolError::TooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        expect_array(&mut decoder, 4)?;
        let raw_error = decode_u8(&mut decoder)?;
        let error = if raw_error == 0 {
            None
        } else {
            Some(
                PublicErrorCode::from_u64(u64::from(raw_error))
                    .ok_or(ProtocolError::Unsupported)?,
            )
        };
        let retry = RetryCategory::from_u64(u64::from(decode_u8(&mut decoder)?))
            .ok_or(ProtocolError::Unsupported)?;
        let correlation_id = CorrelationId::new(decode_fixed_bytes(&mut decoder)?);
        let body = Zeroizing::new(decode_bounded_bytes(&mut decoder, MAX_RESPONSE_BODY_BYTES)?);
        require_end(&decoder, bytes)?;
        let response = Self::new(error, retry, correlation_id, body)?;
        if response.encode()?.as_slice() != bytes {
            return Err(ProtocolError::NonCanonical);
        }
        Ok(response)
    }
}

impl fmt::Debug for ResponseEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseEnvelope")
            .field("error", &self.error)
            .field("retry", &self.retry)
            .field("correlation_id", &self.correlation_id)
            .field("body", &"REDACTED")
            .finish()
    }
}
