//! Bounded, deterministic protocol types for the trusted Librarian agent.
//!
//! Transport code authenticates a peer and supplies its derived [`ClientRole`]
//! before this crate parses a handshake or request. This crate never observes
//! processes, opens the vault, or performs cryptography.

#![forbid(unsafe_code)]

mod cbor;
mod events;
mod frame;
mod message;
mod operations;
mod session;
mod types;

pub use events::{AgentEvent, EventQueue, EventQueueOverflow};
pub use frame::{Frame, FrameError, FrameHeader, MessageKind};
pub use message::{
    ClientHello, EndpointDescriptor, ProtocolError, RequestEnvelope, ResponseEnvelope, ServerHello,
};
pub use operations::{
    AccountFields, AccountView, OperationRequest, PasskeyAssertionView, PasskeyCredentialView,
    PasskeyManagementSummaryView, PasskeyRequestProof, PasskeySummaryView, PasskeyTransactionProof,
    encode_account, encode_account_id, encode_account_summaries, encode_empty_result,
    encode_passkey_assertion, encode_passkey_credential, encode_passkey_management_summaries,
    encode_passkey_summaries, encode_status,
};
pub use session::{
    BeginRequestError, Connection, ConnectionError, ConnectionLimits, RequestCompletion,
    RequestPermit,
};
pub use types::{
    AgentState, ClientRole, CorrelationId, OperationCode, PublicErrorCode, RetryCategory, Version,
};

/// Fixed bytes in every protocol frame.
pub const HEADER_BYTES: usize = 40;
/// Maximum payload accepted before allocation.
pub const MAX_PAYLOAD_BYTES: usize = 65_536;
/// Smallest negotiated payload that can carry a detail-free failure response.
pub const MIN_NEGOTIATED_PAYLOAD_BYTES: usize = 21;
/// Maximum discovery descriptor size.
pub const MAX_ENDPOINT_DESCRIPTOR_BYTES: usize = 4_096;
/// Version 1 permits no more than four concurrent requests per connection.
pub const MAX_IN_FLIGHT_PER_CONNECTION: usize = 4;
/// Version 1 permits no more than 32 concurrent requests across the agent.
pub const MAX_IN_FLIGHT_GLOBAL: usize = 32;
/// The complete listener pool is created before endpoint discovery.
pub const MAX_CONNECTIONS: usize = 8;
/// Maximum queued state events per connection.
pub const MAX_EVENT_QUEUE: usize = 8;
/// Header and ordinary handshake deadline.
pub const HANDSHAKE_TIMEOUT_MS: u32 = 2_000;
/// Default deadline for ordinary operations.
pub const ORDINARY_TIMEOUT_MS: u32 = 5_000;
/// Maximum password-unlock deadline.
pub const UNLOCK_TIMEOUT_MS: u32 = 30_000;
/// Maximum Windows-mediated passkey deadline.
pub const PASSKEY_TIMEOUT_MS: u32 = 120_000;

/// Oldest protocol revision accepted by this agent.
pub const MINIMUM_VERSION: Version = Version::new(1, 0);
/// Current trusted-protocol version.
pub const CURRENT_VERSION: Version = Version::new(1, 2);
/// First protocol revision that defines agent-owned Windows Hello operations.
pub const WINDOWS_HELLO_VERSION: Version = Version::new(1, 1);
/// Explicit feature grant required for every Windows Hello operation.
pub const FEATURE_WINDOWS_HELLO: u16 = 1;
/// Explicit feature grant required for vault-backed passkey operations.
pub const FEATURE_PASSKEY_PROVIDER: u16 = 2;
/// First protocol revision that defines vault-backed passkey schemas.
pub const PASSKEY_PROVIDER_VERSION: Version = Version::new(1, 2);
