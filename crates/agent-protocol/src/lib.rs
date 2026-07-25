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
    AccountFields, AccountView, OperationRequest, encode_account, encode_account_id,
    encode_account_summaries, encode_empty_result, encode_status,
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

/// Current trusted-protocol version.
pub const CURRENT_VERSION: Version = Version::new(1, 0);
