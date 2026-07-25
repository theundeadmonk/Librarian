//! Narrow Windows transport and packaged-peer authentication boundary.
//!
//! All Win32 calls are isolated in this crate. Portable protocol parsing and
//! authorization state belong to `librarian-agent-protocol`; vault ownership
//! belongs to `librarian-vault-agent`.

#![deny(unsafe_op_in_unsafe_fn)]

mod identity;

#[cfg(windows)]
mod discovery;

#[cfg(windows)]
mod platform;

pub use identity::{
    ComponentRole, PeerAuthorizationError, PeerObservation, PeerPolicy, authorize_client_role,
    authorize_peer,
};

#[cfg(windows)]
pub use discovery::{DiscoveryError, EndpointDescriptorStore};

#[cfg(windows)]
pub use platform::{
    ListenerPool, PeerHandle, PipeConnection, TransportError, current_process_observation,
    observe_pipe_client, observe_pipe_server,
};
