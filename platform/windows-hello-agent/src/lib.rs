//! Safe Rust ownership for Librarian's agent-internal Windows Hello bridge.
//!
//! The C ABI and all Win32 calls are isolated in this crate. PRF output is
//! written directly into caller-owned zeroizing storage and is never exposed
//! through the desktop protocol.

#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{
    BridgeError, Enrollment, OperationId, ParentWindow, ProtectedStateError, cancel, enroll,
    evaluate, is_available, protect_user_state, remove, replace_file_atomically,
    restrict_user_file, unprotect_user_state, verify_user_file_restriction,
};
