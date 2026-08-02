//! Safe ownership for the agent-internal Windows passkey request verifier.
//!
//! Platform operation and Windows Hello signatures are verified in the native
//! bridge before bounded decoded fields cross into Rust. Private passkey
//! material is structurally absent from this crate.

#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{
    VerificationError, VerifiedAssertionLookup, VerifiedAssertionRequest, VerifiedMakeRequest,
    verify_assertion, verify_assertion_lookup, verify_make,
};
