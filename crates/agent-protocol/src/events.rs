use std::collections::VecDeque;

use minicbor::{Decoder, Encoder};

use crate::{
    AgentState, MAX_EVENT_QUEUE, ProtocolError,
    cbor::{decode_u8, decode_u64, encode_array, encode_u8, encode_u64, expect_array, require_end},
};

/// Bounded non-secret state transition sent by the agent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentEvent {
    state: AgentState,
    unlock_epoch: u64,
}

impl AgentEvent {
    #[must_use]
    pub const fn new(state: AgentState, unlock_epoch: u64) -> Self {
        Self {
            state,
            unlock_epoch,
        }
    }

    #[must_use]
    pub const fn state(self) -> AgentState {
        self.state
    }

    #[must_use]
    pub const fn unlock_epoch(self) -> u64 {
        self.unlock_epoch
    }

    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encode_array(&mut encoder, 2);
        encode_u8(&mut encoder, self.state as u8);
        encode_u64(&mut encoder, self.unlock_epoch);
        encoder.into_writer()
    }

    /// Decodes and canonicalizes one bounded event.
    ///
    /// # Errors
    ///
    /// Rejects unknown state, wrong fields, trailing bytes, and noncanonical
    /// integers.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut decoder = Decoder::new(bytes);
        expect_array(&mut decoder, 2)?;
        let state = AgentState::from_u64(u64::from(decode_u8(&mut decoder)?))
            .ok_or(ProtocolError::Unsupported)?;
        let event = Self::new(state, decode_u64(&mut decoder)?);
        require_end(&decoder, bytes)?;
        if event.encode().as_slice() != bytes {
            return Err(ProtocolError::NonCanonical);
        }
        Ok(event)
    }
}

/// Queue overflow is connection-fatal so a slow peer cannot retain unbounded
/// agent state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventQueueOverflow;

/// Exact version-1 event queue bound for one authenticated connection.
pub struct EventQueue {
    events: VecDeque<AgentEvent>,
}

impl EventQueue {
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: VecDeque::with_capacity(MAX_EVENT_QUEUE),
        }
    }

    /// Adds one state transition.
    ///
    /// # Errors
    ///
    /// Returns `EventQueueOverflow` at the exact version-1 bound; callers must
    /// close the slow connection.
    pub fn push(&mut self, event: AgentEvent) -> Result<(), EventQueueOverflow> {
        if self.events.len() >= MAX_EVENT_QUEUE {
            return Err(EventQueueOverflow);
        }
        self.events.push_back(event);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<AgentEvent> {
        self.events.pop_front()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

impl Default for EventQueue {
    fn default() -> Self {
        Self::new()
    }
}
