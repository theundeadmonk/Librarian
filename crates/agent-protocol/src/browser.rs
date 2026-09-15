//! Closed browser-fill schemas. Origin authority is checked independently by
//! the agent; these types provide bounds and connection-scoped context only.

use minicbor::{Decoder, Encoder};
use zeroize::Zeroizing;

use crate::{
    ProtocolError,
    cbor::{
        SecretWriter, decode_array_length, decode_bounded_text, decode_fixed_bytes, decode_u32,
        decode_u64, encode_array, encode_bytes, encode_text, encode_u32, encode_u64, expect_array,
        require_end,
    },
};

/// Bounded browser-observed context; not proof of a website or user gesture.
#[derive(Clone)]
pub struct BrowserContext {
    request_id: [u8; 16],
    tab_id: u32,
    document_id: [u8; 16],
    top_origin: Zeroizing<String>,
    frame_origin: Zeroizing<String>,
}

impl BrowserContext {
    /// # Errors
    /// Rejects invalid identifiers, embedded frames, unequal or oversized origins.
    /// Canonical HTTPS parsing is additionally required inside the agent.
    pub fn new(
        request_id: [u8; 16],
        tab_id: u32,
        frame_id: u32,
        document_id: [u8; 16],
        top_origin: &str,
        frame_origin: &str,
    ) -> Result<Self, ProtocolError> {
        if request_id == [0; 16]
            || document_id == [0; 16]
            || tab_id > i32::MAX as u32
            || frame_id != 0
            || top_origin.is_empty()
            || top_origin != frame_origin
        {
            return Err(ProtocolError::InvariantViolation);
        }
        if top_origin.len() > 2048 || frame_origin.len() > 2048 {
            return Err(ProtocolError::TooLarge);
        }
        Ok(Self {
            request_id,
            tab_id,
            document_id,
            top_origin: Zeroizing::new(top_origin.to_owned()),
            frame_origin: Zeroizing::new(frame_origin.to_owned()),
        })
    }

    #[must_use]
    pub fn top_origin(&self) -> &str {
        &self.top_origin
    }

    #[must_use]
    pub fn frame_origin(&self) -> &str {
        &self.frame_origin
    }

    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.request_id == other.request_id
            && self.tab_id == other.tab_id
            && self.document_id == other.document_id
            && self.top_origin == other.top_origin
            && self.frame_origin == other.frame_origin
    }

    pub(crate) fn encode_into(&self, encoder: &mut Encoder<SecretWriter>) {
        encode_array(encoder, 6);
        encode_bytes(encoder, &self.request_id);
        encode_u32(encoder, self.tab_id);
        encode_u32(encoder, 0);
        encode_bytes(encoder, &self.document_id);
        encode_text(encoder, &self.top_origin);
        encode_text(encoder, &self.frame_origin);
    }

    pub(crate) fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, ProtocolError> {
        expect_array(decoder, 6)?;
        Self::new(
            decode_fixed_bytes(decoder)?,
            decode_u32(decoder)?,
            decode_u32(decoder)?,
            decode_fixed_bytes(decoder)?,
            &Zeroizing::new(decode_bounded_text(decoder, 2048)?),
            &Zeroizing::new(decode_bounded_text(decoder, 2048)?),
        )
    }
}

/// Single-use, connection-bound selection. No account labels or secrets.
pub struct BrowserSelection {
    token: [u8; 16],
    record_id: [u8; 16],
    revision: u64,
}

impl BrowserSelection {
    /// # Errors
    /// Rejects zero identifiers and revisions.
    pub fn new(token: [u8; 16], record_id: [u8; 16], revision: u64) -> Result<Self, ProtocolError> {
        if token == [0; 16] || record_id == [0; 16] || revision == 0 {
            return Err(ProtocolError::InvariantViolation);
        }
        Ok(Self {
            token,
            record_id,
            revision,
        })
    }

    #[must_use]
    pub const fn record_id(&self) -> [u8; 16] {
        self.record_id
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.token == other.token
            && self.record_id == other.record_id
            && self.revision == other.revision
    }

    pub(crate) fn encode_into(&self, encoder: &mut Encoder<SecretWriter>) {
        encode_array(encoder, 3);
        encode_bytes(encoder, &self.token);
        encode_bytes(encoder, &self.record_id);
        encode_u64(encoder, self.revision);
    }

    pub(crate) fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, ProtocolError> {
        expect_array(decoder, 3)?;
        Self::new(
            decode_fixed_bytes(decoder)?,
            decode_fixed_bytes(decoder)?,
            decode_u64(decoder)?,
        )
    }

    /// Encodes zero or one selection, with no count or unrelated metadata.
    #[must_use]
    pub fn encode_optional(value: Option<&Self>) -> Zeroizing<Vec<u8>> {
        let mut encoder = Encoder::new(SecretWriter::with_capacity(64));
        if let Some(value) = value {
            value.encode_into(&mut encoder);
        } else {
            encode_array(&mut encoder, 0);
        }
        encoder.into_writer().into_bytes()
    }

    /// # Errors
    /// Rejects extra fields, malformed, noncanonical, or oversized responses.
    pub fn decode_optional(bytes: &[u8]) -> Result<Option<Self>, ProtocolError> {
        if bytes.len() > 64 {
            return Err(ProtocolError::TooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        let count = decode_array_length(&mut decoder, 3)?;
        let result = match count {
            0 => None,
            3 => Some(Self::new(
                decode_fixed_bytes(&mut decoder)?,
                decode_fixed_bytes(&mut decoder)?,
                decode_u64(&mut decoder)?,
            )?),
            _ => return Err(ProtocolError::Malformed),
        };
        require_end(&decoder, bytes)?;
        if Self::encode_optional(result.as_ref()).as_slice() != bytes {
            return Err(ProtocolError::NonCanonical);
        }
        Ok(result)
    }
}

/// Only the username and password of one selected account. No formatting,
/// cloning, unrelated metadata, keys, or general-purpose account serialization.
pub struct BrowserCredential {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl BrowserCredential {
    /// # Errors
    /// Rejects fields exceeding their UTF-8 byte bounds.
    pub fn new(username: &str, password: &str) -> Result<Self, ProtocolError> {
        if username.len() > 1024 || password.len() > 16384 {
            return Err(ProtocolError::TooLarge);
        }
        Ok(Self {
            username: Zeroizing::new(username.to_owned()),
            password: Zeroizing::new(password.to_owned()),
        })
    }

    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }

    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut encoder = Encoder::new(SecretWriter::with_capacity(17500));
        encode_array(&mut encoder, 2);
        encode_text(&mut encoder, &self.username);
        encode_text(&mut encoder, &self.password);
        encoder.into_writer().into_bytes()
    }

    /// # Errors
    /// Rejects malformed, extended, noncanonical, or oversized responses.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > 17500 {
            return Err(ProtocolError::TooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        expect_array(&mut decoder, 2)?;
        let result = Self {
            username: Zeroizing::new(decode_bounded_text(&mut decoder, 1024)?),
            password: Zeroizing::new(decode_bounded_text(&mut decoder, 16384)?),
        };
        require_end(&decoder, bytes)?;
        if result.encode().as_slice() != bytes {
            return Err(ProtocolError::NonCanonical);
        }
        Ok(result)
    }
}
