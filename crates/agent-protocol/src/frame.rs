use core::fmt;

use zeroize::Zeroizing;

use crate::{HEADER_BYTES, MAX_PAYLOAD_BYTES, Version};

const MAGIC: [u8; 4] = *b"LBIP";
const HEADER_VERSION: u8 = 1;

/// Closed frame-kind enumeration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageKind {
    ClientHello = 1,
    ServerHello = 2,
    Request = 3,
    Response = 4,
    Cancel = 5,
    Event = 6,
}

impl MessageKind {
    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::ClientHello),
            2 => Some(Self::ServerHello),
            3 => Some(Self::Request),
            4 => Some(Self::Response),
            5 => Some(Self::Cancel),
            6 => Some(Self::Event),
            _ => None,
        }
    }
}

/// Bounded frame-validation failures. No variant retains attacker input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    TooLarge,
    Malformed,
    InvalidHeader,
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLarge => "protocol frame exceeds its limit",
            Self::Malformed => "protocol frame is malformed",
            Self::InvalidHeader => "protocol frame header is invalid",
        })
    }
}

impl std::error::Error for FrameError {}

/// Validated fixed header. Connection identifiers are intentionally omitted
/// from its debug representation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FrameHeader {
    kind: MessageKind,
    version: Version,
    payload_length: u32,
    connection_id: [u8; 16],
    request_id: u64,
}

impl FrameHeader {
    /// Creates and validates one header under the per-kind ADR rules.
    ///
    /// # Errors
    ///
    /// Returns `TooLarge` or `InvalidHeader` for any unsupported combination.
    pub fn new(
        kind: MessageKind,
        version: Version,
        payload_length: usize,
        connection_id: [u8; 16],
        request_id: u64,
    ) -> Result<Self, FrameError> {
        if payload_length > MAX_PAYLOAD_BYTES {
            return Err(FrameError::TooLarge);
        }
        let payload_length = u32::try_from(payload_length).map_err(|_| FrameError::TooLarge)?;
        let header = Self {
            kind,
            version,
            payload_length,
            connection_id,
            request_id,
        };
        header.validate_kind_fields()?;
        Ok(header)
    }

    #[must_use]
    pub const fn kind(&self) -> MessageKind {
        self.kind
    }

    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    #[must_use]
    pub const fn payload_length(&self) -> u32 {
        self.payload_length
    }

    #[must_use]
    pub const fn connection_id(&self) -> &[u8; 16] {
        &self.connection_id
    }

    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut bytes = [0_u8; HEADER_BYTES];
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[4] = HEADER_VERSION;
        bytes[5] = self.kind as u8;
        bytes[6..8].copy_from_slice(&0_u16.to_be_bytes());
        bytes[8..10].copy_from_slice(&self.version.major().to_be_bytes());
        bytes[10..12].copy_from_slice(&self.version.minor().to_be_bytes());
        bytes[12..16].copy_from_slice(&self.payload_length.to_be_bytes());
        bytes[16..32].copy_from_slice(&self.connection_id);
        bytes[32..40].copy_from_slice(&self.request_id.to_be_bytes());
        bytes
    }

    /// Decodes one complete 40-byte header.
    ///
    /// # Errors
    ///
    /// Rejects unknown kinds, flags, oversize declarations, and invalid
    /// per-kind sentinel values.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        let bytes: &[u8; HEADER_BYTES] = bytes.try_into().map_err(|_| FrameError::Malformed)?;
        if bytes[0..4] != MAGIC || bytes[4] != HEADER_VERSION || bytes[6..8] != [0, 0] {
            return Err(FrameError::InvalidHeader);
        }
        let kind = MessageKind::from_u8(bytes[5]).ok_or(FrameError::InvalidHeader)?;
        let version = Version::new(
            u16::from_be_bytes([bytes[8], bytes[9]]),
            u16::from_be_bytes([bytes[10], bytes[11]]),
        );
        let payload_length = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let connection_id = bytes[16..32]
            .try_into()
            .map_err(|_| FrameError::Malformed)?;
        let request_id = u64::from_be_bytes(
            bytes[32..40]
                .try_into()
                .map_err(|_| FrameError::Malformed)?,
        );
        Self::new(
            kind,
            version,
            usize::try_from(payload_length).map_err(|_| FrameError::TooLarge)?,
            connection_id,
            request_id,
        )
    }

    fn validate_kind_fields(&self) -> Result<(), FrameError> {
        let zero_version = self.version == Version::new(0, 0);
        let zero_connection = self.connection_id == [0; 16];
        let zero_request = self.request_id == 0;
        let valid = match self.kind {
            MessageKind::ClientHello => zero_version && zero_connection && zero_request,
            MessageKind::ServerHello | MessageKind::Event => {
                !zero_version && !zero_connection && zero_request
            }
            MessageKind::Request | MessageKind::Response | MessageKind::Cancel => {
                !zero_version && !zero_connection && !zero_request
            }
        };
        if !valid {
            return Err(FrameError::InvalidHeader);
        }
        Ok(())
    }
}

impl fmt::Debug for FrameHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrameHeader")
            .field("kind", &self.kind)
            .field("version", &self.version)
            .field("payload_length", &self.payload_length)
            .field("connection_id", &"REDACTED")
            .field("request_id", &self.request_id)
            .finish()
    }
}

/// One validated frame whose payload is zeroized on every exit path.
pub struct Frame {
    header: FrameHeader,
    payload: Zeroizing<Vec<u8>>,
}

impl Frame {
    /// Builds one complete frame.
    ///
    /// # Errors
    ///
    /// Rejects a payload that disagrees with the header or exceeds the bound.
    pub fn new(header: FrameHeader, payload: Zeroizing<Vec<u8>>) -> Result<Self, FrameError> {
        if usize::try_from(header.payload_length).map_err(|_| FrameError::TooLarge)?
            != payload.len()
        {
            return Err(FrameError::Malformed);
        }
        Ok(Self { header, payload })
    }

    /// Reads one complete in-memory frame without resynchronization.
    ///
    /// # Errors
    ///
    /// Rejects partial, trailing, oversized, or invalid-header input before
    /// retaining a payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < HEADER_BYTES {
            return Err(FrameError::Malformed);
        }
        let header = FrameHeader::decode(&bytes[..HEADER_BYTES])?;
        let payload_length =
            usize::try_from(header.payload_length).map_err(|_| FrameError::TooLarge)?;
        let total = HEADER_BYTES
            .checked_add(payload_length)
            .ok_or(FrameError::TooLarge)?;
        if bytes.len() != total {
            return Err(FrameError::Malformed);
        }
        Self::new(header, Zeroizing::new(bytes[HEADER_BYTES..].to_vec()))
    }

    /// Encodes directly into a pre-sized zeroizing allocation.
    ///
    /// # Errors
    ///
    /// Returns `TooLarge` if the total size cannot be represented.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, FrameError> {
        let total = HEADER_BYTES
            .checked_add(self.payload.len())
            .ok_or(FrameError::TooLarge)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(total));
        bytes.extend_from_slice(&self.header.encode());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    #[must_use]
    pub const fn header(&self) -> &FrameHeader {
        &self.header
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    #[must_use]
    pub fn into_parts(self) -> (FrameHeader, Zeroizing<Vec<u8>>) {
        (self.header, self.payload)
    }
}

impl fmt::Debug for Frame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Frame")
            .field("header", &self.header)
            .field("payload", &"REDACTED")
            .finish()
    }
}
