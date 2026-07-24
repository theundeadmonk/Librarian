use minicbor::{Decoder, Encoder};
use zeroize::Zeroizing;

use crate::{CONTAINER_VERSION, FormatError, MAX_RECORD_ENVELOPE_BYTES};

pub const RECORD_ENVELOPE_VERSION: u32 = 1;
pub const RECORD_SCHEMA: u32 = 1;
pub const WEBSITE_ACCOUNT_RECORD_TYPE: u32 = 1;

pub const MAX_SERVICE_NAME_BYTES: usize = 256;
pub const MAX_ORIGIN_BYTES: usize = 2_048;
pub const MAX_USERNAME_BYTES: usize = 1_024;
pub const MAX_PASSWORD_BYTES: usize = 16 * 1_024;

const RECORD_MAGIC: &str = "LBR-REC";
const TAG_BYTES: usize = 16;

/// One bounded, encrypted record stored in `encrypted_records`.
#[derive(Clone, Eq, PartialEq)]
pub struct RecordEnvelope {
    key_epoch: u32,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

impl RecordEnvelope {
    /// Constructs one version-1 encrypted record envelope.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero key epoch, missing authentication tag, or
    /// an envelope that exceeds the version-1 size limit.
    pub fn new(key_epoch: u32, nonce: [u8; 24], ciphertext: Vec<u8>) -> Result<Self, FormatError> {
        if key_epoch == 0 {
            return Err(FormatError::InvariantViolation);
        }
        if ciphertext.len() < TAG_BYTES {
            return Err(FormatError::Malformed);
        }
        let envelope = Self {
            key_epoch,
            nonce,
            ciphertext,
        };
        envelope.encode()?;
        Ok(envelope)
    }

    #[must_use]
    pub const fn key_epoch(&self) -> u32 {
        self.key_epoch
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }

    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Encodes the envelope using deterministic CBOR.
    ///
    /// # Errors
    ///
    /// Returns an error when an invariant or size limit is violated.
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        if self.key_epoch == 0 || self.ciphertext.len() < TAG_BYTES {
            return Err(FormatError::InvariantViolation);
        }
        let mut encoder = Encoder::new(Vec::new());
        encode_array(&mut encoder, 4);
        encode_u32(&mut encoder, RECORD_ENVELOPE_VERSION);
        encode_u32(&mut encoder, self.key_epoch);
        encode_bytes(&mut encoder, &self.nonce);
        encode_bytes(&mut encoder, &self.ciphertext);
        let bytes = encoder.into_writer();
        if bytes.len() > MAX_RECORD_ENVELOPE_BYTES {
            return Err(FormatError::TooLarge);
        }
        Ok(bytes)
    }

    /// Parses and byte-for-byte canonicalizes a record envelope.
    ///
    /// # Errors
    ///
    /// Returns a bounded format error for oversized, malformed, unsupported,
    /// or noncanonical input.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() > MAX_RECORD_ENVELOPE_BYTES {
            return Err(FormatError::TooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        expect_array(&mut decoder, 4)?;
        expect_u32(&mut decoder, RECORD_ENVELOPE_VERSION)?;
        let key_epoch = decode_u32(&mut decoder)?;
        let nonce = decode_fixed_bytes(&mut decoder)?;
        let ciphertext = decode_bounded_bytes(&mut decoder, MAX_RECORD_ENVELOPE_BYTES)?;
        require_end(&decoder, bytes)?;
        let envelope = Self::new(key_epoch, nonce, ciphertext)?;
        if envelope.encode()?.as_slice() != bytes {
            return Err(FormatError::NonCanonical);
        }
        Ok(envelope)
    }
}

/// Canonical plaintext for the Slice 1 website-account record.
///
/// Every user-authored field is zeroized on drop. This type intentionally does
/// not implement formatting, cloning, serialization, or equality traits.
pub struct WebsiteAccountPlaintext {
    revision: u64,
    created_at_ms: u64,
    modified_at_ms: u64,
    service_name: Zeroizing<String>,
    permitted_origin: Zeroizing<String>,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl WebsiteAccountPlaintext {
    /// Constructs a validated website-account plaintext.
    ///
    /// # Errors
    ///
    /// Returns an invariant or size error for invalid version metadata or
    /// fields outside the Slice 1 bounds.
    pub fn new(
        revision: u64,
        created_at_ms: u64,
        modified_at_ms: u64,
        service_name: Zeroizing<String>,
        permitted_origin: Zeroizing<String>,
        username: Zeroizing<String>,
        password: Zeroizing<String>,
    ) -> Result<Self, FormatError> {
        let value = Self {
            revision,
            created_at_ms,
            modified_at_ms,
            service_name,
            permitted_origin,
            username,
            password,
        };
        validate_plaintext(&value)?;
        Ok(value)
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    #[must_use]
    pub const fn modified_at_ms(&self) -> u64 {
        self.modified_at_ms
    }

    #[must_use]
    pub fn service_name(&self) -> &str {
        self.service_name.as_str()
    }

    #[must_use]
    pub fn permitted_origin(&self) -> &str {
        self.permitted_origin.as_str()
    }

    #[must_use]
    pub fn username(&self) -> &str {
        self.username.as_str()
    }

    #[must_use]
    pub fn password(&self) -> &str {
        self.password.as_str()
    }

    /// Moves the zeroizing user-authored fields out of this format value.
    #[must_use]
    pub fn into_fields(
        self,
    ) -> (
        Zeroizing<String>,
        Zeroizing<String>,
        Zeroizing<String>,
        Zeroizing<String>,
    ) {
        (
            self.service_name,
            self.permitted_origin,
            self.username,
            self.password,
        )
    }

    /// Encodes the plaintext using the fixed version-1 website schema.
    ///
    /// # Errors
    ///
    /// Returns an invariant or size error when the value is not representable.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, FormatError> {
        validate_plaintext(self)?;
        let mut encoder = Encoder::new(Vec::new());
        encode_array(&mut encoder, 6);
        encode_u32(&mut encoder, RECORD_SCHEMA);
        encode_u32(&mut encoder, WEBSITE_ACCOUNT_RECORD_TYPE);
        encode_u64(&mut encoder, self.revision);
        encode_u64(&mut encoder, self.created_at_ms);
        encode_u64(&mut encoder, self.modified_at_ms);
        encode_array(&mut encoder, 4);
        encode_str(&mut encoder, &self.service_name);
        encode_str(&mut encoder, &self.permitted_origin);
        encode_str(&mut encoder, &self.username);
        encode_str(&mut encoder, &self.password);
        let bytes = Zeroizing::new(encoder.into_writer());
        if bytes
            .len()
            .checked_add(TAG_BYTES)
            .ok_or(FormatError::TooLarge)?
            > MAX_RECORD_ENVELOPE_BYTES
        {
            return Err(FormatError::TooLarge);
        }
        Ok(bytes)
    }

    /// Parses and canonicalizes a website-account plaintext.
    ///
    /// # Errors
    ///
    /// Returns a bounded format error for malformed, unsupported, invalid, or
    /// noncanonical input.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes
            .len()
            .checked_add(TAG_BYTES)
            .ok_or(FormatError::TooLarge)?
            > MAX_RECORD_ENVELOPE_BYTES
        {
            return Err(FormatError::TooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        expect_array(&mut decoder, 6)?;
        expect_u32(&mut decoder, RECORD_SCHEMA)?;
        expect_u32(&mut decoder, WEBSITE_ACCOUNT_RECORD_TYPE)?;
        let revision = decode_u64(&mut decoder)?;
        let created_at_ms = decode_u64(&mut decoder)?;
        let modified_at_ms = decode_u64(&mut decoder)?;
        expect_array(&mut decoder, 4)?;
        let service_name =
            Zeroizing::new(decode_bounded_text(&mut decoder, MAX_SERVICE_NAME_BYTES)?);
        let permitted_origin = Zeroizing::new(decode_bounded_text(&mut decoder, MAX_ORIGIN_BYTES)?);
        let username = Zeroizing::new(decode_bounded_text(&mut decoder, MAX_USERNAME_BYTES)?);
        let password = Zeroizing::new(decode_bounded_text(&mut decoder, MAX_PASSWORD_BYTES)?);
        require_end(&decoder, bytes)?;
        let value = Self::new(
            revision,
            created_at_ms,
            modified_at_ms,
            service_name,
            permitted_origin,
            username,
            password,
        )?;
        if value.encode()?.as_slice() != bytes {
            return Err(FormatError::NonCanonical);
        }
        Ok(value)
    }
}

/// Canonical AEAD associated data for one encrypted record.
#[must_use]
pub fn encode_record_aad(vault_id: &[u8; 16], record_id: &[u8; 16], key_epoch: u32) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encode_array(&mut encoder, 6);
    encode_str(&mut encoder, RECORD_MAGIC);
    encode_u32(&mut encoder, CONTAINER_VERSION);
    encode_u32(&mut encoder, RECORD_ENVELOPE_VERSION);
    encode_bytes(&mut encoder, vault_id);
    encode_bytes(&mut encoder, record_id);
    encode_u32(&mut encoder, key_epoch);
    encoder.into_writer()
}

fn validate_plaintext(value: &WebsiteAccountPlaintext) -> Result<(), FormatError> {
    if value.revision == 0
        || value.modified_at_ms < value.created_at_ms
        || value.service_name.is_empty()
        || value.permitted_origin.is_empty()
    {
        return Err(FormatError::InvariantViolation);
    }
    if value.service_name.len() > MAX_SERVICE_NAME_BYTES
        || value.permitted_origin.len() > MAX_ORIGIN_BYTES
        || value.username.len() > MAX_USERNAME_BYTES
        || value.password.len() > MAX_PASSWORD_BYTES
    {
        return Err(FormatError::TooLarge);
    }
    if value.service_name.chars().any(char::is_control)
        || value.permitted_origin.chars().any(char::is_control)
    {
        return Err(FormatError::InvariantViolation);
    }
    Ok(())
}

fn encode_array(encoder: &mut Encoder<Vec<u8>>, length: u64) {
    encoder
        .array(length)
        .expect("encoding into a byte vector cannot fail");
}

fn encode_u32(encoder: &mut Encoder<Vec<u8>>, value: u32) {
    encoder
        .u32(value)
        .expect("encoding into a byte vector cannot fail");
}

fn encode_u64(encoder: &mut Encoder<Vec<u8>>, value: u64) {
    encoder
        .u64(value)
        .expect("encoding into a byte vector cannot fail");
}

fn encode_bytes(encoder: &mut Encoder<Vec<u8>>, value: &[u8]) {
    encoder
        .bytes(value)
        .expect("encoding into a byte vector cannot fail");
}

fn encode_str(encoder: &mut Encoder<Vec<u8>>, value: &str) {
    encoder
        .str(value)
        .expect("encoding into a byte vector cannot fail");
}

fn expect_array(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), FormatError> {
    let actual = decoder
        .array()
        .map_err(|_| FormatError::Malformed)?
        .ok_or(FormatError::Malformed)?;
    if actual != expected {
        return Err(FormatError::Malformed);
    }
    Ok(())
}

fn expect_u32(decoder: &mut Decoder<'_>, expected: u32) -> Result<(), FormatError> {
    let actual = decode_u32(decoder)?;
    if actual != expected {
        return Err(FormatError::Unsupported);
    }
    Ok(())
}

fn decode_u32(decoder: &mut Decoder<'_>) -> Result<u32, FormatError> {
    decoder.u32().map_err(|_| FormatError::Malformed)
}

fn decode_u64(decoder: &mut Decoder<'_>) -> Result<u64, FormatError> {
    decoder.u64().map_err(|_| FormatError::Malformed)
}

fn decode_fixed_bytes<const LENGTH: usize>(
    decoder: &mut Decoder<'_>,
) -> Result<[u8; LENGTH], FormatError> {
    decoder
        .bytes()
        .map_err(|_| FormatError::Malformed)?
        .try_into()
        .map_err(|_| FormatError::Malformed)
}

fn decode_bounded_bytes(decoder: &mut Decoder<'_>, maximum: usize) -> Result<Vec<u8>, FormatError> {
    let value = decoder.bytes().map_err(|_| FormatError::Malformed)?;
    if value.len() > maximum {
        return Err(FormatError::TooLarge);
    }
    Ok(value.to_vec())
}

fn decode_bounded_text(decoder: &mut Decoder<'_>, maximum: usize) -> Result<String, FormatError> {
    let value = decoder.str().map_err(|_| FormatError::Malformed)?;
    if value.len() > maximum {
        return Err(FormatError::TooLarge);
    }
    Ok(value.to_owned())
}

fn require_end(decoder: &Decoder<'_>, original: &[u8]) -> Result<(), FormatError> {
    if decoder.position() != original.len() {
        return Err(FormatError::Malformed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::{RecordEnvelope, WebsiteAccountPlaintext};
    use crate::FormatError;

    fn account() -> WebsiteAccountPlaintext {
        WebsiteAccountPlaintext::new(
            1,
            1_700_000_000_000,
            1_700_000_000_000,
            Zeroizing::new("Example".to_owned()),
            Zeroizing::new("https://example.com".to_owned()),
            Zeroizing::new("person@example.com".to_owned()),
            Zeroizing::new("disposable-password".to_owned()),
        )
        .expect("fixture must be valid")
    }

    #[test]
    fn record_envelope_round_trips_canonically() {
        let envelope =
            RecordEnvelope::new(1, [0x22; 24], vec![0x33; 32]).expect("fixture must be valid");
        let encoded = envelope.encode().expect("fixture must encode");
        assert!(RecordEnvelope::decode(&encoded).is_ok());

        let mut future = encoded;
        future[1] = 2;
        assert!(matches!(
            RecordEnvelope::decode(&future),
            Err(FormatError::Unsupported)
        ));
    }

    #[test]
    fn website_account_round_trips_canonically() {
        let plaintext = account().encode().expect("fixture must encode");
        let decoded =
            WebsiteAccountPlaintext::decode(&plaintext).expect("fixture must decode canonically");
        assert_eq!(decoded.revision(), 1);
        assert_eq!(decoded.permitted_origin(), "https://example.com");
        assert_eq!(decoded.username(), "person@example.com");
    }

    #[test]
    fn website_account_rejects_invalid_versions_and_trailing_bytes() {
        let encoded = account().encode().expect("fixture must encode");
        let mut future = encoded.to_vec();
        future[1] = 2;
        assert!(matches!(
            WebsiteAccountPlaintext::decode(&future),
            Err(FormatError::Unsupported)
        ));

        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(matches!(
            WebsiteAccountPlaintext::decode(&trailing),
            Err(FormatError::Malformed)
        ));
    }
}
