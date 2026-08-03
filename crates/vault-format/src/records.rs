use std::fmt;

use minicbor::{Decoder, Encoder, encode::Write};
use zeroize::Zeroizing;

use crate::{CONTAINER_VERSION, FormatError, MAX_RECORD_ENVELOPE_BYTES};

pub const RECORD_ENVELOPE_VERSION: u32 = 1;
pub const RECORD_SCHEMA: u32 = 1;
pub const WEBSITE_ACCOUNT_RECORD_TYPE: u32 = 1;
pub const PASSKEY_RECORD_TYPE: u32 = 2;

pub const MAX_SERVICE_NAME_BYTES: usize = 256;
pub const MAX_ORIGIN_BYTES: usize = 2_048;
pub const MAX_USERNAME_BYTES: usize = 1_024;
pub const MAX_PASSWORD_BYTES: usize = 16 * 1_024;
pub const MAX_PASSKEY_RP_ID_BYTES: usize = 253;
pub const MAX_PASSKEY_USER_HANDLE_BYTES: usize = 64;
pub const MAX_PASSKEY_USER_NAME_BYTES: usize = 256;
pub const MAX_PASSKEY_USER_DISPLAY_NAME_BYTES: usize = 256;
pub const PASSKEY_CREDENTIAL_ID_BYTES: usize = 32;
pub const PASSKEY_PRIVATE_KEY_BYTES: usize = 32;

const RECORD_MAGIC: &str = "LBR-REC";
const TAG_BYTES: usize = 16;
const WEBSITE_ACCOUNT_ENCODING_OVERHEAD_BYTES: usize = 128;
const PASSKEY_ENCODING_OVERHEAD_BYTES: usize = 192;

/// Supported encrypted-record plaintext families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordType {
    WebsiteAccount,
    Passkey,
}

/// Durable publication state for one vault-backed passkey.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum PasskeyCreationState {
    Pending = 1,
    Confirmed = 2,
}

impl PasskeyCreationState {
    const fn code(self) -> u32 {
        self as u32
    }

    fn from_code(value: u32) -> Result<Self, FormatError> {
        match value {
            1 => Ok(Self::Pending),
            2 => Ok(Self::Confirmed),
            _ => Err(FormatError::Unsupported),
        }
    }
}

struct SecretWriter {
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretWriter {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(capacity)),
        }
    }

    fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

#[derive(Debug)]
struct SecretWriterOverflow;

impl Write for SecretWriter {
    type Error = SecretWriterOverflow;

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let required = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(SecretWriterOverflow)?;
        if required > self.bytes.capacity() {
            return Err(SecretWriterOverflow);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

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
        let capacity = self
            .service_name
            .len()
            .checked_add(self.permitted_origin.len())
            .and_then(|value| value.checked_add(self.username.len()))
            .and_then(|value| value.checked_add(self.password.len()))
            .and_then(|value| value.checked_add(WEBSITE_ACCOUNT_ENCODING_OVERHEAD_BYTES))
            .ok_or(FormatError::TooLarge)?;
        let mut encoder = Encoder::new(SecretWriter::with_capacity(capacity));
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
        let bytes = encoder.into_writer().into_bytes();
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

/// Canonical plaintext for one discoverable ES256 passkey.
///
/// The credential private scalar and user metadata are zeroized on drop. The
/// private scalar is deliberately stored only inside the encrypted record and
/// this type intentionally provides no formatting, cloning, or serialization
/// traits beyond its bounded canonical encoder.
pub struct PasskeyPlaintext {
    revision: u64,
    created_at_ms: u64,
    modified_at_ms: u64,
    signature_counter: u32,
    creation_state: PasskeyCreationState,
    rp_id: Zeroizing<String>,
    user_handle: Zeroizing<Vec<u8>>,
    user_name: Zeroizing<String>,
    user_display_name: Zeroizing<String>,
    credential_id: [u8; PASSKEY_CREDENTIAL_ID_BYTES],
    private_key: Zeroizing<[u8; PASSKEY_PRIVATE_KEY_BYTES]>,
}

/// Secret-bearing fields moved out of one decoded passkey record.
pub type PasskeyPlaintextFields = (
    Zeroizing<String>,
    Zeroizing<Vec<u8>>,
    Zeroizing<String>,
    Zeroizing<String>,
    [u8; PASSKEY_CREDENTIAL_ID_BYTES],
    Zeroizing<[u8; PASSKEY_PRIVATE_KEY_BYTES]>,
);

impl PasskeyPlaintext {
    /// Constructs one bounded passkey plaintext.
    ///
    /// # Errors
    ///
    /// Rejects invalid version metadata, empty required fields, zero
    /// identifiers or private material, and fields outside the `WebAuthn` bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        revision: u64,
        created_at_ms: u64,
        modified_at_ms: u64,
        signature_counter: u32,
        creation_state: PasskeyCreationState,
        rp_id: Zeroizing<String>,
        user_handle: Zeroizing<Vec<u8>>,
        user_name: Zeroizing<String>,
        user_display_name: Zeroizing<String>,
        credential_id: [u8; PASSKEY_CREDENTIAL_ID_BYTES],
        private_key: Zeroizing<[u8; PASSKEY_PRIVATE_KEY_BYTES]>,
    ) -> Result<Self, FormatError> {
        let value = Self {
            revision,
            created_at_ms,
            modified_at_ms,
            signature_counter,
            creation_state,
            rp_id,
            user_handle,
            user_name,
            user_display_name,
            credential_id,
            private_key,
        };
        validate_passkey_plaintext(&value)?;
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
    pub const fn signature_counter(&self) -> u32 {
        self.signature_counter
    }

    #[must_use]
    pub const fn creation_state(&self) -> PasskeyCreationState {
        self.creation_state
    }

    #[must_use]
    pub fn rp_id(&self) -> &str {
        self.rp_id.as_str()
    }

    #[must_use]
    pub fn user_handle(&self) -> &[u8] {
        self.user_handle.as_slice()
    }

    #[must_use]
    pub fn user_name(&self) -> &str {
        self.user_name.as_str()
    }

    #[must_use]
    pub fn user_display_name(&self) -> &str {
        self.user_display_name.as_str()
    }

    #[must_use]
    pub const fn credential_id(&self) -> &[u8; PASSKEY_CREDENTIAL_ID_BYTES] {
        &self.credential_id
    }

    #[must_use]
    pub fn private_key(&self) -> &[u8; PASSKEY_PRIVATE_KEY_BYTES] {
        &self.private_key
    }

    /// Moves secret-bearing fields out of this format value.
    #[must_use]
    pub fn into_fields(self) -> PasskeyPlaintextFields {
        (
            self.rp_id,
            self.user_handle,
            self.user_name,
            self.user_display_name,
            self.credential_id,
            self.private_key,
        )
    }

    /// Encodes the plaintext using the fixed version-1 passkey schema.
    ///
    /// # Errors
    ///
    /// Returns an invariant or size error when the value is not representable.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, FormatError> {
        validate_passkey_plaintext(self)?;
        let capacity = self
            .rp_id
            .len()
            .checked_add(self.user_handle.len())
            .and_then(|value| value.checked_add(self.user_name.len()))
            .and_then(|value| value.checked_add(self.user_display_name.len()))
            .and_then(|value| value.checked_add(PASSKEY_ENCODING_OVERHEAD_BYTES))
            .ok_or(FormatError::TooLarge)?;
        let mut encoder = Encoder::new(SecretWriter::with_capacity(capacity));
        encode_array(&mut encoder, 6);
        encode_u32(&mut encoder, RECORD_SCHEMA);
        encode_u32(&mut encoder, PASSKEY_RECORD_TYPE);
        encode_u64(&mut encoder, self.revision);
        encode_u64(&mut encoder, self.created_at_ms);
        encode_u64(&mut encoder, self.modified_at_ms);
        encode_array(&mut encoder, 8);
        encode_u32(&mut encoder, self.signature_counter);
        encode_u32(&mut encoder, self.creation_state.code());
        encode_str(&mut encoder, &self.rp_id);
        encode_bytes(&mut encoder, &self.user_handle);
        encode_str(&mut encoder, &self.user_name);
        encode_str(&mut encoder, &self.user_display_name);
        encode_bytes(&mut encoder, &self.credential_id);
        encode_bytes(&mut encoder, &*self.private_key);
        let bytes = encoder.into_writer().into_bytes();
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

    /// Parses and canonicalizes a passkey plaintext.
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
        expect_u32(&mut decoder, PASSKEY_RECORD_TYPE)?;
        let revision = decode_u64(&mut decoder)?;
        let created_at_ms = decode_u64(&mut decoder)?;
        let modified_at_ms = decode_u64(&mut decoder)?;
        expect_array(&mut decoder, 8)?;
        let signature_counter = decode_u32(&mut decoder)?;
        let creation_state = PasskeyCreationState::from_code(decode_u32(&mut decoder)?)?;
        let rp_id = Zeroizing::new(decode_bounded_text(&mut decoder, MAX_PASSKEY_RP_ID_BYTES)?);
        let user_handle = Zeroizing::new(decode_bounded_bytes(
            &mut decoder,
            MAX_PASSKEY_USER_HANDLE_BYTES,
        )?);
        let user_name = Zeroizing::new(decode_bounded_text(
            &mut decoder,
            MAX_PASSKEY_USER_NAME_BYTES,
        )?);
        let user_display_name = Zeroizing::new(decode_bounded_text(
            &mut decoder,
            MAX_PASSKEY_USER_DISPLAY_NAME_BYTES,
        )?);
        let credential_id = decode_fixed_bytes(&mut decoder)?;
        let private_key = decode_zeroizing_fixed_bytes(&mut decoder)?;
        require_end(&decoder, bytes)?;
        let value = Self::new(
            revision,
            created_at_ms,
            modified_at_ms,
            signature_counter,
            creation_state,
            rp_id,
            user_handle,
            user_name,
            user_display_name,
            credential_id,
            private_key,
        )?;
        if value.encode()?.as_slice() != bytes {
            return Err(FormatError::NonCanonical);
        }
        Ok(value)
    }
}

/// Reads the authenticated plaintext discriminator before type-specific decode.
///
/// # Errors
///
/// Rejects malformed, unsupported, or oversized plaintext prefixes.
pub fn record_type(bytes: &[u8]) -> Result<RecordType, FormatError> {
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
    match decode_u32(&mut decoder)? {
        WEBSITE_ACCOUNT_RECORD_TYPE => Ok(RecordType::WebsiteAccount),
        PASSKEY_RECORD_TYPE => Ok(RecordType::Passkey),
        _ => Err(FormatError::Unsupported),
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

fn validate_passkey_plaintext(value: &PasskeyPlaintext) -> Result<(), FormatError> {
    if value.revision == 0
        || value.modified_at_ms < value.created_at_ms
        || value.rp_id.is_empty()
        || value.user_handle.is_empty()
        || value.user_name.is_empty()
        || value.user_display_name.is_empty()
        || value.credential_id.iter().all(|byte| *byte == 0)
        || value.private_key.iter().all(|byte| *byte == 0)
    {
        return Err(FormatError::InvariantViolation);
    }
    if value.rp_id.len() > MAX_PASSKEY_RP_ID_BYTES
        || value.user_handle.len() > MAX_PASSKEY_USER_HANDLE_BYTES
        || value.user_name.len() > MAX_PASSKEY_USER_NAME_BYTES
        || value.user_display_name.len() > MAX_PASSKEY_USER_DISPLAY_NAME_BYTES
    {
        return Err(FormatError::TooLarge);
    }
    if value.rp_id.chars().any(char::is_control)
        || value.user_name.chars().any(char::is_control)
        || value.user_display_name.chars().any(char::is_control)
    {
        return Err(FormatError::InvariantViolation);
    }
    Ok(())
}

fn encode_array<W>(encoder: &mut Encoder<W>, length: u64)
where
    W: Write,
    W::Error: fmt::Debug,
{
    encoder
        .array(length)
        .expect("encoding into a byte vector cannot fail");
}

fn encode_u32<W>(encoder: &mut Encoder<W>, value: u32)
where
    W: Write,
    W::Error: fmt::Debug,
{
    encoder
        .u32(value)
        .expect("encoding into a byte vector cannot fail");
}

fn encode_u64<W>(encoder: &mut Encoder<W>, value: u64)
where
    W: Write,
    W::Error: fmt::Debug,
{
    encoder
        .u64(value)
        .expect("encoding into a byte vector cannot fail");
}

fn encode_bytes<W>(encoder: &mut Encoder<W>, value: &[u8])
where
    W: Write,
    W::Error: fmt::Debug,
{
    encoder
        .bytes(value)
        .expect("encoding into a byte vector cannot fail");
}

fn encode_str<W>(encoder: &mut Encoder<W>, value: &str)
where
    W: Write,
    W::Error: fmt::Debug,
{
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

fn decode_zeroizing_fixed_bytes<const LENGTH: usize>(
    decoder: &mut Decoder<'_>,
) -> Result<Zeroizing<[u8; LENGTH]>, FormatError> {
    let value = decoder.bytes().map_err(|_| FormatError::Malformed)?;
    if value.len() != LENGTH {
        return Err(FormatError::Malformed);
    }
    let mut output = Zeroizing::new([0_u8; LENGTH]);
    output.copy_from_slice(value);
    Ok(output)
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

    use super::{
        PasskeyCreationState, PasskeyPlaintext, RecordEnvelope, RecordType,
        WebsiteAccountPlaintext, record_type,
    };
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

    fn passkey() -> PasskeyPlaintext {
        PasskeyPlaintext::new(
            1,
            1_700_000_000_000,
            1_700_000_000_000,
            0,
            PasskeyCreationState::Confirmed,
            Zeroizing::new("example.com".to_owned()),
            Zeroizing::new(vec![0x21; 32]),
            Zeroizing::new("person@example.com".to_owned()),
            Zeroizing::new("Disposable Person".to_owned()),
            [0x31; 32],
            Zeroizing::new([0x41; 32]),
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
    fn passkey_round_trips_without_exposing_private_material() {
        let plaintext = passkey().encode().expect("fixture must encode");
        assert_eq!(record_type(&plaintext), Ok(RecordType::Passkey));
        let decoded = PasskeyPlaintext::decode(&plaintext).expect("canonical passkey");
        assert_eq!(decoded.rp_id(), "example.com");
        assert_eq!(decoded.user_handle(), &[0x21; 32]);
        assert_eq!(decoded.credential_id(), &[0x31; 32]);
        assert_eq!(decoded.signature_counter(), 0);
        assert_eq!(decoded.creation_state(), PasskeyCreationState::Confirmed);
    }

    #[test]
    fn passkey_rejects_zero_private_material_and_trailing_bytes() {
        assert!(matches!(
            PasskeyPlaintext::new(
                1,
                1,
                1,
                0,
                PasskeyCreationState::Confirmed,
                Zeroizing::new("example.com".to_owned()),
                Zeroizing::new(vec![1]),
                Zeroizing::new("user".to_owned()),
                Zeroizing::new("User".to_owned()),
                [2; 32],
                Zeroizing::new([0; 32]),
            ),
            Err(FormatError::InvariantViolation)
        ));

        let mut trailing = passkey().encode().expect("fixture must encode").to_vec();
        trailing.push(0);
        assert!(matches!(
            PasskeyPlaintext::decode(&trailing),
            Err(FormatError::Malformed)
        ));
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
