//! Canonical, bounded wire types for the Librarian vault format.
//!
//! This crate owns bytes, not cryptography or storage. It deliberately keeps
//! the production-readiness gate disabled until the independent review
//! required by ADR 0005 is recorded.

#![forbid(unsafe_code)]

use std::fmt;

use minicbor::{Decoder, Encoder};

mod records;

pub use records::{
    MAX_ORIGIN_BYTES, MAX_PASSWORD_BYTES, MAX_SERVICE_NAME_BYTES, MAX_USERNAME_BYTES,
    RECORD_ENVELOPE_VERSION, RECORD_SCHEMA, RecordEnvelope, WEBSITE_ACCOUNT_RECORD_TYPE,
    WebsiteAccountPlaintext, encode_record_aad,
};

pub const CONTAINER_VERSION: u32 = 1;
pub const MINIMUM_READER_VERSION: u32 = 1;
pub const KEY_SCHEDULE: u32 = 1;
pub const AEAD_SUITE: u32 = 1;
pub const ENCODING: u32 = 1;
pub const DIGEST_SUITE: u32 = 1;
pub const KDF_SUITE: u32 = 1;
pub const ARGON2_VERSION: u32 = 0x13;
pub const ARGON2_MEMORY_KIB: u32 = 65_536;
pub const ARGON2_TIME_COST: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 4;
pub const RECOVERY_WRAPPER_VERSION: u32 = 1;
pub const MANIFEST_ENVELOPE_VERSION: u32 = 1;
pub const MANIFEST_SCHEMA: u32 = 1;
pub const VAULT_SCHEMA: u32 = 1;

pub const MAX_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_MANIFEST_ENVELOPE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RECORDS: usize = 100_000;
pub const MAX_RECORD_ENVELOPE_BYTES: usize = 1024 * 1024;
pub const MAX_DATABASE_BYTES: u64 = 512 * 1024 * 1024;

const VAULT_MAGIC: &str = "LBR-VLT";
const MASTER_WRAPPER_TYPE: u32 = 1;
const RECOVERY_WRAPPER_TYPE: u32 = 2;
const TAG_BYTES: usize = 16;

/// Security maturity of the vault format in this repository revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatReadiness {
    /// Format work is testable, but production credential storage is disabled.
    ScaffoldOnly,
}

/// Returns the only valid state until ADR 0005's independent review completes.
#[must_use]
pub const fn readiness() -> FormatReadiness {
    FormatReadiness::ScaffoldOnly
}

/// A non-secret failure while parsing or encoding the wire format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatError {
    TooLarge,
    Malformed,
    Unsupported,
    NonCanonical,
    InvariantViolation,
}

impl fmt::Display for FormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLarge => "vault structure exceeds a format limit",
            Self::Malformed => "vault structure is malformed",
            Self::Unsupported => "vault format version is unsupported",
            Self::NonCanonical => "vault structure is not canonical",
            Self::InvariantViolation => "vault structure violates an invariant",
        })
    }
}

impl std::error::Error for FormatError {}

/// The password-derived wrapper stored in the clear vault header.
#[derive(Clone, Eq, PartialEq)]
pub struct MasterWrapper {
    password_salt: [u8; 16],
    nonce: [u8; 24],
    wrapped_vrk: [u8; 48],
}

impl MasterWrapper {
    #[must_use]
    pub const fn new(password_salt: [u8; 16], nonce: [u8; 24], wrapped_vrk: [u8; 48]) -> Self {
        Self {
            password_salt,
            nonce,
            wrapped_vrk,
        }
    }

    #[must_use]
    pub const fn password_salt(&self) -> &[u8; 16] {
        &self.password_salt
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }

    #[must_use]
    pub const fn wrapped_vrk(&self) -> &[u8; 48] {
        &self.wrapped_vrk
    }
}

/// The recovery-key wrapper stored in the clear vault header.
#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryWrapper {
    nonce: [u8; 24],
    wrapped_vrk: [u8; 48],
}

impl RecoveryWrapper {
    #[must_use]
    pub const fn new(nonce: [u8; 24], wrapped_vrk: [u8; 48]) -> Self {
        Self { nonce, wrapped_vrk }
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }

    #[must_use]
    pub const fn wrapped_vrk(&self) -> &[u8; 48] {
        &self.wrapped_vrk
    }
}

/// The complete clear singleton header from ADR 0005.
#[derive(Clone, Eq, PartialEq)]
pub struct VaultHeader {
    vault_id: [u8; 16],
    key_epoch: u32,
    master_wrapper: MasterWrapper,
    recovery_wrapper: RecoveryWrapper,
}

impl VaultHeader {
    #[must_use]
    pub const fn new(
        vault_id: [u8; 16],
        key_epoch: u32,
        master_wrapper: MasterWrapper,
        recovery_wrapper: RecoveryWrapper,
    ) -> Self {
        Self {
            vault_id,
            key_epoch,
            master_wrapper,
            recovery_wrapper,
        }
    }

    #[must_use]
    pub const fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }

    #[must_use]
    pub const fn key_epoch(&self) -> u32 {
        self.key_epoch
    }

    #[must_use]
    pub const fn master_wrapper(&self) -> &MasterWrapper {
        &self.master_wrapper
    }

    #[must_use]
    pub const fn recovery_wrapper(&self) -> &RecoveryWrapper {
        &self.recovery_wrapper
    }

    /// Encodes this value using ADR 0005's deterministic CBOR profile.
    ///
    /// # Errors
    ///
    /// Returns an invariant or size error if this value cannot be represented
    /// as a valid version-1 header.
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        if self.key_epoch == 0 {
            return Err(FormatError::InvariantViolation);
        }

        let mut encoder = Encoder::new(Vec::new());
        encode_header_into(&mut encoder, self);
        let bytes = encoder.into_writer();
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(FormatError::TooLarge);
        }
        Ok(bytes)
    }

    /// Parses, validates, and byte-for-byte canonicalizes a clear header.
    ///
    /// # Errors
    ///
    /// Returns a bounded format error for oversized, malformed, unsupported,
    /// noncanonical, or internally inconsistent input.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(FormatError::TooLarge);
        }

        let mut decoder = Decoder::new(bytes);
        let header = decode_header_from(&mut decoder)?;
        require_end(&decoder, bytes)?;
        if header.encode()?.as_slice() != bytes {
            return Err(FormatError::NonCanonical);
        }
        Ok(header)
    }
}

/// One active-record commitment in the encrypted manifest.
#[derive(Clone, Eq, PartialEq)]
pub struct ManifestEntry {
    record_id: [u8; 16],
    envelope_digest: [u8; 32],
}

impl ManifestEntry {
    #[must_use]
    pub const fn new(record_id: [u8; 16], envelope_digest: [u8; 32]) -> Self {
        Self {
            record_id,
            envelope_digest,
        }
    }

    #[must_use]
    pub const fn record_id(&self) -> &[u8; 16] {
        &self.record_id
    }

    #[must_use]
    pub const fn envelope_digest(&self) -> &[u8; 32] {
        &self.envelope_digest
    }
}

/// The authenticated active-record manifest plaintext.
#[derive(Clone, Eq, PartialEq)]
pub struct Manifest {
    generation: u64,
    key_epoch: u32,
    vault_schema: u32,
    created_at_ms: u64,
    committed_at_ms: u64,
    entries: Vec<ManifestEntry>,
}

impl Manifest {
    #[must_use]
    pub const fn empty(created_at_ms: u64, key_epoch: u32) -> Self {
        Self {
            generation: 0,
            key_epoch,
            vault_schema: VAULT_SCHEMA,
            created_at_ms,
            committed_at_ms: created_at_ms,
            entries: Vec::new(),
        }
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn key_epoch(&self) -> u32 {
        self.key_epoch
    }

    #[must_use]
    pub const fn vault_schema(&self) -> u32 {
        self.vault_schema
    }

    #[must_use]
    pub const fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    #[must_use]
    pub const fn committed_at_ms(&self) -> u64 {
        self.committed_at_ms
    }

    #[must_use]
    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    /// Builds the next committed manifest without mutating the authenticated
    /// current generation.
    ///
    /// # Errors
    ///
    /// Returns an error if the generation overflows, time moves backwards, or
    /// the proposed active-record commitments violate the format invariants.
    pub fn next_generation(
        &self,
        committed_at_ms: u64,
        entries: Vec<ManifestEntry>,
    ) -> Result<Self, FormatError> {
        if committed_at_ms < self.committed_at_ms {
            return Err(FormatError::InvariantViolation);
        }
        let next = Self {
            generation: self
                .generation
                .checked_add(1)
                .ok_or(FormatError::InvariantViolation)?,
            key_epoch: self.key_epoch,
            vault_schema: self.vault_schema,
            created_at_ms: self.created_at_ms,
            committed_at_ms,
            entries,
        };
        validate_manifest(&next)?;
        Ok(next)
    }

    /// Encodes the manifest using the deterministic version-1 schema.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest is oversized, unsorted, duplicated, or
    /// incompatible with the version-1 schema.
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        validate_manifest(self)?;

        let mut encoder = Encoder::new(Vec::new());
        encode_array(&mut encoder, 7);
        encode_u32(&mut encoder, MANIFEST_SCHEMA);
        encode_u64(&mut encoder, self.generation);
        encode_u32(&mut encoder, self.key_epoch);
        encode_u32(&mut encoder, self.vault_schema);
        encode_u64(&mut encoder, self.created_at_ms);
        encode_u64(&mut encoder, self.committed_at_ms);
        encode_array(
            &mut encoder,
            u64::try_from(self.entries.len()).map_err(|_| FormatError::TooLarge)?,
        );
        for entry in &self.entries {
            encode_array(&mut encoder, 2);
            encode_bytes(&mut encoder, &entry.record_id);
            encode_bytes(&mut encoder, &entry.envelope_digest);
        }

        let bytes = encoder.into_writer();
        if bytes
            .len()
            .checked_add(TAG_BYTES)
            .ok_or(FormatError::TooLarge)?
            > MAX_MANIFEST_ENVELOPE_BYTES
        {
            return Err(FormatError::TooLarge);
        }
        Ok(bytes)
    }

    /// Parses and canonicalizes a version-1 manifest plaintext.
    ///
    /// # Errors
    ///
    /// Returns a bounded format error for oversized, malformed, unsupported,
    /// noncanonical, unsorted, or duplicated input.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes
            .len()
            .checked_add(TAG_BYTES)
            .ok_or(FormatError::TooLarge)?
            > MAX_MANIFEST_ENVELOPE_BYTES
        {
            return Err(FormatError::TooLarge);
        }

        let mut decoder = Decoder::new(bytes);
        expect_array(&mut decoder, 7)?;
        expect_u32(&mut decoder, MANIFEST_SCHEMA)?;
        let generation = decode_u64(&mut decoder)?;
        let key_epoch = decode_u32(&mut decoder)?;
        let vault_schema = decode_u32(&mut decoder)?;
        let created_at_ms = decode_u64(&mut decoder)?;
        let committed_at_ms = decode_u64(&mut decoder)?;
        let entry_count = decode_array_len(&mut decoder)?;
        if entry_count > MAX_RECORDS {
            return Err(FormatError::TooLarge);
        }
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            expect_array(&mut decoder, 2)?;
            entries.push(ManifestEntry::new(
                decode_fixed_bytes(&mut decoder)?,
                decode_fixed_bytes(&mut decoder)?,
            ));
        }
        require_end(&decoder, bytes)?;

        let manifest = Self {
            generation,
            key_epoch,
            vault_schema,
            created_at_ms,
            committed_at_ms,
            entries,
        };
        validate_manifest(&manifest)?;
        if manifest.encode()?.as_slice() != bytes {
            return Err(FormatError::NonCanonical);
        }
        Ok(manifest)
    }
}

/// The separately stored encrypted manifest envelope.
#[derive(Clone, Eq, PartialEq)]
pub struct ManifestEnvelope {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

impl ManifestEnvelope {
    /// Constructs a bounded encrypted-manifest envelope.
    ///
    /// # Errors
    ///
    /// Returns an error when the ciphertext cannot contain an authentication
    /// tag or when the encoded envelope exceeds its version-1 bound.
    pub fn new(nonce: [u8; 24], ciphertext: Vec<u8>) -> Result<Self, FormatError> {
        if ciphertext.len() < TAG_BYTES {
            return Err(FormatError::Malformed);
        }
        let envelope = Self { nonce, ciphertext };
        if envelope.encode()?.len() > MAX_MANIFEST_ENVELOPE_BYTES {
            return Err(FormatError::TooLarge);
        }
        Ok(envelope)
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }

    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Encodes this envelope using deterministic CBOR.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing authentication tag or an oversized
    /// envelope.
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        if self.ciphertext.len() < TAG_BYTES {
            return Err(FormatError::Malformed);
        }
        let mut encoder = Encoder::new(Vec::new());
        encode_array(&mut encoder, 3);
        encode_u32(&mut encoder, MANIFEST_ENVELOPE_VERSION);
        encode_bytes(&mut encoder, &self.nonce);
        encode_bytes(&mut encoder, &self.ciphertext);
        let bytes = encoder.into_writer();
        if bytes.len() > MAX_MANIFEST_ENVELOPE_BYTES {
            return Err(FormatError::TooLarge);
        }
        Ok(bytes)
    }

    /// Parses and canonicalizes an encrypted-manifest envelope.
    ///
    /// # Errors
    ///
    /// Returns a bounded format error for oversized, malformed, unsupported,
    /// or noncanonical input.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() > MAX_MANIFEST_ENVELOPE_BYTES {
            return Err(FormatError::TooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        expect_array(&mut decoder, 3)?;
        expect_u32(&mut decoder, MANIFEST_ENVELOPE_VERSION)?;
        let nonce = decode_fixed_bytes(&mut decoder)?;
        let ciphertext = decode_bounded_bytes(&mut decoder, MAX_MANIFEST_ENVELOPE_BYTES)?;
        require_end(&decoder, bytes)?;

        let envelope = Self::new(nonce, ciphertext)?;
        if envelope.encode()?.as_slice() != bytes {
            return Err(FormatError::NonCanonical);
        }
        Ok(envelope)
    }
}

/// Canonical associated data for the password-derived VRK wrapper.
#[must_use]
pub fn encode_master_wrapper_aad(vault_id: &[u8; 16], key_epoch: u32, salt: &[u8; 16]) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encode_array(&mut encoder, 17);
    encode_str(&mut encoder, VAULT_MAGIC);
    encode_u32(&mut encoder, CONTAINER_VERSION);
    encode_u32(&mut encoder, MINIMUM_READER_VERSION);
    encode_u32(&mut encoder, KEY_SCHEDULE);
    encode_u32(&mut encoder, AEAD_SUITE);
    encode_u32(&mut encoder, ENCODING);
    encode_u32(&mut encoder, DIGEST_SUITE);
    encode_bytes(&mut encoder, vault_id);
    encode_u32(&mut encoder, key_epoch);
    encode_u32(&mut encoder, MASTER_WRAPPER_TYPE);
    encode_u32(&mut encoder, 1);
    encode_u32(&mut encoder, KDF_SUITE);
    encode_u32(&mut encoder, ARGON2_VERSION);
    encode_u32(&mut encoder, ARGON2_MEMORY_KIB);
    encode_u32(&mut encoder, ARGON2_TIME_COST);
    encode_u32(&mut encoder, ARGON2_PARALLELISM);
    encode_bytes(&mut encoder, salt);
    encoder.into_writer()
}

/// Canonical associated data for the recovery-key VRK wrapper.
#[must_use]
pub fn encode_recovery_wrapper_aad(vault_id: &[u8; 16], key_epoch: u32) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encode_array(&mut encoder, 11);
    encode_str(&mut encoder, VAULT_MAGIC);
    encode_u32(&mut encoder, CONTAINER_VERSION);
    encode_u32(&mut encoder, MINIMUM_READER_VERSION);
    encode_u32(&mut encoder, KEY_SCHEDULE);
    encode_u32(&mut encoder, AEAD_SUITE);
    encode_u32(&mut encoder, ENCODING);
    encode_u32(&mut encoder, DIGEST_SUITE);
    encode_bytes(&mut encoder, vault_id);
    encode_u32(&mut encoder, key_epoch);
    encode_u32(&mut encoder, RECOVERY_WRAPPER_TYPE);
    encode_u32(&mut encoder, RECOVERY_WRAPPER_VERSION);
    encoder.into_writer()
}

/// Canonical associated data binding the manifest to the complete clear header.
#[must_use]
pub fn encode_manifest_aad(header: &VaultHeader, nonce: &[u8; 24]) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encode_array(&mut encoder, 3);
    encode_header_into(&mut encoder, header);
    encode_u32(&mut encoder, MANIFEST_ENVELOPE_VERSION);
    encode_bytes(&mut encoder, nonce);
    encoder.into_writer()
}

fn validate_manifest(manifest: &Manifest) -> Result<(), FormatError> {
    if manifest.key_epoch == 0 || manifest.vault_schema != VAULT_SCHEMA {
        return Err(FormatError::Unsupported);
    }
    if manifest.committed_at_ms < manifest.created_at_ms {
        return Err(FormatError::InvariantViolation);
    }
    if manifest.entries.len() > MAX_RECORDS {
        return Err(FormatError::TooLarge);
    }
    if manifest
        .entries
        .windows(2)
        .any(|pair| pair[0].record_id >= pair[1].record_id)
    {
        return Err(FormatError::InvariantViolation);
    }
    Ok(())
}

fn encode_header_into(encoder: &mut Encoder<Vec<u8>>, header: &VaultHeader) {
    encode_array(encoder, 11);
    encode_str(encoder, VAULT_MAGIC);
    encode_u32(encoder, CONTAINER_VERSION);
    encode_u32(encoder, MINIMUM_READER_VERSION);
    encode_u32(encoder, KEY_SCHEDULE);
    encode_u32(encoder, AEAD_SUITE);
    encode_u32(encoder, ENCODING);
    encode_u32(encoder, DIGEST_SUITE);
    encode_bytes(encoder, &header.vault_id);
    encode_u32(encoder, header.key_epoch);

    encode_array(encoder, 8);
    encode_u32(encoder, KDF_SUITE);
    encode_u32(encoder, ARGON2_VERSION);
    encode_u32(encoder, ARGON2_MEMORY_KIB);
    encode_u32(encoder, ARGON2_TIME_COST);
    encode_u32(encoder, ARGON2_PARALLELISM);
    encode_bytes(encoder, &header.master_wrapper.password_salt);
    encode_bytes(encoder, &header.master_wrapper.nonce);
    encode_bytes(encoder, &header.master_wrapper.wrapped_vrk);

    encode_array(encoder, 3);
    encode_u32(encoder, RECOVERY_WRAPPER_VERSION);
    encode_bytes(encoder, &header.recovery_wrapper.nonce);
    encode_bytes(encoder, &header.recovery_wrapper.wrapped_vrk);
}

fn decode_header_from(decoder: &mut Decoder<'_>) -> Result<VaultHeader, FormatError> {
    expect_array(decoder, 11)?;
    if decode_str(decoder)? != VAULT_MAGIC {
        return Err(FormatError::Malformed);
    }
    expect_u32(decoder, CONTAINER_VERSION)?;
    expect_u32(decoder, MINIMUM_READER_VERSION)?;
    expect_u32(decoder, KEY_SCHEDULE)?;
    expect_u32(decoder, AEAD_SUITE)?;
    expect_u32(decoder, ENCODING)?;
    expect_u32(decoder, DIGEST_SUITE)?;
    let vault_id = decode_fixed_bytes(decoder)?;
    let key_epoch = decode_u32(decoder)?;
    if key_epoch == 0 {
        return Err(FormatError::Malformed);
    }

    expect_array(decoder, 8)?;
    expect_u32(decoder, KDF_SUITE)?;
    expect_u32(decoder, ARGON2_VERSION)?;
    expect_u32(decoder, ARGON2_MEMORY_KIB)?;
    expect_u32(decoder, ARGON2_TIME_COST)?;
    expect_u32(decoder, ARGON2_PARALLELISM)?;
    let password_salt = decode_fixed_bytes(decoder)?;
    let master_nonce = decode_fixed_bytes(decoder)?;
    let master_wrapped_vrk = decode_fixed_bytes(decoder)?;

    expect_array(decoder, 3)?;
    expect_u32(decoder, RECOVERY_WRAPPER_VERSION)?;
    let recovery_nonce = decode_fixed_bytes(decoder)?;
    let recovery_wrapped_vrk = decode_fixed_bytes(decoder)?;

    Ok(VaultHeader::new(
        vault_id,
        key_epoch,
        MasterWrapper::new(password_salt, master_nonce, master_wrapped_vrk),
        RecoveryWrapper::new(recovery_nonce, recovery_wrapped_vrk),
    ))
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

fn encode_bytes(encoder: &mut Encoder<Vec<u8>>, bytes: &[u8]) {
    encoder
        .bytes(bytes)
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

fn decode_array_len(decoder: &mut Decoder<'_>) -> Result<usize, FormatError> {
    let length = decoder
        .array()
        .map_err(|_| FormatError::Malformed)?
        .ok_or(FormatError::Malformed)?;
    usize::try_from(length).map_err(|_| FormatError::TooLarge)
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

fn decode_str<'bytes>(decoder: &mut Decoder<'bytes>) -> Result<&'bytes str, FormatError> {
    decoder.str().map_err(|_| FormatError::Malformed)
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

fn require_end(decoder: &Decoder<'_>, original: &[u8]) -> Result<(), FormatError> {
    if decoder.position() != original.len() {
        return Err(FormatError::Malformed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        FormatError, FormatReadiness, Manifest, ManifestEntry, ManifestEnvelope, MasterWrapper,
        RecoveryWrapper, VaultHeader, readiness,
    };

    fn example_header() -> VaultHeader {
        VaultHeader::new(
            [0x11; 16],
            1,
            MasterWrapper::new([0x22; 16], [0x33; 24], [0x44; 48]),
            RecoveryWrapper::new([0x55; 24], [0x66; 48]),
        )
    }

    #[test]
    fn production_readiness_remains_disabled() {
        assert_eq!(readiness(), FormatReadiness::ScaffoldOnly);
    }

    #[test]
    fn header_round_trips_canonically() {
        let header = example_header();
        let encoded = header.encode().expect("example header must encode");
        let decoded = VaultHeader::decode(&encoded).expect("canonical header must decode");
        assert!(decoded == header);
        assert_eq!(
            encoded,
            decoded.encode().expect("decoded header must re-encode")
        );
    }

    #[test]
    fn header_rejects_trailing_and_noncanonical_bytes() {
        let encoded = example_header().encode().expect("example must encode");
        for truncated_length in 0..encoded.len() {
            assert!(VaultHeader::decode(&encoded[..truncated_length]).is_err());
        }

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            VaultHeader::decode(&trailing),
            Err(FormatError::Malformed)
        ));

        let mut noncanonical = example_header().encode().expect("example must encode");
        let version_offset = 9;
        assert_eq!(noncanonical[version_offset], 1);
        noncanonical.splice(version_offset..=version_offset, [0x18, 0x01]);
        assert!(matches!(
            VaultHeader::decode(&noncanonical),
            Err(FormatError::NonCanonical)
        ));

        let mut future_version = encoded;
        future_version[version_offset] = 2;
        assert!(matches!(
            VaultHeader::decode(&future_version),
            Err(FormatError::Unsupported)
        ));
    }

    #[test]
    fn manifest_round_trips_and_enforces_exact_envelope() {
        let manifest = Manifest::empty(1_700_000_000_000, 1);
        let plaintext = manifest.encode().expect("empty manifest must encode");
        assert!(Manifest::decode(&plaintext).is_ok());

        let envelope = ManifestEnvelope::new([0x77; 24], vec![0x88; 32]).expect("valid envelope");
        let encoded = envelope.encode().expect("envelope must encode");
        assert!(ManifestEnvelope::decode(&encoded).is_ok());

        let truncated = &encoded[..encoded.len() - 1];
        assert!(ManifestEnvelope::decode(truncated).is_err());
    }

    #[test]
    fn manifest_mutation_increments_once_and_rejects_time_rollback() {
        let created_at_ms = 1_700_000_000_000;
        let initial = Manifest::empty(created_at_ms, 1);
        let committed = initial
            .next_generation(
                created_at_ms + 1,
                vec![ManifestEntry::new([0x11; 16], [0x22; 32])],
            )
            .expect("next generation must be valid");
        assert_eq!(committed.generation(), 1);
        assert_eq!(committed.committed_at_ms(), created_at_ms + 1);
        assert!(matches!(
            committed.next_generation(created_at_ms, Vec::new()),
            Err(FormatError::InvariantViolation)
        ));
    }
}
