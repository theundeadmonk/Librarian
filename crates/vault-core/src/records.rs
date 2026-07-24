use std::fmt;

use librarian_vault_format::{
    MAX_ORIGIN_BYTES, MAX_PASSWORD_BYTES, MAX_RECORDS, MAX_SERVICE_NAME_BYTES, MAX_USERNAME_BYTES,
    Manifest, ManifestEntry, ManifestEnvelope, RecordEnvelope, VaultHeader,
    WebsiteAccountPlaintext, encode_manifest_aad, encode_record_aad,
};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

use super::{
    CancellationFlag, CreateVaultError, EntropySource, SystemEntropy, UnlockedVault, decrypt_bytes,
    derive_key, derive_manifest_key, encrypt_bytes, random_array,
};

const RECORD_LABEL_PREFIX: &[u8] = b"librarian/vault/v1/record/";
const MAX_RECORD_ID_ATTEMPTS: usize = 128;

/// A stable, random identifier with no embedded timestamp or semantic value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecordId([u8; 16]);

impl RecordId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// One opaque `SQLite` record row presented to the cryptographic core.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedRecord {
    id: RecordId,
    envelope: Vec<u8>,
}

impl EncryptedRecord {
    #[must_use]
    pub fn new(id: RecordId, envelope: Vec<u8>) -> Self {
        Self { id, envelope }
    }

    #[must_use]
    pub const fn id(&self) -> RecordId {
        self.id
    }

    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }
}

/// Actionable input validation failures before a vault operation starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebsiteAccountInputError {
    InvalidServiceName,
    InvalidOrigin,
    FieldTooLarge,
}

impl fmt::Display for WebsiteAccountInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidServiceName => "service name is invalid",
            Self::InvalidOrigin => "website origin is invalid",
            Self::FieldTooLarge => "website account field exceeds its size limit",
        })
    }
}

impl std::error::Error for WebsiteAccountInputError {}

/// Validated, normalized user input for a website account.
///
/// This type intentionally does not implement formatting, cloning,
/// serialization, or equality. All user-authored allocations are zeroized.
pub struct WebsiteAccountInput {
    service_name: Zeroizing<String>,
    permitted_origin: Zeroizing<String>,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl WebsiteAccountInput {
    /// Validates bounded fields and reduces an HTTP(S) URL to its canonical
    /// WHATWG origin.
    ///
    /// Paths other than `/`, credentials, query strings, and fragments are
    /// rejected so callers cannot accidentally widen an exact-origin policy.
    ///
    /// # Errors
    ///
    /// Returns a non-secret validation category for invalid or oversized input.
    pub fn new(
        service_name: &str,
        permitted_origin: &str,
        username: &str,
        password: &str,
    ) -> Result<Self, WebsiteAccountInputError> {
        validate_input_lengths(service_name, permitted_origin, username, password)?;
        if service_name.is_empty() || service_name.chars().any(char::is_control) {
            return Err(WebsiteAccountInputError::InvalidServiceName);
        }
        let permitted_origin = normalize_origin(permitted_origin)?;
        Ok(Self {
            service_name: Zeroizing::new(service_name.to_owned()),
            permitted_origin,
            username: Zeroizing::new(username.to_owned()),
            password: Zeroizing::new(password.to_owned()),
        })
    }
}

/// Decrypted website-account result owned by the trusted agent.
///
/// User-authored fields are zeroized on drop. The type intentionally does not
/// implement formatting, cloning, serialization, or equality.
pub struct WebsiteAccount {
    id: RecordId,
    revision: u64,
    created_at_ms: u64,
    modified_at_ms: u64,
    service_name: Zeroizing<String>,
    permitted_origin: Zeroizing<String>,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl WebsiteAccount {
    #[must_use]
    pub const fn id(&self) -> RecordId {
        self.id
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
}

/// Deliberately small public result classes for record operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordOperationError {
    NotFound,
    Failed,
}

impl fmt::Display for RecordOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotFound => "website account was not found",
            Self::Failed => "website account operation failed",
        })
    }
}

impl std::error::Error for RecordOperationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordMutationKind {
    Insert,
    Update,
    Delete,
}

/// Opaque encrypted mutation that is safe for the agent to persist atomically.
pub struct PreparedRecordMutation {
    kind: RecordMutationKind,
    id: RecordId,
    envelope: Option<Vec<u8>>,
    manifest_envelope: Vec<u8>,
    expected_generation: u64,
    next_manifest: Manifest,
}

impl PreparedRecordMutation {
    #[must_use]
    pub const fn kind(&self) -> RecordMutationKind {
        self.kind
    }

    #[must_use]
    pub const fn id(&self) -> RecordId {
        self.id
    }

    #[must_use]
    pub fn envelope(&self) -> Option<&[u8]> {
        self.envelope.as_deref()
    }

    #[must_use]
    pub fn manifest_envelope(&self) -> &[u8] {
        &self.manifest_envelope
    }
}

impl UnlockedVault {
    /// Fully authenticates a snapshot and returns every website account.
    ///
    /// # Errors
    ///
    /// Any stale generation, malformed row, digest mismatch, unsupported
    /// record, or authentication failure returns `Failed`.
    pub fn list_website_accounts(
        &self,
        header_bytes: &[u8],
        manifest_envelope_bytes: &[u8],
        records: &[EncryptedRecord],
    ) -> Result<Vec<WebsiteAccount>, RecordOperationError> {
        self.authenticate_snapshot(header_bytes, manifest_envelope_bytes, records)
    }

    /// Fully authenticates a snapshot and returns one matching account.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` only after the complete snapshot authenticates.
    pub fn get_website_account(
        &self,
        header_bytes: &[u8],
        manifest_envelope_bytes: &[u8],
        records: &[EncryptedRecord],
        id: RecordId,
    ) -> Result<WebsiteAccount, RecordOperationError> {
        self.authenticate_snapshot(header_bytes, manifest_envelope_bytes, records)?
            .into_iter()
            .find(|account| account.id == id)
            .ok_or(RecordOperationError::NotFound)
    }

    /// Prepares an encrypted insert and the matching next manifest.
    ///
    /// # Errors
    ///
    /// Returns `Failed` if the current snapshot is unauthenticated, a secure
    /// identifier cannot be allocated, or cryptographic construction fails.
    pub fn prepare_add_website_account(
        &self,
        header_bytes: &[u8],
        manifest_envelope_bytes: &[u8],
        records: &[EncryptedRecord],
        input: WebsiteAccountInput,
        committed_at_ms: u64,
    ) -> Result<PreparedRecordMutation, RecordOperationError> {
        let accounts =
            self.authenticate_snapshot(header_bytes, manifest_envelope_bytes, records)?;
        drop(accounts);
        self.prepare_add_with_entropy(input, committed_at_ms, &mut SystemEntropy)
    }

    /// Prepares an encrypted update and the matching next manifest.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` only after the complete snapshot authenticates.
    pub fn prepare_update_website_account(
        &self,
        header_bytes: &[u8],
        manifest_envelope_bytes: &[u8],
        records: &[EncryptedRecord],
        id: RecordId,
        input: WebsiteAccountInput,
        committed_at_ms: u64,
    ) -> Result<PreparedRecordMutation, RecordOperationError> {
        let account =
            self.get_website_account(header_bytes, manifest_envelope_bytes, records, id)?;
        let revision = account
            .revision
            .checked_add(1)
            .ok_or(RecordOperationError::Failed)?;
        let created_at_ms = account.created_at_ms;
        drop(account);
        self.prepare_upsert(
            RecordMutationKind::Update,
            id,
            revision,
            created_at_ms,
            input,
            committed_at_ms,
            &mut SystemEntropy,
        )
    }

    /// Prepares deletion of one authenticated record.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` only after the complete snapshot authenticates.
    pub fn prepare_delete_website_account(
        &self,
        header_bytes: &[u8],
        manifest_envelope_bytes: &[u8],
        records: &[EncryptedRecord],
        id: RecordId,
        committed_at_ms: u64,
    ) -> Result<PreparedRecordMutation, RecordOperationError> {
        let account =
            self.get_website_account(header_bytes, manifest_envelope_bytes, records, id)?;
        drop(account);
        let mut entries = self.manifest.entries().to_vec();
        let original_len = entries.len();
        entries.retain(|entry| entry.record_id() != id.as_bytes());
        if entries.len() == original_len {
            return Err(RecordOperationError::NotFound);
        }
        self.prepare_manifest_mutation(
            RecordMutationKind::Delete,
            id,
            None,
            entries,
            committed_at_ms,
            &mut SystemEntropy,
        )
    }

    /// Advances in-memory authenticated state only after `SQLite` commit.
    ///
    /// # Errors
    ///
    /// A stale or skipped generation fails without changing the session.
    pub fn commit_record_mutation(
        &mut self,
        mutation: PreparedRecordMutation,
    ) -> Result<RecordId, RecordOperationError> {
        if self.manifest.generation() != mutation.expected_generation
            || mutation.next_manifest.generation()
                != mutation
                    .expected_generation
                    .checked_add(1)
                    .ok_or(RecordOperationError::Failed)?
        {
            return Err(RecordOperationError::Failed);
        }
        self.manifest = mutation.next_manifest;
        Ok(mutation.id)
    }

    fn authenticate_snapshot(
        &self,
        header_bytes: &[u8],
        manifest_envelope_bytes: &[u8],
        records: &[EncryptedRecord],
    ) -> Result<Vec<WebsiteAccount>, RecordOperationError> {
        let header = VaultHeader::decode(header_bytes).map_err(|_| RecordOperationError::Failed)?;
        if header != self.header {
            return Err(RecordOperationError::Failed);
        }
        let manifest = decrypt_manifest(self, manifest_envelope_bytes)?;
        if manifest != self.manifest {
            return Err(RecordOperationError::Failed);
        }
        authenticate_records_inner(self, records)
    }

    fn prepare_add_with_entropy(
        &self,
        input: WebsiteAccountInput,
        committed_at_ms: u64,
        entropy: &mut impl EntropySource,
    ) -> Result<PreparedRecordMutation, RecordOperationError> {
        if self.manifest.entries().len() >= MAX_RECORDS {
            return Err(RecordOperationError::Failed);
        }
        let id = (0..MAX_RECORD_ID_ATTEMPTS)
            .find_map(|_| {
                random_array(entropy)
                    .ok()
                    .map(RecordId::from_bytes)
                    .filter(|candidate| {
                        !self
                            .manifest
                            .entries()
                            .iter()
                            .any(|entry| entry.record_id() == candidate.as_bytes())
                    })
            })
            .ok_or(RecordOperationError::Failed)?;
        self.prepare_upsert(
            RecordMutationKind::Insert,
            id,
            1,
            committed_at_ms,
            input,
            committed_at_ms,
            entropy,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_upsert(
        &self,
        kind: RecordMutationKind,
        id: RecordId,
        revision: u64,
        created_at_ms: u64,
        input: WebsiteAccountInput,
        committed_at_ms: u64,
        entropy: &mut impl EntropySource,
    ) -> Result<PreparedRecordMutation, RecordOperationError> {
        let plaintext = WebsiteAccountPlaintext::new(
            revision,
            created_at_ms,
            committed_at_ms,
            input.service_name,
            input.permitted_origin,
            input.username,
            input.password,
        )
        .map_err(|_| RecordOperationError::Failed)?;
        let plaintext_bytes = plaintext
            .encode()
            .map_err(|_| RecordOperationError::Failed)?;
        let nonce = random_array(entropy).map_err(|_| RecordOperationError::Failed)?;
        let record_key = derive_record_key(self, id)?;
        let aad = encode_record_aad(self.vault_id(), id.as_bytes(), self.key_epoch());
        let ciphertext = encrypt_bytes(&record_key, &nonce, &plaintext_bytes, &aad)
            .map_err(|_| RecordOperationError::Failed)?;
        let envelope = RecordEnvelope::new(self.key_epoch(), nonce, ciphertext)
            .and_then(|value| value.encode())
            .map_err(|_| RecordOperationError::Failed)?;
        let digest: [u8; 32] = Sha256::digest(&envelope).into();
        let mut entries = self.manifest.entries().to_vec();
        match kind {
            RecordMutationKind::Insert => {
                entries.push(ManifestEntry::new(*id.as_bytes(), digest));
            }
            RecordMutationKind::Update => {
                let entry = entries
                    .iter_mut()
                    .find(|entry| entry.record_id() == id.as_bytes())
                    .ok_or(RecordOperationError::NotFound)?;
                *entry = ManifestEntry::new(*id.as_bytes(), digest);
            }
            RecordMutationKind::Delete => return Err(RecordOperationError::Failed),
        }
        entries.sort_by(|left, right| left.record_id().cmp(right.record_id()));
        self.prepare_manifest_mutation(kind, id, Some(envelope), entries, committed_at_ms, entropy)
    }

    fn prepare_manifest_mutation(
        &self,
        kind: RecordMutationKind,
        id: RecordId,
        envelope: Option<Vec<u8>>,
        entries: Vec<ManifestEntry>,
        committed_at_ms: u64,
        entropy: &mut impl EntropySource,
    ) -> Result<PreparedRecordMutation, RecordOperationError> {
        let next_manifest = self
            .manifest
            .next_generation(committed_at_ms, entries)
            .map_err(|_| RecordOperationError::Failed)?;
        let manifest_plaintext = Zeroizing::new(
            next_manifest
                .encode()
                .map_err(|_| RecordOperationError::Failed)?,
        );
        let nonce = random_array(entropy).map_err(|_| RecordOperationError::Failed)?;
        let manifest_key =
            derive_manifest_key(&self.vault_root_key[..], self.vault_id(), self.key_epoch())
                .map_err(|()| RecordOperationError::Failed)?;
        let aad = encode_manifest_aad(&self.header, &nonce);
        let ciphertext = encrypt_bytes(&manifest_key, &nonce, &manifest_plaintext, &aad)
            .map_err(|_| RecordOperationError::Failed)?;
        let manifest_envelope = ManifestEnvelope::new(nonce, ciphertext)
            .and_then(|value| value.encode())
            .map_err(|_| RecordOperationError::Failed)?;
        Ok(PreparedRecordMutation {
            kind,
            id,
            envelope,
            manifest_envelope,
            expected_generation: self.manifest.generation(),
            next_manifest,
        })
    }
}

pub(super) fn authenticate_records(
    vault: &UnlockedVault,
    records: &[EncryptedRecord],
    cancellation: &CancellationFlag,
) -> Result<(), super::UnlockError> {
    let accounts = authenticate_records_inner_with_cancellation(vault, records, Some(cancellation))
        .map_err(|error| match error {
            SnapshotAuthenticationError::Cancelled => super::UnlockError::Cancelled,
            SnapshotAuthenticationError::Failed => super::UnlockError::Failed,
        })?;
    drop(accounts);
    if cancellation.is_cancelled() {
        return Err(super::UnlockError::Cancelled);
    }
    Ok(())
}

fn authenticate_records_inner(
    vault: &UnlockedVault,
    records: &[EncryptedRecord],
) -> Result<Vec<WebsiteAccount>, RecordOperationError> {
    authenticate_records_inner_with_cancellation(vault, records, None)
        .map_err(|_| RecordOperationError::Failed)
}

fn authenticate_records_inner_with_cancellation(
    vault: &UnlockedVault,
    records: &[EncryptedRecord],
    cancellation: Option<&CancellationFlag>,
) -> Result<Vec<WebsiteAccount>, SnapshotAuthenticationError> {
    if records.len() != vault.manifest.entries().len() || records.len() > MAX_RECORDS {
        return Err(SnapshotAuthenticationError::Failed);
    }
    if records
        .windows(2)
        .any(|pair| pair[0].id.as_bytes() >= pair[1].id.as_bytes())
    {
        return Err(SnapshotAuthenticationError::Failed);
    }
    let mut accounts = Vec::with_capacity(records.len());
    for (record, commitment) in records.iter().zip(vault.manifest.entries()) {
        if cancellation.is_some_and(CancellationFlag::is_cancelled) {
            return Err(SnapshotAuthenticationError::Cancelled);
        }
        if record.id.as_bytes() != commitment.record_id()
            || Sha256::digest(record.envelope.as_slice()).as_slice() != commitment.envelope_digest()
        {
            return Err(SnapshotAuthenticationError::Failed);
        }
        accounts.push(decrypt_website_account(vault, record)?);
    }
    Ok(accounts)
}

fn decrypt_manifest(
    vault: &UnlockedVault,
    envelope_bytes: &[u8],
) -> Result<Manifest, RecordOperationError> {
    let envelope =
        ManifestEnvelope::decode(envelope_bytes).map_err(|_| RecordOperationError::Failed)?;
    let manifest_key = derive_manifest_key(
        &vault.vault_root_key[..],
        vault.vault_id(),
        vault.key_epoch(),
    )
    .map_err(|()| RecordOperationError::Failed)?;
    let aad = encode_manifest_aad(&vault.header, envelope.nonce());
    let plaintext = decrypt_bytes(&manifest_key, envelope.nonce(), envelope.ciphertext(), &aad)
        .map_err(|()| RecordOperationError::Failed)?;
    Manifest::decode(&plaintext).map_err(|_| RecordOperationError::Failed)
}

fn decrypt_website_account(
    vault: &UnlockedVault,
    record: &EncryptedRecord,
) -> Result<WebsiteAccount, SnapshotAuthenticationError> {
    let envelope = RecordEnvelope::decode(&record.envelope)
        .map_err(|_| SnapshotAuthenticationError::Failed)?;
    if envelope.key_epoch() != vault.key_epoch() {
        return Err(SnapshotAuthenticationError::Failed);
    }
    let record_key =
        derive_record_key(vault, record.id).map_err(|_| SnapshotAuthenticationError::Failed)?;
    let aad = encode_record_aad(vault.vault_id(), record.id.as_bytes(), vault.key_epoch());
    let plaintext = decrypt_bytes(&record_key, envelope.nonce(), envelope.ciphertext(), &aad)
        .map_err(|()| SnapshotAuthenticationError::Failed)?;
    let decoded = WebsiteAccountPlaintext::decode(&plaintext)
        .map_err(|_| SnapshotAuthenticationError::Failed)?;
    let normalized = normalize_origin(decoded.permitted_origin())
        .map_err(|_| SnapshotAuthenticationError::Failed)?;
    if normalized.as_str() != decoded.permitted_origin() {
        return Err(SnapshotAuthenticationError::Failed);
    }
    let revision = decoded.revision();
    let created_at_ms = decoded.created_at_ms();
    let modified_at_ms = decoded.modified_at_ms();
    let (service_name, permitted_origin, username, password) = decoded.into_fields();
    Ok(WebsiteAccount {
        id: record.id,
        revision,
        created_at_ms,
        modified_at_ms,
        service_name,
        permitted_origin,
        username,
        password,
    })
}

fn derive_record_key(
    vault: &UnlockedVault,
    record_id: RecordId,
) -> Result<Zeroizing<[u8; 32]>, RecordOperationError> {
    let mut label = Vec::with_capacity(RECORD_LABEL_PREFIX.len() + 16 + 4);
    label.extend_from_slice(RECORD_LABEL_PREFIX);
    label.extend_from_slice(record_id.as_bytes());
    label.extend_from_slice(&vault.key_epoch().to_be_bytes());
    derive_key(&vault.vault_root_key[..], vault.vault_id(), &label)
        .map_err(|()| RecordOperationError::Failed)
}

fn normalize_origin(value: &str) -> Result<Zeroizing<String>, WebsiteAccountInputError> {
    if value.len() > MAX_ORIGIN_BYTES {
        return Err(WebsiteAccountInputError::FieldTooLarge);
    }
    let parsed = Url::parse(value).map_err(|_| WebsiteAccountInputError::InvalidOrigin)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(WebsiteAccountInputError::InvalidOrigin);
    }
    let normalized = parsed.origin().ascii_serialization();
    if normalized == "null" || normalized.len() > MAX_ORIGIN_BYTES {
        return Err(WebsiteAccountInputError::InvalidOrigin);
    }
    Ok(Zeroizing::new(normalized))
}

fn validate_input_lengths(
    service_name: &str,
    permitted_origin: &str,
    username: &str,
    password: &str,
) -> Result<(), WebsiteAccountInputError> {
    if service_name.len() > MAX_SERVICE_NAME_BYTES
        || permitted_origin.len() > MAX_ORIGIN_BYTES
        || username.len() > MAX_USERNAME_BYTES
        || password.len() > MAX_PASSWORD_BYTES
    {
        return Err(WebsiteAccountInputError::FieldTooLarge);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum SnapshotAuthenticationError {
    Cancelled,
    Failed,
}

impl From<RecordOperationError> for SnapshotAuthenticationError {
    fn from(_: RecordOperationError) -> Self {
        Self::Failed
    }
}

impl From<CreateVaultError> for RecordOperationError {
    fn from(_: CreateVaultError) -> Self {
        Self::Failed
    }
}

#[cfg(test)]
mod tests {
    use librarian_vault_format::MAX_SERVICE_NAME_BYTES;

    use super::{WebsiteAccountInput, WebsiteAccountInputError};

    #[test]
    fn origin_normalization_is_exact_and_whatwg_based() {
        let input =
            WebsiteAccountInput::new("Example", "HTTPS://EXAMPLE.COM:443/", "person", "password")
                .expect("origin must normalize");
        assert_eq!(input.permitted_origin.as_str(), "https://example.com");
    }

    #[test]
    fn origin_rejects_paths_credentials_queries_and_non_http_schemes() {
        for origin in [
            "https://example.com/login",
            "https://user@example.com/",
            "https://example.com/?next=login",
            "https://example.com/#login",
            "file:///tmp/example",
            "javascript:alert(1)",
        ] {
            assert!(matches!(
                WebsiteAccountInput::new("Example", origin, "person", "password"),
                Err(WebsiteAccountInputError::InvalidOrigin)
            ));
        }
    }

    #[test]
    fn account_input_enforces_byte_bounds_and_a_meaningful_service_name() {
        assert!(matches!(
            WebsiteAccountInput::new("", "https://example.com", "person", "password"),
            Err(WebsiteAccountInputError::InvalidServiceName)
        ));
        let oversized = "x".repeat(MAX_SERVICE_NAME_BYTES + 1);
        assert!(matches!(
            WebsiteAccountInput::new(&oversized, "https://example.com", "person", "password"),
            Err(WebsiteAccountInputError::FieldTooLarge)
        ));
        let exact = "x".repeat(MAX_SERVICE_NAME_BYTES);
        assert!(
            WebsiteAccountInput::new(&exact, "https://example.com", "", "").is_ok(),
            "empty usernames and passwords remain representable for real website edge cases"
        );
    }
}
