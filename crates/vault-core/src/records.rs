use std::{collections::BTreeSet, fmt};

use librarian_vault_format::{
    MAX_ORIGIN_BYTES, MAX_PASSKEY_RP_ID_BYTES, MAX_PASSKEY_USER_DISPLAY_NAME_BYTES,
    MAX_PASSKEY_USER_HANDLE_BYTES, MAX_PASSKEY_USER_NAME_BYTES, MAX_PASSWORD_BYTES, MAX_RECORDS,
    MAX_SERVICE_NAME_BYTES, MAX_USERNAME_BYTES, Manifest, ManifestEntry, ManifestEnvelope,
    PASSKEY_CREDENTIAL_ID_BYTES, PASSKEY_PRIVATE_KEY_BYTES, PasskeyPlaintext, RecordEnvelope,
    RecordType, VaultHeader, WebsiteAccountPlaintext, encode_manifest_aad, encode_record_aad,
    record_type,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

use super::{
    CancellationFlag, CreateVaultError, EntropySource, SystemEntropy, UnlockedVault, decrypt_bytes,
    derive_key, derive_manifest_key, encrypt_bytes, random_array,
};

const RECORD_LABEL_PREFIX: &[u8] = b"librarian/vault/v1/record/";
const MAX_RECORD_ID_ATTEMPTS: usize = 128;
const MAX_WEBSITE_ACCOUNT_PAGE_SIZE: usize = 100;
const MAX_PASSKEY_ASSERTION_CANDIDATES: usize = 64;
const MAX_PASSKEY_CREDENTIALS: usize = 64;
const PASSKEY_PUBLIC_KEY_BYTES: usize = 65;
const PASSKEY_AUTHENTICATOR_DATA_BYTES: usize = 37;
const PASSKEY_USER_PRESENT: u8 = 0x01;
const PASSKEY_USER_VERIFIED: u8 = 0x04;
const PASSKEY_BACKUP_ELIGIBLE: u8 = 0x08;

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

/// Actionable passkey input failures before a vault operation starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasskeyInputError {
    InvalidRpId,
    InvalidUser,
    FieldTooLarge,
}

impl fmt::Display for PasskeyInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRpId => "relying-party identifier is invalid",
            Self::InvalidUser => "passkey user entity is invalid",
            Self::FieldTooLarge => "passkey field exceeds its size limit",
        })
    }
}

impl std::error::Error for PasskeyInputError {}

/// Validated passkey user and relying-party input.
///
/// User-authored allocations are zeroized and this value intentionally has no
/// formatting or cloning implementation.
pub struct PasskeyInput {
    rp_id: Zeroizing<String>,
    user_handle: Zeroizing<Vec<u8>>,
    user_name: Zeroizing<String>,
    user_display_name: Zeroizing<String>,
}

impl PasskeyInput {
    /// Validates and canonicalizes an exact `WebAuthn` relying-party identifier.
    ///
    /// # Errors
    ///
    /// Rejects URLs, ports, paths, empty user fields, control characters, and
    /// values outside the `WebAuthn` and Librarian bounds.
    pub fn new(
        rp_id: &str,
        user_handle: &[u8],
        user_name: &str,
        user_display_name: &str,
    ) -> Result<Self, PasskeyInputError> {
        if rp_id.len() > MAX_PASSKEY_RP_ID_BYTES
            || user_handle.len() > MAX_PASSKEY_USER_HANDLE_BYTES
            || user_name.len() > MAX_PASSKEY_USER_NAME_BYTES
            || user_display_name.len() > MAX_PASSKEY_USER_DISPLAY_NAME_BYTES
        {
            return Err(PasskeyInputError::FieldTooLarge);
        }
        if user_handle.is_empty()
            || user_name.is_empty()
            || user_display_name.is_empty()
            || user_name.chars().any(char::is_control)
            || user_display_name.chars().any(char::is_control)
        {
            return Err(PasskeyInputError::InvalidUser);
        }
        let normalized_rp_id = normalize_rp_id(rp_id)?;
        if normalized_rp_id.as_str() != rp_id {
            return Err(PasskeyInputError::InvalidRpId);
        }
        Ok(Self {
            rp_id: normalized_rp_id,
            user_handle: Zeroizing::new(user_handle.to_vec()),
            user_name: Zeroizing::new(user_name.to_owned()),
            user_display_name: Zeroizing::new(user_display_name.to_owned()),
        })
    }
}

/// Public material returned after a passkey is durably committed.
pub struct PasskeyCredential {
    credential_id: [u8; PASSKEY_CREDENTIAL_ID_BYTES],
    user_handle: Zeroizing<Vec<u8>>,
    public_key: [u8; PASSKEY_PUBLIC_KEY_BYTES],
}

/// Public metadata for one vault-backed passkey. Private key material and the
/// signature counter are structurally absent.
pub struct PasskeySummary {
    credential_id: [u8; PASSKEY_CREDENTIAL_ID_BYTES],
    rp_id: Zeroizing<String>,
    user_handle: Zeroizing<Vec<u8>>,
    user_name: Zeroizing<String>,
    user_display_name: Zeroizing<String>,
}

impl PasskeySummary {
    #[must_use]
    pub const fn credential_id(&self) -> &[u8; PASSKEY_CREDENTIAL_ID_BYTES] {
        &self.credential_id
    }

    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    #[must_use]
    pub fn user_handle(&self) -> &[u8] {
        self.user_handle.as_slice()
    }

    #[must_use]
    pub fn user_name(&self) -> &str {
        &self.user_name
    }

    #[must_use]
    pub fn user_display_name(&self) -> &str {
        &self.user_display_name
    }
}

impl PasskeyCredential {
    #[must_use]
    pub const fn credential_id(&self) -> &[u8; PASSKEY_CREDENTIAL_ID_BYTES] {
        &self.credential_id
    }

    #[must_use]
    pub fn user_handle(&self) -> &[u8] {
        self.user_handle.as_slice()
    }

    /// Returns the uncompressed SEC1 P-256 public point: `0x04 || X || Y`.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; PASSKEY_PUBLIC_KEY_BYTES] {
        &self.public_key
    }
}

/// Transaction-bound assertion produced without releasing private material.
pub struct PasskeyAssertion {
    credential_id: [u8; PASSKEY_CREDENTIAL_ID_BYTES],
    user_handle: Zeroizing<Vec<u8>>,
    authenticator_data: [u8; PASSKEY_AUTHENTICATOR_DATA_BYTES],
    signature_der: Zeroizing<Vec<u8>>,
}

impl PasskeyAssertion {
    #[must_use]
    pub const fn credential_id(&self) -> &[u8; PASSKEY_CREDENTIAL_ID_BYTES] {
        &self.credential_id
    }

    #[must_use]
    pub fn user_handle(&self) -> &[u8] {
        self.user_handle.as_slice()
    }

    #[must_use]
    pub const fn authenticator_data(&self) -> &[u8; PASSKEY_AUTHENTICATOR_DATA_BYTES] {
        &self.authenticator_data
    }

    #[must_use]
    pub fn signature_der(&self) -> &[u8] {
        self.signature_der.as_slice()
    }
}

struct PasskeyRecord {
    id: RecordId,
    revision: u64,
    created_at_ms: u64,
    signature_counter: u32,
    rp_id: Zeroizing<String>,
    user_handle: Zeroizing<Vec<u8>>,
    user_name: Zeroizing<String>,
    user_display_name: Zeroizing<String>,
    credential_id: [u8; PASSKEY_CREDENTIAL_ID_BYTES],
    private_key: Zeroizing<[u8; PASSKEY_PRIVATE_KEY_BYTES]>,
}

enum DecryptedRecord {
    WebsiteAccount(WebsiteAccount),
    Passkey(PasskeyRecord),
}

/// Deliberately small public result classes for record operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordOperationError {
    NotFound,
    Conflict,
    Cancelled,
    Failed,
}

impl fmt::Display for RecordOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotFound => "vault record was not found",
            Self::Conflict => "vault record conflicts with the request",
            Self::Cancelled => "vault record operation was cancelled",
            Self::Failed => "vault record operation failed",
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
        self.authenticate_snapshot_metadata(header_bytes, manifest_envelope_bytes)?;
        let mut accounts = Vec::with_capacity(records.len());
        visit_authenticated_records(
            self,
            records,
            || false,
            |record| {
                if let DecryptedRecord::WebsiteAccount(account) = record {
                    accounts.push(account);
                }
            },
        )
        .map_err(map_snapshot_operation_error)?;
        Ok(accounts)
    }

    /// Fully authenticates a snapshot while retaining only one bounded account
    /// page in plaintext.
    ///
    /// # Errors
    ///
    /// Any stale generation, malformed row, digest mismatch, unsupported
    /// record, authentication failure, or invalid page range returns `Failed`.
    pub fn list_website_account_page(
        &self,
        header_bytes: &[u8],
        manifest_envelope_bytes: &[u8],
        records: &[EncryptedRecord],
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<WebsiteAccount>, bool), RecordOperationError> {
        self.list_website_account_page_with_check(
            header_bytes,
            manifest_envelope_bytes,
            records,
            offset,
            limit,
            || false,
        )
    }

    /// Fully authenticates a bounded page while checking request authority
    /// before each record is decrypted.
    ///
    /// # Errors
    ///
    /// Returns `Cancelled` when `should_cancel` wins. Integrity failures and
    /// invalid page ranges return `Failed`.
    pub fn list_website_account_page_with_check(
        &self,
        header_bytes: &[u8],
        manifest_envelope_bytes: &[u8],
        records: &[EncryptedRecord],
        offset: usize,
        limit: usize,
        should_cancel: impl FnMut() -> bool,
    ) -> Result<(Vec<WebsiteAccount>, bool), RecordOperationError> {
        if limit == 0 || limit > MAX_WEBSITE_ACCOUNT_PAGE_SIZE {
            return Err(RecordOperationError::Failed);
        }
        self.authenticate_snapshot_metadata(header_bytes, manifest_envelope_bytes)?;
        let end = offset
            .checked_add(limit)
            .ok_or(RecordOperationError::Failed)?;
        let mut index = 0_usize;
        let mut accounts = Vec::with_capacity(limit);
        let mut has_more = false;
        visit_authenticated_records(self, records, should_cancel, |record| {
            if let DecryptedRecord::WebsiteAccount(account) = record {
                if index >= offset && index < end {
                    accounts.push(account);
                } else if index >= end {
                    has_more = true;
                }
                index = index.saturating_add(1);
            }
        })
        .map_err(map_snapshot_operation_error)?;
        Ok((accounts, has_more))
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
        self.get_website_account_with_check(
            header_bytes,
            manifest_envelope_bytes,
            records,
            id,
            || false,
        )
    }

    /// Authenticates a snapshot while checking request authority before each
    /// record is decrypted.
    ///
    /// # Errors
    ///
    /// Returns `Cancelled` when `should_cancel` wins, `NotFound` only after a
    /// complete authenticated visit, and `Failed` for integrity errors.
    pub fn get_website_account_with_check(
        &self,
        header_bytes: &[u8],
        manifest_envelope_bytes: &[u8],
        records: &[EncryptedRecord],
        id: RecordId,
        should_cancel: impl FnMut() -> bool,
    ) -> Result<WebsiteAccount, RecordOperationError> {
        self.authenticate_snapshot_metadata(header_bytes, manifest_envelope_bytes)?;
        let mut found = None;
        visit_authenticated_records(self, records, should_cancel, |record| {
            if let DecryptedRecord::WebsiteAccount(account) = record
                && account.id == id
            {
                found = Some(account);
            }
        })
        .map_err(map_snapshot_operation_error)?;
        found.ok_or(RecordOperationError::NotFound)
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
        self.prepare_add_website_account_with_check(
            header_bytes,
            manifest_envelope_bytes,
            records,
            input,
            committed_at_ms,
            || false,
        )
    }

    /// Prepares an insert while checking request authority before every record.
    ///
    /// # Errors
    ///
    /// Returns `Cancelled` when `should_cancel` wins and `Failed` for integrity
    /// or cryptographic failures.
    pub fn prepare_add_website_account_with_check(
        &self,
        header_bytes: &[u8],
        manifest_envelope_bytes: &[u8],
        records: &[EncryptedRecord],
        input: WebsiteAccountInput,
        committed_at_ms: u64,
        should_cancel: impl FnMut() -> bool,
    ) -> Result<PreparedRecordMutation, RecordOperationError> {
        self.authenticate_snapshot_metadata(header_bytes, manifest_envelope_bytes)?;
        authenticate_records_only_with_check(self, records, should_cancel)?;
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
        self.prepare_update_website_account_with_check(
            header_bytes,
            manifest_envelope_bytes,
            records,
            id,
            input,
            committed_at_ms,
            || false,
        )
    }

    /// Prepares an update while checking request authority before every record.
    ///
    /// # Errors
    ///
    /// Returns `Cancelled` when `should_cancel` wins, `NotFound` after full
    /// authentication, and `Failed` for integrity or cryptographic failures.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_update_website_account_with_check(
        &self,
        header_bytes: &[u8],
        manifest_envelope_bytes: &[u8],
        records: &[EncryptedRecord],
        id: RecordId,
        input: WebsiteAccountInput,
        committed_at_ms: u64,
        should_cancel: impl FnMut() -> bool,
    ) -> Result<PreparedRecordMutation, RecordOperationError> {
        let account = self.get_website_account_with_check(
            header_bytes,
            manifest_envelope_bytes,
            records,
            id,
            should_cancel,
        )?;
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
        self.prepare_delete_website_account_with_check(
            header_bytes,
            manifest_envelope_bytes,
            records,
            id,
            committed_at_ms,
            || false,
        )
    }

    /// Prepares deletion while checking request authority before every record.
    ///
    /// # Errors
    ///
    /// Returns `Cancelled` when `should_cancel` wins, `NotFound` after full
    /// authentication, and `Failed` for integrity or cryptographic failures.
    pub fn prepare_delete_website_account_with_check(
        &self,
        header_bytes: &[u8],
        manifest_envelope_bytes: &[u8],
        records: &[EncryptedRecord],
        id: RecordId,
        committed_at_ms: u64,
        should_cancel: impl FnMut() -> bool,
    ) -> Result<PreparedRecordMutation, RecordOperationError> {
        let account = self.get_website_account_with_check(
            header_bytes,
            manifest_envelope_bytes,
            records,
            id,
            should_cancel,
        )?;
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

    /// Prepares a new vault-backed ES256 passkey.
    ///
    /// The private scalar is generated and encrypted inside the vault core.
    /// Only the credential identifier, user handle, and public point are
    /// returned to the caller.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` when an authenticated excluded credential already
    /// exists, `Cancelled` when request authority is revoked, and `Failed` for
    /// integrity, capacity, entropy, or cryptographic failures.
    #[allow(
        clippy::too_many_arguments,
        reason = "snapshot authentication and cancellation inputs remain explicit at the crypto boundary"
    )]
    pub fn prepare_add_passkey_with_check(
        &self,
        header_bytes: &[u8],
        manifest_envelope_bytes: &[u8],
        records: &[EncryptedRecord],
        input: PasskeyInput,
        excluded_credential_ids: &[[u8; PASSKEY_CREDENTIAL_ID_BYTES]],
        committed_at_ms: u64,
        should_cancel: impl FnMut() -> bool,
    ) -> Result<(PreparedRecordMutation, PasskeyCredential), RecordOperationError> {
        self.authenticate_snapshot_metadata(header_bytes, manifest_envelope_bytes)?;
        let mut conflict = false;
        let mut existing_credential_ids = BTreeSet::new();
        let mut invalid = false;
        visit_authenticated_records(self, records, should_cancel, |record| {
            if let DecryptedRecord::Passkey(passkey) = record {
                if !existing_credential_ids.insert(passkey.credential_id) {
                    invalid = true;
                    return;
                }
                if passkey.rp_id.as_str() == input.rp_id.as_str()
                    && excluded_credential_ids.contains(&passkey.credential_id)
                {
                    conflict = true;
                }
            }
        })
        .map_err(map_snapshot_operation_error)?;
        if invalid || !has_passkey_capacity(existing_credential_ids.len()) {
            return Err(RecordOperationError::Failed);
        }
        if conflict {
            return Err(RecordOperationError::Conflict);
        }
        if self.manifest.entries().len() >= MAX_RECORDS {
            return Err(RecordOperationError::Failed);
        }
        let mut entropy = SystemEntropy;
        let id = self.allocate_record_id(&mut entropy)?;
        let credential_id = allocate_credential_id(&existing_credential_ids, &mut entropy)?;
        let private_key = generate_signing_key(&mut entropy)?;
        let signing_key =
            SigningKey::from_slice(&*private_key).map_err(|_| RecordOperationError::Failed)?;
        let encoded_point = signing_key.verifying_key().to_sec1_point(false);
        let public_key: [u8; PASSKEY_PUBLIC_KEY_BYTES] = encoded_point
            .as_bytes()
            .try_into()
            .map_err(|_| RecordOperationError::Failed)?;
        let user_handle = Zeroizing::new(input.user_handle.to_vec());
        let plaintext = PasskeyPlaintext::new(
            1,
            committed_at_ms,
            committed_at_ms,
            0,
            input.rp_id,
            input.user_handle,
            input.user_name,
            input.user_display_name,
            credential_id,
            private_key,
        )
        .map_err(|_| RecordOperationError::Failed)?;
        let plaintext_bytes = plaintext
            .encode()
            .map_err(|_| RecordOperationError::Failed)?;
        let mutation = self.prepare_plaintext_upsert(
            RecordMutationKind::Insert,
            id,
            &plaintext_bytes,
            committed_at_ms,
            &mut entropy,
        )?;
        Ok((
            mutation,
            PasskeyCredential {
                credential_id,
                user_handle,
                public_key,
            },
        ))
    }

    /// Lists public passkey metadata matching one exact assertion request.
    ///
    /// A request without an allow-list selects every credential for the exact
    /// RP ID. A present allow-list selects only supported exact 32-byte IDs;
    /// when none are supported it selects no credential. The complete snapshot
    /// is authenticated before any result is returned.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` for a noncanonical RP ID or oversized allow-list,
    /// `Cancelled` when request authority is revoked, and `Failed` for an
    /// integrity failure, duplicate credential ID, or oversized result.
    pub fn list_passkeys_for_assertion_with_check(
        &self,
        header_bytes: &[u8],
        manifest_envelope_bytes: &[u8],
        records: &[EncryptedRecord],
        rp_id: &str,
        allowed_credential_ids: Option<&[[u8; PASSKEY_CREDENTIAL_ID_BYTES]]>,
        should_cancel: impl FnMut() -> bool,
    ) -> Result<Vec<PasskeySummary>, RecordOperationError> {
        let allow_list_present = allowed_credential_ids.is_some();
        let allowed_credential_ids = allowed_credential_ids.unwrap_or_default();
        if allowed_credential_ids.len() > MAX_PASSKEY_ASSERTION_CANDIDATES {
            return Err(RecordOperationError::Conflict);
        }
        let expected_rp_id = normalize_rp_id(rp_id).map_err(|_| RecordOperationError::Conflict)?;
        if expected_rp_id.as_str() != rp_id {
            return Err(RecordOperationError::Conflict);
        }
        self.authenticate_snapshot_metadata(header_bytes, manifest_envelope_bytes)?;
        let mut credential_ids = BTreeSet::new();
        let mut passkeys = Vec::new();
        let mut invalid = false;
        visit_authenticated_records(self, records, should_cancel, |record| {
            if let DecryptedRecord::Passkey(passkey) = record {
                if !credential_ids.insert(passkey.credential_id) {
                    invalid = true;
                    return;
                }
                let is_allowed =
                    !allow_list_present || allowed_credential_ids.contains(&passkey.credential_id);
                if passkey.rp_id.as_str() == expected_rp_id.as_str() && is_allowed {
                    if passkeys.len() >= MAX_PASSKEY_ASSERTION_CANDIDATES {
                        invalid = true;
                        return;
                    }
                    passkeys.push(PasskeySummary {
                        credential_id: passkey.credential_id,
                        rp_id: passkey.rp_id,
                        user_handle: passkey.user_handle,
                        user_name: passkey.user_name,
                        user_display_name: passkey.user_display_name,
                    });
                }
            }
        })
        .map_err(map_snapshot_operation_error)?;
        if invalid {
            return Err(RecordOperationError::Failed);
        }
        Ok(passkeys)
    }

    /// Lists public metadata for every vault-backed passkey after authenticating
    /// the complete snapshot. Private keys and signature counters are absent.
    ///
    /// # Errors
    ///
    /// Returns `Cancelled` when request authority is revoked and `Failed` for
    /// an integrity failure, duplicate credential ID, or oversized result.
    pub fn list_passkeys_with_check(
        &self,
        header_bytes: &[u8],
        manifest_envelope_bytes: &[u8],
        records: &[EncryptedRecord],
        should_cancel: impl FnMut() -> bool,
    ) -> Result<Vec<PasskeySummary>, RecordOperationError> {
        self.authenticate_snapshot_metadata(header_bytes, manifest_envelope_bytes)?;
        let mut credential_ids = BTreeSet::new();
        let mut passkeys = Vec::new();
        let mut invalid = false;
        visit_authenticated_records(self, records, should_cancel, |record| {
            if let DecryptedRecord::Passkey(passkey) = record {
                if !credential_ids.insert(passkey.credential_id)
                    || passkeys.len() >= MAX_PASSKEY_ASSERTION_CANDIDATES
                {
                    invalid = true;
                    return;
                }
                passkeys.push(PasskeySummary {
                    credential_id: passkey.credential_id,
                    rp_id: passkey.rp_id,
                    user_handle: passkey.user_handle,
                    user_name: passkey.user_name,
                    user_display_name: passkey.user_display_name,
                });
            }
        })
        .map_err(map_snapshot_operation_error)?;
        if invalid {
            return Err(RecordOperationError::Failed);
        }
        passkeys.sort_by(|left, right| {
            left.rp_id
                .as_str()
                .cmp(right.rp_id.as_str())
                .then_with(|| left.user_name.as_str().cmp(right.user_name.as_str()))
                .then_with(|| left.credential_id.cmp(&right.credential_id))
        });
        Ok(passkeys)
    }

    /// Signs one exact `WebAuthn` assertion and prepares the counter update.
    ///
    /// `client_data_hash` must be the 32-byte hash decoded from the
    /// Windows-signed CTAP request. The core creates the authenticator data so
    /// a client cannot substitute a different RP hash, UV flag, or counter.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` only after the full snapshot authenticates,
    /// `Conflict` for an RP mismatch or exhausted counter, and `Cancelled` when
    /// request authority is revoked.
    #[allow(
        clippy::too_many_arguments,
        reason = "snapshot authentication and transaction-bound signing inputs remain explicit"
    )]
    pub fn prepare_passkey_assertion_with_check(
        &self,
        header_bytes: &[u8],
        manifest_envelope_bytes: &[u8],
        records: &[EncryptedRecord],
        rp_id: &str,
        credential_id: &[u8; PASSKEY_CREDENTIAL_ID_BYTES],
        client_data_hash: &[u8; 32],
        committed_at_ms: u64,
        should_cancel: impl FnMut() -> bool,
    ) -> Result<(PreparedRecordMutation, PasskeyAssertion), RecordOperationError> {
        self.authenticate_snapshot_metadata(header_bytes, manifest_envelope_bytes)?;
        let expected_rp_id = normalize_rp_id(rp_id).map_err(|_| RecordOperationError::Conflict)?;
        let mut found = None;
        let mut duplicate = false;
        visit_authenticated_records(self, records, should_cancel, |record| {
            if let DecryptedRecord::Passkey(passkey) = record
                && &passkey.credential_id == credential_id
                && found.replace(passkey).is_some()
            {
                duplicate = true;
            }
        })
        .map_err(map_snapshot_operation_error)?;
        if duplicate {
            return Err(RecordOperationError::Failed);
        }
        let passkey = found.ok_or(RecordOperationError::NotFound)?;
        if passkey.rp_id.as_str() != expected_rp_id.as_str() {
            return Err(RecordOperationError::Conflict);
        }
        let next_revision = passkey
            .revision
            .checked_add(1)
            .ok_or(RecordOperationError::Conflict)?;
        let next_counter = passkey
            .signature_counter
            .checked_add(1)
            .ok_or(RecordOperationError::Conflict)?;
        let mut authenticator_data = [0_u8; PASSKEY_AUTHENTICATOR_DATA_BYTES];
        authenticator_data[..32].copy_from_slice(&Sha256::digest(expected_rp_id.as_bytes()));
        authenticator_data[32] =
            PASSKEY_USER_PRESENT | PASSKEY_USER_VERIFIED | PASSKEY_BACKUP_ELIGIBLE;
        authenticator_data[33..].copy_from_slice(&next_counter.to_be_bytes());
        let mut signed_bytes = Zeroizing::new(Vec::with_capacity(
            PASSKEY_AUTHENTICATOR_DATA_BYTES + client_data_hash.len(),
        ));
        signed_bytes.extend_from_slice(&authenticator_data);
        signed_bytes.extend_from_slice(client_data_hash);
        let signing_key = SigningKey::from_slice(&*passkey.private_key)
            .map_err(|_| RecordOperationError::Failed)?;
        let signature: Signature = signing_key.sign(&signed_bytes);
        let signature_der = Zeroizing::new(signature.to_der().as_bytes().to_vec());
        let user_handle = Zeroizing::new(passkey.user_handle.to_vec());
        let committed_at_ms = passkey_update_time(
            passkey.created_at_ms,
            self.manifest.committed_at_ms(),
            committed_at_ms,
        );
        let plaintext = PasskeyPlaintext::new(
            next_revision,
            passkey.created_at_ms,
            committed_at_ms,
            next_counter,
            passkey.rp_id,
            passkey.user_handle,
            passkey.user_name,
            passkey.user_display_name,
            passkey.credential_id,
            passkey.private_key,
        )
        .map_err(|_| RecordOperationError::Failed)?;
        let mut entropy = SystemEntropy;
        let plaintext_bytes = plaintext
            .encode()
            .map_err(|_| RecordOperationError::Failed)?;
        let mutation = self.prepare_plaintext_upsert(
            RecordMutationKind::Update,
            passkey.id,
            &plaintext_bytes,
            committed_at_ms,
            &mut entropy,
        )?;
        Ok((
            mutation,
            PasskeyAssertion {
                credential_id: *credential_id,
                user_handle,
                authenticator_data,
                signature_der,
            },
        ))
    }

    /// Prepares deletion of one passkey selected by its public credential ID.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` only after complete snapshot authentication and
    /// `Cancelled` when request authority is revoked.
    pub fn prepare_delete_passkey_with_check(
        &self,
        header_bytes: &[u8],
        manifest_envelope_bytes: &[u8],
        records: &[EncryptedRecord],
        credential_id: &[u8; PASSKEY_CREDENTIAL_ID_BYTES],
        committed_at_ms: u64,
        should_cancel: impl FnMut() -> bool,
    ) -> Result<PreparedRecordMutation, RecordOperationError> {
        self.authenticate_snapshot_metadata(header_bytes, manifest_envelope_bytes)?;
        let mut found = None;
        let mut duplicate = false;
        visit_authenticated_records(self, records, should_cancel, |record| {
            if let DecryptedRecord::Passkey(passkey) = record
                && &passkey.credential_id == credential_id
                && found.replace(passkey.id).is_some()
            {
                duplicate = true;
            }
        })
        .map_err(map_snapshot_operation_error)?;
        if duplicate {
            return Err(RecordOperationError::Failed);
        }
        let id = found.ok_or(RecordOperationError::NotFound)?;
        let mut entries = self.manifest.entries().to_vec();
        entries.retain(|entry| entry.record_id() != id.as_bytes());
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

    fn authenticate_snapshot_metadata(
        &self,
        header_bytes: &[u8],
        manifest_envelope_bytes: &[u8],
    ) -> Result<(), RecordOperationError> {
        let header = VaultHeader::decode(header_bytes).map_err(|_| RecordOperationError::Failed)?;
        if header != self.header {
            return Err(RecordOperationError::Failed);
        }
        let manifest = decrypt_manifest(self, manifest_envelope_bytes)?;
        if manifest != self.manifest {
            return Err(RecordOperationError::Failed);
        }
        Ok(())
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
        let id = self.allocate_record_id(entropy)?;
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
        self.prepare_plaintext_upsert(kind, id, &plaintext_bytes, committed_at_ms, entropy)
    }

    fn allocate_record_id(
        &self,
        entropy: &mut impl EntropySource,
    ) -> Result<RecordId, RecordOperationError> {
        (0..MAX_RECORD_ID_ATTEMPTS)
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
            .ok_or(RecordOperationError::Failed)
    }

    fn prepare_plaintext_upsert(
        &self,
        kind: RecordMutationKind,
        id: RecordId,
        plaintext_bytes: &Zeroizing<Vec<u8>>,
        committed_at_ms: u64,
        entropy: &mut impl EntropySource,
    ) -> Result<PreparedRecordMutation, RecordOperationError> {
        let nonce = random_array(entropy).map_err(|_| RecordOperationError::Failed)?;
        let record_key = derive_record_key(self, id)?;
        let aad = encode_record_aad(self.vault_id(), id.as_bytes(), self.key_epoch());
        let ciphertext = encrypt_bytes(&record_key, &nonce, plaintext_bytes.as_slice(), &aad)
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
    visit_authenticated_records(vault, records, || cancellation.is_cancelled(), drop).map_err(
        |error| match error {
            SnapshotAuthenticationError::Cancelled => super::UnlockError::Cancelled,
            SnapshotAuthenticationError::Failed => super::UnlockError::Failed,
        },
    )?;
    if cancellation.is_cancelled() {
        return Err(super::UnlockError::Cancelled);
    }
    Ok(())
}

fn authenticate_records_only_with_check(
    vault: &UnlockedVault,
    records: &[EncryptedRecord],
    should_cancel: impl FnMut() -> bool,
) -> Result<(), RecordOperationError> {
    visit_authenticated_records(vault, records, should_cancel, drop)
        .map_err(map_snapshot_operation_error)
}

fn visit_authenticated_records(
    vault: &UnlockedVault,
    records: &[EncryptedRecord],
    mut should_cancel: impl FnMut() -> bool,
    mut visit: impl FnMut(DecryptedRecord),
) -> Result<(), SnapshotAuthenticationError> {
    if records.len() != vault.manifest.entries().len() || records.len() > MAX_RECORDS {
        return Err(SnapshotAuthenticationError::Failed);
    }
    if records
        .windows(2)
        .any(|pair| pair[0].id.as_bytes() >= pair[1].id.as_bytes())
    {
        return Err(SnapshotAuthenticationError::Failed);
    }
    for (record, commitment) in records.iter().zip(vault.manifest.entries()) {
        if should_cancel() {
            return Err(SnapshotAuthenticationError::Cancelled);
        }
        if record.id.as_bytes() != commitment.record_id()
            || Sha256::digest(record.envelope.as_slice()).as_slice() != commitment.envelope_digest()
        {
            return Err(SnapshotAuthenticationError::Failed);
        }
        visit(decrypt_record(vault, record)?);
    }
    Ok(())
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

fn decrypt_record(
    vault: &UnlockedVault,
    record: &EncryptedRecord,
) -> Result<DecryptedRecord, SnapshotAuthenticationError> {
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
    match record_type(&plaintext).map_err(|_| SnapshotAuthenticationError::Failed)? {
        RecordType::WebsiteAccount => decrypt_website_account_plaintext(record.id, &plaintext),
        RecordType::Passkey => decrypt_passkey_plaintext(record.id, &plaintext),
    }
}

fn decrypt_website_account_plaintext(
    id: RecordId,
    plaintext: &[u8],
) -> Result<DecryptedRecord, SnapshotAuthenticationError> {
    let decoded = WebsiteAccountPlaintext::decode(plaintext)
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
    Ok(DecryptedRecord::WebsiteAccount(WebsiteAccount {
        id,
        revision,
        created_at_ms,
        modified_at_ms,
        service_name,
        permitted_origin,
        username,
        password,
    }))
}

fn decrypt_passkey_plaintext(
    id: RecordId,
    plaintext: &[u8],
) -> Result<DecryptedRecord, SnapshotAuthenticationError> {
    let decoded =
        PasskeyPlaintext::decode(plaintext).map_err(|_| SnapshotAuthenticationError::Failed)?;
    let normalized =
        normalize_rp_id(decoded.rp_id()).map_err(|_| SnapshotAuthenticationError::Failed)?;
    if normalized.as_str() != decoded.rp_id() {
        return Err(SnapshotAuthenticationError::Failed);
    }
    SigningKey::from_slice(decoded.private_key())
        .map_err(|_| SnapshotAuthenticationError::Failed)?;
    let revision = decoded.revision();
    let created_at_ms = decoded.created_at_ms();
    let signature_counter = decoded.signature_counter();
    let (rp_id, user_handle, user_name, user_display_name, credential_id, private_key) =
        decoded.into_fields();
    Ok(DecryptedRecord::Passkey(PasskeyRecord {
        id,
        revision,
        created_at_ms,
        signature_counter,
        rp_id,
        user_handle,
        user_name,
        user_display_name,
        credential_id,
        private_key,
    }))
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

fn normalize_rp_id(value: &str) -> Result<Zeroizing<String>, PasskeyInputError> {
    if value.is_empty()
        || value.len() > MAX_PASSKEY_RP_ID_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(if value.len() > MAX_PASSKEY_RP_ID_BYTES {
            PasskeyInputError::FieldTooLarge
        } else {
            PasskeyInputError::InvalidRpId
        });
    }
    let parsed =
        Url::parse(&format!("https://{value}")).map_err(|_| PasskeyInputError::InvalidRpId)?;
    if parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(PasskeyInputError::InvalidRpId);
    }
    let host = parsed
        .host_str()
        .ok_or(PasskeyInputError::InvalidRpId)?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty() || host.len() > MAX_PASSKEY_RP_ID_BYTES || value.ends_with('.') {
        return Err(PasskeyInputError::InvalidRpId);
    }
    Ok(Zeroizing::new(host))
}

fn allocate_credential_id(
    existing: &BTreeSet<[u8; PASSKEY_CREDENTIAL_ID_BYTES]>,
    entropy: &mut impl EntropySource,
) -> Result<[u8; PASSKEY_CREDENTIAL_ID_BYTES], RecordOperationError> {
    (0..MAX_RECORD_ID_ATTEMPTS)
        .find_map(|_| {
            let candidate: [u8; PASSKEY_CREDENTIAL_ID_BYTES] = random_array(entropy).ok()?;
            (candidate != [0; PASSKEY_CREDENTIAL_ID_BYTES] && !existing.contains(&candidate))
                .then_some(candidate)
        })
        .ok_or(RecordOperationError::Failed)
}

const fn has_passkey_capacity(existing: usize) -> bool {
    existing < MAX_PASSKEY_CREDENTIALS
}

fn passkey_update_time(
    created_at_ms: u64,
    manifest_committed_at_ms: u64,
    wall_clock_ms: u64,
) -> u64 {
    wall_clock_ms
        .max(created_at_ms)
        .max(manifest_committed_at_ms)
}

fn generate_signing_key(
    entropy: &mut impl EntropySource,
) -> Result<Zeroizing<[u8; PASSKEY_PRIVATE_KEY_BYTES]>, RecordOperationError> {
    for _ in 0..MAX_RECORD_ID_ATTEMPTS {
        let mut candidate = Zeroizing::new([0_u8; PASSKEY_PRIVATE_KEY_BYTES]);
        entropy
            .fill(candidate.as_mut())
            .map_err(|_| RecordOperationError::Failed)?;
        if SigningKey::from_slice(candidate.as_ref()).is_ok() {
            return Ok(candidate);
        }
    }
    Err(RecordOperationError::Failed)
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

const fn map_snapshot_operation_error(error: SnapshotAuthenticationError) -> RecordOperationError {
    match error {
        SnapshotAuthenticationError::Cancelled => RecordOperationError::Cancelled,
        SnapshotAuthenticationError::Failed => RecordOperationError::Failed,
    }
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

    use super::{
        WebsiteAccountInput, WebsiteAccountInputError, has_passkey_capacity, passkey_update_time,
    };

    #[test]
    fn passkey_capacity_stops_before_management_encoding_overflows() {
        assert!(has_passkey_capacity(63));
        assert!(!has_passkey_capacity(64));
        assert!(!has_passkey_capacity(65));
    }

    #[test]
    fn passkey_update_time_never_precedes_the_record_or_manifest() {
        assert_eq!(passkey_update_time(20, 30, 10), 30);
        assert_eq!(passkey_update_time(30, 20, 10), 30);
        assert_eq!(passkey_update_time(20, 30, 40), 40);
    }

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
