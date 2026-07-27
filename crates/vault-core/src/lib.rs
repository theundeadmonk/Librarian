//! Portable vault-key lifecycle for Librarian.
//!
//! Cryptography and secret-bearing state live here. `SQLite` ownership remains
//! in `librarian-vault-agent`, and production credential APIs remain disabled
//! until ADR 0005's independent review gate completes.

#![forbid(unsafe_code)]

use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
pub use librarian_vault_format::FormatReadiness;
use librarian_vault_format::{
    ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, ARGON2_TIME_COST, Manifest, ManifestEnvelope,
    MasterWrapper, RecoveryWrapper, VaultHeader, WindowsHelloProtector, encode_manifest_aad,
    encode_master_wrapper_aad, encode_recovery_wrapper_aad, encode_windows_hello_wrapper_aad,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

mod records;

pub use records::{
    EncryptedRecord, PreparedRecordMutation, RecordId, RecordMutationKind, RecordOperationError,
    WebsiteAccount, WebsiteAccountInput, WebsiteAccountInputError,
};

const KEY_BYTES: usize = 32;
const WRAPPED_KEY_BYTES: usize = 48;
const INITIAL_KEY_EPOCH: u32 = 1;
const MAX_MASTER_PASSWORD_BYTES: usize = 1024;
const MASTER_WRAP_LABEL: &[u8] = b"librarian/vault/v1/master-wrap";
const RECOVERY_WRAP_LABEL: &[u8] = b"librarian/vault/v1/recovery-wrap";
const WINDOWS_HELLO_WRAP_LABEL: &[u8] = b"librarian/vault/v1/windows-hello-wrap";
const WINDOWS_HELLO_INSTALLATION_ID_LABEL: &[u8] =
    b"librarian/vault/v1/windows-hello-installation-id";
const MANIFEST_LABEL_PREFIX: &[u8] = b"librarian/vault/v1/manifest/";

/// Reports whether this revision may store production credentials.
#[must_use]
pub const fn credential_storage_is_approved() -> bool {
    match librarian_vault_format::readiness() {
        FormatReadiness::ScaffoldOnly => false,
    }
}

/// A master password whose allocation is cleared on drop.
///
/// This type intentionally does not implement `Debug`, `Display`, `Clone`,
/// serialization, or equality.
pub struct MasterPassword(Zeroizing<Vec<u8>>);

impl MasterPassword {
    /// Copies the exact UTF-8 bytes without trimming or normalization.
    ///
    /// # Errors
    ///
    /// Returns `PasswordInputError` when the UTF-8 input exceeds the
    /// version-1 bound.
    pub fn new(value: &str) -> Result<Self, PasswordInputError> {
        if value.len() > MAX_MASTER_PASSWORD_BYTES {
            return Err(PasswordInputError);
        }
        Ok(Self(Zeroizing::new(value.as_bytes().to_vec())))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Master-password input is invalid before any vault operation begins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasswordInputError;

impl fmt::Display for PasswordInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("master password input is invalid")
    }
}

impl std::error::Error for PasswordInputError {}

/// The independent recovery material generated with a new vault.
///
/// The recovery UX is owned by Slice 4. Until then this type deliberately
/// exposes no byte-access API that could copy the key into non-zeroizing
/// memory.
pub struct RecoveryKey(
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "recovery material remains opaque until the Slice 4 encoded-output API"
        )
    )]
    Zeroizing<[u8; KEY_BYTES]>,
);

/// One transient 32-byte `WebAuthn` PRF result released after Windows-owned user
/// verification. The allocation is move-only, unformattable, and zeroized on
/// drop.
pub struct WindowsHelloPrfOutput(Zeroizing<[u8; KEY_BYTES]>);

impl WindowsHelloPrfOutput {
    #[must_use]
    pub fn new(value: [u8; KEY_BYTES]) -> Self {
        Self(Zeroizing::new(value))
    }

    fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

/// Agent-owned installation secret used to make a Windows Hello protector
/// unusable when copied to another Librarian installation.
///
/// This value must be persisted by the trusted agent using an OS-protected
/// store. It is move-only, unformattable, and zeroized on drop.
pub struct WindowsHelloInstallationKey(Zeroizing<[u8; KEY_BYTES]>);

impl WindowsHelloInstallationKey {
    #[must_use]
    pub fn new(value: [u8; KEY_BYTES]) -> Self {
        Self(Zeroizing::new(value))
    }

    #[must_use]
    pub fn from_zeroizing(value: Zeroizing<[u8; KEY_BYTES]>) -> Self {
        Self(value)
    }

    fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

/// A cancellation signal checked before and after expensive unlock work.
#[derive(Default)]
pub struct CancellationFlag(AtomicBool);

impl CancellationFlag {
    #[must_use]
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Non-secret failures while creating a brand-new vault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateVaultError {
    RandomnessUnavailable,
    CryptographicFailure,
    FormatFailure,
}

impl fmt::Display for CreateVaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RandomnessUnavailable => "operating-system randomness is unavailable",
            Self::CryptographicFailure => "vault cryptographic initialization failed",
            Self::FormatFailure => "vault format initialization failed",
        })
    }
}

impl std::error::Error for CreateVaultError {}

/// The deliberately uniform public result of an unlock attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnlockError {
    Failed,
    Cancelled,
}

impl fmt::Display for UnlockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Failed => "vault unlock failed",
            Self::Cancelled => "vault unlock was cancelled",
        })
    }
}

impl std::error::Error for UnlockError {}

/// Bytes ready for the agent's atomic initial `SQLite` transaction.
///
/// This type owns an unlocked session so vault creation can transition directly
/// into the unlocked state without re-running the password KDF.
pub struct CreatedVault {
    header: Vec<u8>,
    manifest_envelope: Vec<u8>,
    recovery_key: RecoveryKey,
    session: UnlockedVault,
}

impl CreatedVault {
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>, RecoveryKey, UnlockedVault) {
        (
            self.header,
            self.manifest_envelope,
            self.recovery_key,
            self.session,
        )
    }
}

/// The only reusable plaintext root-key state for an unlocked vault.
///
/// The key is zeroized when this value is dropped. This type intentionally
/// implements none of the formatting, cloning, serialization, or equality
/// traits.
pub struct UnlockedVault {
    vault_root_key: Zeroizing<[u8; KEY_BYTES]>,
    header: VaultHeader,
    manifest: Manifest,
}

impl UnlockedVault {
    #[must_use]
    pub const fn vault_id(&self) -> &[u8; 16] {
        self.header.vault_id()
    }

    #[must_use]
    pub const fn key_epoch(&self) -> u32 {
        self.header.key_epoch()
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.manifest.generation()
    }

    /// Wraps this session's VRK for one installation-bound Windows Hello
    /// credential. The returned canonical bytes contain no PRF output or
    /// plaintext key and are not part of the portable vault or backup.
    ///
    /// # Errors
    ///
    /// Returns a non-secret format, randomness, or cryptographic failure.
    pub fn create_windows_hello_protector(
        &self,
        installation_key: &WindowsHelloInstallationKey,
        credential_id: &[u8],
        prf_salt: [u8; 32],
        prf_output: WindowsHelloPrfOutput,
    ) -> Result<Vec<u8>, CreateVaultError> {
        let mut entropy = SystemEntropy;
        let nonce = random_array(&mut entropy)?;
        let installation_id = windows_hello_installation_id(installation_key.as_bytes());
        let template = WindowsHelloProtector::new(
            *self.vault_id(),
            self.key_epoch(),
            installation_id,
            credential_id.to_vec(),
            prf_salt,
            nonce,
            [0; WRAPPED_KEY_BYTES],
        )
        .map_err(|_| CreateVaultError::FormatFailure)?;
        let wrapping_key = derive_windows_hello_wrapping_key(
            prf_output.as_bytes(),
            installation_key.as_bytes(),
            self.vault_id(),
        )
        .map_err(|()| CreateVaultError::CryptographicFailure)?;
        drop(prf_output);
        let wrapped_vrk = encrypt_fixed_key(
            &wrapping_key,
            template.nonce(),
            self.root_key(),
            &encode_windows_hello_wrapper_aad(&template),
        )?;
        WindowsHelloProtector::new(
            *template.vault_id(),
            template.key_epoch(),
            *template.installation_id(),
            template.credential_id().to_vec(),
            *template.prf_salt(),
            *template.nonce(),
            wrapped_vrk,
        )
        .and_then(|protector| protector.encode())
        .map_err(|_| CreateVaultError::FormatFailure)
    }

    /// A private proof that the key allocation is retained by this session.
    fn root_key(&self) -> &[u8; KEY_BYTES] {
        &self.vault_root_key
    }
}

/// Creates an empty version-1 vault using the operating-system CSPRNG.
///
/// # Errors
///
/// Returns a non-secret creation error if operating-system randomness,
/// cryptographic initialization, or canonical format construction fails.
pub fn create_vault(
    password: MasterPassword,
    created_at_ms: u64,
) -> Result<CreatedVault, CreateVaultError> {
    create_vault_with_entropy(password, created_at_ms, &mut SystemEntropy)
}

/// Authenticates an empty version-1 vault through its master-password wrapper.
///
/// All parse, version, corruption, and authentication failures collapse to
/// `UnlockError::Failed`. There is no automatic fallback to another method.
///
/// # Errors
///
/// Returns `Cancelled` when the supplied flag wins the attempt, and `Failed`
/// for every other unsuccessful unlock condition.
pub fn unlock_vault(
    password: MasterPassword,
    header_bytes: &[u8],
    manifest_envelope_bytes: &[u8],
    records: &[EncryptedRecord],
    cancellation: &CancellationFlag,
) -> Result<UnlockedVault, UnlockError> {
    if cancellation.is_cancelled() {
        return Err(UnlockError::Cancelled);
    }

    let header = VaultHeader::decode(header_bytes).map_err(|_| UnlockError::Failed)?;
    let envelope =
        ManifestEnvelope::decode(manifest_envelope_bytes).map_err(|_| UnlockError::Failed)?;

    let password_key =
        derive_password_key(password.as_bytes(), header.master_wrapper().password_salt())
            .map_err(|()| UnlockError::Failed)?;
    drop(password);
    if cancellation.is_cancelled() {
        return Err(UnlockError::Cancelled);
    }

    let master_kek = derive_key(&password_key[..], header.vault_id(), MASTER_WRAP_LABEL)
        .map_err(|()| UnlockError::Failed)?;
    let master_aad = encode_master_wrapper_aad(
        header.vault_id(),
        header.key_epoch(),
        header.master_wrapper().password_salt(),
    );
    let vault_root_key = decrypt_fixed_key(
        &master_kek,
        header.master_wrapper().nonce(),
        header.master_wrapper().wrapped_vrk(),
        &master_aad,
    )
    .map_err(|()| UnlockError::Failed)?;
    authenticate_vault_root_key(vault_root_key, header, &envelope, records, cancellation)
}

/// Authenticates a vault through an installation-bound Windows Hello
/// protector. Every parse, binding, corruption, credential mismatch, and
/// cryptographic failure collapses to `UnlockError::Failed`.
///
/// # Errors
///
/// Returns `Cancelled` when cancellation wins and `Failed` for every other
/// unsuccessful unlock condition.
#[allow(
    clippy::too_many_arguments,
    reason = "the explicit trust-boundary inputs must not be bundled into a cloneable request value"
)]
pub fn unlock_vault_with_windows_hello(
    prf_output: WindowsHelloPrfOutput,
    installation_key: &WindowsHelloInstallationKey,
    credential_id: &[u8],
    protector_bytes: &[u8],
    header_bytes: &[u8],
    manifest_envelope_bytes: &[u8],
    records: &[EncryptedRecord],
    cancellation: &CancellationFlag,
) -> Result<UnlockedVault, UnlockError> {
    if cancellation.is_cancelled() {
        return Err(UnlockError::Cancelled);
    }
    let header = VaultHeader::decode(header_bytes).map_err(|_| UnlockError::Failed)?;
    let envelope =
        ManifestEnvelope::decode(manifest_envelope_bytes).map_err(|_| UnlockError::Failed)?;
    let protector =
        WindowsHelloProtector::decode(protector_bytes).map_err(|_| UnlockError::Failed)?;
    let installation_id = windows_hello_installation_id(installation_key.as_bytes());
    if protector.vault_id() != header.vault_id()
        || protector.key_epoch() != header.key_epoch()
        || protector.installation_id() != &installation_id
        || protector.credential_id() != credential_id
    {
        return Err(UnlockError::Failed);
    }
    let wrapping_key = derive_windows_hello_wrapping_key(
        prf_output.as_bytes(),
        installation_key.as_bytes(),
        header.vault_id(),
    )
    .map_err(|()| UnlockError::Failed)?;
    drop(prf_output);
    if cancellation.is_cancelled() {
        return Err(UnlockError::Cancelled);
    }
    let vault_root_key = decrypt_fixed_key(
        &wrapping_key,
        protector.nonce(),
        protector.wrapped_vrk(),
        &encode_windows_hello_wrapper_aad(&protector),
    )
    .map_err(|()| UnlockError::Failed)?;
    authenticate_vault_root_key(vault_root_key, header, &envelope, records, cancellation)
}

fn authenticate_vault_root_key(
    vault_root_key: Zeroizing<[u8; KEY_BYTES]>,
    header: VaultHeader,
    envelope: &ManifestEnvelope,
    records: &[EncryptedRecord],
    cancellation: &CancellationFlag,
) -> Result<UnlockedVault, UnlockError> {
    let manifest_key =
        derive_manifest_key(&vault_root_key[..], header.vault_id(), header.key_epoch())
            .map_err(|()| UnlockError::Failed)?;
    let manifest_aad = encode_manifest_aad(&header, envelope.nonce());
    let manifest_plaintext = decrypt_bytes(
        &manifest_key,
        envelope.nonce(),
        envelope.ciphertext(),
        &manifest_aad,
    )
    .map_err(|()| UnlockError::Failed)?;
    let manifest = Manifest::decode(&manifest_plaintext).map_err(|_| UnlockError::Failed)?;

    if cancellation.is_cancelled() {
        return Err(UnlockError::Cancelled);
    }
    if manifest.key_epoch() != header.key_epoch()
        || manifest.vault_schema() != librarian_vault_format::VAULT_SCHEMA
    {
        return Err(UnlockError::Failed);
    }

    let unlocked = UnlockedVault {
        vault_root_key,
        header,
        manifest,
    };
    records::authenticate_records(&unlocked, records, cancellation)?;
    Ok(unlocked)
}

/// Authenticates a version-1 vault that is expected to contain no records.
///
/// This compatibility entry point keeps the lifecycle tests explicit while
/// the agent uses [`unlock_vault`] for general vaults.
///
/// # Errors
///
/// Returns the same deliberately uniform error classes as [`unlock_vault`].
pub fn unlock_empty_vault(
    password: MasterPassword,
    header_bytes: &[u8],
    manifest_envelope_bytes: &[u8],
    cancellation: &CancellationFlag,
) -> Result<UnlockedVault, UnlockError> {
    unlock_vault(
        password,
        header_bytes,
        manifest_envelope_bytes,
        &[],
        cancellation,
    )
}

trait EntropySource {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), CreateVaultError>;
}

struct SystemEntropy;

impl EntropySource for SystemEntropy {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), CreateVaultError> {
        getrandom::fill(destination).map_err(|_| CreateVaultError::RandomnessUnavailable)
    }
}

fn create_vault_with_entropy(
    password: MasterPassword,
    created_at_ms: u64,
    entropy: &mut impl EntropySource,
) -> Result<CreatedVault, CreateVaultError> {
    let vault_id = random_array(entropy)?;
    let vault_root_key = random_secret_array(entropy)?;
    let recovery_key_bytes = random_secret_array(entropy)?;
    let password_salt = random_array(entropy)?;
    let master_nonce = random_array(entropy)?;
    let recovery_nonce = random_array(entropy)?;
    let manifest_nonce = random_array(entropy)?;

    let password_key = derive_password_key(password.as_bytes(), &password_salt)
        .map_err(|()| CreateVaultError::CryptographicFailure)?;
    drop(password);
    let master_kek = derive_key(&password_key[..], &vault_id, MASTER_WRAP_LABEL)
        .map_err(|()| CreateVaultError::CryptographicFailure)?;
    let master_aad = encode_master_wrapper_aad(&vault_id, INITIAL_KEY_EPOCH, &password_salt);
    let master_wrapped_vrk =
        encrypt_fixed_key(&master_kek, &master_nonce, &vault_root_key, &master_aad)?;

    let recovery_kek = derive_key(&recovery_key_bytes[..], &vault_id, RECOVERY_WRAP_LABEL)
        .map_err(|()| CreateVaultError::CryptographicFailure)?;
    let recovery_aad = encode_recovery_wrapper_aad(&vault_id, INITIAL_KEY_EPOCH);
    let recovery_wrapped_vrk = encrypt_fixed_key(
        &recovery_kek,
        &recovery_nonce,
        &vault_root_key,
        &recovery_aad,
    )?;

    let header = VaultHeader::new(
        vault_id,
        INITIAL_KEY_EPOCH,
        MasterWrapper::new(password_salt, master_nonce, master_wrapped_vrk),
        RecoveryWrapper::new(recovery_nonce, recovery_wrapped_vrk),
    );
    let header_bytes = header
        .encode()
        .map_err(|_| CreateVaultError::FormatFailure)?;

    let manifest = Manifest::empty(created_at_ms, INITIAL_KEY_EPOCH);
    let manifest_plaintext = Zeroizing::new(
        manifest
            .encode()
            .map_err(|_| CreateVaultError::FormatFailure)?,
    );
    let manifest_key = derive_manifest_key(&vault_root_key[..], &vault_id, INITIAL_KEY_EPOCH)
        .map_err(|()| CreateVaultError::CryptographicFailure)?;
    let manifest_aad = encode_manifest_aad(&header, &manifest_nonce);
    let manifest_ciphertext = encrypt_bytes(
        &manifest_key,
        &manifest_nonce,
        &manifest_plaintext,
        &manifest_aad,
    )?;
    let manifest_envelope = ManifestEnvelope::new(manifest_nonce, manifest_ciphertext)
        .and_then(|value| value.encode())
        .map_err(|_| CreateVaultError::FormatFailure)?;

    // Prove the produced bytes pass the same parser before the agent publishes
    // them. The expensive KDF is not repeated here.
    VaultHeader::decode(&header_bytes).map_err(|_| CreateVaultError::FormatFailure)?;
    ManifestEnvelope::decode(&manifest_envelope).map_err(|_| CreateVaultError::FormatFailure)?;

    let session = UnlockedVault {
        vault_root_key,
        header,
        manifest,
    };
    let _ = session.root_key();

    Ok(CreatedVault {
        header: header_bytes,
        manifest_envelope,
        recovery_key: RecoveryKey(recovery_key_bytes),
        session,
    })
}

fn random_array<const LENGTH: usize>(
    entropy: &mut impl EntropySource,
) -> Result<[u8; LENGTH], CreateVaultError> {
    let mut value = [0_u8; LENGTH];
    entropy.fill(&mut value)?;
    Ok(value)
}

fn random_secret_array<const LENGTH: usize>(
    entropy: &mut impl EntropySource,
) -> Result<Zeroizing<[u8; LENGTH]>, CreateVaultError> {
    let mut value = Zeroizing::new([0_u8; LENGTH]);
    entropy.fill(value.as_mut())?;
    Ok(value)
}

fn derive_password_key(password: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; KEY_BYTES]>, ()> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(KEY_BYTES),
    )
    .map_err(|_| ())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0_u8; KEY_BYTES]);
    argon2
        .hash_password_into(password, salt, output.as_mut())
        .map_err(|_| ())?;
    Ok(output)
}

fn derive_key(
    input_key: &[u8],
    vault_id: &[u8; 16],
    label: &[u8],
) -> Result<Zeroizing<[u8; KEY_BYTES]>, ()> {
    let hkdf = Hkdf::<Sha256>::new(Some(vault_id), input_key);
    let mut output = Zeroizing::new([0_u8; KEY_BYTES]);
    hkdf.expand(label, output.as_mut()).map_err(|_| ())?;
    Ok(output)
}

fn windows_hello_installation_id(installation_key: &[u8; KEY_BYTES]) -> [u8; KEY_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(WINDOWS_HELLO_INSTALLATION_ID_LABEL);
    hasher.update(installation_key);
    hasher.finalize().into()
}

fn derive_windows_hello_wrapping_key(
    prf_output: &[u8; KEY_BYTES],
    installation_key: &[u8; KEY_BYTES],
    vault_id: &[u8; 16],
) -> Result<Zeroizing<[u8; KEY_BYTES]>, ()> {
    let mut input_key = Zeroizing::new([0_u8; KEY_BYTES * 2]);
    input_key[..KEY_BYTES].copy_from_slice(prf_output);
    input_key[KEY_BYTES..].copy_from_slice(installation_key);
    derive_key(&input_key[..], vault_id, WINDOWS_HELLO_WRAP_LABEL)
}

fn derive_manifest_key(
    vault_root_key: &[u8],
    vault_id: &[u8; 16],
    key_epoch: u32,
) -> Result<Zeroizing<[u8; KEY_BYTES]>, ()> {
    let mut label = Vec::with_capacity(MANIFEST_LABEL_PREFIX.len() + 4);
    label.extend_from_slice(MANIFEST_LABEL_PREFIX);
    label.extend_from_slice(&key_epoch.to_be_bytes());
    derive_key(vault_root_key, vault_id, &label)
}

fn encrypt_fixed_key(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; 24],
    plaintext: &[u8; KEY_BYTES],
    aad: &[u8],
) -> Result<[u8; WRAPPED_KEY_BYTES], CreateVaultError> {
    let ciphertext = encrypt_bytes(key, nonce, plaintext, aad)?;
    ciphertext
        .try_into()
        .map_err(|_| CreateVaultError::CryptographicFailure)
}

fn encrypt_bytes(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; 24],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CreateVaultError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CreateVaultError::CryptographicFailure)?;
    let nonce = XNonce::from(*nonce);
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CreateVaultError::CryptographicFailure)
}

fn decrypt_fixed_key(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; 24],
    ciphertext: &[u8; WRAPPED_KEY_BYTES],
    aad: &[u8],
) -> Result<Zeroizing<[u8; KEY_BYTES]>, ()> {
    let plaintext = decrypt_bytes(key, nonce, ciphertext, aad)?;
    let mut result = Zeroizing::new([0_u8; KEY_BYTES]);
    if plaintext.len() != KEY_BYTES {
        return Err(());
    }
    result.copy_from_slice(&plaintext);
    Ok(result)
}

fn decrypt_bytes(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ()> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| ())?;
    let nonce = XNonce::from(*nonce);
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| ())?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use hkdf::Hkdf;
    use sha2::{Digest, Sha256};

    use super::{
        CancellationFlag, CreateVaultError, EntropySource, MasterPassword, UnlockError,
        WindowsHelloInstallationKey, WindowsHelloPrfOutput, create_vault_with_entropy,
        unlock_empty_vault, unlock_vault_with_windows_hello,
    };

    struct DeterministicEntropy(u8);

    impl DeterministicEntropy {
        const fn new() -> Self {
            Self(1)
        }
    }

    impl EntropySource for DeterministicEntropy {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CreateVaultError> {
            for byte in destination {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    fn deterministic_vault(password: &str) -> super::CreatedVault {
        create_vault_with_entropy(
            MasterPassword::new(password).expect("test password is valid"),
            1_700_000_000_000,
            &mut DeterministicEntropy::new(),
        )
        .expect("deterministic vault creation must succeed")
    }

    #[test]
    fn exact_password_unlocks_the_created_empty_vault() {
        let created = deterministic_vault("correct horse battery staple");
        let (header, manifest, _recovery, _initial_session) = created.into_parts();
        let unlocked = unlock_empty_vault(
            MasterPassword::new("correct horse battery staple").expect("valid password"),
            &header,
            &manifest,
            &CancellationFlag::new(),
        )
        .expect("correct password must unlock");

        assert_eq!(unlocked.key_epoch(), 1);
        assert_eq!(unlocked.generation(), 0);
    }

    #[test]
    fn recovery_wrapper_releases_the_same_vault_root_key() {
        let created = deterministic_vault("recovery-wrapper password");
        let (header_bytes, _manifest, recovery_unlock_key, initial_session) = created.into_parts();
        let header = librarian_vault_format::VaultHeader::decode(&header_bytes)
            .expect("created header must decode");
        let derived_recovery_kek = super::derive_key(
            &recovery_unlock_key.0[..],
            header.vault_id(),
            super::RECOVERY_WRAP_LABEL,
        )
        .expect("recovery key derivation must succeed");
        let recovery_aad = librarian_vault_format::encode_recovery_wrapper_aad(
            header.vault_id(),
            header.key_epoch(),
        );
        let recovered_root = super::decrypt_fixed_key(
            &derived_recovery_kek,
            header.recovery_wrapper().nonce(),
            header.recovery_wrapper().wrapped_vrk(),
            &recovery_aad,
        )
        .expect("recovery wrapper must authenticate");

        assert_eq!(
            Sha256::digest(recovered_root.as_slice()),
            Sha256::digest(initial_session.root_key())
        );
    }

    #[test]
    fn windows_hello_protector_releases_the_same_vault_root_key() {
        let created = deterministic_vault("hello password");
        let (header, manifest, _recovery, initial_session) = created.into_parts();
        let installation_key = [0x71; 32];
        let credential_id = [0x72; 64];
        let prf_salt = [0x73; 32];
        let prf = [0x74; 32];
        let protector = initial_session
            .create_windows_hello_protector(
                &WindowsHelloInstallationKey::new(installation_key),
                &credential_id,
                prf_salt,
                WindowsHelloPrfOutput::new(prf),
            )
            .expect("Hello protector");

        let unlocked = unlock_vault_with_windows_hello(
            WindowsHelloPrfOutput::new(prf),
            &WindowsHelloInstallationKey::new(installation_key),
            &credential_id,
            &protector,
            &header,
            &manifest,
            &[],
            &CancellationFlag::new(),
        )
        .expect("Hello unlock");
        assert_eq!(unlocked.vault_id(), initial_session.vault_id());
        assert_eq!(unlocked.key_epoch(), initial_session.key_epoch());
        assert_eq!(unlocked.generation(), initial_session.generation());

        let password_unlocked = unlock_empty_vault(
            MasterPassword::new("hello password").expect("password"),
            &header,
            &manifest,
            &CancellationFlag::new(),
        )
        .expect("master wrapper remains independent");
        assert_eq!(password_unlocked.vault_id(), initial_session.vault_id());
    }

    #[test]
    fn windows_hello_binding_and_corruption_fail_uniformly() {
        let created = deterministic_vault("Hello fallback password");
        let (header, manifest, _recovery, session) = created.into_parts();
        let installation_key = [0x81; 32];
        let credential_id = [0x82; 64];
        let prf_salt = [0x83; 32];
        let prf = [0x84; 32];
        let protector = session
            .create_windows_hello_protector(
                &WindowsHelloInstallationKey::new(installation_key),
                &credential_id,
                prf_salt,
                WindowsHelloPrfOutput::new(prf),
            )
            .expect("Hello protector");

        let wrong_prf = unlock_vault_with_windows_hello(
            WindowsHelloPrfOutput::new([0x85; 32]),
            &WindowsHelloInstallationKey::new(installation_key),
            &credential_id,
            &protector,
            &header,
            &manifest,
            &[],
            &CancellationFlag::new(),
        );
        let wrong_installation = unlock_vault_with_windows_hello(
            WindowsHelloPrfOutput::new(prf),
            &WindowsHelloInstallationKey::new([0x86; 32]),
            &credential_id,
            &protector,
            &header,
            &manifest,
            &[],
            &CancellationFlag::new(),
        );
        let wrong_credential = unlock_vault_with_windows_hello(
            WindowsHelloPrfOutput::new(prf),
            &WindowsHelloInstallationKey::new(installation_key),
            &[0x87; 64],
            &protector,
            &header,
            &manifest,
            &[],
            &CancellationFlag::new(),
        );
        let mut corrupted = protector;
        let last = corrupted.last_mut().expect("protector is not empty");
        *last ^= 1;
        let corrupt = unlock_vault_with_windows_hello(
            WindowsHelloPrfOutput::new(prf),
            &WindowsHelloInstallationKey::new(installation_key),
            &credential_id,
            &corrupted,
            &header,
            &manifest,
            &[],
            &CancellationFlag::new(),
        );

        assert!(matches!(wrong_prf, Err(UnlockError::Failed)));
        assert!(matches!(wrong_installation, Err(UnlockError::Failed)));
        assert!(matches!(wrong_credential, Err(UnlockError::Failed)));
        assert!(matches!(corrupt, Err(UnlockError::Failed)));
    }

    #[test]
    fn password_bytes_are_not_trimmed_or_normalized() {
        let created = deterministic_vault(" space matters ");
        let (header, manifest, _recovery, _initial_session) = created.into_parts();
        assert!(matches!(
            unlock_empty_vault(
                MasterPassword::new("space matters").expect("valid password"),
                &header,
                &manifest,
                &CancellationFlag::new(),
            ),
            Err(UnlockError::Failed)
        ));
    }

    #[test]
    fn wrong_password_and_tampering_share_the_public_failure() {
        let created = deterministic_vault("right password");
        let (header, manifest, _recovery, _initial_session) = created.into_parts();

        let wrong = unlock_empty_vault(
            MasterPassword::new("wrong password").expect("valid password"),
            &header,
            &manifest,
            &CancellationFlag::new(),
        );

        let mut tampered_manifest = manifest;
        let last = tampered_manifest
            .last_mut()
            .expect("manifest envelope is not empty");
        *last ^= 1;
        let tampered = unlock_empty_vault(
            MasterPassword::new("right password").expect("valid password"),
            &header,
            &tampered_manifest,
            &CancellationFlag::new(),
        );

        assert!(matches!(wrong, Err(UnlockError::Failed)));
        assert!(matches!(tampered, Err(UnlockError::Failed)));
    }

    #[test]
    fn cancelled_unlock_does_no_work_and_releases_no_session() {
        let created = deterministic_vault("cancel me");
        let (header, manifest, _recovery, _initial_session) = created.into_parts();
        let cancellation = CancellationFlag::new();
        cancellation.cancel();

        assert!(matches!(
            unlock_empty_vault(
                MasterPassword::new("cancel me").expect("valid password"),
                &header,
                &manifest,
                &cancellation,
            ),
            Err(UnlockError::Cancelled)
        ));
    }

    #[test]
    fn deterministic_inputs_produce_stable_complete_format_bytes() {
        let first = deterministic_vault("vector password");
        let second = deterministic_vault("vector password");
        let (first_header, first_manifest, _first_recovery, _first_session) = first.into_parts();
        let (second_header, second_manifest, _second_recovery, _second_session) =
            second.into_parts();

        assert_eq!(first_header, second_header);
        assert_eq!(first_manifest, second_manifest);

        let mut digest = Sha256::new();
        digest.update(
            u64::try_from(first_header.len())
                .expect("header length must fit")
                .to_be_bytes(),
        );
        digest.update(&first_header);
        digest.update(
            u64::try_from(first_manifest.len())
                .expect("manifest length must fit")
                .to_be_bytes(),
        );
        digest.update(&first_manifest);
        assert_eq!(
            to_hex(&digest.finalize()),
            include_str!("../../../tests/test-vectors/vault-format-v1/empty-vault-v1.sha256")
                .trim()
        );
    }

    #[test]
    fn fresh_system_entropy_changes_new_vault_material() {
        let first = super::create_vault(
            MasterPassword::new("same password").expect("valid password"),
            1,
        )
        .expect("first vault must be created");
        let second = super::create_vault(
            MasterPassword::new("same password").expect("valid password"),
            1,
        )
        .expect("second vault must be created");
        let (first_header, _, _, _) = first.into_parts();
        let (second_header, _, _, _) = second.into_parts();

        assert_ne!(first_header, second_header);
    }

    #[test]
    fn hkdf_matches_rfc_5869_test_case_one() {
        let input_key = vec![0x0b; 22];
        let salt = decode_hex("000102030405060708090a0b0c");
        let info = decode_hex("f0f1f2f3f4f5f6f7f8f9");
        let expected = decode_hex(
            "3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865",
        );
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &input_key);
        let mut actual = vec![0_u8; expected.len()];
        hkdf.expand(&info, &mut actual)
            .expect("RFC output length must be valid");
        assert_eq!(actual, expected);
    }

    #[test]
    fn xchacha20_poly1305_matches_the_published_draft_vector() {
        let key: [u8; 32] =
            decode_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .try_into()
                .expect("vector key length");
        let nonce: [u8; 24] = decode_hex(
            "404142434445464748494a4b4c4d4e4f\
             5051525354555657",
        )
        .try_into()
        .expect("vector nonce length");
        let aad = decode_hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: \
            If I could offer you only one tip for the future, sunscreen would be it.";
        let expected = decode_hex(
            "bd6d179d3e83d43b9576579493c0e939\
             572a1700252bfaccbed2902c21396cbb\
             731c7f1b0b4aa6440bf3a82f4eda7e\
             39ae64c6708c54c216cb96b72e1213b\
             4522f8c9ba40db5d945b11b69b982c1\
             bb9e3f3fac2bc369488f76b2383565d3\
             fff921f9664c97637da9768812f615c6\
             8b13b52ec0875924c1c7987947deafd8\
             780acf49",
        );

        let actual =
            super::encrypt_bytes(&key, &nonce, plaintext, &aad).expect("vector must encrypt");
        assert_eq!(actual, expected);
    }

    #[test]
    #[ignore = "manual Windows baseline measurement"]
    fn benchmark_version_one_argon2_unlock_profile() {
        const SAMPLE_COUNT: usize = 20;

        let created = deterministic_vault("benchmark password");
        let (header, manifest, _recovery, _initial_session) = created.into_parts();
        let mut samples = Vec::with_capacity(SAMPLE_COUNT);
        for _ in 0..SAMPLE_COUNT {
            let started = Instant::now();
            let session = unlock_empty_vault(
                MasterPassword::new("benchmark password").expect("valid password"),
                &header,
                &manifest,
                &CancellationFlag::new(),
            )
            .expect("benchmark password must unlock");
            samples.push(started.elapsed().as_millis());
            drop(session);
        }
        samples.sort_unstable();
        let median = samples[SAMPLE_COUNT / 2];
        let p95_index = (SAMPLE_COUNT * 95).div_ceil(100) - 1;
        let p95 = samples[p95_index];

        println!("argon2id-v1 samples={SAMPLE_COUNT} median_ms={median} p95_ms={p95}");
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        let compact = value
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        assert!(compact.len().is_multiple_of(2));
        compact
            .chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect()
    }

    const fn hex_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            b'A'..=b'F' => value - b'A' + 10,
            _ => panic!("invalid test-vector hex"),
        }
    }

    fn to_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}
