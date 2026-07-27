#[cfg(windows)]
use std::{
    fmt::Write as _,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use librarian_vault_core::{WindowsHelloInstallationKey, WindowsHelloPrfOutput};
use librarian_vault_format::{
    MAX_WINDOWS_HELLO_CREDENTIAL_ID_BYTES, MAX_WINDOWS_HELLO_PROTECTOR_BYTES, WindowsHelloProtector,
};
#[cfg(any(windows, test))]
use minicbor::{Decoder, Encoder};
use zeroize::Zeroizing;

#[cfg(windows)]
use crate::filesystem::{
    acquire_ancestor_guards, create_staging_reservation,
    guarded_file_matches_path_with_ancestor_guards, guarded_file_size, guarded_files_match,
    hard_link_with_ancestor_guards, open_optional_regular_file_guard_with_ancestor_guards,
    open_regular_file_guard_with_ancestor_guards, remove_file_with_ancestor_guards,
    sync_parent_directory_with_ancestor_guards,
};

#[cfg(any(windows, test))]
const LOCAL_STATE_MAGIC: &str = "LBR-HLO";
#[cfg(any(windows, test))]
const LOCAL_STATE_VERSION: u32 = 1;
#[cfg(any(windows, test))]
const LOCAL_STATE_FIELDS: u64 = 8;
const INSTALLATION_KEY_BYTES: usize = 32;
const PRF_SALT_BYTES: usize = 32;
#[cfg(any(windows, test))]
const MAXIMUM_LOCAL_STATE_BYTES: usize = 4 * 1_024;
#[cfg(windows)]
const MAXIMUM_PROTECTED_STATE_BYTES: u64 = 16 * 1_024;

#[cfg_attr(
    not(any(windows, test)),
    allow(
        dead_code,
        reason = "the portable runtime matches errors constructed by Windows and test repositories"
    )
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsHelloStateError {
    NotFound,
    Invalid,
    Failed,
    // Atomic publication completed, but a later verification or durability
    // barrier failed. The selected credential must remain available.
    Published,
}

#[cfg_attr(
    not(any(windows, test)),
    allow(
        dead_code,
        reason = "the portable runtime maps errors constructed by Windows and test providers"
    )
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsHelloProviderError {
    InvalidRequest,
    Unavailable,
    Cancelled,
    Failed,
    RemovalFailed,
}

/// One enrollment result whose PRF allocation remains inside the agent.
///
/// Formatting and cloning are intentionally unavailable.
pub(crate) struct WindowsHelloEnrollment {
    pub(crate) credential_id: Vec<u8>,
    pub(crate) prf_salt: [u8; PRF_SALT_BYTES],
    pub(crate) prf_output: WindowsHelloPrfOutput,
}

pub(crate) trait WindowsHelloProvider: Send + Sync {
    fn enroll(
        &self,
        parent_window: u64,
        authenticated_process_id: u32,
        operation_id: [u8; 16],
    ) -> Result<WindowsHelloEnrollment, WindowsHelloProviderError>;

    fn evaluate(
        &self,
        parent_window: u64,
        authenticated_process_id: u32,
        operation_id: [u8; 16],
        credential_id: &[u8],
        prf_salt: &[u8; PRF_SALT_BYTES],
    ) -> Result<WindowsHelloPrfOutput, WindowsHelloProviderError>;

    fn cancel(&self, operation_id: [u8; 16]);

    fn remove(&self, credential_id: &[u8]) -> Result<(), WindowsHelloProviderError>;
}

pub(crate) trait WindowsHelloStateRepository: Send + Sync {
    fn load(&self) -> Result<WindowsHelloLocalState, WindowsHelloStateError>;
    fn save(&self, state: &WindowsHelloLocalState) -> Result<(), WindowsHelloStateError>;
    fn remove(&self) -> Result<(), WindowsHelloStateError>;
}

#[cfg(windows)]
pub(crate) struct PlatformWindowsHelloProvider;

#[cfg(windows)]
impl WindowsHelloProvider for PlatformWindowsHelloProvider {
    fn enroll(
        &self,
        parent_window: u64,
        authenticated_process_id: u32,
        operation_id: [u8; 16],
    ) -> Result<WindowsHelloEnrollment, WindowsHelloProviderError> {
        let parent = platform_parent(parent_window, authenticated_process_id)?;
        let operation = platform_operation(operation_id)?;
        let enrollment =
            librarian_windows_hello_agent::enroll(parent, operation).map_err(map_bridge_error)?;
        let (credential_id, prf_salt, prf_output) = enrollment.into_parts();
        Ok(WindowsHelloEnrollment {
            credential_id,
            prf_salt,
            prf_output,
        })
    }

    fn evaluate(
        &self,
        parent_window: u64,
        authenticated_process_id: u32,
        operation_id: [u8; 16],
        credential_id: &[u8],
        prf_salt: &[u8; PRF_SALT_BYTES],
    ) -> Result<WindowsHelloPrfOutput, WindowsHelloProviderError> {
        let parent = platform_parent(parent_window, authenticated_process_id)?;
        let operation = platform_operation(operation_id)?;
        librarian_windows_hello_agent::evaluate(parent, operation, credential_id, prf_salt)
            .map_err(map_bridge_error)
    }

    fn cancel(&self, operation_id: [u8; 16]) {
        if let Ok(operation) = platform_operation(operation_id) {
            let _ = librarian_windows_hello_agent::cancel(operation);
        }
    }

    fn remove(&self, credential_id: &[u8]) -> Result<(), WindowsHelloProviderError> {
        librarian_windows_hello_agent::remove(credential_id).map_err(map_bridge_error)
    }
}

#[cfg(windows)]
fn platform_parent(
    parent_window: u64,
    authenticated_process_id: u32,
) -> Result<librarian_windows_hello_agent::ParentWindow, WindowsHelloProviderError> {
    let parent_window =
        usize::try_from(parent_window).map_err(|_| WindowsHelloProviderError::InvalidRequest)?;
    librarian_windows_hello_agent::ParentWindow::for_authenticated_process(
        parent_window,
        authenticated_process_id,
    )
    .map_err(map_bridge_error)
}

#[cfg(windows)]
fn platform_operation(
    operation_id: [u8; 16],
) -> Result<librarian_windows_hello_agent::OperationId, WindowsHelloProviderError> {
    librarian_windows_hello_agent::OperationId::new(operation_id).map_err(map_bridge_error)
}

#[cfg(windows)]
const fn map_bridge_error(
    error: librarian_windows_hello_agent::BridgeError,
) -> WindowsHelloProviderError {
    use librarian_windows_hello_agent::BridgeError;

    match error {
        BridgeError::InvalidArgument => WindowsHelloProviderError::InvalidRequest,
        BridgeError::Unavailable | BridgeError::Unsupported => {
            WindowsHelloProviderError::Unavailable
        }
        BridgeError::Cancelled => WindowsHelloProviderError::Cancelled,
        BridgeError::CredentialRemovalFailed => WindowsHelloProviderError::RemovalFailed,
        BridgeError::InvalidResponse | BridgeError::PlatformFailure => {
            WindowsHelloProviderError::Failed
        }
    }
}

/// Canonical plaintext protected as one opaque current-user DPAPI blob.
///
/// This type intentionally has no formatting or cloning implementation.
pub(crate) struct WindowsHelloLocalState {
    vault_id: [u8; 16],
    key_epoch: u32,
    installation_key: Zeroizing<[u8; INSTALLATION_KEY_BYTES]>,
    credential_id: Vec<u8>,
    prf_salt: [u8; PRF_SALT_BYTES],
    protector: Vec<u8>,
}

impl WindowsHelloLocalState {
    pub(crate) fn new(
        vault_id: [u8; 16],
        key_epoch: u32,
        installation_key: Zeroizing<[u8; INSTALLATION_KEY_BYTES]>,
        credential_id: Vec<u8>,
        prf_salt: [u8; PRF_SALT_BYTES],
        protector: Vec<u8>,
    ) -> Result<Self, WindowsHelloStateError> {
        if vault_id == [0; 16]
            || key_epoch == 0
            || installation_key.as_ref() == [0; INSTALLATION_KEY_BYTES]
            || credential_id.is_empty()
            || credential_id.len() > MAX_WINDOWS_HELLO_CREDENTIAL_ID_BYTES
            || prf_salt == [0; PRF_SALT_BYTES]
            || protector.is_empty()
            || protector.len() > MAX_WINDOWS_HELLO_PROTECTOR_BYTES
        {
            return Err(WindowsHelloStateError::Invalid);
        }
        let decoded = WindowsHelloProtector::decode(&protector)
            .map_err(|_| WindowsHelloStateError::Invalid)?;
        if decoded.vault_id() != &vault_id
            || decoded.key_epoch() != key_epoch
            || decoded.credential_id() != credential_id
            || decoded.prf_salt() != &prf_salt
        {
            return Err(WindowsHelloStateError::Invalid);
        }
        Ok(Self {
            vault_id,
            key_epoch,
            installation_key,
            credential_id,
            prf_salt,
            protector,
        })
    }

    pub(crate) const fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }

    pub(crate) const fn key_epoch(&self) -> u32 {
        self.key_epoch
    }

    pub(crate) fn installation_key(&self) -> WindowsHelloInstallationKey {
        WindowsHelloInstallationKey::from_zeroizing(self.installation_key.clone())
    }

    pub(crate) fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    pub(crate) const fn prf_salt(&self) -> &[u8; PRF_SALT_BYTES] {
        &self.prf_salt
    }

    pub(crate) fn protector(&self) -> &[u8] {
        &self.protector
    }

    #[cfg(any(windows, test))]
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, WindowsHelloStateError> {
        let mut encoder = Encoder::new(Vec::with_capacity(MAXIMUM_LOCAL_STATE_BYTES));
        encoder
            .array(LOCAL_STATE_FIELDS)
            .and_then(|value| value.str(LOCAL_STATE_MAGIC))
            .and_then(|value| value.u32(LOCAL_STATE_VERSION))
            .and_then(|value| value.bytes(&self.vault_id))
            .and_then(|value| value.u32(self.key_epoch))
            .and_then(|value| value.bytes(self.installation_key.as_slice()))
            .and_then(|value| value.bytes(&self.credential_id))
            .and_then(|value| value.bytes(&self.prf_salt))
            .and_then(|value| value.bytes(&self.protector))
            .map_err(|_| WindowsHelloStateError::Failed)?;
        let bytes = Zeroizing::new(encoder.into_writer());
        if bytes.len() > MAXIMUM_LOCAL_STATE_BYTES {
            return Err(WindowsHelloStateError::Invalid);
        }
        Ok(bytes)
    }

    #[cfg(any(windows, test))]
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, WindowsHelloStateError> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_LOCAL_STATE_BYTES {
            return Err(WindowsHelloStateError::Invalid);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder
            .array()
            .map_err(|_| WindowsHelloStateError::Invalid)?
            != Some(LOCAL_STATE_FIELDS)
            || decoder.str().map_err(|_| WindowsHelloStateError::Invalid)? != LOCAL_STATE_MAGIC
            || decoder.u32().map_err(|_| WindowsHelloStateError::Invalid)? != LOCAL_STATE_VERSION
        {
            return Err(WindowsHelloStateError::Invalid);
        }
        let vault_id = fixed_bytes(&mut decoder)?;
        let key_epoch = decoder.u32().map_err(|_| WindowsHelloStateError::Invalid)?;
        let installation_key = fixed_secret_bytes(&mut decoder)?;
        let credential_id = bounded_bytes(&mut decoder, 1, MAX_WINDOWS_HELLO_CREDENTIAL_ID_BYTES)?;
        let prf_salt = fixed_bytes(&mut decoder)?;
        let protector = bounded_bytes(&mut decoder, 1, MAX_WINDOWS_HELLO_PROTECTOR_BYTES)?;
        if decoder.position() != bytes.len() {
            return Err(WindowsHelloStateError::Invalid);
        }
        let state = Self::new(
            vault_id,
            key_epoch,
            installation_key,
            credential_id,
            prf_salt,
            protector,
        )?;
        if state.encode()?.as_slice() != bytes {
            return Err(WindowsHelloStateError::Invalid);
        }
        Ok(state)
    }
}

#[cfg(any(windows, test))]
fn fixed_bytes<const N: usize>(
    decoder: &mut Decoder<'_>,
) -> Result<[u8; N], WindowsHelloStateError> {
    decoder
        .bytes()
        .map_err(|_| WindowsHelloStateError::Invalid)?
        .try_into()
        .map_err(|_| WindowsHelloStateError::Invalid)
}

#[cfg(any(windows, test))]
fn fixed_secret_bytes<const N: usize>(
    decoder: &mut Decoder<'_>,
) -> Result<Zeroizing<[u8; N]>, WindowsHelloStateError> {
    let bytes = decoder
        .bytes()
        .map_err(|_| WindowsHelloStateError::Invalid)?;
    if bytes.len() != N {
        return Err(WindowsHelloStateError::Invalid);
    }
    let mut value = Zeroizing::new([0_u8; N]);
    value.copy_from_slice(bytes);
    Ok(value)
}

#[cfg(any(windows, test))]
fn bounded_bytes(
    decoder: &mut Decoder<'_>,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, WindowsHelloStateError> {
    let value = decoder
        .bytes()
        .map_err(|_| WindowsHelloStateError::Invalid)?;
    if !(minimum..=maximum).contains(&value.len()) {
        return Err(WindowsHelloStateError::Invalid);
    }
    Ok(value.to_vec())
}

#[cfg(windows)]
pub(crate) struct WindowsHelloStateStore {
    path: PathBuf,
}

#[cfg(windows)]
impl WindowsHelloStateStore {
    pub(crate) fn new(path: impl AsRef<Path>) -> Result<Self, WindowsHelloStateError> {
        let path = path.as_ref();
        if !path.is_absolute() || path.file_name().is_none() || path.parent().is_none() {
            return Err(WindowsHelloStateError::Invalid);
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    pub(crate) fn load(&self) -> Result<WindowsHelloLocalState, WindowsHelloStateError> {
        let ancestors =
            acquire_ancestor_guards(&self.path).map_err(|_| WindowsHelloStateError::Failed)?;
        let mut file = open_optional_regular_file_guard_with_ancestor_guards(
            &ancestors, &self.path, false, false,
        )
        .map_err(|_| WindowsHelloStateError::Failed)?
        .ok_or(WindowsHelloStateError::NotFound)?;
        librarian_windows_hello_agent::verify_user_file_restriction(&self.path)
            .map_err(|_| WindowsHelloStateError::Failed)?;
        guarded_file_matches_path_with_ancestor_guards(&file, &self.path, &ancestors)
            .map_err(|_| WindowsHelloStateError::Failed)?;
        let length = guarded_file_size(Some(&file), MAXIMUM_PROTECTED_STATE_BYTES)
            .map_err(|_| WindowsHelloStateError::Failed)?;
        if length == 0 {
            return Err(WindowsHelloStateError::Invalid);
        }
        let mut protected = Vec::with_capacity(
            usize::try_from(length).map_err(|_| WindowsHelloStateError::Failed)?,
        );
        file.read_to_end(&mut protected)
            .map_err(|_| WindowsHelloStateError::Failed)?;
        guarded_file_matches_path_with_ancestor_guards(&file, &self.path, &ancestors)
            .map_err(|_| WindowsHelloStateError::Failed)?;
        let plaintext = librarian_windows_hello_agent::unprotect_user_state(&protected)
            .map_err(|_| WindowsHelloStateError::Failed)?;
        WindowsHelloLocalState::decode(&plaintext)
    }

    pub(crate) fn save(
        &self,
        state: &WindowsHelloLocalState,
    ) -> Result<(), WindowsHelloStateError> {
        let protected = librarian_windows_hello_agent::protect_user_state(state.encode()?)
            .map_err(|_| WindowsHelloStateError::Failed)?;
        let ancestors =
            acquire_ancestor_guards(&self.path).map_err(|_| WindowsHelloStateError::Failed)?;
        let existing = open_optional_regular_file_guard_with_ancestor_guards(
            &ancestors, &self.path, true, true,
        )
        .map_err(|_| WindowsHelloStateError::Failed)?;
        if let Some(existing) = existing.as_ref() {
            librarian_windows_hello_agent::verify_user_file_restriction(&self.path)
                .map_err(|_| WindowsHelloStateError::Failed)?;
            guarded_file_matches_path_with_ancestor_guards(existing, &self.path, &ancestors)
                .map_err(|_| WindowsHelloStateError::Failed)?;
        }
        let staging_path = self.staging_path()?;
        let mut staging = create_staging_reservation(&ancestors, &staging_path)
            .map_err(|_| WindowsHelloStateError::Failed)?;
        let mut published = false;
        let result = (|| {
            staging
                .write_all(&protected)
                .and_then(|()| staging.flush())
                .and_then(|()| staging.sync_all())
                .map_err(|_| WindowsHelloStateError::Failed)?;
            librarian_windows_hello_agent::restrict_user_file(&staging_path)
                .map_err(|_| WindowsHelloStateError::Failed)?;
            staging
                .seek(SeekFrom::Start(0))
                .map_err(|_| WindowsHelloStateError::Failed)?;
            let staging_guard =
                open_regular_file_guard_with_ancestor_guards(&ancestors, &staging_path, true, true)
                    .map_err(|_| WindowsHelloStateError::Failed)?;
            librarian_windows_hello_agent::verify_user_file_restriction(&staging_path)
                .map_err(|_| WindowsHelloStateError::Failed)?;
            guarded_file_matches_path_with_ancestor_guards(
                &staging_guard,
                &staging_path,
                &ancestors,
            )
            .map_err(|_| WindowsHelloStateError::Failed)?;
            drop(staging);

            let replacing = existing.is_some();
            if let Some(existing) = existing.as_ref() {
                guarded_file_matches_path_with_ancestor_guards(existing, &self.path, &ancestors)
                    .map_err(|_| WindowsHelloStateError::Failed)?;
            }
            drop(existing);
            if replacing {
                drop(staging_guard);
                librarian_windows_hello_agent::replace_file_atomically(&self.path, &staging_path)
                    .map_err(|_| WindowsHelloStateError::Failed)?;
                published = true;
                let mut published = open_regular_file_guard_with_ancestor_guards(
                    &ancestors, &self.path, false, false,
                )
                .map_err(|_| WindowsHelloStateError::Failed)?;
                guarded_file_matches_path_with_ancestor_guards(&published, &self.path, &ancestors)
                    .map_err(|_| WindowsHelloStateError::Failed)?;
                librarian_windows_hello_agent::verify_user_file_restriction(&self.path)
                    .map_err(|_| WindowsHelloStateError::Failed)?;
                guarded_file_matches_path_with_ancestor_guards(&published, &self.path, &ancestors)
                    .map_err(|_| WindowsHelloStateError::Failed)?;
                let mut verified = Vec::new();
                published
                    .read_to_end(&mut verified)
                    .map_err(|_| WindowsHelloStateError::Failed)?;
                if verified != protected {
                    return Err(WindowsHelloStateError::Failed);
                }
            } else {
                hard_link_with_ancestor_guards(&ancestors, &staging_path, &self.path)
                    .map_err(|_| WindowsHelloStateError::Failed)?;
                published = true;
                let published = open_regular_file_guard_with_ancestor_guards(
                    &ancestors, &self.path, false, false,
                )
                .map_err(|_| WindowsHelloStateError::Failed)?;
                guarded_files_match(&staging_guard, &published)
                    .map_err(|_| WindowsHelloStateError::Failed)?;
                librarian_windows_hello_agent::verify_user_file_restriction(&self.path)
                    .map_err(|_| WindowsHelloStateError::Failed)?;
                guarded_file_matches_path_with_ancestor_guards(&published, &self.path, &ancestors)
                    .map_err(|_| WindowsHelloStateError::Failed)?;
                remove_file_with_ancestor_guards(&ancestors, &staging_path)
                    .map_err(|_| WindowsHelloStateError::Failed)?;
            }
            sync_parent_directory_with_ancestor_guards(&self.path, &ancestors)
                .map_err(|_| WindowsHelloStateError::Failed)
        })();
        if result.is_err() {
            let _ = remove_file_with_ancestor_guards(&ancestors, &staging_path);
        }
        result.map_err(|_| {
            if published {
                WindowsHelloStateError::Published
            } else {
                WindowsHelloStateError::Failed
            }
        })
    }

    pub(crate) fn remove(&self) -> Result<(), WindowsHelloStateError> {
        let ancestors =
            acquire_ancestor_guards(&self.path).map_err(|_| WindowsHelloStateError::Failed)?;
        let existing = open_optional_regular_file_guard_with_ancestor_guards(
            &ancestors, &self.path, false, true,
        )
        .map_err(|_| WindowsHelloStateError::Failed)?
        .ok_or(WindowsHelloStateError::NotFound)?;
        librarian_windows_hello_agent::verify_user_file_restriction(&self.path)
            .map_err(|_| WindowsHelloStateError::Failed)?;
        guarded_file_matches_path_with_ancestor_guards(&existing, &self.path, &ancestors)
            .map_err(|_| WindowsHelloStateError::Failed)?;
        remove_file_with_ancestor_guards(&ancestors, &self.path)
            .map_err(|_| WindowsHelloStateError::Failed)?;
        sync_parent_directory_with_ancestor_guards(&self.path, &ancestors)
            .map_err(|_| WindowsHelloStateError::Failed)
    }

    fn staging_path(&self) -> Result<PathBuf, WindowsHelloStateError> {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| WindowsHelloStateError::Failed)?;
        if random == [0; 16] {
            return Err(WindowsHelloStateError::Failed);
        }
        let name = self
            .path
            .file_name()
            .ok_or(WindowsHelloStateError::Invalid)?
            .to_string_lossy();
        let mut suffix = String::with_capacity(32);
        for byte in random {
            write!(&mut suffix, "{byte:02x}").map_err(|_| WindowsHelloStateError::Failed)?;
        }
        Ok(self.path.with_file_name(format!("{name}.{suffix}.tmp")))
    }
}

#[cfg(windows)]
impl WindowsHelloStateRepository for WindowsHelloStateStore {
    fn load(&self) -> Result<WindowsHelloLocalState, WindowsHelloStateError> {
        Self::load(self)
    }

    fn save(&self, state: &WindowsHelloLocalState) -> Result<(), WindowsHelloStateError> {
        Self::save(self, state)
    }

    fn remove(&self) -> Result<(), WindowsHelloStateError> {
        Self::remove(self)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use std::fs;

    use super::*;

    fn state(marker: u8) -> WindowsHelloLocalState {
        let credential_id = vec![marker; 64];
        let prf_salt = [marker.wrapping_add(1); 32];
        let protector = WindowsHelloProtector::new(
            [marker.wrapping_add(2); 16],
            1,
            [marker.wrapping_add(3); 32],
            credential_id.clone(),
            prf_salt,
            [marker.wrapping_add(4); 24],
            [marker.wrapping_add(5); 48],
        )
        .expect("test protector")
        .encode()
        .expect("encoded protector");
        WindowsHelloLocalState::new(
            [marker.wrapping_add(2); 16],
            1,
            Zeroizing::new([marker.wrapping_add(6); 32]),
            credential_id,
            prf_salt,
            protector,
        )
        .expect("test state")
    }

    #[test]
    fn local_state_is_canonical_and_binding_checked() {
        let state = state(0x31);
        let encoded = state.encode().expect("encoded local state");
        let decoded = WindowsHelloLocalState::decode(&encoded).expect("decoded local state");
        assert_eq!(decoded.vault_id(), state.vault_id());
        assert_eq!(decoded.key_epoch(), state.key_epoch());
        assert_eq!(decoded.credential_id(), state.credential_id());
        assert_eq!(decoded.prf_salt(), state.prf_salt());
        assert_eq!(decoded.protector(), state.protector());

        let mut corrupted = encoded.to_vec();
        corrupted.push(0);
        assert!(WindowsHelloLocalState::decode(&corrupted).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn protected_store_round_trips_replaces_and_removes_without_plaintext() {
        let root = std::env::temp_dir().join(format!(
            "librarian-hello-state-{}-{}",
            std::process::id(),
            super::super::lifecycle::unix_time_ms().expect("test clock")
        ));
        fs::create_dir(&root).expect("test directory");
        let path = root.join("windows-hello.dat");
        let store = WindowsHelloStateStore::new(&path).expect("state store");
        let first = state(0x41);
        store.save(&first).expect("first save");
        let raw = fs::read(&path).expect("protected bytes");
        assert!(!raw.windows(32).any(|value| value == [0x47; 32]));
        let loaded = store.load().expect("first load");
        assert_eq!(loaded.credential_id(), first.credential_id());

        let second = state(0x51);
        store.save(&second).expect("atomic replacement");
        let loaded = store.load().expect("second load");
        assert_eq!(loaded.credential_id(), second.credential_id());

        store.remove().expect("state removal");
        assert_eq!(store.load().err(), Some(WindowsHelloStateError::NotFound));
        fs::remove_dir(&root).expect("test directory cleanup");
    }
}
