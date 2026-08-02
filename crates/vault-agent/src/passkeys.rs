use std::sync::Arc;

use librarian_agent_protocol::{PasskeyRequestProof, PasskeyTransactionProof};
use librarian_vault_format::PASSKEY_CREDENTIAL_ID_BYTES;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PasskeyVerificationError {
    Invalid,
    Unavailable,
    Failed,
}

pub(crate) struct VerifiedMakeRequest {
    rp_id: Zeroizing<String>,
    user_handle: Zeroizing<Vec<u8>>,
    user_name: Zeroizing<String>,
    user_display_name: Zeroizing<String>,
    excluded_credential_ids: Vec<[u8; PASSKEY_CREDENTIAL_ID_BYTES]>,
}

impl VerifiedMakeRequest {
    #[cfg(test)]
    pub(crate) fn new_for_test(
        rp_id: &str,
        user_handle: &[u8],
        user_name: &str,
        user_display_name: &str,
        excluded_credential_ids: Vec<[u8; PASSKEY_CREDENTIAL_ID_BYTES]>,
    ) -> Self {
        Self {
            rp_id: Zeroizing::new(rp_id.to_owned()),
            user_handle: Zeroizing::new(user_handle.to_vec()),
            user_name: Zeroizing::new(user_name.to_owned()),
            user_display_name: Zeroizing::new(user_display_name.to_owned()),
            excluded_credential_ids,
        }
    }

    pub(crate) fn rp_id(&self) -> &str {
        &self.rp_id
    }

    pub(crate) fn user_handle(&self) -> &[u8] {
        &self.user_handle
    }

    pub(crate) fn user_name(&self) -> &str {
        &self.user_name
    }

    pub(crate) fn user_display_name(&self) -> &str {
        &self.user_display_name
    }

    pub(crate) fn excluded_credential_ids(&self) -> &[[u8; PASSKEY_CREDENTIAL_ID_BYTES]] {
        &self.excluded_credential_ids
    }
}

pub(crate) struct VerifiedAssertionRequest {
    rp_id: Zeroizing<String>,
    client_data_hash: [u8; 32],
}

pub(crate) struct VerifiedAssertionLookup {
    rp_id: Zeroizing<String>,
    allowed_credential_ids: Vec<[u8; PASSKEY_CREDENTIAL_ID_BYTES]>,
    allow_list_present: bool,
}

impl VerifiedAssertionLookup {
    #[cfg(test)]
    pub(crate) fn new_for_test(
        rp_id: &str,
        allowed_credential_ids: Vec<[u8; PASSKEY_CREDENTIAL_ID_BYTES]>,
        allow_list_present: bool,
    ) -> Self {
        Self {
            rp_id: Zeroizing::new(rp_id.to_owned()),
            allowed_credential_ids,
            allow_list_present,
        }
    }

    pub(crate) fn rp_id(&self) -> &str {
        &self.rp_id
    }

    pub(crate) fn allowed_credential_ids(&self) -> &[[u8; PASSKEY_CREDENTIAL_ID_BYTES]] {
        &self.allowed_credential_ids
    }

    pub(crate) const fn allow_list_present(&self) -> bool {
        self.allow_list_present
    }
}

impl VerifiedAssertionRequest {
    #[cfg(test)]
    pub(crate) fn new_for_test(rp_id: &str, client_data_hash: [u8; 32]) -> Self {
        Self {
            rp_id: Zeroizing::new(rp_id.to_owned()),
            client_data_hash,
        }
    }

    pub(crate) fn rp_id(&self) -> &str {
        &self.rp_id
    }

    pub(crate) const fn client_data_hash(&self) -> &[u8; 32] {
        &self.client_data_hash
    }
}

pub(crate) trait PasskeyRequestVerifier: Send + Sync {
    fn verify_assertion_lookup(
        &self,
        proof: &PasskeyRequestProof,
    ) -> Result<VerifiedAssertionLookup, PasskeyVerificationError>;

    fn verify_make(
        &self,
        proof: &PasskeyTransactionProof,
    ) -> Result<VerifiedMakeRequest, PasskeyVerificationError>;

    fn verify_assertion(
        &self,
        proof: &PasskeyTransactionProof,
        credential_id: &[u8; PASSKEY_CREDENTIAL_ID_BYTES],
    ) -> Result<VerifiedAssertionRequest, PasskeyVerificationError>;
}

#[cfg(windows)]
struct PlatformPasskeyRequestVerifier;

#[cfg(windows)]
impl PasskeyRequestVerifier for PlatformPasskeyRequestVerifier {
    fn verify_assertion_lookup(
        &self,
        proof: &PasskeyRequestProof,
    ) -> Result<VerifiedAssertionLookup, PasskeyVerificationError> {
        let verified = librarian_windows_passkey_agent::verify_assertion_lookup(proof)
            .map_err(map_platform_error)?;
        Ok(VerifiedAssertionLookup {
            rp_id: Zeroizing::new(verified.rp_id().to_owned()),
            allowed_credential_ids: verified.allowed_credential_ids().to_vec(),
            allow_list_present: verified.allow_list_present(),
        })
    }

    fn verify_make(
        &self,
        proof: &PasskeyTransactionProof,
    ) -> Result<VerifiedMakeRequest, PasskeyVerificationError> {
        let verified =
            librarian_windows_passkey_agent::verify_make(proof).map_err(map_platform_error)?;
        Ok(VerifiedMakeRequest {
            rp_id: Zeroizing::new(verified.rp_id().to_owned()),
            user_handle: Zeroizing::new(verified.user_handle().to_vec()),
            user_name: Zeroizing::new(verified.user_name().to_owned()),
            user_display_name: Zeroizing::new(verified.user_display_name().to_owned()),
            excluded_credential_ids: verified.excluded_credential_ids().to_vec(),
        })
    }

    fn verify_assertion(
        &self,
        proof: &PasskeyTransactionProof,
        credential_id: &[u8; PASSKEY_CREDENTIAL_ID_BYTES],
    ) -> Result<VerifiedAssertionRequest, PasskeyVerificationError> {
        let verified = librarian_windows_passkey_agent::verify_assertion(proof, credential_id)
            .map_err(map_platform_error)?;
        Ok(VerifiedAssertionRequest {
            rp_id: Zeroizing::new(verified.rp_id().to_owned()),
            client_data_hash: *verified.client_data_hash(),
        })
    }
}

#[cfg(windows)]
fn map_platform_error(
    error: librarian_windows_passkey_agent::VerificationError,
) -> PasskeyVerificationError {
    match error {
        librarian_windows_passkey_agent::VerificationError::Invalid => {
            PasskeyVerificationError::Invalid
        }
        librarian_windows_passkey_agent::VerificationError::Unavailable => {
            PasskeyVerificationError::Unavailable
        }
        librarian_windows_passkey_agent::VerificationError::Failed => {
            PasskeyVerificationError::Failed
        }
    }
}

#[cfg(not(windows))]
struct PlatformPasskeyRequestVerifier;

#[cfg(not(windows))]
impl PasskeyRequestVerifier for PlatformPasskeyRequestVerifier {
    fn verify_assertion_lookup(
        &self,
        _: &PasskeyRequestProof,
    ) -> Result<VerifiedAssertionLookup, PasskeyVerificationError> {
        Err(PasskeyVerificationError::Unavailable)
    }

    fn verify_make(
        &self,
        _: &PasskeyTransactionProof,
    ) -> Result<VerifiedMakeRequest, PasskeyVerificationError> {
        Err(PasskeyVerificationError::Unavailable)
    }

    fn verify_assertion(
        &self,
        _: &PasskeyTransactionProof,
        _: &[u8; PASSKEY_CREDENTIAL_ID_BYTES],
    ) -> Result<VerifiedAssertionRequest, PasskeyVerificationError> {
        Err(PasskeyVerificationError::Unavailable)
    }
}

pub(crate) fn platform_passkey_request_verifier() -> Arc<dyn PasskeyRequestVerifier> {
    Arc::new(PlatformPasskeyRequestVerifier)
}
