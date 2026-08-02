use librarian_agent_protocol::{PasskeyRequestProof, PasskeyTransactionProof};
use zeroize::Zeroizing;

const MAX_RP_ID_BYTES: usize = 253;
const MAX_USER_HANDLE_BYTES: usize = 64;
const MAX_USER_NAME_BYTES: usize = 256;
const MAX_USER_DISPLAY_NAME_BYTES: usize = 256;
const MAX_EXCLUDED_CREDENTIALS: usize = 64;
const CREDENTIAL_ID_BYTES: usize = 32;
const CREDENTIAL_ID_BYTES_U32: u32 = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    Invalid,
    Unavailable,
    Failed,
}

pub struct VerifiedMakeRequest {
    rp_id: Zeroizing<String>,
    client_data_hash: [u8; 32],
    user_handle: Zeroizing<Vec<u8>>,
    user_name: Zeroizing<String>,
    user_display_name: Zeroizing<String>,
    excluded_credential_ids: Vec<[u8; CREDENTIAL_ID_BYTES]>,
}

impl VerifiedMakeRequest {
    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }
    #[must_use]
    pub const fn client_data_hash(&self) -> &[u8; 32] {
        &self.client_data_hash
    }
    #[must_use]
    pub fn user_handle(&self) -> &[u8] {
        &self.user_handle
    }
    #[must_use]
    pub fn user_name(&self) -> &str {
        &self.user_name
    }
    #[must_use]
    pub fn user_display_name(&self) -> &str {
        &self.user_display_name
    }
    #[must_use]
    pub fn excluded_credential_ids(&self) -> &[[u8; CREDENTIAL_ID_BYTES]] {
        &self.excluded_credential_ids
    }
}

pub struct VerifiedAssertionRequest {
    rp_id: Zeroizing<String>,
    client_data_hash: [u8; 32],
}

pub struct VerifiedAssertionLookup {
    rp_id: Zeroizing<String>,
    allowed_credential_ids: Vec<[u8; CREDENTIAL_ID_BYTES]>,
    allow_list_present: bool,
}

impl VerifiedAssertionLookup {
    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    #[must_use]
    pub fn allowed_credential_ids(&self) -> &[[u8; CREDENTIAL_ID_BYTES]] {
        &self.allowed_credential_ids
    }

    #[must_use]
    pub const fn allow_list_present(&self) -> bool {
        self.allow_list_present
    }
}

impl VerifiedAssertionRequest {
    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }
    #[must_use]
    pub const fn client_data_hash(&self) -> &[u8; 32] {
        &self.client_data_hash
    }
}

#[repr(C)]
struct NativeProof {
    transaction_id: *const u8,
    request_type: u32,
    request_signature: *const u8,
    request_signature_bytes: u32,
    encoded_request: *const u8,
    encoded_request_bytes: u32,
    agent_challenge: *const u8,
    agent_challenge_bytes: u32,
    user_verification_signature: *const u8,
    user_verification_signature_bytes: u32,
}

unsafe extern "C" {
    fn librarian_windows_passkey_verify_make(
        proof: *const NativeProof,
        rp_id: *mut u8,
        rp_id_capacity: u32,
        rp_id_bytes: *mut u32,
        client_data_hash: *mut u8,
        user_handle: *mut u8,
        user_handle_capacity: u32,
        user_handle_bytes: *mut u32,
        user_name: *mut u8,
        user_name_capacity: u32,
        user_name_bytes: *mut u32,
        user_display_name: *mut u8,
        user_display_name_capacity: u32,
        user_display_name_bytes: *mut u32,
        excluded_credential_ids: *mut u8,
        excluded_credential_ids_capacity: u32,
        excluded_credential_ids_count: *mut u32,
    ) -> u32;

    fn librarian_windows_passkey_verify_assertion(
        proof: *const NativeProof,
        selected_credential_id: *const u8,
        selected_credential_id_bytes: u32,
        rp_id: *mut u8,
        rp_id_capacity: u32,
        rp_id_bytes: *mut u32,
        client_data_hash: *mut u8,
    ) -> u32;

    fn librarian_windows_passkey_verify_assertion_lookup(
        proof: *const NativeProof,
        rp_id: *mut u8,
        rp_id_capacity: u32,
        rp_id_bytes: *mut u32,
        allowed_credential_ids: *mut u8,
        allowed_credential_ids_capacity: u32,
        allowed_credential_ids_count: *mut u32,
        allow_list_present: *mut u8,
    ) -> u32;
}

/// Verifies and decodes the Windows-signed portion of an assertion request.
///
/// This lookup returns only public metadata selectors. It does not verify user
/// presence and therefore cannot authorize signing.
///
/// # Errors
///
/// Returns an error when Windows' verifier is unavailable, the operation
/// signature is invalid, or the decoded request violates Librarian's bounds.
pub fn verify_assertion_lookup(
    proof: &PasskeyRequestProof,
) -> Result<VerifiedAssertionLookup, VerificationError> {
    let native = native_request_proof(proof)?;
    let mut rp_id = Zeroizing::new(vec![0_u8; MAX_RP_ID_BYTES]);
    let mut rp_id_bytes = 0_u32;
    let mut allowed = vec![0_u8; MAX_EXCLUDED_CREDENTIALS * CREDENTIAL_ID_BYTES];
    let mut allowed_count = 0_u32;
    let mut allow_list_present = 0_u8;
    // SAFETY: every output pointer references a live allocation whose exact
    // capacity is supplied to the native bridge.
    let result = unsafe {
        librarian_windows_passkey_verify_assertion_lookup(
            &raw const native,
            rp_id.as_mut_ptr(),
            u32::try_from(rp_id.len()).map_err(|_| VerificationError::Failed)?,
            &raw mut rp_id_bytes,
            allowed.as_mut_ptr(),
            u32::try_from(allowed.len()).map_err(|_| VerificationError::Failed)?,
            &raw mut allowed_count,
            &raw mut allow_list_present,
        )
    };
    map_result(result)?;
    truncate(&mut rp_id, rp_id_bytes)?;
    let allowed_count = usize::try_from(allowed_count).map_err(|_| VerificationError::Failed)?;
    if allowed_count > MAX_EXCLUDED_CREDENTIALS {
        return Err(VerificationError::Failed);
    }
    if allow_list_present > 1 {
        return Err(VerificationError::Failed);
    }
    allowed.truncate(allowed_count * CREDENTIAL_ID_BYTES);
    let allowed_credential_ids = allowed
        .chunks_exact(CREDENTIAL_ID_BYTES)
        .map(|value| value.try_into().map_err(|_| VerificationError::Failed))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(VerifiedAssertionLookup {
        rp_id: Zeroizing::new(
            String::from_utf8(rp_id.to_vec()).map_err(|_| VerificationError::Invalid)?,
        ),
        allowed_credential_ids,
        allow_list_present: allow_list_present != 0,
    })
}

/// Verifies and decodes a Windows-signed make-credential transaction.
///
/// # Errors
///
/// Returns an error when Windows' verifier is unavailable, either signature
/// is invalid, or the decoded request violates Librarian's bounds.
pub fn verify_make(
    proof: &PasskeyTransactionProof,
) -> Result<VerifiedMakeRequest, VerificationError> {
    let native = native_proof(proof)?;
    let mut rp_id = Zeroizing::new(vec![0_u8; MAX_RP_ID_BYTES]);
    let mut rp_id_bytes = 0_u32;
    let mut client_data_hash = [0_u8; 32];
    let mut user_handle = Zeroizing::new(vec![0_u8; MAX_USER_HANDLE_BYTES]);
    let mut user_handle_bytes = 0_u32;
    let mut user_name = Zeroizing::new(vec![0_u8; MAX_USER_NAME_BYTES]);
    let mut user_name_bytes = 0_u32;
    let mut user_display_name = Zeroizing::new(vec![0_u8; MAX_USER_DISPLAY_NAME_BYTES]);
    let mut user_display_name_bytes = 0_u32;
    let mut excluded = vec![0_u8; MAX_EXCLUDED_CREDENTIALS * CREDENTIAL_ID_BYTES];
    let mut excluded_count = 0_u32;
    // SAFETY: every pointer references a live allocation with the exact
    // capacity supplied to the native bridge; the bridge writes lengths only
    // after validating all inputs and output capacities.
    let result = unsafe {
        librarian_windows_passkey_verify_make(
            &raw const native,
            rp_id.as_mut_ptr(),
            u32::try_from(rp_id.len()).map_err(|_| VerificationError::Failed)?,
            &raw mut rp_id_bytes,
            client_data_hash.as_mut_ptr(),
            user_handle.as_mut_ptr(),
            u32::try_from(user_handle.len()).map_err(|_| VerificationError::Failed)?,
            &raw mut user_handle_bytes,
            user_name.as_mut_ptr(),
            u32::try_from(user_name.len()).map_err(|_| VerificationError::Failed)?,
            &raw mut user_name_bytes,
            user_display_name.as_mut_ptr(),
            u32::try_from(user_display_name.len()).map_err(|_| VerificationError::Failed)?,
            &raw mut user_display_name_bytes,
            excluded.as_mut_ptr(),
            u32::try_from(excluded.len()).map_err(|_| VerificationError::Failed)?,
            &raw mut excluded_count,
        )
    };
    map_result(result)?;
    truncate(&mut rp_id, rp_id_bytes)?;
    truncate(&mut user_handle, user_handle_bytes)?;
    truncate(&mut user_name, user_name_bytes)?;
    truncate(&mut user_display_name, user_display_name_bytes)?;
    let excluded_count = usize::try_from(excluded_count).map_err(|_| VerificationError::Failed)?;
    if excluded_count > MAX_EXCLUDED_CREDENTIALS {
        return Err(VerificationError::Failed);
    }
    excluded.truncate(excluded_count * CREDENTIAL_ID_BYTES);
    let excluded_credential_ids = excluded
        .chunks_exact(CREDENTIAL_ID_BYTES)
        .map(|value| value.try_into().map_err(|_| VerificationError::Failed))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(VerifiedMakeRequest {
        rp_id: Zeroizing::new(
            String::from_utf8(rp_id.to_vec()).map_err(|_| VerificationError::Invalid)?,
        ),
        client_data_hash,
        user_handle,
        user_name: Zeroizing::new(
            String::from_utf8(user_name.to_vec()).map_err(|_| VerificationError::Invalid)?,
        ),
        user_display_name: Zeroizing::new(
            String::from_utf8(user_display_name.to_vec())
                .map_err(|_| VerificationError::Invalid)?,
        ),
        excluded_credential_ids,
    })
}

/// Verifies and decodes a Windows-signed assertion transaction.
///
/// # Errors
///
/// Returns an error when Windows' verifier is unavailable, either signature
/// is invalid, or the selected credential is not allowed by the request.
pub fn verify_assertion(
    proof: &PasskeyTransactionProof,
    credential_id: &[u8; CREDENTIAL_ID_BYTES],
) -> Result<VerifiedAssertionRequest, VerificationError> {
    let native = native_proof(proof)?;
    let mut rp_id = Zeroizing::new(vec![0_u8; MAX_RP_ID_BYTES]);
    let mut rp_id_bytes = 0_u32;
    let mut client_data_hash = [0_u8; 32];
    // SAFETY: pointers and capacities refer to live, correctly sized Rust
    // allocations for the duration of the call.
    let result = unsafe {
        librarian_windows_passkey_verify_assertion(
            &raw const native,
            credential_id.as_ptr(),
            CREDENTIAL_ID_BYTES_U32,
            rp_id.as_mut_ptr(),
            u32::try_from(rp_id.len()).map_err(|_| VerificationError::Failed)?,
            &raw mut rp_id_bytes,
            client_data_hash.as_mut_ptr(),
        )
    };
    map_result(result)?;
    truncate(&mut rp_id, rp_id_bytes)?;
    Ok(VerifiedAssertionRequest {
        rp_id: Zeroizing::new(
            String::from_utf8(rp_id.to_vec()).map_err(|_| VerificationError::Invalid)?,
        ),
        client_data_hash,
    })
}

fn native_proof(proof: &PasskeyTransactionProof) -> Result<NativeProof, VerificationError> {
    let mut native = native_request_proof(proof.request())?;
    native.user_verification_signature = proof.user_verification_signature().as_ptr();
    native.user_verification_signature_bytes =
        u32::try_from(proof.user_verification_signature().len())
            .map_err(|_| VerificationError::Invalid)?;
    native.agent_challenge = proof.agent_challenge().as_ptr();
    native.agent_challenge_bytes =
        u32::try_from(proof.agent_challenge().len()).map_err(|_| VerificationError::Invalid)?;
    Ok(native)
}

fn native_request_proof(proof: &PasskeyRequestProof) -> Result<NativeProof, VerificationError> {
    Ok(NativeProof {
        transaction_id: proof.transaction_id().as_ptr(),
        request_type: u32::from(proof.request_type()),
        request_signature: proof.request_signature().as_ptr(),
        request_signature_bytes: u32::try_from(proof.request_signature().len())
            .map_err(|_| VerificationError::Invalid)?,
        encoded_request: proof.encoded_request().as_ptr(),
        encoded_request_bytes: u32::try_from(proof.encoded_request().len())
            .map_err(|_| VerificationError::Invalid)?,
        agent_challenge: core::ptr::null(),
        agent_challenge_bytes: 0,
        user_verification_signature: core::ptr::null(),
        user_verification_signature_bytes: 0,
    })
}

fn truncate(value: &mut Zeroizing<Vec<u8>>, length: u32) -> Result<(), VerificationError> {
    let length = usize::try_from(length).map_err(|_| VerificationError::Failed)?;
    if length == 0 || length > value.len() {
        return Err(VerificationError::Failed);
    }
    value.truncate(length);
    Ok(())
}

fn map_result(value: u32) -> Result<(), VerificationError> {
    match value {
        0 => Ok(()),
        1 => Err(VerificationError::Invalid),
        2 => Err(VerificationError::Unavailable),
        _ => Err(VerificationError::Failed),
    }
}
