use minicbor::{Decoder, Encoder};
use zeroize::Zeroizing;

use crate::{
    AgentState, MAX_PAYLOAD_BYTES, OperationCode, ProtocolError,
    cbor::{
        SecretWriter, decode_bounded_bytes, decode_bounded_text, decode_fixed_bytes, decode_u8,
        decode_u16, decode_u32, decode_u64, encode_array, encode_bytes, encode_null, encode_text,
        encode_u8, encode_u16, encode_u32, encode_u64, expect_array, require_end,
    },
};

const MAX_MASTER_PASSWORD_BYTES: usize = 1_024;
const MAX_SERVICE_NAME_BYTES: usize = 256;
const MAX_ORIGIN_BYTES: usize = 2_048;
const MAX_USERNAME_BYTES: usize = 1_024;
const MAX_PASSWORD_BYTES: usize = 16 * 1_024;
const MAX_PASSKEY_ENCODED_REQUEST_BYTES: usize = 48 * 1_024;
const MAX_PASSKEY_SIGNATURE_BYTES: usize = 2 * 1_024;
const MAX_PASSKEY_USER_HANDLE_BYTES: usize = 64;
const MAX_PASSKEY_RP_ID_BYTES: usize = 253;
const MAX_PASSKEY_USER_NAME_BYTES: usize = 256;
const MAX_PASSKEY_CREDENTIALS: usize = 64;
const PASSKEY_CREDENTIAL_ID_BYTES: usize = 32;
const PASSKEY_PUBLIC_KEY_BYTES: usize = 65;
const PASSKEY_AUTHENTICATOR_DATA_BYTES: usize = 37;
const MAX_PASSKEY_ASSERTION_SIGNATURE_BYTES: usize = 80;
const CTAP2_CBOR_REQUEST_TYPE: u8 = 1;
const MAX_LIST_PAGE_SIZE: u16 = 100;
const MAX_REQUEST_BODY_BYTES: usize = MAX_PAYLOAD_BYTES - 128;
const MAX_RESPONSE_BODY_BYTES: usize = MAX_PAYLOAD_BYTES - 96;

/// Validated secret-bearing website-account fields. Formatting and cloning are
/// intentionally unavailable.
pub struct AccountFields {
    service_name: Zeroizing<String>,
    permitted_origin: Zeroizing<String>,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

/// One bounded Windows-signed `WebAuthn` plugin request.
///
/// The agent verifies this proof before returning public credential metadata.
/// It is intentionally insufficient to authorize private-key use.
pub struct PasskeyRequestProof {
    transaction_id: [u8; 16],
    request_type: u8,
    request_signature: Zeroizing<Vec<u8>>,
    encoded_request: Zeroizing<Vec<u8>>,
}

impl PasskeyRequestProof {
    /// Constructs one bounded Windows request proof.
    ///
    /// # Errors
    ///
    /// Rejects a zero transaction, unsupported request type, empty proof, or
    /// values outside the protocol bounds.
    pub fn new(
        transaction_id: [u8; 16],
        request_type: u8,
        request_signature: &[u8],
        encoded_request: &[u8],
    ) -> Result<Self, ProtocolError> {
        if transaction_id == [0; 16]
            || request_type != CTAP2_CBOR_REQUEST_TYPE
            || request_signature.is_empty()
            || encoded_request.is_empty()
        {
            return Err(ProtocolError::InvariantViolation);
        }
        if request_signature.len() > MAX_PASSKEY_SIGNATURE_BYTES
            || encoded_request.len() > MAX_PASSKEY_ENCODED_REQUEST_BYTES
        {
            return Err(ProtocolError::TooLarge);
        }
        Ok(Self {
            transaction_id,
            request_type,
            request_signature: Zeroizing::new(request_signature.to_vec()),
            encoded_request: Zeroizing::new(encoded_request.to_vec()),
        })
    }

    #[must_use]
    pub const fn transaction_id(&self) -> &[u8; 16] {
        &self.transaction_id
    }

    #[must_use]
    pub const fn request_type(&self) -> u8 {
        self.request_type
    }

    #[must_use]
    pub fn request_signature(&self) -> &[u8] {
        self.request_signature.as_slice()
    }

    #[must_use]
    pub fn encoded_request(&self) -> &[u8] {
        self.encoded_request.as_slice()
    }
}

/// Windows-signed request plus the matching Windows Hello UV proof. The agent
/// validates both proofs independently before permitting private-key use.
pub struct PasskeyTransactionProof {
    request: PasskeyRequestProof,
    agent_challenge: [u8; 16],
    user_verification_signature: Zeroizing<Vec<u8>>,
}

impl PasskeyTransactionProof {
    /// Constructs one bounded proof envelope.
    ///
    /// # Errors
    ///
    /// Rejects a zero transaction, unsupported request type, empty proof, or
    /// values outside the protocol bounds.
    pub fn new(
        transaction_id: [u8; 16],
        request_type: u8,
        request_signature: &[u8],
        encoded_request: &[u8],
        agent_challenge: [u8; 16],
        user_verification_signature: &[u8],
    ) -> Result<Self, ProtocolError> {
        if agent_challenge == [0; 16] || user_verification_signature.is_empty() {
            return Err(ProtocolError::InvariantViolation);
        }
        if user_verification_signature.len() > MAX_PASSKEY_SIGNATURE_BYTES {
            return Err(ProtocolError::TooLarge);
        }
        Ok(Self {
            request: PasskeyRequestProof::new(
                transaction_id,
                request_type,
                request_signature,
                encoded_request,
            )?,
            agent_challenge,
            user_verification_signature: Zeroizing::new(user_verification_signature.to_vec()),
        })
    }

    #[must_use]
    pub const fn request(&self) -> &PasskeyRequestProof {
        &self.request
    }

    #[must_use]
    pub const fn transaction_id(&self) -> &[u8; 16] {
        self.request.transaction_id()
    }

    #[must_use]
    pub const fn request_type(&self) -> u8 {
        self.request.request_type()
    }

    #[must_use]
    pub fn request_signature(&self) -> &[u8] {
        self.request.request_signature()
    }

    #[must_use]
    pub fn encoded_request(&self) -> &[u8] {
        self.request.encoded_request()
    }

    #[must_use]
    pub fn user_verification_signature(&self) -> &[u8] {
        self.user_verification_signature.as_slice()
    }

    #[must_use]
    pub const fn agent_challenge(&self) -> &[u8; 16] {
        &self.agent_challenge
    }
}

impl AccountFields {
    /// Constructs bounded fields. Origin normalization and service-name
    /// validation remain the vault core's responsibility.
    ///
    /// # Errors
    ///
    /// Rejects a field that exceeds its protocol limit.
    pub fn new(
        service_name: &str,
        permitted_origin: &str,
        username: &str,
        password: &str,
    ) -> Result<Self, ProtocolError> {
        if service_name.len() > MAX_SERVICE_NAME_BYTES
            || permitted_origin.len() > MAX_ORIGIN_BYTES
            || username.len() > MAX_USERNAME_BYTES
            || password.len() > MAX_PASSWORD_BYTES
        {
            return Err(ProtocolError::TooLarge);
        }
        Ok(Self {
            service_name: Zeroizing::new(service_name.to_owned()),
            permitted_origin: Zeroizing::new(permitted_origin.to_owned()),
            username: Zeroizing::new(username.to_owned()),
            password: Zeroizing::new(password.to_owned()),
        })
    }

    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    #[must_use]
    pub fn permitted_origin(&self) -> &str {
        &self.permitted_origin
    }

    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }
}

/// Strict version-1 body for an operation implemented by the Windows MVP
/// agent. Reserved future operations are rejected until their owning issue
/// adds a complete schema.
pub enum OperationRequest {
    Status,
    CreateVault {
        master_password: Zeroizing<String>,
    },
    UnlockMasterPassword {
        master_password: Zeroizing<String>,
    },
    Lock,
    ListAccountSummaries {
        offset: u32,
        limit: u16,
    },
    GetAccount {
        id: [u8; 16],
    },
    AddAccount {
        fields: AccountFields,
    },
    UpdateAccount {
        id: [u8; 16],
        fields: AccountFields,
    },
    DeleteAccount {
        id: [u8; 16],
    },
    EnrollWindowsHello {
        parent_window: u64,
    },
    UnlockWindowsHello {
        parent_window: u64,
    },
    RemoveWindowsHello,
    MakePasskey {
        proof: PasskeyTransactionProof,
    },
    GetPasskeyAssertion {
        proof: PasskeyTransactionProof,
        credential_id: [u8; PASSKEY_CREDENTIAL_ID_BYTES],
    },
    DeletePasskey {
        credential_id: [u8; PASSKEY_CREDENTIAL_ID_BYTES],
    },
    ListPasskeysForAssertion {
        proof: PasskeyRequestProof,
    },
    ListPasskeys,
    ConfirmPasskeyCreation {
        proof: PasskeyTransactionProof,
        credential_id: [u8; PASSKEY_CREDENTIAL_ID_BYTES],
    },
    RollbackPasskeyCreation {
        proof: PasskeyTransactionProof,
        credential_id: [u8; PASSKEY_CREDENTIAL_ID_BYTES],
    },
}

impl OperationRequest {
    #[must_use]
    pub const fn operation(&self) -> OperationCode {
        match self {
            Self::Status => OperationCode::Status,
            Self::CreateVault { .. } => OperationCode::CreateVault,
            Self::UnlockMasterPassword { .. } => OperationCode::UnlockMasterPassword,
            Self::Lock => OperationCode::Lock,
            Self::ListAccountSummaries { .. } => OperationCode::ListAccountSummaries,
            Self::GetAccount { .. } => OperationCode::GetAccount,
            Self::AddAccount { .. } => OperationCode::AddAccount,
            Self::UpdateAccount { .. } => OperationCode::UpdateAccount,
            Self::DeleteAccount { .. } => OperationCode::DeleteAccount,
            Self::EnrollWindowsHello { .. } => OperationCode::EnrollWindowsHello,
            Self::UnlockWindowsHello { .. } => OperationCode::UnlockWindowsHello,
            Self::RemoveWindowsHello => OperationCode::RemoveWindowsHello,
            Self::MakePasskey { .. } => OperationCode::MakePasskey,
            Self::GetPasskeyAssertion { .. } => OperationCode::GetPasskeyAssertion,
            Self::DeletePasskey { .. } => OperationCode::DeletePasskey,
            Self::ListPasskeysForAssertion { .. } => OperationCode::ListPasskeysForAssertion,
            Self::ListPasskeys => OperationCode::ListPasskeys,
            Self::ConfirmPasskeyCreation { .. } => OperationCode::ConfirmPasskeyCreation,
            Self::RollbackPasskeyCreation { .. } => OperationCode::RollbackPasskeyCreation,
        }
    }

    #[must_use]
    pub fn master_password(&self) -> Option<&str> {
        match self {
            Self::CreateVault { master_password }
            | Self::UnlockMasterPassword { master_password } => Some(master_password),
            _ => None,
        }
    }

    #[must_use]
    pub const fn list_window(&self) -> Option<(u32, u16)> {
        match self {
            Self::ListAccountSummaries { offset, limit } => Some((*offset, *limit)),
            _ => None,
        }
    }

    #[must_use]
    pub const fn account_id(&self) -> Option<[u8; 16]> {
        match self {
            Self::GetAccount { id }
            | Self::UpdateAccount { id, .. }
            | Self::DeleteAccount { id } => Some(*id),
            _ => None,
        }
    }

    #[must_use]
    pub const fn account_fields(&self) -> Option<&AccountFields> {
        match self {
            Self::AddAccount { fields } | Self::UpdateAccount { fields, .. } => Some(fields),
            _ => None,
        }
    }

    #[must_use]
    pub const fn parent_window(&self) -> Option<u64> {
        match self {
            Self::EnrollWindowsHello { parent_window }
            | Self::UnlockWindowsHello { parent_window } => Some(*parent_window),
            _ => None,
        }
    }

    #[must_use]
    pub const fn passkey_proof(&self) -> Option<&PasskeyTransactionProof> {
        match self {
            Self::MakePasskey { proof }
            | Self::GetPasskeyAssertion { proof, .. }
            | Self::ConfirmPasskeyCreation { proof, .. }
            | Self::RollbackPasskeyCreation { proof, .. } => Some(proof),
            _ => None,
        }
    }

    #[must_use]
    pub const fn passkey_request_proof(&self) -> Option<&PasskeyRequestProof> {
        match self {
            Self::MakePasskey { proof }
            | Self::GetPasskeyAssertion { proof, .. }
            | Self::ConfirmPasskeyCreation { proof, .. }
            | Self::RollbackPasskeyCreation { proof, .. } => Some(proof.request()),
            Self::ListPasskeysForAssertion { proof } => Some(proof),
            _ => None,
        }
    }

    #[must_use]
    pub const fn passkey_credential_id(&self) -> Option<[u8; PASSKEY_CREDENTIAL_ID_BYTES]> {
        match self {
            Self::GetPasskeyAssertion { credential_id, .. }
            | Self::DeletePasskey { credential_id }
            | Self::ConfirmPasskeyCreation { credential_id, .. }
            | Self::RollbackPasskeyCreation { credential_id, .. } => Some(*credential_id),
            _ => None,
        }
    }

    /// Decodes a complete operation body and verifies its deterministic
    /// encoding byte for byte.
    ///
    /// # Errors
    ///
    /// Rejects unknown/reserved schemas, extra fields, indefinite values,
    /// noncanonical values, invalid bounds, and trailing bytes.
    pub fn decode(operation: OperationCode, bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(ProtocolError::TooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        let request = match operation {
            OperationCode::Status => {
                expect_array(&mut decoder, 0)?;
                Self::Status
            }
            OperationCode::CreateVault => {
                expect_array(&mut decoder, 1)?;
                Self::CreateVault {
                    master_password: decode_secret_text(&mut decoder, MAX_MASTER_PASSWORD_BYTES)?,
                }
            }
            OperationCode::UnlockMasterPassword => {
                expect_array(&mut decoder, 1)?;
                Self::UnlockMasterPassword {
                    master_password: decode_secret_text(&mut decoder, MAX_MASTER_PASSWORD_BYTES)?,
                }
            }
            OperationCode::Lock => {
                expect_array(&mut decoder, 0)?;
                Self::Lock
            }
            OperationCode::ListAccountSummaries => {
                expect_array(&mut decoder, 2)?;
                let offset = decode_u32(&mut decoder)?;
                let limit = decode_u16(&mut decoder)?;
                if limit == 0 || limit > MAX_LIST_PAGE_SIZE {
                    return Err(ProtocolError::InvariantViolation);
                }
                Self::ListAccountSummaries { offset, limit }
            }
            OperationCode::GetAccount => {
                expect_array(&mut decoder, 1)?;
                Self::GetAccount {
                    id: decode_fixed_bytes(&mut decoder)?,
                }
            }
            OperationCode::AddAccount => {
                expect_array(&mut decoder, 4)?;
                Self::AddAccount {
                    fields: decode_account_fields(&mut decoder)?,
                }
            }
            OperationCode::UpdateAccount => {
                expect_array(&mut decoder, 5)?;
                Self::UpdateAccount {
                    id: decode_fixed_bytes(&mut decoder)?,
                    fields: decode_account_fields(&mut decoder)?,
                }
            }
            OperationCode::DeleteAccount => {
                expect_array(&mut decoder, 1)?;
                Self::DeleteAccount {
                    id: decode_fixed_bytes(&mut decoder)?,
                }
            }
            OperationCode::EnrollWindowsHello => Self::EnrollWindowsHello {
                parent_window: decode_parent_window(&mut decoder)?,
            },
            OperationCode::UnlockWindowsHello => Self::UnlockWindowsHello {
                parent_window: decode_parent_window(&mut decoder)?,
            },
            OperationCode::RemoveWindowsHello => {
                expect_array(&mut decoder, 0)?;
                Self::RemoveWindowsHello
            }
            OperationCode::ListPasskeys => {
                expect_array(&mut decoder, 0)?;
                Self::ListPasskeys
            }
            operation @ (OperationCode::MakePasskey
            | OperationCode::GetPasskeyAssertion
            | OperationCode::DeletePasskey
            | OperationCode::ListPasskeysForAssertion
            | OperationCode::ConfirmPasskeyCreation
            | OperationCode::RollbackPasskeyCreation) => {
                decode_passkey_request(&mut decoder, operation)?
            }
            OperationCode::ExactOriginMatches
            | OperationCode::GetSelectedCredential
            | OperationCode::CaptureCredential
            | OperationCode::UpdateCredential => return Err(ProtocolError::Unsupported),
        };
        require_end(&decoder, bytes)?;
        if request.encode()?.as_slice() != bytes {
            return Err(ProtocolError::NonCanonical);
        }
        Ok(request)
    }

    /// Encodes the complete body directly into zeroizing storage.
    ///
    /// # Errors
    ///
    /// Returns `TooLarge` if the body exceeds the protocol frame limit and
    /// `InvariantViolation` for an invalid page limit.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        if self
            .master_password()
            .is_some_and(|password| password.len() > MAX_MASTER_PASSWORD_BYTES)
        {
            return Err(ProtocolError::TooLarge);
        }
        if self
            .list_window()
            .is_some_and(|(_, limit)| limit == 0 || limit > MAX_LIST_PAGE_SIZE)
        {
            return Err(ProtocolError::InvariantViolation);
        }
        let mut encoder = Encoder::new(SecretWriter::with_capacity(MAX_PAYLOAD_BYTES));
        match self {
            Self::Status | Self::Lock | Self::RemoveWindowsHello | Self::ListPasskeys => {
                encode_array(&mut encoder, 0);
            }
            Self::CreateVault { master_password }
            | Self::UnlockMasterPassword { master_password } => {
                encode_array(&mut encoder, 1);
                encode_text(&mut encoder, master_password);
            }
            Self::ListAccountSummaries { offset, limit } => {
                encode_array(&mut encoder, 2);
                encode_u32(&mut encoder, *offset);
                encode_u16(&mut encoder, *limit);
            }
            Self::GetAccount { id } | Self::DeleteAccount { id } => {
                encode_array(&mut encoder, 1);
                encode_bytes(&mut encoder, id);
            }
            Self::AddAccount { fields } => {
                encode_array(&mut encoder, 4);
                encode_account_fields(&mut encoder, fields);
            }
            Self::UpdateAccount { id, fields } => {
                encode_array(&mut encoder, 5);
                encode_bytes(&mut encoder, id);
                encode_account_fields(&mut encoder, fields);
            }
            Self::EnrollWindowsHello { parent_window }
            | Self::UnlockWindowsHello { parent_window } => {
                if *parent_window == 0 {
                    return Err(ProtocolError::InvariantViolation);
                }
                encode_array(&mut encoder, 1);
                encode_u64(&mut encoder, *parent_window);
            }
            Self::MakePasskey { proof } => {
                encode_array(&mut encoder, 6);
                encode_passkey_proof(&mut encoder, proof);
            }
            Self::GetPasskeyAssertion {
                proof,
                credential_id,
            }
            | Self::ConfirmPasskeyCreation {
                proof,
                credential_id,
            }
            | Self::RollbackPasskeyCreation {
                proof,
                credential_id,
            } => {
                encode_array(&mut encoder, 7);
                encode_passkey_proof(&mut encoder, proof);
                encode_bytes(&mut encoder, credential_id);
            }
            Self::DeletePasskey { credential_id } => {
                encode_array(&mut encoder, 1);
                encode_bytes(&mut encoder, credential_id);
            }
            Self::ListPasskeysForAssertion { proof } => {
                encode_array(&mut encoder, 4);
                encode_passkey_request_proof(&mut encoder, proof);
            }
        }
        checked_request_body(encoder.into_writer().into_bytes())
    }
}

fn decode_parent_window(decoder: &mut Decoder<'_>) -> Result<u64, ProtocolError> {
    expect_array(decoder, 1)?;
    let parent_window = decode_u64(decoder)?;
    (parent_window != 0)
        .then_some(parent_window)
        .ok_or(ProtocolError::InvariantViolation)
}

fn decode_passkey_request_proof(
    decoder: &mut Decoder<'_>,
) -> Result<PasskeyRequestProof, ProtocolError> {
    let transaction_id = decode_fixed_bytes(decoder)?;
    let request_type = decode_u8(decoder)?;
    let request_signature = decode_bounded_bytes(decoder, MAX_PASSKEY_SIGNATURE_BYTES)?;
    let encoded_request = decode_bounded_bytes(decoder, MAX_PASSKEY_ENCODED_REQUEST_BYTES)?;
    PasskeyRequestProof::new(
        transaction_id,
        request_type,
        &request_signature,
        &encoded_request,
    )
}

fn decode_passkey_proof(
    decoder: &mut Decoder<'_>,
) -> Result<PasskeyTransactionProof, ProtocolError> {
    let request = decode_passkey_request_proof(decoder)?;
    let agent_challenge = decode_fixed_bytes(decoder)?;
    let user_verification_signature = decode_bounded_bytes(decoder, MAX_PASSKEY_SIGNATURE_BYTES)?;
    PasskeyTransactionProof::new(
        *request.transaction_id(),
        request.request_type(),
        request.request_signature(),
        request.encoded_request(),
        agent_challenge,
        &user_verification_signature,
    )
}

fn decode_passkey_request(
    decoder: &mut Decoder<'_>,
    operation: OperationCode,
) -> Result<OperationRequest, ProtocolError> {
    match operation {
        OperationCode::MakePasskey => {
            expect_array(decoder, 6)?;
            Ok(OperationRequest::MakePasskey {
                proof: decode_passkey_proof(decoder)?,
            })
        }
        OperationCode::GetPasskeyAssertion => {
            expect_array(decoder, 7)?;
            Ok(OperationRequest::GetPasskeyAssertion {
                proof: decode_passkey_proof(decoder)?,
                credential_id: decode_fixed_bytes(decoder)?,
            })
        }
        OperationCode::DeletePasskey => {
            expect_array(decoder, 1)?;
            Ok(OperationRequest::DeletePasskey {
                credential_id: decode_fixed_bytes(decoder)?,
            })
        }
        OperationCode::ListPasskeysForAssertion => {
            expect_array(decoder, 4)?;
            Ok(OperationRequest::ListPasskeysForAssertion {
                proof: decode_passkey_request_proof(decoder)?,
            })
        }
        OperationCode::RollbackPasskeyCreation => {
            expect_array(decoder, 7)?;
            Ok(OperationRequest::RollbackPasskeyCreation {
                proof: decode_passkey_proof(decoder)?,
                credential_id: decode_fixed_bytes(decoder)?,
            })
        }
        OperationCode::ConfirmPasskeyCreation => {
            expect_array(decoder, 7)?;
            Ok(OperationRequest::ConfirmPasskeyCreation {
                proof: decode_passkey_proof(decoder)?,
                credential_id: decode_fixed_bytes(decoder)?,
            })
        }
        _ => Err(ProtocolError::Unsupported),
    }
}

fn encode_passkey_request_proof<W>(encoder: &mut Encoder<W>, proof: &PasskeyRequestProof)
where
    W: minicbor::encode::Write,
    W::Error: core::fmt::Debug,
{
    encode_bytes(encoder, proof.transaction_id());
    encode_u8(encoder, proof.request_type());
    encode_bytes(encoder, proof.request_signature());
    encode_bytes(encoder, proof.encoded_request());
}

fn encode_passkey_proof<W>(encoder: &mut Encoder<W>, proof: &PasskeyTransactionProof)
where
    W: minicbor::encode::Write,
    W::Error: core::fmt::Debug,
{
    encode_passkey_request_proof(encoder, proof.request());
    encode_bytes(encoder, proof.agent_challenge());
    encode_bytes(encoder, proof.user_verification_signature());
}

fn decode_secret_text(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<Zeroizing<String>, ProtocolError> {
    decode_bounded_text(decoder, maximum).map(Zeroizing::new)
}

fn decode_account_fields(decoder: &mut Decoder<'_>) -> Result<AccountFields, ProtocolError> {
    let service_name = decode_secret_text(decoder, MAX_SERVICE_NAME_BYTES)?;
    let permitted_origin = decode_secret_text(decoder, MAX_ORIGIN_BYTES)?;
    let username = decode_secret_text(decoder, MAX_USERNAME_BYTES)?;
    let password = decode_secret_text(decoder, MAX_PASSWORD_BYTES)?;
    Ok(AccountFields {
        service_name,
        permitted_origin,
        username,
        password,
    })
}

fn encode_account_fields<W>(encoder: &mut Encoder<W>, fields: &AccountFields)
where
    W: minicbor::encode::Write,
    W::Error: core::fmt::Debug,
{
    encode_text(encoder, fields.service_name());
    encode_text(encoder, fields.permitted_origin());
    encode_text(encoder, fields.username());
    encode_text(encoder, fields.password());
}

/// Borrowed account view used to encode a response without cloning plaintext.
pub struct AccountView<'a> {
    pub id: [u8; 16],
    pub revision: u64,
    pub created_at_ms: u64,
    pub modified_at_ms: u64,
    pub service_name: &'a str,
    pub permitted_origin: &'a str,
    pub username: &'a str,
    pub password: &'a str,
}

/// Borrowed public passkey material returned after durable creation.
pub struct PasskeyCredentialView<'a> {
    pub credential_id: [u8; PASSKEY_CREDENTIAL_ID_BYTES],
    pub user_handle: &'a [u8],
    pub public_key: [u8; PASSKEY_PUBLIC_KEY_BYTES],
}

/// Borrowed assertion result. Private key material is structurally absent.
pub struct PasskeyAssertionView<'a> {
    pub credential_id: [u8; PASSKEY_CREDENTIAL_ID_BYTES],
    pub user_handle: &'a [u8],
    pub authenticator_data: [u8; PASSKEY_AUTHENTICATOR_DATA_BYTES],
    pub signature_der: &'a [u8],
}

/// Public metadata for one credential eligible for an assertion request.
pub struct PasskeySummaryView<'a> {
    pub credential_id: [u8; PASSKEY_CREDENTIAL_ID_BYTES],
    pub user_handle: &'a [u8],
    pub user_name: &'a str,
    pub user_display_name: &'a str,
}

/// Public passkey metadata exposed only to the authorized desktop management
/// surface. User handles, private keys, and signature counters are absent.
pub struct PasskeyManagementSummaryView<'a> {
    pub credential_id: [u8; PASSKEY_CREDENTIAL_ID_BYTES],
    pub rp_id: &'a str,
    pub user_name: &'a str,
    pub user_display_name: &'a str,
}

/// Encodes an empty successful operation result.
///
/// # Errors
///
/// This fixed response fails only if the protocol limit becomes inconsistent.
pub fn encode_empty_result() -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let mut encoder = Encoder::new(SecretWriter::with_capacity(MAX_PAYLOAD_BYTES));
    encode_array(&mut encoder, 0);
    checked_response_body(encoder.into_writer().into_bytes())
}

/// Encodes non-secret agent state and the current authorization epoch.
///
/// # Errors
///
/// This fixed response fails only if the protocol limit becomes inconsistent.
pub fn encode_status(
    state: AgentState,
    unlock_epoch: u64,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let mut encoder = Encoder::new(SecretWriter::with_capacity(MAX_PAYLOAD_BYTES));
    encode_array(&mut encoder, 2);
    encode_u8(&mut encoder, state as u8);
    encode_u64(&mut encoder, unlock_epoch);
    checked_response_body(encoder.into_writer().into_bytes())
}

/// Encodes one newly allocated opaque account identifier.
///
/// # Errors
///
/// This fixed response fails only if the protocol limit becomes inconsistent.
pub fn encode_account_id(id: [u8; 16]) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let mut encoder = Encoder::new(SecretWriter::with_capacity(MAX_PAYLOAD_BYTES));
    encode_array(&mut encoder, 1);
    encode_bytes(&mut encoder, &id);
    checked_response_body(encoder.into_writer().into_bytes())
}

/// Encodes public material for one newly created passkey.
///
/// # Errors
///
/// Rejects an empty or oversized user handle and malformed public material.
pub fn encode_passkey_credential(
    credential: &PasskeyCredentialView<'_>,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    if credential.credential_id == [0; PASSKEY_CREDENTIAL_ID_BYTES]
        || credential.user_handle.is_empty()
        || credential.user_handle.len() > MAX_PASSKEY_USER_HANDLE_BYTES
        || credential.public_key[0] != 0x04
    {
        return Err(ProtocolError::InvariantViolation);
    }
    let mut encoder = Encoder::new(SecretWriter::with_capacity(MAX_PAYLOAD_BYTES));
    encode_array(&mut encoder, 3);
    encode_bytes(&mut encoder, &credential.credential_id);
    encode_bytes(&mut encoder, credential.user_handle);
    encode_bytes(&mut encoder, &credential.public_key);
    checked_response_body(encoder.into_writer().into_bytes())
}

/// Encodes one transaction-bound passkey assertion.
///
/// # Errors
///
/// Rejects malformed identifiers, user handles, authenticator data, or DER
/// signatures outside the bounded ES256 response size.
pub fn encode_passkey_assertion(
    assertion: &PasskeyAssertionView<'_>,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    if assertion.credential_id == [0; PASSKEY_CREDENTIAL_ID_BYTES]
        || assertion.user_handle.is_empty()
        || assertion.user_handle.len() > MAX_PASSKEY_USER_HANDLE_BYTES
        || assertion.signature_der.is_empty()
        || assertion.signature_der.len() > MAX_PASSKEY_ASSERTION_SIGNATURE_BYTES
    {
        return Err(ProtocolError::InvariantViolation);
    }
    let mut encoder = Encoder::new(SecretWriter::with_capacity(MAX_PAYLOAD_BYTES));
    encode_array(&mut encoder, 4);
    encode_bytes(&mut encoder, &assertion.credential_id);
    encode_bytes(&mut encoder, assertion.user_handle);
    encode_bytes(&mut encoder, &assertion.authenticator_data);
    encode_bytes(&mut encoder, assertion.signature_der);
    checked_response_body(encoder.into_writer().into_bytes())
}

/// Encodes the bounded public credential set matching one Windows-signed
/// assertion request.
///
/// # Errors
///
/// Rejects malformed metadata, more than 64 credentials, or an oversized
/// response body.
pub fn encode_passkey_summaries(
    passkeys: &[PasskeySummaryView<'_>],
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    if passkeys.len() > MAX_PASSKEY_CREDENTIALS {
        return Err(ProtocolError::TooLarge);
    }
    let mut encoder = Encoder::new(SecretWriter::with_capacity(MAX_PAYLOAD_BYTES));
    encode_array(
        &mut encoder,
        u64::try_from(passkeys.len()).map_err(|_| ProtocolError::TooLarge)?,
    );
    for passkey in passkeys {
        if passkey.credential_id == [0; PASSKEY_CREDENTIAL_ID_BYTES]
            || passkey.user_handle.is_empty()
            || passkey.user_handle.len() > MAX_PASSKEY_USER_HANDLE_BYTES
            || passkey.user_name.is_empty()
            || passkey.user_name.len() > MAX_PASSKEY_USER_NAME_BYTES
            || passkey.user_display_name.is_empty()
            || passkey.user_display_name.len() > MAX_PASSKEY_USER_NAME_BYTES
        {
            return Err(ProtocolError::InvariantViolation);
        }
        encode_array(&mut encoder, 4);
        encode_bytes(&mut encoder, &passkey.credential_id);
        encode_bytes(&mut encoder, passkey.user_handle);
        encode_text(&mut encoder, passkey.user_name);
        encode_text(&mut encoder, passkey.user_display_name);
    }
    checked_response_body(encoder.into_writer().into_bytes())
}

/// Encodes the bounded public passkey set for the desktop management surface.
///
/// # Errors
///
/// Rejects malformed metadata, more than 64 credentials, or an oversized
/// response body.
pub fn encode_passkey_management_summaries(
    passkeys: &[PasskeyManagementSummaryView<'_>],
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    if passkeys.len() > MAX_PASSKEY_CREDENTIALS {
        return Err(ProtocolError::TooLarge);
    }
    let mut encoder = Encoder::new(SecretWriter::with_capacity(MAX_PAYLOAD_BYTES));
    encode_array(
        &mut encoder,
        u64::try_from(passkeys.len()).map_err(|_| ProtocolError::TooLarge)?,
    );
    for passkey in passkeys {
        if passkey.credential_id == [0; PASSKEY_CREDENTIAL_ID_BYTES]
            || passkey.rp_id.is_empty()
            || passkey.rp_id.len() > MAX_PASSKEY_RP_ID_BYTES
            || passkey.user_name.is_empty()
            || passkey.user_name.len() > MAX_PASSKEY_USER_NAME_BYTES
            || passkey.user_display_name.is_empty()
            || passkey.user_display_name.len() > MAX_PASSKEY_USER_NAME_BYTES
        {
            return Err(ProtocolError::InvariantViolation);
        }
        encode_array(&mut encoder, 4);
        encode_bytes(&mut encoder, &passkey.credential_id);
        encode_text(&mut encoder, passkey.rp_id);
        encode_text(&mut encoder, passkey.user_name);
        encode_text(&mut encoder, passkey.user_display_name);
    }
    checked_response_body(encoder.into_writer().into_bytes())
}

/// Encodes one complete account only for the authorized desktop response.
///
/// # Errors
///
/// Returns `TooLarge` when fields cannot fit in one bounded response.
pub fn encode_account(account: &AccountView<'_>) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    validate_view_fields(account, true)?;
    let mut encoder = Encoder::new(SecretWriter::with_capacity(MAX_PAYLOAD_BYTES));
    encode_array(&mut encoder, 8);
    encode_bytes(&mut encoder, &account.id);
    encode_u64(&mut encoder, account.revision);
    encode_u64(&mut encoder, account.created_at_ms);
    encode_u64(&mut encoder, account.modified_at_ms);
    encode_text(&mut encoder, account.service_name);
    encode_text(&mut encoder, account.permitted_origin);
    encode_text(&mut encoder, account.username);
    encode_text(&mut encoder, account.password);
    checked_response_body(encoder.into_writer().into_bytes())
}

/// Encodes one bounded page of account summaries without passwords.
///
/// # Errors
///
/// Returns `TooLarge` for more than 100 accounts or an oversized body.
pub fn encode_account_summaries(
    accounts: &[AccountView<'_>],
    next_offset: Option<u32>,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    if accounts.len() > usize::from(MAX_LIST_PAGE_SIZE) {
        return Err(ProtocolError::TooLarge);
    }
    let mut maximum_encoded = 8_usize;
    for account in accounts {
        validate_view_fields(account, false)?;
        maximum_encoded = maximum_encoded
            .checked_add(54)
            .and_then(|length| length.checked_add(account.service_name.len()))
            .and_then(|length| length.checked_add(account.permitted_origin.len()))
            .and_then(|length| length.checked_add(account.username.len()))
            .ok_or(ProtocolError::TooLarge)?;
    }
    if maximum_encoded > MAX_RESPONSE_BODY_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    let mut encoder = Encoder::new(SecretWriter::with_capacity(MAX_PAYLOAD_BYTES));
    encode_array(&mut encoder, 2);
    if let Some(offset) = next_offset {
        encode_u32(&mut encoder, offset);
    } else {
        encode_null(&mut encoder);
    }
    encode_array(
        &mut encoder,
        u64::try_from(accounts.len()).map_err(|_| ProtocolError::TooLarge)?,
    );
    for account in accounts {
        encode_array(&mut encoder, 7);
        encode_bytes(&mut encoder, &account.id);
        encode_u64(&mut encoder, account.revision);
        encode_u64(&mut encoder, account.created_at_ms);
        encode_u64(&mut encoder, account.modified_at_ms);
        encode_text(&mut encoder, account.service_name);
        encode_text(&mut encoder, account.permitted_origin);
        encode_text(&mut encoder, account.username);
    }
    checked_response_body(encoder.into_writer().into_bytes())
}

fn validate_view_fields(
    account: &AccountView<'_>,
    include_password: bool,
) -> Result<(), ProtocolError> {
    if account.service_name.len() > MAX_SERVICE_NAME_BYTES
        || account.permitted_origin.len() > MAX_ORIGIN_BYTES
        || account.username.len() > MAX_USERNAME_BYTES
        || (include_password && account.password.len() > MAX_PASSWORD_BYTES)
    {
        return Err(ProtocolError::TooLarge);
    }
    Ok(())
}

fn checked_request_body(bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    if bytes.len() > MAX_REQUEST_BODY_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    Ok(bytes)
}

fn checked_response_body(bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    if bytes.len() > MAX_RESPONSE_BODY_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    Ok(bytes)
}
