use minicbor::{Decoder, Encoder};
use zeroize::Zeroizing;

use crate::{
    AgentState, MAX_PAYLOAD_BYTES, OperationCode, ProtocolError,
    cbor::{
        SecretWriter, decode_bounded_text, decode_fixed_bytes, decode_u16, decode_u32,
        encode_array, encode_bytes, encode_null, encode_text, encode_u8, encode_u16, encode_u32,
        encode_u64, expect_array, require_end,
    },
};

const MAX_MASTER_PASSWORD_BYTES: usize = 1_024;
const MAX_SERVICE_NAME_BYTES: usize = 256;
const MAX_ORIGIN_BYTES: usize = 2_048;
const MAX_USERNAME_BYTES: usize = 1_024;
const MAX_PASSWORD_BYTES: usize = 16 * 1_024;
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
    CreateVault { master_password: Zeroizing<String> },
    UnlockMasterPassword { master_password: Zeroizing<String> },
    Lock,
    ListAccountSummaries { offset: u32, limit: u16 },
    GetAccount { id: [u8; 16] },
    AddAccount { fields: AccountFields },
    UpdateAccount { id: [u8; 16], fields: AccountFields },
    DeleteAccount { id: [u8; 16] },
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
            OperationCode::EnrollWindowsHello
            | OperationCode::RemoveWindowsHello
            | OperationCode::ExactOriginMatches
            | OperationCode::GetSelectedCredential
            | OperationCode::CaptureCredential
            | OperationCode::UpdateCredential
            | OperationCode::MakePasskey
            | OperationCode::GetPasskeyAssertion
            | OperationCode::DeletePasskey => return Err(ProtocolError::Unsupported),
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
    /// Returns `TooLarge` if the body exceeds the protocol frame limit.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        if self
            .master_password()
            .is_some_and(|password| password.len() > MAX_MASTER_PASSWORD_BYTES)
        {
            return Err(ProtocolError::TooLarge);
        }
        let mut encoder = Encoder::new(SecretWriter::with_capacity(MAX_PAYLOAD_BYTES));
        match self {
            Self::Status | Self::Lock => encode_array(&mut encoder, 0),
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
        }
        checked_request_body(encoder.into_writer().into_bytes())
    }
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
