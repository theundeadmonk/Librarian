use core::fmt;

/// A negotiated protocol version.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Version {
    major: u16,
    minor: u16,
}

impl Version {
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }
}

/// Role derived from authenticated process and package identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ClientRole {
    Desktop = 1,
    NativeHost = 2,
    PasskeyProvider = 3,
}

impl ClientRole {
    pub(crate) const fn from_u64(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::Desktop),
            2 => Some(Self::NativeHost),
            3 => Some(Self::PasskeyProvider),
            _ => None,
        }
    }
}

/// Public lifecycle state. It contains no vault metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AgentState {
    Starting = 1,
    NoVault = 2,
    Locked = 3,
    Unlocking = 4,
    Unlocked = 5,
    Updating = 6,
    ShuttingDown = 7,
}

impl AgentState {
    pub(crate) const fn from_u64(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::Starting),
            2 => Some(Self::NoVault),
            3 => Some(Self::Locked),
            4 => Some(Self::Unlocking),
            5 => Some(Self::Unlocked),
            6 => Some(Self::Updating),
            7 => Some(Self::ShuttingDown),
            _ => None,
        }
    }
}

/// Closed version-1 operation set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum OperationCode {
    Status = 1,
    CreateVault = 2,
    UnlockMasterPassword = 3,
    Lock = 4,
    ListAccountSummaries = 5,
    GetAccount = 6,
    AddAccount = 7,
    UpdateAccount = 8,
    DeleteAccount = 9,
    EnrollWindowsHello = 10,
    RemoveWindowsHello = 11,
    UnlockWindowsHello = 12,
    ExactOriginMatches = 20,
    GetSelectedCredential = 21,
    CaptureCredential = 22,
    UpdateCredential = 23,
    MakePasskey = 30,
    GetPasskeyAssertion = 31,
    DeletePasskey = 32,
}

impl OperationCode {
    /// Complete closed operation set for version 1.
    pub const ALL: [Self; 19] = [
        Self::Status,
        Self::CreateVault,
        Self::UnlockMasterPassword,
        Self::Lock,
        Self::ListAccountSummaries,
        Self::GetAccount,
        Self::AddAccount,
        Self::UpdateAccount,
        Self::DeleteAccount,
        Self::EnrollWindowsHello,
        Self::RemoveWindowsHello,
        Self::UnlockWindowsHello,
        Self::ExactOriginMatches,
        Self::GetSelectedCredential,
        Self::CaptureCredential,
        Self::UpdateCredential,
        Self::MakePasskey,
        Self::GetPasskeyAssertion,
        Self::DeletePasskey,
    ];

    #[must_use]
    pub const fn is_authorized_for(self, role: ClientRole) -> bool {
        match role {
            ClientRole::Desktop => matches!(
                self,
                Self::Status
                    | Self::CreateVault
                    | Self::UnlockMasterPassword
                    | Self::Lock
                    | Self::ListAccountSummaries
                    | Self::GetAccount
                    | Self::AddAccount
                    | Self::UpdateAccount
                    | Self::DeleteAccount
                    | Self::EnrollWindowsHello
                    | Self::RemoveWindowsHello
                    | Self::UnlockWindowsHello
            ),
            ClientRole::NativeHost => matches!(
                self,
                Self::Status
                    | Self::ExactOriginMatches
                    | Self::GetSelectedCredential
                    | Self::CaptureCredential
                    | Self::UpdateCredential
            ),
            ClientRole::PasskeyProvider => matches!(
                self,
                Self::Status | Self::MakePasskey | Self::GetPasskeyAssertion | Self::DeletePasskey
            ),
        }
    }

    #[must_use]
    pub const fn requires_idempotency_key(self) -> bool {
        matches!(
            self,
            Self::CreateVault
                | Self::AddAccount
                | Self::UpdateAccount
                | Self::DeleteAccount
                | Self::EnrollWindowsHello
                | Self::RemoveWindowsHello
                | Self::CaptureCredential
                | Self::UpdateCredential
                | Self::MakePasskey
                | Self::DeletePasskey
        )
    }

    #[must_use]
    pub const fn requires_unlocked_epoch(self) -> bool {
        matches!(
            self,
            Self::ListAccountSummaries
                | Self::GetAccount
                | Self::AddAccount
                | Self::UpdateAccount
                | Self::DeleteAccount
                | Self::EnrollWindowsHello
                | Self::RemoveWindowsHello
                | Self::ExactOriginMatches
                | Self::GetSelectedCredential
                | Self::CaptureCredential
                | Self::UpdateCredential
                | Self::MakePasskey
                | Self::GetPasskeyAssertion
                | Self::DeletePasskey
        )
    }

    pub(crate) const fn from_u64(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::Status),
            2 => Some(Self::CreateVault),
            3 => Some(Self::UnlockMasterPassword),
            4 => Some(Self::Lock),
            5 => Some(Self::ListAccountSummaries),
            6 => Some(Self::GetAccount),
            7 => Some(Self::AddAccount),
            8 => Some(Self::UpdateAccount),
            9 => Some(Self::DeleteAccount),
            10 => Some(Self::EnrollWindowsHello),
            11 => Some(Self::RemoveWindowsHello),
            12 => Some(Self::UnlockWindowsHello),
            20 => Some(Self::ExactOriginMatches),
            21 => Some(Self::GetSelectedCredential),
            22 => Some(Self::CaptureCredential),
            23 => Some(Self::UpdateCredential),
            30 => Some(Self::MakePasskey),
            31 => Some(Self::GetPasskeyAssertion),
            32 => Some(Self::DeletePasskey),
            _ => None,
        }
    }
}

/// Stable public error categories from ADR 0006.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PublicErrorCode {
    InvalidRequest = 1,
    UnauthorizedOperation = 2,
    Locked = 3,
    NotFound = 4,
    Conflict = 5,
    Busy = 6,
    Cancelled = 7,
    DeadlineExceeded = 8,
    AgentUnavailable = 9,
    Incompatible = 10,
    OperationFailed = 11,
}

impl PublicErrorCode {
    pub(crate) const fn from_u64(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::InvalidRequest),
            2 => Some(Self::UnauthorizedOperation),
            3 => Some(Self::Locked),
            4 => Some(Self::NotFound),
            5 => Some(Self::Conflict),
            6 => Some(Self::Busy),
            7 => Some(Self::Cancelled),
            8 => Some(Self::DeadlineExceeded),
            9 => Some(Self::AgentUnavailable),
            10 => Some(Self::Incompatible),
            11 => Some(Self::OperationFailed),
            _ => None,
        }
    }
}

/// Whether an operation may be retried without inventing semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RetryCategory {
    Never = 1,
    Reconnect = 2,
    AfterUnlock = 3,
    Backoff = 4,
}

impl RetryCategory {
    pub(crate) const fn from_u64(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::Never),
            2 => Some(Self::Reconnect),
            3 => Some(Self::AfterUnlock),
            4 => Some(Self::Backoff),
            _ => None,
        }
    }
}

/// Random non-secret identifier used to correlate redacted diagnostics.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CorrelationId([u8; 16]);

impl CorrelationId {
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for CorrelationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CorrelationId(REDACTED)")
    }
}
