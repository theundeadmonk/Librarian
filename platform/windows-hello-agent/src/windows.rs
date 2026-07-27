use std::{
    ffi::c_void, mem::size_of, num::NonZeroUsize, os::windows::ffi::OsStrExt, path::Path, ptr,
    slice,
};

use librarian_vault_core::WindowsHelloPrfOutput;
use windows_sys::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, GetLastError, HANDLE, LocalFree,
        },
        Security::{
            ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                ConvertStringSidToSidW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
                SetNamedSecurityInfoW,
            },
            Cryptography::{
                CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
            },
            DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
            GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
            GetTokenInformation, IsValidAcl, IsValidSid, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
            TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        Storage::FileSystem::{FILE_ALL_ACCESS, ReplaceFileW},
        System::{
            SystemServices::ACCESS_ALLOWED_ACE_TYPE,
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
        UI::WindowsAndMessaging::{GetWindowThreadProcessId, IsWindow},
    },
    core::PWSTR,
};
use zeroize::Zeroizing;

const OPERATION_ID_BYTES: usize = 16;
const OPERATION_ID_BYTES_U32: u32 = 16;
const PRF_BYTES: usize = 32;
const PRF_BYTES_U32: u32 = 32;
const MAXIMUM_CREDENTIAL_ID_BYTES: usize = 1_024;
const MAXIMUM_CREDENTIAL_ID_BYTES_U32: u32 = 1_024;
const MAXIMUM_PROTECTED_STATE_PLAINTEXT_BYTES: usize = 4 * 1_024;
const MAXIMUM_DPAPI_BLOB_BYTES: usize = 16 * 1_024;
const MAXIMUM_TOKEN_INFORMATION_BYTES: u32 = 1_048_576;
const MAXIMUM_SID_CHARACTERS: usize = 256;
const SID_HEADER_BYTES: usize = 8;
const SID_SUBAUTHORITY_BYTES: usize = 4;
const DPAPI_ENTROPY: &[u8] = b"Librarian Windows Hello local state v1";
const SYSTEM_SID: &str = "S-1-5-18";

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_ARGUMENT: u32 = 1;
const STATUS_UNAVAILABLE: u32 = 2;
const STATUS_UNSUPPORTED: u32 = 3;
const STATUS_CANCELLED: u32 = 4;
const STATUS_INVALID_RESPONSE: u32 = 5;
const STATUS_PLATFORM_FAILURE: u32 = 6;
const STATUS_CREDENTIAL_REMOVAL_FAILED: u32 = 7;

unsafe extern "C" {
    fn librarian_windows_hello_is_available(available: *mut u32) -> u32;
    fn librarian_windows_hello_enroll(
        parent_window: usize,
        operation_id: *const u8,
        operation_id_bytes: u32,
        credential_id: *mut u8,
        credential_id_capacity: u32,
        credential_id_bytes: *mut u32,
        salt: *mut u8,
        salt_bytes: u32,
        prf_output: *mut u8,
        prf_output_bytes: u32,
    ) -> u32;
    fn librarian_windows_hello_evaluate(
        parent_window: usize,
        operation_id: *const u8,
        operation_id_bytes: u32,
        credential_id: *const u8,
        credential_id_bytes: u32,
        salt: *const u8,
        salt_bytes: u32,
        prf_output: *mut u8,
        prf_output_bytes: u32,
    ) -> u32;
    fn librarian_windows_hello_cancel(operation_id: *const u8, operation_id_bytes: u32) -> u32;
    fn librarian_windows_hello_remove(credential_id: *const u8, credential_id_bytes: u32) -> u32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeError {
    InvalidArgument,
    Unavailable,
    Unsupported,
    Cancelled,
    InvalidResponse,
    PlatformFailure,
    CredentialRemovalFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedStateError {
    InvalidArgument,
    PlatformFailure,
}

struct LocalBlob(CRYPT_INTEGER_BLOB);

impl LocalBlob {
    fn as_slice(&self) -> Result<&[u8], ProtectedStateError> {
        let length =
            usize::try_from(self.0.cbData).map_err(|_| ProtectedStateError::PlatformFailure)?;
        if self.0.pbData.is_null() || length == 0 {
            return Err(ProtectedStateError::PlatformFailure);
        }
        // SAFETY: DPAPI returned a live allocation with `cbData` initialized.
        Ok(unsafe { slice::from_raw_parts(self.0.pbData, length) })
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper uniquely owns a successful token handle.
            let _ = unsafe { CloseHandle(self.0) };
            self.0 = ptr::null_mut();
        }
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: every allocation in this wrapper is documented to use
            // `LocalAlloc` and is uniquely released here.
            let _ = unsafe { LocalFree(self.0) };
            self.0 = ptr::null_mut();
        }
    }
}

struct AlignedBuffer {
    words: Vec<usize>,
    byte_len: usize,
}

impl AlignedBuffer {
    fn new(byte_len: usize) -> Result<Self, ProtectedStateError> {
        let word_size = size_of::<usize>();
        let words = byte_len
            .checked_add(word_size - 1)
            .ok_or(ProtectedStateError::PlatformFailure)?
            / word_size;
        Ok(Self {
            words: vec![0; words],
            byte_len,
        })
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.words.as_mut_ptr().cast()
    }

    fn cast_ptr<T>(&self) -> *const T {
        self.words.as_ptr().cast()
    }
}

impl Drop for LocalBlob {
    fn drop(&mut self) {
        if self.0.pbData.is_null() {
            return;
        }
        let Ok(length) = usize::try_from(self.0.cbData) else {
            return;
        };
        for index in 0..length {
            // SAFETY: the DPAPI allocation contains `cbData` writable bytes
            // until it is released by `LocalFree` below.
            unsafe { ptr::write_volatile(self.0.pbData.add(index), 0) };
        }
        // SAFETY: DPAPI documents that its returned blob uses `LocalAlloc`.
        let _ = unsafe { LocalFree(self.0.pbData.cast()) };
        self.0.pbData = ptr::null_mut();
        self.0.cbData = 0;
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct OperationId([u8; OPERATION_ID_BYTES]);

impl OperationId {
    /// Creates a nonzero identifier for exactly one Windows ceremony.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` for the all-zero sentinel.
    pub fn new(value: [u8; OPERATION_ID_BYTES]) -> Result<Self, BridgeError> {
        if value.iter().all(|byte| *byte == 0) {
            return Err(BridgeError::InvalidArgument);
        }
        Ok(Self(value))
    }

    fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ParentWindow(NonZeroUsize);

impl ParentWindow {
    /// Binds a live window to the already authenticated desktop process.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` for a zero, stale, or foreign window.
    pub fn for_authenticated_process(
        value: usize,
        authenticated_process_id: u32,
    ) -> Result<Self, BridgeError> {
        let value = NonZeroUsize::new(value).ok_or(BridgeError::InvalidArgument)?;
        let window = value.get() as *mut c_void;
        if unsafe { IsWindow(window) } == 0 {
            return Err(BridgeError::InvalidArgument);
        }
        let mut actual_process_id = 0_u32;
        if unsafe { GetWindowThreadProcessId(window, &raw mut actual_process_id) } == 0
            || actual_process_id == 0
            || actual_process_id != authenticated_process_id
        {
            return Err(BridgeError::InvalidArgument);
        }
        Ok(Self(value))
    }

    fn get(self) -> usize {
        self.0.get()
    }
}

pub struct Enrollment {
    credential_id: Vec<u8>,
    salt: [u8; PRF_BYTES],
    prf_output: WindowsHelloPrfOutput,
}

impl Enrollment {
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, [u8; PRF_BYTES], WindowsHelloPrfOutput) {
        (self.credential_id, self.salt, self.prf_output)
    }
}

/// Reports whether the required Windows platform authenticator is available.
///
/// # Errors
///
/// Returns a detail-free platform failure if capability discovery fails.
pub fn is_available() -> Result<bool, BridgeError> {
    let mut available = 0_u32;
    let status = unsafe { librarian_windows_hello_is_available(&raw mut available) };
    map_status(status)?;
    match available {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(BridgeError::InvalidResponse),
    }
}

/// Performs one Windows-owned enrollment ceremony.
///
/// # Errors
///
/// Returns a bounded bridge category for invalid input, cancellation,
/// unavailable capability, invalid native output, or platform failure.
pub fn enroll(parent: ParentWindow, operation_id: OperationId) -> Result<Enrollment, BridgeError> {
    let mut credential_id = vec![0_u8; MAXIMUM_CREDENTIAL_ID_BYTES];
    let mut credential_id_bytes = 0_u32;
    let mut salt = [0_u8; PRF_BYTES];
    let mut prf_output = Zeroizing::new([0_u8; PRF_BYTES]);
    let status = unsafe {
        librarian_windows_hello_enroll(
            parent.get(),
            operation_id.as_ptr(),
            OPERATION_ID_BYTES_U32,
            credential_id.as_mut_ptr(),
            MAXIMUM_CREDENTIAL_ID_BYTES_U32,
            &raw mut credential_id_bytes,
            salt.as_mut_ptr(),
            PRF_BYTES_U32,
            prf_output.as_mut_ptr(),
            PRF_BYTES_U32,
        )
    };
    map_status(status)?;
    let credential_id_bytes =
        usize::try_from(credential_id_bytes).map_err(|_| BridgeError::InvalidResponse)?;
    if credential_id_bytes == 0 || credential_id_bytes > credential_id.len() {
        return Err(BridgeError::InvalidResponse);
    }
    credential_id.truncate(credential_id_bytes);
    Ok(Enrollment {
        credential_id,
        salt,
        prf_output: WindowsHelloPrfOutput::new(*prf_output),
    })
}

/// Evaluates PRF after one Windows-owned verification ceremony.
///
/// # Errors
///
/// Returns a bounded bridge category for invalid input, cancellation,
/// unavailable capability, invalid native output, or platform failure.
pub fn evaluate(
    parent: ParentWindow,
    operation_id: OperationId,
    credential_id: &[u8],
    salt: &[u8; PRF_BYTES],
) -> Result<WindowsHelloPrfOutput, BridgeError> {
    if credential_id.is_empty() || credential_id.len() > MAXIMUM_CREDENTIAL_ID_BYTES {
        return Err(BridgeError::InvalidArgument);
    }
    let mut prf_output = Zeroizing::new([0_u8; PRF_BYTES]);
    let status = unsafe {
        librarian_windows_hello_evaluate(
            parent.get(),
            operation_id.as_ptr(),
            OPERATION_ID_BYTES_U32,
            credential_id.as_ptr(),
            u32::try_from(credential_id.len()).map_err(|_| BridgeError::InvalidArgument)?,
            salt.as_ptr(),
            PRF_BYTES_U32,
            prf_output.as_mut_ptr(),
            PRF_BYTES_U32,
        )
    };
    map_status(status)?;
    Ok(WindowsHelloPrfOutput::new(*prf_output))
}

/// Cancels the exact ceremony carrying `operation_id`.
///
/// # Errors
///
/// Returns a bounded bridge category if native cancellation fails.
pub fn cancel(operation_id: OperationId) -> Result<(), BridgeError> {
    let status =
        unsafe { librarian_windows_hello_cancel(operation_id.as_ptr(), OPERATION_ID_BYTES_U32) };
    map_status(status)
}

/// Removes exactly one Librarian platform credential.
///
/// # Errors
///
/// Returns a bounded bridge category for invalid input or removal failure.
pub fn remove(credential_id: &[u8]) -> Result<(), BridgeError> {
    if credential_id.is_empty() || credential_id.len() > MAXIMUM_CREDENTIAL_ID_BYTES {
        return Err(BridgeError::InvalidArgument);
    }
    let status = unsafe {
        librarian_windows_hello_remove(
            credential_id.as_ptr(),
            u32::try_from(credential_id.len()).map_err(|_| BridgeError::InvalidArgument)?,
        )
    };
    map_status(status)
}

/// Protects one bounded local-state record for the current Windows user.
///
/// # Errors
///
/// Returns `InvalidArgument` for an empty or oversized record and
/// `PlatformFailure` if DPAPI cannot protect it without UI.
pub fn protect_user_state(
    mut plaintext: Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>, ProtectedStateError> {
    if plaintext.is_empty() || plaintext.len() > MAXIMUM_PROTECTED_STATE_PLAINTEXT_BYTES {
        return Err(ProtectedStateError::InvalidArgument);
    }
    let input_length =
        u32::try_from(plaintext.len()).map_err(|_| ProtectedStateError::InvalidArgument)?;
    let entropy_length =
        u32::try_from(DPAPI_ENTROPY.len()).map_err(|_| ProtectedStateError::PlatformFailure)?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: input_length,
        pbData: plaintext.as_mut_ptr(),
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: entropy_length,
        pbData: DPAPI_ENTROPY.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: every input blob points to a live allocation for the duration
    // of the call; output is writable and UI is explicitly forbidden.
    if unsafe {
        CryptProtectData(
            &raw const input,
            ptr::null(),
            &raw const entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    } == 0
    {
        return Err(ProtectedStateError::PlatformFailure);
    }
    let output = LocalBlob(output);
    let bytes = output.as_slice()?;
    if bytes.len() > MAXIMUM_DPAPI_BLOB_BYTES {
        return Err(ProtectedStateError::PlatformFailure);
    }
    Ok(bytes.to_vec())
}

/// Unprotects one bounded local-state record for the current Windows user.
///
/// # Errors
///
/// Returns `InvalidArgument` for an empty or oversized blob and
/// `PlatformFailure` for a wrong user, corruption, or any DPAPI failure.
pub fn unprotect_user_state(ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProtectedStateError> {
    if ciphertext.is_empty() || ciphertext.len() > MAXIMUM_DPAPI_BLOB_BYTES {
        return Err(ProtectedStateError::InvalidArgument);
    }
    let input_length =
        u32::try_from(ciphertext.len()).map_err(|_| ProtectedStateError::InvalidArgument)?;
    let entropy_length =
        u32::try_from(DPAPI_ENTROPY.len()).map_err(|_| ProtectedStateError::PlatformFailure)?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: input_length,
        pbData: ciphertext.as_ptr().cast_mut(),
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: entropy_length,
        pbData: DPAPI_ENTROPY.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: every input blob points to a live allocation for the duration
    // of the call; output is writable and UI is explicitly forbidden.
    if unsafe {
        CryptUnprotectData(
            &raw const input,
            ptr::null_mut(),
            &raw const entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    } == 0
    {
        return Err(ProtectedStateError::PlatformFailure);
    }
    let output = LocalBlob(output);
    let bytes = output.as_slice()?;
    if bytes.len() > MAXIMUM_PROTECTED_STATE_PLAINTEXT_BYTES {
        return Err(ProtectedStateError::PlatformFailure);
    }
    Ok(Zeroizing::new(bytes.to_vec()))
}

/// Replaces inheritance with an exact current-user and `LocalSystem` file DACL.
///
/// # Errors
///
/// Returns `InvalidArgument` for a non-absolute path or embedded NUL and
/// `PlatformFailure` if the token, descriptor, ACL update, or readback fails.
pub fn restrict_user_file(path: &Path) -> Result<(), ProtectedStateError> {
    if !path.is_absolute() {
        return Err(ProtectedStateError::InvalidArgument);
    }
    let user_sid = current_user_sid()?;
    let sddl = format!("O:{user_sid}D:P(A;;FA;;;SY)(A;;FA;;;{user_sid})");
    let descriptor = descriptor_from_sddl(&sddl)?;
    validate_restricted_descriptor(descriptor.0, &user_sid)?;

    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = ptr::null_mut();
    // SAFETY: the descriptor is live and every output points to initialized,
    // writable storage.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor.0,
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
    } == 0
        || present == 0
        || defaulted != 0
        || dacl.is_null()
    {
        return Err(ProtectedStateError::PlatformFailure);
    }

    let mut wide = wide_path(path)?;
    // SAFETY: the path is a live terminated UTF-16 string and the DACL
    // remains owned by `descriptor` for the duration of this call.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(ProtectedStateError::PlatformFailure);
    }
    verify_user_file_restriction(path)
}

/// Verifies that a file is owned by the current user and has exactly the
/// protected current-user and `LocalSystem` full-control DACL.
///
/// # Errors
///
/// Returns `InvalidArgument` for a non-absolute path or embedded NUL and
/// `PlatformFailure` for a missing, inherited, broadened, or unreadable ACL.
pub fn verify_user_file_restriction(path: &Path) -> Result<(), ProtectedStateError> {
    if !path.is_absolute() {
        return Err(ProtectedStateError::InvalidArgument);
    }
    let user_sid = current_user_sid()?;
    let wide = wide_path(path)?;
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: the path is a live terminated UTF-16 string and all requested
    // output pointers refer to writable storage. The returned descriptor owns
    // the embedded owner and DACL pointers.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            ptr::null_mut(),
            &raw mut dacl,
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() {
        return Err(ProtectedStateError::PlatformFailure);
    }
    let descriptor = LocalAllocation(descriptor);
    if owner.is_null() || dacl.is_null() {
        return Err(ProtectedStateError::PlatformFailure);
    }
    validate_restricted_descriptor(descriptor.0, &user_sid)
}

fn current_user_sid() -> Result<String, ProtectedStateError> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: the pseudo process handle is always valid for this query and
    // `token` points to writable handle storage.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0
        || token.is_null()
    {
        return Err(ProtectedStateError::PlatformFailure);
    }
    let token = OwnedHandle(token);
    let mut bytes = 0_u32;
    // SAFETY: a null buffer and zero length is the documented sizing query.
    let size_result =
        unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &raw mut bytes) };
    // SAFETY: this immediately observes the error from the sizing query.
    let size_error = unsafe { GetLastError() };
    if size_result != 0
        || size_error != ERROR_INSUFFICIENT_BUFFER
        || bytes == 0
        || bytes > MAXIMUM_TOKEN_INFORMATION_BYTES
    {
        return Err(ProtectedStateError::PlatformFailure);
    }
    let mut buffer = AlignedBuffer::new(
        usize::try_from(bytes).map_err(|_| ProtectedStateError::PlatformFailure)?,
    )?;
    let mut written = bytes;
    // SAFETY: `buffer` has `bytes` writable, suitably aligned bytes and
    // remains live for the call.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr(),
            bytes,
            &raw mut written,
        )
    } == 0
        || written
            < u32::try_from(size_of::<TOKEN_USER>())
                .map_err(|_| ProtectedStateError::PlatformFailure)?
        || usize::try_from(written).map_or(true, |length| length > buffer.byte_len)
    {
        return Err(ProtectedStateError::PlatformFailure);
    }
    // SAFETY: the successful token query returned at least one `TOKEN_USER`.
    let user = unsafe { &*buffer.cast_ptr::<TOKEN_USER>() };
    if user.User.Sid.is_null() || unsafe { IsValidSid(user.User.Sid) } == 0 {
        return Err(ProtectedStateError::PlatformFailure);
    }
    sid_to_string(user.User.Sid)
}

fn sid_to_string(sid: PSID) -> Result<String, ProtectedStateError> {
    let mut raw: PWSTR = ptr::null_mut();
    // SAFETY: the caller supplied a validated SID and `raw` points to writable
    // pointer storage. Windows allocates the result with `LocalAlloc`.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut raw) } == 0 || raw.is_null() {
        return Err(ProtectedStateError::PlatformFailure);
    }
    let allocation = LocalAllocation(raw.cast());
    let mut length = 0_usize;
    // SAFETY: the conversion API returned a terminated Windows string.
    unsafe {
        while *raw.add(length) != 0 {
            length = length
                .checked_add(1)
                .ok_or(ProtectedStateError::PlatformFailure)?;
            if length > MAXIMUM_SID_CHARACTERS {
                return Err(ProtectedStateError::PlatformFailure);
            }
        }
        let value = String::from_utf16(slice::from_raw_parts(raw, length))
            .map_err(|_| ProtectedStateError::PlatformFailure)?;
        drop(allocation);
        Ok(value)
    }
}

fn descriptor_from_sddl(value: &str) -> Result<LocalAllocation, ProtectedStateError> {
    let wide = wide_string(value)?;
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `wide` is terminated and `descriptor` points to writable output
    // storage. Windows allocates the result with `LocalAlloc`.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            ptr::null_mut(),
        )
    } == 0
        || descriptor.is_null()
    {
        return Err(ProtectedStateError::PlatformFailure);
    }
    Ok(LocalAllocation(descriptor))
}

fn string_to_sid(value: &str) -> Result<LocalAllocation, ProtectedStateError> {
    let wide = wide_string(value)?;
    let mut sid: PSID = ptr::null_mut();
    // SAFETY: `wide` is terminated and `sid` points to writable output
    // storage. Windows allocates the result with `LocalAlloc`.
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &raw mut sid) } == 0 || sid.is_null() {
        return Err(ProtectedStateError::PlatformFailure);
    }
    let sid = LocalAllocation(sid);
    if unsafe { IsValidSid(sid.0.cast()) } == 0 {
        return Err(ProtectedStateError::PlatformFailure);
    }
    Ok(sid)
}

#[derive(Clone, Copy)]
enum RestrictedTrustee {
    CurrentUser,
    LocalSystem,
}

fn validate_restricted_descriptor(
    descriptor: PSECURITY_DESCRIPTOR,
    user_sid: &str,
) -> Result<(), ProtectedStateError> {
    if descriptor.is_null() {
        return Err(ProtectedStateError::PlatformFailure);
    }
    let mut owner: PSID = ptr::null_mut();
    let mut owner_defaulted = 0;
    // SAFETY: `descriptor` is live and both outputs point to writable storage.
    if unsafe { GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut owner_defaulted) }
        == 0
        || owner.is_null()
        || unsafe { IsValidSid(owner) } == 0
        || owner_defaulted != 0
    {
        return Err(ProtectedStateError::PlatformFailure);
    }

    let expected_user = string_to_sid(user_sid)?;
    if unsafe { EqualSid(owner, expected_user.0.cast()) } == 0 {
        return Err(ProtectedStateError::PlatformFailure);
    }

    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = ptr::null_mut();
    // SAFETY: `descriptor` is live and all outputs point to writable storage.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
    } == 0
        || present == 0
        || defaulted != 0
        || dacl.is_null()
        || unsafe { IsValidAcl(dacl) } == 0
    {
        return Err(ProtectedStateError::PlatformFailure);
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: `descriptor` is live and both scalar outputs are writable.
    if unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Err(ProtectedStateError::PlatformFailure);
    }

    let mut size = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` belongs to the live descriptor and `size` is a correctly
    // sized writable output.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut size).cast(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>())
                .map_err(|_| ProtectedStateError::PlatformFailure)?,
            AclSizeInformation,
        )
    } == 0
        || size.AceCount != 2
    {
        return Err(ProtectedStateError::PlatformFailure);
    }

    let system = string_to_sid(SYSTEM_SID)?;
    let mut saw_system = false;
    let mut saw_user = false;
    for index in 0..size.AceCount {
        let mut raw_ace: *mut c_void = ptr::null_mut();
        // SAFETY: `index` is below the ACL's reported ACE count and output
        // storage is writable.
        if unsafe { GetAce(dacl, index, &raw mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(ProtectedStateError::PlatformFailure);
        }
        match restricted_ace_trustee(raw_ace, expected_user.0.cast(), system.0.cast())? {
            RestrictedTrustee::LocalSystem => {
                if saw_system {
                    return Err(ProtectedStateError::PlatformFailure);
                }
                saw_system = true;
            }
            RestrictedTrustee::CurrentUser => {
                if saw_user {
                    return Err(ProtectedStateError::PlatformFailure);
                }
                saw_user = true;
            }
        }
    }
    if !saw_system || !saw_user {
        return Err(ProtectedStateError::PlatformFailure);
    }
    Ok(())
}

fn restricted_ace_trustee(
    raw_ace: *mut c_void,
    expected_user: PSID,
    system: PSID,
) -> Result<RestrictedTrustee, ProtectedStateError> {
    // SAFETY: `GetAce` returned this live ACE pointer from a validated ACL.
    let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
    if u32::from(ace.Header.AceType) != ACCESS_ALLOWED_ACE_TYPE
        || ace.Header.AceFlags != 0
        || usize::from(ace.Header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
        || ace.Mask != FILE_ALL_ACCESS
    {
        return Err(ProtectedStateError::PlatformFailure);
    }
    let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    let sid_bytes = usize::from(ace.Header.AceSize)
        .checked_sub(sid_offset)
        .ok_or(ProtectedStateError::PlatformFailure)?;
    if sid_bytes < SID_HEADER_BYTES {
        return Err(ProtectedStateError::PlatformFailure);
    }
    let sid: PSID = (&raw const ace.SidStart).cast_mut().cast();
    // SAFETY: `sid_bytes` proves the fixed SID header, including the
    // subauthority-count byte, remains inside this validated ACE.
    let subauthority_count = unsafe { *sid.cast::<u8>().add(1) };
    let expected_sid_bytes = usize::from(subauthority_count)
        .checked_mul(SID_SUBAUTHORITY_BYTES)
        .and_then(|bytes| bytes.checked_add(SID_HEADER_BYTES))
        .ok_or(ProtectedStateError::PlatformFailure)?;
    if expected_sid_bytes != sid_bytes || unsafe { IsValidSid(sid) } == 0 {
        return Err(ProtectedStateError::PlatformFailure);
    }
    if unsafe { EqualSid(sid, system) } != 0 {
        Ok(RestrictedTrustee::LocalSystem)
    } else if unsafe { EqualSid(sid, expected_user) } != 0 {
        Ok(RestrictedTrustee::CurrentUser)
    } else {
        Err(ProtectedStateError::PlatformFailure)
    }
}

fn wide_string(value: &str) -> Result<Vec<u16>, ProtectedStateError> {
    let mut wide: Vec<u16> = value.encode_utf16().collect();
    if wide.contains(&0) {
        return Err(ProtectedStateError::InvalidArgument);
    }
    wide.push(0);
    Ok(wide)
}

/// Replaces one existing file with a fully written sibling staging file.
///
/// # Errors
///
/// Returns `InvalidArgument` unless both paths are distinct absolute siblings
/// without embedded NUL values. Returns `PlatformFailure` if Windows cannot
/// perform the atomic replacement.
pub fn replace_file_atomically(
    replaced: &Path,
    replacement: &Path,
) -> Result<(), ProtectedStateError> {
    if !replaced.is_absolute()
        || !replacement.is_absolute()
        || replaced == replacement
        || replaced.parent().is_none()
        || replaced.parent() != replacement.parent()
    {
        return Err(ProtectedStateError::InvalidArgument);
    }
    let replaced = wide_path(replaced)?;
    let replacement = wide_path(replacement)?;
    // SAFETY: both paths are live, terminated UTF-16 strings; optional backup
    // and merge callback pointers are null.
    if unsafe {
        ReplaceFileW(
            replaced.as_ptr(),
            replacement.as_ptr(),
            ptr::null(),
            0,
            ptr::null(),
            ptr::null(),
        )
    } == 0
    {
        return Err(ProtectedStateError::PlatformFailure);
    }
    Ok(())
}

fn wide_path(path: &Path) -> Result<Vec<u16>, ProtectedStateError> {
    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.contains(&0) {
        return Err(ProtectedStateError::InvalidArgument);
    }
    value.push(0);
    Ok(value)
}

fn map_status(status: u32) -> Result<(), BridgeError> {
    if status == STATUS_INVALID_RESPONSE {
        return Err(BridgeError::InvalidResponse);
    }
    match status {
        STATUS_SUCCESS => Ok(()),
        STATUS_INVALID_ARGUMENT => Err(BridgeError::InvalidArgument),
        STATUS_UNAVAILABLE => Err(BridgeError::Unavailable),
        STATUS_UNSUPPORTED => Err(BridgeError::Unsupported),
        STATUS_CANCELLED => Err(BridgeError::Cancelled),
        STATUS_PLATFORM_FAILURE => Err(BridgeError::PlatformFailure),
        STATUS_CREDENTIAL_REMOVAL_FAILED => Err(BridgeError::CredentialRemovalFailed),
        _ => Err(BridgeError::InvalidResponse),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    use zeroize::Zeroizing;

    use super::{
        BridgeError, OperationId, ParentWindow, ProtectedStateError, is_available,
        protect_user_state, restrict_user_file, unprotect_user_state, verify_user_file_restriction,
    };

    static TEST_FILE_COUNTER: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn operation_identifiers_and_parent_windows_reject_zero() {
        assert!(matches!(
            OperationId::new([0; 16]),
            Err(BridgeError::InvalidArgument)
        ));
        assert!(matches!(
            ParentWindow::for_authenticated_process(0, 1),
            Err(BridgeError::InvalidArgument)
        ));
    }

    #[test]
    fn capability_check_is_detail_free() {
        assert!(matches!(
            is_available(),
            Ok(_) | Err(BridgeError::PlatformFailure)
        ));
    }

    #[test]
    fn dpapi_round_trip_is_current_user_bound_and_ui_forbidden() {
        let plaintext = b"disposable Windows Hello state test value".to_vec();
        let protected =
            protect_user_state(Zeroizing::new(plaintext.clone())).expect("DPAPI protect");
        assert!(
            !protected
                .windows(plaintext.len())
                .any(|value| value == plaintext)
        );
        let unprotected = unprotect_user_state(&protected).expect("DPAPI unprotect");
        assert_eq!(unprotected.as_slice(), plaintext);

        let mut corrupted = protected;
        let last = corrupted.last_mut().expect("DPAPI output is nonempty");
        *last ^= 1;
        assert!(matches!(
            unprotect_user_state(&corrupted),
            Err(ProtectedStateError::PlatformFailure)
        ));
    }

    #[test]
    fn local_state_acl_is_protected_and_exact() {
        let sequence = TEST_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "librarian-hello-acl-{}-{sequence}.tmp",
            std::process::id()
        ));
        fs::write(&path, b"disposable protected-state ACL test").expect("test file");
        assert!(matches!(
            verify_user_file_restriction(&path),
            Err(ProtectedStateError::PlatformFailure)
        ));
        restrict_user_file(&path).expect("restrict test file");
        verify_user_file_restriction(&path).expect("verify restricted test file");
        fs::remove_file(path).expect("remove test file");
    }
}
