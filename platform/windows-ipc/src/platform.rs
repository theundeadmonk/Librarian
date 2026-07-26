use std::{
    ffi::c_void,
    fmt,
    mem::{offset_of, size_of},
    path::PathBuf,
    ptr, slice,
    time::{Duration, Instant},
};

use librarian_agent_protocol::{Frame, FrameError, FrameHeader, HEADER_BYTES, MAX_CONNECTIONS};
use windows_sys::{
    Win32::{
        Foundation::{
            APPMODEL_ERROR_NO_APPLICATION, APPMODEL_ERROR_NO_PACKAGE, CloseHandle,
            ERROR_ALREADY_EXISTS, ERROR_INSUFFICIENT_BUFFER, ERROR_IO_PENDING, ERROR_PIPE_BUSY,
            ERROR_PIPE_CONNECTED, ERROR_SUCCESS, FILETIME, GENERIC_ALL, GENERIC_READ,
            GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree, WAIT_OBJECT_0,
            WAIT_TIMEOUT,
        },
        Security::{
            ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                ConvertStringSidToSidW, SDDL_REVISION_1,
            },
            EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorDacl, GetSidSubAuthority,
            GetSidSubAuthorityCount, GetTokenInformation, IsValidSid, PSECURITY_DESCRIPTOR, PSID,
            RevertToSelf, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_GROUPS,
            TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenGroups,
            TokenIntegrityLevel, TokenIsAppContainer, TokenSessionId, TokenUser,
        },
        Storage::{
            FileSystem::{
                CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
                PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_EFFECTIVE_ONLY, SECURITY_IDENTIFICATION,
                SECURITY_SQOS_PRESENT, SYNCHRONIZE, WriteFile,
            },
            Packaging::Appx::{
                GetApplicationUserModelIdFromToken, GetPackageFamilyNameFromToken,
                GetPackageFullNameFromToken,
            },
        },
        System::{
            IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
                GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
                ImpersonateNamedPipeClient, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_TYPE_BYTE, PIPE_WAIT, WaitNamedPipeW,
            },
            SystemServices::{ACCESS_ALLOWED_ACE_TYPE, SE_GROUP_LOGON_ID},
            Threading::{
                CreateEventW, CreateMutexW, GetCurrentProcessId, GetCurrentThread, GetProcessTimes,
                OpenProcess, OpenProcessToken, OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION,
                QueryFullProcessImageNameW, WaitForMultipleObjects, WaitForSingleObject,
            },
        },
    },
    core::PWSTR,
};
use zeroize::Zeroizing;

use crate::{
    ComponentRole, PeerAuthorizationError, PeerObservation, PeerPolicy, authorize_client_role,
    authorize_peer,
};

const PIPE_BUFFER_BYTES: u32 = 65_576;
const MAX_IMAGE_CHARACTERS: usize = 32_768;
const MAX_TOKEN_INFORMATION_BYTES: u32 = 1_048_576;
const SYSTEM_SID: &str = "S-1-5-18";
const AGENT_INSTANCE_NAME: &str = r"Local\Librarian.Agent.Singleton.v1";
const PIPE_NAME_PREFIX: &str = r"\\.\pipe\LOCAL\Librarian.Agent.v1.";
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Redacted, stable transport failures. Raw Windows errors never cross the
/// trusted-agent boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    AccessDenied,
    PeerExited,
    Timeout,
    MalformedFrame,
    ResourceLimit,
    ListenerLost,
    Unavailable,
    Internal,
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AccessDenied => "local peer was not authorized",
            Self::PeerExited => "local peer exited",
            Self::Timeout => "local transport deadline exceeded",
            Self::MalformedFrame => "local protocol frame was malformed",
            Self::ResourceLimit => "local transport resource limit reached",
            Self::ListenerLost => "local listener pool must be rotated",
            Self::Unavailable => "local agent is unavailable",
            Self::Internal => "local transport operation failed",
        })
    }
}

impl std::error::Error for TransportError {}

impl From<FrameError> for TransportError {
    fn from(_: FrameError) -> Self {
        Self::MalformedFrame
    }
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> Result<Self, TransportError> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(TransportError::Internal);
        }
        Ok(Self(handle))
    }

    const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: `OwnedHandle` is constructed only from an owned, non-null,
        // non-INVALID_HANDLE_VALUE handle and closes it exactly once here.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer was allocated by a Windows conversion API
            // documented to require `LocalFree`, and ownership is unique.
            unsafe {
                let _ = LocalFree(self.0);
            }
        }
    }
}

struct ImpersonationGuard {
    active: bool,
}

impl ImpersonationGuard {
    fn begin(pipe: HANDLE) -> Result<Self, TransportError> {
        // SAFETY: `pipe` is the connected server end of a named pipe. The
        // client constrains this token to SecurityIdentification, which permits
        // identity queries but not resource access in the client's context.
        if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
            return Err(TransportError::AccessDenied);
        }
        Ok(Self { active: true })
    }

    fn revert(mut self) -> Result<(), TransportError> {
        // SAFETY: this thread is currently impersonating the connected client.
        if unsafe { RevertToSelf() } == 0 {
            return Err(TransportError::Internal);
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: best-effort fail-closed cleanup after an earlier error.
            unsafe {
                let _ = RevertToSelf();
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
struct TokenObservation {
    session_id: u32,
    user_sid: String,
    logon_sid: String,
    integrity_rid: u32,
    elevated: bool,
    app_container: bool,
    package_full_name: Option<String>,
    package_family_name: Option<String>,
    application_user_model_id: Option<String>,
}

impl TokenObservation {
    fn from_peer(observation: &PeerObservation) -> Self {
        Self {
            session_id: observation.session_id,
            user_sid: observation.user_sid.clone(),
            logon_sid: observation.logon_sid.clone(),
            integrity_rid: observation.integrity_rid,
            elevated: observation.elevated,
            app_container: observation.app_container,
            package_full_name: observation.package_full_name.clone(),
            package_family_name: observation.package_family_name.clone(),
            application_user_model_id: observation.application_user_model_id.clone(),
        }
    }
}

/// A kernel process handle retained for the full transport connection.
pub struct PeerHandle {
    process: OwnedHandle,
    observation: PeerObservation,
}

impl PeerHandle {
    #[must_use]
    pub const fn observation(&self) -> &PeerObservation {
        &self.observation
    }

    #[must_use]
    pub fn is_alive(&self) -> bool {
        // SAFETY: the retained process handle remains valid for `self`.
        unsafe { WaitForSingleObject(self.process.raw(), 0) == WAIT_TIMEOUT }
    }
}

impl fmt::Debug for PeerHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerHandle(REDACTED)")
    }
}

/// Observes the current process through a retained real process handle.
///
/// # Errors
///
/// Fails closed when any required identity dimension cannot be queried.
pub fn current_process_observation() -> Result<PeerHandle, TransportError> {
    // SAFETY: `GetCurrentProcessId` has no preconditions.
    let process_id = unsafe { GetCurrentProcessId() };
    observe_process(process_id)
}

fn observe_process(process_id: u32) -> Result<PeerHandle, TransportError> {
    if process_id == 0 {
        return Err(TransportError::AccessDenied);
    }
    // SAFETY: the process ID is kernel-observed or is the current process.
    // The requested rights are query-only plus synchronization.
    let raw_process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            0,
            process_id,
        )
    };
    let process = OwnedHandle::new(raw_process).map_err(|_| TransportError::AccessDenied)?;
    let token = open_process_token(process.raw())?;
    let token = observe_token(token.raw())?;
    let process_creation_time = process_creation_time(process.raw())?;
    let image_path = process_image(process.raw())?;

    Ok(PeerHandle {
        process,
        observation: PeerObservation {
            process_id,
            process_creation_time,
            session_id: token.session_id,
            user_sid: token.user_sid,
            logon_sid: token.logon_sid,
            integrity_rid: token.integrity_rid,
            elevated: token.elevated,
            app_container: token.app_container,
            image_path,
            package_full_name: token.package_full_name,
            package_family_name: token.package_family_name,
            application_user_model_id: token.application_user_model_id,
        },
    })
}

fn open_process_token(process: HANDLE) -> Result<OwnedHandle, TransportError> {
    let mut raw_token = ptr::null_mut();
    // SAFETY: `process` is a valid retained process handle and `raw_token`
    // points to initialized writable storage.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut raw_token) } == 0 {
        return Err(TransportError::AccessDenied);
    }
    OwnedHandle::new(raw_token).map_err(|_| TransportError::AccessDenied)
}

fn observe_token(token: HANDLE) -> Result<TokenObservation, TransportError> {
    let user = token_information(token, TokenUser)?;
    let groups = token_information(token, TokenGroups)?;
    let integrity = token_information(token, TokenIntegrityLevel)?;
    let elevation = token_information(token, TokenElevation)?;
    let app_container = token_information(token, TokenIsAppContainer)?;
    let session = token_information(token, TokenSessionId)?;

    Ok(TokenObservation {
        session_id: scalar_from_token::<u32>(&session)?,
        user_sid: token_user_sid(&user)?,
        logon_sid: token_logon_sid(&groups)?,
        integrity_rid: token_integrity_rid(&integrity)?,
        elevated: scalar_from_token::<TOKEN_ELEVATION>(&elevation)?.TokenIsElevated != 0,
        app_container: scalar_from_token::<u32>(&app_container)? != 0,
        package_full_name: appmodel_string(token, GetPackageFullNameFromToken)?,
        package_family_name: appmodel_string(token, GetPackageFamilyNameFromToken)?,
        application_user_model_id: appmodel_string(token, GetApplicationUserModelIdFromToken)?,
    })
}

struct AlignedBuffer {
    words: Vec<usize>,
    byte_len: usize,
}

impl AlignedBuffer {
    fn new(byte_len: usize) -> Result<Self, TransportError> {
        let word_size = size_of::<usize>();
        let words = byte_len
            .checked_add(word_size - 1)
            .ok_or(TransportError::ResourceLimit)?
            / word_size;
        Ok(Self {
            words: vec![0; words],
            byte_len,
        })
    }

    fn cast_ptr<T>(&self) -> *const T {
        self.words.as_ptr().cast()
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.words.as_mut_ptr().cast()
    }
}

fn token_information(token: HANDLE, class: i32) -> Result<AlignedBuffer, TransportError> {
    let mut bytes = 0_u32;
    // SAFETY: a null buffer with zero length is the documented size query.
    let size_result =
        unsafe { GetTokenInformation(token, class, ptr::null_mut(), 0, &raw mut bytes) };
    // Windows returns either `ERROR_INSUFFICIENT_BUFFER` or `ERROR_BAD_LENGTH`
    // for fixed-size token classes. A failed size query with a sane nonzero
    // required length is the only accepted outcome.
    if size_result != 0 || bytes == 0 || bytes > MAX_TOKEN_INFORMATION_BYTES {
        return Err(TransportError::AccessDenied);
    }
    let byte_len = usize::try_from(bytes).map_err(|_| TransportError::ResourceLimit)?;
    let mut buffer = AlignedBuffer::new(byte_len)?;
    let mut written = bytes;
    // SAFETY: `buffer` has at least `bytes` writable bytes, is suitably
    // aligned for token structures, and remains alive for the call.
    if unsafe { GetTokenInformation(token, class, buffer.as_mut_ptr(), bytes, &raw mut written) }
        == 0
        || written == 0
        || usize::try_from(written).map_or(true, |length| length > buffer.byte_len)
    {
        return Err(TransportError::AccessDenied);
    }
    buffer.byte_len = usize::try_from(written).map_err(|_| TransportError::ResourceLimit)?;
    Ok(buffer)
}

fn scalar_from_token<T: Copy>(buffer: &AlignedBuffer) -> Result<T, TransportError> {
    if buffer.byte_len < size_of::<T>() {
        return Err(TransportError::AccessDenied);
    }
    // SAFETY: `AlignedBuffer` is aligned to `usize`, all token scalar types
    // used here have no greater alignment, and the size check is above.
    Ok(unsafe { buffer.cast_ptr::<T>().read() })
}

fn token_user_sid(buffer: &AlignedBuffer) -> Result<String, TransportError> {
    if buffer.byte_len < size_of::<TOKEN_USER>() {
        return Err(TransportError::AccessDenied);
    }
    // SAFETY: the aligned token buffer is large enough for `TOKEN_USER`.
    let user = unsafe { &*buffer.cast_ptr::<TOKEN_USER>() };
    sid_to_string(user.User.Sid)
}

fn token_logon_sid(buffer: &AlignedBuffer) -> Result<String, TransportError> {
    if buffer.byte_len < offset_of!(TOKEN_GROUPS, Groups) {
        return Err(TransportError::AccessDenied);
    }
    // SAFETY: the prefix through `GroupCount` is present and aligned.
    let groups = unsafe { &*buffer.cast_ptr::<TOKEN_GROUPS>() };
    let group_count =
        usize::try_from(groups.GroupCount).map_err(|_| TransportError::ResourceLimit)?;
    let groups_bytes = group_count
        .checked_mul(size_of::<windows_sys::Win32::Security::SID_AND_ATTRIBUTES>())
        .and_then(|bytes| bytes.checked_add(offset_of!(TOKEN_GROUPS, Groups)))
        .ok_or(TransportError::ResourceLimit)?;
    if groups_bytes > buffer.byte_len {
        return Err(TransportError::AccessDenied);
    }
    // SAFETY: the byte-length calculation above proves the flexible array is
    // fully contained in `buffer`.
    let entries = unsafe { slice::from_raw_parts(groups.Groups.as_ptr(), group_count) };
    let logon_mask = u32::from_ne_bytes(SE_GROUP_LOGON_ID.to_ne_bytes());
    entries
        .iter()
        .find(|group| group.Attributes & logon_mask == logon_mask)
        .ok_or(TransportError::AccessDenied)
        .and_then(|group| sid_to_string(group.Sid))
}

fn token_integrity_rid(buffer: &AlignedBuffer) -> Result<u32, TransportError> {
    if buffer.byte_len < size_of::<TOKEN_MANDATORY_LABEL>() {
        return Err(TransportError::AccessDenied);
    }
    // SAFETY: the aligned token buffer is large enough for this structure.
    let label = unsafe { &*buffer.cast_ptr::<TOKEN_MANDATORY_LABEL>() };
    // SAFETY: Windows supplied the SID pointer in a successfully returned
    // `TokenIntegrityLevel` buffer.
    if label.Label.Sid.is_null() || unsafe { IsValidSid(label.Label.Sid) } == 0 {
        return Err(TransportError::AccessDenied);
    }
    // SAFETY: `IsValidSid` succeeded, so the count pointer is valid.
    let count = unsafe { GetSidSubAuthorityCount(label.Label.Sid) };
    if count.is_null() {
        return Err(TransportError::AccessDenied);
    }
    // SAFETY: the count pointer belongs to the validated SID.
    let sub_authority_count = unsafe { *count };
    if sub_authority_count == 0 {
        return Err(TransportError::AccessDenied);
    }
    let index = u32::from(sub_authority_count - 1);
    // SAFETY: the index is within the validated SID's sub-authority count.
    let rid = unsafe { GetSidSubAuthority(label.Label.Sid, index) };
    if rid.is_null() {
        return Err(TransportError::AccessDenied);
    }
    // SAFETY: `GetSidSubAuthority` returned a pointer into the validated SID.
    Ok(unsafe { *rid })
}

pub(crate) fn sid_to_string(sid: PSID) -> Result<String, TransportError> {
    if sid.is_null() {
        return Err(TransportError::AccessDenied);
    }
    let mut raw: PWSTR = ptr::null_mut();
    // SAFETY: `sid` came from a successfully queried token and `raw` points to
    // writable pointer storage.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut raw) } == 0 || raw.is_null() {
        return Err(TransportError::AccessDenied);
    }
    let _allocation = LocalAllocation(raw.cast());
    wide_pointer_to_string(raw)
}

fn wide_pointer_to_string(raw: PWSTR) -> Result<String, TransportError> {
    let mut length = 0_usize;
    // SAFETY: callers provide a documented null-terminated Windows string.
    unsafe {
        while *raw.add(length) != 0 {
            length = length.checked_add(1).ok_or(TransportError::ResourceLimit)?;
            if length > MAX_IMAGE_CHARACTERS {
                return Err(TransportError::ResourceLimit);
            }
        }
        String::from_utf16(slice::from_raw_parts(raw, length))
            .map_err(|_| TransportError::AccessDenied)
    }
}

fn process_creation_time(process: HANDLE) -> Result<u64, TransportError> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all output pointers refer to initialized writable structures and
    // `process` is a retained query handle.
    if unsafe {
        GetProcessTimes(
            process,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    } == 0
    {
        return Err(TransportError::AccessDenied);
    }
    let value = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    if value == 0 {
        return Err(TransportError::AccessDenied);
    }
    Ok(value)
}

fn process_image(process: HANDLE) -> Result<PathBuf, TransportError> {
    let mut buffer = vec![0_u16; MAX_IMAGE_CHARACTERS];
    let mut characters = u32::try_from(buffer.len()).map_err(|_| TransportError::ResourceLimit)?;
    // SAFETY: `buffer` has `characters` writable UTF-16 elements and `process`
    // is a retained query handle.
    if unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &raw mut characters) }
        == 0
    {
        return Err(TransportError::AccessDenied);
    }
    let length = usize::try_from(characters).map_err(|_| TransportError::ResourceLimit)?;
    if length == 0 || length > buffer.len() {
        return Err(TransportError::AccessDenied);
    }
    Ok(PathBuf::from(
        String::from_utf16(&buffer[..length]).map_err(|_| TransportError::AccessDenied)?,
    ))
}

type AppModelQuery = unsafe extern "system" fn(HANDLE, *mut u32, PWSTR) -> u32;

fn appmodel_string(
    identity: HANDLE,
    query: AppModelQuery,
) -> Result<Option<String>, TransportError> {
    let mut characters = 0_u32;
    // SAFETY: `identity` is the retained token used for the other token-bound
    // observations; a null output with zero count is the documented size query.
    let status = unsafe { query(identity, &raw mut characters, ptr::null_mut()) };
    if status == APPMODEL_ERROR_NO_PACKAGE || status == APPMODEL_ERROR_NO_APPLICATION {
        return Ok(None);
    }
    if status != ERROR_INSUFFICIENT_BUFFER || characters == 0 {
        return Err(TransportError::AccessDenied);
    }
    let capacity = usize::try_from(characters).map_err(|_| TransportError::ResourceLimit)?;
    if capacity > MAX_IMAGE_CHARACTERS {
        return Err(TransportError::ResourceLimit);
    }
    let mut buffer = vec![0_u16; capacity];
    // SAFETY: `buffer` contains `characters` writable UTF-16 elements.
    let status = unsafe { query(identity, &raw mut characters, buffer.as_mut_ptr()) };
    if status != ERROR_SUCCESS {
        return Err(TransportError::AccessDenied);
    }
    let length = buffer
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(buffer.len());
    let value = String::from_utf16(&buffer[..length]).map_err(|_| TransportError::AccessDenied)?;
    if value.is_empty() {
        return Err(TransportError::AccessDenied);
    }
    Ok(Some(value))
}

struct PipeSecurity {
    descriptor: LocalAllocation,
    attributes: SECURITY_ATTRIBUTES,
}

impl PipeSecurity {
    fn for_current_logon(logon_sid: &str) -> Result<Self, TransportError> {
        let sddl = format!("D:P(A;;GA;;;SY)(A;;GA;;;{logon_sid})");
        let wide = wide_string(&sddl)?;
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `wide` is null terminated and `descriptor` points to writable
        // output storage. The returned allocation is owned by `LocalFree`.
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
            return Err(TransportError::Internal);
        }
        let allocation = LocalAllocation(descriptor);
        validate_pipe_dacl(descriptor, logon_sid)?;
        Ok(Self {
            attributes: SECURITY_ATTRIBUTES {
                nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                    .map_err(|_| TransportError::Internal)?,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            },
            descriptor: allocation,
        })
    }

    fn attributes(&self) -> *const SECURITY_ATTRIBUTES {
        &raw const self.attributes
    }
}

fn validate_pipe_dacl(
    descriptor: PSECURITY_DESCRIPTOR,
    logon_sid: &str,
) -> Result<(), TransportError> {
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = ptr::null_mut();
    // SAFETY: the descriptor was returned by the SDDL conversion API and all
    // outputs point to writable storage.
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
    {
        return Err(TransportError::Internal);
    }
    let mut size = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` belongs to the validated descriptor and `size` is a
    // correctly sized writable output structure.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut size).cast(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>())
                .map_err(|_| TransportError::Internal)?,
            AclSizeInformation,
        )
    } == 0
        || size.AceCount != 2
    {
        return Err(TransportError::Internal);
    }
    let system = string_to_sid(SYSTEM_SID)?;
    let logon = string_to_sid(logon_sid)?;
    let mut saw_system = false;
    let mut saw_logon = false;
    for index in 0..size.AceCount {
        let mut raw_ace = ptr::null_mut();
        // SAFETY: `index` is below the ACL's reported ACE count and output
        // storage is writable.
        if unsafe { GetAce(dacl, index, &raw mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(TransportError::Internal);
        }
        // SAFETY: `GetAce` succeeded and every expected ACE is at least the
        // fixed `ACCESS_ALLOWED_ACE` prefix.
        let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        if u32::from(ace.Header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || ace.Mask != GENERIC_ALL
            || usize::from(ace.Header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(TransportError::Internal);
        }
        let sid: PSID = (&raw const ace.SidStart).cast_mut().cast();
        // SAFETY: the SID begins at the documented `SidStart` field of a
        // validated access-allowed ACE.
        if unsafe { EqualSid(sid, system.0.cast()) } != 0 {
            saw_system = true;
        } else if unsafe { EqualSid(sid, logon.0.cast()) } != 0 {
            saw_logon = true;
        } else {
            return Err(TransportError::Internal);
        }
    }
    if !saw_system || !saw_logon {
        return Err(TransportError::Internal);
    }
    Ok(())
}

fn string_to_sid(value: &str) -> Result<LocalAllocation, TransportError> {
    let wide = wide_string(value)?;
    let mut sid: PSID = ptr::null_mut();
    // SAFETY: `wide` is null terminated and `sid` points to writable output
    // storage. The result is documented for `LocalFree`.
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &raw mut sid) } == 0 || sid.is_null() {
        return Err(TransportError::Internal);
    }
    Ok(LocalAllocation(sid))
}

fn wide_string(value: &str) -> Result<Vec<u16>, TransportError> {
    if value.encode_utf16().any(|character| character == 0) {
        return Err(TransportError::Internal);
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}

/// Complete eight-instance server pool. The name must not be published until
/// construction succeeds.
pub struct ListenerPool {
    pipe_name: String,
    listeners: Vec<OwnedHandle>,
    _instance_guard: OwnedHandle,
}

impl ListenerPool {
    /// Creates all listener instances under a protected logon-session DACL.
    ///
    /// # Errors
    ///
    /// Any partial creation closes all handles and returns `ListenerLost`.
    pub fn create() -> Result<Self, TransportError> {
        let current = current_process_observation()?;
        let security = PipeSecurity::for_current_logon(&current.observation.logon_sid)?;
        let instance_guard = create_agent_instance_guard(&security)?;
        let pipe_name = random_pipe_name()?;
        let wide_name = wide_string(&pipe_name)?;
        let mut listeners = Vec::with_capacity(MAX_CONNECTIONS);
        for index in 0..MAX_CONNECTIONS {
            let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
            if index == 0 {
                open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
            }
            // SAFETY: name and security descriptor remain alive for the call;
            // all sizes and mode flags satisfy the named-pipe contract.
            let raw = unsafe {
                CreateNamedPipeW(
                    wide_name.as_ptr(),
                    open_mode,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    u32::try_from(MAX_CONNECTIONS).map_err(|_| TransportError::Internal)?,
                    PIPE_BUFFER_BYTES,
                    PIPE_BUFFER_BYTES,
                    0,
                    security.attributes(),
                )
            };
            match OwnedHandle::new(raw) {
                Ok(listener) => listeners.push(listener),
                Err(_) => return Err(TransportError::ListenerLost),
            }
        }
        // Keep the security allocation live until every CreateNamedPipeW call
        // above has returned.
        let _ = security.descriptor.0;
        Ok(Self {
            pipe_name,
            listeners,
            _instance_guard: instance_guard,
        })
    }

    #[must_use]
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    #[must_use]
    pub fn available_listeners(&self) -> usize {
        self.listeners.len()
    }

    /// Accepts one client and authenticates its kernel-observed process before
    /// deriving exactly one role and returning a connection capable of reading
    /// application frames.
    ///
    /// # Errors
    ///
    /// Identity failures, zero/multiple matching client policies, and invalid
    /// policy sets close the pipe without a protocol response. A consumed
    /// listener that cannot be accepted requires endpoint rotation.
    pub fn accept(
        &mut self,
        policies: &[PeerPolicy],
        timeout: Duration,
    ) -> Result<PipeConnection, TransportError> {
        if self.listeners.is_empty() {
            return Err(TransportError::ResourceLimit);
        }
        let selected = match accept_listener_pool(&self.listeners, timeout) {
            Ok(selected) => selected,
            Err(TransportError::Timeout) => return Err(TransportError::Timeout),
            Err(_) => {
                self.listeners.clear();
                return Err(TransportError::ListenerLost);
            }
        };
        if selected >= self.listeners.len() {
            self.listeners.clear();
            return Err(TransportError::ListenerLost);
        }
        let pipe = self.listeners.swap_remove(selected);
        let peer = match observe_pipe_peer(pipe.raw(), PeerSide::Client) {
            Ok(peer) => peer,
            Err(error) => {
                self.recycle_rejected(pipe)?;
                return Err(error);
            }
        };
        let role = match authorize_client_role(peer.observation(), policies).map_err(map_peer_error)
        {
            Ok(role) => role,
            Err(error) => {
                drop(peer);
                self.recycle_rejected(pipe)?;
                return Err(error);
            }
        };
        if !peer.is_alive() {
            drop(peer);
            self.recycle_rejected(pipe)?;
            return Err(TransportError::PeerExited);
        }
        Ok(PipeConnection {
            pipe,
            peer,
            server_side: true,
            component_role: role.into(),
        })
    }

    /// Reuses an authenticated server instance after disconnecting it. Any
    /// failure closes the complete pool so callers must rotate discovery.
    ///
    /// # Errors
    ///
    /// Returns `ListenerLost` when the instance cannot be safely reused.
    pub fn recycle(&mut self, connection: PipeConnection) -> Result<(), TransportError> {
        if !connection.server_side || self.listeners.len() >= MAX_CONNECTIONS {
            return Err(TransportError::ListenerLost);
        }
        let PipeConnection {
            pipe,
            peer,
            server_side: _,
            component_role: _,
        } = connection;
        drop(peer);
        // SAFETY: `pipe` is a valid server-side named-pipe instance with no
        // pending operation when a public connection method returns.
        if unsafe { DisconnectNamedPipe(pipe.raw()) } == 0 {
            self.listeners.clear();
            return Err(TransportError::ListenerLost);
        }
        self.listeners.push(pipe);
        Ok(())
    }

    fn recycle_rejected(&mut self, pipe: OwnedHandle) -> Result<(), TransportError> {
        // SAFETY: authentication runs only after a successful server-side
        // connection and before application I/O can be issued.
        if unsafe { DisconnectNamedPipe(pipe.raw()) } == 0 {
            self.listeners.clear();
            return Err(TransportError::ListenerLost);
        }
        self.listeners.push(pipe);
        Ok(())
    }
}

fn create_agent_instance_guard(security: &PipeSecurity) -> Result<OwnedHandle, TransportError> {
    let name = wide_string(AGENT_INSTANCE_NAME)?;
    // SAFETY: the name is null terminated and the protected security
    // descriptor remains live for the call.
    let raw = unsafe { CreateMutexW(security.attributes(), 0, name.as_ptr()) };
    // SAFETY: the last-error value is captured immediately after creation.
    let already_exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    let guard = OwnedHandle::new(raw).map_err(|_| TransportError::ListenerLost)?;
    if already_exists {
        return Err(TransportError::ListenerLost);
    }
    Ok(guard)
}

fn random_pipe_name() -> Result<String, TransportError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| TransportError::Internal)?;
    if random == [0; 16] {
        return Err(TransportError::Internal);
    }
    let mut suffix = String::with_capacity(32);
    for byte in random {
        suffix.push(char::from(HEX[usize::from(byte >> 4)]));
        suffix.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(format!("{PIPE_NAME_PREFIX}{suffix}"))
}

fn valid_local_pipe_name(pipe_name: &str) -> bool {
    pipe_name
        .strip_prefix(PIPE_NAME_PREFIX)
        .is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && suffix.bytes().any(|byte| byte != b'0')
        })
}

#[derive(Clone, Copy)]
enum PeerSide {
    Client,
    Server,
}

fn observe_pipe_client_token(pipe: HANDLE) -> Result<TokenObservation, TransportError> {
    let impersonation = ImpersonationGuard::begin(pipe)?;
    let mut raw_token = ptr::null_mut();
    // SAFETY: this thread is impersonating the connected client at
    // SecurityIdentification. `OpenAsSelf` permits a query-only handle to that
    // identification token and the output points to writable storage.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut raw_token) } == 0 {
        return Err(TransportError::AccessDenied);
    }
    let token = OwnedHandle::new(raw_token).map_err(|_| TransportError::AccessDenied)?;
    impersonation.revert()?;
    observe_token(token.raw())
}

fn token_matches_peer(token: &TokenObservation, peer: &PeerObservation) -> bool {
    token == &TokenObservation::from_peer(peer)
}

fn observe_pipe_peer(pipe: HANDLE, side: PeerSide) -> Result<PeerHandle, TransportError> {
    let bound_client_token = match side {
        PeerSide::Client => Some(observe_pipe_client_token(pipe)?),
        PeerSide::Server => None,
    };
    let mut process_id = 0_u32;
    // SAFETY: `pipe` is a connected named-pipe handle and the process ID
    // output points to writable storage.
    let success = unsafe {
        match side {
            PeerSide::Client => GetNamedPipeClientProcessId(pipe, &raw mut process_id),
            PeerSide::Server => GetNamedPipeServerProcessId(pipe, &raw mut process_id),
        }
    };
    if success == 0 || process_id == 0 {
        return Err(TransportError::AccessDenied);
    }
    let peer = observe_process(process_id)?;
    if bound_client_token
        .as_ref()
        .is_some_and(|token| !token_matches_peer(token, peer.observation()))
    {
        return Err(TransportError::AccessDenied);
    }
    Ok(peer)
}

/// Returns the client observation retained by a server-side connection.
#[must_use]
pub fn observe_pipe_client(connection: &PipeConnection) -> &PeerHandle {
    &connection.peer
}

/// Returns the server observation retained by a client-side connection.
#[must_use]
pub fn observe_pipe_server(connection: &PipeConnection) -> &PeerHandle {
    &connection.peer
}

/// One mutually authenticated named-pipe connection.
pub struct PipeConnection {
    pipe: OwnedHandle,
    peer: PeerHandle,
    server_side: bool,
    component_role: ComponentRole,
}

impl PipeConnection {
    /// Connects with identification-only security `QoS` and authenticates the
    /// server before any application frame can be sent.
    ///
    /// # Errors
    ///
    /// Rejects stale discovery PID/creation-time data and every policy mismatch.
    pub fn connect(
        pipe_name: &str,
        expected_process_id: u32,
        expected_creation_time: u64,
        policy: &PeerPolicy,
        timeout: Duration,
    ) -> Result<Self, TransportError> {
        if policy.role != ComponentRole::Agent {
            return Err(TransportError::Internal);
        }
        if !valid_local_pipe_name(pipe_name) {
            return Err(TransportError::AccessDenied);
        }
        let wide_name = wide_string(pipe_name)?;
        let timeout_ms = duration_millis(timeout);
        let mut raw = INVALID_HANDLE_VALUE;
        for attempt in 0..2 {
            // SAFETY: the name is null terminated. Security QoS prevents the
            // server from impersonating the client.
            raw = unsafe {
                CreateFileW(
                    wide_name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED
                        | SECURITY_SQOS_PRESENT
                        | SECURITY_IDENTIFICATION
                        | SECURITY_EFFECTIVE_ONLY,
                    ptr::null_mut(),
                )
            };
            if raw != INVALID_HANDLE_VALUE {
                break;
            }
            // SAFETY: `GetLastError` is read immediately after `CreateFileW`.
            if attempt != 0 || unsafe { GetLastError() } != ERROR_PIPE_BUSY {
                return Err(TransportError::Unavailable);
            }
            // SAFETY: the name is null terminated and timeout is bounded.
            if unsafe { WaitNamedPipeW(wide_name.as_ptr(), timeout_ms) } == 0 {
                return Err(TransportError::Unavailable);
            }
        }
        let pipe = OwnedHandle::new(raw).map_err(|_| TransportError::Unavailable)?;
        let peer = observe_pipe_peer(pipe.raw(), PeerSide::Server)?;
        if peer.observation.process_id != expected_process_id
            || peer.observation.process_creation_time != expected_creation_time
        {
            return Err(TransportError::AccessDenied);
        }
        let component_role = authorize_peer(peer.observation(), policy).map_err(map_peer_error)?;
        if !peer.is_alive() {
            return Err(TransportError::PeerExited);
        }
        Ok(Self {
            pipe,
            peer,
            server_side: false,
            component_role,
        })
    }

    #[must_use]
    pub const fn peer(&self) -> &PeerHandle {
        &self.peer
    }

    #[must_use]
    pub const fn component_role(&self) -> ComponentRole {
        self.component_role
    }

    /// Verifies that the retained, authenticated peer process is still alive.
    ///
    /// Callers must use this immediately before admitting a decoded request to
    /// the runtime. The transport also performs the check after every complete
    /// frame read and around every frame write.
    ///
    /// # Errors
    ///
    /// Returns `PeerExited` after the authenticated process has terminated.
    pub fn ensure_peer_alive(&self) -> Result<(), TransportError> {
        require_peer_alive(&self.peer)
    }

    /// Reads exactly one bounded frame. Header validation happens before the
    /// zeroizing payload allocation.
    ///
    /// # Errors
    ///
    /// Partial, malformed, oversized, timed-out, or peer-exit reads fail and
    /// must close the connection.
    pub fn read_frame(&self, timeout: Duration) -> Result<Frame, TransportError> {
        let deadline = deadline_after(timeout)?;
        let mut header_bytes = [0_u8; HEADER_BYTES];
        read_exact(
            self.pipe.raw(),
            self.peer.process.raw(),
            &mut header_bytes,
            deadline,
        )?;
        let header = FrameHeader::decode(&header_bytes)?;
        let payload_length =
            usize::try_from(header.payload_length()).map_err(|_| TransportError::MalformedFrame)?;
        let mut payload = Zeroizing::new(vec![0_u8; payload_length]);
        read_exact(
            self.pipe.raw(),
            self.peer.process.raw(),
            &mut payload,
            deadline,
        )?;
        let frame = Frame::new(header, payload)?;
        retain_frame_from_live_peer(frame, &self.peer)
    }

    /// Writes one complete frame from zeroizing storage.
    ///
    /// # Errors
    ///
    /// Partial, timed-out, or peer-exit writes fail and close the connection.
    pub fn write_frame(&self, frame: &Frame, timeout: Duration) -> Result<(), TransportError> {
        self.ensure_peer_alive()?;
        let bytes = frame.encode()?;
        write_all(
            self.pipe.raw(),
            self.peer.process.raw(),
            &bytes,
            deadline_after(timeout)?,
        )?;
        self.ensure_peer_alive()
    }
}

impl fmt::Debug for PipeConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PipeConnection(REDACTED)")
    }
}

struct PendingAccept {
    event: OwnedHandle,
    overlapped: Box<OVERLAPPED>,
    pending: bool,
}

fn accept_listener_pool(
    listeners: &[OwnedHandle],
    timeout: Duration,
) -> Result<usize, TransportError> {
    let mut accepts = Vec::with_capacity(listeners.len());
    let mut selected = None;
    for (index, listener) in listeners.iter().enumerate() {
        let event = create_event()?;
        let mut overlapped = Box::new(OVERLAPPED {
            hEvent: event.raw(),
            ..OVERLAPPED::default()
        });
        // SAFETY: each listener was created for overlapped named-pipe I/O. The
        // boxed `OVERLAPPED` and event remain stable until every operation is
        // completed or cancelled and drained below.
        let connected = unsafe { ConnectNamedPipe(listener.raw(), &raw mut *overlapped) };
        let mut pending = false;
        if connected == 0 {
            // SAFETY: read immediately after `ConnectNamedPipe`.
            match unsafe { GetLastError() } {
                ERROR_PIPE_CONNECTED => selected = Some(index),
                ERROR_IO_PENDING => pending = true,
                _ => {
                    cancel_accepts(listeners, &mut accepts, None);
                    return Err(TransportError::ListenerLost);
                }
            }
        } else {
            selected = Some(index);
        }
        accepts.push(PendingAccept {
            event,
            overlapped,
            pending,
        });
        if selected.is_some() {
            break;
        }
    }

    if selected.is_none() {
        let events: Vec<_> = accepts.iter().map(|accept| accept.event.raw()).collect();
        // SAFETY: every event in the bounded array is a live waitable handle.
        let wait = unsafe {
            WaitForMultipleObjects(
                u32::try_from(events.len()).map_err(|_| TransportError::ResourceLimit)?,
                events.as_ptr(),
                0,
                duration_millis(timeout),
            )
        };
        if wait == WAIT_TIMEOUT {
            cancel_accepts(listeners, &mut accepts, None);
            return Err(TransportError::Timeout);
        }
        let Some(offset) = wait
            .checked_sub(WAIT_OBJECT_0)
            .and_then(|value| usize::try_from(value).ok())
            .filter(|index| *index < accepts.len())
        else {
            cancel_accepts(listeners, &mut accepts, None);
            return Err(TransportError::ListenerLost);
        };
        let mut transferred = 0_u32;
        // SAFETY: this event was signaled for the corresponding outstanding
        // accept and all overlapped storage remains alive.
        if unsafe {
            GetOverlappedResult(
                listeners[offset].raw(),
                &raw const *accepts[offset].overlapped,
                &raw mut transferred,
                0,
            )
        } == 0
            || transferred != 0
        {
            cancel_accepts(listeners, &mut accepts, None);
            return Err(TransportError::ListenerLost);
        }
        accepts[offset].pending = false;
        selected = Some(offset);
    }

    let selected = selected.ok_or(TransportError::ListenerLost)?;
    cancel_accepts(listeners, &mut accepts, Some(selected));
    Ok(selected)
}

fn cancel_accepts(
    listeners: &[OwnedHandle],
    accepts: &mut [PendingAccept],
    selected: Option<usize>,
) {
    for (index, accept) in accepts.iter_mut().enumerate() {
        if accept.pending && selected != Some(index) {
            cancel_and_drain(listeners[index].raw(), &mut accept.overlapped);
            // A second client may have won the race before cancellation. Force
            // that unselected instance back to a disconnected reusable state.
            // SAFETY: the pending operation has been drained.
            unsafe {
                let _ = DisconnectNamedPipe(listeners[index].raw());
            }
            accept.pending = false;
        }
    }
}

fn create_event() -> Result<OwnedHandle, TransportError> {
    // SAFETY: null security/name pointers and boolean values satisfy the API.
    OwnedHandle::new(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })
        .map_err(|_| TransportError::Internal)
}

fn deadline_after(timeout: Duration) -> Result<Instant, TransportError> {
    Instant::now()
        .checked_add(timeout)
        .ok_or(TransportError::Timeout)
}

fn remaining_millis(deadline: Instant) -> Result<u32, TransportError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(TransportError::Timeout)?;
    let millis = remaining.as_millis().max(1);
    u32::try_from(millis).map_err(|_| TransportError::ResourceLimit)
}

fn duration_millis(duration: Duration) -> u32 {
    u32::try_from(duration.as_millis()).unwrap_or(u32::MAX)
}

fn read_exact(
    pipe: HANDLE,
    peer: HANDLE,
    mut target: &mut [u8],
    deadline: Instant,
) -> Result<(), TransportError> {
    while !target.is_empty() {
        let transferred = read_once(pipe, peer, target, deadline)?;
        if transferred == 0 || transferred > target.len() {
            return Err(TransportError::MalformedFrame);
        }
        target = &mut target[transferred..];
    }
    Ok(())
}

fn write_all(
    pipe: HANDLE,
    peer: HANDLE,
    mut source: &[u8],
    deadline: Instant,
) -> Result<(), TransportError> {
    while !source.is_empty() {
        let transferred = write_once(pipe, peer, source, deadline)?;
        if transferred == 0 || transferred > source.len() {
            return Err(TransportError::PeerExited);
        }
        source = &source[transferred..];
    }
    Ok(())
}

fn read_once(
    pipe: HANDLE,
    peer: HANDLE,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<usize, TransportError> {
    let event = create_event()?;
    let mut overlapped = OVERLAPPED {
        hEvent: event.raw(),
        ..OVERLAPPED::default()
    };
    let length = u32::try_from(buffer.len()).map_err(|_| TransportError::ResourceLimit)?;
    let mut transferred = 0_u32;
    // SAFETY: the pipe is overlapped, `overlapped` remains alive until the
    // operation is drained, and `buffer` is writable for `length` bytes.
    let success = unsafe {
        ReadFile(
            pipe,
            buffer.as_mut_ptr(),
            length,
            &raw mut transferred,
            &raw mut overlapped,
        )
    };
    if success == 0 {
        // SAFETY: read immediately after failed I/O call.
        if unsafe { GetLastError() } != ERROR_IO_PENDING {
            return Err(TransportError::PeerExited);
        }
        transferred = wait_for_io(pipe, &mut overlapped, peer, deadline)?;
    }
    usize::try_from(transferred).map_err(|_| TransportError::ResourceLimit)
}

fn write_once(
    pipe: HANDLE,
    peer: HANDLE,
    buffer: &[u8],
    deadline: Instant,
) -> Result<usize, TransportError> {
    let event = create_event()?;
    let mut overlapped = OVERLAPPED {
        hEvent: event.raw(),
        ..OVERLAPPED::default()
    };
    let length = u32::try_from(buffer.len()).map_err(|_| TransportError::ResourceLimit)?;
    let mut transferred = 0_u32;
    // SAFETY: the pipe is overlapped, `overlapped` remains alive until the
    // operation is drained, and `buffer` is readable for `length` bytes.
    let success = unsafe {
        WriteFile(
            pipe,
            buffer.as_ptr(),
            length,
            &raw mut transferred,
            &raw mut overlapped,
        )
    };
    if success == 0 {
        // SAFETY: read immediately after failed I/O call.
        if unsafe { GetLastError() } != ERROR_IO_PENDING {
            return Err(TransportError::PeerExited);
        }
        transferred = wait_for_io(pipe, &mut overlapped, peer, deadline)?;
    }
    usize::try_from(transferred).map_err(|_| TransportError::ResourceLimit)
}

fn wait_for_io(
    pipe: HANDLE,
    overlapped: &mut OVERLAPPED,
    peer: HANDLE,
    deadline: Instant,
) -> Result<u32, TransportError> {
    let handles = [overlapped.hEvent, peer];
    let count = if peer.is_null() { 1 } else { 2 };
    let wait_timeout = match remaining_millis(deadline) {
        Ok(timeout) => timeout,
        Err(error) => {
            cancel_and_drain(pipe, overlapped);
            return Err(error);
        }
    };
    // SAFETY: `handles` contains `count` valid waitable handles.
    let wait = unsafe { WaitForMultipleObjects(count, handles.as_ptr(), 0, wait_timeout) };
    if wait == WAIT_OBJECT_0 {
        let mut transferred = 0_u32;
        // SAFETY: the overlapped operation completed and all arguments remain
        // alive until `GetOverlappedResult` returns.
        if unsafe { GetOverlappedResult(pipe, overlapped, &raw mut transferred, 0) } == 0 {
            return Err(TransportError::Internal);
        }
        return Ok(transferred);
    }
    let reason = if count == 2 && wait == WAIT_OBJECT_0 + 1 {
        TransportError::PeerExited
    } else if wait == WAIT_TIMEOUT {
        TransportError::Timeout
    } else {
        TransportError::Internal
    };
    cancel_and_drain(pipe, overlapped);
    Err(reason)
}

fn cancel_and_drain(pipe: HANDLE, overlapped: &mut OVERLAPPED) {
    // SAFETY: `overlapped` belongs to an operation issued by this thread on
    // `pipe`; cancellation is followed by a completion drain.
    unsafe {
        let _ = CancelIoEx(pipe, overlapped);
    }
    let mut ignored = 0_u32;
    // SAFETY: the drain is mandatory even when cancellation reports an error:
    // it ensures kernel access to `overlapped` and its buffer has ended before
    // their storage is released.
    let _completed = unsafe { GetOverlappedResult(pipe, overlapped, &raw mut ignored, 1) };
}

fn require_peer_alive(peer: &PeerHandle) -> Result<(), TransportError> {
    if peer.is_alive() {
        Ok(())
    } else {
        Err(TransportError::PeerExited)
    }
}

fn retain_frame_from_live_peer(frame: Frame, peer: &PeerHandle) -> Result<Frame, TransportError> {
    require_peer_alive(peer)?;
    Ok(frame)
}

fn map_peer_error(error: PeerAuthorizationError) -> TransportError {
    match error {
        PeerAuthorizationError::InvalidPolicySet => TransportError::Internal,
        PeerAuthorizationError::NoMatchingPolicy | PeerAuthorizationError::AmbiguousRole => {
            TransportError::AccessDenied
        }
        PeerAuthorizationError::ProcessExited => TransportError::PeerExited,
        PeerAuthorizationError::WrongUser
        | PeerAuthorizationError::WrongLogon
        | PeerAuthorizationError::WrongSession
        | PeerAuthorizationError::Elevated
        | PeerAuthorizationError::AppContainer
        | PeerAuthorizationError::WrongIntegrity
        | PeerAuthorizationError::MissingPackageIdentity
        | PeerAuthorizationError::WrongPackage
        | PeerAuthorizationError::WrongApplication
        | PeerAuthorizationError::WrongImage => TransportError::AccessDenied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        process::Command,
        sync::{Mutex, mpsc},
    };

    static AGENT_INSTANCE_TEST: Mutex<()> = Mutex::new(());

    #[test]
    fn random_pipe_names_are_scoped_and_distinct() {
        let first = random_pipe_name().expect("random endpoint");
        let second = random_pipe_name().expect("random endpoint");
        assert!(first.starts_with(PIPE_NAME_PREFIX));
        assert_eq!(first.len(), PIPE_NAME_PREFIX.len() + 32);
        assert_ne!(first, second);
        assert!(valid_local_pipe_name(&first));
        for invalid in [
            r"\\server\pipe\LOCAL\Librarian.Agent.v1.0123456789abcdef0123456789abcdef",
            r"\\.\pipe\Librarian.Agent.v1.0123456789abcdef0123456789abcdef",
            r"\\.\pipe\LOCAL\Librarian.Agent.v1.0123456789abcdef",
            r"\\.\pipe\LOCAL\Librarian.Agent.v1.00000000000000000000000000000000",
            r"\\.\pipe\LOCAL\Librarian.Agent.v1.0123456789abcdef0123456789abcdeG",
            r"\\.\pipe\LOCAL\Librarian.Agent.v1.0123456789abcdef0123456789ABCDE",
            r"\\.\pipe\LOCAL\Librarian.Agent.v1.0123456789abcdef0123456789abcdef\extra",
        ] {
            assert!(!valid_local_pipe_name(invalid), "{invalid}");
        }
        let policy = PeerPolicy {
            role: ComponentRole::Agent,
            session_id: 0,
            user_sid: String::new(),
            logon_sid: String::new(),
            maximum_integrity_rid: 0,
            image_path: PathBuf::new(),
            package_full_name: String::new(),
            package_family_name: String::new(),
            application_user_model_id: None,
        };
        assert!(matches!(
            PipeConnection::connect(
                r"\\remote.example\pipe\Librarian",
                1,
                1,
                &policy,
                Duration::ZERO,
            ),
            Err(TransportError::AccessDenied)
        ));
    }

    #[test]
    fn completed_frames_from_exited_peers_are_rejected() {
        let mut child = Command::new("cmd.exe")
            .args(["/D", "/C", "ping -n 30 127.0.0.1 >nul"])
            .spawn()
            .expect("long-lived child process");
        let peer = observe_process(child.id()).expect("observe child");
        assert!(peer.is_alive());
        child.kill().expect("stop child");
        child.wait().expect("reap child");

        let header = FrameHeader::new(
            librarian_agent_protocol::MessageKind::Cancel,
            librarian_agent_protocol::CURRENT_VERSION,
            0,
            [0xA5; 16],
            1,
        )
        .expect("frame header");
        let frame = Frame::new(header, Zeroizing::new(Vec::new())).expect("frame");
        assert!(matches!(
            retain_frame_from_live_peer(frame, &peer),
            Err(TransportError::PeerExited)
        ));
    }

    #[test]
    fn expired_deadlines_are_reported_before_a_wait() {
        let expired = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("representable deadline");
        assert_eq!(remaining_millis(expired), Err(TransportError::Timeout));
    }

    #[test]
    fn protected_dacl_is_constructible_for_current_logon() {
        let current = current_process_observation().expect("current identity");
        PipeSecurity::for_current_logon(&current.observation.logon_sid)
            .expect("two-entry protected DACL");
    }

    #[test]
    fn current_process_identity_fields_are_queryable() {
        // SAFETY: `GetCurrentProcessId` has no preconditions.
        let process_id = unsafe { GetCurrentProcessId() };
        // SAFETY: the current PID is valid and rights are query-only.
        let process = OwnedHandle::new(unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                0,
                process_id,
            )
        })
        .expect("open current process");
        let token = open_process_token(process.raw()).expect("open current token");
        let user = token_information(token.raw(), TokenUser).expect("query user");
        let groups = token_information(token.raw(), TokenGroups).expect("query groups");
        let integrity =
            token_information(token.raw(), TokenIntegrityLevel).expect("query integrity");
        let elevation = token_information(token.raw(), TokenElevation).expect("query elevation");
        let app_container =
            token_information(token.raw(), TokenIsAppContainer).expect("query app container");
        let session = token_information(token.raw(), TokenSessionId).expect("query session");
        token_user_sid(&user).expect("convert user SID");
        token_logon_sid(&groups).expect("convert logon SID");
        token_integrity_rid(&integrity).expect("read integrity RID");
        scalar_from_token::<TOKEN_ELEVATION>(&elevation).expect("read elevation");
        scalar_from_token::<u32>(&app_container).expect("read app container");
        scalar_from_token::<u32>(&session).expect("read session");
        process_creation_time(process.raw()).expect("read creation time");
        process_image(process.raw()).expect("read image");
        appmodel_string(token.raw(), GetPackageFullNameFromToken).expect("query package full name");
        appmodel_string(token.raw(), GetPackageFamilyNameFromToken)
            .expect("query package family name");
        appmodel_string(token.raw(), GetApplicationUserModelIdFromToken).expect("query AUMID");
    }

    #[test]
    fn pipe_bound_client_token_rejects_a_substituted_process_identity() {
        let _serial = AGENT_INSTANCE_TEST
            .lock()
            .expect("agent instance tests serialize");
        let pool = ListenerPool::create().expect("complete listener pool");
        let pipe_name = pool.pipe_name().to_owned();
        let (connected_tx, connected_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let client = std::thread::spawn(move || {
            let name = wide_string(&pipe_name).expect("pipe name");
            // SAFETY: the local name is null terminated and the identification
            // QoS exposes only the token facts required for authorization.
            let raw = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED
                        | SECURITY_SQOS_PRESENT
                        | SECURITY_IDENTIFICATION
                        | SECURITY_EFFECTIVE_ONLY,
                    ptr::null_mut(),
                )
            };
            let handle = OwnedHandle::new(raw).expect("client connects");
            connected_tx.send(()).expect("connected signal");
            release_rx.recv().expect("release signal");
            drop(handle);
        });
        connected_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("client connection");
        let selected =
            accept_listener_pool(&pool.listeners, Duration::from_secs(2)).expect("accepted client");
        let pipe = &pool.listeners[selected];
        let bound_token =
            observe_pipe_client_token(pipe.raw()).expect("pipe-bound identification token");
        let mut process_id = 0_u32;
        // SAFETY: `pipe` is a connected server-side named-pipe instance and
        // the process-ID output points to writable storage.
        assert_ne!(
            unsafe { GetNamedPipeClientProcessId(pipe.raw(), &raw mut process_id) },
            0
        );
        let peer = observe_process(process_id).expect("retained connected process");
        assert!(token_matches_peer(&bound_token, peer.observation()));

        let mut substituted = peer.observation().clone();
        substituted.package_full_name = Some(format!(
            "{}#substituted",
            substituted
                .package_full_name
                .as_deref()
                .unwrap_or("unpackaged")
        ));
        assert!(
            !token_matches_peer(&bound_token, &substituted),
            "a reopened PID cannot substitute a process whose token identity was not bound to the pipe"
        );

        release_tx.send(()).expect("release client");
        client.join().expect("client worker");
        // SAFETY: the client handle is closed and no I/O is pending.
        assert_ne!(unsafe { DisconnectNamedPipe(pipe.raw()) }, 0);
    }

    #[test]
    fn unpackaged_current_process_cannot_satisfy_production_policy() {
        let current = current_process_observation().expect("current identity");
        if current.observation.package_full_name.is_some() {
            return;
        }
        let mut observation = current.observation.clone();
        // Hosted Windows runners may execute with an elevated token. Isolate
        // the missing-package invariant so the test does not depend on which
        // earlier fail-closed identity check applies to the runner itself.
        observation.elevated = false;
        observation.app_container = false;
        observation.integrity_rid = observation.integrity_rid.min(
            u32::try_from(
                windows_sys::Win32::System::SystemServices::SECURITY_MANDATORY_MEDIUM_RID,
            )
            .expect("medium RID is positive"),
        );
        let policy = PeerPolicy {
            role: ComponentRole::Desktop,
            session_id: observation.session_id,
            user_sid: observation.user_sid.clone(),
            logon_sid: observation.logon_sid.clone(),
            maximum_integrity_rid: u32::try_from(
                windows_sys::Win32::System::SystemServices::SECURITY_MANDATORY_MEDIUM_RID,
            )
            .expect("medium RID is positive"),
            image_path: observation.image_path.clone(),
            package_full_name: "Librarian_Production".to_owned(),
            package_family_name: "Librarian_Publisher".to_owned(),
            application_user_model_id: Some("Librarian.Desktop".to_owned()),
        };
        assert_eq!(
            authorize_peer(&observation, &policy),
            Err(PeerAuthorizationError::MissingPackageIdentity)
        );
    }

    #[test]
    fn first_instance_flag_blocks_a_duplicate_server() {
        let _serial = AGENT_INSTANCE_TEST
            .lock()
            .expect("agent instance tests serialize");
        let pool = ListenerPool::create().expect("complete listener pool");
        assert!(matches!(
            ListenerPool::create(),
            Err(TransportError::ListenerLost)
        ));
        let current = current_process_observation().expect("current identity");
        let security =
            PipeSecurity::for_current_logon(&current.observation.logon_sid).expect("pipe DACL");
        let name = wide_string(pool.pipe_name()).expect("pipe name");
        // SAFETY: all pointers remain live for the call and the duplicate uses
        // the same constrained pipe modes as the real listener.
        let duplicate = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                u32::try_from(MAX_CONNECTIONS).expect("connection bound"),
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                0,
                security.attributes(),
            )
        };
        assert_eq!(duplicate, INVALID_HANDLE_VALUE);
        assert_eq!(pool.available_listeners(), MAX_CONNECTIONS);
    }

    #[test]
    fn unpackaged_hostile_client_is_rejected_before_bytes_and_listener_is_reused() {
        let _serial = AGENT_INSTANCE_TEST
            .lock()
            .expect("agent instance tests serialize");
        let mut pool = ListenerPool::create().expect("complete listener pool");
        let current = current_process_observation().expect("current identity");
        let policy = PeerPolicy {
            role: ComponentRole::Desktop,
            session_id: current.observation.session_id,
            user_sid: current.observation.user_sid.clone(),
            logon_sid: current.observation.logon_sid.clone(),
            maximum_integrity_rid: current.observation.integrity_rid,
            image_path: current.observation.image_path.clone(),
            package_full_name: "Librarian_Production".to_owned(),
            package_family_name: "Librarian_Publisher".to_owned(),
            application_user_model_id: Some("Librarian.Desktop".to_owned()),
        };
        let pipe_name = pool.pipe_name().to_owned();
        let (connected_tx, connected_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let hostile = std::thread::spawn(move || {
            let name = wide_string(&pipe_name).expect("pipe name");
            // SAFETY: the name is null terminated. This intentionally models a
            // same-user client that knows the endpoint but has no package ID.
            let raw = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    ptr::null_mut(),
                )
            };
            let handle = OwnedHandle::new(raw).expect("hostile client connects");
            connected_tx.send(()).expect("connected signal");
            release_rx.recv().expect("release signal");
            drop(handle);
        });

        connected_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("hostile client connection");
        assert!(matches!(
            pool.accept(&[policy], Duration::from_secs(2)),
            Err(TransportError::AccessDenied)
        ));
        assert_eq!(pool.available_listeners(), MAX_CONNECTIONS);
        release_tx.send(()).expect("release hostile client");
        hostile.join().expect("hostile client thread");
    }
}
