use std::{
    env,
    ffi::c_void,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
    ptr,
};

use librarian_agent_protocol::{EndpointDescriptor, MAX_ENDPOINT_DESCRIPTOR_BYTES, ProtocolError};
use windows_sys::Win32::{
    Foundation::{ERROR_SUCCESS, LocalFree},
    Security::{
        Authorization::{ConvertStringSidToSidW, GetSecurityInfo, SE_FILE_OBJECT},
        EqualSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    },
    Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW},
};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Stable, non-secret discovery failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryError {
    Unavailable,
    Oversized,
    Malformed,
    Incompatible,
    Redirected,
    Replaced,
    Internal,
}

/// Guarded package-local endpoint descriptor lifecycle.
pub struct EndpointDescriptorStore {
    path: PathBuf,
    owner_sid: String,
}

impl EndpointDescriptorStore {
    /// Binds one absolute descriptor path with an existing non-redirected
    /// parent directory.
    ///
    /// # Errors
    ///
    /// Rejects relative, root-only, missing-parent, and reparse-point paths.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, DiscoveryError> {
        let path = path.as_ref();
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(DiscoveryError::Redirected);
        }
        let _guards = acquire_ancestor_guards(path)?;
        let owner_sid = crate::platform::current_process_observation()
            .map_err(|_| DiscoveryError::Internal)?
            .observation()
            .user_sid
            .clone();
        Ok(Self {
            path: path.to_path_buf(),
            owner_sid,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Atomically publishes one canonical descriptor after listeners are
    /// ready.
    ///
    /// # Errors
    ///
    /// Fails closed for path redirection, replacement, durability, random, or
    /// publication failures.
    pub fn publish(&self, descriptor: &EndpointDescriptor) -> Result<(), DiscoveryError> {
        let guards = acquire_ancestor_guards(&self.path)?;
        let bytes = descriptor.encode();
        if bytes.len() > MAX_ENDPOINT_DESCRIPTOR_BYTES {
            return Err(DiscoveryError::Oversized);
        }
        let temporary_path = self.temporary_path()?;
        let mut temporary = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&temporary_path)
            .map_err(|_| DiscoveryError::Internal)?;
        let result = (|| {
            verify_regular(&temporary, &self.owner_sid)?;
            temporary
                .write_all(&bytes)
                .and_then(|()| temporary.sync_all())
                .map_err(|_| DiscoveryError::Internal)?;
            let expected = same_file::Handle::from_file(
                temporary
                    .try_clone()
                    .map_err(|_| DiscoveryError::Internal)?,
            )
            .map_err(|_| DiscoveryError::Internal)?;
            move_replace(&temporary_path, &self.path)?;
            // The retained staging handle has read/write access and delete
            // sharing, so this identity check must reciprocally share both.
            let published = open_regular(&self.path, true, true, &self.owner_sid)?;
            let actual = same_file::Handle::from_file(
                published
                    .try_clone()
                    .map_err(|_| DiscoveryError::Internal)?,
            )
            .map_err(|_| DiscoveryError::Internal)?;
            if expected != actual {
                return Err(DiscoveryError::Replaced);
            }
            sync_parent_directory(&self.path)?;
            revalidate_ancestor_guards(&guards)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }

    /// Loads and canonicalizes one bounded descriptor from a guarded regular
    /// file.
    ///
    /// # Errors
    ///
    /// Rejects stale replacement, redirects, truncation, oversize, malformed
    /// data, and future descriptor schemas.
    pub fn load(&self) -> Result<EndpointDescriptor, DiscoveryError> {
        self.load_with_before_revalidation(|| {})
    }

    fn load_with_before_revalidation(
        &self,
        before_revalidation: impl FnOnce(),
    ) -> Result<EndpointDescriptor, DiscoveryError> {
        let guards = acquire_ancestor_guards(&self.path)?;
        let mut file = open_regular(&self.path, false, false, &self.owner_sid)?;
        let initial =
            same_file::Handle::from_file(file.try_clone().map_err(|_| DiscoveryError::Internal)?)
                .map_err(|_| DiscoveryError::Internal)?;
        let length = guarded_length(&file)?;
        let mut bytes = vec![0_u8; length];
        file.read_exact(&mut bytes)
            .map_err(|_| DiscoveryError::Malformed)?;
        let mut trailing = [0_u8; 1];
        if file
            .read(&mut trailing)
            .map_err(|_| DiscoveryError::Internal)?
            != 0
        {
            return Err(DiscoveryError::Malformed);
        }
        before_revalidation();
        let current =
            same_file::Handle::from_file(open_regular(&self.path, false, false, &self.owner_sid)?)
                .map_err(|_| DiscoveryError::Internal)?;
        if initial != current || guarded_length(&file)? != length {
            return Err(DiscoveryError::Replaced);
        }
        revalidate_ancestor_guards(&guards)?;
        EndpointDescriptor::decode(&bytes).map_err(map_protocol_error)
    }

    /// Removes discovery before intentional shutdown.
    ///
    /// # Errors
    ///
    /// Rejects redirected/non-regular targets and removal failures.
    pub fn remove(&self) -> Result<(), DiscoveryError> {
        let guards = acquire_ancestor_guards(&self.path)?;
        let file = match open_regular(&self.path, false, true, &self.owner_sid) {
            Ok(file) => file,
            Err(DiscoveryError::Unavailable) => return Ok(()),
            Err(error) => return Err(error),
        };
        let expected = same_file::Handle::from_file(file).map_err(|_| DiscoveryError::Internal)?;
        let current =
            same_file::Handle::from_file(open_regular(&self.path, false, true, &self.owner_sid)?)
                .map_err(|_| DiscoveryError::Internal)?;
        if expected != current {
            return Err(DiscoveryError::Replaced);
        }
        fs::remove_file(&self.path).map_err(|_| DiscoveryError::Internal)?;
        sync_parent_directory(&self.path)?;
        revalidate_ancestor_guards(&guards)
    }

    fn temporary_path(&self) -> Result<PathBuf, DiscoveryError> {
        let parent = self.path.parent().ok_or(DiscoveryError::Redirected)?;
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| DiscoveryError::Internal)?;
        if random == [0; 16] {
            return Err(DiscoveryError::Internal);
        }
        let mut suffix = String::with_capacity(32);
        for byte in random {
            suffix.push(char::from(HEX[usize::from(byte >> 4)]));
            suffix.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Ok(parent.join(format!(".librarian-agent-endpoint-{suffix}.tmp")))
    }
}

struct AncestorGuards(Vec<(PathBuf, File)>);

fn acquire_ancestor_guards(path: &Path) -> Result<AncestorGuards, DiscoveryError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|_| DiscoveryError::Redirected)?
            .join(path)
    };
    let parent = absolute.parent().ok_or(DiscoveryError::Redirected)?;
    let mut ancestors: Vec<_> = parent
        .ancestors()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .collect();
    ancestors.reverse();
    let mut guards = Vec::with_capacity(ancestors.len());
    for ancestor in ancestors {
        let file = OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(ancestor)
            .map_err(|_| DiscoveryError::Redirected)?;
        let metadata = file.metadata().map_err(|_| DiscoveryError::Redirected)?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(DiscoveryError::Redirected);
        }
        guards.push((ancestor.to_path_buf(), file));
    }
    Ok(AncestorGuards(guards))
}

fn revalidate_ancestor_guards(guards: &AncestorGuards) -> Result<(), DiscoveryError> {
    for (path, expected_file) in &guards.0 {
        let current = OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| DiscoveryError::Redirected)?;
        let expected = same_file::Handle::from_file(
            expected_file
                .try_clone()
                .map_err(|_| DiscoveryError::Internal)?,
        )
        .map_err(|_| DiscoveryError::Internal)?;
        let current =
            same_file::Handle::from_file(current).map_err(|_| DiscoveryError::Internal)?;
        if expected != current {
            return Err(DiscoveryError::Replaced);
        }
    }
    Ok(())
}

fn open_regular(
    path: &Path,
    share_writes: bool,
    share_deletes: bool,
    owner_sid: &str,
) -> Result<File, DiscoveryError> {
    let mut share_mode = FILE_SHARE_READ;
    if share_writes {
        share_mode |= FILE_SHARE_WRITE;
    }
    if share_deletes {
        share_mode |= FILE_SHARE_DELETE;
    }
    let file = OpenOptions::new()
        .read(true)
        .share_mode(share_mode)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                DiscoveryError::Unavailable
            } else {
                DiscoveryError::Redirected
            }
        })?;
    verify_regular(&file, owner_sid)?;
    Ok(file)
}

fn verify_regular(file: &File, owner_sid: &str) -> Result<(), DiscoveryError> {
    let metadata = file.metadata().map_err(|_| DiscoveryError::Redirected)?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DiscoveryError::Redirected);
    }
    verify_file_owner(file, owner_sid)?;
    Ok(())
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Windows security conversion/query APIs document
            // `LocalFree` ownership for these returned allocations.
            unsafe {
                let _ = LocalFree(self.0);
            }
        }
    }
}

fn verify_file_owner(file: &File, expected_owner_sid: &str) -> Result<(), DiscoveryError> {
    let mut owner: PSID = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: the file handle is live and every requested output points to
    // writable storage. Unrequested group/DACL/SACL outputs are null.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &raw mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || owner.is_null() || descriptor.is_null() {
        return Err(DiscoveryError::Redirected);
    }
    let _descriptor = LocalAllocation(descriptor);
    let expected_wide: Vec<_> = expected_owner_sid.encode_utf16().chain(Some(0)).collect();
    let mut expected: PSID = ptr::null_mut();
    // SAFETY: the expected SID string is null terminated and output storage is
    // writable. The returned SID is owned by `LocalFree`.
    if unsafe { ConvertStringSidToSidW(expected_wide.as_ptr(), &raw mut expected) } == 0
        || expected.is_null()
    {
        return Err(DiscoveryError::Internal);
    }
    let _expected = LocalAllocation(expected);
    // SAFETY: both SIDs are live for the comparison.
    if unsafe { EqualSid(owner, expected) } == 0 {
        return Err(DiscoveryError::Redirected);
    }
    Ok(())
}

fn guarded_length(file: &File) -> Result<usize, DiscoveryError> {
    let length = file.metadata().map_err(|_| DiscoveryError::Internal)?.len();
    if length
        > u64::try_from(MAX_ENDPOINT_DESCRIPTOR_BYTES).map_err(|_| DiscoveryError::Internal)?
    {
        return Err(DiscoveryError::Oversized);
    }
    usize::try_from(length).map_err(|_| DiscoveryError::Oversized)
}

fn move_replace(source: &Path, target: &Path) -> Result<(), DiscoveryError> {
    let source: Vec<_> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let target: Vec<_> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: both paths are null-terminated UTF-16 and remain live for the
    // call. Replacement occurs within the already guarded parent directory.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(DiscoveryError::Internal);
    }
    Ok(())
}

fn sync_parent_directory(path: &Path) -> Result<(), DiscoveryError> {
    let parent = path.parent().ok_or(DiscoveryError::Redirected)?;
    OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| DiscoveryError::Internal)
}

fn map_protocol_error(error: ProtocolError) -> DiscoveryError {
    match error {
        ProtocolError::TooLarge => DiscoveryError::Oversized,
        ProtocolError::Unsupported => DiscoveryError::Incompatible,
        ProtocolError::Malformed
        | ProtocolError::NonCanonical
        | ProtocolError::InvariantViolation => DiscoveryError::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "librarian-discovery-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test directory");
            Self(path)
        }

        fn descriptor_path(&self) -> PathBuf {
            self.0.join("agent-endpoint-v1.cbor")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn descriptor() -> EndpointDescriptor {
        EndpointDescriptor::new(
            r"\\.\pipe\LOCAL\Librarian.Agent.v1.0123456789abcdef".to_owned(),
            41,
            73,
            "Librarian_1.0.0.0_x64__publisher".to_owned(),
            1,
            1,
            [0xA5; 32],
        )
        .expect("descriptor")
    }

    #[test]
    fn publish_load_replace_and_remove_are_canonical() {
        let directory = TestDirectory::new();
        let store = EndpointDescriptorStore::new(directory.descriptor_path()).expect("store");
        let expected = descriptor();
        store.publish(&expected).expect("publish");
        assert_eq!(store.load(), Ok(expected.clone()));
        store.publish(&expected).expect("atomic replacement");
        assert_eq!(store.load(), Ok(expected));
        store.remove().expect("remove");
        assert_eq!(store.load(), Err(DiscoveryError::Unavailable));
    }

    #[test]
    fn truncated_oversized_and_future_descriptors_fail_closed() {
        let directory = TestDirectory::new();
        let path = directory.descriptor_path();
        let store = EndpointDescriptorStore::new(&path).expect("store");

        fs::write(&path, [0x88, 0x01]).expect("truncated fixture");
        assert_eq!(store.load(), Err(DiscoveryError::Malformed));

        fs::write(&path, vec![0_u8; MAX_ENDPOINT_DESCRIPTOR_BYTES + 1]).expect("oversized fixture");
        assert_eq!(store.load(), Err(DiscoveryError::Oversized));

        let mut future = descriptor().encode();
        assert_eq!(future[1], 1);
        future[1] = 2;
        fs::write(&path, future).expect("future fixture");
        assert_eq!(store.load(), Err(DiscoveryError::Incompatible));
    }

    #[test]
    fn redirected_descriptors_fail_and_inflight_replacement_is_blocked() {
        let directory = TestDirectory::new();
        let path = directory.descriptor_path();
        let store = EndpointDescriptorStore::new(&path).expect("store");
        let expected = descriptor();
        store.publish(&expected).expect("publish");

        let replacement = directory.0.join("replacement.cbor");
        fs::write(&replacement, descriptor().encode()).expect("replacement");
        let result = store.load_with_before_revalidation(|| {
            assert!(
                fs::remove_file(&path).is_err(),
                "guarded read must deny deletion"
            );
            assert!(
                fs::rename(&replacement, &path).is_err(),
                "guarded read must deny replacement"
            );
        });
        assert_eq!(result, Ok(expected));
        fs::remove_file(&replacement).expect("remove unused replacement");

        let target = directory.0.join("redirect-target.cbor");
        fs::write(&target, descriptor().encode()).expect("redirect target");
        fs::remove_file(&path).expect("remove descriptor");
        std::os::windows::fs::symlink_file(&target, &path).expect("descriptor symlink");
        assert_eq!(store.load(), Err(DiscoveryError::Redirected));
    }
}
