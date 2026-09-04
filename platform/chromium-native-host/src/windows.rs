use std::{
    env,
    ffi::OsString,
    fs::File,
    io::{Read, stdin, stdout},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use librarian_agent_protocol::{
    AgentState, CURRENT_VERSION, ClientHello, ClientRole, Frame, FrameHeader, MessageKind,
    ServerHello, Version,
};
use librarian_windows_ipc::{
    ComponentRole, EndpointDescriptorStore, PeerObservation, PeerPolicy, PipeConnection,
    current_process_observation,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::protocol::{AgentStatus, BridgeFailure, serve_once};

const HOST_EXECUTABLE: &str = "Librarian.ChromiumNativeHost.exe";
const AGENT_EXECUTABLE: &str = "Librarian.VaultAgent.exe";
const IDENTITY_LAUNCHER_EXECUTABLE: &str = "Librarian.IdentityLauncher.exe";
const HOST_NAME: &str = "com.theundeadmonk.librarian";
const LOCAL_STATE_DIRECTORY: &str = "Librarian";
const ENDPOINT_FILE: &str = "agent-endpoint-v1.cbor";
const MEDIUM_INTEGRITY_RID: u32 = 0x2000;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostError {
    InvalidInvocation,
    Identity,
    Manifest,
    Discovery,
    Transport,
    Protocol,
    Input,
    Output,
}

struct AgentContext {
    endpoint: EndpointDescriptorStore,
    policy: PeerPolicy,
    package_full_name: String,
    build_id: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeHostManifest {
    name: String,
    description: String,
    path: String,
    #[serde(rename = "type")]
    transport: String,
    allowed_origins: Vec<String>,
}

pub fn run() -> Result<(), HostError> {
    let (caller_origin, _parent_window) = invocation()?;
    let current = current_process_observation().map_err(|_| HostError::Identity)?;
    let observation = current.observation();
    let (package_full_name, package_family_name, install_root) = validate_host(observation)?;
    validate_declared_origin(&install_root, &caller_origin)?;
    let endpoint_path = local_endpoint_path(package_family_name)?;
    let context = AgentContext {
        endpoint: EndpointDescriptorStore::new(endpoint_path).map_err(|_| HostError::Discovery)?,
        policy: PeerPolicy {
            role: ComponentRole::Agent,
            session_id: observation.session_id,
            user_sid: observation.user_sid.clone(),
            logon_sid: observation.logon_sid.clone(),
            maximum_integrity_rid: MEDIUM_INTEGRITY_RID,
            image_path: install_root.join(AGENT_EXECUTABLE),
            package_full_name: package_full_name.to_owned(),
            package_family_name: package_family_name.to_owned(),
            application_user_model_id: Some(format!("{package_family_name}!VaultAgent")),
        },
        package_full_name: package_full_name.to_owned(),
        build_id: sha256_file(&observation.image_path)?,
    };
    serve_once(&mut stdin().lock(), &mut stdout().lock(), |timeout| {
        context.status(timeout).map_err(map_bridge_error)
    })
    .map_err(|error| match error {
        crate::protocol::ServeError::Input => HostError::Input,
        crate::protocol::ServeError::Output => HostError::Output,
    })
}

impl AgentContext {
    fn status(&self, timeout: Duration) -> Result<AgentStatus, HostError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(HostError::Transport)?;
        let descriptor = self.endpoint.load().map_err(|_| HostError::Discovery)?;
        if descriptor.package_full_name() != self.package_full_name
            || descriptor.minimum_major() > CURRENT_VERSION.major()
            || descriptor.maximum_major() < CURRENT_VERSION.major()
        {
            return Err(HostError::Identity);
        }
        let pipe = PipeConnection::connect(
            descriptor.pipe_name(),
            descriptor.agent_process_id(),
            descriptor.agent_process_creation_time(),
            &self.policy,
            remaining(deadline)?,
        )
        .map_err(|_| HostError::Transport)?;
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| HostError::Transport)?;
        let hello = ClientHello::new(
            nonce,
            CURRENT_VERSION,
            CURRENT_VERSION,
            ClientRole::NativeHost,
            self.build_id,
            Vec::new(),
        )
        .map_err(|_| HostError::Protocol)?;
        let payload = Zeroizing::new(hello.encode());
        let header = FrameHeader::new(
            MessageKind::ClientHello,
            Version::new(0, 0),
            payload.len(),
            [0; 16],
            0,
        )
        .map_err(|_| HostError::Protocol)?;
        pipe.write_frame(
            &Frame::new(header, payload).map_err(|_| HostError::Protocol)?,
            remaining(deadline)?,
        )
        .map_err(|_| HostError::Transport)?;
        let frame = pipe
            .read_frame(remaining(deadline)?)
            .map_err(|_| HostError::Transport)?;
        if frame.header().kind() != MessageKind::ServerHello {
            return Err(HostError::Protocol);
        }
        let server = ServerHello::decode(frame.payload()).map_err(|_| HostError::Protocol)?;
        if server.selected_version() != CURRENT_VERSION
            || frame.header().version() != CURRENT_VERSION
            || server.derived_role() != ClientRole::NativeHost
            || !server.granted_features().is_empty()
            || frame.header().connection_id() == &[0; 16]
        {
            return Err(HostError::Protocol);
        }
        Ok(map_agent_state(server.agent_state()))
    }
}

fn invocation() -> Result<(String, String), HostError> {
    let arguments = env::args_os().skip(1).collect::<Vec<OsString>>();
    if arguments.len() != 2 {
        return Err(HostError::InvalidInvocation);
    }
    let origin = arguments[0]
        .to_str()
        .filter(|value| valid_extension_origin(value))
        .ok_or(HostError::InvalidInvocation)?
        .to_owned();
    let parent_window = arguments[1]
        .to_str()
        .filter(|value| valid_parent_window(value))
        .ok_or(HostError::InvalidInvocation)?
        .to_owned();
    Ok((origin, parent_window))
}

fn validate_host(observation: &PeerObservation) -> Result<(&str, &str, PathBuf), HostError> {
    let package_full_name = observation
        .package_full_name
        .as_deref()
        .ok_or(HostError::Identity)?;
    let package_family_name = observation
        .package_family_name
        .as_deref()
        .ok_or(HostError::Identity)?;
    let expected_application = format!("{package_family_name}!ChromiumNativeHost");
    let valid_image = observation
        .image_path
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case(HOST_EXECUTABLE));
    if observation.elevated
        || observation.app_container
        || observation.integrity_rid != MEDIUM_INTEGRITY_RID
        || observation.application_user_model_id.as_deref() != Some(&expected_application)
        || !valid_image
    {
        return Err(HostError::Identity);
    }
    let install_root = observation
        .image_path
        .parent()
        .ok_or(HostError::Identity)?
        .to_path_buf();
    Ok((package_full_name, package_family_name, install_root))
}

fn validate_declared_origin(install_root: &Path, caller_origin: &str) -> Result<(), HostError> {
    let origins = ["chrome", "edge"].map(|browser| {
        read_host_manifest(&install_root.join(format!("{HOST_NAME}.{browser}.json")))
    });
    let [chrome, edge] = origins;
    let chrome = chrome?;
    let edge = edge?;
    if caller_origin != chrome && caller_origin != edge {
        return Err(HostError::Manifest);
    }
    Ok(())
}

fn read_host_manifest(path: &Path) -> Result<String, HostError> {
    let metadata = path.symlink_metadata().map_err(|_| HostError::Manifest)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(HostError::Manifest);
    }
    let bytes = std::fs::read(path).map_err(|_| HostError::Manifest)?;
    let manifest: NativeHostManifest =
        serde_json::from_slice(&bytes).map_err(|_| HostError::Manifest)?;
    if manifest.name != HOST_NAME
        || manifest.description != "Librarian browser bridge"
        || manifest.path != IDENTITY_LAUNCHER_EXECUTABLE
        || manifest.transport != "stdio"
        || manifest.allowed_origins.len() != 1
        || !valid_extension_origin(&manifest.allowed_origins[0])
    {
        return Err(HostError::Manifest);
    }
    Ok(manifest.allowed_origins[0].clone())
}

fn valid_extension_origin(value: &str) -> bool {
    const PREFIX: &str = "chrome-extension://";
    value.len() == PREFIX.len() + 33
        && value.starts_with(PREFIX)
        && value.ends_with('/')
        && value[PREFIX.len()..value.len() - 1]
            .bytes()
            .all(|byte| (b'a'..=b'p').contains(&byte))
}

fn valid_parent_window(value: &str) -> bool {
    const PREFIX: &str = "--parent-window=";
    value.strip_prefix(PREFIX).is_some_and(|handle| {
        !handle.is_empty() && handle.len() <= 20 && handle.bytes().all(|b| b.is_ascii_digit())
    })
}

fn local_endpoint_path(package_family_name: &str) -> Result<PathBuf, HostError> {
    let local_app_data = env::var_os("LOCALAPPDATA").ok_or(HostError::Discovery)?;
    let local_state = PathBuf::from(local_app_data)
        .join("Packages")
        .join(package_family_name)
        .join("LocalState")
        .join(LOCAL_STATE_DIRECTORY);
    if !local_state.is_absolute()
        || !std::fs::symlink_metadata(&local_state).is_ok_and(|metadata| metadata.is_dir())
    {
        return Err(HostError::Discovery);
    }
    Ok(local_state.join(ENDPOINT_FILE))
}

fn sha256_file(path: &Path) -> Result<[u8; 32], HostError> {
    let mut file = File::open(path).map_err(|_| HostError::Identity)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| HostError::Identity)?;
        if read == 0 {
            return Ok(hasher.finalize().into());
        }
        hasher.update(&buffer[..read]);
    }
}

fn remaining(deadline: Instant) -> Result<Duration, HostError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(HostError::Transport)
}

const fn map_agent_state(state: AgentState) -> AgentStatus {
    match state {
        AgentState::Starting => AgentStatus::Starting,
        AgentState::NoVault => AgentStatus::NoVault,
        AgentState::Locked => AgentStatus::Locked,
        AgentState::Unlocking => AgentStatus::Unlocking,
        AgentState::Unlocked => AgentStatus::Unlocked,
        AgentState::Updating => AgentStatus::Updating,
        AgentState::ShuttingDown => AgentStatus::ShuttingDown,
    }
}

const fn map_bridge_error(error: HostError) -> BridgeFailure {
    match error {
        HostError::Discovery | HostError::Transport => BridgeFailure::AgentUnavailable,
        HostError::Identity | HostError::Protocol | HostError::Manifest => {
            BridgeFailure::Incompatible
        }
        HostError::InvalidInvocation | HostError::Input | HostError::Output => {
            BridgeFailure::OperationFailed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chromium_arguments_are_exactly_bounded() {
        assert!(valid_extension_origin(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"
        ));
        assert!(!valid_extension_origin(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
        ));
        assert!(!valid_extension_origin(
            "chrome-extension://abcdefghijklmnopabcdefghijklmn0p/"
        ));
        assert!(valid_parent_window("--parent-window=0"));
        assert!(valid_parent_window("--parent-window=18446744073709551615"));
        assert!(!valid_parent_window("--parent-window="));
        assert!(!valid_parent_window("--parent-window=-1"));
    }
}
