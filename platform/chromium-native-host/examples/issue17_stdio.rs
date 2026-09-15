//! TEST ONLY: real native JSON framing + real encrypted `AgentRuntime`, joined by
//! synthetic in-process connections. This is NOT the Windows authenticated IPC
//! bridge or installed-browser acceptance. No UI, existing-vault input, network,
//! registration, arbitrary credentials, or product test entry point.

#[path = "../src/protocol.rs"]
mod protocol;

use std::{
    ffi::OsString,
    fs,
    io::{self, BufRead, Write},
    path::{Component, Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant},
};

use librarian_agent_protocol::{
    AccountFields, AgentState, BrowserContext, BrowserCredential, BrowserSelection,
    CURRENT_VERSION, ClientHello, ClientRole, Connection, ConnectionLimits, FEATURE_BROWSER_FILL,
    FrameHeader, MessageKind, OperationRequest, PublicErrorCode, RequestEnvelope, ResponseEnvelope,
};
use librarian_vault_agent::{AgentRuntime, DispatchError};
use protocol::{AgentStatus, BridgeFailure};
use zeroize::Zeroizing;

const PASSWORD: &str = "Issue17-Isolated-Fixture-Only!2026";
const ACCOUNTS: &str = include_str!("../../../tests/fixtures/issue17-accounts.tsv");
const BUILD_ID: [u8; 32] = [0x72; 32];
const MAX_REQUESTS: u8 = 64;
type Result<T> = std::result::Result<T, BridgeFailure>;

fn arguments(args: &[OsString]) -> std::result::Result<(PathBuf, bool), &'static str> {
    if !(args.len() == 2 || (args.len() == 3 && args[2] == "--locked"))
        || args[0] != "--new-directory"
    {
        return Err("usage: issue17-stdio --new-directory ABSOLUTE_NEW_DIRECTORY [--locked]");
    }
    let path = PathBuf::from(&args[1]);
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err("fixture requires an absolute new directory without traversal");
    }
    #[cfg(windows)]
    {
        use std::path::Prefix;
        if !matches!(path.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)))
            || path.components().any(|part| matches!(part, Component::Normal(name) if name.to_string_lossy().contains(':')))
        {
            return Err("fixture requires a local drive path without streams or device namespaces");
        }
    }
    Ok((path, args.len() == 3))
}

fn plain_directory_chain(path: &Path) -> std::result::Result<(), &'static str> {
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| "fixture parent missing")?;
        #[cfg(windows)]
        let redirected = {
            use std::os::windows::fs::MetadataExt;
            metadata.file_attributes() & 0x400 != 0
        };
        #[cfg(not(windows))]
        let redirected = metadata.file_type().is_symlink();
        if !metadata.is_dir() || redirected {
            return Err("fixture path must contain only plain directories");
        }
    }
    Ok(())
}

fn create_directory(path: &Path) -> std::result::Result<(), &'static str> {
    arguments(&["--new-directory".into(), path.as_os_str().to_owned()])?;
    plain_directory_chain(path.parent().ok_or("fixture parent missing")?)?;
    #[cfg(unix)]
    let created = {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)
    };
    #[cfg(not(unix))]
    let created = fs::create_dir(path);
    // No overwrite, recursive creation, or cleanup, even for an empty directory.
    created.map_err(|_| "fixture directory must be new")?;
    plain_directory_chain(path)
}

fn connection(runtime: &AgentRuntime, role: ClientRole, marker: u8) -> Result<Connection> {
    let features = if role == ClientRole::NativeHost {
        vec![FEATURE_BROWSER_FILL]
    } else {
        vec![]
    };
    let hello = ClientHello::new(
        [marker; 32],
        CURRENT_VERSION,
        CURRENT_VERSION,
        role,
        BUILD_ID,
        features.clone(),
    )
    .map_err(|_| BridgeFailure::OperationFailed)?;
    let (state, epoch) = runtime
        .status_snapshot()
        .map_err(|_| BridgeFailure::AgentUnavailable)?;
    Connection::negotiate(
        role,
        17,
        BUILD_ID,
        &hello,
        &features,
        [marker + 1; 32],
        [marker + 2; 16],
        state,
        epoch,
        ConnectionLimits::default(),
    )
    .map(|value| value.0)
    .map_err(|_| BridgeFailure::Incompatible)
}

fn request(
    runtime: &AgentRuntime,
    client: &Connection,
    id: u64,
    operation: &OperationRequest,
    key: Option<[u8; 16]>,
    deadline: Instant,
) -> Result<ResponseEnvelope> {
    let budget = deadline
        .checked_duration_since(Instant::now())
        .ok_or(BridgeFailure::TimedOut)?;
    let timeout = u32::try_from(budget.as_millis()).map_err(|_| BridgeFailure::OperationFailed)?;
    if timeout == 0 {
        return Err(BridgeFailure::TimedOut);
    }
    let request = RequestEnvelope::new(
        operation.operation(),
        runtime.unlock_epoch(),
        timeout,
        key,
        operation
            .encode()
            .map_err(|_| BridgeFailure::OperationFailed)?,
    )
    .map_err(|_| BridgeFailure::OperationFailed)?;
    let encoded = request
        .encode()
        .map_err(|_| BridgeFailure::OperationFailed)?;
    let header = FrameHeader::new(
        MessageKind::Request,
        CURRENT_VERSION,
        encoded.len(),
        *client.connection_id(),
        id,
    )
    .map_err(|_| BridgeFailure::OperationFailed)?;
    let response = runtime
        .dispatch(client, &header, &request, |value| {
            let encoded = value.encode().map_err(|_| DispatchError::Internal)?;
            ResponseEnvelope::decode(&encoded).map_err(|_| DispatchError::Internal)
        })
        .map_err(|_| BridgeFailure::OperationFailed)?;
    match response.error() {
        None => Ok(response),
        Some(PublicErrorCode::Locked) => Err(BridgeFailure::Locked),
        Some(PublicErrorCode::Cancelled) => Err(BridgeFailure::Cancelled),
        Some(PublicErrorCode::DeadlineExceeded) => Err(BridgeFailure::TimedOut),
        Some(PublicErrorCode::AgentUnavailable) => Err(BridgeFailure::AgentUnavailable),
        Some(PublicErrorCode::Incompatible) => Err(BridgeFailure::Incompatible),
        Some(_) => Err(BridgeFailure::OperationFailed),
    }
}

fn seed(runtime: &AgentRuntime, locked: bool) -> Result<()> {
    let desktop = connection(runtime, ClientRole::Desktop, 10)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    request(
        runtime,
        &desktop,
        1,
        &OperationRequest::CreateVault {
            master_password: Zeroizing::new(PASSWORD.to_owned()),
        },
        Some([1; 16]),
        deadline,
    )?;
    let rows: Vec<_> = ACCOUNTS
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    if rows.len() != 5 {
        return Err(BridgeFailure::OperationFailed);
    }
    for (index, row) in rows.iter().enumerate() {
        let fields: Vec<_> = row.split('\t').collect();
        if fields.len() != 4 {
            return Err(BridgeFailure::OperationFailed);
        }
        let marker = u8::try_from(index + 2).map_err(|_| BridgeFailure::OperationFailed)?;
        request(
            runtime,
            &desktop,
            u64::from(marker),
            &OperationRequest::AddAccount {
                fields: AccountFields::new(fields[0], fields[1], fields[2], fields[3])
                    .map_err(|_| BridgeFailure::OperationFailed)?,
            },
            Some([marker; 16]),
            deadline,
        )?;
    }
    if locked {
        request(
            runtime,
            &desktop,
            7,
            &OperationRequest::Lock,
            None,
            deadline,
        )?;
    }
    runtime
        .disconnect(&desktop)
        .map_err(|_| BridgeFailure::OperationFailed)
}

fn fill(
    runtime: &AgentRuntime,
    context: &BrowserContext,
    timeout: Duration,
    marker: u8,
) -> Result<Option<BrowserCredential>> {
    let deadline = Instant::now() + timeout;
    let client = connection(runtime, ClientRole::NativeHost, marker)?;
    let result = (|| {
        let response = request(
            runtime,
            &client,
            1,
            &OperationRequest::ExactOriginMatches {
                context: context.clone(),
            },
            None,
            deadline,
        )?;
        let Some(selection) = BrowserSelection::decode_optional(response.body())
            .map_err(|_| BridgeFailure::OperationFailed)?
        else {
            return Ok(None);
        };
        let response = request(
            runtime,
            &client,
            2,
            &OperationRequest::GetSelectedCredential {
                context: context.clone(),
                selection,
            },
            None,
            deadline,
        )?;
        BrowserCredential::decode(response.body())
            .map(Some)
            .map_err(|_| BridgeFailure::OperationFailed)
    })();
    runtime
        .disconnect(&client)
        .map_err(|_| BridgeFailure::OperationFailed)?;
    result
}

fn status(runtime: &AgentRuntime) -> AgentStatus {
    match runtime.state() {
        AgentState::Starting => AgentStatus::Starting,
        AgentState::NoVault => AgentStatus::NoVault,
        AgentState::Locked => AgentStatus::Locked,
        AgentState::Unlocking => AgentStatus::Unlocking,
        AgentState::Unlocked => AgentStatus::Unlocked,
        AgentState::Updating => AgentStatus::Updating,
        AgentState::ShuttingDown => AgentStatus::ShuttingDown,
    }
}

fn serve(runtime: &AgentRuntime) -> std::result::Result<(), &'static str> {
    // Fixed readiness signal, emitted only after durable seeding. The extension's
    // unchanged per-request timeouts begin after setup, not during password KDF.
    let mut diagnostic = io::stderr().lock();
    diagnostic
        .write_all(b"ISSUE17_FIXTURE_READY\n")
        .map_err(|_| "fixture readiness failed")?;
    diagnostic.flush().map_err(|_| "fixture readiness failed")?;
    let mut reader = io::stdin().lock();
    let mut writer = io::stdout().lock();
    for index in 0..MAX_REQUESTS {
        if reader
            .fill_buf()
            .map_err(|_| "fixture input failed")?
            .is_empty()
        {
            return Ok(());
        }
        protocol::serve_with_fill(
            &mut reader,
            &mut writer,
            |_| Ok(status(runtime)),
            |context, timeout| fill(runtime, context, timeout, 100 + index),
        )
        .map_err(|_| "fixture native framing failed")?;
    }
    Err("fixture request limit reached")
}

fn run(path: &Path, locked: bool) -> std::result::Result<(), &'static str> {
    create_directory(path)?;
    let runtime =
        AgentRuntime::start(path.join("vault.sqlite3")).map_err(|_| "fixture runtime failed")?;
    let result = seed(&runtime, locked)
        .map_err(|_| "fixture setup failed")
        .and_then(|()| serve(&runtime));
    let stopped = runtime.shutdown().map_err(|_| "fixture shutdown failed");
    result.and(stopped)
}

fn main() -> ExitCode {
    match arguments(&std::env::args_os().skip(1).collect::<Vec<_>>())
        .and_then(|(path, locked)| run(&path, locked))
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        let nonce = getrandom::u64().unwrap();
        let path = std::env::temp_dir().join(format!("librarian-stdio-guard-{nonce:016x}"));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn only_new_directory_and_optional_locked_are_accepted() {
        for args in [
            vec![],
            vec!["--new-directory", "relative"],
            vec!["--existing-vault", "vault.sqlite3"],
            vec!["--new-directory", "relative", "--password", "anything"],
        ] {
            assert!(arguments(&args.into_iter().map(OsString::from).collect::<Vec<_>>()).is_err());
        }
        let path = std::env::temp_dir()
            .join("librarian-stdio-new")
            .into_os_string();
        assert!(
            arguments(&["--new-directory".into(), path.clone(), "--locked".into()])
                .unwrap()
                .1
        );
        assert!(arguments(&["--new-directory".into(), path, "--unlock".into()]).is_err());
        assert!(
            arguments(&[
                "--new-directory".into(),
                std::env::temp_dir().join("../escape").into_os_string()
            ])
            .is_err()
        );
        #[cfg(windows)]
        for path in [
            r"\\server\share\fixture",
            r"\\?\C:\fixture",
            r"C:\fixture:stream",
        ] {
            assert!(arguments(&["--new-directory".into(), path.into()]).is_err());
        }
    }

    #[test]
    fn existing_directory_and_vault_are_never_overwritten() {
        let path = root();
        assert!(run(&path, false).is_err());
        let sentinel = path.join("vault.sqlite3");
        fs::write(&sentinel, b"existing vault sentinel").unwrap();
        assert!(run(&path, false).is_err());
        assert_eq!(fs::read(sentinel).unwrap(), b"existing vault sentinel");
    }

    #[test]
    fn missing_parent_is_never_created() {
        let path = root();
        assert!(create_directory(&path.join("missing/fixture")).is_err());
        assert!(!path.join("missing").exists());
    }
}
