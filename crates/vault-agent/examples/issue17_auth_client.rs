//! TEST ONLY. Desktop-role client for a uniquely named, signed Issue 17 lab
//! package. Uses production Windows peer verification and framed IPC, never
//! in-process dispatch. Cannot connect to the ordinary Librarian package and
//! accepts no passwords, vault paths, endpoint paths, or arbitrary operations.
//! A second un-packaged copy acts as the lab-only native stdio launcher.

#[cfg(any(windows, test))]
const PACKAGE_PREFIX: &str = "Librarian.I17.R";

#[cfg(any(windows, test))]
fn valid_package_name(name: &str) -> bool {
    name.strip_prefix(PACKAGE_PREFIX).is_some_and(|suffix| {
        suffix.len() == 24
            && suffix
                .bytes()
                .all(|value| value.is_ascii_hexdigit() && !value.is_ascii_uppercase())
    })
}

#[cfg(windows)]
mod windows {
    use librarian_agent_protocol::{
        AccountFields, AgentState, CURRENT_VERSION, ClientHello, ClientRole, Frame, FrameHeader,
        MessageKind, OperationRequest, RequestEnvelope, ResponseEnvelope, ServerHello, Version,
    };
    use librarian_windows_ipc::{
        ComponentRole, EndpointDescriptorStore, PeerPolicy, PipeConnection, SessionSecurityMonitor,
        current_process_observation,
    };
    use sha2::{Digest, Sha256};
    use std::{
        env, fs,
        io::{Read, Write},
        os::windows::{fs::MetadataExt, process::CommandExt},
        path::{Path, PathBuf},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    use zeroize::Zeroizing;

    type Result<T> = std::result::Result<T, &'static str>;
    const PASSWORD: &str = "Issue17-Isolated-Fixture-Only!2026";
    const ACCOUNTS: &str = include_str!("../../../tests/fixtures/issue17-accounts.tsv");
    const MARKER: &[u8] =
        b"Issue17 fixed public fixture: five accounts created via authenticated IPC\n";

    fn require_fresh_session() -> Result<()> {
        let monitor = SessionSecurityMonitor::register()
            .map_err(|_| "Windows test session must be unlocked and observable")?;
        if monitor
            .shutdown_requested(true)
            .map_err(|_| "Windows test session lifecycle could not be observed")?
        {
            return Err("Windows test session is inactive; fresh user input in the VM is required");
        }
        Ok(())
    }

    struct Context {
        state_path: PathBuf,
        package_full_name: String,
        policy: PeerPolicy,
        build_id: [u8; 32],
    }

    fn plain_chain(path: &Path) -> Result<()> {
        for ancestor in path.ancestors() {
            let metadata =
                fs::symlink_metadata(ancestor).map_err(|_| "lab path inspection failed")?;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("redirected lab path refused");
            }
        }
        Ok(())
    }

    fn installation() -> Result<(PathBuf, String)> {
        if env::var("COMPUTERNAME").as_deref() != Ok("LIBRARIAN-TEST") {
            return Err("test client is restricted to the disposable VM");
        }
        let executable = env::current_exe().map_err(|_| "lab image unavailable")?;
        plain_chain(&executable)?;
        let root = executable.parent().ok_or("lab root missing")?.to_path_buf();
        let name = root
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| super::valid_package_name(name))
            .ok_or("ordinary product or invalid lab package refused")?
            .to_owned();
        let expected =
            PathBuf::from(env::var_os("ProgramFiles").ok_or("program files unavailable")?)
                .join("LibrarianIssue17Lab")
                .join(&name);
        if !root
            .to_string_lossy()
            .eq_ignore_ascii_case(&expected.to_string_lossy())
        {
            return Err("unexpected lab installation path");
        }
        Ok((root, name))
    }

    fn hash(path: &Path) -> Result<[u8; 32]> {
        let mut file = fs::File::open(path).map_err(|_| "lab image read failed")?;
        if file
            .metadata()
            .map_err(|_| "lab image inspection failed")?
            .len()
            > 64 * 1024 * 1024
        {
            return Err("lab image size limit");
        }
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 16384];
        loop {
            let length = file
                .read(&mut buffer)
                .map_err(|_| "lab image read failed")?;
            if length == 0 {
                return Ok(digest.finalize().into());
            }
            digest.update(&buffer[..length]);
        }
    }

    impl Context {
        fn new() -> Result<Self> {
            let (root, name) = installation()?;
            let handle =
                current_process_observation().map_err(|_| "lab identity observation failed")?;
            let current = handle.observation();
            let family = current
                .package_family_name
                .as_ref()
                .ok_or("lab package identity missing")?;
            let full = current
                .package_full_name
                .as_ref()
                .ok_or("lab full package identity missing")?;
            if !family.starts_with(&format!("{name}_"))
                || !full.starts_with(&format!("{name}_"))
                || current.application_user_model_id.as_deref()
                    != Some(&format!("{family}!Desktop"))
                || current.elevated
                || current.app_container
                || current.integrity_rid != 0x2000
                || !current
                    .image_path
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&root.join("Librarian.Windows.exe").to_string_lossy())
            {
                return Err("lab desktop identity mismatch");
            }
            let state_path =
                PathBuf::from(env::var_os("LOCALAPPDATA").ok_or("lab profile missing")?)
                    .join("Packages")
                    .join(family)
                    .join("LocalState")
                    .join("Librarian");
            plain_chain(&state_path)?;
            Ok(Self {
                state_path,
                package_full_name: full.clone(),
                build_id: hash(&current.image_path)?,
                policy: PeerPolicy {
                    role: ComponentRole::Agent,
                    session_id: current.session_id,
                    user_sid: current.user_sid.clone(),
                    logon_sid: current.logon_sid.clone(),
                    maximum_integrity_rid: 0x2000,
                    image_path: root.join("Librarian.VaultAgent.exe"),
                    package_full_name: full.clone(),
                    package_family_name: family.clone(),
                    application_user_model_id: Some(format!("{family}!VaultAgent")),
                },
            })
        }

        fn connect(&self, deadline: Instant) -> Result<(PipeConnection, ServerHello, [u8; 16])> {
            let descriptor =
                EndpointDescriptorStore::new(self.state_path.join("agent-endpoint-v1.cbor"))
                    .map_err(|_| "lab endpoint store failed")?
                    .load()
                    .map_err(|_| "lab endpoint unavailable")?;
            if descriptor.package_full_name() != self.package_full_name {
                return Err("lab endpoint identity mismatch");
            }
            let pipe = PipeConnection::connect(
                descriptor.pipe_name(),
                descriptor.agent_process_id(),
                descriptor.agent_process_creation_time(),
                &self.policy,
                remaining(deadline)?,
            )
            .map_err(|_| "authenticated lab connection rejected")?;
            let mut nonce = [0; 32];
            getrandom::fill(&mut nonce).map_err(|_| "lab nonce failed")?;
            let hello = ClientHello::new(
                nonce,
                CURRENT_VERSION,
                CURRENT_VERSION,
                ClientRole::Desktop,
                self.build_id,
                vec![],
            )
            .map_err(|_| "lab hello failed")?;
            let payload = Zeroizing::new(hello.encode());
            let header = FrameHeader::new(
                MessageKind::ClientHello,
                Version::new(0, 0),
                payload.len(),
                [0; 16],
                0,
            )
            .map_err(|_| "lab hello framing failed")?;
            pipe.write_frame(
                &Frame::new(header, payload).map_err(|_| "lab hello frame failed")?,
                remaining(deadline)?,
            )
            .map_err(|_| "lab hello write failed")?;
            let frame = pipe
                .read_frame(remaining(deadline)?)
                .map_err(|_| "lab hello read failed")?;
            let hello =
                ServerHello::decode(frame.payload()).map_err(|_| "lab hello decode failed")?;
            if frame.header().kind() != MessageKind::ServerHello
                || frame.header().version() != CURRENT_VERSION
                || frame.header().connection_id() == &[0; 16]
                || hello.selected_version() != CURRENT_VERSION
                || hello.derived_role() != ClientRole::Desktop
                || !hello.granted_features().is_empty()
            {
                return Err("lab negotiated identity mismatch");
            }
            Ok((pipe, hello, *frame.header().connection_id()))
        }

        fn state(&self) -> Result<AgentState> {
            self.connect(Instant::now() + Duration::from_secs(5))
                .map(|value| value.1.agent_state())
        }

        fn request(&self, operation: OperationRequest, key: Option<[u8; 16]>) -> Result<()> {
            let operation_code = operation.operation();
            let deadline = Instant::now() + Duration::from_secs(30);
            let (pipe, hello, connection_id) = self.connect(deadline)?;
            let timeout = u32::try_from(remaining(deadline)?.as_millis())
                .map_err(|_| "lab deadline overflow")?;
            let request = RequestEnvelope::new(
                operation.operation(),
                hello.unlock_epoch(),
                timeout,
                key,
                operation
                    .encode()
                    .map_err(|_| "lab operation encode failed")?,
            )
            .map_err(|_| "lab request failed")?;
            drop(operation);
            let payload = request.encode().map_err(|_| "lab request encode failed")?;
            let header = FrameHeader::new(
                MessageKind::Request,
                CURRENT_VERSION,
                payload.len(),
                connection_id,
                1,
            )
            .map_err(|_| "lab request header failed")?;
            pipe.write_frame(
                &Frame::new(header, payload).map_err(|_| "lab request frame failed")?,
                remaining(deadline)?,
            )
            .map_err(|_| "lab request write failed")?;
            let frame = pipe
                .read_frame(remaining(deadline)?)
                .map_err(|_| "lab response read failed")?;
            if frame.header().kind() != MessageKind::Response
                || frame.header().version() != CURRENT_VERSION
                || frame.header().connection_id() != &connection_id
                || frame.header().request_id() != 1
            {
                return Err("lab response identity mismatch");
            }
            let response = ResponseEnvelope::decode(frame.payload())
                .map_err(|_| "lab response decode failed")?;
            if let Some(code) = response.error() {
                // Only closed protocol enums, never payloads or secrets.
                eprintln!("lab operation {operation_code:?} refused with {code:?}");
                return Err("lab operation refused");
            }
            Ok(())
        }

        fn seed(&self) -> Result<()> {
            // Use the production observer; never synthesize activity or change
            // the timeout to keep a test vault unlocked.
            require_fresh_session()?;
            if self.state()? != AgentState::NoVault || self.state_path.join("vault.db").exists() {
                return Err("existing lab vault refused");
            }
            let mut guard = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.state_path.join("issue17-seed-started"))
                .map_err(|_| "lab seed already attempted")?;
            guard.write_all(MARKER).map_err(|_| "lab marker failed")?;
            self.request(
                OperationRequest::CreateVault {
                    master_password: Zeroizing::new(PASSWORD.to_owned()),
                },
                Some([1; 16]),
            )?;
            let accounts: Vec<_> = ACCOUNTS
                .lines()
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .collect();
            if accounts.len() != 5 {
                return Err("lab account inventory invalid");
            }
            for (index, row) in accounts.iter().enumerate() {
                let fields: Vec<_> = row.split('\t').collect();
                if fields.len() != 4 {
                    return Err("lab account row invalid");
                }
                let marker = u8::try_from(index + 2).map_err(|_| "lab marker overflow")?;
                self.request(
                    OperationRequest::AddAccount {
                        fields: AccountFields::new(fields[0], fields[1], fields[2], fields[3])
                            .map_err(|_| "fixed lab account rejected")?,
                    },
                    Some([marker; 16]),
                )?;
            }
            let mut complete = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.state_path.join("issue17-seed-complete"))
                .map_err(|_| "lab completion marker failed")?;
            complete
                .write_all(MARKER)
                .map_err(|_| "lab completion write failed")?;
            complete
                .sync_all()
                .map_err(|_| "lab completion sync failed")?;
            Ok(())
        }

        fn require_seed(&self) -> Result<()> {
            let marker = self.state_path.join("issue17-seed-complete");
            plain_chain(&marker)?;
            let mut bytes = Vec::new();
            fs::File::open(marker)
                .map_err(|_| "completed lab seed required")?
                .take(128)
                .read_to_end(&mut bytes)
                .map_err(|_| "lab marker read failed")?;
            if bytes != MARKER {
                return Err("lab marker mismatch");
            }
            Ok(())
        }
    }

    fn remaining(deadline: Instant) -> Result<Duration> {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|value| value.as_millis() > 0)
            .ok_or("lab deadline exceeded")
    }

    pub fn run() -> Result<()> {
        let args: Vec<_> = env::args().skip(1).collect();
        if args.len() == 2
            && args[0] == "chrome-extension://jiifjoajanfeoabbkmpodkgfmabhikkh/"
            && args[1]
                .strip_prefix("--parent-window=")
                .is_some_and(|value| {
                    !value.is_empty()
                        && value.len() <= 20
                        && value.bytes().all(|v| v.is_ascii_digit())
                })
        {
            let (root, _) = installation()?;
            if env::current_exe()
                .map_err(|_| "lab launcher path failed")?
                .file_name()
                .and_then(|v| v.to_str())
                != Some("Librarian.IdentityLauncher.exe")
            {
                return Err("lab launcher image mismatch");
            }
            let status = Command::new(root.join("Librarian.ChromiumNativeHost.exe"))
                .args(args)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .creation_flags(0x0800_0000)
                .status()
                .map_err(|_| "lab native host launch failed")?;
            return if status.success() {
                Ok(())
            } else {
                Err("lab native host failed")
            };
        }
        if args.len() != 1
            || !["--seed", "--status", "--lock", "--unlock-fixture"].contains(&args[0].as_str())
        {
            return Err("only fixed lab seed/status/lock/unlock operations are supported");
        }
        let context = Context::new()?;
        match args[0].as_str() {
            "--seed" => context.seed()?,
            "--lock" => {
                context.require_seed()?;
                context.request(OperationRequest::Lock, None)?;
            }
            "--unlock-fixture" => {
                context.require_seed()?;
                require_fresh_session()?;
                context.request(
                    OperationRequest::UnlockMasterPassword {
                        master_password: Zeroizing::new(PASSWORD.to_owned()),
                    },
                    None,
                )?;
            }
            _ => {}
        }
        let state = context.state()?;
        if (matches!(args[0].as_str(), "--seed" | "--unlock-fixture")
            && state != AgentState::Unlocked)
            || (args[0] == "--lock" && state != AgentState::Locked)
        {
            return Err("lab final state mismatch");
        }
        println!(
            "{{\"testOnly\":true,\"outcome\":\"Passed\",\"authenticatedWindowsIpc\":true,\"state\":\"{state:?}\",\"operation\":\"{}\"}}",
            args[0]
        );
        Ok(())
    }
}

fn main() -> std::process::ExitCode {
    #[cfg(windows)]
    match windows::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            std::process::ExitCode::FAILURE
        }
    }
    #[cfg(not(windows))]
    {
        eprintln!("Windows-only authenticated lab client");
        std::process::ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ordinary_product_and_malformed_lab_identities_are_rejected() {
        for name in [
            "TheUndeadMonk.Librarian.Development",
            "Librarian.I17.R",
            "Librarian.I17.R../escape",
            "Librarian.I17.RABCDEFGHIJKLMNOPQRSTUVWX",
            "Librarian.I17.R0123456789abcdef012345678",
        ] {
            assert!(!super::valid_package_name(name));
        }
        assert!(super::valid_package_name(
            "Librarian.I17.R0123456789abcdef01234567"
        ));
    }
}
