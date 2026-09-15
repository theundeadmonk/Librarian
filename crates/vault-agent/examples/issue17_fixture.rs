//! TEST ONLY. Creates a NEW, isolated encrypted fixture using production runtime
//! dispatch. No installed-agent connection, UI automation, network listener,
//! arbitrary credentials, existing-vault option, or production entry point.
//! Connection identities below are synthetic in-process test inputs, NOT proof
//! of OS process authentication or installed extension/desktop acceptance.

use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

use librarian_agent_protocol::{
    AccountFields, AgentState, BrowserContext, BrowserCredential, BrowserSelection,
    CURRENT_VERSION, ClientHello, ClientRole, Connection, ConnectionLimits, FEATURE_BROWSER_FILL,
    FrameHeader, MessageKind, OperationRequest, PublicErrorCode, RequestEnvelope, ResponseEnvelope,
};
use librarian_vault_agent::{AgentRuntime, DispatchError};
use zeroize::Zeroizing;

// Public, compiled-in fixture password. Never accepts or reads a user's password.
const FIXTURE_PASSWORD: &str = "Issue17-Isolated-Fixture-Only!2026";
const ACCOUNTS: &str = include_str!("../../../tests/fixtures/issue17-accounts.tsv");
const BUILD_ID: [u8; 32] = [0x71; 32];
const MAX_SCAN_BYTES: u64 = 8 * 1024 * 1024;
type Result<T> = std::result::Result<T, &'static str>;

struct Account<'a> {
    service: &'a str,
    origin: &'a str,
    username: &'a str,
    password: &'a str,
}

#[derive(Default)]
struct Report {
    checks: Vec<(&'static str, bool)>,
    failure: Option<&'static str>,
    created_accounts: usize,
}

impl Report {
    fn check(&mut self, name: &'static str, passed: bool) -> Result<()> {
        self.checks.push((name, passed));
        if passed { Ok(()) } else { Err(name) }
    }

    fn json(&self) -> String {
        // All strings are static, non-secret labels; no exception text or input
        // paths, account contents, native responses, IDs, or tokens are logged.
        let checks = self
            .checks
            .iter()
            .map(|(name, passed)| format!(r#"{{"name":"{name}","passed":{passed}}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let outcome = if self.failure.is_none() {
            "Passed"
        } else {
            "Failed"
        };
        let failure = self
            .failure
            .map_or_else(|| "null".to_owned(), |name| format!("\"{name}\""));
        let created_accounts = self.created_accounts;
        format!(
            r#"{{"schemaVersion":1,"testOnly":true,"outcome":"{outcome}","failure":{failure},"evidenceScope":"isolated in-process production runtime","expectedAccountCount":5,"createdAccounts":{created_accounts},"vaultFile":"vault.sqlite3","existingVaultAccessed":false,"installedBrowserAcceptance":"NotRun","uiAcceptance":"NotRun","osPeerAuthentication":"NotRun","checks":[{checks}]}}"#
        )
    }
}

fn accounts() -> Result<Vec<Account<'static>>> {
    let accounts = ACCOUNTS
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 4 {
                return Err("invalid compiled fixture row");
            }
            Ok(Account {
                service: fields[0],
                origin: fields[1],
                username: fields[2],
                password: fields[3],
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if accounts.len() != 5 {
        return Err("invalid compiled fixture account count");
    }
    Ok(accounts)
}

fn parse_arguments(arguments: &[OsString]) -> Result<PathBuf> {
    if arguments.len() != 2 || arguments[0] != "--new-directory" {
        return Err("usage: issue17-fixture --new-directory ABSOLUTE_NEW_DIRECTORY");
    }
    let path = PathBuf::from(&arguments[1]);
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err("fixture requires an absolute new directory without traversal");
    }
    Ok(path)
}

fn is_redirected(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0 // FILE_ATTRIBUTE_REPARSE_POINT
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn require_plain_directory_chain(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        let metadata =
            fs::symlink_metadata(ancestor).map_err(|_| "fixture parent inspection failed")?;
        if !metadata.is_dir() || is_redirected(&metadata) {
            return Err("fixture parent must not contain links or reparse points");
        }
    }
    Ok(())
}

fn create_directory(path: &Path) -> Result<()> {
    // Reuse the CLI validation for direct test invocations as well.
    parse_arguments(&["--new-directory".into(), path.as_os_str().to_owned()])?;
    let parent = path.parent().ok_or("fixture parent is absent")?;
    require_plain_directory_chain(parent)?;
    // Fail even for an existing EMPTY directory. No file overwrite or cleanup.
    #[cfg(unix)]
    let created = {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)
    };
    #[cfg(not(unix))]
    let created = fs::create_dir(path);
    created.map_err(|_| "fixture directory must not already exist")?;
    require_plain_directory_chain(path)
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
    .map_err(|_| "fixture hello failed")?;
    let (state, epoch) = runtime
        .status_snapshot()
        .map_err(|_| "fixture status failed")?;
    Connection::negotiate(
        role,
        17,
        BUILD_ID,
        &hello,
        &features,
        [marker.wrapping_add(1); 32],
        [marker.wrapping_add(2); 16],
        state,
        epoch,
        ConnectionLimits::default(),
    )
    .map(|value| value.0)
    .map_err(|_| "fixture connection negotiation failed")
}

fn dispatch(
    runtime: &AgentRuntime,
    client: &Connection,
    id: u64,
    operation: &OperationRequest,
    key: Option<[u8; 16]>,
) -> Result<ResponseEnvelope> {
    let request = RequestEnvelope::new(
        operation.operation(),
        runtime.unlock_epoch(),
        30_000,
        key,
        operation
            .encode()
            .map_err(|_| "fixture operation encoding failed")?,
    )
    .map_err(|_| "fixture request failed")?;
    let encoded = request
        .encode()
        .map_err(|_| "fixture request encoding failed")?;
    let header = FrameHeader::new(
        MessageKind::Request,
        CURRENT_VERSION,
        encoded.len(),
        *client.connection_id(),
        id,
    )
    .map_err(|_| "fixture request header failed")?;
    runtime
        .dispatch(client, &header, &request, |response| {
            let encoded = response.encode().map_err(|_| DispatchError::Internal)?;
            ResponseEnvelope::decode(&encoded).map_err(|_| DispatchError::Internal)
        })
        .map_err(|_| "fixture runtime dispatch failed")
}

fn success(
    runtime: &AgentRuntime,
    client: &Connection,
    id: u64,
    operation: &OperationRequest,
    key: Option<[u8; 16]>,
) -> Result<ResponseEnvelope> {
    let response = dispatch(runtime, client, id, operation, key)?;
    if response.error().is_some() {
        return Err("fixture operation returned an error");
    }
    Ok(response)
}

fn context(origin: &str) -> Result<BrowserContext> {
    BrowserContext::new([1; 16], 7, 0, [9; 16], origin, origin)
        .map_err(|_| "fixture browser context failed")
}

fn select(runtime: &AgentRuntime, client: &Connection, origin: &str) -> Result<ResponseEnvelope> {
    dispatch(
        runtime,
        client,
        1,
        &OperationRequest::ExactOriginMatches {
            context: context(origin)?,
        },
        None,
    )
}

fn selected(response: &ResponseEnvelope, origin: &str) -> Result<OperationRequest> {
    Ok(OperationRequest::GetSelectedCredential {
        context: context(origin)?,
        selection: BrowserSelection::decode_optional(response.body())
            .map_err(|_| "fixture selection decoding failed")?
            .ok_or("fixture expected a selection")?,
    })
}

fn seed(runtime: &AgentRuntime, report: &mut Report, accounts: &[Account<'_>]) -> Result<()> {
    let client = connection(runtime, ClientRole::Desktop, 10)?;
    success(
        runtime,
        &client,
        1,
        &OperationRequest::CreateVault {
            master_password: Zeroizing::new(FIXTURE_PASSWORD.to_owned()),
        },
        Some([1; 16]),
    )?;
    report.check(
        "fresh encrypted vault created",
        runtime.state() == AgentState::Unlocked,
    )?;
    for (index, account) in accounts.iter().enumerate() {
        let marker = u8::try_from(index + 2).map_err(|_| "fixture index overflow")?;
        success(
            runtime,
            &client,
            u64::from(marker),
            &OperationRequest::AddAccount {
                fields: AccountFields::new(
                    account.service,
                    account.origin,
                    account.username,
                    account.password,
                )
                .map_err(|_| "compiled account input rejected")?,
            },
            Some([marker; 16]),
        )?;
        report.created_accounts += 1;
    }
    runtime
        .disconnect(&client)
        .map_err(|_| "fixture desktop disconnect failed")?;
    report.check("five synthetic accounts created via runtime", true)
}

fn verify_origin(
    runtime: &AgentRuntime,
    origin: &str,
    expected: Option<&Account<'_>>,
) -> Result<bool> {
    let client = connection(runtime, ClientRole::NativeHost, 30)?;
    let result = (|| {
        let response = select(runtime, &client, origin)?;
        if response.error().is_some() {
            return Ok(false);
        }
        let selection = BrowserSelection::decode_optional(response.body())
            .map_err(|_| "fixture selection decoding failed")?;
        let Some(account) = expected else {
            return Ok(selection.is_none());
        };
        if selection.is_none() {
            return Ok(false);
        }
        let request = selected(&response, origin)?;
        let fill = success(runtime, &client, 2, &request, None)?;
        let credential = BrowserCredential::decode(fill.body())
            .map_err(|_| "fixture credential decoding failed")?;
        let matches =
            credential.username() == account.username && credential.password() == account.password;
        drop(credential);
        let replay = dispatch(runtime, &client, 3, &request, None)?;
        Ok(matches
            && replay.error() == Some(PublicErrorCode::InvalidRequest)
            && replay.body().is_empty())
    })();
    runtime
        .disconnect(&client)
        .map_err(|_| "fixture browser disconnect failed")?;
    result
}

fn origin_checks(
    runtime: &AgentRuntime,
    report: &mut Report,
    accounts: &[Account<'_>],
) -> Result<()> {
    for (name, origin, expected) in [
        (
            "baseline exact origin and single-use disclosure",
            "https://librarian.test",
            Some(&accounts[0]),
        ),
        (
            "non-default port exact match and single-use disclosure",
            "https://ports.librarian.test:8443",
            Some(&accounts[1]),
        ),
        (
            "Unicode stored account matches canonical IDN wire origin",
            "https://xn--bcher-kva.librarian.test",
            Some(&accounts[2]),
        ),
        (
            "omitted non-default port refuses",
            "https://ports.librarian.test",
            None,
        ),
        (
            "different non-default port refuses",
            "https://ports.librarian.test:8444",
            None,
        ),
        (
            "IDN ASCII lookalike refuses",
            "https://bucher.librarian.test",
            None,
        ),
        (
            "IDN subdomain refuses",
            "https://sub.xn--bcher-kva.librarian.test",
            None,
        ),
        (
            "IDN different port refuses",
            "https://xn--bcher-kva.librarian.test:8443",
            None,
        ),
        (
            "two known accounts at exact origin refuse",
            "https://duplicates.librarian.test",
            None,
        ),
        (
            "duplicate account different port refuses",
            "https://duplicates.librarian.test:8443",
            None,
        ),
        (
            "baseline hostname suffix refuses",
            "https://librarian.test.evil.test",
            None,
        ),
    ] {
        report.check(name, verify_origin(runtime, origin, expected)?)?;
    }

    // The native protocol intentionally accepts only canonical HTTPS origins.
    // Browser canonicalization and path/DOM behavior are NOT tested here.
    for (name, origin) in [
        (
            "raw HTTP native origin rejected",
            "http://ports.librarian.test:8443",
        ),
        (
            "raw Unicode native origin rejected",
            "https://bücher.librarian.test",
        ),
        (
            "zero-padded native port rejected",
            "https://ports.librarian.test:08443",
        ),
        (
            "explicit default native port rejected",
            "https://librarian.test:443",
        ),
        (
            "native origin containing path rejected",
            "https://librarian.test/login",
        ),
    ] {
        let client = connection(runtime, ClientRole::NativeHost, 30)?;
        let response = select(runtime, &client, origin)?;
        runtime
            .disconnect(&client)
            .map_err(|_| "fixture browser disconnect failed")?;
        report.check(
            name,
            response.error() == Some(PublicErrorCode::InvalidRequest) && response.body().is_empty(),
        )?;
    }
    Ok(())
}

fn lock_checks(runtime: &AgentRuntime, report: &mut Report) -> Result<()> {
    let desktop = connection(runtime, ClientRole::Desktop, 10)?;
    let browser = connection(runtime, ClientRole::NativeHost, 30)?;
    let selection = select(runtime, &browser, "https://librarian.test")?;
    let request = selected(&selection, "https://librarian.test")?;
    success(runtime, &desktop, 1, &OperationRequest::Lock, None)?;
    report.check(
        "explicit lock changes runtime state",
        runtime.state() == AgentState::Locked,
    )?;
    let denied = dispatch(runtime, &browser, 2, &request, None)?;
    report.check(
        "selected credential unavailable after lock",
        denied.error().is_some() && denied.body().is_empty(),
    )?;
    runtime
        .disconnect(&browser)
        .map_err(|_| "fixture browser disconnect failed")?;
    let locked_browser = connection(runtime, ClientRole::NativeHost, 31)?;
    let denied = select(runtime, &locked_browser, "https://librarian.test")?;
    report.check(
        "locked vault refuses new origin request",
        denied.error() == Some(PublicErrorCode::Locked) && denied.body().is_empty(),
    )?;
    runtime
        .disconnect(&locked_browser)
        .map_err(|_| "fixture browser disconnect failed")?;
    runtime
        .disconnect(&desktop)
        .map_err(|_| "fixture desktop disconnect failed")
}

fn inspect_persisted_accounts(
    path: &Path,
    accounts: &[Account<'_>],
    report: &mut Report,
) -> Result<()> {
    // This can only receive the new path created by this process, never an
    // installed vault path. Readbacks are reduced to booleans; no data is logged.
    let mut agent = librarian_vault_agent::VaultAgent::open_locked(path);
    agent
        .unlock(
            librarian_vault_core::MasterPassword::new(FIXTURE_PASSWORD)
                .map_err(|_| "fixture password construction failed")?,
            &librarian_vault_core::CancellationFlag::new(),
        )
        .map_err(|_| "fixture persisted vault unlock failed")?;
    let stored = agent
        .list_website_accounts()
        .map_err(|_| "fixture persisted account read failed")?;
    report.check(
        "exactly five accounts persist on disk",
        stored.len() == accounts.len(),
    )?;
    for account in accounts {
        let expected_origin = if account.origin == "https://bücher.librarian.test" {
            "https://xn--bcher-kva.librarian.test"
        } else {
            account.origin
        };
        if stored
            .iter()
            .filter(|value| {
                value.service_name() == account.service
                    && value.permitted_origin() == expected_origin
                    && value.username() == account.username
                    && value.password() == account.password
            })
            .count()
            != 1
        {
            return Err("persisted fixture account mismatch");
        }
    }
    report.check("all synthetic fields and duplicate setup verified", true)?;
    drop(stored);
    agent.lock();
    Ok(())
}

fn scan_storage(path: &Path, accounts: &[Account<'_>], report: &mut Report) -> Result<()> {
    let canaries: Vec<_> = std::iter::once(FIXTURE_PASSWORD)
        .chain(
            accounts
                .iter()
                .flat_map(|account| [account.username, account.password]),
        )
        .collect();
    for name in ["vault.sqlite3", "vault.sqlite3-wal", "vault.sqlite3-shm"] {
        let file_path = path.join(name);
        let metadata = match fs::symlink_metadata(&file_path) {
            Ok(value) => value,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && name != "vault.sqlite3" =>
            {
                continue;
            }
            Err(_) => return Err("fixture storage inspection failed"),
        };
        if !metadata.is_file() || is_redirected(&metadata) || metadata.len() > MAX_SCAN_BYTES {
            return Err("fixture storage scan bound or file type failed");
        }
        let mut bytes = Vec::new();
        fs::File::open(&file_path)
            .map_err(|_| "fixture storage read failed")?
            .take(MAX_SCAN_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "fixture storage read failed")?;
        if bytes.len() as u64 > MAX_SCAN_BYTES
            || canaries.iter().any(|canary| {
                bytes
                    .windows(canary.len())
                    .any(|window| window == canary.as_bytes())
            })
        {
            return Err("plaintext canary or oversized fixture storage detected");
        }
    }
    report.check("bounded database and sidecar plaintext-canary scan", true)
}

fn exercise(path: &Path, report: &mut Report) -> Result<()> {
    let accounts = accounts()?;
    let vault_path = path.join("vault.sqlite3");
    let runtime = AgentRuntime::start(&vault_path).map_err(|_| "fixture runtime startup failed")?;
    seed(&runtime, report, &accounts)?;
    origin_checks(&runtime, report, &accounts)?;
    lock_checks(&runtime, report)?;
    runtime
        .shutdown()
        .map_err(|_| "fixture runtime shutdown failed")?;
    drop(runtime);
    inspect_persisted_accounts(&vault_path, &accounts, report)?;
    let restarted =
        AgentRuntime::start(&vault_path).map_err(|_| "fixture runtime restart failed")?;
    report.check(
        "restart begins locked",
        restarted.state() == AgentState::Locked,
    )?;
    let desktop = connection(&restarted, ClientRole::Desktop, 10)?;
    success(
        &restarted,
        &desktop,
        1,
        &OperationRequest::UnlockMasterPassword {
            master_password: Zeroizing::new(FIXTURE_PASSWORD.to_owned()),
        },
        None,
    )?;
    report.check(
        "synthetic fixture unlocks after restart",
        restarted.state() == AgentState::Unlocked,
    )?;
    origin_checks(&restarted, report, &accounts)?;
    restarted
        .shutdown()
        .map_err(|_| "fixture restarted runtime shutdown failed")?;
    drop(restarted);
    report.check("fixture runtime shut down with keys discarded", true)?;
    scan_storage(path, &accounts, report)
}

fn generate(path: &Path) -> Result<Report> {
    create_directory(path)?;
    let mut report = Report::default();
    if let Err(failure) = exercise(path, &mut report) {
        report.failure = Some(failure);
    }
    // Create-new only; retain partial artifacts on failure for diagnosis.
    require_plain_directory_chain(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.join("report.json"))
        .map_err(|_| "fixture report creation failed")?;
    file.write_all(report.json().as_bytes())
        .map_err(|_| "fixture report write failed")?;
    file.sync_all().map_err(|_| "fixture report sync failed")?;
    Ok(report)
}

fn main() -> ExitCode {
    let result = parse_arguments(&std::env::args_os().skip(1).collect::<Vec<_>>())
        .and_then(|path| generate(&path));
    match result {
        Ok(report) => {
            println!("{}", report.json());
            if report.failure.is_none() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_root() -> PathBuf {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let suffix = nonce
            .iter()
            .flat_map(|byte| {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                [
                    char::from(HEX[usize::from(byte >> 4)]),
                    char::from(HEX[usize::from(byte & 15)]),
                ]
            })
            .collect::<String>();
        let path = std::env::temp_dir().join(format!("librarian-isolated-fixture-{suffix}"));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn arguments_reject_unsafe_or_extra_inputs() {
        for arguments in [
            vec![],
            vec!["--new-directory", "relative"],
            vec!["--existing-vault", "vault.sqlite3"],
            vec!["--new-directory", "relative", "--password", "anything"],
        ] {
            assert!(
                parse_arguments(
                    &arguments
                        .into_iter()
                        .map(OsString::from)
                        .collect::<Vec<_>>()
                )
                .is_err()
            );
        }
        assert!(
            parse_arguments(&[
                "--new-directory".into(),
                std::env::temp_dir().join("../escape").into_os_string()
            ])
            .is_err()
        );
    }

    #[test]
    fn existing_directory_and_files_are_never_overwritten() {
        let root = new_root();
        assert!(generate(&root).is_err());
        let sentinel = root.join("vault.sqlite3");
        fs::write(&sentinel, b"existing vault sentinel").unwrap();
        assert!(generate(&root).is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"existing vault sentinel");
        assert!(!root.join("report.json").exists());
    }

    #[test]
    fn missing_parent_is_not_created() {
        let root = new_root();
        assert!(generate(&root.join("missing/fixture")).is_err());
        assert!(!root.join("missing").exists());
    }

    #[test]
    fn generated_fixture_passes_without_secret_report_fields() {
        let root = new_root();
        let output = root.join("new-fixture");
        let report = generate(&output).unwrap();
        assert!(
            report.failure.is_none(),
            "fixture failed at {:?}",
            report.failure
        );
        assert_eq!(report.checks.len(), 43);
        let json = report.json();
        for account in accounts().unwrap() {
            assert!(!json.contains(account.username));
            assert!(!json.contains(account.password));
        }
        assert!(!json.contains(FIXTURE_PASSWORD));
        assert!(json.contains("\"uiAcceptance\":\"NotRun\""));
        assert_eq!(
            fs::read_to_string(output.join("report.json")).unwrap(),
            json
        );
        // Intentionally retain uniquely named test artifacts; no recursive delete.
    }
}
