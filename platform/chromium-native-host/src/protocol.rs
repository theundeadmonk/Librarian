use std::{
    io::{self, Read, Write},
    time::Duration,
};

use librarian_agent_protocol::{BrowserContext as AgentBrowserContext, BrowserCredential};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const BROWSER_PROTOCOL_VERSION: u16 = 1;
pub const MAX_BROWSER_MESSAGE_BYTES: usize = 16 * 1024;
pub const FILL_PROTOCOL_VERSION: u16 = 2;
const MAX_BROWSER_RESPONSE_BYTES: usize = 128 * 1024;
const MIN_TIMEOUT_MS: u32 = 100;
const MAX_TIMEOUT_MS: u32 = 5_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeFailure {
    AgentUnavailable,
    Incompatible,
    OperationFailed,
    Locked,
    Cancelled,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AgentStatus {
    Starting,
    NoVault,
    Locked,
    Unlocking,
    Unlocked,
    Updating,
    ShuttingDown,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrowserRequest {
    protocol_version: u16,
    request_id: String,
    operation: BrowserOperation,
    context: BrowserContext,
    timeout_ms: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum BrowserOperation {
    Status,
    FillSingle,
}

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum BrowserContext {
    None,
    ExactHttps {
        tab_id: u32,
        frame_id: u32,
        document_id: String,
        top_level_origin: String,
        frame_origin: String,
    },
}

#[derive(Serialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum BrowserResponse<'a> {
    Credential {
        protocol_version: u16,
        request_id: &'a str,
        username: &'a str,
        password: &'a str,
    },
    NoCredential {
        protocol_version: u16,
        request_id: &'a str,
    },
    Ok {
        protocol_version: u16,
        request_id: &'a str,
        agent_status: AgentStatus,
    },
    Error {
        protocol_version: u16,
        request_id: Option<&'a str>,
        error: BrowserError,
    },
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
enum BrowserError {
    InvalidRequest,
    Incompatible,
    AgentUnavailable,
    OperationFailed,
    Locked,
    Cancelled,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServeError {
    Input,
    Output,
}

enum ReadFrame {
    EndOfStream,
    Message(Zeroizing<Vec<u8>>),
}

struct ValidRequest {
    request_id: String,
    timeout: Duration,
    fill_context: Option<AgentBrowserContext>,
}

struct RequestFailure {
    request_id: Option<String>,
    error: BrowserError,
    version: u16,
}

#[cfg(test)]
pub fn serve_once(
    reader: &mut impl Read,
    writer: &mut impl Write,
    status: impl FnOnce(Duration) -> Result<AgentStatus, BridgeFailure>,
) -> Result<(), ServeError> {
    serve_with_fill(reader, writer, status, |_, _| {
        Err(BridgeFailure::OperationFailed)
    })
}

pub fn serve_with_fill(
    reader: &mut impl Read,
    writer: &mut impl Write,
    status: impl FnOnce(Duration) -> Result<AgentStatus, BridgeFailure>,
    fill: impl FnOnce(
        &AgentBrowserContext,
        Duration,
    ) -> Result<Option<BrowserCredential>, BridgeFailure>,
) -> Result<(), ServeError> {
    let bytes = match read_frame(reader) {
        Ok(ReadFrame::EndOfStream) => return Ok(()),
        Ok(ReadFrame::Message(bytes)) => bytes,
        Err(()) => {
            write_response(
                writer,
                &BrowserResponse::Error {
                    protocol_version: BROWSER_PROTOCOL_VERSION,
                    request_id: None,
                    error: BrowserError::InvalidRequest,
                },
            )?;
            return Err(ServeError::Input);
        }
    };
    let request = match validate_request(&bytes) {
        Ok(request) => request,
        Err(failure) => {
            write_response(
                writer,
                &BrowserResponse::Error {
                    protocol_version: failure.version,
                    request_id: failure.request_id.as_deref(),
                    error: failure.error,
                },
            )?;
            return Ok(());
        }
    };
    if let Some(context) = &request.fill_context {
        let result = fill(context, request.timeout);
        let response = match &result {
            Ok(Some(credential)) => BrowserResponse::Credential {
                protocol_version: FILL_PROTOCOL_VERSION,
                request_id: &request.request_id,
                username: credential.username(),
                password: credential.password(),
            },
            Ok(None) => BrowserResponse::NoCredential {
                protocol_version: FILL_PROTOCOL_VERSION,
                request_id: &request.request_id,
            },
            Err(error) => BrowserResponse::Error {
                protocol_version: FILL_PROTOCOL_VERSION,
                request_id: Some(&request.request_id),
                error: match error {
                    BridgeFailure::AgentUnavailable => BrowserError::AgentUnavailable,
                    BridgeFailure::Incompatible => BrowserError::Incompatible,
                    BridgeFailure::Locked => BrowserError::Locked,
                    BridgeFailure::Cancelled => BrowserError::Cancelled,
                    BridgeFailure::TimedOut => BrowserError::TimedOut,
                    BridgeFailure::OperationFailed => BrowserError::OperationFailed,
                },
            },
        };
        return write_response(writer, &response);
    }
    let response = match status(request.timeout) {
        Ok(agent_status) => BrowserResponse::Ok {
            protocol_version: BROWSER_PROTOCOL_VERSION,
            request_id: &request.request_id,
            agent_status,
        },
        Err(error) => BrowserResponse::Error {
            protocol_version: BROWSER_PROTOCOL_VERSION,
            request_id: Some(&request.request_id),
            error: match error {
                BridgeFailure::AgentUnavailable => BrowserError::AgentUnavailable,
                BridgeFailure::Incompatible => BrowserError::Incompatible,
                BridgeFailure::OperationFailed
                | BridgeFailure::Locked
                | BridgeFailure::Cancelled
                | BridgeFailure::TimedOut => BrowserError::OperationFailed,
            },
        },
    };
    write_response(writer, &response)
}

fn validate_request(bytes: &[u8]) -> Result<ValidRequest, RequestFailure> {
    let request: BrowserRequest = serde_json::from_slice(bytes).map_err(|_| RequestFailure {
        request_id: None,
        error: BrowserError::InvalidRequest,
        version: BROWSER_PROTOCOL_VERSION,
    })?;
    let request_id = valid_request_id(&request.request_id).then(|| request.request_id.clone());
    let version = match request.operation {
        BrowserOperation::Status => BROWSER_PROTOCOL_VERSION,
        BrowserOperation::FillSingle => FILL_PROTOCOL_VERSION,
    };
    if request.protocol_version != version {
        return Err(RequestFailure {
            request_id,
            error: BrowserError::Incompatible,
            version,
        });
    }
    if request_id.is_none() || !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&request.timeout_ms) {
        return Err(RequestFailure {
            request_id,
            error: BrowserError::InvalidRequest,
            version,
        });
    }
    let fill_context = match (request.operation, request.context) {
        (BrowserOperation::Status, BrowserContext::None) => Some(None),
        (
            BrowserOperation::FillSingle,
            BrowserContext::ExactHttps {
                tab_id,
                frame_id,
                document_id,
                top_level_origin,
                frame_origin,
            },
        ) => parse_hex_id(&request.request_id)
            .zip(parse_document_id(&document_id))
            .filter(|_| canonical_origin(&top_level_origin) && canonical_origin(&frame_origin))
            .and_then(|(id, document)| {
                AgentBrowserContext::new(
                    id,
                    tab_id,
                    frame_id,
                    document,
                    &top_level_origin,
                    &frame_origin,
                )
                .ok()
            })
            .map(Some),
        _ => None,
    }
    .ok_or_else(|| RequestFailure {
        request_id: Some(request.request_id.clone()),
        error: BrowserError::InvalidRequest,
        version,
    })?;
    Ok(ValidRequest {
        request_id: request.request_id,
        timeout: Duration::from_millis(u64::from(request.timeout_ms)),
        fill_context,
    })
}

fn canonical_origin(value: &str) -> bool {
    value.len() <= 2048
        && url::Url::parse(value)
            .is_ok_and(|url| url.scheme() == "https" && url.origin().ascii_serialization() == value)
}

fn parse_hex_id(value: &str) -> Option<[u8; 16]> {
    if !valid_request_id(value) {
        return None;
    }
    let mut result = [0; 16];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(result)
}

fn parse_document_id(value: &str) -> Option<[u8; 16]> {
    if value.len() != 36
        || !value.is_ascii()
        || [8, 13, 18, 23]
            .into_iter()
            .any(|index| value.as_bytes()[index] != b'-')
    {
        return None;
    }
    parse_hex_id(&value.replace('-', ""))
}

fn valid_request_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

fn read_frame(reader: &mut impl Read) -> Result<ReadFrame, ()> {
    let mut length_bytes = [0_u8; 4];
    loop {
        match reader.read(&mut length_bytes[..1]) {
            Ok(0) => return Ok(ReadFrame::EndOfStream),
            Ok(1) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Ok(_) | Err(_) => return Err(()),
        }
    }
    reader.read_exact(&mut length_bytes[1..]).map_err(|_| ())?;
    let length = usize::try_from(u32::from_ne_bytes(length_bytes)).map_err(|_| ())?;
    if length == 0 || length > MAX_BROWSER_MESSAGE_BYTES {
        return Err(());
    }
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    reader.read_exact(&mut bytes).map_err(|_| ())?;
    Ok(ReadFrame::Message(bytes))
}

fn write_response(
    writer: &mut impl Write,
    response: &BrowserResponse<'_>,
) -> Result<(), ServeError> {
    let mut buffer = JsonBuffer(Zeroizing::new(Vec::with_capacity(
        MAX_BROWSER_RESPONSE_BYTES,
    )));
    serde_json::to_writer(&mut buffer, response).map_err(|_| ServeError::Output)?;
    let bytes = buffer.0;
    let length = u32::try_from(bytes.len()).map_err(|_| ServeError::Output)?;
    writer
        .write_all(&length.to_ne_bytes())
        .and_then(|()| writer.write_all(&bytes))
        .and_then(|()| writer.flush())
        .map_err(|_| ServeError::Output)
}

struct JsonBuffer(Zeroizing<Vec<u8>>);

impl Write for JsonBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_BROWSER_RESPONSE_BYTES - self.0.len() {
            return Err(io::Error::other("browser response exceeds bound"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, io::Cursor};

    use serde_json::Value;

    use super::*;

    const REQUEST_ID: &str = "00112233445566778899aabbccddeeff";

    fn frame(json: &str) -> Vec<u8> {
        let mut bytes = u32::try_from(json.len())
            .expect("fixture length")
            .to_ne_bytes()
            .to_vec();
        bytes.extend_from_slice(json.as_bytes());
        bytes
    }

    fn response(bytes: &[u8]) -> Value {
        let length = u32::from_ne_bytes(bytes[..4].try_into().expect("length"));
        assert_eq!(usize::try_from(length).expect("length"), bytes.len() - 4);
        serde_json::from_slice(&bytes[4..]).expect("response json")
    }

    fn request(overrides: &str) -> String {
        format!(
            r#"{{"protocolVersion":1,"requestId":"{REQUEST_ID}","operation":"status","context":{{"kind":"none"}},"timeoutMs":1000{overrides}}}"#
        )
    }

    fn fill_request() -> Value {
        serde_json::json!({ "protocolVersion": 2, "requestId": REQUEST_ID,
            "operation": "fillSingle", "timeoutMs": 2000,
            "context": { "kind": "exactHttps", "tabId": 7, "frameId": 0,
                "documentId": "12345678-1234-4234-8234-123456789abc",
                "topLevelOrigin": "https://example.com", "frameOrigin": "https://example.com" } })
    }

    #[test]
    fn fill_has_a_closed_credential_response_and_bounded_json_escaping() {
        let username = "\0".repeat(1024);
        let password = "\0".repeat(16384);
        let mut output = Vec::new();
        serve_with_fill(
            &mut Cursor::new(frame(&fill_request().to_string())),
            &mut output,
            |_| panic!("fill must not dispatch status"),
            |context, timeout| {
                assert_eq!(timeout, Duration::from_secs(2));
                assert_eq!(context.top_origin(), "https://example.com");
                Ok(Some(BrowserCredential::new(&username, &password).unwrap()))
            },
        )
        .unwrap();
        assert!(output.len() < MAX_BROWSER_RESPONSE_BYTES);
        assert_eq!(
            response(&output),
            serde_json::json!({ "protocolVersion": 2,
            "requestId": REQUEST_ID, "status": "credential", "username": username, "password": password })
        );
    }

    #[test]
    fn fill_rejects_bad_contexts_and_extended_fields_before_agent_access() {
        let replacements = [
            ("topLevelOrigin", serde_json::json!("https://other.test")),
            ("frameOrigin", serde_json::json!("https://sub.example.com")),
            ("frameId", serde_json::json!(1)),
            ("tabId", serde_json::json!(2_147_483_648_u32)),
            (
                "documentId",
                serde_json::json!("00000000-0000-0000-0000-000000000000"),
            ),
            (
                "documentId",
                serde_json::json!("1234567-81234-4234-8234-123456789abc"),
            ),
            ("unexpected", serde_json::json!(true)),
        ];
        for (key, value) in replacements {
            let mut request = fill_request();
            request["context"][key] = value;
            let mut output = Vec::new();
            serve_with_fill(
                &mut Cursor::new(frame(&request.to_string())),
                &mut output,
                |_| panic!("invalid context reached status"),
                |_, _| panic!("invalid context reached agent"),
            )
            .unwrap();
            assert_eq!(response(&output)["error"], "invalidRequest");
        }
        for origin in [
            "http://example.com",
            "https://EXAMPLE.COM",
            "https://example.com:443",
            "https://example.com/",
            "https://example.com@evil.test",
            "blob:https://example.com/id",
        ] {
            let mut request = fill_request();
            request["context"]["topLevelOrigin"] = serde_json::json!(origin);
            request["context"]["frameOrigin"] = serde_json::json!(origin);
            let mut output = Vec::new();
            serve_with_fill(
                &mut Cursor::new(frame(&request.to_string())),
                &mut output,
                |_| panic!("invalid origin reached status"),
                |_, _| panic!("invalid origin reached agent"),
            )
            .unwrap();
            assert_eq!(response(&output)["error"], "invalidRequest");
        }
    }

    #[test]
    fn fill_returns_no_selection_or_detail_free_failures() {
        let failures = [
            (BridgeFailure::Locked, "locked"),
            (BridgeFailure::Cancelled, "cancelled"),
            (BridgeFailure::TimedOut, "timedOut"),
            (BridgeFailure::Incompatible, "incompatible"),
            (BridgeFailure::AgentUnavailable, "agentUnavailable"),
            (BridgeFailure::OperationFailed, "operationFailed"),
        ];
        for (failure, expected) in failures {
            let mut output = Vec::new();
            serve_with_fill(
                &mut Cursor::new(frame(&fill_request().to_string())),
                &mut output,
                |_| panic!("unexpected status"),
                |_, _| Err(failure),
            )
            .unwrap();
            assert_eq!(
                response(&output),
                serde_json::json!({ "protocolVersion": 2, "requestId": REQUEST_ID,
                "status": "error", "error": expected })
            );
        }
        let mut output = Vec::new();
        serve_with_fill(
            &mut Cursor::new(frame(&fill_request().to_string())),
            &mut output,
            |_| panic!("unexpected status"),
            |_, _| Ok(None),
        )
        .unwrap();
        assert_eq!(
            response(&output),
            serde_json::json!({ "protocolVersion": 2, "requestId": REQUEST_ID, "status": "noCredential" })
        );
    }

    #[test]
    fn host_matches_the_shared_canonical_origin_corpus() {
        let corpus = include_str!("../../../tests/fixtures/browser-origin-policy.tsv");
        for line in corpus.lines().filter(|line| !line.starts_with('#')) {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(
                canonical_origin(fields[1]),
                fields[2] != "-",
                "{}",
                fields[0]
            );
        }
    }

    #[test]
    fn relays_one_strict_status_request() {
        let mut input = Cursor::new(frame(&request("")));
        let mut output = Vec::new();
        serve_once(&mut input, &mut output, |timeout| {
            assert_eq!(timeout, Duration::from_secs(1));
            Ok(AgentStatus::Locked)
        })
        .expect("serve request");

        assert_eq!(
            response(&output),
            serde_json::json!({
                "status": "ok",
                "protocolVersion": 1,
                "requestId": REQUEST_ID,
                "agentStatus": "locked"
            })
        );
    }

    #[test]
    fn relays_every_agent_status_with_its_wire_name() {
        let cases = [
            (AgentStatus::Starting, "starting"),
            (AgentStatus::NoVault, "noVault"),
            (AgentStatus::Locked, "locked"),
            (AgentStatus::Unlocking, "unlocking"),
            (AgentStatus::Unlocked, "unlocked"),
            (AgentStatus::Updating, "updating"),
            (AgentStatus::ShuttingDown, "shuttingDown"),
        ];
        for (status, expected) in cases {
            let mut input = Cursor::new(frame(&request("")));
            let mut output = Vec::new();
            serve_once(&mut input, &mut output, |_| Ok(status)).expect("relay status");
            assert_eq!(
                response(&output),
                serde_json::json!({
                    "status": "ok",
                    "protocolVersion": 1,
                    "requestId": REQUEST_ID,
                    "agentStatus": expected
                })
            );
        }
    }

    #[test]
    fn rejects_unknown_fields_before_relay() {
        let called = Cell::new(false);
        let mut input = Cursor::new(frame(&request(",\"unexpected\":true")));
        let mut output = Vec::new();
        serve_once(&mut input, &mut output, |_| {
            called.set(true);
            Ok(AgentStatus::Unlocked)
        })
        .expect("write rejection");

        assert!(!called.get());
        assert_eq!(response(&output)["error"], "invalidRequest");
    }

    #[test]
    fn rejects_stale_versions_with_a_stable_error() {
        let stale = request("").replacen("\"protocolVersion\":1", "\"protocolVersion\":0", 1);
        let mut input = Cursor::new(frame(&stale));
        let mut output = Vec::new();
        serve_once(&mut input, &mut output, |_| panic!("must not relay")).expect("write rejection");

        let reply = response(&output);
        assert_eq!(reply["error"], "incompatible");
        assert_eq!(reply["requestId"], REQUEST_ID);
    }

    #[test]
    fn rejects_invalid_identifiers_context_and_timeouts() {
        let cases = [
            request("").replace(REQUEST_ID, "00000000000000000000000000000000"),
            request("").replace("\"kind\":\"none\"", "\"kind\":\"website\""),
            request("").replace("\"timeoutMs\":1000", "\"timeoutMs\":99"),
            request("").replace("\"timeoutMs\":1000", "\"timeoutMs\":5001"),
        ];
        for case in cases {
            let mut input = Cursor::new(frame(&case));
            let mut output = Vec::new();
            serve_once(&mut input, &mut output, |_| panic!("must not relay"))
                .expect("write rejection");
            assert_eq!(response(&output)["error"], "invalidRequest");
        }
    }

    #[test]
    fn rejects_oversized_and_truncated_frames_without_relay() {
        let cases = [
            u32::try_from(MAX_BROWSER_MESSAGE_BYTES + 1)
                .expect("bound")
                .to_ne_bytes()
                .to_vec(),
            vec![10, 0, 0, 0, b'{'],
        ];
        for case in cases {
            let mut input = Cursor::new(case);
            let mut output = Vec::new();
            assert_eq!(
                serve_once(&mut input, &mut output, |_| panic!("must not relay")),
                Err(ServeError::Input)
            );
            assert_eq!(response(&output)["error"], "invalidRequest");
            assert!(response(&output)["requestId"].is_null());
        }
    }

    #[test]
    fn maps_agent_failures_without_details() {
        let cases = [
            (BridgeFailure::AgentUnavailable, "agentUnavailable"),
            (BridgeFailure::Incompatible, "incompatible"),
            (BridgeFailure::OperationFailed, "operationFailed"),
        ];
        for (failure, expected) in cases {
            let mut input = Cursor::new(frame(&request("")));
            let mut output = Vec::new();
            serve_once(&mut input, &mut output, |_| Err(failure)).expect("write failure");
            let reply = response(&output);
            assert_eq!(reply["error"], expected);
            assert_eq!(reply.as_object().expect("object").len(), 4);
        }
    }

    #[test]
    fn empty_input_is_a_clean_port_cancellation() {
        let mut input = Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        serve_once(&mut input, &mut output, |_| panic!("must not relay"))
            .expect("clean cancellation");
        assert!(output.is_empty());
    }
}
