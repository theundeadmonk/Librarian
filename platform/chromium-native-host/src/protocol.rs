use std::{
    io::{self, Read, Write},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const BROWSER_PROTOCOL_VERSION: u16 = 1;
pub const MAX_BROWSER_MESSAGE_BYTES: usize = 16 * 1024;
const MIN_TIMEOUT_MS: u32 = 100;
const MAX_TIMEOUT_MS: u32 = 5_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeFailure {
    AgentUnavailable,
    Incompatible,
    OperationFailed,
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

#[derive(Debug, Deserialize)]
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
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrowserContext {
    kind: BrowserContextKind,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum BrowserContextKind {
    None,
}

#[derive(Debug, Serialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum BrowserResponse<'a> {
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
}

struct RequestFailure {
    request_id: Option<String>,
    error: BrowserError,
}

pub fn serve_once(
    reader: &mut impl Read,
    writer: &mut impl Write,
    status: impl FnOnce(Duration) -> Result<AgentStatus, BridgeFailure>,
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
                    protocol_version: BROWSER_PROTOCOL_VERSION,
                    request_id: failure.request_id.as_deref(),
                    error: failure.error,
                },
            )?;
            return Ok(());
        }
    };
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
                BridgeFailure::OperationFailed => BrowserError::OperationFailed,
            },
        },
    };
    write_response(writer, &response)
}

fn validate_request(bytes: &[u8]) -> Result<ValidRequest, RequestFailure> {
    let request: BrowserRequest = serde_json::from_slice(bytes).map_err(|_| RequestFailure {
        request_id: None,
        error: BrowserError::InvalidRequest,
    })?;
    let request_id = valid_request_id(&request.request_id).then(|| request.request_id.clone());
    if request.protocol_version != BROWSER_PROTOCOL_VERSION {
        return Err(RequestFailure {
            request_id,
            error: BrowserError::Incompatible,
        });
    }
    if request_id.is_none()
        || request.operation != BrowserOperation::Status
        || request.context.kind != BrowserContextKind::None
        || !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&request.timeout_ms)
    {
        return Err(RequestFailure {
            request_id,
            error: BrowserError::InvalidRequest,
        });
    }
    Ok(ValidRequest {
        request_id: request.request_id,
        timeout: Duration::from_millis(u64::from(request.timeout_ms)),
    })
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
    let bytes = serde_json::to_vec(response).map_err(|_| ServeError::Output)?;
    let length = u32::try_from(bytes.len()).map_err(|_| ServeError::Output)?;
    writer
        .write_all(&length.to_ne_bytes())
        .and_then(|()| writer.write_all(&bytes))
        .and_then(|()| writer.flush())
        .map_err(|_| ServeError::Output)
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
