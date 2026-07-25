use librarian_agent_protocol::{
    AccountFields, AccountView, AgentEvent, AgentState, BeginRequestError, CURRENT_VERSION,
    ClientHello, ClientRole, Connection, ConnectionError, ConnectionLimits, CorrelationId,
    EndpointDescriptor, EventQueue, Frame, FrameError, FrameHeader, MAX_EVENT_QUEUE,
    MAX_PAYLOAD_BYTES, MessageKind, OperationCode, OperationRequest, ProtocolError,
    PublicErrorCode, RequestEnvelope, ResponseEnvelope, RetryCategory, Version, encode_account,
    encode_account_summaries,
};
use zeroize::Zeroizing;

const BUILD_ID: [u8; 32] = [0xB1; 32];
const CLIENT_NONCE: [u8; 32] = [0xC1; 32];
const SERVER_NONCE: [u8; 32] = [0x51; 32];
const CONNECTION_ID: [u8; 16] = [0xA7; 16];

fn hello(role: ClientRole) -> ClientHello {
    ClientHello::new(
        CLIENT_NONCE,
        CURRENT_VERSION,
        CURRENT_VERSION,
        role,
        BUILD_ID,
        vec![1, 4],
    )
    .expect("fixture hello must be valid")
}

fn connection(role: ClientRole) -> Connection {
    Connection::negotiate(
        role,
        BUILD_ID,
        &hello(role),
        &[1, 4, 7],
        SERVER_NONCE,
        CONNECTION_ID,
        AgentState::Locked,
        9,
        ConnectionLimits::default(),
    )
    .expect("fixture handshake must negotiate")
    .0
}

fn request(
    operation: OperationCode,
    unlock_epoch: u64,
    idempotency_key: Option<[u8; 16]>,
) -> RequestEnvelope {
    RequestEnvelope::new(
        operation,
        unlock_epoch,
        5_000,
        idempotency_key,
        Zeroizing::new(vec![0xDA, 0x7A]),
    )
    .expect("fixture request must be valid")
}

fn request_header(request_id: u64, payload_length: usize) -> FrameHeader {
    FrameHeader::new(
        MessageKind::Request,
        CURRENT_VERSION,
        payload_length,
        CONNECTION_ID,
        request_id,
    )
    .expect("fixture header must be valid")
}

#[test]
fn every_frame_kind_has_explicit_header_sentinels() {
    let cases = [
        (MessageKind::ClientHello, Version::new(0, 0), [0; 16], 0),
        (MessageKind::ServerHello, CURRENT_VERSION, CONNECTION_ID, 0),
        (MessageKind::Request, CURRENT_VERSION, CONNECTION_ID, 1),
        (MessageKind::Response, CURRENT_VERSION, CONNECTION_ID, 1),
        (MessageKind::Cancel, CURRENT_VERSION, CONNECTION_ID, 1),
        (MessageKind::Event, CURRENT_VERSION, CONNECTION_ID, 0),
    ];
    for (kind, version, connection_id, request_id) in cases {
        let header = FrameHeader::new(kind, version, 7, connection_id, request_id)
            .expect("per-kind values must be accepted");
        assert_eq!(
            FrameHeader::decode(&header.encode()),
            Ok(header),
            "{kind:?}"
        );
    }

    assert_eq!(
        FrameHeader::new(MessageKind::ClientHello, CURRENT_VERSION, 0, [0; 16], 0,),
        Err(FrameError::InvalidHeader)
    );
    assert_eq!(
        FrameHeader::new(MessageKind::Event, CURRENT_VERSION, 0, CONNECTION_ID, 1,),
        Err(FrameError::InvalidHeader)
    );
}

#[test]
fn frames_are_exact_length_bounded_and_zeroizing() {
    let header = request_header(1, 3);
    let frame =
        Frame::new(header, Zeroizing::new(vec![1, 2, 3])).expect("matching payload must build");
    let encoded = frame.encode().expect("bounded frame must encode");
    let decoded = Frame::decode(&encoded).expect("encoded frame must decode");
    assert_eq!(decoded.header(), &header);
    assert_eq!(decoded.payload(), [1, 2, 3]);

    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(matches!(
        Frame::decode(&trailing),
        Err(FrameError::Malformed)
    ));
    assert_eq!(
        FrameHeader::new(
            MessageKind::Request,
            CURRENT_VERSION,
            MAX_PAYLOAD_BYTES + 1,
            CONNECTION_ID,
            2,
        ),
        Err(FrameError::TooLarge)
    );
}

#[test]
fn handshake_and_discovery_encodings_are_canonical() {
    let client = hello(ClientRole::Desktop);
    assert_eq!(ClientHello::decode(&client.encode()), Ok(client.clone()));

    let (_, server) = Connection::negotiate(
        ClientRole::Desktop,
        BUILD_ID,
        &client,
        &[1, 4],
        SERVER_NONCE,
        CONNECTION_ID,
        AgentState::Unlocked,
        42,
        ConnectionLimits::default(),
    )
    .expect("compatible handshake must negotiate");
    assert_eq!(
        librarian_agent_protocol::ServerHello::decode(&server.encode()),
        Ok(server)
    );

    let descriptor = EndpointDescriptor::new(
        r"\\.\pipe\LOCAL\Librarian.Agent.v1.0123456789abcdef".to_owned(),
        812,
        99,
        "Librarian_1.0.0.0_x64__publisher".to_owned(),
        1,
        1,
        [0x44; 32],
    )
    .expect("descriptor fixture must be valid");
    assert_eq!(
        EndpointDescriptor::decode(&descriptor.encode()),
        Ok(descriptor)
    );
}

#[test]
fn requests_authorize_before_body_decode_and_reject_noncanonical_input() {
    let value = request(OperationCode::Status, 0, None);
    let encoded = value.encode().expect("request must encode");
    assert_eq!(
        RequestEnvelope::peek_operation(&encoded),
        Ok(OperationCode::Status)
    );
    assert_eq!(
        RequestEnvelope::decode(&encoded)
            .expect("canonical request must decode")
            .operation(),
        OperationCode::Status
    );

    let operation_offset = 1;
    assert_eq!(encoded[operation_offset], OperationCode::Status as u8);
    let mut noncanonical = encoded.to_vec();
    noncanonical.splice(operation_offset..=operation_offset, [0x18, 0x01]);
    assert_eq!(
        RequestEnvelope::decode(&noncanonical).map(|_| ()),
        Err(ProtocolError::NonCanonical)
    );
}

#[test]
fn secret_bodies_never_appear_in_debug_output() {
    let request = RequestEnvelope::new(
        OperationCode::UnlockMasterPassword,
        0,
        1_000,
        None,
        Zeroizing::new(b"debug-canary-master-password".to_vec()),
    )
    .expect("request must be valid");
    let debug = format!("{request:?}");
    assert!(!debug.contains("debug-canary"));

    let response = ResponseEnvelope::success(
        CorrelationId::new([1; 16]),
        Zeroizing::new(b"debug-canary-credential".to_vec()),
    )
    .expect("response must be valid");
    let debug = format!("{response:?}");
    assert!(!debug.contains("debug-canary"));
}

#[test]
fn response_errors_are_stable_and_detail_free() {
    let failure = ResponseEnvelope::failure(
        PublicErrorCode::Locked,
        RetryCategory::AfterUnlock,
        CorrelationId::new([0x11; 16]),
    );
    let encoded = failure.encode().expect("failure must encode");
    let decoded = ResponseEnvelope::decode(&encoded).expect("failure must decode");
    assert_eq!(decoded.error(), Some(PublicErrorCode::Locked));
    assert!(decoded.body().is_empty());
}

#[test]
fn every_role_has_a_closed_capability_set() {
    for role in [
        ClientRole::Desktop,
        ClientRole::NativeHost,
        ClientRole::PasskeyProvider,
    ] {
        assert!(
            OperationCode::ALL
                .iter()
                .any(|operation| operation.is_authorized_for(role))
        );
        assert!(
            OperationCode::ALL
                .iter()
                .any(|operation| !operation.is_authorized_for(role))
        );
    }
    assert!(!OperationCode::GetAccount.is_authorized_for(ClientRole::NativeHost));
    assert!(!OperationCode::UnlockMasterPassword.is_authorized_for(ClientRole::PasskeyProvider));
}

#[test]
fn implemented_operation_bodies_are_canonical_bounded_and_strict() {
    let add = OperationRequest::AddAccount {
        fields: AccountFields::new(
            "Example",
            "https://example.test",
            "person@example.test",
            "operation-body-canary",
        )
        .expect("bounded fields"),
    };
    let encoded = add.encode().expect("operation must encode");
    let decoded =
        OperationRequest::decode(OperationCode::AddAccount, &encoded).expect("canonical body");
    assert_eq!(decoded.operation(), OperationCode::AddAccount);
    let fields = decoded.account_fields().expect("account fields");
    assert_eq!(fields.service_name(), "Example");
    assert_eq!(fields.password(), "operation-body-canary");

    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(matches!(
        OperationRequest::decode(OperationCode::AddAccount, &trailing),
        Err(ProtocolError::Malformed)
    ));
    assert_eq!(
        OperationRequest::decode(OperationCode::EnrollWindowsHello, &[0x80]).map(|_| ()),
        Err(ProtocolError::Unsupported)
    );
}

#[test]
fn handshake_claims_never_grant_authority() {
    assert!(matches!(
        Connection::negotiate(
            ClientRole::NativeHost,
            BUILD_ID,
            &hello(ClientRole::Desktop),
            &[1, 4],
            SERVER_NONCE,
            CONNECTION_ID,
            AgentState::Locked,
            1,
            ConnectionLimits::default(),
        ),
        Err(ConnectionError::IdentityClaimMismatch)
    ));

    assert!(matches!(
        Connection::negotiate(
            ClientRole::Desktop,
            [0xFF; 32],
            &hello(ClientRole::Desktop),
            &[1, 4],
            SERVER_NONCE,
            CONNECTION_ID,
            AgentState::Locked,
            1,
            ConnectionLimits::default(),
        ),
        Err(ConnectionError::BuildMismatch)
    ));
}

#[test]
fn incompatible_versions_features_and_restart_connections_fail_closed() {
    let old = ClientHello::new(
        CLIENT_NONCE,
        Version::new(2, 0),
        Version::new(2, 0),
        ClientRole::Desktop,
        BUILD_ID,
        Vec::new(),
    )
    .expect("well-formed incompatible hello");
    assert!(matches!(
        Connection::negotiate(
            ClientRole::Desktop,
            BUILD_ID,
            &old,
            &[],
            SERVER_NONCE,
            CONNECTION_ID,
            AgentState::Locked,
            1,
            ConnectionLimits::default(),
        ),
        Err(ConnectionError::IncompatibleVersion)
    ));

    let unknown_feature = ClientHello::new(
        CLIENT_NONCE,
        CURRENT_VERSION,
        CURRENT_VERSION,
        ClientRole::Desktop,
        BUILD_ID,
        vec![99],
    )
    .expect("well-formed feature offer");
    assert!(matches!(
        Connection::negotiate(
            ClientRole::Desktop,
            BUILD_ID,
            &unknown_feature,
            &[],
            SERVER_NONCE,
            CONNECTION_ID,
            AgentState::Locked,
            1,
            ConnectionLimits::default(),
        ),
        Err(ConnectionError::UnsupportedFeature)
    ));

    let old_connection = connection(ClientRole::Desktop);
    let old_request = request(OperationCode::Status, 0, None);
    let old_header = request_header(1, old_request.encode().expect("request").len());
    let restarted = Connection::negotiate(
        ClientRole::Desktop,
        BUILD_ID,
        &hello(ClientRole::Desktop),
        &[1, 4, 7],
        [0x33; 32],
        [0x34; 16],
        AgentState::Locked,
        10,
        ConnectionLimits::default(),
    )
    .expect("restart connection")
    .0;
    assert_eq!(
        restarted.begin_request(&old_header, &old_request, 10),
        Err(BeginRequestError::Connection(ConnectionError::InvalidFrame))
    );
    assert!(restarted.is_closed());
    assert!(!old_connection.is_closed());
}

#[test]
fn event_queue_is_exactly_bounded_and_events_are_canonical() {
    let mut queue = EventQueue::new();
    for epoch in 1..=MAX_EVENT_QUEUE {
        let event = AgentEvent::new(
            if epoch == MAX_EVENT_QUEUE {
                AgentState::ShuttingDown
            } else {
                AgentState::Locked
            },
            u64::try_from(epoch).expect("small epoch"),
        );
        assert_eq!(AgentEvent::decode(&event.encode()), Ok(event));
        queue.push(event).expect("within queue bound");
    }
    assert!(queue.push(AgentEvent::new(AgentState::Locked, 99)).is_err());
    assert_eq!(queue.len(), MAX_EVENT_QUEUE);
    for _ in 0..MAX_EVENT_QUEUE {
        assert!(queue.pop().is_some());
    }
    assert!(queue.is_empty());
}

#[test]
fn request_ids_cancellation_backpressure_and_epochs_are_deterministic() {
    let connection = connection(ClientRole::Desktop);
    let status = request(OperationCode::Status, 0, None);
    let status_bytes = status.encode().expect("status request must encode");
    let status_header = request_header(1, status_bytes.len());
    let permit = connection
        .begin_request(&status_header, &status, 9)
        .expect("status must be admitted");

    let cancel = FrameHeader::new(MessageKind::Cancel, CURRENT_VERSION, 0, CONNECTION_ID, 1)
        .expect("cancel header must be valid");
    connection.cancel(&cancel).expect("issued ID must cancel");
    connection
        .cancel(&cancel)
        .expect("cancel must be idempotent");
    assert!(connection.is_cancelled(permit));
    connection.finish(permit).expect("request must finish once");
    connection
        .cancel(&cancel)
        .expect("completed cancellation must be ignored");

    let add = request(OperationCode::AddAccount, 8, Some([1; 16]));
    let add_header = request_header(3, add.encode().expect("add must encode").len());
    assert_eq!(
        connection.begin_request(&add_header, &add, 9),
        Err(BeginRequestError::StaleEpoch)
    );

    let replay_header = request_header(2, status_bytes.len());
    assert_eq!(
        connection.begin_request(&replay_header, &status, 9),
        Err(BeginRequestError::Connection(ConnectionError::InvalidFrame))
    );
    assert!(connection.is_closed());
}

#[test]
fn fifth_concurrent_request_is_busy_without_exceeding_the_bound() {
    let connection = connection(ClientRole::Desktop);
    let request = request(OperationCode::Status, 0, None);
    let length = request.encode().expect("request").len();
    let permits: Vec<_> = (1..=4)
        .map(|request_id| {
            connection
                .begin_request(&request_header(request_id, length), &request, 9)
                .expect("within per-connection bound")
        })
        .collect();
    assert_eq!(connection.in_flight_count(), 4);
    assert_eq!(
        connection.begin_request(&request_header(5, length), &request, 9),
        Err(BeginRequestError::Busy)
    );
    assert_eq!(connection.in_flight_count(), 4);
    for permit in permits {
        connection.finish(permit).expect("finish request");
    }
    assert_eq!(connection.in_flight_count(), 0);
    assert!(!connection.is_closed());
}

#[test]
fn unauthorized_and_missing_idempotency_requests_are_terminal_not_privileged() {
    let native_host = connection(ClientRole::NativeHost);
    let list = request(OperationCode::ListAccountSummaries, 9, None);
    let list_header = request_header(1, list.encode().expect("list must encode").len());
    assert_eq!(
        native_host.begin_request(&list_header, &list, 9),
        Err(BeginRequestError::Unauthorized)
    );
    assert!(!native_host.is_closed());

    let desktop = connection(ClientRole::Desktop);
    let add = request(OperationCode::AddAccount, 9, None);
    let add_header = request_header(1, add.encode().expect("add must encode").len());
    assert_eq!(
        desktop.begin_request(&add_header, &add, 9),
        Err(BeginRequestError::MissingIdempotencyKey)
    );
    assert!(!desktop.is_closed());
}

#[test]
fn arbitrary_bytes_never_panic_or_allocate_beyond_protocol_bounds() {
    let mut state = 0xC0DE_CAFE_D15C_A11E_u64;
    for length in 0..=384 {
        let mut bytes = vec![0_u8; length];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state.to_le_bytes()[0];
        }
        let _ = Frame::decode(&bytes);
        let _ = ClientHello::decode(&bytes);
        let _ = librarian_agent_protocol::ServerHello::decode(&bytes);
        let _ = EndpointDescriptor::decode(&bytes);
        let _ = RequestEnvelope::peek_operation(&bytes);
        let _ = RequestEnvelope::decode(&bytes);
        let _ = ResponseEnvelope::decode(&bytes);
        let _ = AgentEvent::decode(&bytes);
        for operation in OperationCode::ALL {
            let _ = OperationRequest::decode(operation, &bytes);
        }
    }
}

#[test]
fn aggregate_and_public_view_response_bounds_fail_without_panicking() {
    let service_name = "s".repeat(256);
    let permitted_origin = "o".repeat(2_048);
    let username = "u".repeat(1_024);
    let views: Vec<_> = (0_u8..100)
        .map(|marker| AccountView {
            id: [marker; 16],
            revision: u64::MAX,
            created_at_ms: u64::MAX,
            modified_at_ms: u64::MAX,
            service_name: &service_name,
            permitted_origin: &permitted_origin,
            username: &username,
            password: "",
        })
        .collect();
    assert!(matches!(
        encode_account_summaries(&views, None),
        Err(ProtocolError::TooLarge)
    ));

    let oversized_password = "p".repeat(16 * 1_024 + 1);
    let oversized = AccountView {
        id: [0xA5; 16],
        revision: 1,
        created_at_ms: 2,
        modified_at_ms: 3,
        service_name: "Example",
        permitted_origin: "https://example.test",
        username: "person@example.test",
        password: &oversized_password,
    };
    assert!(matches!(
        encode_account(&oversized),
        Err(ProtocolError::TooLarge)
    ));

    let oversized_request = OperationRequest::CreateVault {
        master_password: Zeroizing::new("m".repeat(1_025)),
    };
    assert!(matches!(
        oversized_request.encode(),
        Err(ProtocolError::TooLarge)
    ));
}
