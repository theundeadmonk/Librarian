use librarian_agent_protocol::{
    AccountFields, AccountView, AgentEvent, AgentState, BeginRequestError, CURRENT_VERSION,
    ClientHello, ClientRole, Connection, ConnectionError, ConnectionLimits, CorrelationId,
    EndpointDescriptor, EventQueue, FEATURE_PASSKEY_PROVIDER, FEATURE_WINDOWS_HELLO, Frame,
    FrameError, FrameHeader, MAX_EVENT_QUEUE, MAX_PAYLOAD_BYTES, MIN_NEGOTIATED_PAYLOAD_BYTES,
    MessageKind, ORDINARY_TIMEOUT_MS, OperationCode, OperationRequest,
    PasskeyManagementSummaryView, PasskeyRequestProof, PasskeyTransactionProof, ProtocolError,
    PublicErrorCode, RequestCompletion, RequestEnvelope, ResponseEnvelope, RetryCategory,
    UNLOCK_TIMEOUT_MS, Version, encode_account, encode_account_summaries,
    encode_passkey_management_summaries,
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
        17,
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
        (MessageKind::ClientHello, Version::new(0, 0), 7, [0; 16], 0),
        (
            MessageKind::ServerHello,
            CURRENT_VERSION,
            7,
            CONNECTION_ID,
            0,
        ),
        (MessageKind::Request, CURRENT_VERSION, 7, CONNECTION_ID, 1),
        (MessageKind::Response, CURRENT_VERSION, 7, CONNECTION_ID, 1),
        (MessageKind::Cancel, CURRENT_VERSION, 0, CONNECTION_ID, 1),
        (MessageKind::Event, CURRENT_VERSION, 7, CONNECTION_ID, 0),
    ];
    for (kind, version, payload_length, connection_id, request_id) in cases {
        let header = FrameHeader::new(kind, version, payload_length, connection_id, request_id)
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
    assert_eq!(
        FrameHeader::new(MessageKind::Cancel, CURRENT_VERSION, 1, CONNECTION_ID, 1,),
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
        17,
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
fn idempotency_keys_are_rejected_for_non_mutating_operations() {
    assert_eq!(
        RequestEnvelope::new(
            OperationCode::GetAccount,
            9,
            5_000,
            Some([0xA5; 16]),
            Zeroizing::new(vec![0x81, 0x50]),
        )
        .map(|_| ()),
        Err(ProtocolError::InvariantViolation)
    );
}

#[test]
fn response_errors_are_stable_and_detail_free() {
    let failure = ResponseEnvelope::failure(
        PublicErrorCode::Locked,
        RetryCategory::AfterUnlock,
        CorrelationId::new([0x11; 16]),
    )
    .expect("nonzero correlation must build");
    let encoded = failure.encode().expect("failure must encode");
    let decoded = ResponseEnvelope::decode(&encoded).expect("failure must decode");
    assert_eq!(decoded.error(), Some(PublicErrorCode::Locked));
    assert!(decoded.body().is_empty());
    assert!(matches!(
        ResponseEnvelope::failure(
            PublicErrorCode::Locked,
            RetryCategory::AfterUnlock,
            CorrelationId::new([0; 16]),
        ),
        Err(ProtocolError::InvariantViolation)
    ));
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
    for operation in [
        OperationRequest::EnrollWindowsHello {
            parent_window: 0x1234,
        },
        OperationRequest::UnlockWindowsHello {
            parent_window: 0x5678,
        },
    ] {
        let encoded = operation.encode().expect("Hello body");
        let decoded = OperationRequest::decode(operation.operation(), &encoded)
            .expect("canonical Hello body");
        assert_eq!(decoded.operation(), operation.operation());
        assert_eq!(decoded.parent_window(), operation.parent_window());
    }
    let removal = OperationRequest::RemoveWindowsHello;
    let encoded = removal.encode().expect("removal body");
    assert_eq!(
        OperationRequest::decode(OperationCode::RemoveWindowsHello, &encoded)
            .expect("canonical removal")
            .operation(),
        OperationCode::RemoveWindowsHello
    );
    assert!(matches!(
        OperationRequest::EnrollWindowsHello { parent_window: 0 }.encode(),
        Err(ProtocolError::InvariantViolation)
    ));
    assert_eq!(
        OperationRequest::decode(OperationCode::EnrollWindowsHello, &[0x80]).map(|_| ()),
        Err(ProtocolError::Malformed)
    );

    for limit in [0, 101] {
        assert!(matches!(
            OperationRequest::ListAccountSummaries { offset: 0, limit }.encode(),
            Err(ProtocolError::InvariantViolation)
        ));
    }
}

#[test]
fn passkey_transaction_bodies_bind_a_nonzero_agent_challenge() {
    let proof = PasskeyTransactionProof::new(
        [0x11; 16],
        1,
        &[0x22; 64],
        &[0x33; 128],
        [0x34; 16],
        &[0x44; 64],
    )
    .expect("bounded proof");
    let encoded = OperationRequest::MakePasskey { proof }
        .encode()
        .expect("make-passkey body");
    let decoded = OperationRequest::decode(OperationCode::MakePasskey, &encoded)
        .expect("canonical passkey body");
    let decoded_proof = decoded.passkey_proof().expect("passkey proof");
    assert_eq!(decoded_proof.transaction_id(), &[0x11; 16]);
    assert_eq!(decoded_proof.agent_challenge(), &[0x34; 16]);

    let assertion = OperationRequest::GetPasskeyAssertion {
        proof: PasskeyTransactionProof::new(
            [0x51; 16],
            1,
            &[0x52; 64],
            &[0x53; 128],
            [0x54; 16],
            &[0x55; 64],
        )
        .expect("bounded proof"),
        credential_id: [0x55; 32],
    };
    let encoded = assertion.encode().expect("assertion body");
    let decoded = OperationRequest::decode(OperationCode::GetPasskeyAssertion, &encoded)
        .expect("canonical assertion body");
    assert_eq!(decoded.passkey_credential_id(), Some([0x55; 32]));

    let rollback = OperationRequest::RollbackPasskeyCreation {
        proof: PasskeyTransactionProof::new(
            [0x61; 16],
            1,
            &[0x62; 64],
            &[0x63; 128],
            [0x64; 16],
            &[0x65; 64],
        )
        .expect("bounded rollback proof"),
        credential_id: [0x66; 32],
    };
    let encoded = rollback.encode().expect("rollback body");
    let decoded = OperationRequest::decode(OperationCode::RollbackPasskeyCreation, &encoded)
        .expect("canonical rollback body");
    assert_eq!(decoded.passkey_credential_id(), Some([0x66; 32]));
    assert_eq!(
        decoded
            .passkey_proof()
            .expect("rollback proof")
            .transaction_id(),
        &[0x61; 16]
    );
    assert!(OperationCode::RollbackPasskeyCreation.is_authorized_for(ClientRole::PasskeyProvider));
    assert!(!OperationCode::RollbackPasskeyCreation.is_authorized_for(ClientRole::Desktop));
    assert!(OperationCode::RollbackPasskeyCreation.requires_idempotency_key());
    assert!(OperationCode::RollbackPasskeyCreation.requires_unlocked_epoch());
    assert_eq!(
        OperationCode::RollbackPasskeyCreation.required_feature(),
        Some(FEATURE_PASSKEY_PROVIDER)
    );

    assert!(matches!(
        PasskeyTransactionProof::new([0; 16], 1, &[1], &[2], [4; 16], &[3]),
        Err(ProtocolError::InvariantViolation)
    ));
    assert!(matches!(
        PasskeyTransactionProof::new([1; 16], 1, &[1], &[2], [0; 16], &[3]),
        Err(ProtocolError::InvariantViolation)
    ));
}

#[test]
fn passkey_lookup_proof_is_canonical_and_does_not_require_uv() {
    let lookup = OperationRequest::ListPasskeysForAssertion {
        proof: PasskeyRequestProof::new([0x71; 16], 1, &[0x72; 64], &[0x73; 128])
            .expect("bounded request proof"),
    };
    let encoded = lookup.encode().expect("lookup body");
    let decoded = OperationRequest::decode(OperationCode::ListPasskeysForAssertion, &encoded)
        .expect("canonical lookup");
    assert_eq!(
        decoded
            .passkey_request_proof()
            .expect("request proof")
            .transaction_id(),
        &[0x71; 16]
    );
    assert!(!OperationCode::ListPasskeysForAssertion.requires_idempotency_key());
    assert!(OperationCode::ListPasskeysForAssertion.requires_unlocked_epoch());
}

#[test]
fn desktop_passkey_management_is_feature_gated_and_canonical() {
    let request = OperationRequest::ListPasskeys;
    let encoded = request.encode().expect("management list body");
    assert_eq!(encoded.as_slice(), &[0x80]);
    assert!(matches!(
        OperationRequest::decode(OperationCode::ListPasskeys, &encoded),
        Ok(OperationRequest::ListPasskeys)
    ));
    assert!(OperationCode::ListPasskeys.is_authorized_for(ClientRole::Desktop));
    assert!(!OperationCode::ListPasskeys.is_authorized_for(ClientRole::PasskeyProvider));
    assert!(OperationCode::DeletePasskey.is_authorized_for(ClientRole::Desktop));
    assert!(!OperationCode::DeletePasskey.is_authorized_for(ClientRole::PasskeyProvider));
    assert_eq!(
        OperationCode::ListPasskeys.required_feature(),
        Some(FEATURE_PASSKEY_PROVIDER)
    );

    let passkeys = [PasskeyManagementSummaryView {
        credential_id: [0x81; 32],
        rp_id: "example.com",
        user_name: "person@example.com",
        user_display_name: "Disposable Person",
    }];
    let encoded =
        encode_passkey_management_summaries(&passkeys).expect("bounded public management summary");
    assert!(!encoded.is_empty());
    let invalid = [PasskeyManagementSummaryView {
        credential_id: [0; 32],
        rp_id: "example.com",
        user_name: "person@example.com",
        user_display_name: "Disposable Person",
    }];
    assert!(matches!(
        encode_passkey_management_summaries(&invalid),
        Err(ProtocolError::InvariantViolation)
    ));
}

#[test]
fn handshake_claims_never_grant_authority() {
    assert!(matches!(
        Connection::negotiate(
            ClientRole::NativeHost,
            17,
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
            17,
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
fn incompatible_versions_fail_closed() {
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
            17,
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
}

#[test]
fn unknown_features_fail_closed() {
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
            17,
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
}

#[test]
fn legacy_protocol_versions_cannot_use_windows_hello() {
    let version_one = ClientHello::new(
        CLIENT_NONCE,
        Version::new(1, 0),
        Version::new(1, 0),
        ClientRole::Desktop,
        BUILD_ID,
        Vec::new(),
    )
    .expect("well-formed version 1.0 hello");
    let old_protocol = Connection::negotiate(
        ClientRole::Desktop,
        17,
        BUILD_ID,
        &version_one,
        &[FEATURE_WINDOWS_HELLO],
        SERVER_NONCE,
        CONNECTION_ID,
        AgentState::Locked,
        1,
        ConnectionLimits::default(),
    )
    .expect("version 1.0 remains compatible")
    .0;
    assert_eq!(old_protocol.version(), Version::new(1, 0));
    let hello_unlock = request(OperationCode::UnlockWindowsHello, 1, None);
    let hello_header = FrameHeader::new(
        MessageKind::Request,
        Version::new(1, 0),
        hello_unlock.encode().expect("request").len(),
        CONNECTION_ID,
        1,
    )
    .expect("version 1.0 header");
    assert_eq!(
        old_protocol.begin_request(&hello_header, &hello_unlock, 1),
        Err(BeginRequestError::Unauthorized)
    );
}

#[test]
fn legacy_protocol_versions_cannot_grant_passkey_operations() {
    let legacy = ClientHello::new(
        CLIENT_NONCE,
        Version::new(1, 1),
        Version::new(1, 1),
        ClientRole::PasskeyProvider,
        BUILD_ID,
        vec![FEATURE_PASSKEY_PROVIDER],
    )
    .expect("well-formed legacy hello");
    assert!(matches!(
        Connection::negotiate(
            ClientRole::PasskeyProvider,
            17,
            BUILD_ID,
            &legacy,
            &[FEATURE_PASSKEY_PROVIDER],
            SERVER_NONCE,
            CONNECTION_ID,
            AgentState::Unlocked,
            9,
            ConnectionLimits::default(),
        ),
        Err(ConnectionError::UnsupportedFeature)
    ));
}

#[test]
fn legacy_protocol_versions_can_require_other_supported_features() {
    let legacy_feature = 4;
    let version_one = ClientHello::new(
        CLIENT_NONCE,
        Version::new(1, 0),
        Version::new(1, 0),
        ClientRole::Desktop,
        BUILD_ID,
        vec![legacy_feature],
    )
    .expect("well-formed version 1.0 hello");
    let (connection, _response) = Connection::negotiate(
        ClientRole::Desktop,
        17,
        BUILD_ID,
        &version_one,
        &[legacy_feature],
        SERVER_NONCE,
        CONNECTION_ID,
        AgentState::Locked,
        1,
        ConnectionLimits::default(),
    )
    .expect("supported legacy feature must remain compatible");
    assert_eq!(connection.version(), Version::new(1, 0));
}

#[test]
fn restarted_connections_reject_old_frames() {
    let old_connection = connection(ClientRole::Desktop);
    let old_request = request(OperationCode::Status, 0, None);
    let old_header = request_header(1, old_request.encode().expect("request").len());
    let restarted = Connection::negotiate(
        ClientRole::Desktop,
        17,
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
    assert_eq!(connection.finish(permit), Ok(RequestCompletion::Cancelled));
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
fn first_request_id_must_be_one() {
    let connection = connection(ClientRole::Desktop);
    let status = request(OperationCode::Status, 0, None);
    let header = request_header(2, status.encode().expect("status request").len());
    assert_eq!(
        connection.begin_request(&header, &status, 9),
        Err(BeginRequestError::Connection(ConnectionError::InvalidFrame))
    );
    assert!(connection.is_closed());
}

#[test]
fn negotiated_payload_limit_bounds_every_response_envelope() {
    assert_eq!(
        ConnectionLimits::new(
            u32::try_from(MIN_NEGOTIATED_PAYLOAD_BYTES - 1).expect("small limit"),
            1,
        ),
        Err(ConnectionError::InvalidLimit)
    );
    let limits = ConnectionLimits::new(
        u32::try_from(MIN_NEGOTIATED_PAYLOAD_BYTES).expect("minimum payload"),
        1,
    )
    .expect("minimum usable limits");
    let connection = Connection::negotiate(
        ClientRole::Desktop,
        17,
        BUILD_ID,
        &hello(ClientRole::Desktop),
        &[1, 4, 7],
        SERVER_NONCE,
        CONNECTION_ID,
        AgentState::Locked,
        9,
        limits,
    )
    .expect("minimum payload negotiation")
    .0;
    let correlation = CorrelationId::new([0xA9; 16]);
    let failure = ResponseEnvelope::failure(
        PublicErrorCode::OperationFailed,
        RetryCategory::Never,
        correlation,
    )
    .expect("detail-free failure");
    assert_eq!(
        failure.encoded_len(),
        failure.encode().expect("failure encoding").len()
    );
    assert_eq!(failure.encoded_len(), MIN_NEGOTIATED_PAYLOAD_BYTES);
    assert!(connection.response_fits(&failure));

    for body_length in [0, 23, 24, 255, 256] {
        let response =
            ResponseEnvelope::success(correlation, Zeroizing::new(vec![0xA5; body_length]))
                .expect("bounded response");
        assert_eq!(
            response.encoded_len(),
            response.encode().expect("response encoding").len()
        );
        if body_length != 0 {
            assert!(!connection.response_fits(&response));
        }
    }
}

#[test]
fn password_kdf_and_lock_share_the_transition_deadline_cap() {
    let connection = connection(ClientRole::Desktop);
    for (request_id, operation, idempotency_key) in [
        (1, OperationCode::CreateVault, Some([0x31; 16])),
        (2, OperationCode::UnlockMasterPassword, None),
        (3, OperationCode::Lock, None),
    ] {
        let request = RequestEnvelope::new(
            operation,
            0,
            u32::MAX,
            idempotency_key,
            Zeroizing::new(vec![0x80]),
        )
        .expect("bounded request");
        let header = request_header(
            request_id,
            request.encode().expect("request must encode").len(),
        );
        let permit = connection
            .begin_request(&header, &request, 9)
            .expect("state-transition request must be admitted");
        assert_eq!(permit.effective_timeout_ms(), UNLOCK_TIMEOUT_MS);
        assert_eq!(connection.finish(permit), Ok(RequestCompletion::Active));
    }
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
        Err(BeginRequestError::Busy {
            effective_timeout_ms: ORDINARY_TIMEOUT_MS,
        })
    );
    assert_eq!(connection.in_flight_count(), 4);
    for permit in permits {
        assert_eq!(connection.finish(permit), Ok(RequestCompletion::Active));
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
