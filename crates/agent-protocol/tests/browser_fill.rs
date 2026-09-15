use librarian_agent_protocol::{
    AgentState, BROWSER_FILL_VERSION, BeginRequestError, BrowserContext, BrowserCredential,
    BrowserSelection, ClientHello, ClientRole, Connection, ConnectionError, ConnectionLimits,
    FEATURE_BROWSER_FILL, FrameHeader, MessageKind, OperationCode, OperationRequest, ProtocolError,
    RequestEnvelope, Version,
};

fn context() -> BrowserContext {
    BrowserContext::new(
        [1; 16],
        7,
        0,
        [2; 16],
        "https://example.com",
        "https://example.com",
    )
    .unwrap()
}

#[test]
fn browser_bodies_are_closed_bounded_and_canonical() {
    for operation in [
        OperationRequest::ExactOriginMatches { context: context() },
        OperationRequest::GetSelectedCredential {
            context: context(),
            selection: BrowserSelection::new([3; 16], [4; 16], 1).unwrap(),
        },
    ] {
        let bytes = operation.encode().unwrap();
        let decoded = OperationRequest::decode(operation.operation(), &bytes).unwrap();
        assert_eq!(decoded.encode().unwrap(), bytes);
        for length in 0..bytes.len() {
            assert!(OperationRequest::decode(operation.operation(), &bytes[..length]).is_err());
        }
        let mut extended = bytes.to_vec();
        extended.push(0);
        assert!(OperationRequest::decode(operation.operation(), &extended).is_err());
        let mut noncanonical = vec![0x98, bytes[0] - 0x80];
        noncanonical.extend_from_slice(&bytes[1..]);
        assert!(matches!(
            OperationRequest::decode(operation.operation(), &noncanonical),
            Err(ProtocolError::NonCanonical)
        ));
    }
}

#[test]
fn browser_context_rejects_missing_identity_embedded_frames_and_unequal_origins() {
    for (request, tab, frame, document, top, child) in [
        ([0; 16], 7, 0, [2; 16], "https://a.test", "https://a.test"),
        ([1; 16], 7, 0, [0; 16], "https://a.test", "https://a.test"),
        (
            [1; 16],
            u32::MAX,
            0,
            [2; 16],
            "https://a.test",
            "https://a.test",
        ),
        ([1; 16], 7, 1, [2; 16], "https://a.test", "https://a.test"),
        ([1; 16], 7, 0, [2; 16], "https://a.test", "https://b.test"),
        ([1; 16], 7, 0, [2; 16], "", ""),
    ] {
        assert!(BrowserContext::new(request, tab, frame, document, top, child).is_err());
    }
    let huge = "a".repeat(2049);
    assert!(BrowserContext::new([1; 16], 7, 0, [2; 16], &huge, &huge).is_err());
}

#[test]
fn browser_context_comparison_binds_every_field() {
    let original = context();
    assert!(original.matches(&context()));
    for changed in [
        BrowserContext::new(
            [3; 16],
            7,
            0,
            [2; 16],
            "https://example.com",
            "https://example.com",
        ),
        BrowserContext::new(
            [1; 16],
            8,
            0,
            [2; 16],
            "https://example.com",
            "https://example.com",
        ),
        BrowserContext::new(
            [1; 16],
            7,
            0,
            [3; 16],
            "https://example.com",
            "https://example.com",
        ),
        BrowserContext::new(
            [1; 16],
            7,
            0,
            [2; 16],
            "https://other.test",
            "https://other.test",
        ),
    ] {
        assert!(!original.matches(&changed.unwrap()));
    }
}

#[test]
fn browser_selection_and_credentials_reject_extended_or_invalid_results() {
    let selection = BrowserSelection::new([3; 16], [4; 16], 1).unwrap();
    let bytes = BrowserSelection::encode_optional(Some(&selection));
    assert!(
        BrowserSelection::decode_optional(&bytes)
            .unwrap()
            .unwrap()
            .matches(&selection)
    );
    assert!(
        BrowserSelection::decode_optional(&[0x80])
            .unwrap()
            .is_none()
    );
    assert!(BrowserSelection::new([0; 16], [4; 16], 1).is_err());
    assert!(BrowserSelection::new([3; 16], [0; 16], 1).is_err());
    assert!(BrowserSelection::new([3; 16], [4; 16], 0).is_err());
    let credential =
        BrowserCredential::new("u".repeat(1024).as_str(), "p".repeat(16384).as_str()).unwrap();
    let encoded = credential.encode();
    let decoded = BrowserCredential::decode(&encoded).unwrap();
    assert_eq!(decoded.username(), credential.username());
    assert_eq!(decoded.password(), credential.password());
    assert!(BrowserCredential::new(&"u".repeat(1025), "p").is_err());
    assert!(BrowserCredential::new("u", &"é".repeat(8193)).is_err());
    let mut extended = encoded.to_vec();
    extended.push(0);
    assert!(BrowserCredential::decode(&extended).is_err());
    assert!(BrowserCredential::decode(&[0x81, 0x60]).is_err());
    assert!(BrowserSelection::decode_optional(&extended).is_err());
}

#[test]
fn browser_feature_cannot_be_negotiated_on_legacy_versions() {
    for version in [Version::new(1, 0), Version::new(1, 1), Version::new(1, 2)] {
        let hello = ClientHello::new(
            [1; 32],
            version,
            version,
            ClientRole::NativeHost,
            [2; 32],
            vec![FEATURE_BROWSER_FILL],
        )
        .unwrap();
        assert!(matches!(
            Connection::negotiate(
                ClientRole::NativeHost,
                17,
                [2; 32],
                &hello,
                &[FEATURE_BROWSER_FILL],
                [3; 32],
                [4; 16],
                AgentState::Unlocked,
                5,
                ConnectionLimits::default()
            ),
            Err(ConnectionError::UnsupportedFeature)
        ));
    }
}

#[test]
fn browser_operations_require_native_role_and_explicit_feature_grant() {
    for role in [
        ClientRole::Desktop,
        ClientRole::NativeHost,
        ClientRole::PasskeyProvider,
    ] {
        for feature in [false, true] {
            let features = if feature {
                vec![FEATURE_BROWSER_FILL]
            } else {
                vec![]
            };
            let hello = ClientHello::new(
                [1; 32],
                BROWSER_FILL_VERSION,
                BROWSER_FILL_VERSION,
                role,
                [2; 32],
                features,
            )
            .unwrap();
            let (connection, _) = Connection::negotiate(
                role,
                17,
                [2; 32],
                &hello,
                &[FEATURE_BROWSER_FILL],
                [3; 32],
                [4; 16],
                AgentState::Unlocked,
                5,
                ConnectionLimits::default(),
            )
            .unwrap();
            for (index, code) in [
                OperationCode::ExactOriginMatches,
                OperationCode::GetSelectedCredential,
            ]
            .into_iter()
            .enumerate()
            {
                let request = RequestEnvelope::new(code, 5, 5000, None, vec![0xff].into()).unwrap();
                let header = FrameHeader::new(
                    MessageKind::Request,
                    BROWSER_FILL_VERSION,
                    request.encode().unwrap().len(),
                    [4; 16],
                    index as u64 + 1,
                )
                .unwrap();
                let result = connection.begin_request(&header, &request, 5);
                if role == ClientRole::NativeHost && feature {
                    connection.finish(result.unwrap()).unwrap();
                } else {
                    assert!(matches!(result, Err(BeginRequestError::Unauthorized)));
                }
            }
        }
    }
}
