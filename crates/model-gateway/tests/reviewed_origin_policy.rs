//! Host-selected provider policy checks. No test contacts a remote service.
use melissa_model_gateway::transport::{
    ApiKey, Delivery, EndpointTrust, HttpTransport, ProviderEndpoint,
};
use melissa_model_gateway::{DecoderLimits, ErrorKind, Message, Protocol, TurnRequest};
use serde_json::json;
use std::sync::{Arc, atomic::AtomicBool};
use std::time::Duration;
use tokio::net::TcpListener;

fn endpoint(protocol: Protocol, url: &str) -> ProviderEndpoint {
    ProviderEndpoint::new(
        "host-configured-provider".into(),
        "host-configured-resource".into(),
        "host-reviewed-authorization".into(),
        protocol,
        EndpointTrust::RemoteHttps,
        url,
        ApiKey::new("DUMMY_LOCAL_POLICY_TEST_CREDENTIAL".into()).unwrap(),
    )
    .unwrap()
}

fn reviewed_gateway() -> ProviderEndpoint {
    endpoint(
        Protocol::OpenAiResponses,
        "https://api.gateway.example/v1/responses",
    )
    .with_single_attempt_origin("https://api.gateway.example")
    .unwrap()
}

fn request() -> TurnRequest {
    TurnRequest {
        model: "host-configured-test-model".into(),
        system_prompt: "host instructions".into(),
        messages: vec![Message::User {
            text: "hello".into(),
        }],
        tools: vec![],
        max_output_tokens: 128,
        output_schema: None,
    }
}

#[test]
fn standard_openai_and_anthropic_bodies_remain_byte_identical() {
    for protocol in [Protocol::OpenAiResponses, Protocol::AnthropicMessages] {
        let endpoint = endpoint(protocol, "https://other-provider.example/v1/generation");
        let turn = request();
        let expected = match protocol {
            Protocol::OpenAiResponses => melissa_model_gateway::openai::build_request(&turn),
            Protocol::AnthropicMessages => melissa_model_gateway::anthropic::build_request(&turn),
        }
        .unwrap();
        let actual = HttpTransport::body(&endpoint, &turn).unwrap();
        assert_eq!(
            serde_json::to_vec(&actual).unwrap(),
            serde_json::to_vec(&expected).unwrap()
        );
        assert!(actual.get("gateway").is_none());
    }
}

#[test]
fn reviewed_gateway_origin_without_host_opt_in_keeps_standard_body() {
    let endpoint = endpoint(
        Protocol::OpenAiResponses,
        "https://api.gateway.example/v1/responses",
    );
    let mut turn = request();
    turn.messages = vec![Message::User {
        text: r#"{ "gateway": { "retry": { "max_total_attempts": 8 } } }"#.into(),
    }];
    let actual = HttpTransport::body(&endpoint, &turn).unwrap();
    assert_eq!(
        actual,
        melissa_model_gateway::openai::build_request(&turn).unwrap()
    );
    assert!(actual.get("gateway").is_none());
}

#[test]
fn explicit_host_policy_adds_exact_single_dispatch_extension_only() {
    let turn = request();
    let mut actual = HttpTransport::body(&reviewed_gateway(), &turn).unwrap();
    assert_eq!(
        actual.as_object_mut().unwrap().remove("gateway"),
        Some(json!({
            "retry": {
                "max_attempts_per_route": 1,
                "max_total_attempts": 1,
                "backoff": {"type": "none"}
            },
            "routing": {"allow_fallbacks": false}
        }))
    );
    assert_eq!(
        actual,
        melissa_model_gateway::openai::build_request(&turn).unwrap()
    );
}

#[test]
fn reviewed_paths_and_normal_https_port_accept_policy() {
    for url in [
        "https://api.gateway.example/v1/responses",
        "https://api.gateway.example:443/v1/responses",
        "https://api.gateway.example/api/v1/responses",
        "https://API.GATEWAY.EXAMPLE:443/api/v1/responses",
    ] {
        let endpoint = endpoint(Protocol::OpenAiResponses, url)
            .with_single_attempt_origin("https://api.gateway.example")
            .unwrap();
        endpoint.validate().unwrap();
        HttpTransport::body(&endpoint, &request()).unwrap();
    }
}

#[test]
fn policy_rejects_unreviewed_origin_port_path_and_protocol() {
    for url in [
        "https://other-provider.example/v1/responses",
        "https://api.gateway.example.attacker.example/v1/responses",
        "https://sub.api.gateway.example/v1/responses",
        "https://api.gateway.example./v1/responses",
        "https://api.gateway.example:8443/v1/responses",
        "https://api.gateway.example/v1/chat/completions",
        "https://api.gateway.example/v1/messages",
        "https://api.gateway.example/v1/responses/",
        "https://api.gateway.example/v1/responses/extra",
        "https://api.gateway.example/v1/%72esponses",
    ] {
        let error = endpoint(Protocol::OpenAiResponses, url)
            .with_single_attempt_origin("https://api.gateway.example")
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Invalid, "{url}");
    }
    assert_eq!(
        endpoint(
            Protocol::AnthropicMessages,
            "https://api.gateway.example/v1/responses"
        )
        .with_single_attempt_origin("https://api.gateway.example")
        .unwrap_err()
        .kind,
        ErrorKind::Invalid
    );
    let fixture = ProviderEndpoint::new(
        "fixture".into(),
        "resource".into(),
        "auth".into(),
        Protocol::OpenAiResponses,
        EndpointTrust::LoopbackFixture,
        "http://127.0.0.1:12345/v1/responses",
        ApiKey::new("LOCAL_FIXTURE".into()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        fixture
            .with_single_attempt_origin("https://api.gateway.example")
            .unwrap_err()
            .kind,
        ErrorKind::Invalid
    );
}

#[test]
fn body_and_validation_recheck_all_public_endpoint_mutations() {
    for url in [
        "https://other-provider.example/v1/responses",
        "https://api.gateway.example:8443/v1/responses",
        "https://api.gateway.example/v1/messages",
        "https://api.gateway.example/v1/responses?forward=https://other-provider.example",
        "https://api.gateway.example/v1/responses#fragment",
        "https://user:secret@api.gateway.example/v1/responses",
        "http://api.gateway.example/v1/responses",
    ] {
        let mut endpoint = reviewed_gateway();
        endpoint.url = url::Url::parse(url).unwrap();
        assert_eq!(endpoint.validate().unwrap_err().kind, ErrorKind::Invalid);
        assert_eq!(
            HttpTransport::body(&endpoint, &request()).unwrap_err().kind,
            ErrorKind::Invalid
        );
    }
    let mut endpoint = reviewed_gateway();
    endpoint.protocol = Protocol::AnthropicMessages;
    assert_eq!(
        HttpTransport::body(&endpoint, &request()).unwrap_err().kind,
        ErrorKind::Invalid
    );
    let mut endpoint = reviewed_gateway();
    endpoint.trust = EndpointTrust::LoopbackFixture;
    assert_eq!(
        HttpTransport::body(&endpoint, &request()).unwrap_err().kind,
        ErrorKind::Invalid
    );
}

#[tokio::test]
async fn mutated_policy_endpoint_is_not_dispatched_even_with_remote_access_enabled() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut endpoint = reviewed_gateway();
    endpoint.url = url::Url::parse(&format!("http://{address}/v1/responses")).unwrap();
    endpoint.trust = EndpointTrust::LoopbackFixture;
    let outcome = HttpTransport::new(false)
        .unwrap()
        .generate(
            &endpoint,
            &request(),
            1000,
            DecoderLimits::default(),
            Arc::new(AtomicBool::new(false)),
        )
        .await;
    assert_eq!(outcome.delivery, Delivery::NotSent);
    assert_eq!(outcome.error.unwrap().kind, ErrorKind::Invalid);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

#[test]
fn cloning_and_reapplying_policy_preserves_enforcement_and_credential_redaction() {
    let endpoint = reviewed_gateway()
        .clone()
        .with_single_attempt_origin("https://api.gateway.example")
        .unwrap();
    assert!(
        HttpTransport::body(&endpoint, &request())
            .unwrap()
            .get("gateway")
            .is_some()
    );
    let debug = format!("{endpoint:?}");
    assert!(!debug.contains("DUMMY_LOCAL_POLICY_TEST_CREDENTIAL"));
    assert!(debug.contains("[redacted]"));
    let mut clone = endpoint.clone();
    clone.url = url::Url::parse("https://other-provider.example/v1/responses").unwrap();
    assert!(clone.validate().is_err());
    assert!(endpoint.validate().is_ok());
}

#[test]
fn reviewed_origin_is_exact_and_cannot_contain_credentials_or_paths() {
    for origin in [
        "http://api.gateway.example",
        "https://name:password@api.gateway.example",
        "https://api.gateway.example/path",
        "https://api.gateway.example/?x=y",
        "https://api.gateway.example/#fragment",
        "https://attacker.example",
    ] {
        assert!(
            endpoint(
                Protocol::OpenAiResponses,
                "https://api.gateway.example/v1/responses"
            )
            .with_single_attempt_origin(origin)
            .is_err()
        );
    }
    let mut changed = reviewed_gateway();
    changed.url = "https://attacker.example/v1/responses".parse().unwrap();
    assert!(HttpTransport::body(&changed, &request()).is_err());
}

#[test]
fn loopback_fixture_accepts_ipv4_and_ipv6_loopback_only() {
    let fixture = |url: &str| {
        ProviderEndpoint::new(
            "fixture".into(),
            "resource".into(),
            "auth".into(),
            Protocol::OpenAiResponses,
            EndpointTrust::LoopbackFixture,
            url,
            ApiKey::new("LOCAL_FIXTURE".into()).unwrap(),
        )
    };
    for url in [
        "http://127.0.0.1:8080/v1/responses",
        "http://[::1]:8080/v1/responses",
    ] {
        assert!(fixture(url).is_ok(), "{url}");
    }
    for url in [
        "http://localhost:8080/v1/responses",
        "http://10.0.0.1:8080/v1/responses",
        "http://[::2]:8080/v1/responses",
        "https://[::1]:8080/v1/responses",
    ] {
        assert_eq!(fixture(url).unwrap_err().kind, ErrorKind::Invalid, "{url}");
    }
}
