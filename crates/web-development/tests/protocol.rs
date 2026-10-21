use melissa_web_development::protocol::*;
use serde_json::json;
#[test]
fn no_external_target_or_forged_protocol() {
    for path in [
        "https://example.com/",
        "//example.com/",
        "/\\example.com",
        "/\r\nhost:example.com",
    ] {
        assert!(!local_path(path));
    }
    assert!(local_path("/api/items?page=2"));
    for value in [
        json!({"command":"close","extra":true}),
        json!({"command":"query","connection":"x","sql":"select 1","parameters":[],"connection_string":"production"}),
        json!({"command":"evaluate","javascript":"alert(1)"}),
    ] {
        assert!(serde_json::from_value::<Command>(value).is_err());
    }
}
#[test]
fn bounded_http_and_sql_fields() {
    let mut r = ApiRequest {
        session: "a".into(),
        method: Method::Post,
        path: "/api/x".into(),
        headers: Default::default(),
        body: None,
        timeout_ms: 500,
    };
    assert!(r.validate().is_ok());
    r.headers.insert("host".into(), "production".into());
    assert!(r.validate().is_err());
    assert!(
        Command::Query {
            connection: "../db".into(),
            sql: "select 1".into(),
            parameters: vec![]
        }
        .validate()
        .is_err()
    );
    assert!(
        Command::Viewport {
            page: "main".into(),
            width: 0,
            height: 800
        }
        .validate()
        .is_err()
    );
}
