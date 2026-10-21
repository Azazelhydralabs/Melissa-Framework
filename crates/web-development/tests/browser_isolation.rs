mod support;
use melissa_web_development::{plan::App, protocol::*};
use support::*;

#[test]
fn actual_browser_states_stale_locators_tabs_origin_and_context_isolation() {
    let html = r#"<!doctype html><html lang="en"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Owned states</title><style>body{font:16px sans-serif;max-width:70rem;margin:1rem}input{max-width:90%}:focus-visible{outline:3px solid #2255aa}</style><body><h1>Stateful form</h1><p id="state" role="status">empty</p><form><label for="value">Value</label><input id="value" required><button id="save">Save</button></form><button id="fail">Show error</button><button id="replace">Replace form</button><button id="external">External</button><ul id="items"></ul><script>
document.querySelector('form').onsubmit=e=>{e.preventDefault();document.querySelector('#state').textContent='loading';let v=document.querySelector('#value').value;setTimeout(()=>{document.querySelector('#items').textContent=v;document.querySelector('#state').textContent='success'},250)};
document.querySelector('#fail').onclick=()=>document.querySelector('#state').textContent='error';
document.querySelector('#replace').onclick=()=>document.querySelector('#value').outerHTML='<input id="replacement" required aria-label="Replacement">';
document.querySelector('#external').onclick=()=>{fetch('https://example.invalid/secret').catch(()=>{});window.open('https://example.invalid/blocked');new WebSocket('ws://example.invalid/socket');console.error('OWNED_ERROR');};
</script></body></html>"#;
    let mut f = Fixture::new(Service::Browser, None, &[("site/index.html", html)]);
    f.registration.app = Some(App::Static {
        directory: "site".into(),
    });
    let mut s = f.start();
    body(
        &mut s,
        Command::Navigate {
            page: "first".into(),
            path: "/".into(),
        },
    );
    assert!(
        body(
            &mut s,
            Command::Inspect {
                page: "first".into()
            }
        )["aria"]
            .as_str()
            .unwrap()
            .contains("empty")
    );
    body(
        &mut s,
        Command::Click {
            page: "first".into(),
            selector: "#save".into(),
        },
    );
    assert!(
        body(
            &mut s,
            Command::Inspect {
                page: "first".into()
            }
        )["dom"]
            .as_str()
            .unwrap()
            .contains(">empty</p>")
    );
    body(
        &mut s,
        Command::Fill {
            page: "first".into(),
            selector: "#value".into(),
            value: "saved by keyboard".into(),
        },
    );
    body(
        &mut s,
        Command::Press {
            page: "first".into(),
            selector: "#value".into(),
            key: "Enter".into(),
        },
    );
    body(
        &mut s,
        Command::Wait {
            page: "first".into(),
            selector: "#state:text-is('loading')".into(),
            state: "visible".into(),
            timeout_ms: 1000,
        },
    );
    body(
        &mut s,
        Command::Wait {
            page: "first".into(),
            selector: "#state:text-is('success')".into(),
            state: "visible".into(),
            timeout_ms: 2000,
        },
    );
    body(
        &mut s,
        Command::Click {
            page: "first".into(),
            selector: "#fail".into(),
        },
    );
    assert!(
        body(
            &mut s,
            Command::Inspect {
                page: "first".into()
            }
        )["aria"]
            .as_str()
            .unwrap()
            .contains("error")
    );
    body(
        &mut s,
        Command::Click {
            page: "first".into(),
            selector: "#replace".into(),
        },
    );
    // A stale selector is rejected by a real browser deadline, then a fresh DOM is usable.
    assert!(
        !s.command(Command::Wait {
            page: "first".into(),
            selector: "#value".into(),
            state: "visible".into(),
            timeout_ms: 50
        })
        .unwrap()
        .ok
    );
    body(
        &mut s,
        Command::Fill {
            page: "first".into(),
            selector: "#replacement".into(),
            value: "fresh".into(),
        },
    );
    body(
        &mut s,
        Command::Navigate {
            page: "second".into(),
            path: "/".into(),
        },
    );
    assert!(
        body(
            &mut s,
            Command::Inspect {
                page: "second".into()
            }
        )["dom"]
            .as_str()
            .unwrap()
            .contains("id=\"value\"")
    );
    assert!(
        body(
            &mut s,
            Command::Inspect {
                page: "first".into()
            }
        )["dom"]
            .as_str()
            .unwrap()
            .contains("id=\"replacement\"")
    );
    let clicked = body(
        &mut s,
        Command::Click {
            page: "first".into(),
            selector: "#external".into(),
        },
    );
    let events = body(
        &mut s,
        Command::Inspect {
            page: "first".into(),
        },
    );
    let evidence = format!("{clicked}{events}");
    assert!(
        evidence.contains("origin_denied") || evidence.contains("requestfailed"),
        "{events}"
    );
    assert!(
        s.command(Command::Navigate {
            page: "first".into(),
            path: "//evil.invalid/".into()
        })
        .is_err()
    );
    for width in [360, 1440] {
        body(
            &mut s,
            Command::Viewport {
                page: "first".into(),
                width,
                height: 800,
            },
        );
        let v = body(
            &mut s,
            Command::Inspect {
                page: "first".into(),
            },
        );
        assert!(v["layout"]["scrollWidth"].as_u64().unwrap() <= u64::from(width));
        assert_eq!(
            body(
                &mut s,
                Command::Screenshot {
                    page: "first".into()
                }
            )["content_type"],
            "image/png"
        );
    }
    assert!(!s.finish().unwrap().requires_reconciliation);
    // New independently admitted task context starts with an untouched document.
    let mut fresh = Fixture::new(Service::Browser, None, &[("site/index.html", html)]);
    fresh.registration.app = Some(App::Static {
        directory: "site".into(),
    });
    let mut next = fresh.start();
    body(
        &mut next,
        Command::Navigate {
            page: "first".into(),
            path: "/".into(),
        },
    );
    assert!(
        body(
            &mut next,
            Command::Inspect {
                page: "first".into()
            }
        )["aria"]
            .as_str()
            .unwrap()
            .contains("empty")
    );
    assert!(next.finish().unwrap().success);
}
