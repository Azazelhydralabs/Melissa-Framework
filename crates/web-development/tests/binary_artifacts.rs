mod support;
use melissa_web_development::{plan::App, protocol::*};
use support::*;
#[test]
fn real_large_png_and_trace_stream_exact_binary_artifacts_without_json_truncation() {
    let html = r#"<!doctype html><html><title>Owned noise artifact</title><style>body{margin:0}</style><body><button id="change">New frame</button><output id="generation">0</output><canvas width="1024" height="768"></canvas><script>let generation=0;function paint(){const c=document.querySelector('canvas'),x=c.getContext('2d'),d=x.createImageData(1024,768);let n=214789+generation*731;for(let i=0;i<d.data.length;i++){n=(Math.imul(1664525,n)+1013904223)>>>0;d.data[i]=(i%4===3)?255:n>>>24}x.putImageData(d,0,0);document.querySelector('#generation').textContent=String(generation)}paint();document.querySelector('#change').onclick=()=>setTimeout(()=>{generation++;paint()},180);</script></body></html>"#;
    let mut f = Fixture::new(Service::Browser, None, &[("site/index.html", html)]);
    f.registration.app = Some(App::Static {
        directory: "site".into(),
    });
    let mut s = f.start();
    body(
        &mut s,
        Command::Navigate {
            page: "main".into(),
            path: "/".into(),
        },
    );
    let screenshot = body(
        &mut s,
        Command::Screenshot {
            page: "main".into(),
        },
    );
    assert!(screenshot["binary_artifact"]["bytes"].as_u64().unwrap() > 512 * 1024);
    assert_eq!(screenshot["binary_artifact"]["kind"], "png");
    let png_id = s
        .artifact_refs()
        .iter()
        .find(|id| id.ends_with(":png"))
        .unwrap()
        .clone();
    let png = f.store.get_artifact(&f.ctx.task_id, &png_id).unwrap();
    assert_eq!(
        png.len() as u64,
        screenshot["binary_artifact"]["bytes"].as_u64().unwrap()
    );
    assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
    let receipt: serde_json::Value = serde_json::from_slice(
        &f.store
            .get_artifact(&f.ctx.task_id, &format!("{png_id}:receipt"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["blake3"], melissa_web_development::digest(&png));
    assert_eq!(receipt["descriptor"], screenshot["binary_artifact"]);
    for generation in 1..=8 {
        body(
            &mut s,
            Command::Click {
                page: "main".into(),
                selector: "#change".into(),
            },
        );
        body(
            &mut s,
            Command::Wait {
                page: "main".into(),
                selector: format!("#generation:text-is('{generation}')"),
                state: "visible".into(),
                timeout_ms: 3000,
            },
        );
    }
    let outcome = s.finish().unwrap();
    assert!(outcome.success && outcome.cleanup_confirmed && !outcome.requires_reconciliation);
    let trace_id = outcome
        .artifact_refs
        .iter()
        .find(|id| id.ends_with(":trace"))
        .unwrap();
    let trace = f.store.get_artifact(&f.ctx.task_id, trace_id).unwrap();
    assert!(trace.len() > 512 * 1024);
    assert!(trace.starts_with(b"PK\x03\x04"));
}
