#![cfg(windows)]
mod support;
use melissa_build_test::{
    RustOperation,
    full::{Language, Operation, ProcedurePlan, Status, TestSuite},
};
fn run(language: Language, files: &[(&str, &str)], expected: Status) {
    let mut f = support::Fixture::new(
        "pub fn answer()->u32{42}\n",
        RustOperation::Build,
        files,
        support::limits(),
    );
    let source = f.repo.snapshot(&support::no()).unwrap();
    let plan = ProcedurePlan::prepare(
        &f.repo,
        &source,
        language,
        Operation::Test {
            suite: TestSuite::EndToEnd,
            repetitions: 2,
        },
        None,
        support::limits(),
        &support::no(),
    )
    .unwrap();
    let permit = support::permit_for(&mut f, plan.request(), plan.snapshot());
    let r = plan
        .execute(
            &f.repo,
            &mut f.broker,
            &f.task.task_id,
            &permit,
            &support::identity(),
            &support::no(),
        )
        .unwrap();
    assert_eq!(
        r.report.status,
        expected,
        "{}",
        serde_json::to_string_pretty(&r.report).unwrap()
    );
    assert!(
        !r.execution.requires_reconciliation
            && !r.report.task_completed
            && !r.report.protected_acceptance
    );
    assert_eq!(
        std::fs::read(f._dir.path().join("repo/dirty.txt")).unwrap(),
        b"preserve this user's work\r\n"
    );
    assert!(!r.report.details.unwrap().discovered.is_empty());
}
#[test]
fn actual_rust_http_e2e_positive_and_behavioral_failure() {
    for answer in [42, 43] {
        let fixture = format!(
            r#"use std::{{io::{{Read,Write}},net::{{TcpListener,TcpStream}},thread}};
#[test]fn public_http_boundary(){{
 let listener=TcpListener::bind("127.0.0.1:0").unwrap();let address=listener.local_addr().unwrap();
 let server=thread::spawn(move||{{let(mut s,_)=listener.accept().unwrap();let mut b=[0;1024];let n=s.read(&mut b).unwrap();assert!(b[..n].starts_with(b"GET /answer HTTP/1.1"));let body=code06_fixture::answer().to_string();write!(s,"HTTP/1.1 200 OK\r\nContent-Length: {{}}\r\nConnection: close\r\n\r\n{{}}",body.len(),body).unwrap();}});
 let mut client=TcpStream::connect(address).unwrap();client.write_all(b"GET /answer HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();let mut response=String::new();client.read_to_string(&mut response).unwrap();server.join().unwrap();assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));assert_eq!(response.split("\r\n\r\n").nth(1).unwrap(),"{answer}");
}}
"#
        );
        run(
            Language::Rust,
            &[("tests/e2e.rs", &fixture)],
            if answer == 42 {
                Status::Passed
            } else {
                Status::Failed
            },
        );
    }
}
#[test]
fn actual_python_http_e2e_positive_and_behavioral_failure() {
    for answer in [42, 43] {
        let fixture = format!(
            "from http.server import BaseHTTPRequestHandler, HTTPServer\nfrom threading import Thread\nfrom urllib.request import urlopen\nfrom calc import answer\n\ndef test_public_http_boundary():\n    class Handler(BaseHTTPRequestHandler):\n        def do_GET(self):\n            assert self.path == '/answer'\n            self.send_response(200)\n            self.end_headers()\n            self.wfile.write(str(answer()).encode())\n    server = HTTPServer(('127.0.0.1', 0), Handler)\n    thread = Thread(target=server.handle_request)\n    thread.start()\n    try:\n        with urlopen(f'http://127.0.0.1:{{server.server_port}}/answer', timeout=5) as response:\n            assert response.status == 200\n            assert response.read() == b'{answer}'\n    finally:\n        thread.join(timeout=5)\n        server.server_close()\n    assert not thread.is_alive()\n"
        );
        run(
            Language::Python,
            &[
                ("src/calc.py", "def answer() -> int:\n    return 42\n"),
                ("e2e/test_http.py", &fixture),
            ],
            if answer == 42 {
                Status::Passed
            } else {
                Status::Failed
            },
        );
    }
}
#[test]
fn actual_javascript_typescript_http_e2e_positive_and_behavioral_failure() {
    for (language, ext) in [(Language::JavaScript, "js"), (Language::TypeScript, "ts")] {
        for answer in [42, 43] {
            let path = format!("e2e/http.test.{ext}");
            let source = format!("src/calc.{ext}");
            let fixture = format!(
                r#"import {{ test }} from 'node:test';
import {{ strict as assert }} from 'node:assert';
import {{ createServer }} from 'node:http';
import {{ once }} from 'node:events';
import {{ answer }} from '../src/calc.js';
test('public HTTP boundary', async()=>{{
 const server=createServer((req,res)=>{{assert.equal(req.url,'/answer');res.end(String(answer()));}});
 server.listen(0,'127.0.0.1');await once(server,'listening');
 const address=server.address();assert.ok(address && typeof address==='object');
 try {{ const response=await fetch(`http://127.0.0.1:${{address.port}}/answer`);assert.equal(response.status,200);assert.equal(await response.text(),'{answer}'); }}
 finally {{ server.close();await once(server,'close'); }}
}});
"#
            );
            run(
                language,
                &[
                    ("package.json", "{\"type\":\"module\"}"),
                    (&source, "export function answer(){return 42;}\n"),
                    (&path, &fixture),
                ],
                if answer == 42 {
                    Status::Passed
                } else {
                    Status::Failed
                },
            );
        }
    }
}
