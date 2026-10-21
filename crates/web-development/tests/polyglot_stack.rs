mod support;
use melissa_web_development::{
    plan::{App, Database},
    protocol::*,
};
use support::*;
#[test]
fn javascript_and_strict_typescript_real_browser_http_sqlite_final_state() {
    let html = r#"<!doctype html><html lang="en"><title>Owned full stack</title><meta name="viewport" content="width=device-width,initial-scale=1"><body><h1>Owned database notes</h1><label for="note">Note</label><input id="note"><button id="save">Save</button><ul id="items"></ul><script>document.querySelector('#save').onclick=async()=>{let r=await fetch('/api',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({text:document.querySelector('#note').value})});if(!r.ok)throw Error('save failed');let data=await(await fetch('/api')).json();document.querySelector('#items').replaceChildren(...data.map(x=>{let li=document.createElement('li');li.textContent=x.text;return li}))};</script></body></html>"#;
    let js = r#"const http=require('node:http'),fs=require('node:fs');const {DatabaseSync}=require('node:sqlite');const db=new DatabaseSync(process.env.MELISSA_FIXTURE_DB);http.createServer((req,res)=>{if(req.method==='GET'&&req.url==='/'){res.setHeader('content-type','text/html');return res.end(fs.readFileSync('index.html'))}if(req.method==='GET'&&req.url==='/api'){res.setHeader('content-type','application/json');return res.end(JSON.stringify(db.prepare('SELECT id,text FROM notes ORDER BY id').all()))}if(req.method==='POST'&&req.url==='/api'){let raw='';req.on('data',chunk=>raw+=chunk);req.on('end',()=>{let data=JSON.parse(raw);db.prepare('INSERT INTO notes(tenant,text) VALUES(?,?)').run('alice',data.text);res.setHeader('content-type','application/json');res.end(JSON.stringify({saved:true}))});return}res.statusCode=404;res.end('missing')}).listen(Number(process.env.PORT),'127.0.0.1');"#;
    for typescript in [false, true] {
        let ts = format!(
            "declare function require(name:string):any; declare const process:any;\n{}",
            js.replace("(req,res)", "(req:any,res:any)")
                .replace("chunk=>", "(chunk:any)=>")
        );
        let file = if typescript { "app.ts" } else { "app.js" };
        let mut f = Fixture::new(
            Service::Browser,
            Some(Database::Sqlite),
            &[
                (file, if typescript { &ts } else { js }),
                ("index.html", html),
            ],
        );
        f.registration.app = Some(if typescript {
            App::TypeScript { entry: file.into() }
        } else {
            App::JavaScript { entry: file.into() }
        });
        let mut s = f.start();
        assert!(s.last_reply().unwrap().ok, "{:?}", s.last_reply());
        body(
            &mut s,
            Command::Navigate {
                page: "main".into(),
                path: "/".into(),
            },
        );
        body(
            &mut s,
            Command::Fill {
                page: "main".into(),
                selector: "#note".into(),
                value: "UI to real HTTP to SQLite to UI".into(),
            },
        );
        body(
            &mut s,
            Command::Click {
                page: "main".into(),
                selector: "#save".into(),
            },
        );
        body(
            &mut s,
            Command::Wait {
                page: "main".into(),
                selector: "#items li:text-is('UI to real HTTP to SQLite to UI')".into(),
                state: "visible".into(),
                timeout_ms: 5000,
            },
        );
        let observation = body(
            &mut s,
            Command::Inspect {
                page: "main".into(),
            },
        );
        assert!(
            observation["aria"]
                .as_str()
                .unwrap()
                .contains("UI to real HTTP to SQLite to UI")
        );
        assert!(s.finish().unwrap().success);
    }
}
