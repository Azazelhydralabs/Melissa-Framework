"""Owned local development application. No production data or dependencies."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json,os,sqlite3,time
from pathlib import Path
class App(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def send(self,status,body,headers=None):
        data=json.dumps(body).encode();self.send_response(status)
        self.send_header('Content-Type','application/json')
        for k,v in (headers or {}).items():self.send_header(k,v)
        self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def tenant(self):
        cookie=self.headers.get('Cookie','')
        for name in ['alice','bob']:
            if 'session='+name in cookie:return name
        auth=self.headers.get('Authorization','')
        return auth[7:] if auth in ['Bearer alice','Bearer bob'] else None
    def db(self):
        c=sqlite3.connect(os.environ['MELISSA_FIXTURE_DB'],timeout=3);c.execute('PRAGMA foreign_keys=ON');return c
    def do_GET(self):
        if self.path=='/':
            data=Path('index.html').read_bytes();self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data);return
        if self.path=='/redirect':self.send_response(302);self.send_header('Location','https://example.invalid/denied');self.end_headers();return
        user=self.tenant()
        if not user:return self.send(401,{'error':'unauthorized'})
        if self.path=='/api/notes':
            with self.db() as c:items=[{'id':r[0],'text':r[1]} for r in c.execute('SELECT id,text FROM notes WHERE tenant=? ORDER BY id',(user,))]
            return self.send(200,{'items':items})
        self.send(404,{'error':'not_found'})
    def do_POST(self):
        try:body=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
        except Exception:return self.send(400,{'error':'invalid_json'})
        if self.path=='/login':
            user=body.get('user')
            if user not in ['alice','bob']:return self.send(403,{'error':'invalid_user'})
            return self.send(200,{'user':user},{'Set-Cookie':'session='+user+'; HttpOnly; SameSite=Strict; Path=/'})
        user=self.tenant()
        if not user:return self.send(401,{'error':'unauthorized'})
        if self.path not in ['/api/notes','/api/notes?lose_response=1']:return self.send(404,{'error':'not_found'})
        text=body.get('text');key=self.headers.get('Idempotency-Key')
        if not isinstance(text,str) or not text.strip() or len(text)>200 or not key:return self.send(422,{'error':'invalid_input'})
        with self.db() as c:
            c.execute('BEGIN IMMEDIATE')
            row=c.execute('SELECT note_id FROM requests WHERE tenant=? AND key=?',(user,key)).fetchone()
            if row:
                item=c.execute('SELECT id,text FROM notes WHERE id=?',(row[0],)).fetchone()
                if item[1]!=text:return self.send(409,{'error':'idempotency_conflict'})
                return self.send(200,{'id':item[0],'text':item[1],'replayed':True})
            result=c.execute('INSERT INTO notes(tenant,text) VALUES(?,?)',(user,text));identity=result.lastrowid
            c.execute('INSERT INTO requests VALUES(?,?,?)',(user,key,identity));c.commit()
        if self.path.endswith('lose_response=1'):time.sleep(.6)
        self.send(201,{'id':identity,'text':text,'replayed':False})
ThreadingHTTPServer(('127.0.0.1',int(os.environ['PORT'])),App).serve_forever()
