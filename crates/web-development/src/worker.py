"""Isolated development adapter; all process/fixture registration comes from Rust."""
import concurrent.futures
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import selectors
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT=Path.cwd(); PRIVATE=ROOT/'.melissa-code10'; STATE=PRIVATE/'state'
P=json.loads((PRIVATE/'program.json').read_text()); R=P['registration']
ORIGIN='http://127.0.0.1:37641'
processes=[]; connections={}; clients={}; migration_receipts={}; browser=None; pg=None; started=False
read_transactions=set();cursors={};cursor_seq=0;pending_api={};current_seq=0;partial_migrations=set()
exec(compile((PRIVATE/'sql_runtime.py').read_bytes(),str(PRIVATE/'sql_runtime.py'),'exec'))

def run(argv,**kw):
    return subprocess.run(argv,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45,**kw)
def unchanged():
    return all((ROOT/p).is_file() and (ROOT/p).read_bytes()==bytes.fromhex(b) for p,b in P['sources'].items())
def rows(cursor):
    data=cursor.fetchmany(1001) if cursor.description else []
    return {'columns':[c[0] for c in (cursor.description or [])], 'rows':[list(r) for r in data[:1000]], 'truncated':len(data)>1000,'rowcount':cursor.rowcount}
def connection(name,reader=False):
    key=('reader:'+name) if reader and R['database']=='postgres' else name
    if key not in connections:
        if len(connections)>=16:raise ValueError('connection capacity')
        if R['database']=='sqlite':
            c=sqlite3.connect(STATE/'fixture.sqlite',isolation_level=None,timeout=0.5,check_same_thread=False)
            c.execute('PRAGMA foreign_keys=ON');c.execute('PRAGMA busy_timeout=500')
        else:
            import psycopg
            c=psycopg.connect(host=str(STATE/'socket'),port=37642,dbname='postgres',user='melissa_reader' if reader else 'melissa_fixture',autocommit=True,connect_timeout=5)
            c.execute("SET statement_timeout='3s'");c.execute("SET lock_timeout='1500ms'")
        connections[key]=c
    return connections[key]
def schema(c):
    if R['database']=='sqlite':
        values=c.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall()
    else:
        values={
            'columns':c.execute("SELECT table_name,column_name,data_type,is_nullable,column_default FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name,ordinal_position").fetchall(),
            'constraints':c.execute("SELECT c.relname,x.conname,pg_get_constraintdef(x.oid) FROM pg_constraint x JOIN pg_class c ON c.oid=x.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY c.relname,x.conname").fetchall(),
            'indexes':c.execute("SELECT tablename,indexname,indexdef FROM pg_indexes WHERE schemaname='public' ORDER BY tablename,indexname").fetchall(),
            'views':c.execute("SELECT viewname,definition FROM pg_views WHERE schemaname='public' ORDER BY viewname").fetchall(),
            'sequences':c.execute("SELECT sequencename,data_type,start_value,min_value,max_value,increment_by,cycle,cache_size FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename").fetchall(),
            'routines':c.execute("SELECT p.oid::regprocedure::text,pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prokind IN ('f','p') ORDER BY 1").fetchall(),
            'triggers':c.execute("SELECT c.relname,t.tgname,pg_get_triggerdef(t.oid) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal ORDER BY 1,2").fetchall(),
        }
    encoded=json.dumps(values,ensure_ascii=False,separators=(',',':'),default=str).encode()
    return 'sha256:'+hashlib.sha256(encoded).hexdigest()
def statements(text):
    if R['database']=='postgres':
        return pg_statements(text)
    else:
        parts=[];pending=''
        for ch in text:
            pending+=ch
            if ch==';' and sqlite3.complete_statement(pending):parts.append(pending);pending=''
        if pending.strip():parts.append(pending)
    return [p.strip().rstrip(';') for p in parts if p.strip()]
def migration(op):
    m=R['migrations'][op['name']]; c=connection('_migration')
    before=schema(c)
    baseline=m['baseline']
    expected=baseline['digest'] if baseline['kind']=='schema' else migration_receipts.get(baseline['name'])
    if before!=expected:raise ValueError('migration baseline mismatch; no statements dispatched')
    sql=(ROOT/m['source_path']).read_text()
    sequence=statements(sql)
    forbidden={'BEGIN','COMMIT','END','ROLLBACK','SAVEPOINT','RELEASE','VACUUM','ATTACH','DETACH','PRAGMA','ABORT','START','PREPARE','COPY','SET'}
    if not sequence or any(sql_keyword(s) in forbidden for s in sequence):raise ValueError('migration control statement denied')
    applied=0
    try:
        if m['transactional']:c.execute('BEGIN IMMEDIATE' if R['database']=='sqlite' else 'BEGIN')
        for s in sequence:c.execute(s);applied+=1
        if m['transactional']:c.execute('COMMIT')
        after=schema(c);migration_receipts[op['name']]=after
        if baseline['kind']=='after':partial_migrations.discard(baseline['name'])
        return {'unresolved_migrations':sorted(partial_migrations),'applied':applied,'transactional':m['transactional'],'before':before,'after':after,'requires_reconciliation':False}
    except Exception as e:
        rollback=False
        if m['transactional']:
            c.execute('ROLLBACK');rollback=True
        after=schema(c);migration_receipts[op['name']]=after
        if not rollback and applied>0:partial_migrations.add(op['name'])
        return {'unresolved_migrations':sorted(partial_migrations),'failed':True,'applied_before_error':applied,'rolled_back':rollback,'before':before,'after':after,'error':str(e),'requires_reconciliation':not rollback and applied>0}
def query(op, cursor_mode=False):
    c=connection(op['connection'],reader=True);sql=op['sql'];args=op['parameters']
    if any(v['connection']==op['connection'] for v in cursors.values()):raise ValueError('connection owns an unfinished cursor')
    if op.get('command')=='query_plan':sql=('EXPLAIN QUERY PLAN ' if R['database']=='sqlite' else 'EXPLAIN (FORMAT JSON) ')+sql
    if R['database']=='sqlite':
        allowed={sqlite3.SQLITE_SELECT,sqlite3.SQLITE_READ,sqlite3.SQLITE_RECURSIVE}
        def auth(code,a,b,db,origin):
            if code in allowed:return sqlite3.SQLITE_OK
            if code==sqlite3.SQLITE_FUNCTION and str(b).lower() not in ('load_extension','writefile','readfile'):return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY
        c.set_authorizer(auth)
        try:
            cur=c.execute(sql,args)
            return open_cursor(op,c,cur,False) if cursor_mode else rows(cur)
        finally:c.set_authorizer(None)
    # Read-only role prevents writes even inside an already active transaction.
    # SET LOCAL is restored in a finally block; no caller connection strings.
    if c.info.transaction_status.value==0:
        c.execute('BEGIN READ ONLY');own=True
    else:
        own=False
        if not c.execute('SHOW transaction_read_only').fetchone()[0]=='on':
            raise ValueError('query on writable PG transaction requires a separate read-only connection')
    try:
        cur=c.execute(sql,args,prepare=True)
        if cursor_mode:return open_cursor(op,c,cur,own)
        return rows(cur)
    finally:
        if own and not cursor_mode:c.execute('ROLLBACK')
def open_cursor(op,c,cur,own):
    global cursor_seq
    if len(cursors)>=8:raise ValueError('cursor capacity')
    cursor_seq+=1;name='cursor'+str(cursor_seq)
    cursors[name]={'connection':op['connection'],'database':c,'cursor':cur,'own':own,'pending':[],'offset':0}
    return fetch_page(name,op['limit'])
def fetch_page(name,limit):
    item=cursors[name];cur=item['cursor'];data=item['pending']+cur.fetchmany(limit+1-len(item['pending']))
    more=len(data)>limit;item['pending']=data[limit:];page={'cursor':name,'columns':[x[0] for x in cur.description],'rows':[list(r) for r in data[:limit]],'offset':item['offset'],'has_more':more,'snapshot_bound':True}
    item['offset']+=len(page['rows'])
    if not more:
        cur.close()
        if item['own']:item['database'].execute('ROLLBACK')
        del cursors[name]
    return page

def reconcile_api(sequence):
    pending=pending_api.get(sequence)
    if not pending:raise ValueError('no owned pending API operation')
    proofs=[]
    for req in pending:
        key=req['headers'].get('idempotency-key','')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',key):raise ValueError('exact idempotency identity required')
        rules=[r for r in P.get('api_reconciliation_rules',[]) if r['method']==req['method'] and r['path']==req['path']]
        if len(rules)!=1:raise ValueError('no unique host reconciliation rule')
        status=api(dict(req,method='get',path=rules[0]['status_path'].replace('{key}',key),body=None,timeout_ms=3000))
        proof=json.loads(bytes.fromhex(status.get('body_hex','')).decode())
        expected={'method':req['method'],'path':req['path'],'idempotency_key':key,'request_body':req['body']}
        if status['status']!=200 or proof.get('operation')!=expected or proof.get('state') not in ('committed','not_applied'):
            raise ValueError('foreign, incomplete or unresolved API effect proof')
        proofs.append({'request':req,'status':status,'state':proof['state']})
    del pending_api[sequence]
    return {'sequence':sequence,'reconciled':True,'proofs':proofs,'automatic_retry':False,'task_completed':False}
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None
def api(req):
    name=req['session']
    if name not in clients:
        if len(clients)>=16:raise ValueError('API session capacity')
        clients[name]=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    data=None if req['body'] is None else json.dumps(req['body']).encode()
    headers=dict(req['headers'])
    if data is not None:headers.setdefault('content-type','application/json')
    request=urllib.request.Request(ORIGIN+req['path'],data=data,headers=headers,method=req['method'].upper())
    try:
        try:response=clients[name].open(request,timeout=req['timeout_ms']/1000)
        except urllib.error.HTTPError as e:response=e
        with response:
            data=response.read(1024*1024+1)
            if len(data)>1024*1024:raise ValueError('API response truncated')
            return {'status':response.code,'headers':dict(response.headers),'body_hex':data.hex(),'effect':'response_observed','automatic_retry':False}
    except Exception as e:
        return {'status':None,'error':str(e),'effect':'outcome_unknown' if req['method']!='get' else 'read_failed','automatic_retry':False}
def browser_call(op):
    browser.stdin.write(json.dumps(op)+'\n');browser.stdin.flush()
    ready=selectors.DefaultSelector();ready.register(browser.stdout,selectors.EVENT_READ)
    try:
        if not ready.select(35):raise TimeoutError('browser command timeout')
        text=browser.stdout.readline(P['response_limit']+1)
    finally:ready.close()
    if not text or len(text)>P['response_limit']:raise ValueError('browser output incomplete or oversized')
    reply=json.loads(text)
    if not reply['ok']:raise ValueError(reply['error'])
    return reply['body']
def start():
    global browser,pg,started
    if started:raise ValueError('session already started')
    STATE.mkdir()
    sdk={'python':sys.version.split()[0],'sqlite':sqlite3.sqlite_version}
    if R['database']=='postgres':
        pg_bin=next(Path('/usr/lib/postgresql').glob('*/bin'))
        data=STATE/'pg'; socket=STATE/'socket';socket.mkdir()
        run([str(pg_bin/'initdb'),'-D',str(data),'-U','melissa_fixture','--auth-local=trust','--auth-host=reject','--no-locale','--encoding=UTF8'])
        pg=subprocess.Popen([str(pg_bin/'postgres'),'-D',str(data),'-k',str(socket),'-p','37642','-c','listen_addresses=','-c','shared_buffers=16MB','-c','max_connections=16'],stdout=open(STATE/'pg.log','wb'),stderr=subprocess.STDOUT)
        processes.append(pg)
        for _ in range(200):
            if (socket/'.s.PGSQL.37642').exists():break
            if pg.poll() is not None:raise ValueError('PostgreSQL startup failed')
            time.sleep(.025)
        sdk['postgres']=run([str(pg_bin/'postgres'),'--version']).stdout.decode().strip()
    if R['database']:
        c=connection('_seed')
        if R['seed_path']:
            for s in statements((ROOT/R['seed_path']).read_text()):c.execute(s)
        if R['database']=='postgres':
            c.execute('CREATE ROLE melissa_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT')
            c.execute('GRANT USAGE ON SCHEMA public TO melissa_reader')
            c.execute('GRANT SELECT ON ALL TABLES IN SCHEMA public TO melissa_reader')
            c.execute('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO melissa_reader')
    app=R['app']
    if app:
        language=app['language']
        if language=='python':argv=['/opt/melissa-python/bin/python','-I',app['entry']]
        elif language=='java_script':argv=['/opt/node/bin/node',app['entry']]
        elif language=='type_script':
            run(['/opt/node/bin/node','/opt/melissa-tools/node_modules/typescript/bin/tsc',app['entry'],'--target','es2022','--module','commonjs','--outDir',str(PRIVATE/'build'),'--skipLibCheck'])
            argv=['/opt/node/bin/node',str(PRIVATE/'build'/Path(app['entry']).with_suffix('.js').name)]
        else:argv=['/opt/melissa-python/bin/python','-I','-m','http.server','37641','--bind','127.0.0.1','--directory',app['directory']]
        env={k:v for k,v in os.environ.items() if k in ['PATH','HOME','LANG','PLAYWRIGHT_BROWSERS_PATH']}
        env.update(PORT='37641',MELISSA_FIXTURE_DB=str(STATE/'fixture.sqlite'),MELISSA_PG_SOCKET=str(STATE/'socket'))
        server=subprocess.Popen(argv,stdout=open(STATE/'app.log','wb'),stderr=subprocess.STDOUT,env=env)
        processes.append(server)
        for _ in range(200):
            if server.poll() is not None:raise ValueError('application exited before readiness')
            try:
                import socket
                with socket.create_connection(('127.0.0.1',37641),timeout=.1):break
            except OSError:time.sleep(.025)
        else:raise TimeoutError('application readiness deadline')
    if 'browser' in R['services']:
        browser=subprocess.Popen(['/opt/node/bin/node',str(PRIVATE/'browser.cjs')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=open(STATE/'browser.log','wb'),text=True,bufsize=1)
        processes.append(browser);sdk.update(browser_call({'command':'start'}))
    started=True
    return {'sdk':sdk,'source_unchanged':unchanged(),'local_origin':ORIGIN,'database':R['database'],'developer_output_trusted':False}
def command(op):
    if op['command']=='start':return start()
    if not started:raise ValueError('session not started')
    cmd=op['command']
    if cmd=='close':
        data=browser_call(op) if browser else {}
        data.update(source_unchanged=unchanged(),open_transactions=[name for name,c in connections.items() if (c.in_transaction if R['database']=='sqlite' else c.info.transaction_status.value!=0)])
        return data
    if cmd=='reconcile_api':return reconcile_api(op['sequence'])
    if cmd=='api':
        result=api(op['request'])
        if result.get('effect')=='outcome_unknown':pending_api.setdefault(current_seq,[]).append(op['request'])
        return result
    if cmd=='api_concurrent':
        # Independent cookie jars avoid concurrent mutation of one session.
        if len({x['session'] for x in op['requests']})!=len(op['requests']):raise ValueError('concurrent API requests require distinct client sessions')
        missing={x['session'] for x in op['requests']}-set(clients)
        if len(clients)+len(missing)>16:raise ValueError('API session capacity; no batch requests sent')
        for name in missing:clients[name]=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:responses=list(pool.map(api,op['requests']))
        for req,result in zip(op['requests'],responses):
            if result.get('effect')=='outcome_unknown':pending_api.setdefault(current_seq,[]).append(req)
        return {'responses':responses}
    if cmd in ('query','query_plan'):return query(op)
    if cmd=='cursor':return query(op,cursor_mode=True)
    if cmd=='fetch':return fetch_page(op['cursor'],op['limit'])
    if cmd=='sql_parallel':
        result=parallel_sql(op['scripts'],connection,command,R['database'])
        result['database_effect_unknown']=any(r.get('rolled_back') is False for r in result['results'])
        return result
    if cmd=='profile':
        c=connection(op['connection']);result={'schema_digest':schema(c)}
        if R['database']=='sqlite':result.update(integrity=rows(c.execute('PRAGMA integrity_check')),foreign_keys=rows(c.execute('PRAGMA foreign_key_check')))
        return result
    if cmd=='migration':return migration(op)
    if cmd=='execute':
        if op['connection'] in read_transactions:raise ValueError('write on read-only transaction denied')
        statement=R['statements'][op['statement']]
        return rows(connection(op['connection']).execute((ROOT/statement['source_path']).read_text(),op['parameters']))
    if cmd=='begin':
        mode=op['mode'];c=connection(op['connection'],reader=mode=='read_only')
        if mode=='read_only':read_transactions.add(op['connection'])
        sql=('BEGIN IMMEDIATE' if mode=='immediate' else 'BEGIN') if R['database']=='sqlite' else ('BEGIN READ ONLY' if mode=='read_only' else 'BEGIN ISOLATION LEVEL SERIALIZABLE')
        c.execute(sql);return {'transaction':'active','mode':mode}
    if cmd in ['commit','rollback']:
        c=connection(op['connection'],reader=op['connection'] in read_transactions);c.execute(cmd.upper());read_transactions.discard(op['connection']);return {'transaction':'settled'}
    return browser_call(op)
def uncertain_sql_error(op,e):
    if op['command'] not in ('execute','commit','migration','sql_parallel'):return False
    code=getattr(e,'sqlstate',None)
    if R['database']=='postgres':
        return bool(code and (code.startswith('08') or code in ('57P01','57P02','57P03'))) or any(c.closed or c.info.transaction_status.value==4 for c in connections.values())
    code=getattr(e,'sqlite_errorcode',0) or 0
    return code&255 in (7,10,11,13,14,26)
def send_binary(seq,meta):
    if not re.fullmatch(r'a[0-9]{1,9}',meta['id']) or meta['kind'] not in ('png','trace') or not 0<meta['bytes']<=P['artifact_limit']:raise ValueError('binary artifact envelope denied')
    path=PRIVATE/'artifacts'/meta['id']
    raw=path.read_bytes()
    if len(raw)!=meta['bytes'] or 'sha256:'+hashlib.sha256(raw).hexdigest()!=meta['sha256']:raise ValueError('binary artifact changed before transfer')
    for offset in range(0,len(raw),24576):
        part=raw[offset:offset+24576]
        print(json.dumps({'schema_version':'melissa.web-binary/v1','seq':seq,'artifact_id':meta['id'],'offset':offset,'total_bytes':len(raw),'data_hex':part.hex()}),flush=True)
        ack=json.loads(sys.stdin.readline(2048))
        if ack!={'artifact_ack':seq,'offset':offset}:raise ValueError('binary artifact acknowledgement mismatch')
def cleanup():
    for c in connections.values():
        try:c.close()
        except Exception:pass
    for child in reversed(processes):
        if child.poll() is None:
            child.terminate()
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
try:
    for line in sys.stdin:
        request=json.loads(line);op=request['operation'];current_seq=request['seq']
        try:
            body=command(op)
            reply={'ok':True,'body':body,'error':None}
        except Exception as e:
            reply={'ok':False,'body':None,'error':{'kind':type(e).__name__,'message':str(e)[:8192],'sqlstate':getattr(e,'sqlstate',None),'sqlite_errorcode':getattr(e,'sqlite_errorcode',None)}}
            if uncertain_sql_error(op,e):reply['error']['effect']='outcome_unknown'
            if isinstance(e,subprocess.CalledProcessError):
                reply['error'].update(exit_code=e.returncode,argv=e.cmd,stdout_hex=e.stdout[:65536].hex(),stderr_hex=e.stderr[:65536].hex(),truncated=len(e.stdout)>65536 or len(e.stderr)>65536)
        closed=op['command']=='close'
        reply.update(schema_version='melissa.web-reply/v1',seq=request['seq'],source_digest=P['source_digest'],closed=closed,task_completed=False)
        raw=json.dumps(reply,ensure_ascii=False,default=str)
        if len(raw.encode())>P['response_limit']:raise ValueError('response envelope exceeded; no truncated success')
        # Preserve the existing C03 64KiB frame contract. Each bounded response
        # fragment requires an acknowledgement, so the transport queue cannot
        # lose a burst of screenshots/traces. The host validates exact sequence,
        # total/part lengths, reassembles original UTF-8 bytes, then strict-parses.
        encoded=raw.encode('utf-8');parts=(len(encoded)+24575)//24576
        for index in range(parts):
            fragment=encoded[index*24576:(index+1)*24576]
            print(json.dumps({'schema_version':'melissa.web-fragment/v1','seq':request['seq'],'index':index,'parts':parts,'total_bytes':len(encoded),'data_hex':fragment.hex()}),flush=True)
            ack=json.loads(sys.stdin.readline(2048))
            if ack!={'ack':request['seq'],'index':index}:raise ValueError('response fragment acknowledgement mismatch')
        if reply['ok'] and reply['body'].get('binary_artifact'):send_binary(request['seq'],reply['body']['binary_artifact'])
        if closed:break
finally:cleanup()
