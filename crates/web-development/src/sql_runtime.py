"""Fixed SQL parser/cursor/parallel helpers, loaded only from host-owned bytes."""
import re
import threading

def pg_statements(text):
    # PostgreSQL strings, quoted identifiers, dollar bodies and nested comments.
    result=[];start=0;i=0;n=len(text);quote=None;dollar=None;block=0;line=False
    while i<n:
        ch=text[i];pair=text[i:i+2]
        if line:
            if ch=='\n':line=False
        elif block:
            if pair=='/*':block+=1;i+=1
            elif pair=='*/':block-=1;i+=1
        elif dollar:
            if text.startswith(dollar,i):i+=len(dollar)-1;dollar=None
        elif quote:
            if ch==quote:
                if i+1<n and text[i+1]==quote:i+=1
                else:quote=None
            elif ch=='\\' and quote=="'" and escape:i+=1
        elif pair=='--':line=True;i+=1
        elif pair=='/*':block=1;i+=1
        elif ch in "'\"":
            quote=ch;escape=ch=="'" and i>0 and text[i-1] in 'eE' and (i<2 or not (text[i-2].isalnum() or text[i-2]=='_'))
        elif ch=='$' and (i==0 or not (text[i-1].isalnum() or text[i-1] in '_$')):
            match=re.match(r'\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$',text[i:])
            if match:dollar=match.group();i+=len(dollar)-1
        elif ch==';':
            if text[start:i].strip():result.append(text[start:i].strip())
            start=i+1
        i+=1
    if quote or dollar or block:raise ValueError('unterminated SQL quoted body/comment')
    if text[start:].strip():result.append(text[start:].strip())
    return [s for s in result if sql_keyword(s)]

def sql_keyword(text):
    # Skip nested leading comments; control tokens cannot hide behind comments.
    while True:
        text=text.lstrip()
        if text.startswith('--'):
            text=text.partition('\n')[2];continue
        if text.startswith('/*'):
            i=2;depth=1
            while i<len(text) and depth:
                if text[i:i+2]=='/*':depth+=1;i+=2
                elif text[i:i+2]=='*/':depth-=1;i+=2
                else:i+=1
            if depth:raise ValueError('unterminated SQL comment')
            text=text[i:];continue
        match=re.match(r'[A-Za-z]+',text)
        return match.group().upper() if match else ''

def parallel_sql(scripts, connection, command, database):
    barrier=threading.Barrier(len(scripts));results=[None]*len(scripts)
    for s in scripts:connection(s['connection'],reader=s['mode']=='read_only')
    def execute(index,script):
        name=script['connection'];observations=[]
        try:
            command({'command':'begin','connection':name,'mode':script['mode']})
            for step in script['steps']:
                if step['kind']=='barrier':barrier.wait(timeout=8);observations.append({'barrier':True})
                else:observations.append(command(dict(step,command=step['kind'],connection=name)))
            command({'command':'rollback','connection':name}) if not any(s['kind'] in ('commit','rollback') for s in script['steps']) else None
            results[index]={'ok':True,'observations':observations,'automatic_retry':False}
        except Exception as e:
            barrier.abort()
            try:
                command({'command':'rollback','connection':name});rolled_back=True
            except Exception:
                c=connection(name,reader=script['mode']=='read_only')
                rolled_back=not(c.in_transaction if database=='sqlite' else c.info.transaction_status.value!=0)
            results[index]={'ok':False,'observations':observations,'error':str(e),'sqlstate':getattr(e,'sqlstate',None),'sqlite_errorcode':getattr(e,'sqlite_errorcode',None),'rolled_back':rolled_back,'automatic_retry':False}
    threads=[threading.Thread(target=execute,args=(i,s)) for i,s in enumerate(scripts)]
    for t in threads:t.start()
    for t in threads:t.join(timeout=20)
    if any(t.is_alive() for t in threads):raise SystemExit('SQL parallel worker did not settle; outcome unknown')
    return {'database':database,'results':results,'automatic_retry':False}
