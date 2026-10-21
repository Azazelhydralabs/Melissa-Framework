import json,sys
x=json.load(sys.stdin)
target=x["target"]; edges=x["edges"]; seen={target}
while True:
    nxt=seen|{caller for caller,callee in edges if callee in seen}
    if nxt==seen: break
    seen=nxt
findings=sorted(seen-{target})
status="candidate" if findings else "requires_evidence"
print(json.dumps({'schema_version':'melissa.helper-observation/v1','status':status,'findings':findings,'authority':'untrusted_observation','protected_acceptance':False},sort_keys=True))
