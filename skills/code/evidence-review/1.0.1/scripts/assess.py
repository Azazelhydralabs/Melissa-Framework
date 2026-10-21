import json,sys
x=json.load(sys.stdin)
findings=[i for i,r in enumerate(x["findings"]) if not all(r.get(k) for k in ["file","line","evidence","reproducer"])]
status="requires_evidence" if findings else "candidate"
print(json.dumps({'schema_version':'melissa.helper-observation/v1','status':status,'findings':findings,'authority':'untrusted_observation','protected_acceptance':False},sort_keys=True))
