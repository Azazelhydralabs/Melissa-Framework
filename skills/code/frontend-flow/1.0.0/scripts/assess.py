import json,sys
x=json.load(sys.stdin)
findings=[k for k in ["keyboard","focus","responsive","errors"] if x["observations"].get(k) is not True]
status="requires_evidence" if findings else "candidate"
print(json.dumps({'schema_version':'melissa.helper-observation/v1','status':status,'findings':findings,'authority':'untrusted_observation','protected_acceptance':False},sort_keys=True))
