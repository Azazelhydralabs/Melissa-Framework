import json,sys
x=json.load(sys.stdin)
findings=[r for r in x["requirements"] if len(x["coverage"].get(r,[]))<2]
status="requires_evidence" if findings else "candidate"
print(json.dumps({'schema_version':'melissa.helper-observation/v1','status':status,'findings':findings,'authority':'untrusted_observation','protected_acceptance':False},sort_keys=True))
