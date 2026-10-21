import json,sys
x=json.load(sys.stdin)
findings=[]
if x["expected"]!=x["actual"]: findings.append("stale_preimage")
findings.extend("out_of_scope:"+p for p in x["paths"] if p not in x["allowed"])
status="rejected" if findings else "candidate"
print(json.dumps({'schema_version':'melissa.helper-observation/v1','status':status,'findings':findings,'authority':'untrusted_observation','protected_acceptance':False},sort_keys=True))
