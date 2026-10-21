import json,sys
x=json.load(sys.stdin)
findings=list(x["violations"])
if x["applied"]!=x["expected"]: findings.append("migration_sequence_mismatch")
status="rejected" if findings else "candidate"
print(json.dumps({'schema_version':'melissa.helper-observation/v1','status':status,'findings':findings,'authority':'untrusted_observation','protected_acceptance':False},sort_keys=True))
