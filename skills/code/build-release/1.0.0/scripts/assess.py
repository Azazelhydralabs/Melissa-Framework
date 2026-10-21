import json,sys
x=json.load(sys.stdin)
import hashlib
findings=[]
if hashlib.sha256(bytes.fromhex(x["artifact_hex"])).hexdigest()!=x["sha256"]: findings.append("artifact_hash_mismatch")
if x["smoke_exit"]!=0: findings.append("smoke_failed")
status="rejected" if findings else "candidate"
print(json.dumps({'schema_version':'melissa.helper-observation/v1','status':status,'findings':findings,'authority':'untrusted_observation','protected_acceptance':False},sort_keys=True))
