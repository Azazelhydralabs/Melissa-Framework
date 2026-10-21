import json,sys
x=json.load(sys.stdin)
seen={}; findings=[]
for r in x["requests"]:
    key=(r["tenant"],r["key"])
    if key in seen and seen[key]!=r["effect"]: findings.append("duplicate_effect")
    seen[key]=r["effect"]
status="rejected" if findings else "candidate"
print(json.dumps({'schema_version':'melissa.helper-observation/v1','status':status,'findings':findings,'authority':'untrusted_observation','protected_acceptance':False},sort_keys=True))
