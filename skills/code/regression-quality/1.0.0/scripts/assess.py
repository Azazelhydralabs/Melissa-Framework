import json,sys
x=json.load(sys.stdin)
runs=x["runs"]; findings=[]
if not runs or not runs[0]: findings.append("zero_tests")
if len(runs)<2: findings.append("missing_repeat")
for i,r in enumerate(runs):
    if set(r)!=set(runs[0]): findings.append("discovery_changed")
    if any(v!="passed" for v in r.values()): findings.append("failed_skipped_or_flaky")
status="rejected" if findings else "candidate"
print(json.dumps({'schema_version':'melissa.helper-observation/v1','status':status,'findings':findings,'authority':'untrusted_observation','protected_acceptance':False},sort_keys=True))
