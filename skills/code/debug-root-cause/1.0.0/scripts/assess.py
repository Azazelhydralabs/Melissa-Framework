import json,sys
x=json.load(sys.stdin)
import re
groups={}
for line in x["lines"]:
    if re.search(r"error|exception|fatal",line,re.I):
        key=re.sub(r"\b[0-9]{4,}\b","<n>",re.sub(r"0x[0-9a-fA-F]+","<address>",line))
        groups[key]=groups.get(key,0)+1
findings=[{"message":k,"count":v} for k,v in sorted(groups.items())]
status="candidate" if findings else "requires_evidence"
print(json.dumps({'schema_version':'melissa.helper-observation/v1','status':status,'findings':findings,'authority':'untrusted_observation','protected_acceptance':False},sort_keys=True))
