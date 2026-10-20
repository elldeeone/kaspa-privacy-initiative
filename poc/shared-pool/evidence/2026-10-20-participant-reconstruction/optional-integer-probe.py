import json,sys,time,hashlib
from pathlib import Path
from participant_privacy_observer import ParticipantModel,prefix_view
from wallet_policy_observer import eligible
from two_input_privacy_observer import decode,summarize
raw=Path('/input.json').read_bytes();viewraw=Path('/view.json').read_bytes()
data=json.loads(raw);view=json.loads(viewraw);profile=sys.argv[1]
start=time.monotonic();end=16;target=16
births,upper=decode(data)
prefix=dict(data,events=data['events'][:end+1])
m=ParticipantModel(prefix,prefix_view(data,view,end),profile)
assert m.check()
candidates=[]
for candidate in sorted(eligible(data,target,'wallet',upper),key=lambda c:(len(c),c)):
 if m.check(target,candidate): candidates.append(candidate)
assert candidates
result=dict(profile=profile,event=target,through=end,seconds=time.monotonic()-start,
 queries=m.queries,input_sha256=hashlib.sha256(raw).hexdigest(),
 view_sha256=hashlib.sha256(viewraw).hexdigest(),**summarize(candidates,births))
with Path('/output/result.json').open('x') as f: json.dump(result,f,indent=2)
print(json.dumps(dict(seconds=result['seconds'],queries=m.queries,candidates=len(candidates))))
