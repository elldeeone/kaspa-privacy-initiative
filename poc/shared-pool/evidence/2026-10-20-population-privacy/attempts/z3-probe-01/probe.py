import json
from pathlib import Path
from population_privacy_model import Pair, digest, validate_truth
p=json.loads(Path("/public.json").read_text())
v=json.loads(Path("/view.json").read_text())
m=Pair(p,v,diagnostics=True)
w=m.query("z3",kind="independent_baseline_probe")
r={"public_sha256":digest(p),"view_sha256":digest(v),"witness":w,"qualification_pass":False}
if w is not None:
    r["witness_validation"]=validate_truth(p,v,w)
with Path("/output/result.json").open("x") as f:
    json.dump(r,f); f.write("\n")
