import hashlib,json,pathlib,sys
from concurrent.futures import ThreadPoolExecutor
from trusted_util import c
from public_fetch import fetch_object
from retrieve import retrieve
old=["/home/luke/projects/kpi-intensive-2026-10-22/compact-batch-public-parameters-01","/home/luke/projects/kpi-intensive-2026-10-22/continuation","/home/luke/projects/kpi-intensive-2026-10-22/independent-payment-recovery-distribution-02","/home/luke/projects/kpi-intensive-2026-10-22/independent-payment-public-recovery-canary-01"]
assert all(not pathlib.Path(p).exists() for p in old)
print("SOURCE_ABSENCE "+json.dumps({"probe_count":len(old),"all_absent":True,"backup_PK_producer_operator_sources_mounted":False}),flush=True)
raw=pathlib.Path("/selection.json").read_bytes()
assert hashlib.sha256(raw).hexdigest()=="0caf77d22aa2360e790d0480b47f15f32398d443ae48ccf74701b47655052645"
selection=c.TrustedSelection.from_dict(c.parse(raw))
base=sys.argv[1].rstrip("/")
hosts=["github.com","release-assets.githubusercontent.com","objects.githubusercontent.com","api.github.com"]
pool=ThreadPoolExecutor(max_workers=2)
archive=pool.submit(fetch_object,[base+"/software-bundle.tar.zst"],66501581,"17654e748f4c03542646af9d782279cc4e1bd040d5bc97eb0493796515632a46",pathlib.Path("/out/software-bundle.tar.zst"),hosts)
members=pool.submit(fetch_object,[base+"/ARCHIVE-MEMBERS.json"],1146892,"d59d5dbbbac0fd9b68c4d07153f5ac94c6abfcdf8c6bf3aa79efb096a3fe151e",pathlib.Path("/out/ARCHIVE-MEMBERS.json"),hosts)
first=fetch_object([base+"/PUBLICATION.json"],3555,"cd9d49b36850cd3e969f8eeffe8dbabb52c3bfd3f6014fedbd65d61cc10e4d78",pathlib.Path("/out/PUBLICATION.json"),hosts)
print("PUBLICATION_VERIFIED "+json.dumps(first,sort_keys=True),flush=True)
result=retrieve(pathlib.Path("/out/PUBLICATION.json"),"cd9d49b36850cd3e969f8eeffe8dbabb52c3bfd3f6014fedbd65d61cc10e4d78",selection,[{"kind":"release","base":base}],pathlib.Path("/out/materials"),hosts,mode="spend_material")
print("RECOVERY_RESULT "+json.dumps(result,sort_keys=True),flush=True)

print("SOFTWARE_ARCHIVE_RESULT "+json.dumps(archive.result(),sort_keys=True),flush=True)
print("SOFTWARE_MEMBERS_RESULT "+json.dumps(members.result(),sort_keys=True),flush=True)
pool.shutdown()
