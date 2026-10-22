"""Pin an existing public validator/ID adapter; never build or access private data."""
import hashlib,json,shutil,sys
from pathlib import Path
lane=Path(sys.argv[1]).resolve(); root=lane/"worktree"
v1=Path("/home/luke/projects/kpi-orchestration/2026-10-22/native-surface-review/guard-controls-v1")
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
manifest=v1/"RUNTIME-MANIFEST.json"
assert sha(manifest)=="fc6989f26df146639804fb0486aeb9c1b1b45e09e7453e7fc23a741d60db3c67"
m=json.loads(manifest.read_text())
for relative,pin in m["files"].items():
    p=v1/relative
    assert sha(p)==pin["sha256"] and p.stat().st_size==pin["bytes"],relative
copies={"kpi-two-input-lifecycle":"bin/kpi-two-input-lifecycle","kpi-native-guard-id":"adapter-target/release/kpi-native-guard-id"}
binaries={}
for name,relative in copies.items():
    source=v1/relative; target=lane/"bin"/name
    with source.open("rb") as a,target.open("xb") as b:shutil.copyfileobj(a,b)
    assert sha(target)==m["files"][relative]["sha256"]
    target.chmod(0o555); binaries[name]=sha(target)
source_manifest=json.loads((root/"poc/shared-pool/native-usage-build.json").read_text())
for relative,expected in source_manifest["source_sha256"].items(): assert sha(root/relative)==expected,relative
fixtures=["evidence/2026-10-20-two-input-tn10/rehearsal/chain-confirmed.json","evidence/2026-10-20-two-input-tn10/verification-key.json","evidence/2026-10-20-wallet-lifecycle/positive/lineage.json","evidence/2026-10-20-wallet-lifecycle/positive/parents.json","evidence/2026-10-20-wallet-lifecycle/positive/vk.bin"]
pins={"poc/shared-pool/"+rel:sha(root/"poc/shared-pool"/rel) for rel in fixtures}
output=dict(base_commit="dd00ceed35a95d10b6c79b80b744642244cb3226",protocol_commit="9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02",v1_manifest_sha256=sha(manifest),v1_files_verified=len(m["files"]),binary_sha256=binaries,fixtures=pins,source_sha256=source_manifest["source_sha256"])
(lane/"outputs/input-pins.json").write_text(json.dumps(output,indent=2)+"\n")
print(json.dumps({"verified_v1_files":len(m["files"]),"pinned_source_files":len(source_manifest["source_sha256"]),"binary_sha256":binaries}))
