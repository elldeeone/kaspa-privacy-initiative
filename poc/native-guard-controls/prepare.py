"""Read only pinned public sources; create exclusive immutable validator copy."""
import hashlib, json, os, shutil, sys
from pathlib import Path
lane = Path(sys.argv[1]).resolve()
root = lane / "worktree"
source = Path("/home/luke/projects/kaspa-privacy-shared-pool")
manifest_path = root / "poc/shared-pool/native-usage-build.json"
manifest = json.loads(manifest_path.read_text())
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
for rel, expected in manifest["source_sha256"].items():
    assert sha(root / rel) == expected, rel
name = "kpi-two-input-lifecycle"
src = source / "poc/shared-pool/target/release" / name
expected = manifest["binary_sha256"][name]
assert sha(src) == expected
out = lane / "bin" / name
with src.open("rb") as a, out.open("xb") as b:
    shutil.copyfileobj(a, b)
assert sha(src) == sha(out) == expected
out.chmod(0o555)
fixtures = ["positive/lineage.json", "positive/parents.json", "positive/vk.bin", "positive/descriptor.json"]
base = root / "poc/shared-pool/evidence/2026-10-20-wallet-lifecycle"
pins = {str(p.relative_to(root)): sha(p) for p in [base / x for x in fixtures]}
pins.update({"poc/shared-pool/native-usage-build.json": sha(manifest_path), "poc/shared-pool/Cargo.lock": sha(root / "poc/shared-pool/Cargo.lock")})
(lane / "outputs/input-pins.json").write_text(json.dumps({"checkpoint":"9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02", "source_sha256":manifest["source_sha256"], "fixtures":pins,"validator_sha256":expected,"validator_source_manifest":str(manifest_path)}, indent=2)+"\n")
print(json.dumps({"source_files_verified":len(manifest["source_sha256"]),"validator_sha256":expected,"fixture_count":len(fixtures)}))
