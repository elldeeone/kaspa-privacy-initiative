"""One root-authorized batch over twenty explicitly published funding scripts."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[5]
STAGE = Path(__file__).resolve().parent
OLD = ROOT / "research/next-session/private-change/network"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


config = json.loads((STAGE / "INPUT.json").read_text())
previous = json.loads((OLD / "KNOWN-PUBLIC-FUNDING-INPUT-01.json").read_text())
current = {row["script_public_key"] for row in config["scripts"]}
assert len(current) == len(config["scripts"]) == 20
assert current.isdisjoint({row["script_public_key"] for row in previous["scripts"]})
assert digest(STAGE / "INPUT.json") == "127326aa0a2b60615e436e8da3dc797eeddfbccc8abd2a433935d8534cab5b1a"
assert digest(STAGE / "query-source.mjs") == "59f426af0b00cd890361a7ce2bccc66a5f379a2682b029454a1bf36cce413f78"
for row in config["scripts"]:
    assert row["public_provenance"] and row["published_points"]
    for pin in row["public_provenance"]:
        assert digest(ROOT / pin["path"]) == pin["sha256"]

runtime = ROOT / "poc/private-network-recovery/trusted_runtime.py"
assert digest(runtime) == "3ce31ae0eb8f942009a4108f9a5dbb6a08df6c7f0925f06a952315091e1bbd1c"
node = Path("/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node")
assert stat.S_IMODE(node.parent.stat().st_mode) == 0o700
assert stat.S_ISREG(node.stat().st_mode) and stat.S_IMODE(node.stat().st_mode) == 0o500
assert digest(node) == "d1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c"

old_plan = json.loads((OLD / "known-funding-query-02/RUNTIME-PLAN.json").read_text())
replacements = {
    str(OLD / "known-funding-query-02/query-source.mjs"): str(STAGE / "query-source.mjs"),
    str(OLD / "known-funding-query-02/input.json"): str(STAGE / "INPUT.json"),
    str(OLD / "known-funding-query-02/client-output"): str(STAGE / "client-output"),
}
argv = [replacements.get(arg, arg) for arg in old_plan["argv"]]
(STAGE / "client-output").mkdir(mode=0o700)
plan = {
    "schema": "kpx3-scoped-funding-followup-runtime/v1",
    "started_at": datetime.now(timezone.utc).isoformat(),
    "scope": "ONE additional batch, exactly20 NEW public ordinary funding scripts; no payout graph, private store/key/seed/profile/backup, faucet request, signer or broadcast. Root must verify private control before use.",
    "input_sha256": digest(STAGE / "INPUT.json"),
    "query_source_sha256": digest(STAGE / "query-source.mjs"),
    "controller_source_sha256": digest(Path(__file__).resolve()),
    "trusted_runtime_sha256": digest(runtime),
    "reused_query_bytes_unchanged": True,
    "previous_five_query_artifacts_modified": False,
    "argv": argv,
    "environment": {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC"},
}
save(STAGE / "RUNTIME-PLAN.json", plan)
with (STAGE / "query.log").open("x") as log:
    result = subprocess.run(argv, cwd=ROOT, env=plan["environment"], stdout=log,
                            stderr=subprocess.STDOUT, text=True, timeout=600)
observation = STAGE / "client-output/OBSERVATION.json"
receipt = {
    "completed_at": datetime.now(timezone.utc).isoformat(),
    "exit_code": result.returncode,
    "log_sha256": digest(STAGE / "query.log"),
    "observation_sha256": digest(observation) if observation.is_file() else None,
    "additional_batch_count": 1,
}
save(STAGE / "RESULT.json", receipt)
print(json.dumps(receipt, sort_keys=True))
raise SystemExit(result.returncode)
