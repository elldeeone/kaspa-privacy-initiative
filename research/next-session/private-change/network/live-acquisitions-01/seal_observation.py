"""Hash-close a retained public observation; never performs RPC or semantic replay."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def point(value):
    return value["transactionId"], value["index"]


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("observation")
args = parser.parse_args()
assert re.fullmatch(r"observation-[0-9]{2}", args.observation)
stage = BASE / args.observation
fetch_path = stage / "client-output/network-data/fetch.json"
fetch_raw = fetch_path.read_bytes()
bundle = json.loads(fetch_raw)
result = json.loads((stage / "RESULT.json").read_text())
assert result["status"] == "FETCHED_PENDING_REPLAY" and result["fetch_json_sha256"] == sha(fetch_raw)
descriptor_raw = (BASE / "descriptor.json").read_bytes()
descriptor = json.loads(descriptor_raw)
assert sha(descriptor_raw) == sha(canonical(descriptor)) == "1e454b46148e3e10cdfad35c0f81babdaf24005e1b0312f4ed84b5bc9ee47208"
assert bundle["descriptor"] == descriptor and bundle["descriptor_sha256"] == sha(canonical(descriptor))
assert bundle["public_params_manifest_sha256"] == "b440d08fddcdbbfb7d6b8355ab097a7bedd3fb85b8aa228f07070d4fcb3a91d0"
assert sha(canonical(bundle["public_params_manifest"])) == bundle["public_params_manifest_sha256"]
assert (stage / "software/descriptor.json").read_bytes() == descriptor_raw
assert sha((stage / "software/public-manifest.json").read_bytes()) == bundle["public_params_manifest_sha256"]

coverage, view = bundle["coverage"], bundle["current_view"]
after = view["post_query_delta"]
assert coverage["complete"] and coverage["frontier_seen"] and not coverage["pruned"]
assert coverage["start_hash"] == descriptor["birth_start_hash"] == coverage["anchor_header"]["hash"]
assert coverage["end_cursor"] == coverage["frontier"]["hash"] == after["start_hash"]
assert not coverage["missing"] and not coverage["removed_chain_block_hashes"]
assert after["completed"] and not after["removed_chain_block_hashes"] and not after["related_transactions"]
expected = {}
for row in bundle["transactions"]:
    assert row["sdk_transaction_id_recomputed"] is True
    for entry in row["accepted_input_contexts"]:
        expected[point(entry["outpoint"])] = entry["amount_sompi"], entry["script_public_key"]
    for index, output in enumerate(row["transaction"]["outputs"]):
        expected[row["transaction"]["id"], index] = output["value"], output["scriptPublicKey"]
queries = view["queries"]
assert len(queries) == len(expected) and {point(q["outpoint"]) for q in queries} == set(expected)
live = []
for query in queries:
    assert query["queried"] is True
    assert expected[point(query["outpoint"])] == (query["amount_sompi"], query["script_public_key"])
    if query["entry"] is not None:
        entry = query["entry"]
        assert entry["outpoint"] == query["outpoint"]
        assert (entry["amount_sompi"], entry["script_public_key"]) == expected[point(query["outpoint"])]
        live.append(entry)
assert {point(q["outpoint"]) for q in queries if q["entry"] is not None} == {
    point(p) for p in after["watched_outpoints"]}
assert len(after["watched_outpoints"]) == len(live)

pages = [*bundle["pages"], *after["pages"]]
for record in pages:
    path = (fetch_path.parent / record["path"]).resolve()
    assert path.is_relative_to(fetch_path.parent.resolve()) and not path.is_symlink()
    raw = path.read_bytes()
    assert len(raw) == record["gzip_bytes"] and sha(raw) == record["gzip_sha256"]
    decoded = gzip.decompress(raw)
    assert len(decoded) == record["decoded_bytes"] and sha(decoded) == record["decoded_sha256"]

freeze_path = ROOT / "research/next-session/private-service-loss/network/ORDINARY-NETWORK-SOURCE-FREEZE-01.json"
freeze_raw = freeze_path.read_bytes()
assert sha(freeze_raw) == "19dffcaa74e4f45ac681bbfbb26e8b42783467f4348cd1fd6e20ae9eab83e207"
freeze = json.loads(freeze_raw)
for pin in freeze["files"]:
    raw = (ROOT / pin["path"]).read_bytes()
    assert len(raw) == pin["bytes"] and sha(raw) == pin["sha256"]
for name in ("fetch.mjs", "parameter_manifest.mjs", "run_fetch.py", "trusted_runtime.py"):
    assert (stage / "software" / name).read_bytes() == (ROOT / "poc/private-network-recovery" / name).read_bytes()
plan = json.loads((stage / "RUNTIME-PLAN.json").read_text())
assert plan["controller_directory_not_mounted"] == str(stage)
assert plan["writable_client_output"] == str(stage / "client-output")
assert str(stage) not in plan["command"] and str(stage / "client-output") in plan["command"]
assert not plan["release"]["mounted_in_sandbox"]
cleanup = json.loads((stage / "cleanup.json").read_text())
assert cleanup["MainPID_zero_or_explicitly_unloaded"] is True

prefix = None
previous = BASE / f"observation-{int(args.observation[-2:]) - 1:02}"
if (previous / "client-output/network-data/fetch.json").is_file():
    old_raw = (previous / "client-output/network-data/fetch.json").read_bytes()
    old = json.loads(old_raw)
    fields = ("transaction", "accepted_input_contexts", "accepting_block_header")
    count = len(old["transactions"])
    assert count <= len(bundle["transactions"])
    assert [{k: r[k] for k in fields} for r in old["transactions"]] == [
        {k: r[k] for k in fields} for r in bundle["transactions"][:count]]
    prefix = {"previous_fetch_sha256": sha(old_raw), "common_complete_body_context_header_count": count,
              "exact_common_prefix_equal": True, "independent_consensus_or_provider_identity_proved": False}
closure = {
    "schema": "kpx3-private-change-network-observation-closure/v1",
    "fetch_json_sha256": sha(fetch_raw), "rpc": bundle["source"],
    "acquisition_status": "FETCHED_PENDING_OWNER_PUBLIC_SDK_NATIVE_REPLAY",
    "selected_body_count": len(bundle["transactions"]),
    "accepted_transactions_scanned": coverage["accepted_transactions_scanned"],
    "frontier": coverage["frontier"], "post_query_frontier": after["frontier"],
    "finite_frontier_reached_no_missing_pruning_removals_related_spends": True,
    "current_query_count": len(queries), "current_live_entries": live,
    "all_live_queries_watched": True,
    "terminal_candidate_not_semantically_replayed_here": bundle["terminal_candidate_not_yet_replay_verified"],
    "source_freeze_sha256": sha(freeze_raw), "all_source_pins_unchanged": len(freeze["files"]),
    "raw_page_pairs_rehashed": len(pages), "decoded_bytes": sum(p["decoded_bytes"] for p in pages),
    "local_gzip_bytes": sum(p["gzip_bytes"] for p in pages),
    "disk_sizes_are_not_wire_byte_measurements": True,
    "raw_pages_retained_locally_ignored_not_publication_payloads": True,
    "previous_observation_common_prefix": prefix,
    "view_is_atomic": False, "selected_validating_node_and_history_availability_assumed": True,
    "fresh_native_validation_or_ownership_or_hidden_conservation_claimed_here": False,
    "sdk_hash_evidence": "Acquisition executed pinnedSDK checks; this closure does not independently recompute them.",
    "old_bundle_current_now_proved": False,
    "private_input_or_PK_or_prover_or_operator_rehearsal_files_read": False,
    "runtime_result": result, "cleanup": cleanup,
}
save(stage / "CLOSURE.json", closure)
payloads = []
for path in sorted(stage.rglob("*")):
    if not path.is_file() or "pages" in path.relative_to(stage).parts:
        continue
    assert not path.is_symlink()
    raw = path.read_bytes()
    assert raw[:4] != b"\x7fELF"
    payloads.append({"path": str(path.relative_to(ROOT)), "bytes": len(raw), "sha256": sha(raw)})
manifest = {"schema": "kpx3-private-change-network-publication/v1", "files": payloads,
            "payload_count": len(payloads), "payload_bytes": sum(p["bytes"] for p in payloads),
            "raw_page_pairs_local_only": pages}
save(stage / "MANIFEST.json", manifest)
paths = [p["path"] for p in payloads] + [str((stage / name).relative_to(ROOT)) for name in ("MANIFEST.json", "PUBLIC-FILES.txt")]
with (stage / "PUBLIC-FILES.txt").open("x") as stream:
    stream.write("\n".join(sorted(paths)) + "\n")
print(json.dumps({"observation": args.observation, "fetch_sha256": sha(fetch_raw),
                  "closure_sha256": sha((stage / "CLOSURE.json").read_bytes()),
                  "manifest_sha256": sha((stage / "MANIFEST.json").read_bytes()),
                  "public_paths": len(paths), "payload_bytes": manifest["payload_bytes"]}, sort_keys=True))
