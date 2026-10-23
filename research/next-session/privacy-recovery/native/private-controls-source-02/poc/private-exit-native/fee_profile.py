#!/usr/bin/env python3
"""Extract exact body fees and cross-check pinned source arithmetic; no VM/RPC."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "research/next-session/exit-fee/cost_envelope.py"
HELPER_SHA = "ea382803c79c07272c8485fb51505aabe27c90180e9f8e325de29f21f807a6df"


def read(path):
    return json.loads(Path(path).read_text())


def pin(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def extract(args):
    if args.output.exists():
        raise ValueError("fresh fee profile identity required")
    if pin(HELPER)["sha256"] != HELPER_SHA:
        raise ValueError("pinned integer mass calculator changed")
    spec = importlib.util.spec_from_file_location("pinned_fee_arithmetic", HELPER)
    arithmetic = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(arithmetic)
    manifest = read(args.prepared / "MATERIALIZED.json")
    directories = [("funding-prep", Path(manifest["funding_prep_quote_directory"])),
                   ("founding", Path(manifest["founding_body_directory"])),
                   ("admit", Path(manifest["admit_body_directory"]))]
    directories.extend((item["stage"], Path(item["body_directory"])) for item in manifest["stages"])
    directories.append(("reveal-first-continuing", args.controls / "reveal-first-positive"))
    rows = []
    sources = {Path(__file__).resolve(), HELPER, args.prepared / "MATERIALIZED.json"}
    for name, directory in directories:
        paths = {key: directory / filename for key, filename in (
            ("transaction", "transaction.json"), ("context", "supplied-context.json"), ("metrics", "metrics.json"))}
        sources.update(paths.values())
        tx, entries, metrics = (read(paths[key]) for key in ("transaction", "context", "metrics"))
        if (any(output.get("covenant") is not None for output in tx["outputs"])
                or len(tx["inputs"]) != len(entries)):
            raise ValueError("only selected absent-metadata supplied contexts supported")
        sigs = [len(bytes.fromhex(item["signatureScript"])) for item in tx["inputs"]]
        budgets = [item["computeBudget"] for item in tx["inputs"]]
        spks = [len(bytes.fromhex(item["scriptPublicKey"])) - 2 for item in tx["outputs"]]
        incoming = [(1, item["amount_sompi"]) for item in entries]
        outgoing = [(1, item["value"]) for item in tx["outputs"]]
        size = 94 + sum(54 + size for size in sigs) + sum(18 + size for size in spks) + len(bytes.fromhex(tx["payload"]))
        checked = arithmetic.mass(size, spks, budgets, incoming, outgoing)
        mapping = {"estimated_bytes": "estimated_bytes", "compute_mass": "compute_mass", "transient_mass": "transient_mass",
                   "storage_mass": "storage_mass", "default_relay_mass": "relay_mass", "normalized_mining_mass": "mining_mass"}
        if any(checked[key] != metrics[value] for key, value in mapping.items()):
            raise ValueError("official metric/source arithmetic mismatch: " + name)
        fee = sum(amount for _, amount in incoming) - sum(amount for _, amount in outgoing)
        if fee != metrics["actual_fee_sompi"] or any(quote["required_sompi"] != quote["rate"] * metrics["mining_mass"] for quote in metrics["quotes"]):
            raise ValueError("fee or fixed-body quote mismatch")
        rows.append({"stage": name, "directory": str(directory.resolve()), "body_files": {key: pin(path) for key, path in paths.items()},
                     "inputs_sompi": [amount for _, amount in incoming], "outputs_sompi": [amount for _, amount in outgoing],
                     "payload_bytes": len(bytes.fromhex(tx["payload"])), "input_signature_script_lengths": sigs,
                     "input_compute_budgets": budgets, "output_raw_script_lengths": spks,
                     "metrics": metrics, "exact_source_arithmetic_matches_official_metrics": True,
                     "proof_placeholder_in_this_body": name in ("spend", "bob-partial", "bob-full", "charlie-terminal")})
    result = {"classification": "PUBLIC_SYNTHETIC_BODY_FEE_PROFILE_NO_VM", "domain_hex32": manifest["domain_hex32"],
              "vk_sha256": manifest["vk_sha256"], "rows": rows, "sources": [pin(path) for path in sorted(sources)],
              "fixed_body_quotes_not_repriced_authorizations": True, "rates": [100, 200, 500],
              "actual_fee_authorized_at_reference_rate100_only": True,
              "context_warning": "Mining=max(compute,2*estimated_bytes,storage(actual amounts)); another rate or reserve/payout context needs its own fixed point.",
              "native_VM_or_Full_executed_here": False, "accepted_chain_backing": False,
              "network_or_broadcast": False, "fee_qualification_claimed": False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return {"profile": pin(args.output), "rows": len(rows), "exact_arithmetic_cross_checks": len(rows)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("prepared", "controls", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    print(json.dumps(extract(parser.parse_args()), sort_keys=True))
