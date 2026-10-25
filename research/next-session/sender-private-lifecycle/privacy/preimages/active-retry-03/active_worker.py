#!/usr/bin/env python3
"""Count-only active retry experiment on fresh hidden wire fixtures.

No wallet seed, financial proof or real KAS exists. The observer uses actual
MASCOT-opened inputs, known membership, and colluder B's own stable NF stand-in.
Only individual owners open their own truth. Guesses remain in a salted private
capsule; four restricted count leaves produce global counts only.
"""
import argparse
import hashlib
import os
from pathlib import Path
import secrets

import codec
from measurement import enumerate_abort_assignments, need
from owner_score import EXPERIMENT, hx
from runtime import canonical, checked, parse, read, write_new

TAG, COUNT_BYTES = b"KPX9AC01", 112


def own():
    value = parse(read(Path("/owner/TRUTH.json"), mode=0o600))
    need(type(value) is dict and set(value) == {"schema", "owner_handle", "nf_hex32"} and
         value["schema"] == "kpx9-private-active-wire-owner/v1", "one-own-wire-truth")
    hx(value["owner_handle"], 32); hx(value["nf_hex32"], 32)
    return value


def init(handle):
    hx(handle, 32)
    nf = secrets.token_bytes(32)
    while nf == bytes(32):
        nf = secrets.token_bytes(32)
    write_new(Path("/owner/TRUTH.json"), canonical({"schema": "kpx9-private-active-wire-owner/v1",
              "owner_handle": handle, "nf_hex32": nf.hex()}), 0o600)


def prepare(attempt, party, session_sha):
    need(attempt in ("000001", "000002", "000003") and type(party) is int and 0 <= party < 3,
         "fixed-active-attempt-and-party")
    hx(session_sha, 32)
    value = own()
    directory = checked(Path("/owner/attempts") / attempt / "input")
    directory.mkdir(parents=True, mode=0o700)
    row = hx(value["nf_hex32"], 32) + secrets.token_bytes(64)
    outputs = [secrets.token_bytes(520), secrets.token_bytes(520)]
    write_new(directory / ("Input-P%d-0" % party), codec.owner_input(row, outputs, secrets.randbelow(codec.Q)))
    write_new(directory.parent / "SESSION.json", canonical({"session_sha256": session_sha,
              "party": party, "fixture_only": True}), 0o600)


def selected_views(descriptor, descriptor_pin):
    value = parse(read(descriptor, sha256=descriptor_pin))
    need(type(value) is dict and set(value) == {"schema", "experiment_sha256", "attempts", "stratum"} and
         value["schema"] == "kpx9-active-wire-observer-view/v1" and value["experiment_sha256"] == EXPERIMENT and
         value["stratum"] == "MPC_WIRE_FIXTURE_ACTIVE_INTERSECTION" and len(value["attempts"]) == 3,
         "fixed-active-actual-view")
    attempts, inventory = [], []
    for attempt in value["attempts"]:
        need(type(attempt) is dict and set(attempt) == {"members", "artifacts"} and
             type(attempt["members"]) is list and len(attempt["members"]) == len(set(attempt["members"])) == 3,
             "three-known-active-members")
        for member in attempt["members"]: hx(member, 32)
        packet = None
        for item in attempt["artifacts"]:
            need(type(item) is dict and set(item) == {"alias", "sha256", "bytes", "kind"} and
                 item["kind"] in ("packet", "stdout", "stderr", "mixed", "observer") and
                 type(item["alias"]) is str and item["alias"].isascii() and item["alias"].isdigit(),
                 "complete-actual-coordinator-artifact")
            hx(item["sha256"], 32)
            raw = read(Path("/artifacts") / item["alias"], sha256=item["sha256"], size=item["bytes"])
            inventory.append(dict(item))
            if item["kind"] == "packet":
                need(packet is None, "one-actual-coordinator-input")
                packet = parse(raw)
        need({item["kind"] for item in attempt["artifacts"]} == {"packet", "stdout", "stderr", "mixed", "observer"},
             "all-actual-coordinator-artifacts")
        need(packet["schema"] == "kpx9-coordinator-public-ipc/v1" and packet["phase"] == "admit" and
             packet["effects_digest_hex32"] == "0" * 64 and len(packet["party_projections"]) == 3 and
             packet["party_projections"][0] == packet["party_projections"][1] == packet["party_projections"][2],
             "all-three-actual-opened-input-projections")
        inputs, _, _ = codec.validate_admission(packet["party_projections"][0], packet["session_sha256"])
        attempts.append({"members": attempt["members"], "input_ids": [row[:32].hex() for row in inputs],
                         "inputs_opened": True, "effects_authorized": False, "settled": False})
    return attempts, inventory


def observe(descriptor_pin):
    attempts, inventory = selected_views(Path("/view"), descriptor_pin)
    known = own()
    pairs = [(known["nf_hex32"], known["owner_handle"])]
    results = {"overlap": enumerate_abort_assignments(attempts[:2], pairs),
               "same_cohort": enumerate_abort_assignments([attempts[0], attempts[2]], pairs)}
    need(results["overlap"]["feasible_explanations"] > 0 and
         results["same_cohort"]["feasible_explanations"] > 0, "consistent-actual-active-views")
    views = hashlib.sha256(canonical(inventory)).hexdigest()
    payload = {"schema": "kpx9-private-active-predictions/v1", "experiment_sha256": EXPERIMENT,
               "view_sha256": views, "known_owner_handle": known["owner_handle"], "results": results}
    salt = secrets.token_bytes(32)
    seal = hashlib.sha256(b"KPX9 active prediction seal\0" + salt + canonical(payload)).hexdigest()
    write_new(Path("/private/CAPSULE.json"), canonical({"salt_hex32": salt.hex(), "payload": payload}))
    write_new(Path("/out/CONTEXT.json"), canonical({"schema": "kpx9-active-query-context/v1",
              "experiment_sha256": EXPERIMENT, "view_sha256": views, "prediction_seal_sha256": seal}))
    write_new(Path("/out/PRESEALED.json"), canonical({"schema": "kpx9-active-presealed-ambiguity/v1",
              "overlap_feasible_explanations": results["overlap"]["feasible_explanations"],
              "same_cohort_feasible_explanations": results["same_cohort"]["feasible_explanations"],
              "private_owner_or_NF_associations_exported": False}))


def context(pin):
    value = parse(read(Path("/context"), sha256=pin))
    need(type(value) is dict and set(value) == {"schema", "experiment_sha256", "view_sha256", "prediction_seal_sha256"}
         and value["schema"] == "kpx9-active-query-context/v1" and value["experiment_sha256"] == EXPERIMENT,
         "selected-active-query-context")
    for name in ("experiment_sha256", "view_sha256", "prediction_seal_sha256"): hx(value[name], 32)
    return value


def prefix(selected):
    return TAG + b"".join(hx(selected[name], 32) for name in
                         ("experiment_sha256", "view_sha256", "prediction_seal_sha256"))


def score(context_pin):
    selected = context(context_pin)
    capsule = parse(read(Path("/capsule")))
    need(type(capsule) is dict and set(capsule) == {"salt_hex32", "payload"}, "private-active-capsule")
    payload = capsule["payload"]
    need(payload["schema"] == "kpx9-private-active-predictions/v1" and
         payload["experiment_sha256"] == selected["experiment_sha256"] and
         payload["view_sha256"] == selected["view_sha256"] and
         hashlib.sha256(b"KPX9 active prediction seal\0" + hx(capsule["salt_hex32"], 32) + canonical(payload)).hexdigest()
         == selected["prediction_seal_sha256"], "presealed-active-predictions")
    write_new(Path("/diagnostic/QUERY-CLOSED"), canonical(selected))
    value = own()
    counts = []
    for name in ("overlap", "same_cohort"):
        candidates = payload["results"][name]["candidate_owners"]
        present = value["nf_hex32"] in candidates
        known = present and value["owner_handle"] == payload["known_owner_handle"]
        eligible = present and not known
        unique = eligible and len(candidates[value["nf_hex32"]]) == 1
        matched = unique and candidates[value["nf_hex32"]] == [value["owner_handle"]]
        counts.extend(map(int, (eligible, unique, matched, known)))
    raw = prefix(selected) + bytes(counts)
    need(len(raw) == COUNT_BYTES, "fixed-active-private-count-width")
    write_new(Path("/diagnostic/COUNT.bin"), raw)


def aggregate(context_pin):
    selected = context(context_pin)
    paths = [checked(Path("/counts") / (str(i) + ".bin")) for i in range(4)]
    need(len({(p.lstat().st_dev, p.lstat().st_ino) for p in paths}) == 4, "four-distinct-active-owner-leaves")
    values = []
    for path in paths:
        raw = read(path, size=COUNT_BYTES, mode=0o400)
        need(raw[:104] == prefix(selected), "same-sealed-active-query-context")
        row = list(raw[104:])
        for start in (0, 4):
            eligible, unique, matched, known = row[start:start + 4]
            need(0 <= matched <= unique <= eligible <= 1 and known in (0, 1) and not (known and eligible),
                 "bounded-active-private-counts")
        values.append(row)
    reports = {}
    for index, name in enumerate(("overlap", "same_cohort")):
        counts = [sum(value[4 * index + i] for value in values) for i in range(4)]
        expected = 3 if name == "overlap" else 2
        need(counts[0] == expected and counts[3] == 1, "actual-complete-active-owner-cohort")
        reports[name] = {"unknown_eligible": counts[0], "unique_predictions": counts[1],
                         "owner_verified_matches": counts[2], "known_colluder_excluded": counts[3]}
    report = {"schema": "kpx9-actual-active-intersection-global-counts/v1",
              "stratum": "MPC_WIRE_FIXTURE_ACTIVE_INTERSECTION", **selected, "cases": reports,
              "active_candidate_failed": reports["overlap"]["owner_verified_matches"] > 0,
              "financial_proofs_or_backing_verified": False, "privacy_qualified": False,
              "original_private_contents_read": False, "private_owner_or_NF_associations_exported": False}
    write_new(Path("/out/RESULT.json"), canonical(report))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("init", "prepare", "observe", "score", "aggregate"))
    parser.add_argument("--handle"); parser.add_argument("--attempt"); parser.add_argument("--party", type=int)
    parser.add_argument("--session-sha256"); parser.add_argument("--view-sha256"); parser.add_argument("--context-sha256")
    args = parser.parse_args()
    if args.operation == "init": init(args.handle)
    elif args.operation == "prepare": prepare(args.attempt, args.party, args.session_sha256)
    elif args.operation == "observe": observe(args.view_sha256)
    elif args.operation == "score": score(args.context_sha256)
    else: aggregate(args.context_sha256)


if __name__ == "__main__":
    os.umask(0o077)
    try:
        main()
    except Exception:
        os.write(2, b"KPX9_ACTIVE_INCOMPLETE\n")
        raise SystemExit(2)
