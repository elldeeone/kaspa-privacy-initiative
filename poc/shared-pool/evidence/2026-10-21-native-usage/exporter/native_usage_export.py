#!/usr/bin/env python3
"""Post-run public packaging; NOT part of the frozen experiment.

No generator, observer, solver, prover, network or private-truth reads. This
closed allowlist exports only a completed, unchanged frozen attempt. The ten
declared participant views are the sole allowed files under native/private/.
Prefix inputs and individual results are hash-checked but omitted as duplicates
of reconstructible public inputs and combined sealed predictions.
"""
import argparse
import copy
from datetime import datetime
import gzip
import hashlib
import io
import json
import math
from pathlib import Path, PurePosixPath
import re
import tempfile

FREEZE = "f841e1d66a1f3e5fdd564aefe035701e3a32c41ffe0f7d4ca498d94509e74ac5"
BASE = "9ae5b3efeb1698cf45d35e064c95f91c1ac5a54e"
# Deterministic public-only runner/generator/observer/scorer controls, recomputed
# from the reviewed source; never taken from an uninspected private attempt.
CONTROL_RESULT = "6194db9a2f69099e9b4866e71acf98c031efbb9d82853354058935c68c44deb6"
SOURCES = ("early_privacy_surface.py", "two_input_privacy_observer.py", "two_input_privacy_z3.py",
           "population_privacy_model.py", "population_privacy_workload.py", "two-input-lifecycle.py",
           "native_usage_trial.py", "native_usage_generate.py", "native_usage_surface.py",
           "native_usage_observer.py", "native_usage_score.py", "NATIVE-USAGE-PRIVACY-SPEC.md")
NOTES = ("SECURITY-INVARIANTS.md", "docs/rfc/0012-useful-privacy-requirements.md",
         "docs/rfc/0015-native-usage-privacy-screen.md",
         "research/shielded-kas-native-usage-privacy-2026-10-21.md",
         "poc/shared-pool/native-usage-build.json")
NATIVE = ("descriptor.json", "vk.bin", "lineage.json", "parents.json", "head.json",
          "checked.json", "directory.json", "timing.json")
PROFILES = ("C", *(f"P{i}" for i in range(8)), "pooled")
VARIANTS = ("prior", "residual", "split", "native_graph")
METRICS = ("sender", "recipient", "relationship", "amount_within_10pct", "amount_exact")
STRATA = ("primary", "all_undisclosed", "startup", "adversary_endpoint")
ACCOUNTING = "external_source_count external_injection_sompi final_native_unspent_sompi pool_fees_sompi ordinary_fees_sompi native_transaction_count consumed_native_outpoints whole_experiment_conserved"
OBS_INPUTS = ("/raw.json", "/directory.json", "/view.json", "/timing.json", "/policy.json")
SCORE_INPUTS = ("/raw.json", "/directory.json", "/timing.json", "/policy.json", "/truth.json", "/predictions.json")
DIAGNOSTIC_TEXT = dict(
    timing="Declared modeled minutes; not native-chain timestamps",
    equality_meaning="Exact byte equality only; not a sender, recipient or human-identity inference",
    bridge_meaning="Exact serialized payout-to-parent-to-funding-output references; not separate value flows or source-owner labels",
    validation="Pinned pool replay and separate native validation of each funding bridge against all input UTXOs are caller prerequisites",
    transaction_size_meaning="canonical_json_bytes counts the named JSON encoding, not Kaspa binary serialization or consensus mass")
PADDING_TEXT = "not decoded; positive and zero encrypted note values are inferred only by the declared arithmetic profiles"
REPLAY_SCOPE = "offline native replay; descriptor and accepted-chain view must be authenticated externally"


def need(ok, message):
    if not ok:
        raise ValueError(message)


def fields(value, names, label):
    names = names.split() if isinstance(names, str) else names
    need(type(value) is dict and set(value) == set(names), label + " fields")


def integer(value, low=0, high=2**64-1):
    need(type(value) is int and low <= value <= high, "integer/range")
    return value


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def canonical(value):
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())


def encoded(value):
    # Exact frozen runner save() representation, including insertion order.
    return (json.dumps(value, indent=2, allow_nan=False) + "\n").encode()


def compressed_exact(blob):
    """Reversible packaging only, with neither timestamp nor original filename."""
    stream = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", compresslevel=9, fileobj=stream, mtime=0) as output:
        output.write(blob)
    result = stream.getvalue()
    need(gzip.decompress(result) == blob, "gzip round-trip mismatch")
    return result


def load(blob):
    def pairs(entries):
        result = {}
        for key, value in entries:
            need(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    def nonfinite(_):
        raise ValueError("nonfinite JSON value")
    return json.loads(blob, object_pairs_hook=pairs, parse_constant=nonfinite)


def hexbytes(value, length=None):
    need(type(value) is str and len(value) % 2 == 0
         and all(c in "0123456789abcdef" for c in value), "canonical hex")
    result = bytes.fromhex(value)
    need(length is None or len(result) == length, "hex length")
    return result


def hash_array(value):
    need(type(value) is list and len(value) == 32, "public hash array")
    for n in value: integer(n, 0, 255)


def decimal(value):
    need(type(value) is str and value.isascii() and value.isdigit()
         and str(int(value)) == value, "canonical decimal amount")
    return int(value)


def literal(value, expected):
    need(type(value) is str and value == expected, "unexpected static metadata text")


def fraction(value, optional=True):
    if value is None:
        need(optional, "missing required fraction")
        return
    fields(value, "numerator denominator", "exact fraction")
    integer(value["numerator"], -(2**64), 2**64); integer(value["denominator"], 1)


def counter(value, selective=False):
    fields(value, "correct eligible population nominal_percent realized_coverage rate" if selective
           else "correct eligible rate", "aggregate counter")
    integer(value["eligible"], 0, 64); integer(value["correct"], 0, value["eligible"])
    fraction(value["rate"])
    if selective:
        integer(value["population"], value["eligible"], 64)
        need(type(value["nominal_percent"]) is int and value["nominal_percent"] in (5, 10, 25), "coverage percent")
        fraction(value["realized_coverage"])


def warnings(value, outer=False):
    need(type(value) is list, "warning list")
    for row in value:
        need(type(row) is dict and row.get("kind") in ("absolute", "selective", "prior_advantage"), "warning kind")
        names = "variant stratum metric kind cap " + ("difference" if row["kind"] == "prior_advantage" else "rate")
        if row["kind"] == "selective": names += " nominal_percent"
        if outer: names += " profile horizon"
        fields(row, names, "aggregate warning")
        need(row["variant"] in VARIANTS and row["stratum"] in STRATA
             and row["metric"] in (*METRICS, "selective_relationship"), "warning metric scope")
        fraction(row["cap"], False)
        fraction(row["difference"] if row["kind"] == "prior_advantage" else row["rate"], False)
        if row["kind"] == "selective":
            need(type(row["nominal_percent"]) is int and row["nominal_percent"] in (5, 10, 25), "warning coverage")
        if outer: need(row["profile"] in PROFILES and row["horizon"] in ("creation", "cashout", "final"), "warning horizon")


def relative(name):
    need(type(name) is str and name and "\\" not in name, "relative path")
    p = PurePosixPath(name)
    need(not p.is_absolute() and ".." not in p.parts and str(p) == name, "canonical contained path")
    return p


def checked(path, directory=False):
    path = Path(path).absolute()
    need(".." not in path.parts and all(not p.is_symlink() for p in (path, *path.parents)),
         "symlink or parent traversal")
    need(path.is_dir() if directory else path.is_file(), "missing/nonregular artifact")
    return path


def child(root, name):
    return Path(root).joinpath(*relative(name).parts)


def allowed(points=()):
    names = {"freeze.json", "policy.json", "native-source.patch", "controls.json", "generation.json",
             "generation-process.json", "seed-commitment.json", "native/native-result.json",
             "native/execution-pins-before.json", "native/execution-pins-after.json",
             "native/public/native-ledger.json", "native/public/final-replay.json", "native-replay.json",
             "replay-process.json", "predictions.json", "prediction-batch.json", "completion.json"}
    names.update("code/"+n for n in SOURCES)
    names.update("notes/"+n for n in NOTES)
    names.update("native/public/final/"+n for n in NATIVE)
    names.update("native/private/views/"+p+".json" for p in PROFILES)
    labels = ["controls", "score"]
    for end in points:
        integer(end, 0, 65535)
        prefix = f"inputs/prefix-{end:04d}/"
        names.update(prefix+n+".json" for n in ("raw", "directory", "timing", *PROFILES))
        for profile in PROFILES:
            label = f"observe-{end:04d}-{profile}"
            labels.append(label)
            names.add("runs/"+label+"/prediction-seal.json")
    names.update("inputs/final/"+n+".json" for n in ("raw", "directory", "timing"))
    for label in labels:
        names.update(f"runs/{label}/{n}.json" for n in ("result", "isolation", "inputs", "process"))
    return names


class Reader:
    def __init__(self, root):
        self.root = checked(root, True)
        self.allowed, self.blobs, self.pins = allowed(), {}, {}

    def path(self, name):
        need(name in self.allowed, "read outside closed public allowlist: " + str(name))
        return checked(child(self.root, name))

    def blob(self, name):
        if name not in self.blobs:
            blob = self.path(name).read_bytes()
            need(name not in self.pins or self.pins[name] == sha(blob), "artifact changed before read")
            self.blobs[name] = blob
            self.pins[name] = sha(blob)
        return self.blobs[name]

    def read(self, name):
        return load(self.blob(name))

    def hash(self, name):
        if name in self.blobs:
            return sha(self.blobs[name])
        h = hashlib.sha256()
        with self.path(name).open("rb") as stream:
            for block in iter(lambda: stream.read(1024*1024), b""):
                h.update(block)
        result = h.hexdigest()
        need(name not in self.pins or self.pins[name] == result, "artifact changed during verification")
        self.pins[name] = result
        return result

    def unchanged(self):
        for name, expected in self.pins.items():
            h = hashlib.sha256()
            with self.path(name).open("rb") as stream:
                for block in iter(lambda: stream.read(1024*1024), b""):
                    h.update(block)
            need(h.hexdigest() == expected, "artifact changed during export: " + name)


def time(value):
    result = datetime.fromisoformat(value)
    need(result.tzinfo is not None, "timezone required")
    return result


def process(value):
    fields(value, "started_utc ended_utc returncode", "process receipt")
    need(type(value["returncode"]) is int and value["returncode"] == 0
         and time(value["started_utc"]) <= time(value["ended_utc"]), "failed or invalid process")


def isolation(value, mode, mounts):
    fields(value, "interfaces home_accessible mode inputs private_truth_mounted private_seed_mounted wallet_backup_mounted", "isolation")
    need(value == dict(interfaces=["lo"], home_accessible=False, mode=mode, inputs=list(mounts),
                      private_truth_mounted=mode == "_score", private_seed_mounted=False,
                      wallet_backup_mounted=False), "isolation boundary changed")


def point(value):
    fields(value, "transactionId index", "native point")
    hexbytes(value["transactionId"], 32)
    return value["transactionId"], integer(value["index"], 0, 2**32-1)


def transaction(value):
    fields(value, "version id inputs outputs lockTime subnetworkId gas payload storageMass", "native transaction")
    hexbytes(value["id"], 32); hexbytes(value["payload"]); hexbytes(value["subnetworkId"], 20)
    integer(value["version"]); decimal(value["lockTime"]); decimal(value["gas"]); decimal(value["storageMass"])
    need(type(value["inputs"]) is list and type(value["outputs"]) is list, "native lists")
    for item in value["inputs"]:
        fields(item, "previousOutpoint signatureScript sequence sigOpCount computeBudget", "native input")
        point(item["previousOutpoint"]); hexbytes(item["signatureScript"])
        decimal(item["sequence"]); integer(item["sigOpCount"]); integer(item["computeBudget"])
    for item in value["outputs"]:
        fields(item, "value scriptPublicKey covenant", "native output")
        need(item["covenant"] is None, "unsupported covenant metadata")
        hexbytes(item["scriptPublicKey"]); decimal(item["value"])


def view(value, profile):
    fields(value, "schema members receipts authored", "participant view")
    members = [] if profile == "C" else list(range(8)) if profile == "pooled" else [int(profile[1:])]
    need(value["schema"] == "kpi-native-usage-view-v1" and value["members"] == members
         and all(type(n) is int for n in value["members"]),
         "undeclared participant disclosure")
    for row in value["receipts"]:
        fields(row, "owner position value", "receipt")
        need(type(row["owner"]) is int and row["owner"] in members, "honest receipt not allowed")
        integer(row["position"]); integer(row["value"], 60_000_000)
    for row in value["authored"]:
        fields(row, "owner event_id inputs outputs", "authored disclosure")
        need(type(row["owner"]) is int and row["owner"] in members, "honest authored record not allowed")
        hexbytes(row["event_id"], 32)
        for p in row["inputs"]:
            integer(p)
        for output in row["outputs"]:
            fields(output, "position value recipient", "authored output")
            integer(output["position"]); integer(output["value"])
            need(output["recipient"] is None or type(output["recipient"]) is int and 0 <= output["recipient"] < 32,
                 "authored recipient")


def modes(raw):
    result = []
    for tx in raw["lineage"][1:]:
        payload = hexbytes(tx["payload"], 5228)
        need(payload[:8] == b"KPICR06\0" and payload[8:16] == b"KPICU06\0", "v6 payload framing")
        result.append(integer(payload[212], 0, 2))
    return result


def prefixes(raw, directory, timing, full_view, end, operation_modes):
    """Independent reconstruction, including the exact frozen JSON byte format."""
    lineage = raw["lineage"][:end+2]
    points = {point(lineage[0]["inputs"][0]["previousOutpoint"])}
    points.update(point(lineage[i+1]["inputs"][1]["previousOutpoint"])
                  for i, mode in enumerate(operation_modes[:end+1]) if mode == 0)
    ids = {x[0] for x in points}
    r = {**raw, "lineage": lineage, "parents": [p for p in raw["parents"] if p["id"] in ids]}
    d = {**directory, "entries": [e for e in directory["entries"] if (e["transaction_id"], e["index"]) in points]}
    count = 1 + 2*sum(mode != 2 for mode in operation_modes[:end+1])
    events = {tx["id"] for tx in lineage[1:]}
    v = {**full_view, "receipts": [r for r in full_view["receipts"] if r["position"] < count],
         "authored": [r for r in full_view["authored"] if r["event_id"] in events]}
    t = {**timing, "events": timing["events"][:end+1]}
    return r, d, v, t


def prediction(value, profile, end):
    fields(value, "schema complete raw_sha256 directory_sha256 view_sha256 timing_sha256 policy_sha256 profile through_event rows boundary diagnostics", "prediction")
    need(value["schema"] == "kpi-native-usage-predictions-v1" and value["complete"] is True
         and value["profile"] == profile and value["through_event"] == end, "prediction scope")
    for row in value["rows"]:
        fields(row, "event event_id guesses", "predicted row")
        integer(row["event"]); hexbytes(row["event_id"], 32)
        fields(row["guesses"], VARIANTS, "fixed variants")
        for guess in row["guesses"].values():
            fields(guess, "sender recipient amount relationship_rank", "guess")
            integer(guess["sender"], 0, 31); integer(guess["recipient"], 0, 31); integer(guess["amount"])
            need(type(guess["relationship_rank"]) is list and len(guess["relationship_rank"]) == 4,
                 "rank length")
            for n in guess["relationship_rank"]:
                integer(n, -(2**63)+1, 2**63-1)
    for edge in value["boundary"]:
        fields(edge, "transaction_id index source_event source_outpoint destination_owner source_owner_guess same_owner_guess", "predicted native boundary")
        fields(edge["source_outpoint"], "transaction_id index", "boundary outpoint")
        hexbytes(edge["transaction_id"], 32); integer(edge["index"]); integer(edge["source_event"])
        hexbytes(edge["source_outpoint"]["transaction_id"], 32); integer(edge["source_outpoint"]["index"])
        for name in ("destination_owner", "source_owner_guess"):
            need(edge[name] is None or type(edge[name]) is int and 0 <= edge[name] < 32, "boundary owner guess")
        need(edge["same_owner_guess"] is None or type(edge["same_owner_guess"]) is bool, "boundary hypothesis")
    d = value["diagnostics"]
    fields(d, "input_sha256 equality zero_padding layouts event_ids timing equality_meaning bridge_meaning validation chain_acceptance_verified transaction_size_meaning", "public diagnostics")
    fields(d["input_sha256"], "raw directory view timing policy", "diagnostic input pins")
    for pin in d["input_sha256"].values(): hexbytes(pin, 32)
    for row in d["layouts"]:
        fields(row, "event event_id mode canonical_json_bytes payload_bytes signature_bytes ciphertext_bytes proof_bytes authorization_bytes inputs outputs", "public byte layout")
        hexbytes(row["event_id"], 32)
        for name, item in row.items():
            if name == "event_id": continue
            if name in ("signature_bytes", "ciphertext_bytes"):
                need(type(item) is list, "byte length list")
                for n in item: integer(n)
            else: integer(item)
    fields(d["equality"], "commitment_positions nonzero_nullifiers nonzero_ciphertexts nonzero_ciphertext_ephemeral_prefixes proofs funding_and_payout_scripts", "public equality")
    for name, groups in d["equality"].items():
        need(type(groups) is list, "equality groups")
        for group in groups:
            fields(group, "value occurrences", "equality group")
            hexbytes(group["value"])
            need(type(group["occurrences"]) is list, "public occurrences")
            for label in group["occurrences"]:
                if name in ("commitment_positions", "proofs"): integer(label)
                else:
                    pattern = r"founding-input|event-[0-9]+-(funding|payout)" if name == "funding_and_payout_scripts" else r"event-[0-9]+-slot-[01]"
                    need(type(label) is str and re.fullmatch(pattern, label) is not None, "public occurrence label")
    fields(d["zero_padding"], "authorization_commitment_slots authorization_nullifier_slots ciphertext_slots note_values", "public padding")
    for name, item in d["zero_padding"].items():
        if name == "note_values":
            literal(item, PADDING_TEXT)
        else:
            need(type(item) is list and all(type(x) is str and re.fullmatch(r"event-[0-9]+-slot-[01]", x) for x in item), "public padding labels")
    for event in d["event_ids"]: hexbytes(event, 32)
    for name, text in DIAGNOSTIC_TEXT.items():
        literal(d[name], text)
    need(d["chain_acceptance_verified"] is False, "unsupported chain claim")


def accounting(value):
    fields(value, ACCOUNTING, "native accounting")
    for name, n in value.items():
        if name == "whole_experiment_conserved":
            need(n is True, "native conservation incomplete")
        else:
            integer(n)


def replay_record(record, full=False):
    fields(record, ("transaction" if full else "transaction_id")+" full_hash authorization_sha256 proof_sha256", "replay record")
    for name in ("full_hash", "authorization_sha256", "proof_sha256"):
        need(name == "full_hash" or record[name] is None or type(record[name]) is str, "replay hash")
        if record[name] is not None: hexbytes(record[name], 32)
    if full: transaction(record["transaction"])
    else: hexbytes(record["transaction_id"], 32)


def replay_summary(value):
    fields(value, "scope chain_acceptance_verified bootstrap_validated transactions drained state reserve accounting records", "native replay summary")
    need(value["chain_acceptance_verified"] is False and value["bootstrap_validated"] is True
         and value["drained"] is True and value["reserve"] is None, "terminal summary scope")
    literal(value["scope"], REPLAY_SCOPE)
    fields(value["state"], "cm_count nf_count cm_root nf_root history_root", "compact public state")
    for key in ("cm_count", "nf_count"): integer(value["state"][key])
    for key in ("cm_root", "nf_root", "history_root"): hash_array(value["state"][key])
    fields(value["accounting"], "initial_reserve_sompi admitted_sompi paid_sompi pool_fees_sompi remaining_reserve_sompi founding_input_sompi founding_change_sompi founding_fee_sompi", "pool accounting")
    for n in value["accounting"].values(): decimal(n)
    for record in value["records"]: replay_record(record)


def aggregate(value):
    """Reject private extensions: score contents are counters, not target rows."""
    fields(value, "schema complete status qualification_pass independent_histories raw_sha256 directory_sha256 timing_sha256 policy_sha256 predictions_sha256 checked profiles observed_primary_warnings validated_disclosure_search_performed limits", "aggregate score")
    need(value["schema"] == "kpi-native-usage-score-v1" and value["complete"] is True
         and value["qualification_pass"] is False and value["independent_histories"] == 1
         and value["status"] in ("observed-finite-case-cap-warning", "completed-native-screen-no-observed-primary-warning")
         and value["validated_disclosure_search_performed"] is False, "incomplete or unsupported score")
    fields(value["checked"], "native_accounting private_ledger usage_policy required_activity cashout_modes fixed_truth observation_prefixes predictions target_profile_horizons", "score checks")
    c = value["checked"]
    for name in ("observation_prefixes", "predictions", "target_profile_horizons"): integer(c[name], 1)
    accounting(c["native_accounting"])
    fields(c["private_ledger"], "complete note_positions positive_claims pool_fees_sompi full_drainage one_input_payments two_input_payments", "private ledger aggregates")
    for name, item in c["private_ledger"].items():
        if name in ("complete", "full_drainage"): need(item is True, "private ledger incomplete")
        else: integer(item)
    fields(c["usage_policy"], "complete passed payments roles bridges payments_with_noncapital_input payments_spending_payment_receipts payments_spending_readmission_credits full_drainage accounting scope", "policy aggregates")
    accounting(c["usage_policy"]["accounting"])
    for name, item in c["usage_policy"].items():
        if name == "accounting": continue
        if name == "scope":
            literal(item, "policy/native graph and actual wallet receipt-scan consistency; Rust verifies proofs and native scripts")
        elif name in ("complete", "passed", "full_drainage"): need(item is True, "usage incomplete")
        else: integer(item)
    fields(c["required_activity"], "complete counts missing scope", "activity aggregates")
    fields(c["required_activity"]["counts"], "payments_with_noncapital_input payments_spending_payment_receipts payments_spending_readmission_credits one_input_payments two_input_payments", "activity counts")
    need(c["required_activity"]["complete"] is True and c["required_activity"]["missing"] == [], "required activity missing")
    for item in c["required_activity"]["counts"].values(): integer(item, 0, 64)
    literal(c["required_activity"]["scope"], "Missing required activity leaves this retained attempt incomplete; never resample.")
    fields(c["cashout_modes"], "prompt accumulated retain", "mode counts")
    for item in c["cashout_modes"].values(): integer(item, 0, 32)
    fields(c["fixed_truth"], "complete cp_sat z3 models scope", "fixed truth status")
    need(c["fixed_truth"]["complete"] is True and c["fixed_truth"]["cp_sat"] == c["fixed_truth"]["z3"] == "SAT", "truth relation incomplete")
    integer(c["fixed_truth"]["models"], 1, 1)
    literal(c["fixed_truth"]["scope"], "Final concrete witness only; private admission owners pinned, no reconstruction or uniqueness search")
    fields(value["profiles"], PROFILES, "profile aggregates")
    for profile in value["profiles"].values():
        fields(profile, "creation cashout final native_boundary_final", "horizon aggregates")
        fields(profile["native_boundary_final"], "edges same_owner_true cross_user_true guesses abstentions true_positive false_positive true_negative false_negative source_owner_correct source_owner_guesses", "boundary counters")
        for item in profile["native_boundary_final"].values(): integer(item, 0, 4)
        for horizon in ("creation", "cashout", "final"):
            h = profile[horizon]
            fields(h, "complete targets known_exclusions variants primary_prior_advantages observed_primary_warnings diagnostic_exceedances", "horizon result")
            need(h["complete"] is True and h["targets"] == 64, "horizon incomplete")
            fields(h["known_exclusions"], METRICS, "known counts")
            for item in h["known_exclusions"].values(): integer(item, 0, 64)
            fields(h["variants"], VARIANTS, "variant aggregates")
            for variant in h["variants"].values():
                fields(variant, STRATA, "strata")
                for stratum in variant.values():
                    fields(stratum, (*METRICS, "selective_relationship"), "metric aggregates")
                    for metric in METRICS:
                        counter(stratum[metric])
                    fields(stratum["selective_relationship"], ("5", "10", "25"), "ranked coverage")
                    for item in stratum["selective_relationship"].values(): counter(item, True)
            fields(h["primary_prior_advantages"], VARIANTS[1:], "paired variants")
            for variant in h["primary_prior_advantages"].values():
                fields(variant, ("sender", "recipient", "amount_within_10pct"), "paired metrics")
                for comparison in variant.values():
                    fields(comparison, "difference eligible cap", "paired comparison")
                    integer(comparison["eligible"], 0, 64); fraction(comparison["difference"]); fraction(comparison["cap"], False)
            warnings(h["observed_primary_warnings"]); warnings(h["diagnostic_exceedances"])
    warnings(value["observed_primary_warnings"], True)
    need(value["limits"] == [
        "One dependent synthetic usage scenario with genuine offline native bytes, not a population qualification.",
        "Observed cap warnings are descriptive; no confidence intervals or statistically certified breaches.",
        "Heuristic hits and native value-flow edges are not forced internal disclosures or common-owner facts.",
        "Native signature/proof checks, freeze identity and sealing barrier are caller prerequisites; no accepted-chain claim."],
        "score limits changed")
    # A final recursive key allowlist closes all nested rational/warning records.
    keys = set("schema complete status qualification_pass independent_histories raw_sha256 directory_sha256 timing_sha256 policy_sha256 predictions_sha256 checked profiles observed_primary_warnings validated_disclosure_search_performed limits native_accounting private_ledger usage_policy required_activity cashout_modes fixed_truth observation_prefixes predictions target_profile_horizons note_positions positive_claims pool_fees_sompi full_drainage one_input_payments two_input_payments passed payments roles bridges payments_with_noncapital_input payments_spending_payment_receipts payments_spending_readmission_credits accounting scope counts missing prompt accumulated retain cp_sat z3 models creation cashout final native_boundary_final edges same_owner_true cross_user_true guesses abstentions true_positive false_positive true_negative false_negative source_owner_correct source_owner_guesses targets known_exclusions variants primary_prior_advantages diagnostic_exceedances selective_relationship correct eligible rate population nominal_percent realized_coverage difference cap numerator denominator variant stratum metric kind profile horizon".split())
    keys.update(ACCOUNTING.split()); keys.update(PROFILES); keys.update(VARIANTS); keys.update(STRATA); keys.update(METRICS); keys.update(("5", "10", "25"))
    def visit(item):
        if type(item) is dict:
            need(set(item) <= keys, "unexpected private extension in aggregate")
            for v in item.values(): visit(v)
        elif type(item) is list:
            for v in item: visit(v)
        else:
            need(item is None or type(item) in (str, int, bool), "unexpected aggregate leaf")
    visit(value)


def verify(reader):
    need(reader.hash("freeze.json") == FREEZE, "wrong frozen attempt")
    frozen = reader.read("freeze.json")
    fields(frozen, "schema frozen_utc base_commit sources notes candidate_files native_source_patch_sha256 binaries policy_sha256 parameter_root parameters dependency_root dependencies scope scoring_barrier qualification_pass trust", "freeze")
    need(frozen["schema"] == "kpi-native-usage-freeze-v1" and frozen["base_commit"] == BASE
         and frozen["qualification_pass"] is False, "freeze scope")
    fields(frozen["sources"], SOURCES, "frozen source roster"); fields(frozen["notes"], NOTES, "frozen note roster")
    for folder, pins in (("code", frozen["sources"]), ("notes", frozen["notes"])):
        for name, pin in pins.items():
            need(reader.hash(folder+"/"+name) == pin, "frozen file drift: " + name)
    need(reader.hash("native-source.patch") == frozen["native_source_patch_sha256"]
         and reader.hash("policy.json") == frozen["policy_sha256"], "patch/policy drift")
    completion = reader.read("completion.json")
    fields(completion, "complete completed_utc status prediction_batch_sha256 score_sha256 native_replay_sha256 proof_count observed_prefixes observed_profiles independent_histories qualification_pass", "completion")
    need(completion["complete"] is True and completion["qualification_pass"] is False
         and completion["independent_histories"] == 1 and completion["observed_profiles"] == 10,
         "incomplete experiment")
    generation = reader.read("generation.json")
    fields(generation, "complete completed_utc freeze_sha256 native_result_sha256 seed_commitment_sha256", "generation receipt")
    need(generation["complete"] is True and generation["freeze_sha256"] == FREEZE
         and generation["native_result_sha256"] == reader.hash("native/native-result.json")
         and generation["seed_commitment_sha256"] == reader.hash("seed-commitment.json"), "generation identity")
    generation_completed = time(generation["completed_utc"])
    seed_commitment = reader.read("seed-commitment.json")
    fields(seed_commitment, "sampled_utc freeze_sha256 seed_file_sha256", "seed commitment")
    need(seed_commitment["freeze_sha256"] == FREEZE
         and time(frozen["frozen_utc"]) <= time(seed_commitment["sampled_utc"]), "freeze after sampling")
    hexbytes(seed_commitment["seed_file_sha256"], 32)  # Never open that private file.
    native = reader.read("native/native-result.json")
    fields(native, "schema completed public_dir truth_file views_dir native_ledger_file native_ledger_sha256 policy_sha256 policy_canonical_sha256 truth_sha256 views_sha256 public_files proof_count genuine_proof_count checked accounting original_backups_unchanged chain_acceptance_verified elapsed_seconds", "native provenance")
    need(native["schema"] == "kpi-native-usage-generation-v1" and native["completed"] is True
         and native["public_dir"] == "public/final" and native["truth_file"] == "private/truth.json"
         and native["views_dir"] == "private/views" and native["native_ledger_file"] == "public/native-ledger.json"
         and native["chain_acceptance_verified"] is False and native["original_backups_unchanged"] is True
         and native["proof_count"] == native["genuine_proof_count"] == completion["proof_count"], "native scope")
    hexbytes(native["truth_sha256"], 32)
    need(type(native["elapsed_seconds"]) in (int, float) and math.isfinite(native["elapsed_seconds"])
         and native["elapsed_seconds"] >= 0, "native elapsed seconds")
    fields(native["public_files"], NATIVE, "native public roster")
    fields(native["views_sha256"], [p+".json" for p in PROFILES], "participant roster")
    for name, pin in native["public_files"].items():
        need(reader.hash("native/public/final/"+name) == pin, "native public drift")
    views = {}
    for profile in PROFILES:
        name = "native/private/views/"+profile+".json"
        need(reader.hash(name) == native["views_sha256"][profile+".json"], "participant view drift")
        views[profile] = reader.read(name); view(views[profile], profile)
    for profile in PROFILES:
        members = views[profile]["members"]
        need(views[profile]["receipts"] == [r for r in views["pooled"]["receipts"] if r["owner"] in members]
             and views[profile]["authored"] == [r for r in views["pooled"]["authored"] if r["owner"] in members],
             "individual/public participant projections disagree with pooled disclosures")
    policy = reader.read("policy.json")
    need(native["policy_sha256"] == frozen["policy_sha256"] and native["policy_canonical_sha256"] == canonical(policy), "native policy pin")
    raw = {name: reader.read("native/public/final/"+name+".json") for name in ("descriptor", "lineage", "parents")}
    raw = dict(descriptor=raw["descriptor"], vk_hex=reader.blob("native/public/final/vk.bin").hex(),
               lineage=raw["lineage"], parents=raw["parents"])
    fields(raw["descriptor"], "format network genesis domain initial_commitment initial_value_sompi vk_sha256 funding_txid funding_full_hash", "public descriptor")
    literal(raw["descriptor"]["format"], "kpi-v6-public-replay-v1")
    literal(raw["descriptor"]["network"], "testnet-10")
    literal(raw["descriptor"]["genesis"], "f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370")
    decimal(raw["descriptor"]["initial_value_sompi"])
    for key in ("vk_sha256", "funding_txid", "funding_full_hash"): hexbytes(raw["descriptor"][key], 32)
    for key in ("domain", "initial_commitment"): hash_array(raw["descriptor"][key])
    need(sha(bytes.fromhex(raw["vk_hex"])) == frozen["parameters"]["vk_sha256"], "verification key identity")
    for tx in raw["lineage"] + raw["parents"]: transaction(tx)
    op_modes = modes(raw)
    need(len(op_modes) == completion["proof_count"] and op_modes[0] == 1, "pool operation count")
    targets = [i for i, mode in enumerate(op_modes) if i and mode == 1]
    need(len(targets) == 64, "ordinary PAY coverage")
    points = sorted({len(op_modes)-1, *targets,
                     *(next((j for j in range(i+1, len(op_modes)) if op_modes[j] == 2), len(op_modes)-1) for i in targets)})
    reader.allowed = allowed(points)
    directory = reader.read("native/public/final/directory.json")
    timing = reader.read("native/public/final/timing.json")
    fields(directory, "schema roles adversaries entries", "initial directory")
    literal(directory["schema"], "kpi-native-usage-directory-v1")
    need(directory["roles"] == list(range(32)) and directory["adversaries"] == list(range(8)), "role roster")
    for row in directory["entries"]:
        fields(row, "transaction_id index owner", "directory entry")
        hexbytes(row["transaction_id"], 32); integer(row["index"]); integer(row["owner"], 0, 31)
    fields(timing, "schema events", "modeled timing")
    literal(timing["schema"], "kpi-native-usage-timing-v1")
    for row in timing["events"]:
        fields(row, "event_id minute", "modeled time")
        hexbytes(row["event_id"], 32); integer(row["minute"])
    need([r["event_id"] for r in timing["events"]] == [t["id"] for t in raw["lineage"][1:]], "modeled timing order")
    ledger = reader.read("native/public/native-ledger.json")
    need(reader.hash("native/public/native-ledger.json") == native["native_ledger_sha256"], "native ledger pin")
    fields(ledger, "schema synthetic_inputs validations scope", "native ledger")
    literal(ledger["scope"], "synthetic initial context; every ordinary and pool spend validated against exact input outputs; global once-only outpoints")
    need(ledger["schema"] == "kpi-native-usage-native-ledger-v1" and len(ledger["synthetic_inputs"]) == 32, "native context coverage")
    for row in ledger["synthetic_inputs"]:
        fields(row, "txid index amount spk daa is_coinbase", "synthetic UTXO context")
        hexbytes(row["txid"], 32); integer(row["index"]); decimal(row["amount"]); hexbytes(row["spk"]); decimal(row["daa"])
        need(row["is_coinbase"] is False, "ordinary synthetic context")
    validations = {}
    for row in ledger["validations"]:
        fields(row, "transaction_id native_validation_passed chain_acceptance_verified fee_sompi full_hash", "native validation receipt")
        hexbytes(row["transaction_id"], 32); hexbytes(row["full_hash"], 32); decimal(row["fee_sompi"])
        need(row["native_validation_passed"] is True and row["chain_acceptance_verified"] is False
             and row["transaction_id"] not in validations, "native validation scope/duplicate")
        validations[row["transaction_id"]] = row
    need(set(validations) == {t["id"] for t in raw["lineage"] + raw["parents"]}, "native transaction validation coverage")
    replay = reader.read("native-replay.json")
    fields(replay, "scope chain_acceptance_verified bootstrap_validated state reserve accounting records", "native replay")
    literal(replay["scope"], REPLAY_SCOPE)
    need(replay["chain_acceptance_verified"] is False and replay["bootstrap_validated"] is True and replay["reserve"] is None
         and [r["transaction"] for r in replay["records"]] == raw["lineage"], "terminal native replay")
    fields(replay["state"], "commitments nullifiers roots", "full public state")
    for key in ("commitments", "roots"):
        for h in replay["state"][key]: hash_array(h)
    for leaf in replay["state"]["nullifiers"]:
        fields(leaf, "value next_index next_value", "public indexed nullifier leaf")
        hash_array(leaf["value"]); hash_array(leaf["next_value"]); integer(leaf["next_index"])
    for record in replay["records"]:
        replay_record(record, True)
        need(record["full_hash"] == validations[record["transaction"]["id"]]["full_hash"], "native fullhash disagreement")
    summary = reader.read("native/public/final-replay.json"); replay_summary(summary)
    need(summary["transactions"] == len(raw["lineage"]) and summary["accounting"] == replay["accounting"]
         and summary["records"] == [dict(transaction_id=r["transaction"]["id"], **{k: v for k, v in r.items() if k != "transaction"})
                                     for r in replay["records"]], "independent replay summary disagreement")
    checkpoint = reader.read("native/public/final/checked.json")
    fields(checkpoint, "head replay", "native checkpoint")
    head = reader.read("native/public/final/head.json")
    fields(head, "transaction_count last_full_hash", "public head")
    need(checkpoint["head"] == head and checkpoint["replay"] == summary
         and head["transaction_count"] == len(raw["lineage"])
         and head["last_full_hash"] == replay["records"][-1]["full_hash"], "checkpoint/fullhash binding")
    need(completion["native_replay_sha256"] == reader.hash("native-replay.json"), "independent replay pin")
    replay_process = reader.read("replay-process.json")
    fields(replay_process, "returncode completed_utc", "independent replay process")
    need(type(replay_process["returncode"]) is int and replay_process["returncode"] == 0,
         "independent replay process failed")
    replay_ended = time(replay_process["completed_utc"])
    need(generation_completed <= replay_ended, "replay predates completed generation")
    pins = reader.read("native/execution-pins-before.json")
    fields(pins, "wallet helper replay generator lifecycle_driver sampler decoder", "execution pins")
    need(pins == reader.read("native/execution-pins-after.json"), "execution identity drift")
    for name in ("wallet", "helper", "replay"): need(pins[name] == frozen["binaries"][name]["sha256"], "binary pin mismatch")
    for name, source in (("generator", "native_usage_generate.py"), ("lifecycle_driver", "two-input-lifecycle.py"),
                         ("sampler", "population_privacy_workload.py"), ("decoder", "early_privacy_surface.py")):
        need(pins[name] == frozen["sources"][source], "execution source mismatch")
    batch = reader.read("prediction-batch.json")
    fields(batch, "schema complete sealed_utc scoring_started freeze_sha256 generation_sha256 predictions_sha256 profiles through_events records", "prediction batch")
    need(batch["schema"] == "kpi-native-usage-prediction-batch-v1" and batch["complete"] is True
         and batch["scoring_started"] is False and batch["freeze_sha256"] == FREEZE
         and batch["generation_sha256"] == reader.hash("generation.json") and batch["profiles"] == list(PROFILES)
         and batch["through_events"] == points and completion["observed_prefixes"] == len(points)
         and completion["prediction_batch_sha256"] == reader.hash("prediction-batch.json")
         and batch["predictions_sha256"] == reader.hash("predictions.json"), "sealed prediction batch")
    predictions = reader.read("predictions.json")
    expected = [(profile, end) for end in points for profile in PROFILES]
    need(len(predictions) == len(batch["records"]) == len(expected), "complete prediction roster")
    for (profile, end), entry, item in zip(expected, predictions, batch["records"], strict=True):
        fields(entry, "profile through_event prediction", "combined prediction")
        need((entry["profile"], entry["through_event"]) == (profile, end), "prediction order/identity")
        p = entry["prediction"]; prediction(p, profile, end)
        label = f"observe-{end:04d}-{profile}"; base = "runs/"+label+"/"
        fields(item, "label seal seal_sha256", "batch seal")
        need(item["label"] == label and item["seal_sha256"] == reader.hash(base+"prediction-seal.json")
             and item["seal"] == reader.read(base+"prediction-seal.json"), "individual seal identity")
        seal = item["seal"]
        fields(seal, "profile through_event sealed_utc freeze_sha256 generation_sha256 prediction_sha256 inputs", "prediction seal")
        need((seal["profile"], seal["through_event"]) == (profile, end)
             and seal["freeze_sha256"] == FREEZE and seal["generation_sha256"] == reader.hash("generation.json")
             and seal["prediction_sha256"] == reader.hash(base+"result.json") == sha(encoded(p)), "prediction byte identity")
        r, d, v, t = prefixes(raw, directory, timing, views[profile], end, op_modes)
        data = (r, d, v, t, policy)
        input_pins = {mount: sha(encoded(value)) for mount, value in zip(OBS_INPUTS, data, strict=True)}
        # Policy is copied verbatim, not re-serialized by the runner.
        input_pins["/policy.json"] = frozen["policy_sha256"]
        need(seal["inputs"] == reader.read(base+"inputs.json") == input_pins, "reconstructed prefix input hashes")
        for name, value in zip(("raw", "directory", profile, "timing"), data[:4], strict=True):
            need(reader.hash(f"inputs/prefix-{end:04d}/{name}.json") == sha(encoded(value)), "prefix input drift")
        need([p[name+"_sha256"] for name in ("raw", "directory", "view", "timing", "policy")]
             == [canonical(value) for value in data], "prediction canonical input binding")
        need(p["diagnostics"]["input_sha256"] == {name: canonical(value) for name, value in
             zip(("raw", "directory", "view", "timing", "policy"), data, strict=True)}
             and p["diagnostics"]["event_ids"] == [tx["id"] for tx in r["lineage"][1:]],
             "public diagnostic prefix binding")
        need([row["event"] for row in p["rows"]] == [i for i in targets if i <= end], "visible target coverage")
        isolation(reader.read(base+"isolation.json"), "_observe", OBS_INPUTS)
        proc = reader.read(base+"process.json"); process(proc)
        need(replay_ended <= time(proc["started_utc"]) <= time(proc["ended_utc"])
             <= time(seal["sealed_utc"]) <= time(batch["sealed_utc"]), "prediction seal chronology")
    score = reader.read("runs/score/result.json"); aggregate(score)
    need(completion["score_sha256"] == reader.hash("runs/score/result.json") and completion["status"] == score["status"], "score completion pin")
    need(score["raw_sha256"] == canonical(raw) and score["directory_sha256"] == canonical(directory)
         and score["timing_sha256"] == canonical(timing) and score["policy_sha256"] == canonical(policy)
         and score["predictions_sha256"] == canonical(predictions), "scorer input identity")
    need(score["checked"]["native_accounting"] == native["accounting"]
         and score["checked"]["usage_policy"] == native["checked"], "native/scorer aggregate agreement")
    fields(reader.read("runs/score/inputs.json"), SCORE_INPUTS, "score input pins")
    expected_inputs = {"/raw.json": sha(encoded(raw)), "/directory.json": sha(encoded(directory)),
                       "/timing.json": sha(encoded(timing)), "/policy.json": frozen["policy_sha256"],
                       "/truth.json": native["truth_sha256"], "/predictions.json": reader.hash("predictions.json")}
    need(reader.read("runs/score/inputs.json") == expected_inputs, "score input hashes")
    for name, value in (("raw", raw), ("directory", directory), ("timing", timing)):
        need(reader.hash("inputs/final/"+name+".json") == sha(encoded(value)), "final scorer public input drift")
    isolation(reader.read("runs/score/isolation.json"), "_score", SCORE_INPUTS)
    scored = reader.read("runs/score/process.json"); process(scored)
    need(time(batch["sealed_utc"]) <= time(scored["started_utc"]) <= time(scored["ended_utc"])
         <= time(completion["completed_utc"]), "all-predictions-before-score barrier")
    process(reader.read("generation-process.json"))
    control = reader.read("controls.json")
    fields(control, "passed completed_utc result_sha256 result", "control receipt")
    need(control["passed"] is True and control["result_sha256"] == reader.hash("runs/controls/result.json")
         and control["result"] == reader.read("runs/controls/result.json")
         and canonical(control["result"]) == CONTROL_RESULT
         and time(control["completed_utc"]) <= time(seed_commitment["sampled_utc"]), "controls before sampling")
    isolation(reader.read("runs/controls/isolation.json"), "_controls", ())
    need(reader.read("runs/controls/inputs.json") == {}, "control input closure")
    process(reader.read("runs/controls/process.json"))
    return frozen, native, points


README = """# Native usage privacy: public evidence

One dependent synthetic usage history, genuine offline native transactions and
proofs, 32 fresh wallets, eight declared colluders, 64 ordinary PAYs and four
transparent bridge controls. Synthetic source UTXOs and supplied accepted history
remain assumptions. This is not chain acceptance, human usage, cryptographic
certification or a population privacy qualification.

This package was made AFTER the experiment by `exporter/native_usage_export.py`.
The exporter is not part of the frozen observer, generator or scorer. It does not
read seeds, full truth, wallets, private requests, honest scans or private logs.
The only disclosed records from the private area are the predeclared C, P0–P7
and pooled participant views. Guess outputs and ranks are hypotheses, not truth.

`native/final` retains the eight exact public inputs; `native/native-ledger.json`
retains synthetic input contexts and per-transaction native validation receipts.
`native-replay.json` is the independently repeated pool replay. Native source is
reconstructible from the frozen base commit plus `native-source.patch`; build,
binary, parameter and dependency identities remain in the public freeze/pins.
Binaries, installed dependencies and proving parameters are not duplicated.

`predictions.json.gz` and `prediction-batch.json` preserve every prediction and seal.
The combined predictions are packaged with gzip level 9, zero timestamp and no
embedded filename. Decompressing reproduces the exact frozen `predictions.json`
bytes and SHA-256; compression changes no guesses, ranks, diagnostics or seals.
The manifest records both the compressed and uncompressed sizes and hashes.
Each run retains its seal, isolation, input-hash and process receipts. Reconstruct
any prefix from native/final, its declared final participant view and policy using
the frozen `native_usage_surface.prefix_inputs`: lineage through operation N,
only funding parents consumed by then, receipt positions born by then, authored
events visible by then and matching directory/timing prefixes. Serialize with
`json.dumps(value, indent=2, allow_nan=False) + '\\n'` to reproduce input file pins.
Individual result.json bytes are the same serialization of each corresponding
combined entry's `prediction`. The exporter checked both original and recreated
byte hashes. Duplicate prefix archives and individual predictions are omitted.

`freeze-public.json` removes only host parameter/dependency roots and adds explicit
derivative provenance. `native/provenance-public.json` removes private artifact
path fields, retaining hashes and aggregate results. All other exported originals
are byte-exact, with combined predictions byte-exact after decompression. Frozen
Markdown snapshots have `.txt` appended to preserve their
original bytes without presenting their old relative links as working local links.
See `export-manifest.json` for the exact original-to-export path/hash mapping.

The combined package contains final observations from every declared profile.
It must NOT be mounted wholesale as an early-prefix or individual observer input.
The score contains only aggregate counts and descriptive exact-fraction warnings;
all prediction seals precede its process start. Low rates are not a privacy pass.

Packaging reproduction after explicit authorization:
`python3 native_usage_export.py export RETAINED_ATTEMPT NEW_PUBLIC_DIRECTORY`
`python3 native_usage_export.py controls` runs public-only guard fixtures.
No output directory is overwritten. The retained attempt remains untouched.
"""


def export(source, destination):
    reader = Reader(source)
    frozen, native, points = verify(reader)
    destination = Path(destination).absolute()
    need(not destination.exists() and ".." not in destination.parts
         and all(not p.is_symlink() for p in (destination, *destination.parents))
         and not destination.is_relative_to(reader.root), "new external destination required")
    outputs, mapping = {}, []
    names = {"policy.json", "native-source.patch", "controls.json", "generation.json", "generation-process.json",
             "seed-commitment.json", "prediction-batch.json", "predictions.json", "completion.json",
             "native-replay.json", "replay-process.json", "native/public/native-ledger.json",
             "native/public/final-replay.json", "native/execution-pins-before.json", "native/execution-pins-after.json"}
    names.update("code/"+n for n in SOURCES); names.update("notes/"+n for n in NOTES)
    names.update("native/public/final/"+n for n in NATIVE)
    names.update("native/private/views/"+p+".json" for p in PROFILES)
    for label in ("controls", "score", *(f"observe-{end:04d}-{profile}" for end in points for profile in PROFILES)):
        names.update(f"runs/{label}/{n}.json" for n in ("isolation", "inputs", "process"))
        names.add(f"runs/{label}/" + ("prediction-seal.json" if label.startswith("observe-") else "result.json"))
    for name in sorted(names | {"freeze.json", "native/native-result.json"}):
        blob, target, treatment = reader.blob(name), name, "exact original"
        packaging = {}
        if name == "freeze.json":
            value = {k: v for k, v in frozen.items() if k not in ("parameter_root", "dependency_root")}
            value.update(export_derivative=True, original_sha256=FREEZE,
                         omitted_fields=["parameter_root", "dependency_root"])
            blob, target, treatment = encoded(value), "freeze-public.json", "explicit derivative"
        elif name == "native/native-result.json":
            omit = ("public_dir", "truth_file", "views_dir", "native_ledger_file")
            value = {k: v for k, v in native.items() if k not in omit}
            value.update(export_derivative=True, original_sha256=reader.hash(name), omitted_fields=list(omit))
            blob, target, treatment = encoded(value), "native/provenance-public.json", "explicit derivative"
        elif name.startswith("native/public/"):
            target = "native/"+name.removeprefix("native/public/")
        elif name.startswith("native/private/views/"):
            target = "views/"+name.removeprefix("native/private/views/")
        elif name == "predictions.json":
            packaging = dict(encoding="gzip", uncompressed_sha256=sha(blob),
                             uncompressed_bytes=len(blob))
            blob = compressed_exact(blob)
            target, treatment = "predictions.json.gz", "deterministic gzip of exact original"
        if target.endswith(".md"):
            target += ".txt"
        need(target not in outputs, "export path collision")
        outputs[target] = blob
        mapping.append(dict(source=name, destination=target, treatment=treatment,
                            source_sha256=reader.hash(name), exported_sha256=sha(blob), bytes=len(blob),
                            **packaging))
    tool = checked(__file__).read_bytes()
    outputs["exporter/native_usage_export.py"] = tool
    outputs["README.md"] = README.encode()
    manifest = dict(schema="kpi-native-usage-public-export-v1", original_freeze_sha256=FREEZE,
        post_run_packaging=True, exporter_sha256=sha(tool), complete=True, originals=mapping,
        verified_source_pins=reader.pins, reconstructed_prefixes=len(points), profiles=list(PROFILES),
        private_truth_read=False, private_seed_read=False, wallet_backups_read=False,
        private_operational_logs_read=False, combined_export_is_observer_input=False,
        omitted=["host roots", "private truth and seed bytes", "wallets", "actions", "honest scans", "operational logs",
                 "duplicate public prefixes/individual predictions", "binaries", "installed dependencies", "proving parameters"])
    outputs["export-manifest.json"] = encoded(manifest)
    outputs["SHA256SUMS"] = "".join(sha(blob)+"  "+name+"\n" for name, blob in sorted(outputs.items())).encode()
    reader.unchanged()
    destination.mkdir(mode=0o755)
    for name, blob in sorted(outputs.items()):
        path = child(destination, name)
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        with path.open("xb") as stream: stream.write(blob)
        need(checked(path).read_bytes() == blob, "export copy mismatch")
    reader.unchanged()
    return dict(exported=True, files=len(outputs), bytes=sum(map(len, outputs.values())),
                freeze_sha256=FREEZE, manifest_sha256=sha(outputs["export-manifest.json"]),
                post_run_packaging=True, qualification_pass=False)


def controls():
    tests = []
    def reject(fn, name):
        try: fn()
        except ValueError: tests.append(name)
        else: raise ValueError("guard accepted " + name)
    for name in ("/absolute", "../escape", "a/../b", "a//b", "a\\b", "./a"):
        reject(lambda: relative(name), "path-reject-"+name)
    with tempfile.TemporaryDirectory(prefix="kpi-public-export-control-") as temp:
        root = Path(temp); (root/"policy.json").write_text("{}")
        reader = Reader(root)
        need(reader.read("policy.json") == {}, "public read")
        for name in ("private/seed.json", "native/private/truth.json", "native/founder/backup.json",
                     "native/private/events.jsonl", "native/private/views/P8.json", "runs/score/stdout.log"):
            reject(lambda: reader.blob(name), "private-path-reject-"+name)
        (root/"code").symlink_to(root, target_is_directory=True)
        reject(lambda: reader.blob("code/native_usage_trial.py"), "symlink-ancestor-reject")
        (root/"policy.json").write_text('{"changed":true}')
        reject(reader.unchanged, "source-drift-reject")
    reject(lambda: load(b'{"x":1,"x":2}'), "duplicate-json-field-reject")
    reject(lambda: load(b'{"x":NaN}'), "nonfinite-json-reject")
    v = dict(schema="kpi-native-usage-view-v1", members=[0], receipts=[dict(owner=0, position=1, value=60_000_000)], authored=[])
    view(v, "P0")
    bad = copy.deepcopy(v); bad["receipts"][0]["owner"] = 8
    reject(lambda: view(bad, "P0"), "honest-receipt-disclosure-reject")
    bad = copy.deepcopy(v); bad["wallet_backup"] = {}
    reject(lambda: view(bad, "P0"), "view-private-extension-reject")
    isolation(dict(interfaces=["lo"], home_accessible=False, mode="_observe", inputs=list(OBS_INPUTS),
                   private_truth_mounted=False, private_seed_mounted=False, wallet_backup_mounted=False), "_observe", OBS_INPUTS)
    tests.append("public-only-observer-isolation-positive")
    need("native/private/views/pooled.json" in allowed() and "native/private/truth.json" not in allowed([1]), "closed nested private allowance")
    tests.append("declared-pooled-only-private-area-exception")
    h = lambda n: f"{n:064x}"
    native_point = lambda n: dict(previousOutpoint=dict(transactionId=h(n), index=0))
    raw = dict(descriptor={}, vk_hex="", parents=[dict(id=h(10)), dict(id=h(11))],
               lineage=[dict(id=h(20), inputs=[native_point(10)]),
                        dict(id=h(21), inputs=[native_point(20)]),
                        dict(id=h(22), inputs=[native_point(21)]),
                        dict(id=h(23), inputs=[native_point(22), native_point(11)])])
    directory = dict(entries=[dict(transaction_id=h(10), index=0, owner=0),
                              dict(transaction_id=h(11), index=0, owner=1)])
    timing = dict(events=[dict(event_id=h(i), minute=i) for i in (21, 22, 23)])
    full_view = dict(schema="kpi-native-usage-view-v1", members=[0],
                     receipts=[dict(owner=0, position=1, value=60_000_000),
                               dict(owner=0, position=3, value=60_000_000)],
                     authored=[dict(owner=0, event_id=h(21), inputs=[0], outputs=[]),
                               dict(owner=0, event_id=h(23), inputs=[], outputs=[])])
    r, d, v, t = prefixes(raw, directory, timing, full_view, 1, [1, 2, 0])
    need(r["parents"] == raw["parents"][:1] and len(r["lineage"]) == 3
         and d["entries"] == directory["entries"][:1] and v["receipts"] == full_view["receipts"][:1]
         and v["authored"] == full_view["authored"][:1] and t["events"] == timing["events"][:2],
         "post-DRAIN cut excludes later bridge admission and disclosures")
    r, d, v, t = prefixes(raw, directory, timing, full_view, 2, [1, 2, 0])
    need(r == raw and d == directory and v == full_view and t == timing,
         "post-ADMIT complete prefix")
    tests.append("prefix-parent-directory-time-receipt-author-cuts")
    need(encoded(dict(a=1, b=[2])) == b'{\n  "a": 1,\n  "b": [\n    2\n  ]\n}\n',
         "frozen runner exact byte serialization")
    tests.append("exact-runner-input-and-prediction-byte-format")
    reject(lambda: decimal("01"), "noncanonical-native-decimal-reject")
    reject(lambda: hash_array([False]*32), "boolean-public-hash-byte-reject")
    counter(dict(correct=1, eligible=2, rate=dict(numerator=1, denominator=2)))
    reject(lambda: counter(dict(correct=[dict(sender=8, recipient=9, amount_exact=123)], eligible=2, rate=None)),
           "aggregate-counter-private-container-reject")
    reject(lambda: fraction(dict(numerator="PRIVATE_MARKER", denominator=1)), "fraction-private-string-reject")
    reject(lambda: warnings([dict(kind="absolute", variant="prior", stratum="primary", metric="sender",
                                  cap=dict(numerator=1, denominator=10), rate=dict(numerator=1, denominator=2),
                                  sender=8)]), "warning-extra-private-fact-reject")
    d = dict(input_sha256={name: "0"*64 for name in ("raw", "directory", "view", "timing", "policy")},
             equality={name: [] for name in ("commitment_positions", "nonzero_nullifiers", "nonzero_ciphertexts",
                       "nonzero_ciphertext_ephemeral_prefixes", "proofs", "funding_and_payout_scripts")},
             zero_padding=dict(authorization_commitment_slots=[], authorization_nullifier_slots=[],
                               ciphertext_slots=[], note_values=PADDING_TEXT),
             layouts=[], event_ids=[], chain_acceptance_verified=False, **DIAGNOSTIC_TEXT)
    p = dict(schema="kpi-native-usage-predictions-v1", complete=True, profile="C", through_event=0,
             rows=[], boundary=[], diagnostics=d,
             **{name+"_sha256": "0"*64 for name in ("raw", "directory", "view", "timing", "policy")})
    prediction(p, "C", 0)
    bad = copy.deepcopy(p); bad["diagnostics"]["validation"] = dict(private_seed="PRIVATE_MARKER")
    reject(lambda: prediction(bad, "C", 0), "diagnostic-prose-private-container-reject")
    bad = copy.deepcopy(p); bad["diagnostics"]["zero_padding"]["note_values"] = [dict(sender=8, recipient=9, amount=123)]
    reject(lambda: prediction(bad, "C", 0), "padding-prose-private-container-reject")
    tests.append("typed-public-prediction-diagnostics-positive")
    original = b'{"public_fixture":true,"literal":"\\n"}\n' * 10
    packed = compressed_exact(original)
    need(packed == compressed_exact(original) and gzip.decompress(packed) == original,
         "deterministic gzip preserves exact original")
    need(packed[:10] == b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff",
         "gzip timestamp, filename or metadata changed")
    tests.append("deterministic-gzip-exact-roundtrip-no-name-or-time")
    return dict(passed=True, complete=True, controls=len(tests), tests=tests,
                scope="Public temporary fixtures only; exporter not run against any experiment")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("controls")
    command = commands.add_parser("export")
    command.add_argument("source", type=Path); command.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(json.dumps(controls() if args.command == "controls" else export(args.source, args.destination), indent=2))


if __name__ == "__main__":
    main()
