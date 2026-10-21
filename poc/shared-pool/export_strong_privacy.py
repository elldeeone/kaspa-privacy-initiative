#!/usr/bin/env python3
"""Export one completed strong-privacy screen through a closed public allowlist.

Post-run packaging only: no generator, observer, solver, prover or network calls.
Never opens seeds, full truth, private wallet files or operational logs. Run only
after the owner authorizes export. Existing evidence is never overwritten.
"""
import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import tempfile

FREEZE = "1fdbd5c8a20a475578490161c4eff8c0c437f1adc5ead0a9db6ac724eecd5cf9"
CANDIDATE = "52c209296184d880221432fcbf56bb20d3f64d10"
CONTROL_RESULT = "ccee49ba55f4ceb50c635f769d2f1e77ade1c190a74d427c8fcb64a645d8bf7b"
REVIEW_CHECKER = "0fa36fa69bc355e4280aa9ff70674b4d44b3bfb094ba9b41808a1db7e7de626d"
SOURCES = ("population_privacy_strong_trial.py", "population_privacy_strong.py",
           "population_privacy_strong_score.py", "population_privacy_strong_workload.py",
           "population_privacy_workload.py", "population_privacy_model.py",
           "two_input_privacy_observer.py", "two_input_privacy_z3.py", "early_privacy_surface.py",
           "POPULATION-PRIVACY-STRONG-SPEC.md")
NOTES = ("docs/rfc/0012-useful-privacy-requirements.md",
         "docs/rfc/0014-owner-aware-privacy-evaluation.md",
         "research/shielded-kas-strong-privacy-screen-2026-10-21.md")
CASES = tuple(f"set-{i:02d}-persistent" for i in range(1, 17))
REGIMES = ("overlap",) * 8 + ("sparse",) * 8
VIEWS = ("public.json", "pooled.json", "C.json") + tuple(f"P-{i}.json" for i in range(8))
VARIANTS = ("prior", "cashout_residual", "split_balance", "tag_split")
STRATA = ("primary", "all_undisclosed", "startup", "adversary_endpoint")
METRICS = ("sender", "recipient", "relationship", "amount_within_10pct", "amount_exact")
COVERAGES = ("5", "10", "25")
CAPS = {"sender": .1, "recipient": .1, "amount_within_10pct": .2}
SCOPES = ("pooled", "overlap", "sparse")
MAX = 2_900_000_000_000_000_000
CONTROL_TEXT = {
    "model": ("meaning", "Explicit development controls; no held-out workload, proofs or chain acceptance"),
    "workload": ("scope", "published development fixtures only; no held-out seeds or predictions"),
    "scorer": ("scope", "Hand-built scoring and statistical controls; no held-out execution"),
}
CONTROL_ROSTERS = {
    "model": "19fdd8e0e94ab701df3d27b5f056448a0bf6263bf49982928aa3b98878067d8d",
    "workload": "82536dc894966cbc0137a96c7a7f79e58ccb367f958e80ed100f81c20ba17a97",
    "observer": "07316ec5fab8f08683a86ef17ce2c11c6e069e940d4f29b536113b997d3a6191",
    "scorer": "80c53042ad95375078e7b3c5fab6c3a41ab4261867bbed051902694c3c3a6fbc",
}
INFERENCE = dict(method="Bonferroni simultaneous two-sided Hoeffding", family_intervals=99,
    tails=198, family_alpha=.05, unit="independent history, equally weighted", unit_range=[0, 1],
    paired_difference_range=[-1, 1],
    sampling_assumption="Runner independently sampled sixteen frozen-policy histories",
    caps_scope="Primary only; other strata and exact amount are descriptive",
    prior_limit="One frozen policy-aware prior; not proof it is strongest possible")
LIMITS = ["Finite synthetic workload, pooled final observation only; omitted native/provider surfaces remain open.",
          "Guesses and uncalibrated rankings are not forced disclosures or posterior probabilities.",
          "Wide intervals and no certified breach cannot establish useful privacy."]


def need(condition, message):
    if not condition:
        raise ValueError(message)


def fields(value, expected, label):
    expected = set(expected.split()) if isinstance(expected, str) else set(expected)
    need(type(value) is dict and set(value) == expected, label + " fields")


def integer(value, low=0, high=MAX):
    need(type(value) is int and low <= value <= high, "integer outside approved domain")


def string(value):
    need(type(value) is str, "string required")


def literal(value, expected):
    need(type(value) is str and value == expected, "unexpected free-text content")


def hashes(values):
    for value in values:
        need(type(value) is str and len(value) == 64
             and all(c in "0123456789abcdef" for c in value), "SHA256/opaque-label encoding")


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def canonical(value):
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def roster(names, expected):
    need(type(names) is list and all(type(n) is str for n in names)
         and canonical(names) == expected, "changed approved control-name roster")


def timestamp(value):
    string(value)
    result = datetime.fromisoformat(value)
    need(result.tzinfo is not None, "timezone required")
    return result


def relative(value):
    string(value)
    p = PurePosixPath(value)
    need(value and not p.is_absolute() and ".." not in p.parts
         and str(p) == value and "\\" not in value, "noncanonical relative path")
    return p


def checked(path, directory=False):
    path = Path(path).absolute()
    need(all(not p.is_symlink() for p in (path, *path.parents)), "symlink ancestor rejected")
    need(path.is_dir() if directory else path.is_file(), "missing/nonregular approved artifact")
    return path


def child(root, name):
    p = root.joinpath(*relative(name).parts)
    need(p.resolve().is_relative_to(root.resolve()), "artifact escapes root")
    return p


def json_load(blob):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def invalid_constant(_):
        raise ValueError("nonfinite JSON number")
    return json.loads(blob, object_pairs_hook=pairs, parse_constant=invalid_constant)


def allowed_files():
    names = {"freeze.json", "policy.json", "controls.json", "generation.json",
             "prediction-batch.json", "scores.json", "completion.json"}
    names.update("review/" + name for name in ("checker.py", "aggregate.json", "summary.json"))
    names.update("review/" + case + ".json" for case in CASES)
    names.update("code/" + n for n in SOURCES)
    names.update("notes/" + n for n in NOTES)
    for label in ("controls", "generate", "aggregate") + tuple(
            suffix for case in CASES for suffix in
            (case + "-pooled-final", case + "-pooled-final-score")):
        names.update("runs/" + label + "/" + n
                     for n in ("inputs.json", "isolation.json", "process.json", "result.json"))
    for case in CASES:
        names.update(f"runs/generate/public/{case}/{n}" for n in VIEWS)
        names.update(f"runs/{case}-pooled-final/{n}" for n in ("prediction-seal.json", "completion.json"))
    return names


class Reader:
    def __init__(self, root):
        self.root = checked(root, directory=True)
        self.allowed = allowed_files()
        self.blobs = {}

    def blob(self, name):
        need(name in self.allowed, "read outside closed public allowlist")
        if name not in self.blobs:
            self.blobs[name] = checked(child(self.root, name)).read_bytes()
        return self.blobs[name]

    def read(self, name):
        return json_load(self.blob(name))

    def sha(self, name):
        return digest(self.blob(name))

    def unchanged(self):
        for name, blob in self.blobs.items():
            need(checked(child(self.root, name)).read_bytes() == blob, "approved source changed during export")


def check_public(p):
    fields(p, "schema roles adversaries algebra commitments funding_owners bootstrap_self modeled", "public")
    need(p["schema"] == "kpi-population-public-v1" and p["bootstrap_self"] is True
         and p["roles"] == list(range(32)) and p["adversaries"] == list(range(8)), "public population")
    fields(p["algebra"], "schema initial events", "algebra")
    need(p["algebra"]["schema"] == "kpi-h14-public-v1", "algebra schema")
    initial = p["algebra"]["initial"]
    fields(initial, "id value funding_group", "initial")
    hashes([initial["id"], initial["funding_group"]]); integer(initial["value"])
    need(type(p["commitments"]) is list, "commitment list")
    hashes(p["commitments"])
    for e in p["algebra"]["events"]:
        fields(e, "id minute mode anchor_count count_before new fee deposit payout reserve_out destination funding_group", "event")
        hashes([e["id"]])
        for k in ("minute", "anchor_count", "count_before", "fee", "deposit", "payout", "reserve_out"):
            integer(e[k])
        integer(e["mode"], 0, 2)
        need(type(e["new"]) is list and len(e["new"]) in (0, 2), "new positions")
        for pos in e["new"]:
            integer(pos, 0, len(p["commitments"]) - 1)
        for key in ("destination", "funding_group"):
            if e[key] is not None:
                hashes([e[key]])
    for owners in (p["funding_owners"], p["modeled"].get("receive_contacts")):
        need(type(owners) is dict and len(owners) == 32, "public owner directory")
        hashes(owners)
        for owner in owners.values():
            integer(owner, 0, 31)
    m = p["modeled"]
    fields(m, "kind timing receive_contacts floor_sompi payout_floor_sompi fee_sompi cryptographic_identifiers selection_policy population", "modeled")
    need(m["kind"] == "synthetic-wallet-history" and m["timing"] == "modeled-minute-slots"
         and m["cryptographic_identifiers"] == "independent-opaque-random-labels"
         and m["selection_policy"] == "least-excess-fewest-inputs-lexicographic"
         and m["population"] == 32 and m["floor_sompi"] == 60_000_000
         and m["payout_floor_sompi"] == 10_000_000 and m["fee_sompi"] == 40_000_000, "model identity")


def check_view(v, public, members):
    fields(v, "schema public_sha256 members receipts authored", "view")
    need(v["schema"] == "kpi-population-view-v1" and v["members"] == members
         and v["public_sha256"] == canonical(public), "participant view identity")
    need(type(v["receipts"]) is list and type(v["authored"]) is list, "view record lists")
    for row in v["receipts"]:
        fields(row, "owner position value", "receipt")
        integer(row["owner"], 0, 7); need(row["owner"] in members, "receipt outside member set")
        integer(row["position"], 0, len(public["commitments"]) - 1); integer(row["value"], 60_000_000)
    for row in v["authored"]:
        fields(row, "owner event inputs outputs", "authored")
        integer(row["owner"], 0, 7); need(row["owner"] in members, "author outside member set")
        integer(row["event"], 0, len(public["algebra"]["events"]) - 1)
        need(type(row["inputs"]) is list and len(row["inputs"]) <= 2, "authored inputs")
        for pos in row["inputs"]:
            integer(pos, 0, len(public["commitments"]) - 1)
        need(type(row["outputs"]) is list and len(row["outputs"]) <= 2, "authored outputs")
        for out in row["outputs"]:
            fields(out, "position value recipient", "authored output")
            integer(out["position"], 0, len(public["commitments"]) - 1); integer(out["value"])
            need(out["recipient"] is None if out["value"] == 0 else type(out["recipient"]) is int,
                 "recipient padding")
            if out["recipient"] is not None:
                integer(out["recipient"], 0, 31)


def check_prediction(p, public, view, policy):
    fields(p, "schema complete public_sha256 view_sha256 policy_sha256 horizon variants rows", "prediction")
    need(p["schema"] == "kpi-population-strong-predictions-v1" and p["complete"] is True
         and p["horizon"] == "final" and p["variants"] == list(VARIANTS), "prediction scope")
    need([p[k] for k in ("public_sha256", "view_sha256", "policy_sha256")]
         == [canonical(public), canonical(view), canonical(policy)], "prediction input identity")
    targets = [i for i, e in enumerate(public["algebra"]["events"]) if i and e["mode"] == 1]
    need(len(targets) == len(p["rows"]) == 128, "target coverage")
    for i, row in zip(targets, p["rows"], strict=True):
        fields(row, "event guesses", "prediction row")
        need(type(row["event"]) is int and row["event"] == i, "target order")
        fields(row["guesses"], VARIANTS, "guesses")
        for name, guess in row["guesses"].items():
            fields(guess, "sender recipient amount relationship_rank", "guess")
            integer(guess["sender"], 0, 31); integer(guess["recipient"], 0, 31); integer(guess["amount"])
            rank = guess["relationship_rank"]
            need(type(rank) is list and len(rank) == 4, "rank shape")
            for x in rank:
                integer(x, -(2**63) + 1, 2**63 - 1)
            need(0 <= rank[0] <= 2 and rank[1] >= 0 and rank[2] >= 0 and rank[3] <= 0
                 and (name != "prior" or rank == [0, 0, 0, 0]), "rank domain")


def counter(c):
    fields(c, "correct eligible", "counter")
    integer(c["eligible"], 0, 128); integer(c["correct"], 0, c["eligible"])


def check_score(s):
    fields(s, "schema complete public_sha256 view_sha256 prediction_sha256 policy_sha256 regime arm horizon targets truth_consistency policy_validation tested_primary_targets variants qualification_pass", "score")
    need(s["schema"] == "kpi-population-strong-score-v1" and s["complete"] is True
         and s["qualification_pass"] is False and s["regime"] in REGIMES
         and s["arm"] == "persistent" and s["horizon"] == "final" and s["targets"] == 128, "score identity")
    hashes(s[k] for k in ("public_sha256", "view_sha256", "prediction_sha256", "policy_sha256"))
    need(s["truth_consistency"] == dict(complete=True, cp_sat="SAT", z3="SAT"), "truth consistency")
    fields(s["policy_validation"], "passed complete payments startup_payments active_payments full_drainage scope", "policy validation")
    need(s["policy_validation"] == dict(passed=True, complete=True, payments=128, startup_payments=16,
         active_payments=32, full_drainage=True,
         scope="exact policy/accounting check; no seed-randomness or cryptographic claim"), "policy validation result")
    integer(s["tested_primary_targets"], 0, 128)
    fields(s["variants"], VARIANTS, "score variants")
    for name, variants in s["variants"].items():
        fields(variants, STRATA, "strata")
        for stratum, stats in variants.items():
            fields(stats, set(METRICS) | {"selective_relationship"}, "statistics")
            for metric in METRICS:
                counter(stats[metric])
                need(stats[metric]["eligible"] == s["variants"]["prior"][stratum][metric]["eligible"], "variant denominator")
                if stratum == "primary":
                    need(stats[metric]["eligible"] == s["tested_primary_targets"], "primary denominator")
            fields(stats["selective_relationship"], COVERAGES, "coverages")
            for percent, c in stats["selective_relationship"].items():
                fields(c, "correct eligible population nominal_percent realized_coverage", "selective counter")
                integer(c["population"], 0, 128); integer(c["eligible"], 0, c["population"])
                integer(c["correct"], 0, c["eligible"])
                need(c["population"] == stats["relationship"]["eligible"] and c["nominal_percent"] == int(percent)
                     and c["eligible"] == (c["population"] * int(percent) + 99) // 100
                     and c["realized_coverage"] == (c["eligible"] / c["population"] if c["population"] else None),
                     "selective denominator")


def check_aggregate(a):
    fields(a, "schema complete status qualification_pass scopes certified_breaches descriptive_point_estimate_exceedances inference limits", "aggregate")
    need(a["schema"] == "kpi-population-strong-summary-v1" and type(a["complete"]) is bool
         and a["qualification_pass"] is False and a["status"] in
         ("incomplete", "evidence-valid cap-breach", "bounded-screen-complete-no-certified-breach"), "aggregate scope")
    fields(a["scopes"], SCOPES, "aggregate scopes")
    def descriptive(d):
        fields(d, "correct eligible pooled_rate defined_histories total_histories mean_history_rate", "descriptive")
        for k in ("correct", "eligible", "defined_histories", "total_histories"):
            integer(d[k])
        need(d["correct"] <= d["eligible"] and d["defined_histories"] <= d["total_histories"], "descriptive counts")
        for k in ("pooled_rate", "mean_history_rate"):
            need(d[k] is None or type(d[k]) in (float, int) and 0 <= d[k] <= 1, "descriptive rate")
    base = {"complete", "histories", "defined_histories", "mean", "lower", "upper"}
    def interval(d, extras, lo=0, hi=1):
        fields(d, base | set(extras), "interval")
        need(type(d["complete"]) is bool, "interval complete")
        integer(d["histories"], 0, 16); integer(d["defined_histories"], 0, d["histories"])
        for k in ("mean", "lower", "upper"):
            need(d[k] is None if not d["complete"] else type(d[k]) in (float, int) and lo <= d[k] <= hi,
                 "interval numeric range")
        need(type(d["certified_breach"]) is bool and type(d["point_estimate_exceeds_cap"]) is bool, "breach booleans")
    for scope, contents in a["scopes"].items():
        fields(contents, "histories variants paired_prior_advantages", "scope")
        need(contents["histories"] == (16 if scope == "pooled" else 8), "scope sample count")
        fields(contents["variants"], VARIANTS, "aggregate variants")
        for stats in contents["variants"].values():
            fields(stats, "descriptive absolute selective_relationship", "variant aggregate")
            fields(stats["descriptive"], STRATA, "descriptive strata")
            for metrics in stats["descriptive"].values():
                fields(metrics, METRICS, "descriptive metrics")
                for d in metrics.values(): descriptive(d)
            fields(stats["absolute"], CAPS, "absolute metrics")
            for metric, d in stats["absolute"].items():
                interval(d, {"cap", "certified_breach", "point_estimate_exceeds_cap"})
                need(d["cap"] == CAPS[metric], "absolute cap")
            fields(stats["selective_relationship"], COVERAGES, "selective metrics")
            for d in stats["selective_relationship"].values():
                interval(d, {"cap", "certified_breach", "point_estimate_exceeds_cap", "descriptive", "realized_coverages"})
                need(d["cap"] == .5 and len(d["realized_coverages"]) == contents["histories"], "selective cap/coverage")
                descriptive(d["descriptive"])
                need(all(v is None or type(v) in (int, float) and 0 <= v <= 1 for v in d["realized_coverages"]), "coverage range")
        fields(contents["paired_prior_advantages"], VARIANTS[1:], "advantage variants")
        for metrics in contents["paired_prior_advantages"].values():
            fields(metrics, CAPS, "advantage metrics")
            for d in metrics.values():
                interval(d, {"cap", "baseline", "certified_breach", "point_estimate_exceeds_cap"}, -1, 1)
                need(d["cap"] == .05 and d["baseline"] == "prior", "advantage cap/prior")
    for list_name, quantity in (("certified_breaches", "lower"), ("descriptive_point_estimate_exceedances", "mean")):
        for row in a[list_name]:
            keys = {"scope", "variant", "metric", "cap", quantity, "kind"}
            if row.get("kind") == "selective": keys.add("nominal_percent")
            fields(row, keys, "breach/signal")
            need(row["scope"] in SCOPES and row["variant"] in VARIANTS
                 and row["metric"] in set(CAPS) | {"selective_relationship"}
                 and row["kind"] in ("absolute", "selective", "paired_prior_advantage"), "signal domain")
            need(type(row[quantity]) in (float, int) and -1 <= row[quantity] <= 1, "signal numeric range")
            need(row["cap"] in (.05, .1, .2, .5), "signal cap")
            if "nominal_percent" in row: need(str(row["nominal_percent"]) in COVERAGES, "signal coverage")
    need(a["inference"] == INFERENCE and a["limits"] == LIMITS, "changed inference/limit metadata")


def check_controls(c):
    fields(c, "passed results", "controls")
    need(c["passed"] is True, "controls failed")
    fields(c["results"], "model workload observer scorer", "control groups")
    schemas = {
        "model": "passed complete tests controls exhaustive_proposition_comparisons pending meaning",
        "workload": "passed complete controls truth_consistency development_seed scope",
        "observer": "schema passed complete controls count held_out_data_used candidate_truncation",
        "scorer": "passed complete tests family_intervals scope"}
    for name, d in c["results"].items():
        fields(d, schemas[name], "control " + name)
        need(d["passed"] is d["complete"] is True, "incomplete control")
        if name in CONTROL_TEXT:
            key, text = CONTROL_TEXT[name]
            literal(d[key], text)
        if name == "observer":
            need(d["schema"] == "kpi-population-strong-controls-v1"
                 and d["held_out_data_used"] is False and d["candidate_truncation"] is False, "observer controls")
            for row in d["controls"]:
                fields(row, "name passed", "observer control")
                string(row["name"]); need(row["passed"] is True, "control failure")
            need(d["count"] == len(d["controls"]), "control count")
            roster([row["name"] for row in d["controls"]], CONTROL_ROSTERS[name])
        else:
            rows = d["controls"] if name == "workload" else d["tests"]
            need(type(rows) is list, "test names")
            for name_text in rows: string(name_text)
            roster(rows, CONTROL_ROSTERS[name])
        if name == "workload":
            need(d["truth_consistency"] == dict(complete=True, cp_sat="SAT", z3="SAT"), "development truth")
            need(d["development_seed"] == {"requests": bytes(range(32)).hex(),
                 "opaque": bytes(reversed(range(32))).hex()}, "only published development seed permitted")
        elif name == "model":
            need(d["pending"] == [] and d["controls"] == len(d["tests"]), "model control completion")
            integer(d["exhaustive_proposition_comparisons"])
        elif name == "scorer": need(d["family_intervals"] == 99, "control family")


def check_generation(g, extra=False):
    keys = {"complete", "cases", "independent_histories"}
    if extra: keys |= {"completed_utc", "seed_commitments_sha256", "result_sha256"}
    fields(g, keys, "generation")
    need(g["complete"] is True and g["independent_histories"] == len(g["cases"]) == 16, "generation incomplete")
    for name, regime, case in zip(CASES, REGIMES, g["cases"], strict=True):
        fields(case, "name regime complete error events ordinary_payments pins truth_sha256 accounting", "generated case")
        need(case["name"] == name and case["regime"] == regime and case["complete"] is True
             and case["error"] is None and case["ordinary_payments"] == 128, "generated case identity")
        integer(case["events"], 128, 65535); hashes([case["truth_sha256"]])
        fields(case["pins"], VIEWS, "public case pins"); hashes(case["pins"].values())
        acc = case["accounting"]
        fields(acc, "native_funded_sompi payouts_sompi pool_fees_sompi remaining_reserve_sompi capital_share payment_value_share operation_share", "aggregate accounting")
        for key in ("native_funded_sompi", "payouts_sompi", "pool_fees_sompi", "remaining_reserve_sompi"):
            integer(acc[key])
        need(acc["remaining_reserve_sompi"] == 0 and acc["native_funded_sompi"] == acc["payouts_sompi"] + acc["pool_fees_sompi"], "aggregate backing")
        for key in ("capital_share", "payment_value_share", "operation_share"):
            fields(acc[key], "adversary total", "aggregate share")
            integer(acc[key]["total"]); integer(acc[key]["adversary"], 0, acc[key]["total"])


def attest(reader, label, mode, inputs):
    prefix = "runs/" + label + "/"
    seen = reader.read(prefix + "inputs.json")
    fields(seen, inputs, "input hash map"); hashes(seen.values())
    for name, expected in inputs.items():
        need(expected is None or seen[name] == expected, "input hash mismatch")
    isolation = reader.read(prefix + "isolation.json")
    fields(isolation, "interfaces home_accessible mode inputs private_truth_mounted private_seeds_mounted", "isolation")
    need(isolation == dict(interfaces=["lo"], home_accessible=False, mode=mode, inputs=list(inputs),
         private_truth_mounted="/truth.json" in inputs, private_seeds_mounted="/seeds.json" in inputs), "isolation roster")
    process = reader.read(prefix + "process.json")
    fields(process, "started_utc ended_utc returncode", "process")
    need(type(process["returncode"]) is int and process["returncode"] == 0, "failed process")
    start, end = timestamp(process["started_utc"]), timestamp(process["ended_utc"])
    need(start <= end, "reversed process times")
    return start, end


def review_receipt(receipt, inputs, result, batch_hash):
    # Canonical encoding enforces the entire nested schema and distinguishes
    # integers from booleans/floats. No unrestricted text is copied from review.
    expected = dict(checker_sha256=REVIEW_CHECKER, prediction_batch_sha256=batch_hash,
        input_sha256=inputs, isolation=dict(home_accessible=False, interfaces=["lo"]), result=result)
    need(canonical(receipt) == canonical(expected), "review receipt identity/schema")


def check_review(reader, generation, scores, aggregate, policy):
    need(reader.sha("review/checker.py") == REVIEW_CHECKER, "post-run review checker changed")
    batch_hash = reader.sha("prediction-batch.json")
    for case, record in zip(generation["cases"], scores, strict=True):
        name = case["name"]
        pub = f"runs/generate/public/{name}/"
        observed = f"runs/{name}-pooled-final/result.json"
        scored = f"runs/{name}-pooled-final-score/result.json"
        inputs = {"/public.json": reader.sha(pub + "public.json"),
                  "/view.json": reader.sha(pub + "pooled.json"),
                  "/prediction.json": reader.sha(observed), "/truth.json": case["truth_sha256"],
                  "/score.json": reader.sha(scored), "/policy.json": reader.sha("policy.json")}
        result = dict(schema="kpi-strong-independent-review-v1", mode="case", passed=True,
            ordinary_targets=128, primary_targets=record["score"]["tested_primary_targets"],
            field_counter_cells=80, selective_counter_cells=48, digests={
                "public": canonical(reader.read(pub + "public.json")),
                "view": canonical(reader.read(pub + "pooled.json")),
                "prediction": canonical(reader.read(observed)),
                "score": canonical(record["score"]), "policy": canonical(policy)})
        review_receipt(reader.read(f"review/{name}.json"), inputs, result, batch_hash)
    result = dict(schema="kpi-strong-independent-review-v1", mode="aggregate", passed=True,
        histories=16, intervals=99, tails=198, certified_breaches=len(aggregate["certified_breaches"]),
        exploratory_signals=len(aggregate["descriptive_point_estimate_exceedances"]),
        digests=dict(scores=canonical(scores), summary=canonical(aggregate)))
    review_receipt(reader.read("review/aggregate.json"),
        {"/scores.json": reader.sha("scores.json"),
         "/summary.json": reader.sha("runs/aggregate/result.json")}, result, batch_hash)
    expected = dict(passed=True, histories=16, ordinary_targets=2048, checker_sha256=REVIEW_CHECKER,
        field_counter_cells=1280, selective_counter_cells=768, aggregate=result,
        case_receipts={name: reader.sha(f"review/{name}.json") for name in CASES},
        scope="Independent author-team recount and statistics review; no new cryptographic or native validation")
    need(canonical(reader.read("review/summary.json")) == canonical(expected), "review summary identity/schema")


def validate(reader):
    need(reader.sha("freeze.json") == FREEZE, "not the authorized frozen experiment")
    frozen = reader.read("freeze.json")
    fields(frozen, "schema frozen_utc candidate policy_sha256 sources notes candidate_files calibration dependency_root dependencies ordered_regimes independent_histories scope scoring_barrier maximum_parallel_scorers qualification_pass runtime_trust", "freeze")
    need(frozen["candidate"] == CANDIDATE and frozen["ordered_regimes"] == list(REGIMES)
         and frozen["independent_histories"] == 16 and frozen["qualification_pass"] is False, "freeze scope")
    fields(frozen["sources"], SOURCES, "frozen sources"); fields(frozen["notes"], NOTES, "frozen notes")
    for prefix, pins in (("code/", frozen["sources"]), ("notes/", frozen["notes"])):
        for name, pin in pins.items(): need(reader.sha(prefix + name) == pin, "frozen source hash")
    need(reader.sha("policy.json") == frozen["policy_sha256"], "policy hash")
    policy = reader.read("policy.json")  # Exact freeze pin; no path/secret content generated at runtime.
    # This known public development artifact was inspected after controls, before
    # held-out scoring. Pinning it also fixes every control name/text/count.
    need(reader.sha("runs/controls/result.json") == CONTROL_RESULT, "changed approved control output")
    controls = reader.read("runs/controls/result.json"); check_controls(controls)
    controls_meta = reader.read("controls.json")
    fields(controls_meta, "passed completed_utc result_sha256 result", "controls metadata")
    need(controls_meta["passed"] is True and controls_meta["result"] == controls
         and controls_meta["result_sha256"] == reader.sha("runs/controls/result.json"), "control identity")
    cs, ce = attest(reader, "controls", "_controls", {})
    g = reader.read("generation.json"); check_generation(g, extra=True)
    raw_g = reader.read("runs/generate/result.json"); check_generation(raw_g)
    need({k: g[k] for k in raw_g} == raw_g and g["result_sha256"] == reader.sha("runs/generate/result.json"), "generation identity")
    hashes([g["seed_commitments_sha256"]])  # Reference only; seed files are never opened.
    gs, ge = attest(reader, "generate", "_generate", {"/seeds.json": None})
    need(timestamp(frozen["frozen_utc"]) <= cs <= ce <= timestamp(controls_meta["completed_utc"]) <= gs <= ge
         <= timestamp(g["completed_utc"]), "pre-sampling controls/freeze ordering")
    batch = reader.read("prediction-batch.json")
    fields(batch, "schema sealed_utc complete predictions freeze_sha256 generation_sha256 scoring_started", "batch")
    need(batch["schema"] == "kpi-strong-privacy-batch-v1" and batch["complete"] is True
         and batch["scoring_started"] is False and batch["freeze_sha256"] == FREEZE
         and batch["generation_sha256"] == reader.sha("generation.json") and len(batch["predictions"]) == 16, "batch identity")
    batch_time = timestamp(batch["sealed_utc"])
    scores = reader.read("scores.json")
    need(type(scores) is list and len(scores) == 16, "score roster")
    last_score_end = batch_time
    for case, entry, scored in zip(g["cases"], batch["predictions"], scores, strict=True):
        name = case["name"]; label = name + "-pooled-final"
        public_prefix = f"runs/generate/public/{name}/"
        for filename, expected in case["pins"].items(): need(reader.sha(public_prefix + filename) == expected, "public artifact pin")
        public = reader.read(public_prefix + "public.json"); check_public(public)
        views = {}
        for filename in VIEWS[1:]:
            members = list(range(8)) if filename == "pooled.json" else [] if filename == "C.json" else [int(filename[2])]
            views[filename] = reader.read(public_prefix + filename)
            check_view(views[filename], public, members)
        fields(entry, "case label prediction seal_sha256", "batch entry")
        seal = reader.read(f"runs/{label}/prediction-seal.json")
        fields(seal, "case sealed_utc freeze_sha256 prediction_sha256 inputs truth_sha256", "prediction seal")
        need(entry["case"] == name and entry["label"] == label and entry["prediction"] == seal
             and entry["seal_sha256"] == reader.sha(f"runs/{label}/prediction-seal.json")
             and seal["case"] == name and seal["freeze_sha256"] == FREEZE
             and seal["truth_sha256"] == case["truth_sha256"], "seal identity")
        inputs = {"/public.json": case["pins"]["public.json"], "/view.json": case["pins"]["pooled.json"],
                  "/policy.json": frozen["policy_sha256"]}
        need(seal["inputs"] == inputs and seal["prediction_sha256"] == reader.sha(f"runs/{label}/result.json"), "prediction byte identity")
        prediction = reader.read(f"runs/{label}/result.json")
        check_prediction(prediction, public, views["pooled.json"], policy)
        ps, pe = attest(reader, label, "_observe", inputs)
        score_label = label + "-score"
        ss, se = attest(reader, score_label, "_score", dict(inputs, **{
            "/prediction.json": seal["prediction_sha256"], "/truth.json": case["truth_sha256"]}))
        need(timestamp(g["completed_utc"]) <= ps <= pe <= timestamp(seal["sealed_utc"]) <= batch_time <= ss <= se,
             "prediction-before-score barrier")
        last_score_end = max(last_score_end, se)
        score = reader.read(f"runs/{score_label}/result.json"); check_score(score)
        fields(scored, "case regime score", "scores entry")
        need(scored == dict(case=name, regime=case["regime"], score=score) and score["regime"] == case["regime"], "score record identity")
        need([score[k] for k in ("public_sha256", "view_sha256", "prediction_sha256", "policy_sha256")]
             == [canonical(public), canonical(views["pooled.json"]), canonical(prediction), canonical(policy)], "scorer input identity")
        completed = reader.read(f"runs/{label}/completion.json")
        fields(completed, "complete prediction_batch_sha256 score_sha256 qualification_pass", "case completion")
        need(completed == dict(complete=True, prediction_batch_sha256=reader.sha("prediction-batch.json"),
             score_sha256=reader.sha(f"runs/{score_label}/result.json"), qualification_pass=False), "case completion identity")
    aggregate = reader.read("runs/aggregate/result.json"); check_aggregate(aggregate)
    ast, aend = attest(reader, "aggregate", "_aggregate", {"/scores.json": reader.sha("scores.json")})
    need(last_score_end <= ast <= aend, "aggregate precedes scores")
    completion = reader.read("completion.json")
    fields(completion, "complete execution_completed completed_utc prediction_batch_sha256 aggregate_sha256 scores_sha256 qualification_pass independent_histories result", "completion")
    need(completion["execution_completed"] is True and completion["complete"] == aggregate["complete"]
         and completion["qualification_pass"] is False and completion["independent_histories"] == 16
         and completion["result"] == aggregate and completion["prediction_batch_sha256"] == reader.sha("prediction-batch.json")
         and completion["aggregate_sha256"] == reader.sha("runs/aggregate/result.json")
         and completion["scores_sha256"] == reader.sha("scores.json")
         and aend <= timestamp(completion["completed_utc"]), "completion identity")
    check_review(reader, g, scores, aggregate, policy)
    need(set(reader.blobs) == reader.allowed, "allowlist coverage changed")
    reader.unchanged()
    return frozen, completion


README = """# Stronger practical privacy screen: public evidence

Sixteen independent synthetic persistent histories, 32 modeled roles and eight
colluding roles each. This is a pooled final-history attack screen. There are no
new native proofs, accepted-chain observations, funds or real-user anonymity
measurements. `qualification_pass` remains false, regardless of the result.

This combined package is **not an isolated observer input**. Public histories,
permitted pooled/separate participant records, predictions and subsequent scores
are all preserved here. Generation/accounting shares are harness summaries;
they were not mounted in observer processes. The source contains the published
development seed and deliberate fixture choices, never a held-out seed file.

- `runs/generate/public/<case>` preserves exact public/C/pooled/P-0 through P-7
  records. Participant records disclose only the approved adversarial views.
- `runs/<case>-pooled-final` preserves predictions, byte-exact seals and
  completion links. `*-score` and `aggregate` contain aggregate-only scores.
- Process/isolation/input-hash attestations retain original bytes; no raw logs
  are included. Truth and seed hashes are provenance references, not anonymous
  substitutes for low-entropy secret values. Full truth and seeds stay withheld.
- `freeze-public.json` is an explicit derivative omitting `dependency_root`.
  Seals still reference the original freeze hash, not the derivative hash.
- `code` and `notes` preserve frozen sources/specification/research; Markdown
  snapshots use `.md.txt`. Candidate source and earlier calibration hashes remain
  in the freeze. `exporter` contains this later packaging tool, which was not
  part of the frozen observer or scorer.
- `review` preserves the later stdlib-only checker, sixteen case receipts,
  aggregate receipt and linked summary. These are post-run author-team checks
  of counts/statistics with isolated inputs, not frozen inference code or an
  external audit. Only hashes and aggregate checks are retained. The host-path
  wrapper and the private truth it mounted remain excluded.

The exporter checked closed/nested schemas, source/input hashes, coverage and
prediction-before-score ordering. It did not open private truth, seed or wallet
files, invoke a solver, rerun inference or certify host isolation. Source hashes
and author-team checks are not independent audit or cryptographic assurance.
Opaque labels, assumed coin selection and modeled time omit actual byte/network
features. No certified breach is not a privacy pass; retain raw exceedances and
the deliberately wide uncertainty bounds.

`export-manifest.json` binds each retained original and exported file identity.
`SHA256SUMS` covers every exported file except itself. Originals remain unchanged.
"""


def export(source, destination):
    reader = Reader(source)
    destination = Path(destination).absolute()
    need(not destination.exists() and not destination.is_symlink(), "destination exists; preserve evidence")
    checked(destination.parent, directory=True)
    need(not destination.resolve().is_relative_to(reader.root.resolve()), "export cannot be inside retained trial")
    frozen, completion = validate(reader)
    outputs, entries = {}, []
    for name, blob in sorted(reader.blobs.items()):
        target, treatment, omitted = name, "byte-exact", []
        if name == "freeze.json":
            target, treatment, omitted = "freeze-public.json", "explicit derivative", ["dependency_root"]
            value = {k: v for k, v in frozen.items() if k not in omitted}
            value.update(export_derivative=True, source_artifact="freeze.json", source_sha256=FREEZE, omitted_fields=omitted)
            blob = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        elif target.endswith(".md"):
            target += ".txt"
        relative(target); outputs[target] = blob
        entries.append(dict(path=target, treatment=treatment, source_label=name,
                            source_sha256=reader.sha(name), exported_sha256=digest(blob), bytes=len(blob)))
    tool = checked(Path(__file__).absolute()).read_bytes()
    tool_path = "exporter/export_strong_privacy.py"
    outputs[tool_path] = tool
    entries.append(dict(path=tool_path, treatment="byte-exact", source_label="post-run packaging tool",
                        source_sha256=digest(tool), exported_sha256=digest(tool), bytes=len(tool)))
    manifest = dict(schema="kpi-strong-privacy-public-export-v1", original_freeze_sha256=FREEZE,
        original_prediction_batch_sha256=reader.sha("prediction-batch.json"),
        completion_sha256=reader.sha("completion.json"), execution_completed=True,
        post_run_review_checker_sha256=REVIEW_CHECKER,
        evidence_complete=completion["complete"], qualification_pass=False, entries=entries,
        excluded="held-out seeds, complete truth, wallet files, other private views, all operational logs, dependency binaries",
        combined_export_is_observer_input=False)
    outputs["README.md"] = README.encode()
    outputs["export-manifest.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    outputs["SHA256SUMS"] = "".join(f"{digest(blob)}  {name}\n" for name, blob in sorted(outputs.items())).encode()
    reader.unchanged()
    destination.mkdir(mode=0o755)  # Exclusive creation; a partial failed export is retained, never replaced.
    for name, blob in sorted(outputs.items()):
        path = child(destination, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        checked(path.parent, directory=True)
        with path.open("xb") as stream: stream.write(blob)
        path.chmod(0o644)
        need(checked(path).read_bytes() == blob, "export write verification")
    reader.unchanged()
    return dict(exported=True, files=len(outputs), bytes=sum(map(len, outputs.values())),
        manifest_entries=len(entries), original_freeze_sha256=FREEZE,
        export_manifest_sha256=digest(outputs["export-manifest.json"]),
        sha256sums_sha256=digest(outputs["SHA256SUMS"]), qualification_pass=False)


def self_test():
    """Confidentiality/integrity rejection checks; no experiment data read."""
    def reject(call):
        try: call()
        except (ValueError, KeyError, TypeError): return
        raise AssertionError("malformed/forbidden input was accepted")
    reject(lambda: json_load(b'{"approved":1,"approved":2}'))
    reject(lambda: json_load(b'{"n":NaN}'))
    for p in ("../truth.json", "/truth.json", "a/../truth.json", "a//x", "a\\x"):
        reject(lambda p=p: relative(p))
    reject(lambda: fields({"correct": 1, "eligible": 1, "actual_owner": 9}, "correct eligible", "counter"))
    reject(lambda: counter({"correct": True, "eligible": 1}))
    reject(lambda: counter({"correct": 2, "eligible": 1}))
    for _, text in CONTROL_TEXT.values():
        literal(text, text)
        reject(lambda text=text: literal({"actual_truth": [9]}, text))
        reject(lambda text=text: literal(text + " altered", text))
    roster(["published-control"], canonical(["published-control"]))
    reject(lambda: roster([{"actual_truth": [9]}], canonical(["published-control"])))
    reject(lambda: roster(["changed text"], canonical(["published-control"])))
    inputs, result, batch = {"/public.json": "0" * 64}, {"passed": True, "histories": 16}, "1" * 64
    receipt = dict(checker_sha256=REVIEW_CHECKER, prediction_batch_sha256=batch,
        input_sha256=inputs, isolation=dict(home_accessible=False, interfaces=["lo"]), result=result)
    review_receipt(receipt, inputs, result, batch)
    reject(lambda: review_receipt(dict(receipt, result=dict(result, hidden_rows=[9])), inputs, result, batch))
    reject(lambda: review_receipt(dict(receipt, result=dict(result, passed=1)), inputs, result, batch))
    reject(lambda: review_receipt(dict(receipt, input_sha256={"/private-path": "0" * 64}), inputs, result, batch))
    with tempfile.TemporaryDirectory(prefix="kpi-export-guard-") as temp:
        root = Path(temp); (root / "real").mkdir(); (root / "real/x").write_text("public")
        (root / "alias").symlink_to(root / "real", target_is_directory=True)
        reject(lambda: checked(root / "alias/x"))
        r = Reader(root)
        for name in ("private/seeds.json", "runs/generate/private/set-01-persistent.json", "runs/controls/stdout.log"):
            reject(lambda name=name: r.blob(name))
        (root / "policy.json").write_text("{}")
        r.blob("policy.json"); (root / "policy.json").write_text('{"changed":true}')
        reject(r.unchanged)
    return dict(passed=True, scope="allowlist, canonical paths, symlink ancestors, nested extra keys, exact review receipts, duplicate/nonfinite JSON, mutation detection")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("destination", type=Path, nargs="?")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        need(args.source is None and args.destination is None, "self-test does not accept trial paths")
        result = self_test()
    else:
        need(args.source is not None and args.destination is not None, "source and destination required")
        result = export(args.source, args.destination)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
