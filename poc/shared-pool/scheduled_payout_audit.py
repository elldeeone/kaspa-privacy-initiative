"""Post-score explanation of H18 results; never an observer input or gate."""
import importlib.util
from pathlib import Path
import statistics
import sys

from scheduled_payout_observer import Q, weight

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("h18", HERE / "scheduled-payout.py")
h18 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h18)


def counts(values):
    return dict(minimum=min(values), median=statistics.median(values), maximum=max(values))


def audit(root):
    # Require complete scoring before reading any private pairing information.
    summary = h18.read(root / "summary.json")
    assert summary["observations"] == 252 and summary["all_truth_survives"]
    cfg = h18.freeze()
    result = dict(
        purpose="Post-score aggregate explanation, not a new hypothesis or decision gate",
        candidate_meaning="Creating transactions/source sets, not owners or probabilities",
        participant_meaning="Separate views aggregated; never a colluding observer",
        full_coverage_guesses=True, unique_inference_precision=1,
        regimes={})
    for regime in cfg["regimes"]:
        names = [f"{regime}-{i:02}" for i in range(cfg["cases_per_regime"])]
        report = {}
        for arm in ("full", "scheduled"):
            report[arm] = {}
            for knowledge in ("untimed", "timed"):
                report[arm][knowledge] = {}
                for profile in ("chain", "participants"):
                    observers = ["chain"] if profile == "chain" else [
                        f"participant-{i}" for i in range(4)]
                    rows, payments, distinct_claims, distinct_payments = [], [], set(), set()
                    for name in names:
                        for obs in observers:
                            score = h18.read(root / name / arm / obs / "score.json")[knowledge]
                            rows.extend(score["claims"])
                            payments.extend(score["payments"])
                            distinct_claims.update((name, r["claim"]) for r in score["claims"] if r["unique"])
                            distinct_payments.update((name, r["event"]) for r in score["payments"] if r["unique"])
                    common = [n for r in rows for n in r["common_leg_counts"]]
                    report[arm][knowledge][profile] = dict(
                        claim_targets=len(rows), unique_claim_observations=sum(r["unique"] for r in rows),
                        distinct_unique_claims=len(distinct_claims),
                        claim_candidates=counts([r["minimum_candidates"] for r in rows]),
                        common_leg_candidates=counts(common) if common else None,
                        correct_guesses={a: sum(r["correct"][a] for r in rows) for a in rows[0]["correct"]},
                        payment_targets=len(payments),
                        unique_payment_observations=sum(r["unique"] for r in payments),
                        distinct_unique_payments=len(distinct_payments),
                        payment_candidates=counts([r["candidates"] for r in payments]),
                        correct_payment_guesses={
                            a: sum(r["correct"][a] for r in payments) for a in payments[0]["correct"]})
        pair_counts, unique_correct, sources_equal, source_pairs = [], 0, 0, 0
        for name in names:
            data = h18.read(root / name / "scheduled" / "public.json")
            private = h18.read(root / name / "scheduled" / "private.json")
            full_private = h18.read(root / name / "full" / "private.json")
            old_claims = {c["claim"]: c for c in full_private["claims"]}
            for claim in private["claims"]:
                if not claim["shaped"]:
                    continue
                first, last = claim["legs"]
                assert data["events"][first]["payout"] == Q
                tails = [i for i, e in enumerate(data["events"])
                         if i > first and e["mode"] == 2 and weight(data, first, i)]
                assert last in tails
                pair_counts.append(len(tails))
                unique_correct += tails == [last]
            for obs in ("chain", *[f"participant-{i}" for i in range(4)]):
                old = {r["event"]: r for r in h18.read(
                    root / name / "full" / obs / "predictions.json")["timed"]["rows"]}
                new = {r["event"]: r for r in h18.read(
                    root / name / "scheduled" / obs / "predictions.json")["timed"]["rows"]}
                eligible = {c["claim"] for c in h18.read(
                    root / name / "scheduled" / obs / "score.json")["timed"]["claims"]}
                for claim in private["claims"]:
                    if claim["claim"] not in eligible:
                        continue
                    reference = old[old_claims[claim["claim"]]["legs"][0]]["candidates"]
                    source_pairs += 1
                    sources_equal += all(new[i]["candidates"] == reference for i in claim["legs"])
        report["public_timing_pairing"] = dict(
            common_payouts=len(pair_counts), compatible_full_tail_counts=counts(pair_counts),
            sole_compatible_tail_matches_truth=unique_correct,
            matched_claim_view_pairs=source_pairs,
            all_leg_source_candidates_equal_to_full_baseline=sources_equal,
            boundary="Normal policy and modeled clock/queue assumptions; not a protocol guarantee")
        result["regimes"][regime] = report
    return result


if __name__ == "__main__":
    h18.save(Path(sys.argv[2]).resolve(), audit(Path(sys.argv[1]).resolve()))
