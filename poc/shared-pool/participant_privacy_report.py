"""Derive readable metrics from exported H16 scores, without private records."""
import argparse
import hashlib
import json
from pathlib import Path


def derive(root):
    summary = json.loads((root / "summary.json").read_text())
    if summary["completed_observations"] != 64 or not summary["all_truth_survives"]:
        raise ValueError("incomplete H16 results")
    indexed = {}
    for path in sorted(root.glob("*/*/*/*/score.json")):
        case, arm, participant, profile, _ = path.relative_to(root).parts
        score = json.loads(path.read_text())
        for row in score["rows"]:
            if row["attack"] == "joint":
                indexed[case, arm, int(participant), profile, row["event"], row["through"]] = row
    distinct = []
    for profile in ("records", "wallet"):
        for arm in ("fresh", "saved"):
            for category in ("payment", "partial", "exit"):
                for horizon in ("at_event", "after_drain"):
                    groups = {}
                    for (case, a, participant, p, event, through), row in indexed.items():
                        if (a != arm or p != profile or row["category"] != category
                                or through != (event if horizon == "at_event" else 18)):
                            continue
                        groups.setdefault((case, event), []).append(row)
                    distinct.append(dict(
                        profile=profile, arm=arm, category=category, horizon=horizon,
                        distinct_targets=len(groups),
                        unique_for_at_least_one_participant=sum(
                            any(r["unique_sources"] for r in rows) for rows in groups.values()),
                        newly_unique_for_at_least_one_participant=sum(
                            any(r["new_unique_sources"] for r in rows) for rows in groups.values()),
                        unique_for_every_eligible_participant=sum(
                            all(r["unique_sources"] for r in rows) for rows in groups.values()),
                    ))
    new_links = []
    ownership_added = []
    for key, row in indexed.items():
        case, arm, participant, profile, event, through = key
        if through != 18:
            continue
        if row["new_unique_sources"]:
            earlier = [(k[-1], r) for k, r in indexed.items() if k[:-1] == key[:-1]]
            first = min(t for t, r in earlier if r["new_unique_sources"])
            new_links.append(dict(case=case, arm=arm, participant=participant, profile=profile,
                                  event=event, category=row["category"], first_observed_through=first,
                                  already_forced_at_appearance=first == event,
                                  baseline_candidates=row["baseline_source_candidates"]))
        if profile == "wallet" and row["unique_sources"]:
            record = indexed[case, arm, participant, "records", event, through]
            if not record["unique_sources"]:
                ownership_added.append(dict(case=case, arm=arm, participant=participant,
                                            event=event, category=row["category"],
                                            records_candidates=record["source_candidates"]))
    return dict(
        summary_sha256=hashlib.sha256((root / "summary.json").read_bytes()).hexdigest(),
        report_code_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        distinct=distinct, newly_forced_links=new_links, ownership_added_unique_links=ownership_added,
        meaning="at least one separate disclosing participant, never pooled disclosures",
        horizon_limit="appearance then exit checkpoints; first detection after an exit is not proof that exit alone caused it",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    with args.output.open("x") as output:
        json.dump(derive(args.evidence), output, indent=2)
        output.write("\n")
