#!/usr/bin/env python3
"""Hash the complete prospective public packet for independent review."""
import argparse
import json
from pathlib import Path

from prepare_controls import CLASS, load, pin, save


def freeze(args):
    expected = load(args.expected)
    if expected.get("classification") != CLASS or expected.get("scope") != "PRIVATE_EXIT_NATIVE_ORDINARY_CONTROLS":
        raise ValueError("ordinary public control packet required")
    files = {args.expected.resolve(), Path(__file__).resolve(),
             Path(__file__).with_name("prepare_controls.py").resolve(),
             Path(__file__).with_name("run_controls.py").resolve()}
    files.update(Path(item["path"]) for item in expected["sources"])
    files.add(Path(expected["native_binary"]["path"]))
    for case in expected["cases"]:
        for key in ("validation_case", "transaction", "supplied_context"):
            item = case[key]
            if pin(item["path"]) != item:
                raise ValueError("prepared public case changed")
            files.add(Path(item["path"]))
    for item in expected["sources"] + [expected["native_binary"]]:
        if pin(item["path"]) != item:
            raise ValueError("prepared source or executable changed")
    result = {"classification": CLASS, "scope": expected["scope"],
              "runtime_authorized": args.authorize, "review_note": args.review_note,
              "network_or_broadcast_authorized": False,
              "files": [pin(path) for path in sorted(files)]}
    save(args.output, result)
    return {"freeze": str(args.output), "sha256": pin(args.output)["sha256"],
            "files": len(files), "runtime_authorized": args.authorize}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--review-note", required=True)
    parser.add_argument("--authorize", action="store_true")
    print(json.dumps(freeze(parser.parse_args()), sort_keys=True))
