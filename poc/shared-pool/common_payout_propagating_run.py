#!/usr/bin/env python3
"""Snapshot the additional entailed constraints, then use the existing sandbox."""
import argparse
from pathlib import Path
import shutil
import subprocess

import common_payout_batch_run as runner

HERE = Path(__file__).resolve().parent


def run(root, source, case, participant):
    snapshot = root.with_name(root.name + "-code")
    snapshot.mkdir(mode=0o700)
    names = subprocess.check_output(["git", "ls-files", "*.py", "*.json"],
                                    cwd=HERE, text=True).splitlines()
    for name in names:
        original = HERE / name
        # Only the flat analysis tools are needed by the existing oracle.
        if original.parent != HERE:
            continue
        shutil.copyfile(original, snapshot / name)
    mapping = {
        "common_payout_batch_impl.py": "common_payout_batch_observer.py",
        "common_payout_batch_observer.py": "common_payout_propagating_observer.py",
    }
    for mounted, original in mapping.items():
        shutil.copyfile(HERE / original, snapshot / mounted)
    runner.h17.save(snapshot / "source-map.json", dict(
        variant="single-input-balance-implications",
        source_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=HERE, text=True).strip(),
        mappings={mounted: dict(source=original, sha256=runner.h17.sha(HERE / original))
                  for mounted, original in mapping.items()},
        launcher_sha256=runner.h17.sha(HERE / "common_payout_propagating_run.py"),
        tests_sha256=runner.h17.sha(HERE / "common_payout_propagating_tests.py")))
    with (snapshot / "propagating-controls.log").open("x") as log:
        subprocess.run([str(runner.h17.h16.h14.VENV / "bin/python"), "-m", "unittest",
                        "common_payout_propagating_tests", "-v"], cwd=HERE,
                       stdout=log, stderr=log, check=True)
    runner.HERE = snapshot
    runner.h17.OBSERVER_FILES = (*runner.h17.OBSERVER_FILES, "common_payout_batch_impl.py")
    runner.run(root, source, case, participant)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("root", type=Path)
    p.add_argument("source", type=Path)
    p.add_argument("case")
    p.add_argument("participant", type=int, choices=range(4))
    a = p.parse_args()
    run(a.root.resolve(), a.source.resolve(), a.case, a.participant)
