"""Only the four controls affected by prospective node metadata/LOCAL wrapping."""
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "poc/future-testnet"))
import test_recovery_check


def verify():
    for item in json.loads((HERE / "PRE-RUN-FREEZE-03.json").read_bytes())["files"]:
        raw = (ROOT / item["path"]).read_bytes()
        if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("delta source/input changed")


def main():
    verify()
    names = ["test_01_two_seed_only_terminal_receivers_and_true_zero",
             "test_15_removed_acceptance_and_wrong_node_network_reject",
             "test_18_network_confirmation_metadata_cannot_contradict_itself",
             "test_19_local_native_full_adapter_cannot_claim_node_acceptance"]
    suite = unittest.TestSuite(test_recovery_check.AcceptedRecoveryTests(name) for name in names)
    destination = HERE / "delta-01"
    destination.mkdir(exist_ok=False)
    log = io.StringIO()
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    verify()
    (destination / "tests.log").write_text(log.getvalue())
    report = {"classification": "OFFLINE_LOCAL_AND_MOCK_NODE_METADATA_CONTROLS",
              "passed": result.wasSuccessful(), "tests_run": result.testsRun,
              "failures": len(result.failures), "errors": len(result.errors),
              "network_contacted": False, "live_trial_or_seed_read": False}
    (destination / "results.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
