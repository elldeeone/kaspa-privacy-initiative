"""Frozen LOCAL controls only; never reads a live trial or contacts a node."""
import hashlib
import io
import json
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "poc/future-testnet"))
import recovery_check
import test_recovery_check


def verify():
    manifest = json.loads((HERE / "PRE-RUN-FREEZE-01.json").read_bytes())
    for item in manifest["files"]:
        raw = (ROOT / item["path"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != item["sha256"] or len(raw) != item["bytes"]:
            raise ValueError("frozen control input changed")
    bridge = ROOT.parent / "recipient-target/debug/kpi-future-recipient-crypto"
    if hashlib.sha256(bridge.read_bytes()).hexdigest() != manifest["bridge_sha256"]:
        raise ValueError("crypto bridge changed")
    return bridge


def main():
    bridge = verify()
    destination = HERE / "attempt-01"
    destination.mkdir(exist_ok=False)
    log = io.StringIO()
    started = time.monotonic()
    tests = unittest.defaultTestLoader.loadTestsFromModule(test_recovery_check)
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(tests)
    (destination / "tests.log").write_text(log.getvalue())
    metadata = {"oracle_stage": recovery_check.LOCAL, "network_contacted": False,
                "live_trial_or_seed_read": False, "tests_run": result.testsRun,
                "failures": len(result.failures), "errors": len(result.errors),
                "passed": result.wasSuccessful(), "elapsed_seconds": time.monotonic() - started}
    if result.wasSuccessful():
        crypto = recovery_check.Crypto(bridge)
        verdicts = [recovery_check.evaluate(*test_recovery_check.fixture(label=label),
                    crypto, label, recovery_check.LOCAL) for label in ("bob", "charlie")]
        (destination / "local-verdicts.json").write_text(json.dumps(verdicts, indent=2, sort_keys=True) + "\n")
    verify()
    (destination / "results.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    print(json.dumps(metadata, sort_keys=True))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
