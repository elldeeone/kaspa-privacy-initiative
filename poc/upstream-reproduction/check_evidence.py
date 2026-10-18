#!/usr/bin/env python3
"""Reverify stored local receipts with the pinned upstream CPU executable.

No proof generation, GPU, network, funding or transaction broadcast.
The public archive is obtained from upstream PR51's pinned source checkout.
This trusts that prebuilt executable, not an independently implemented verifier.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
ARCHIVE_SHA = 'f28dfcea27c8c357cece022b7036f013895d907a48b151c4e45d9700f3c2e5a0'
VERIFIER_SHA = 'd9ee19513d2ba2b4296e0e9c4199c175ba2d0948b0f130d3df53a5e875415109'


def main():
    archive = Path(sys.argv[1])
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == ARCHIVE_SHA
    evidence = HERE/'evidence'
    manifest = json.loads((evidence/'manifest.json').read_text())
    for name, record in manifest['files'].items():
        path = (evidence/name).resolve()
        assert path.is_relative_to(evidence.resolve()) and not path.is_symlink()
        data = path.read_bytes()
        assert len(data) == record['bytes'] and hashlib.sha256(data).hexdigest() == record['sha256'], name
    import os
    env = {k: os.environ[k] for k in ('PATH', 'HOME', 'LD_LIBRARY_PATH') if k in os.environ}
    result = json.loads((evidence/'result.json').read_text())
    with tempfile.TemporaryDirectory() as temporary:
        out = Path(temporary)
        # Read only this exact regular member; execute no returned GPU binary.
        with tarfile.open(archive, 'r:gz') as tar:
            member = tar.getmember('bin/kpi-private-native-verifier')
            assert member.isfile() and member.size == 16224728
            binary = tar.extractfile(member).read()
        assert hashlib.sha256(binary).hexdigest() == VERIFIER_SHA
        verifier = out/'verifier'
        verifier.write_bytes(binary)
        verifier.chmod(0o700)
        for case, row in result['batches'].items():
            folder = evidence/row['directory']
            measured = json.loads((folder/'measurement.json').read_text())
            samples = [json.loads(line) for line in (folder/'samples.jsonl').read_text().splitlines()]
            assert measured['exitCode'] == 0 and measured['independentCpuVerified']
            assert measured['matchingGpuProcessObserved'] and not measured['devMode']
            assert not measured['actualTN10Broadcast'] and not measured['privateWitnesses']
            assert max(sum(p['vramMiB'] for p in s['matchingGpuProcesses']) for s in samples) == measured['peakSampledMatchingVramMiB'] == row['peakSampledMatchingVramMiB']
            assert max(s['summedRssBytes'] for s in samples) == measured['peakSampledSummedRssBytes']
            receipt = evidence/row['receipt']
            assert hashlib.sha256(receipt.read_bytes()).hexdigest() == row['receiptSha256']
            subprocess.run([str(verifier), 'verify-receipt', case, str(receipt), str(out/case)],
                           env=env, stdin=subprocess.DEVNULL, check=True, timeout=120)
            report = json.loads((out/case/'verification.json').read_text())
            assert report['programImage'] == result['programImage']
            assert report['exactJournalVerified'] and report['noUnresolvedAssumptions']
            assert report['developmentMode'] is False
            negatives = report['negativeControls']
            assert negatives['tamperedJournalOffsetsRejected'] == list(range(0, 352, 32))
            assert all(negatives[key] for key in ('wrongImageRejected', 'corruptedSealRejected',
                       'malformedControlInclusionRejected', 'wrongExpectedControlRejectedBySealVerifier'))
        receipt = evidence/result['batches']['exit']['receipt']
        subprocess.run([str(verifier), 'verify-native-exit', str(receipt), str(out/'native')],
                       env=env, stdin=subprocess.DEVNULL, check=True, timeout=120)
        native = json.loads((out/'native/native-verification.json').read_text())
        assert native['permissionIssuanceReceiptVerified'] and native['matchesFrozenReconciliationInput']
        payout = native['payout']
        assert payout['positiveNativeScriptsAccepted'] and all(row['rejected'] for row in payout['negativeControls'])
        for field, amount in [('principalPaidSompi', 400_000_000), ('permissionRentRefundSompi', 50_000_000),
                              ('delegateChangeSompi', 600_000_000), ('stateRentExcludedSompi', 100_000_000)]:
            assert payout[field] == amount
    assert len(result['batches']) == 4
    print('OK: four fresh local receipts, exact journals, cryptographic negatives and synthetic native exit verified on CPU.')


if __name__ == '__main__':
    main()
