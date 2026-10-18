#!/usr/bin/env python3
"""Restore with only one actor's backup and public history mounted; no network."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    host, history, proofs, backup, output = map(lambda s: Path(s).resolve(), sys.argv[1:6])
    expected_pin, expected_balance = sys.argv[6], int(sys.argv[7])
    if 'RISC0_DEV_MODE' in os.environ: raise RuntimeError('development mode forbidden')
    if sha(history) != expected_pin: raise RuntimeError('externally supplied history pin mismatch')
    output.mkdir(mode=0o700, exist_ok=False)
    work, reports = output / 'work', output / 'reports'
    work.mkdir(mode=0o700); reports.mkdir(mode=0o700)
    shutil.copyfile(host, work / 'wallet-host'); (work / 'wallet-host').chmod(0o500)
    shutil.copyfile(backup, work / 'backup.json'); (work / 'backup.json').chmod(0o400)
    shutil.copyfile(history, work / 'history.json')
    h = json.loads(history.read_text())
    copied = {}
    for row in h['records']:
        name = row['name']
        if not re.fullmatch('[a-zA-Z0-9-]+', name): raise RuntimeError('unsafe proof name')
        expected = row['receipt_sha256']
        if name in copied:
            if copied[name] != expected: raise RuntimeError('conflicting receipt identities for repeated name')
            continue
        p = work / 'proofs' / name / 'proof'; p.mkdir(parents=True, exist_ok=False)
        shutil.copyfile(proofs / name / 'proof/wallet-receipt.bin', p / 'wallet-receipt.bin')
        if sha(p / 'wallet-receipt.bin') != expected: raise RuntimeError('receipt identity mismatch')
        copied[name] = expected
    command = ['bwrap', '--unshare-all', '--die-with-parent',
               '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib',
               '--ro-bind', '/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev',
               '--ro-bind', str(work), '/work', '--bind', str(reports), '/reports',
               '--chdir', '/work', '--', '/work/wallet-host', 'restore',
               '/work/history.json', expected_pin, '/work/proofs', '/work/backup.json', '/reports/restore.json']
    with (output / 'stdout.log').open('x') as log, (output / 'stderr.log').open('x') as errors:
        result = subprocess.run(command, env={'PATH': '/usr/bin:/bin'}, stdout=log, stderr=errors, timeout=3600)
    if result.returncode: raise RuntimeError('isolated restore failed; logs retained')
    restored = json.loads((reports / 'restore.json').read_text())
    if restored['spendableSompi'] != expected_balance: raise RuntimeError('unexpected isolated restored balance')
    report = {'scope': 'SAME_HOST_NETWORK_AND_FILESYSTEM_ISOLATED_OWN_BACKUP_RESTORE_NOT_INDEPENDENT_OPERATOR_R16',
              'hostSha256': sha(host), 'historySha256': expected_pin,
              'ownBackupOnly': True, 'otherActorBackupMounted': False, 'originalProverWitnessFilesMounted': False,
              'networkNamespaceIsolated': True, 'sameHost': True,
              'receiptCopies': len(copied), 'historyRecords': len(h['records']), 'restored': restored, 'nativeTransactions': 0}
    with (output / 'report.json').open('x') as f: json.dump(report, f, indent=2); f.write('\n')
    print(json.dumps({'isolatedRestorePassed': True, 'spendableSompi': expected_balance}))


if __name__ == '__main__': main()
