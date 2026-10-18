#!/usr/bin/env python3
"""Retain whitelisted public wallet evidence, excluding fresh keys/witnesses."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
from datetime import datetime, timezone
import wire_format as wire

ROOT = Path(__file__).resolve().parents[2]
NAMES = ('credit', 'transfer', 'exit', 'restored-exit')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def secret_patterns(task):
    # Local omission check only. Nothing collected here is serialized or logged.
    secrets = set()
    for backup in (task / 'cases').glob('*backup.json'):
        value = json.loads(backup.read_text())
        for key in value['orchard_keys']:
            secrets.add(bytes.fromhex(key))
        if value.get('pending_deposit_seed'):
            secrets.add(bytes.fromhex(value['pending_deposit_seed']))
    for name in NAMES:
        r = wire.Reader((task / 'cases' / name / 'input.bin').read_bytes())
        if r.take(len(b'KPI/private-payment/witness/v1')) != b'KPI/private-payment/witness/v1':
            raise RuntimeError('unexpected private frame during omission check')
        r.take(r.number(32))
        for _ in range(2):
            secrets.add(r.take(32)); r.take(1 + 11 + 8)
            r.take(32); secrets.add(r.take(32))  # rho is public for real notes; seed is secret
            flag = r.number(8)
            if flag == 1: r.take(4 + 32 * 32)
            elif flag != 0: raise RuntimeError('unexpected private path flag')
        for _ in range(2):
            r.take(43 + 8); secrets.add(r.take(32)); r.take(512)
    if any(len(x) != 32 for x in secrets): raise RuntimeError('secret-pattern width')
    return secrets


def run(task, review, archive, manifest):
    if archive.exists() or manifest.exists(): raise FileExistsError('evidence output exists')
    if not (task / 'all-wallet-checks.done.json').is_file():
        raise RuntimeError('full proof/restore run is incomplete')
    files = {}

    def add(name, path):
        if name in files: raise RuntimeError('duplicate archive path')
        if path.is_symlink() or not path.is_file(): raise RuntimeError('regular evidence file required')
        if any(p.lower().endswith('backup.json') or p == 'input.bin' for p in Path(name).parts):
            raise RuntimeError('private file name refused')
        files[name] = path.read_bytes()

    # Exact reviewed relation/final code. No host executables, targets or caches.
    for folder in ('wallet-core', 'wallet-guest', 'wallet-host'):
        base = ROOT / 'poc/private-payment' / folder
        for path in [base / 'Cargo.toml', base / 'Cargo.lock', *sorted((base / 'src').rglob('*.rs'))]:
            add('source/' + str(path.relative_to(ROOT)), path)
    for name in ('public_binding.py', 'wire_format.py', 'run_wallet.py', 'run_wallet_negatives.py',
                 'check_wallet_public.py', 'check_isolated_restore.py', 'package_wallet_evidence.py',
                 'suite-candidate.json', 'WALLET.md', 'WALLET-PLAN.md', 'WALLET-ADVERSARIAL.md', 'WALLET-RESULTS.md'):
        path = ROOT / 'poc/private-payment' / name
        add('source/' + str(path.relative_to(ROOT)), path)
    for name in ('SECURITY-INVARIANTS.md', 'THREAT-MODEL.md', 'docs/ARCHITECTURE.md',
                 'docs/adr/0020-offline-wallet-relation.md',
                 'docs/rfc/0003-private-payment-proof-and-settlement.md',
                 'docs/rfc/0004-private-payment-suite-and-encoding.md'):
        add('source/' + name, ROOT / name)
    # Shared signature verifier is part of the proved guest's actual dependency.
    base = ROOT / 'poc/private-payment/recovery-auth-vectors'
    for name in ('Cargo.toml', 'Cargo.lock', 'src/lib.rs'):
        add('source/poc/private-payment/recovery-auth-vectors/' + name, base / name)

    proofs = []
    for name in NAMES:
        p = task / 'proofs' / name
        result = json.loads((p / 'result.json').read_text())
        report = json.loads((p / 'proof/report.json').read_text())
        verify = json.loads((p / 'verification/report.json').read_text())
        resource = json.loads((p / 'proof-resources.resources.json').read_text())
        if not (result['walletReceiptVerified'] and report['walletReceiptVerified'] and
                verify['savedWalletReceiptVerified'] and resource['positiveProcessSmObserved'] and
                resource['exitCode'] == 0 and resource['failure'] is None):
            raise RuntimeError('unqualified wallet proof phase')
        receipt = (p / 'proof/wallet-receipt.bin').read_bytes()
        if sha(receipt) != report['receiptSha256'] or sha(receipt) != verify['receiptSha256']:
            raise RuntimeError('retained wallet receipt identity mismatch')
        proofs.append({'case': name, 'receiptSha256': sha(receipt), 'seconds': report['seconds'],
                       'stats': report['stats'], 'verifierParameters': report['verifierParameters']})
        for path in sorted(p.rglob('*')):
            if path.is_file() and 'cuda-cache' not in path.relative_to(p).parts:
                add('proofs/' + name + '/' + str(path.relative_to(p)), path)
        for entry in ('case.json', 'intent.bin', 'authorization.bin', 'expected-journal.bin'):
            add('cases/' + name + '/' + entry, task / 'cases' / name / entry)
    add('program.bin', task / 'program.bin')
    # Mixed history intentionally retains a well-formed false receipt.
    add('proofs/invalid-wallet/proof/wallet-receipt.bin', task / 'proofs/invalid-wallet/proof/wallet-receipt.bin')
    for folder in ('restore', 'final', 'negative-vm-results', 'receipt-codec-controls'):
        for path in sorted((task / folder).rglob('*')):
            if path.is_file() and 'cuda-cache' not in path.relative_to(task / folder).parts: add('checks/' + folder + '/' + str(path.relative_to(task / folder)), path)
    for folder in sorted(task.glob('isolated-*')):
        # Never traverse work/, which contains one actor's private backup.
        for entry in ('report.json', 'stdout.log', 'stderr.log', 'reports/restore.json'):
            add('checks/' + folder.name + '/' + entry, folder / entry)
    for name in ('native-controls-v2.json', 'wire-interop.json', 'public-interop.json',
                 'public-interop-final.json', 'reproduction.json', 'build-provenance.json',
                 'credit-history.json', 'credit-public-verification.json',
                 'credit-duplicate-history.json', 'credit-duplicate-public-verification.json',
                 'transfer-history.json', 'transfer-public-verification.json',
                 'transfer-duplicate-history.json', 'transfer-duplicate-public-verification.json',
                 'final-public-verification.json', 'mixed-public-verification.json',
                 'all-wallet-checks.done.json', 'backup-key-rejections.json'):
        add('checks/' + name, task / name)
    for name in ('initial-review.md', 'host-review.md', 'credit-runtime-review.md',
                 'final-runtime-review.md', 'isolated-credit-review.md',
                 'duplicate-and-encoding-review.md', 'receipt-codec-fix-review.md', 'transfer-runtime-review.md', 'manifest.json', 'scan-boundary-results.json',
                 'host-boundary-results.json', 'scan_boundary_probe.rs', 'host_boundary_probe.rs',
                 'final-runtime-results.json', 'final-runtime-link-artifacts.json',
                 'final-runtime-review-evidence.json',
                 'final-proof-evidence-consistency.json', 'final-source-comparison.json',
                 'final_runtime_probe.rs', 'transfer-runtime-results.json', 'transfer_runtime_probe.rs',
                 'receipt-codec-results.json', 'receipt_codec_probe.rs'):
        add('separate-agent-review/' + name, review / name)
    for folder in ('final-public-runtime', 'final-runtime-python'):
        for path in sorted((review / folder).rglob('*')):
            if not path.is_file(): continue
            if path.suffix not in ('.json', '.py', '.txt'):
                raise RuntimeError('unexpected separate-review runtime artifact')
            add('separate-agent-review/' + folder + '/' + str(path.relative_to(review / folder)), path)
    # All reviewed snapshots are exact, immutable, source-only copies.
    for name in ('manifest.json',):
        source_manifest = json.loads((review / name).read_text())
        for relative, meta in source_manifest['files'].items():
            path = review / relative
            expected = meta['sha256'] if isinstance(meta, dict) else meta
            if sha(path.read_bytes()) != expected: raise RuntimeError('initial reviewed input changed')
            add('separate-agent-review/initial-inputs/' + relative, path)
    for folder in sorted(review.glob('*inputs*')):
        if not folder.is_dir(): continue
        for path in sorted(folder.rglob('*')):
            if path.is_file(): add('separate-agent-review/' + folder.name + '/' + str(path.relative_to(folder)), path)
    patterns = secret_patterns(task)
    for raw in files.values():
        if any(secret in raw or secret.hex().encode() in raw for secret in patterns):
            raise RuntimeError('fresh key/seed plaintext detected; no archive was written')
    prior = []
    for name in ('review-preparation', 'recovery-authority', 'node-recheck', 'agent-composition-review'):
        path = ROOT / f'poc/private-payment/evidence/2026-10-18-{name}.json'
        old = json.loads(path.read_text()); artifact = path.with_name(old['archive']['file'])
        if sha(artifact.read_bytes()) != old['archive']['sha256']: raise RuntimeError('historical archive changed')
        prior.append({'file': artifact.name, 'sha256': old['archive']['sha256']})
    with tarfile.open(archive, 'x:gz') as tar:
        for name, raw in sorted(files.items()):
            info = tarfile.TarInfo(name); info.size = len(raw); info.mode = 0o644; info.mtime = 0
            tar.addfile(info, io.BytesIO(raw))
    with tarfile.open(archive, 'r:gz') as tar:
        if len(tar.getmembers()) != len(files): raise RuntimeError('archive member count mismatch')
        for member in tar.getmembers():
            if tar.extractfile(member).read() != files[member.name]: raise RuntimeError('archive member identity mismatch')
    result = {'scope': 'FULL_OFFLINE_WALLET_GPU_RECEIPTS_HOST_ADMISSION_AND_RESTORE_NOT_PROVED_OUTER_OR_NATIVE',
              'recordedAtUtc': datetime.now(timezone.utc).isoformat(), 'walletProofs': proofs,
              'nativeTransactions': 0, 'mainnet': False, 'realFunds': False,
              'archive': {'file': archive.name, 'sha256': sha(archive.read_bytes()), 'bytes': archive.stat().st_size},
              'files': {name: {'sha256': sha(raw), 'bytes': len(raw)} for name, raw in sorted(files.items())},
              'validation': {'archiveMemberHashes': True, 'freshKeyAndSeedPlaintextOmissionCheck': True,
                             'omissionCheckIsPrivacyProof': False, 'priorArchivesUnchanged': prior}}
    with manifest.open('x') as f: json.dump(result, f, indent=2); f.write('\n')
    print(json.dumps({'publicEvidenceFiles': len(files), 'realWalletReceipts': len(proofs),
                      'archiveSha256': result['archive']['sha256'], 'freshSecretsExcluded': True}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ('task', 'review', 'archive', 'manifest'): parser.add_argument(arg, type=Path)
    a = parser.parse_args(); run(a.task.resolve(), a.review.resolve(), a.archive.resolve(), a.manifest.resolve())
