#!/usr/bin/env python3
"""Explicit public-artifact allowlist; never copy wallet/proving witness files."""
import argparse
import hashlib
import json
from pathlib import Path


def export(source: Path, destination: Path, role: str):
    destination.mkdir(parents=True, exist_ok=False)
    copied = {}

    def sanitize(value):
        if isinstance(value, dict):
            return {k: sanitize(v) for k, v in value.items()
                    if k not in {'mounts', 'root', 'offlineRoot', 'endpoint'}}
        if isinstance(value, list):
            return [sanitize(v) for v in value]
        if isinstance(value, str):
            return value.replace(str(source), 'PRIVATE_TRIAL_ROOT')
        return value

    def copy(relative, target=None):
        path = source / relative
        if not path.is_file():
            raise ValueError(f'missing required evidence: {relative}')
        out = destination / (target or relative)
        out.parent.mkdir(parents=True, exist_ok=True)
        raw = path.read_bytes()
        if path.suffix == '.json':
            data = json.loads(raw)
            encoded = json.dumps(sanitize(data), indent=2, sort_keys=True) + '\n'
            out.write_text(encoded)
        else:
            out.write_bytes(raw)
        copied[str(out.relative_to(destination))] = {
            'source_sha256': hashlib.sha256(raw).hexdigest(),
            'export_sha256': hashlib.sha256(out.read_bytes()).hexdigest(),
        }

    for name in ['manifest.json', 'vk.bin', 'source-utxo.json', 'bob.bundle.json']:
        copy('public/' + name)
    result = json.loads((source / ('offline-result.json' if role == 'offline' else 'result.json')).read_text())
    count = result['transactions' if role == 'offline' else 'confirmedTransactions']
    payments = result['payments_after_bob_authorization' if role == 'offline' else 'paymentsAfterBobAuthorization']
    bob_step = payments + 2
    for step in range(count):
        for suffix in ['.json', '.metrics.json']:
            copy(f'public/{step:04}{suffix}')
    if role == 'offline':
        copy('offline-result.json')
        copy('native-controls.json')
        copy('independent-state.json')
        # The native transactions already carry every public proof/auth; do not
        # duplicate all payment bundles or export private wallet requests.
    else:
        for name in ['result.json', 'identity.json', 'node-before.json',
                     'bob-prover-stopped.json', 'all-payment-provers-stopped.json', 'chain-confirmed.json']:
            copy(name)
        for step in range(count):
            if step == bob_step:
                continue
            for suffix in ['.inputs.json', '.submission.json', '.response.json', '.confirmed.json']:
                copy(f'live/{step:04}{suffix}')
        for name in ['result.json', 'isolation.json', 'node.json', 'discovery.json']:
            copy('bob-public-rebuilder/output/' + name, 'rebuilder/' + name)
        for suffix in ['.inputs.json', '.submission.json', '.response.json', '.confirmed.json']:
            name=f'{bob_step:04}{suffix}'
            copy('bob-public-rebuilder/output/' + name, 'rebuilder/' + name)
        for label in ['alice-prover', 'bob-prover', 'alice-cleanup-prover', 'carol-cleanup-prover']:
            for name in ['isolation.json', 'ready.json', 'process-exit.json']:
                copy(label + '/' + name)
            for report in sorted((source / label).glob('*.report.json')):
                copy(label + '/' + report.name)
    (destination / 'export.json').write_text(json.dumps({
        'role': role, 'allowlist_only': True,
        'omitted': ['wallet files', 'spending/viewing/native keys', 'private notes',
                    'proving keys', 'private requests', 'raw process mounts', 'local endpoint'],
        'files': copied,
        'scope': 'Public experimental evidence; not a chain-only observer input or anonymity estimate',
    }, indent=2) + '\n')
    print(json.dumps({'exported': str(destination), 'files': len(copied)}))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('role', choices=['offline', 'rehearsal', 'trial'])
    p.add_argument('source', type=Path)
    p.add_argument('destination', type=Path)
    a = p.parse_args()
    export(a.source.resolve(), a.destination.resolve(), a.role)
