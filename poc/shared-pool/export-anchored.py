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
    for step in range(6):
        for suffix in ['.json', '.metrics.json']:
            copy(f'public/{step:04}{suffix}')
    if role == 'offline':
        copy('offline-result.json')
        copy('native-controls.json')
        for label in ['bootstrap', 'alice', 'bob-new-note', 'alice-exit']:
            copy('public/' + label + '.bundle.json')
    else:
        for name in ['result.json', 'identity.json', 'node-before.json',
                     'bob-prover-stopped.json', 'chain-confirmed.json']:
            copy(name)
        for step in [0, 1, 2, 4, 5]:
            for suffix in ['.inputs.json', '.submission.json', '.response.json', '.confirmed.json']:
                copy(f'live/{step:04}{suffix}')
        for name in ['result.json', 'isolation.json', 'node.json', 'discovery.json',
                     '0002.inputs.json', '0003.inputs.json', '0003.submission.json',
                     '0003.response.json', '0003.confirmed.json']:
            copy('bob-public-rebuilder/output/' + name, 'rebuilder/' + name)
        for label, reports in [('alice-prover', ['bootstrap', 'alice', 'alice-exit']),
                               ('bob-prover', ['bob']), ('bob-cleanup-prover', ['bob-new-note'])]:
            for name in ['isolation.json', 'ready.json', 'process-exit.json']:
                copy(label + '/' + name)
            for report in reports:
                copy(label + '/' + report + '.report.json')
        for label in ['bootstrap', 'alice', 'bob-new-note', 'alice-exit']:
            copy(label + '-rebuild/process.json')
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
