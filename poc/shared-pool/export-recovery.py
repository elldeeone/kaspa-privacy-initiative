#!/usr/bin/env python3
"""Export H7 public evidence by allowlist, rejecting known backup secrets."""
import argparse
import hashlib
import json
import re
from pathlib import Path


def export(source: Path, destination: Path, role: str):
    result_name = 'offline-result.json' if role == 'offline' else 'result.json'
    result = json.loads((source / result_name).read_text())
    assert result['complete'] and result['role'] == role
    secrets = []
    for index in range(3):
        backup = json.loads((source / f'backups/wallet{index}.json').read_text())
        secrets.extend(bytes(value) for value in backup['wallet'].values())
        if backup['initial_note']:
            secrets.append(bytes(backup['initial_note']['rho']))
    funding_key = source / 'synthetic-funding.key'
    if funding_key.exists():
        secrets.append(bytes.fromhex(funding_key.read_text().strip()))
    forbidden = {'spending', 'viewing', 'initial_note', 'rho', 'future_note',
                 'mnemonic', 'seed', 'privateKey', 'private_key', 'wallets_private'}
    hashes = {}
    destination.mkdir(parents=True, exist_ok=False)

    def sanitize(value):
        if isinstance(value, dict):
            assert not forbidden.intersection(value), 'private field in evidence'
            return {k: sanitize(v) for k, v in value.items()
                    if k not in {'mounts', 'pidNamespace', 'networkDevices', 'endpoint', 'root'}}
        if isinstance(value, list):
            if len(value) == 32 and all(isinstance(x, int) and 0 <= x <= 255 for x in value):
                assert bytes(value) not in secrets, 'private key/opening in evidence'
            return [sanitize(v) for v in value]
        if isinstance(value, str):
            # Check before redaction; never hide a failed secret check.
            assert all(s.hex() not in value.lower() for s in secrets), 'secret hex in evidence'
            value = value.replace(str(source), 'PRIVATE_TRIAL_ROOT')
            value = re.sub(r'/home/(?:luke|ubuntu)/[^\s"\x27]*', 'PRIVATE_HOST_PATH', value)
            return re.sub(r'(?:ws|http)://10\.[0-9.:]+/?', 'ORIGINAL_PRIVATE_ENDPOINT/', value)
        return value

    def copy(relative, target=None):
        original = source / relative
        raw = original.read_bytes()
        out = destination / (target or relative)
        out.parent.mkdir(parents=True, exist_ok=True)
        if original.suffix == '.json':
            encoded = (json.dumps(sanitize(json.loads(raw)), indent=2, sort_keys=True) + '\n').encode()
        elif original.suffix == '.bin':
            assert relative == 'public/vk.bin'
            encoded = raw
        else:
            encoded = sanitize(raw.decode()).encode()
        for secret in secrets:
            assert secret not in encoded and secret.hex().encode() not in encoded.lower(), 'secret in output'
        out.write_bytes(encoded)
        hashes[str(out.relative_to(destination))] = {
            'source_sha256': hashlib.sha256(raw).hexdigest(),
            'export_sha256': hashlib.sha256(encoded).hexdigest(),
        }

    for name in ['descriptor.json', 'vk.bin', 'source-utxo.json']:
        copy('public/' + name)
    for step in range(6):
        for suffix in ['.json', '.metrics.json']:
            copy(f'public/{step:04}{suffix}')
    for name in [result_name, 'identity.json', 'accounting.json', 'independent-state.json', 'originals-stopped.json']:
        copy(name)
    if role == 'offline':
        for name in ['recovery-controls.json', 'native-controls.json']:
            copy(name)
    else:
        for name in ['node-before.json', 'original-source-stopped.json', 'chain-confirmed.json']:
            copy(name)
        for step in range(3):
            for suffix in ['.inputs.json', '.submission.json', '.response.json', '.confirmed.json']:
                copy(f'logs/{step:04}{suffix}')
    for index in [1, 2, 0]:
        prefix = f'recovered-{index}'
        copy(prefix + '/process-exit.json')
        for name in ['result.json', 'exit-report.json', 'isolation.json', 'sources.json',
                     'create-exit.resources.txt', 'source-1-check.stdout.json']:
            copy(prefix + '/output/' + name)
        if role != 'offline':
            for name in ['node.json', 'node-after-proof.json', 'current-input.json', 'submission.json', 'response.json',
                         'confirmed.json', 'accepted.json', 'after-exit.stdout.json']:
                copy(prefix + '/output/' + name)
    (destination / 'export.json').write_text(json.dumps({
        'role': role, 'allowlist_only': True, 'known_backup_secrets_checked': len(secrets),
        'omitted': ['backups', 'private wallet files', 'note openings', 'proving key',
                    'original address book', 'raw mounts', 'private host paths'],
        'files': hashes,
        'scope': 'Synthetic experimental evidence with wallet labels; not chain-observer input or an anonymity result',
    }, indent=2) + '\n')
    print(json.dumps({'role': role, 'files': len(hashes), 'destination': str(destination)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('role', choices=['offline', 'rehearsal', 'trial', 'cleanup'])
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    export(args.source.resolve(), args.destination.resolve(), args.role)
